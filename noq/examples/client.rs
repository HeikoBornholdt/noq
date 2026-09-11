//! This example demonstrates an HTTP client that requests files from a server.
//!
//! Checkout the `README.md` for guidance.

use std::{
    fs,
    io::{self, Write},
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use clap::Parser;
use noq::{PathError, PathStatus};
use proto::{TransportConfig, crypto::rustls::QuicClientConfig};
use rustls::pki_types::CertificateDer;
use tokio_stream::StreamExt;
use tracing::{error, info};
use url::Url;

mod common;

/// HTTP/0.9 over QUIC client
#[derive(Parser, Debug)]
#[clap(name = "client")]
struct Opt {
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[clap(long = "keylog")]
    keylog: bool,

    url: Url,

    /// Override hostname used for certificate verification
    #[clap(long = "host")]
    host: Option<String>,

    /// Custom certificate authority to trust, in DER format
    #[clap(long = "ca")]
    ca: Option<PathBuf>,

    /// Simulate NAT rebinding after connecting
    #[clap(long = "rebind")]
    rebind: bool,

    /// Address to bind on
    #[clap(long = "bind", default_value = "[::]:0")]
    bind: SocketAddr,
}

/// Keep-alive interval of every path, set on this side only.
const KEEP_ALIVE: Duration = Duration::from_secs(5);

/// Idle timeout of every path.
const PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long to stay connected after the response, to watch the backup path.
const LINGER: Duration = Duration::from_secs(40);

fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    let opt = Opt::parse();
    let code = {
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    let url = options.url;
    let url_host = strip_ipv6_brackets(url.host_str().unwrap());
    let remote = (url_host, url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca_path) = options.ca {
        roots.add(CertificateDer::from(fs::read(ca_path)?))?;
    } else {
        let dirs = directories_next::ProjectDirs::from("org", "noq", "noq-examples").unwrap();
        match fs::read(dirs.data_local_dir().join("cert.der")) {
            Ok(cert) => {
                roots.add(CertificateDer::from(cert))?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("local server certificate not found");
            }
            Err(e) => {
                error!("failed to open local server certificate: {}", e);
            }
        }
    }
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    client_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    if options.keylog {
        client_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let mut transport = TransportConfig::default();
    transport
        .send_observed_address_reports(true)
        .receive_observed_address_reports(true)
        .max_concurrent_multipath_paths(2)
        .default_path_keep_alive_interval(Some(KEEP_ALIVE))
        .default_path_max_idle_timeout(Some(PATH_IDLE_TIMEOUT));
    let mut client_config =
        noq::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(Arc::new(transport));
    let endpoint = noq::Endpoint::client(options.bind)?;
    endpoint.set_default_client_config(client_config);

    let request = format!("GET {}\r\n", url.path());
    let start = Instant::now();
    let rebind = options.rebind;
    let host = options.host.as_deref().unwrap_or(url_host);

    eprintln!("connecting to {host} at {remote}");
    let conn = endpoint
        .connect(remote, host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;
    eprintln!("connected at {:?}", start.elapsed());
    let mut external_addresses = conn.observed_external_addr();
    tokio::spawn(async move {
        while let Some(new_addr) = external_addresses.next().await {
            info!(%new_addr, "new external address report");
        }
    });

    let mut path_events = conn.path_events();
    tokio::spawn(async move {
        while let Some(Ok(event)) = path_events.next().await {
            info!(?event, "path event");
        }
    });
    open_backup_path(&conn, remote).await?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;
    if rebind {
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let addr = socket.local_addr().unwrap();
        eprintln!("rebinding to {addr}");
        endpoint.rebind(socket).expect("rebind failed");
    }

    send.write_all(request.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to send request: {}", e))?;
    send.finish().unwrap();
    let response_start = Instant::now();
    eprintln!("request sent at {:?}", response_start - start);
    let resp = recv
        .read_to_end(usize::MAX)
        .await
        .map_err(|e| anyhow!("failed to read response: {}", e))?;
    let duration = response_start.elapsed();
    eprintln!(
        "response received in {:?} - {} KiB/s",
        duration,
        resp.len() as f32 / (duration_secs(&duration) * 1024.0)
    );
    io::stdout().write_all(&resp).unwrap();
    io::stdout().flush().unwrap();
    eprintln!("staying connected for {}s", LINGER.as_secs());
    tokio::time::sleep(LINGER).await;
    conn.close(0u32.into(), b"done");

    // Give the server a fair chance to receive the close packet
    endpoint.wait_all_draining().await;

    Ok(())
}

/// Opens a second path to `remote`, marks it as backup and keeps it alive from this side only.
///
/// The server is expected to answer the keep-alive pings without keeping the path alive itself.
async fn open_backup_path(conn: &noq::Connection, remote: SocketAddr) -> Result<()> {
    // The server needs a moment to issue connection IDs for the second path.
    let path = loop {
        match conn.open_path(remote, PathStatus::Available).await {
            Ok(path) => break path,
            Err(PathError::RemoteCidsExhausted) => {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
            Err(e) => return Err(anyhow!("failed to open backup path: {}", e)),
        }
    };
    path.set_status(PathStatus::Backup)?;
    eprintln!(
        "backup path {:?} open: keep-alive {}s, idle timeout {}s",
        path.id(),
        KEEP_ALIVE.as_secs(),
        PATH_IDLE_TIMEOUT.as_secs()
    );
    Ok(())
}

fn strip_ipv6_brackets(host: &str) -> &str {
    // An ipv6 url looks like eg https://[::1]:4433/Cargo.toml, wherein the host [::1] is the
    // ipv6 address ::1 wrapped in brackets, per RFC 2732. This strips those.
    if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}
