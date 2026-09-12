//! This example demonstrates an HTTP client that requests files from a server.
//!
//! Checkout the `README.md` for guidance.

use std::{
    fs,
    io::{self, Write},
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use clap::Parser;
use noq::{PathId, PathStatus};
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

/// Idle timeout of the extra path, set on that path alone.
const PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to stay connected after the response, to watch the abandoned path.
const LINGER: Duration = Duration::from_secs(30);

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
        .max_concurrent_multipath_paths(2);
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
    // Kept alive for the whole run: the path points at this socket.
    let (unreachable_path, _black_hole) = open_unreachable_path(&conn).await?;

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
    eprintln!(
        "path {:?} after {}s: {}",
        unreachable_path,
        LINGER.as_secs(),
        match conn.path(unreachable_path) {
            Some(path) => format!("still here, path_status() = {:?}", path.status()),
            None => "gone".to_owned(),
        }
    );
    conn.close(0u32.into(), b"done");

    // Give the server a fair chance to receive the close packet
    endpoint.wait_all_draining().await;

    Ok(())
}

/// Opens a second path to an address that never answers, and gives that path an idle timeout.
///
/// Nothing ever reads from the returned socket, so the path never validates and the server never
/// learns that it exists. The idle timeout is set on this path alone, so it is the only path that
/// can time out, and nothing in this example closes it.
async fn open_unreachable_path(conn: &noq::Connection) -> Result<(PathId, UdpSocket)> {
    let black_hole = UdpSocket::bind("127.0.0.1:0")?;
    let black_hole_addr = black_hole.local_addr()?;

    // The server needs a moment to issue connection IDs for the second path.
    let path_id = loop {
        let open = conn.open_path(black_hole_addr, PathStatus::Available);
        // Not awaited: the address never answers, so the path never finishes opening.
        if let Some(path_id) = open.path_id() {
            break path_id;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    conn.path(path_id)
        .ok_or_else(|| anyhow!("path {path_id:?} vanished"))?
        .set_max_idle_timeout(Some(PATH_IDLE_TIMEOUT))?;
    eprintln!(
        "path {:?} open to {}, which never answers: idle timeout {}s, nothing here closes it",
        path_id,
        black_hole_addr,
        PATH_IDLE_TIMEOUT.as_secs()
    );
    Ok((path_id, black_hole))
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
