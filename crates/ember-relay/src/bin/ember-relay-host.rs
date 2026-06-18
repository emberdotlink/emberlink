//! CLASSIFICATION: PUBLIC
//!
//! `ember-relay-host` — macOS-host side of the yolo VM bridge.
//!
//! Listens on a loopback TCP port with mTLS, accepts a connection from the
//! VM-side relay, then dials AF_UNIX to the local emberd socket and forwards
//! bytes bidirectionally.
//!
//! Architecturally the host relay sits inside the daemon's trust surface but
//! runs as a separate process so the daemon never has to bind a TCP listener.
//! All non-loopback exposure decisions live in the launchd plist; this binary
//! binds whatever address the operator passes via `--tcp-listen`.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use ember_relay::{DRAIN_TIMEOUT, copy_bidirectional, mtls};
use tokio::net::{TcpListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(name = "ember-relay-host", version)]
struct Args {
    /// TCP address to listen on (e.g. `127.0.0.1:8765`). The VM-side relay
    /// dials this address over TLS.
    #[arg(long)]
    tcp_listen: String,

    /// AF_UNIX path the relay DIALS for each forwarded connection — the
    /// daemon's own listener (e.g. `~/.ember/run/daemon.sock`).
    #[arg(long)]
    uds_target: PathBuf,

    /// Server certificate PEM (presented during TLS handshake).
    #[arg(long)]
    cert: PathBuf,

    /// Server private key PEM (PKCS#8 or SEC1).
    #[arg(long)]
    key: PathBuf,

    /// CA bundle PEM used to verify the client (VM) cert.
    #[arg(long)]
    ca: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    let server_config = mtls::server_config_from_files(&args.cert, &args.key, &args.ca)
        .context("build server TLS config")?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind(&args.tcp_listen)
        .await
        .with_context(|| format!("bind tcp listener on {}", args.tcp_listen))?;
    let local = listener.local_addr().context("local addr")?;
    info!(addr = %local, uds_target = %args.uds_target.display(), "ember-relay-host listening");

    let shutdown = Arc::new(Notify::new());
    spawn_shutdown_watcher(shutdown.clone());

    let mut sessions: JoinSet<()> = JoinSet::new();
    let mut session_id: u64 = 0;

    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("ember-relay-host received shutdown; draining");
                break;
            }
            accept_result = listener.accept() => {
                let (tcp, peer) = match accept_result {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "accept failed");
                        continue;
                    }
                };
                session_id = session_id.wrapping_add(1);
                let sid = session_id;
                let acceptor = acceptor.clone();
                let uds_target = args.uds_target.clone();
                sessions.spawn(async move {
                    if let Err(e) = handle_tcp_session(sid, peer, tcp, acceptor, &uds_target).await {
                        warn!(sid, error = %e, "session ended with error");
                    } else {
                        info!(sid, "session ended");
                    }
                });
            }
            Some(_joined) = sessions.join_next(), if !sessions.is_empty() => {
                // Reap completed sessions so the JoinSet doesn't grow unbounded.
            }
        }
    }

    let drain = tokio::time::timeout(DRAIN_TIMEOUT, async {
        while sessions.join_next().await.is_some() {}
    })
    .await;
    if drain.is_err() {
        warn!("drain timed out — exiting with sessions still in flight");
    }

    Ok(())
}

async fn handle_tcp_session(
    sid: u64,
    peer: std::net::SocketAddr,
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    uds_target: &std::path::Path,
) -> Result<()> {
    info!(sid, %peer, "tcp accept");
    let tls = match acceptor.accept(tcp).await {
        Ok(t) => t,
        Err(e) => {
            warn!(sid, %peer, error = %e, "tls-handshake-failure");
            return Err(e.into());
        }
    };
    info!(sid, %peer, "tls-handshake-ok");

    let uds = UnixStream::connect(uds_target)
        .await
        .with_context(|| format!("dial uds {}", uds_target.display()))?;

    let mut tls = tls;
    let mut uds = uds;
    match copy_bidirectional(&mut tls, &mut uds).await {
        Ok((a_b, b_a)) => {
            info!(sid, tcp_to_uds = a_b, uds_to_tcp = b_a, "session bytes");
            Ok(())
        }
        Err(e) => {
            warn!(sid, error = %e, "copy_bidirectional ended");
            Err(e.into())
        }
    }
}

fn spawn_shutdown_watcher(notify: Arc<Notify>) {
    tokio::spawn(async move {
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to install SIGTERM handler");
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to install SIGINT handler");
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => info!("SIGTERM received"),
            _ = sigint.recv() => info!("SIGINT received"),
        }
        notify.notify_waiters();
    });
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
