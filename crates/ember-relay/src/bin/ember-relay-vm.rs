//! CLASSIFICATION: PUBLIC
//!
//! `ember-relay-vm` — Linux-VM side of the yolo VM bridge.
//!
//! Listens on AF_UNIX (where worker-container agents connect), dials the host
//! relay over TLS+TCP, writes a single HELLO frame, then forwards bytes
//! bidirectionally.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use ember_relay::{DRAIN_TIMEOUT, copy_bidirectional, handshake::Hello, mtls, write_hello};
use rustls::pki_types::ServerName;
use tokio::net::{TcpStream, UnixListener};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(name = "ember-relay-vm", version)]
struct Args {
    /// AF_UNIX path to LISTEN on. Worker-container agents connect here.
    #[arg(long)]
    uds_listen: PathBuf,

    /// TCP target (e.g. `host.docker.internal:8765`). The host-side relay
    /// listens on the other end.
    #[arg(long)]
    tcp_target: String,

    /// Client certificate PEM (presented to the host relay's mTLS verifier).
    #[arg(long)]
    cert: PathBuf,

    /// Client private key PEM.
    #[arg(long)]
    key: PathBuf,

    /// CA bundle PEM used to verify the host relay's server cert.
    #[arg(long)]
    ca: PathBuf,

    /// Persona id this VM claims to be acting on behalf of. Embedded in the
    /// HELLO frame. The daemon enforces grants — the claim is *not* authority.
    #[arg(long)]
    claimed_persona: String,

    /// Optional server-name override for SNI / hostname verification. Defaults
    /// to the host portion of `--tcp-target` (or `localhost` if the target is
    /// IP-only).
    #[arg(long)]
    server_name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    let client_config = mtls::client_config_from_files(&args.cert, &args.key, &args.ca)
        .context("build client TLS config")?;
    let connector = TlsConnector::from(Arc::new(client_config));

    // Set up the AF_UNIX listener. Unlink first if a stale socket sits there.
    if args.uds_listen.exists()
        && let Err(e) = std::fs::remove_file(&args.uds_listen)
    {
        warn!(path = %args.uds_listen.display(), error = %e, "could not unlink stale socket; bind will fail");
    }
    let listener = UnixListener::bind(&args.uds_listen)
        .with_context(|| format!("bind uds listener at {}", args.uds_listen.display()))?;
    set_socket_perms(&args.uds_listen);
    info!(path = %args.uds_listen.display(), target = %args.tcp_target, "ember-relay-vm listening");

    let shutdown = Arc::new(Notify::new());
    spawn_shutdown_watcher(shutdown.clone());

    let mut sessions: JoinSet<()> = JoinSet::new();
    let mut session_id: u64 = 0;

    let server_name_str = args
        .server_name
        .clone()
        .unwrap_or_else(|| derive_server_name(&args.tcp_target));

    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("ember-relay-vm received shutdown; draining");
                break;
            }
            accept_result = listener.accept() => {
                let (uds, _peer) = match accept_result {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "accept failed");
                        continue;
                    }
                };
                session_id = session_id.wrapping_add(1);
                let sid = session_id;
                let connector = connector.clone();
                let tcp_target = args.tcp_target.clone();
                let server_name_str = server_name_str.clone();
                let hello = Hello::new(args.claimed_persona.clone());
                sessions.spawn(async move {
                    if let Err(e) = handle_uds_session(sid, uds, connector, &tcp_target, &server_name_str, hello).await {
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

async fn handle_uds_session(
    sid: u64,
    mut uds: tokio::net::UnixStream,
    connector: TlsConnector,
    tcp_target: &str,
    server_name_str: &str,
    hello: Hello,
) -> Result<()> {
    info!(sid, "uds accept");
    let tcp = TcpStream::connect(tcp_target)
        .await
        .with_context(|| format!("dial tcp {tcp_target}"))?;
    let server_name =
        ServerName::try_from(server_name_str.to_string()).context("invalid server name for SNI")?;
    let mut tls = match connector.connect(server_name, tcp).await {
        Ok(t) => t,
        Err(e) => {
            warn!(sid, error = %e, "tls-handshake-failure");
            return Err(e.into());
        }
    };
    info!(sid, "tls-handshake-ok");
    write_hello(&mut tls, &hello).await.context("write hello")?;

    match copy_bidirectional(&mut uds, &mut tls).await {
        Ok((a_b, b_a)) => {
            info!(sid, uds_to_tcp = a_b, tcp_to_uds = b_a, "session bytes");
            Ok(())
        }
        Err(e) => {
            warn!(sid, error = %e, "copy_bidirectional ended");
            Err(e.into())
        }
    }
}

fn set_socket_perms(path: &std::path::Path) {
    // Mode 0660. Group `ember` is best-effort — chown to a missing group is a
    // warn, not a fatal.
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)) {
        warn!(path = %path.display(), error = %e, "could not set 0660 on socket");
    }
    // chown group is best-effort and platform-specific; not implemented here
    // to avoid pulling in nix or unsafe libc binding for a soft requirement.
    // Operator scripts should chown the parent directory or pre-create the
    // socket directory with the right group.
}

fn derive_server_name(tcp_target: &str) -> String {
    if let Some(host) = tcp_target.rsplit_once(':').map(|(h, _)| h.trim())
        && !host.is_empty()
    {
        return host.to_string();
    }
    "localhost".to_string()
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
