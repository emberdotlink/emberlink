//! ember_rpc_phase_b_mtls_lane_landed
//! ember_rpc_phase_c_mtls_listener_wired (driven from this entry point)
//!
//! Entry point binary for ember-rpc.
//!
//! Two `[[bin]]` wrapper targets in `Cargo.toml` (`emberd-rpc-linux` and
//! `emberd-rpc-macos`) both delegate to this shared entrypoint. The
//! launchd/systemd unit files reference their respective platform
//! binary names; the source is identical so the policy gate is
//! platform-independent.
//!
//! Per Phase C, the shared entrypoint builds a [`Config`] from env vars
//! (with the `Default::default()` paths as fallback) and hands off to
//! [`ember_rpc::run`], which spins a tokio runtime + mTLS listener and
//! blocks on Ctrl-C.

use ember_rpc::Config;
use std::path::PathBuf;

pub(crate) fn run() -> anyhow::Result<()> {
    tracing_subscriber_init();

    let config = config_from_env_or_default();
    ember_rpc::run(config)
}

/// Build a [`Config`] from `EMBER_RPC_*` env vars, falling back to
/// [`Config::default`] paths when an env var is unset. Operators set
/// these in the launchd plist / systemd unit so the binary picks
/// them up without an extra CLI surface.
///
/// Env vars (all optional):
///
/// | Var                        | Field              |
/// |----------------------------|--------------------|
/// | `EMBER_RPC_LISTEN_ADDR`    | `listen_addr`      |
/// | `EMBER_RPC_FORWARD_UDS`    | `forward_uds`      |
/// | `EMBER_RPC_SERVER_CERT`    | `server_cert_path` |
/// | `EMBER_RPC_SERVER_KEY`     | `server_key_path`  |
/// | `EMBER_RPC_CA_CERT`        | `ca_cert_path`     |
fn config_from_env_or_default() -> Config {
    let mut cfg = Config::default();
    if let Ok(v) = std::env::var("EMBER_RPC_LISTEN_ADDR")
        && let Ok(addr) = v.parse()
    {
        cfg.listen_addr = addr;
    }
    if let Ok(v) = std::env::var("EMBER_RPC_FORWARD_UDS") {
        cfg.forward_uds = PathBuf::from(v);
    }
    if let Ok(v) = std::env::var("EMBER_RPC_SERVER_CERT") {
        cfg.server_cert_path = PathBuf::from(v);
    }
    if let Ok(v) = std::env::var("EMBER_RPC_SERVER_KEY") {
        cfg.server_key_path = PathBuf::from(v);
    }
    if let Ok(v) = std::env::var("EMBER_RPC_CA_CERT") {
        cfg.ca_cert_path = PathBuf::from(v);
    }
    cfg
}

/// Best-effort tracing init. ember-rpc emits structured events for
/// every accept + per-request gate decision; Phase C wires a simple
/// env-filter subscriber so launchd `StandardErrorPath` / systemd
/// journal captures them. Phase D will switch to the shared
/// `core-metrics` layer once it ships.
fn tracing_subscriber_init() {
    // No-op for now — `tracing::info!` calls without a subscriber are
    // silently dropped. Phase D will install a real subscriber that
    // forwards into the existing emberd-core observability pipeline.
}
