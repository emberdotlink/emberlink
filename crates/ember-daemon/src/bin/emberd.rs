//! CLASSIFICATION: PUBLIC
//!
//! `emberd` — trust broker daemon entry point.
//!
//! Thin shim that boots a tokio runtime and runs `DaemonRuntime::run()`. The
//! same code path is reachable via `ember daemon start`; this binary exists
//! so LaunchDaemon (macOS) and systemd (Linux) can exec a single-purpose
//! binary as the dedicated `ember` system uid per ADR 131, rather than
//! routing through the multi-purpose user-facing CLI.
//!
//! Logging: JSON to stderr; LaunchDaemon's `StandardErrorPath` /
//! systemd's journal capture it. RUST_LOG env-filter honored.

use ember_daemon::infra::config::DaemonConfig;
use ember_daemon::infra::runtime::DaemonRuntime;
use std::process;
use tracing_subscriber::EnvFilter;

fn main() {
    // `emberd print-install-manifest [--json]` — emit the authoritative macOS
    // install set for the build/install lanes to consume. Handled before any
    // logging/config setup so it works from a freshly-built binary in `target/`
    // before an install exists. Currently only `--json` is supported.
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("print-install-manifest") => {
            print!(
                "{}",
                ember_daemon::install_manifest::macos_install_set_json()
            );
            println!();
            return;
        }
        #[cfg(target_os = "macos")]
        Some("se-probe") => {
            process::exit(ember_daemon::se_probe::run());
        }
        #[cfg(not(target_os = "macos"))]
        Some("se-probe") => {
            eprintln!("se-probe is macOS-only (requires Secure Enclave)");
            process::exit(1);
        }
        _ => {}
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .json()
        .init();

    ember_daemon::infra::process_hardening::harden_process();

    // META-T3-USER-SOCKET-LEAK-GUARD-B-EMBERD: resolve a real on-disk config.
    // EMBER_CONFIG env override → `~/.ember/config.toml` → loud-fail. No silent
    // `DaemonConfig::default()` fallback — that path was the May-12 25-hour
    // leaked-daemon root cause (silent inheritance of user-home socket binding
    // in contexts where no config existed). Mirrors the post-fix shape in
    // `crates/emberlink-cli/src/bin/ember.rs::load_config`.
    let config_path: std::path::PathBuf = std::env::var_os("EMBER_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(DaemonConfig::default_config_path);

    if !config_path.exists() {
        eprintln!(
            "emberd: no ember config found at {}. Run `ember init` to create one, or set EMBER_CONFIG.",
            config_path.display()
        );
        process::exit(1);
    }

    let config = match DaemonConfig::load(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!(
                "emberd: failed to load config from {}: {e}",
                config_path.display()
            );
            process::exit(1);
        }
    };

    if let Err(e) = config.ensure_dirs() {
        eprintln!("emberd: ensure_dirs failed: {e}");
        process::exit(1);
    }

    // emberd_sandbox_startup_probe (META-DAEMON-SECCOMP-PROFILE-HOST-E-STARTUP-PROBE).
    // Verify the daemon is actually sandboxed before accepting connections.
    // WARN-by-default; EMBER_REQUIRE_SANDBOX=1 turns this into a refuse-to-start.
    if let Err(e) = ember_daemon::infra::runtime::check_sandbox_at_startup() {
        eprintln!("emberd: sandbox-startup-probe refused (strict mode): {e}");
        process::exit(1);
    }

    let runtime = DaemonRuntime::new_with_config_path(config, config_path);

    let rt = tokio::runtime::Runtime::new().expect("emberd: failed to create tokio runtime");
    if let Err(e) = rt.block_on(runtime.run(None)) {
        eprintln!("emberd: daemon run failed: {e}");
        process::exit(1);
    }
}
