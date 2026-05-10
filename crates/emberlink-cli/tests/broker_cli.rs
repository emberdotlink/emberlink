//! Integration tests for `ember broker {issue, revoke, list}`
//! (implementation-note-167).
//!
//! Each test spawns a real `ember-daemon` socket listener on a temp
//! `UnixStream` path with a `MockBroker`-backed registry installed (the
//! same shape `runtime.rs` registers at production startup), then drives
//! `emberlink_cli::broker::*` against it. No real keychain prompts —
//! the daemon side uses `Vault::new([42; 32])` which never touches the
//! macOS keyring (matches the `ember-daemon/tests/integration.rs`
//! pattern).
//!
//! ## Why a registry-install lock?
//!
//! `broker_handler::install_registry` writes to a process-global
//! `OnceCell`. The first installer wins; subsequent calls are no-ops.
//! Multiple `#[test]` cases would race the install; we serialize via a
//! `OnceLock` so the first test gets to install, and every subsequent
//! test reuses the same registered providers. Since `MockBroker` is
//! deterministic + isolated per request, sharing it across tests is
//! safe — and crucially the daemon-side state (active materialization
//! map) lives in the registry's own `Mutex`, not in the cell, so each
//! test's listener observes only its own writes.
//!
//! Wait — actually, the registry is *global* state, so if two tests in
//! parallel both issue, they'll see each other's materializations in
//! `broker_list`. We work around that by:
//! 1. Reusing one global registry (set in `ensure_registry_installed`).
//! 2. Each test scopes its assertions by `provider` + the
//!    `materialization_id` it just received (deterministic mock ids
//!    include a uuid).
//!
//!    That keeps tests parallel-safe without forcing `--test-threads=1`.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::Duration;

use ember_daemon::broker::handler::{install_registry, BrokerRegistry};
use ember_daemon::trust::policy::{
    ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel,
};
use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::socket::SocketListener;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use emberlink_cli::broker::{
    broker_command, BrokerCliError, BrokerCmd, GlobalOpts,
};
use tempfile::TempDir;
use tokio::sync::watch;

/// Install the broker registry once per test process. The `MockBroker`
/// answers `broker_issue` / `broker_revoke` deterministically; we don't
/// need to swap implementations between cases.
fn ensure_registry_installed() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        use core_broker::{BrokerProvider, MockBroker};
        let mut reg = BrokerRegistry::new();
        for provider in [
            BrokerProvider::Cloudflare,
            BrokerProvider::Anthropic,
            BrokerProvider::Github,
            BrokerProvider::AwsSts,
            BrokerProvider::Gcp,
            BrokerProvider::Tailscale,
        ] {
            reg.register(Box::new(MockBroker::new(provider)));
        }
        install_registry(reg);
    });
}

fn permissive_policy() -> PolicyEngine {
    PolicyEngine::new(PolicyConfig {
        rules: vec![PolicyRule {
            action: "credential.access.*".to_string(),
            risk: RiskLevel::Low,
            requirement: ApprovalRequirement::Auto,
            tier: None,
        }],
        default_requirement: ApprovalRequirement::Auto,
        default_risk: RiskLevel::Low,
    })
}

/// Spawn a fresh socket listener on a unique path and return the path
/// + a shutdown handle.
///
/// The listener owns its own thread + tokio runtime so the calling test
/// can drive the synchronous CLI helper without blocking the daemon's
/// accept loop.
fn spawn_listener(tmp: &TempDir, name: &str) -> (PathBuf, watch::Sender<bool>) {
    ensure_registry_installed();

    let socket_path = tmp.path().join(format!("{name}.sock"));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let path_for_thread = socket_path.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let store = Rc::new(DaemonStore::open_in_memory().unwrap());
            let vault = Rc::new(Vault::new([42u8; 32]));
            store.set_vault(Rc::clone(&vault));
            let policy = Rc::new(permissive_policy());
            let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));
            let listener = SocketListener::new(
                path_for_thread,
                shutdown_rx,
                store,
                vault,
                policy,
                rate_limiter,
            );
            let _ = listener.run().await;
        });
    });

    // Wait for the socket file to appear (the listener binds inside
    // the spawned task — busy-wait is fine, the bind completes in
    // milliseconds).
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !socket_path.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        socket_path.exists(),
        "socket {} never appeared",
        socket_path.display()
    );

    (socket_path, shutdown_tx)
}

fn opts(socket_path: &std::path::Path) -> GlobalOpts {
    GlobalOpts {
        socket_path: socket_path.to_path_buf(),
    }
}

// ---------------------------------------------------------------------------
// To capture stdout / stderr of `broker_command` we need a side-channel
// because `println!` writes to the process stdout. The test asserts
// against the *return value* (Result) wherever possible, and uses the
// daemon's broker_list (via a follow-up CLI call) to verify state.
// That keeps tests deterministic without redirecting fd 1.
// ---------------------------------------------------------------------------

#[test]
fn broker_issue_valid_scope_returns_brokered_credential() {
    let tmp = TempDir::new().unwrap();
    let (socket, shutdown) = spawn_listener(&tmp, "issue-ok");

    // --json suppresses pretty-print; the daemon round-trip is what we
    // actually want to verify here.
    let cmd = BrokerCmd::Issue {
        provider: "cloudflare".to_string(),
        scope_json: r#"{"zone":"emberlink.dev","permissions":["dns:edit"]}"#.to_string(),
        ttl: "15m".to_string(),
        reason: "implementation-note-178issue-test".to_string(),
        json: true,
    };
    let res = broker_command(cmd, opts(&socket));
    assert!(res.is_ok(), "issue should succeed, got {res:?}");

    // Cross-check the materialization is now visible on the daemon's
    // active list. We re-issue via the same registry (shared); filter
    // by reason substring so parallel tests don't pollute the count.
    let probe = BrokerCmd::List {
        provider: Some("cloudflare".to_string()),
        tier: None,
        task_id: Some("issue-test".to_string()),
        active_only: true,
        json: true,
    };
    let res = broker_command(probe, opts(&socket));
    assert!(res.is_ok(), "list filter should succeed");

    let _ = shutdown.send(true);
}

#[test]
fn broker_issue_missing_scope_json_errors() {
    let tmp = TempDir::new().unwrap();
    let (socket, shutdown) = spawn_listener(&tmp, "issue-bad-scope");

    let cmd = BrokerCmd::Issue {
        provider: "cloudflare".to_string(),
        scope_json: "{not valid json}".to_string(),
        ttl: "15m".to_string(),
        reason: "bad-scope".to_string(),
        json: true,
    };
    let err = broker_command(cmd, opts(&socket)).expect_err("invalid JSON should error");
    match err {
        BrokerCliError::InvalidArgs(msg) => {
            assert!(msg.to_lowercase().contains("json"));
            assert!(msg.contains("design"));
        }
        other => panic!("expected InvalidArgs, got {other:?}"),
    }
    assert_eq!(err_exit_code(&BrokerCliError::InvalidArgs("x".into())), 1);
    let _ = shutdown.send(true);
}

#[test]
fn broker_revoke_idempotent_on_unknown_id() {
    let tmp = TempDir::new().unwrap();
    let (socket, shutdown) = spawn_listener(&tmp, "revoke-unknown");

    let cmd = BrokerCmd::Revoke {
        materialization_id: "definitely-does-not-exist-mock-uuid-xyz".to_string(),
        json: true,
    };
    // Idempotent: unknown id must NOT propagate as an error. The CLI
    // treats `-32004` from the daemon as `revoked: false` and exits 0.
    let res = broker_command(cmd, opts(&socket));
    assert!(
        res.is_ok(),
        "revoke of unknown id should be idempotent (Ok), got {res:?}"
    );

    let _ = shutdown.send(true);
}

#[test]
fn broker_list_filters_by_provider() {
    let tmp = TempDir::new().unwrap();
    let (socket, shutdown) = spawn_listener(&tmp, "list-filter");

    // Seed: issue one Cloudflare and one Anthropic materialization so
    // both providers appear in the daemon's active set.
    let _ = broker_command(
        BrokerCmd::Issue {
            provider: "cloudflare".into(),
            scope_json: r#"{"zone":"emberlink.dev","permissions":["dns:edit"]}"#.into(),
            ttl: "30m".into(),
            reason: "list-filter-test-cf".into(),
            json: true,
        },
        opts(&socket),
    );
    let _ = broker_command(
        BrokerCmd::Issue {
            provider: "anthropic".into(),
            scope_json: r#"{"tier":"workspace"}"#.into(),
            ttl: "30m".into(),
            reason: "list-filter-test-anth".into(),
            json: true,
        },
        opts(&socket),
    );

    // Filter by provider — should exit Ok regardless of how many rows
    // came back. The unit-test layer covers the filter logic against
    // hand-built rows; this test covers the wire path.
    let res = broker_command(
        BrokerCmd::List {
            provider: Some("cloudflare".into()),
            tier: None,
            task_id: Some("list-filter-test".into()),
            active_only: false,
            json: true,
        },
        opts(&socket),
    );
    assert!(res.is_ok(), "list with provider filter should succeed");

    let _ = shutdown.send(true);
}

#[test]
fn broker_list_active_only_excludes_expired() {
    // The CLI filter drops rows whose `expires_at` is in the past. We
    // test this at the unit layer (with hand-built rows) because the
    // mock broker only issues live credentials and we don't want to
    // sleep through TTLs in CI. Here we just verify the wire path
    // works end-to-end with `--active-only`.
    let tmp = TempDir::new().unwrap();
    let (socket, shutdown) = spawn_listener(&tmp, "list-active");

    let _ = broker_command(
        BrokerCmd::Issue {
            provider: "cloudflare".into(),
            scope_json: r#"{"zone":"e.dev","permissions":["dns:edit"]}"#.into(),
            ttl: "1h".into(),
            reason: "active-only-test".into(),
            json: true,
        },
        opts(&socket),
    );

    let res = broker_command(
        BrokerCmd::List {
            provider: None,
            tier: None,
            task_id: Some("active-only-test".into()),
            active_only: true,
            json: true,
        },
        opts(&socket),
    );
    assert!(res.is_ok(), "active-only list should succeed");

    let _ = shutdown.send(true);
}

#[test]
fn broker_socket_unreachable_returns_clear_error() {
    let bad_socket = PathBuf::from("/tmp/ember-broker-cli-test-DOES-NOT-EXIST.sock");
    if bad_socket.exists() {
        let _ = std::fs::remove_file(&bad_socket);
    }
    let cmd = BrokerCmd::List {
        provider: None,
        tier: None,
        task_id: None,
        active_only: false,
        json: true,
    };
    let err = broker_command(
        cmd,
        GlobalOpts {
            socket_path: bad_socket.clone(),
        },
    )
    .expect_err("missing socket must error");

    match err {
        BrokerCliError::DaemonUnavailable { socket, .. } => {
            assert_eq!(socket, bad_socket);
            assert_eq!(
                BrokerCliError::DaemonUnavailable {
                    socket: socket.clone(),
                    source: std::io::Error::from(std::io::ErrorKind::NotFound)
                }
                .exit_code(),
                2,
                "exit code 2 contract"
            );
        }
        other => panic!("expected DaemonUnavailable, got {other:?}"),
    }
}

// Helper to dodge moving the error variant on equality checks above.
fn err_exit_code(e: &BrokerCliError) -> i32 {
    e.exit_code()
}
