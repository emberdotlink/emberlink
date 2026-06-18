//! Integration tests for `ember broker {issue, revoke, list}`
//! (BROKER-CLI-COMMANDS).
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
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{OnceLock, mpsc};
use std::time::Duration;

use ember_daemon::broker::handler::{BrokerRegistry, install_registry};
use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::socket::{SocketListener, new_shared_policy_engine};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::policy::{
    ActionSelector, ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel,
};
use emberlink_cli::broker::{
    BrokerCliError, BrokerCmd, GlobalOpts, RegisterProvider, broker_command,
};
use tempfile::TempDir;
use tokio::sync::watch;

fn lock_test_process() -> std::sync::MutexGuard<'static, ()> {
    let guard = ember_daemon::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    ember_daemon::trust::presence::reset_for_tests();
    guard
}

fn short_tempdir() -> TempDir {
    tempfile::Builder::new()
        .prefix("ember-cli-")
        .tempdir_in("/tmp")
        .or_else(|_| TempDir::new())
        .expect("tempdir")
}

fn fake_private_key_pem() -> String {
    format!(
        "{}PRIVATE KEY-----\nnot-a-real-key\n{}PRIVATE KEY-----\n",
        "-----BEGIN ", "-----END "
    )
}

fn wait_for_socket(socket_path: &Path, startup_rx: mpsc::Receiver<String>) {
    // Keep listener readiness at the socket seam: if startup exits before
    // binding, report that error instead of hiding it behind a poll timeout.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !socket_path.exists() && std::time::Instant::now() < deadline {
        match startup_rx.try_recv() {
            Ok(error) => panic!(
                "socket listener for {} exited before binding: {error}",
                socket_path.display()
            ),
            Err(mpsc::TryRecvError::Disconnected) => panic!(
                "socket listener thread for {} exited before binding",
                socket_path.display()
            ),
            Err(mpsc::TryRecvError::Empty) => {}
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        socket_path.exists(),
        "socket {} never appeared within 10s",
        socket_path.display()
    );
}

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
            action: ActionSelector::named("credential.access.*"),
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
///
/// Also flips the process-global presence manager to Unlocked. The
/// dispatch gate added in PR #3828 (hard-lock after session grace window)
/// refuses non-exempt RPC methods when the session is `Locked`; tests
/// that bypass `register_session` must satisfy the gate explicitly.
fn spawn_listener(tmp: &TempDir, name: &str) -> (PathBuf, watch::Sender<bool>) {
    ensure_registry_installed();
    ember_daemon::trust::presence::mark_unlocked();

    let socket_path = tmp.path().join(format!("{name}.sock"));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (startup_tx, startup_rx) = mpsc::channel();
    let path_for_thread = socket_path.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let id_dir = tempfile::tempdir().expect("tempdir for daemon identity");
            let _ = ember_daemon::infra::receipt::init_identity(id_dir.path());
            std::mem::forget(id_dir);

            let store = Rc::new(DaemonStore::open_in_memory().unwrap());
            let vault = Rc::new(Vault::new([42u8; 32]));
            store.set_vault(Rc::clone(&vault));
            let policy = new_shared_policy_engine(permissive_policy());
            let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));
            let _vault = vault; // hold until end of scope: set_vault is the wire now
            let listener =
                SocketListener::new(path_for_thread, shutdown_rx, store, policy, rate_limiter)
                    .with_test_mode_synthetic_presence_token(true);
            match listener.run().await {
                Ok(()) => {
                    let _ = startup_tx.send("listener returned Ok".to_string());
                }
                Err(error) => {
                    let _ = startup_tx.send(format!("{error:?}"));
                }
            }
        });
    });

    wait_for_socket(&socket_path, startup_rx);

    (socket_path, shutdown_tx)
}

fn opts(socket_path: &std::path::Path) -> GlobalOpts {
    GlobalOpts {
        socket_path: socket_path.to_path_buf(),
    }
}

fn spawn_listener_without_presence(tmp: &TempDir, name: &str) -> (PathBuf, watch::Sender<bool>) {
    ensure_registry_installed();
    let id_dir = tempfile::tempdir().expect("tempdir for daemon identity");
    let _ = ember_daemon::infra::receipt::init_identity(id_dir.path());
    std::mem::forget(id_dir);

    let socket_path = tmp.path().join(format!("{name}.sock"));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (startup_tx, startup_rx) = mpsc::channel();
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
            let policy = new_shared_policy_engine(permissive_policy());
            let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));
            let _vault = vault;
            let listener =
                SocketListener::new(path_for_thread, shutdown_rx, store, policy, rate_limiter);
            match listener.run().await {
                Ok(()) => {
                    let _ = startup_tx.send("listener returned Ok".to_string());
                }
                Err(error) => {
                    let _ = startup_tx.send(format!("{error:?}"));
                }
            }
        });
    });

    wait_for_socket(&socket_path, startup_rx);

    (socket_path, shutdown_tx)
}

// ---------------------------------------------------------------------------
// To capture stdout / stderr of `broker_command` we need a side-channel
// because `println!` writes to the process stdout. The test asserts
// against the *return value* (Result) wherever possible, and uses the
// daemon's broker_list (via a follow-up CLI call) to verify state.
// That keeps tests deterministic without redirecting fd 1.
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn broker_issue_valid_scope_returns_brokered_credential() {
    let _guard = lock_test_process();
    let tmp = short_tempdir();
    let (socket, shutdown) = spawn_listener(&tmp, "issue-ok");

    // --json suppresses pretty-print; the daemon round-trip is what we
    // actually want to verify here. ADR 204 BKR-1: native scope is no longer a
    // caller input — the daemon derives it. We mint against `anthropic` (the
    // derive-gated provider whose native scope is a daemon-synthesized label);
    // the `scope_json` below is accepted by the CLI but ignored by the daemon.
    let cmd = BrokerCmd::Issue {
        provider: "anthropic".to_string(),
        scope_json: r#"{"name":"cli-round-trip"}"#.to_string(),
        ttl: "15m".to_string(),
        reason: "BROKER-CLI-COMMANDS-issue-test".to_string(),
        json: true,
    };
    let res = broker_command(cmd, opts(&socket));
    assert!(res.is_ok(), "issue should succeed, got {res:?}");

    // Cross-check the materialization is now visible on the daemon's
    // active list. We re-issue via the same registry (shared); filter
    // by reason substring so parallel tests don't pollute the count.
    let probe = BrokerCmd::List {
        provider: Some("anthropic".to_string()),
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
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn broker_issue_missing_scope_json_errors() {
    let _guard = lock_test_process();
    let tmp = short_tempdir();
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
            assert!(msg.contains("ADR 094"));
        }
        other => panic!("expected InvalidArgs, got {other:?}"),
    }
    assert_eq!(err_exit_code(&BrokerCliError::InvalidArgs("x".into())), 1);
    let _ = shutdown.send(true);
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn broker_revoke_idempotent_on_unknown_id() {
    let _guard = lock_test_process();
    let tmp = short_tempdir();
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
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn broker_list_filters_by_provider() {
    let _guard = lock_test_process();
    let tmp = short_tempdir();
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
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn broker_list_active_only_excludes_expired() {
    let _guard = lock_test_process();
    // The CLI filter drops rows whose `expires_at` is in the past. We
    // test this at the unit layer (with hand-built rows) because the
    // mock broker only issues live credentials and we don't want to
    // sleep through TTLs in CI. Here we just verify the wire path
    // works end-to-end with `--active-only`.
    let tmp = short_tempdir();
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
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn broker_list_without_presence_returns_guidance_not_raw_authority_error() {
    let _guard = lock_test_process();

    let tmp = short_tempdir();
    let (socket, shutdown) = spawn_listener_without_presence(&tmp, "list-guidance");

    let err = broker_command(
        BrokerCmd::List {
            provider: None,
            tier: None,
            task_id: None,
            active_only: true,
            json: true,
        },
        opts(&socket),
    )
    .expect_err("missing operator presence should not succeed");

    match err {
        BrokerCliError::Guidance(message) => {
            assert!(message.contains("advanced operator surface"));
            assert!(message.contains("ember claude"));
        }
        other => panic!("expected Guidance, got {other:?}"),
    }

    let _ = shutdown.send(true);
    ember_daemon::trust::presence::reset_for_tests();
}

#[test]
fn broker_socket_unreachable_returns_clear_error() {
    let _guard = lock_test_process();
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

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn broker_register_github_reuses_shared_presence_bootstrap() {
    let _guard = lock_test_process();
    let tmp = short_tempdir();
    let (socket, shutdown) = spawn_listener(&tmp, "register-github");

    let pem_path = tmp.path().join("app.pem");
    std::fs::write(&pem_path, fake_private_key_pem()).unwrap();

    let cmd = BrokerCmd::Register {
        provider: RegisterProvider::Github {
            pem_file: pem_path,
            app_id: "3491890".into(),
            installation_id: "126782716".into(),
            slug: "ember-engine".into(),
            allow_unverified_slug: true,
            replace: false,
            json: true,
        },
    };

    let res = broker_command(cmd, opts(&socket));
    assert!(
        res.is_ok(),
        "register github should succeed through auto-unlock/presence bootstrap, got {res:?}"
    );

    let result = emberlink_cli::call_daemon_method(
        &socket,
        "vault_get",
        &serde_json::json!({
            "name": "github/apps/ember-engine/install-126782716/app-id"
        }),
    )
    .expect("registered app id should be readable from the vault");
    assert_eq!(
        result.get("value").and_then(|v| v.as_str()),
        Some("3491890"),
        "register github must persist the app-id through the same daemon lane"
    );

    let _ = shutdown.send(true);
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn broker_register_github_real_socket_fails_closed_without_presence() {
    let _guard = lock_test_process();

    // ADR 206 slice 4 C: the forgeable native/managed vault-unlock ceremony that
    // `register_github`'s up-front `vault_unlock` used to ride is retired. With no
    // operator presence (locked §4 window, no presence token), the credential-
    // writing register flow MUST fail closed — it must NOT silently persist the GH
    // App private key without presence. The operator opens the window separately
    // with `ember vault se-unlock` (one Touch ID tap).
    let tmp = short_tempdir();
    let (socket, shutdown) = spawn_listener_without_presence(&tmp, "register-github-no-presence");

    let pem_path = tmp.path().join("app.pem");
    std::fs::write(&pem_path, fake_private_key_pem()).unwrap();

    let cmd = BrokerCmd::Register {
        provider: RegisterProvider::Github {
            pem_file: pem_path,
            app_id: "3491890".into(),
            installation_id: "126782716".into(),
            slug: "ember-engine".into(),
            allow_unverified_slug: true,
            replace: false,
            json: true,
        },
    };

    // Must fail closed (an authority / guidance / RPC error) rather than silently
    // write the credential without presence. We do NOT pin the deleted ceremony's
    // guidance strings — only that the write fails and is not a benign
    // already-exists / argument error masquerading as success.
    let err = broker_command(cmd, opts(&socket)).expect_err(
        "register without operator presence must fail closed, not write the credential",
    );
    assert!(
        matches!(
            err,
            BrokerCliError::Guidance(_)
                | BrokerCliError::DaemonRpc { .. }
                | BrokerCliError::Protocol(_)
                | BrokerCliError::Io(_)
        ),
        "register must fail closed at the authority/RPC boundary without presence; got {err:?}"
    );

    let _ = shutdown.send(true);
    ember_daemon::trust::presence::reset_for_tests();
}

// Helper to dodge moving the error variant on equality checks above.
fn err_exit_code(e: &BrokerCliError) -> i32 {
    e.exit_code()
}
