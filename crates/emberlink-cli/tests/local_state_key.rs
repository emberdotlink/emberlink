//! T2 integration test: `resolve_encryption_key` round-trips via daemon socket.
//!
//! Spawns a `SocketListener` backed by `DaemonStore::open_in_memory()` and
//! `Vault::new([42u8; 32])`, points `EMBER_SOCKET_PATH` at the test socket,
//! then calls `emberlink_cli::local_state_content_key()` (the public shim over
//! `resolve_encryption_key`) and verifies:
//!   - The key has the canonical `xchacha20-key:` prefix (daemon-sourced key).
//!   - A second call returns the same key (idempotent round-trip).
//!   - The `EMBERLINK_KEY` env-var bypass is still honored (both prefix forms).
//!
//! All tests that mutate env vars share an `ENV_LOCK` mutex to prevent races.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::Duration;

use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::socket::SocketListener;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::policy::{
    ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel,
};
use tempfile::TempDir;
use tokio::sync::watch;

/// Mutex serializing tests that mutate `EMBER_SOCKET_PATH` / `EMBERLINK_KEY`.
static ENV_LOCK: Mutex<()> = Mutex::new(());

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

/// Spawn a daemon socket listener on a temp path and return the socket
/// path plus a shutdown handle. The listener uses an in-memory store and
/// a fixed vault key so no real keychain is touched.
fn spawn_listener(tmp: &TempDir, name: &str) -> (PathBuf, watch::Sender<bool>) {
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

    // Wait for the socket file to appear.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn local_state_key_resolves_via_daemon_socket() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, _shutdown) = spawn_listener(&tmp, "local-state-key");

    let _guard = ENV_LOCK.lock().unwrap();
    // Point resolve_encryption_key at the test socket.
    unsafe { std::env::set_var("EMBER_SOCKET_PATH", socket_path.as_os_str()) };
    // Ensure EMBERLINK_KEY is unset so we exercise the daemon path.
    unsafe { std::env::remove_var("EMBERLINK_KEY") };

    let key = emberlink_cli::local_state_content_key()
        .expect("local_state_content_key should succeed via daemon socket");

    unsafe { std::env::remove_var("EMBER_SOCKET_PATH") };

    // Daemon generates keys via core_crypto::generate_content_key("local-state")
    // which produces "xchacha20-key:<64 hex>" = 78 chars total.
    assert!(
        key.starts_with("xchacha20-key:"),
        "expected xchacha20-key: prefix, got: {key}"
    );
    assert_eq!(
        key.len(),
        78,
        "expected 78-char xchacha20-key: key, got len {} for: {key}",
        key.len()
    );
}

#[test]
fn local_state_key_is_idempotent_across_calls() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, _shutdown) = spawn_listener(&tmp, "local-state-key-idem");

    let _guard = ENV_LOCK.lock().unwrap();
    unsafe { std::env::set_var("EMBER_SOCKET_PATH", socket_path.as_os_str()) };
    unsafe { std::env::remove_var("EMBERLINK_KEY") };

    let key1 = emberlink_cli::local_state_content_key()
        .expect("first call should succeed");
    let key2 = emberlink_cli::local_state_content_key()
        .expect("second call should succeed");

    unsafe { std::env::remove_var("EMBER_SOCKET_PATH") };

    assert_eq!(
        key1, key2,
        "daemon must return the same key on repeated calls for the same caller"
    );
}

#[test]
fn emberlink_key_env_var_bypass_honored_for_xchacha20_prefix() {
    // Build a syntactically valid xchacha20-key: key (78 chars total:
    // 14-char prefix + 64 hex digits).
    let hex64 = "a".repeat(64);
    let test_key = format!("xchacha20-key:{hex64}");
    assert_eq!(test_key.len(), 78);

    let _guard = ENV_LOCK.lock().unwrap();
    // EMBERLINK_KEY takes priority — no daemon socket needed.
    unsafe { std::env::remove_var("EMBER_SOCKET_PATH") };
    unsafe { std::env::set_var("EMBERLINK_KEY", &test_key) };

    let key = emberlink_cli::local_state_content_key()
        .expect("EMBERLINK_KEY xchacha20-key: prefix should be accepted");

    unsafe { std::env::remove_var("EMBERLINK_KEY") };

    assert_eq!(key, test_key);
}

#[test]
fn daemon_unavailable_returns_structured_error() {
    let _guard = ENV_LOCK.lock().unwrap();
    // Use a socket path that doesn't exist — daemon is not running.
    unsafe { std::env::set_var("EMBER_SOCKET_PATH", "/tmp/no-such-ember-socket.sock") };
    unsafe { std::env::remove_var("EMBERLINK_KEY") };

    let err = emberlink_cli::local_state_content_key()
        .expect_err("should fail when daemon socket does not exist");

    unsafe { std::env::remove_var("EMBER_SOCKET_PATH") };

    let msg = err.to_string();
    assert!(
        msg.contains("daemon unavailable"),
        "expected 'daemon unavailable' in error, got: {msg}"
    );
    assert!(
        msg.contains("ember daemon start"),
        "expected 'ember daemon start' hint in error, got: {msg}"
    );
}
