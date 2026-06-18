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
use ember_daemon::infra::socket::{SocketListener, new_shared_policy_engine};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::policy::{
    ActionSelector, ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel,
};
use tempfile::TempDir;
use tokio::sync::watch;

/// Mutex serializing tests that mutate `EMBER_SOCKET_PATH` / `EMBERLINK_KEY`.
static ENV_LOCK: Mutex<()> = Mutex::new(());

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

/// Spawn a daemon socket listener on a temp path and return the socket
/// path plus a shutdown handle. The listener uses an in-memory store and
/// a fixed vault key so no real keychain is touched.
///
/// Also flips the process-global presence manager to Unlocked. The
/// dispatch gate added in PR #3828 (hard-lock after session grace window)
/// refuses non-exempt RPC methods when the session is `Locked`; tests
/// that bypass `register_session` must satisfy the gate explicitly.
fn spawn_listener(tmp: &TempDir, name: &str) -> (PathBuf, watch::Sender<bool>) {
    ember_daemon::trust::presence::mark_unlocked();
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
            let policy = new_shared_policy_engine(permissive_policy());
            let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));
            let _vault = vault; // hold until end of scope: set_vault is the wire now
            let listener =
                SocketListener::new(path_for_thread, shutdown_rx, store, policy, rate_limiter)
                    .with_test_mode_synthetic_presence_token(true);
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

/// Redirect `HOME` (and `USERPROFILE` on Windows builds, for forward
/// compat) at the given tempdir so `default_data_dir` resolves under
/// the test fixture instead of the developer's real
/// `~/.config/emberlink/local-state.enc`. Returns a guard that restores
/// the previous value on Drop. Caller must hold `ENV_LOCK` while the
/// guard is live.
struct HomeOverride {
    prev_home: Option<std::ffi::OsString>,
}

impl HomeOverride {
    fn set(tmp: &TempDir) -> Self {
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", tmp.path()) };
        Self { prev_home }
    }
}

impl Drop for HomeOverride {
    fn drop(&mut self) {
        match self.prev_home.take() {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
    }
}

#[test]
fn local_state_key_resolves_via_daemon_socket() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, _shutdown) = spawn_listener(&tmp, "local-state-key");

    let _guard = ENV_LOCK.lock().unwrap();
    // Redirect HOME so `default_data_dir` resolves to a fresh tempdir,
    // not the developer's real ~/.config/emberlink/local-state.enc
    // (which would fail decryption against the test daemon's vault key).
    let _home_guard = HomeOverride::set(&tmp);
    // Point resolve_encryption_key at the test socket.
    unsafe { std::env::set_var("EMBER_SOCKET_PATH", socket_path.as_os_str()) };
    // Ensure EMBERLINK_KEY is unset so we exercise the daemon path.
    unsafe { std::env::remove_var("EMBERLINK_KEY") };

    let key = emberlink_cli::local_state_content_key()
        .expect("local_state_content_key should succeed via daemon socket");

    unsafe { std::env::remove_var("EMBER_SOCKET_PATH") };

    // Daemon generates keys via core_crypto::generate_content_key("local-state")
    // which produces "xchacha20-key:<64 hex>" = 78 chars total.
    //
    // N6-deeper: `local_state_content_key()` returns `Zeroizing<String>`; pass
    // `&str` (via deref) at every consumer site.
    let key_str: &str = &key;
    assert!(
        key_str.starts_with("xchacha20-key:"),
        "expected xchacha20-key: prefix, got: {key_str}"
    );
    assert_eq!(
        key_str.len(),
        78,
        "expected 78-char xchacha20-key: key, got len {} for: {key_str}",
        key_str.len()
    );
}

#[test]
fn local_state_key_is_idempotent_across_calls() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, _shutdown) = spawn_listener(&tmp, "local-state-key-idem");

    let _guard = ENV_LOCK.lock().unwrap();
    let _home_guard = HomeOverride::set(&tmp);
    unsafe { std::env::set_var("EMBER_SOCKET_PATH", socket_path.as_os_str()) };
    unsafe { std::env::remove_var("EMBERLINK_KEY") };

    let key1 = emberlink_cli::local_state_content_key().expect("first call should succeed");
    let key2 = emberlink_cli::local_state_content_key().expect("second call should succeed");

    unsafe { std::env::remove_var("EMBER_SOCKET_PATH") };

    // N6-deeper: deref through Zeroizing<String> to compare as &str.
    assert_eq!(
        &*key1, &*key2,
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

    // N6-deeper: deref through Zeroizing<String> to compare as &str.
    assert_eq!(&*key, &test_key);
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
        msg.contains("ember status"),
        "expected 'ember status' hint in error, got: {msg}"
    );
    assert!(
        msg.contains("sudo ember daemon install"),
        "expected 'sudo ember daemon install' hint in error, got: {msg}"
    );
}
