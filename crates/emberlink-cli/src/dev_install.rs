//! dev_prod_parity_dev_launchdaemon_plist_landed — Phase 3 ADR 157
//!
//! Renders + installs the dev LaunchDaemon plist. Idempotent: re-render +
//! compare; only bootout/bootstrap if content changed. Advisory file lock at
//! /var/run/ember-dev-install.lock serializes launchctl operations.
//!
//! CLASSIFICATION: PUBLIC

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;

const PLIST_TEMPLATE: &str =
    include_str!("../templates/install/sh.emberlink.daemon.dev.plist.template");
const PLIST_DEST: &str = "/Library/LaunchDaemons/sh.emberlink.daemon.dev.plist";
const LOCK_PATH: &str = "/var/run/ember-dev-install.lock";
const PLIST_LABEL: &str = "sh.emberlink.daemon.dev";

/// Variables required to render the dev LaunchDaemon plist template.
///
/// All three fields are mandatory — the template has no optional substitution
/// sites; a missing value would leave a `{{…}}` token in the rendered plist,
/// which `plutil -lint` would reject.
pub struct DevInstallVars {
    /// Launchd label for this worktree-scoped dev runtime.
    pub label: String,
    /// Absolute path to the dev `emberd` binary, e.g.
    /// `/usr/local/bin/emberd-dev`.
    pub ember_dev_bin: String,
    /// Colon-separated list of trust-root fingerprints, e.g.
    /// `sha256:abc123:sha256:def456`. Injected verbatim as
    /// `EMBER_TRUST_ROOTS`.
    pub trust_roots: String,
    /// Operator home directory baked into the dev LaunchDaemon environment so
    /// the separate-uid daemon resolves dev-owned files under the operator's
    /// tree rather than `_ember_dev`'s directory-service home.
    pub home: String,
    /// Absolute config file path passed through `EMBER_CONFIG`.
    pub config_path: String,
    /// Absolute daemon socket path passed through `EMBER_DAEMON_SOCKET`.
    pub socket_path: String,
    /// Absolute GitHub App env-file path for the dev daemon.
    pub gh_app_env_path: String,
    /// Absolute GitHub App PEM path for the dev daemon.
    pub gh_app_pem_path: String,
    /// Absolute vault directory path for the dev daemon.
    pub vault_dir: String,
    /// Absolute binary manifest path for the dev daemon.
    pub manifest_path: String,
    /// Per-runtime stderr log path.
    pub stderr_path: String,
}

/// Render the plist template by substituting all `{{…}}` placeholders.
///
/// Returns the rendered XML string. Does not write to disk.
pub fn render_plist(vars: &DevInstallVars) -> String {
    PLIST_TEMPLATE
        .replace("{{PLIST_LABEL}}", &vars.label)
        .replace("{{EMBER_DEV_BIN}}", &vars.ember_dev_bin)
        .replace("{{TRUST_ROOTS}}", &vars.trust_roots)
        .replace("{{HOME}}", &vars.home)
        .replace("{{CONFIG_PATH}}", &vars.config_path)
        .replace("{{SOCKET_PATH}}", &vars.socket_path)
        .replace("{{GH_APP_ENV_PATH}}", &vars.gh_app_env_path)
        .replace("{{GH_APP_PEM_PATH}}", &vars.gh_app_pem_path)
        .replace("{{VAULT_DIR}}", &vars.vault_dir)
        .replace("{{MANIFEST_PATH}}", &vars.manifest_path)
        .replace("{{STDERR_PATH}}", &vars.stderr_path)
}

/// Abstraction over launchctl + filesystem writes so tests can inject stubs
/// without executing privileged operations.
///
/// The production implementation ([`RealInstallOps`]) shells out to
/// `launchctl bootout` / `launchctl bootstrap`. Tests supply a
/// `StubInstallOps` that records calls and returns controlled outcomes.
pub trait InstallOps {
    /// Write `content` to `dest`, creating or truncating the file.
    fn write_plist(&self, dest: &str, content: &str) -> io::Result<()>;
    /// Read the current contents of `dest`. Returns `None` if the file does
    /// not exist; propagates other I/O errors.
    fn read_plist(&self, dest: &str) -> io::Result<Option<String>>;
    /// Acquire an advisory lock file at `path`, creating it if absent.
    /// The lock is released when the returned `LockGuard` drops.
    fn acquire_lock(&self, path: &str) -> io::Result<LockGuard>;
    /// Run `launchctl bootout system/<label>`. Ignores exit code 113
    /// (service not loaded) so the call is idempotent.
    fn launchctl_bootout(&self, label: &str) -> io::Result<()>;
    /// Run `launchctl bootstrap system <plist_path>`.
    fn launchctl_bootstrap(&self, plist_path: &str) -> io::Result<()>;
}

/// Advisory lock guard. Drops (closes) the underlying file descriptor on
/// release. The lock file itself is NOT removed on drop — it is an advisory
/// marker, not a counting semaphore.
pub struct LockGuard {
    _file: fs::File,
}

impl LockGuard {
    fn new(file: fs::File) -> Self {
        Self { _file: file }
    }
}

/// Production [`InstallOps`] — real filesystem writes + launchctl calls.
pub struct RealInstallOps;

impl InstallOps for RealInstallOps {
    fn write_plist(&self, dest: &str, content: &str) -> io::Result<()> {
        fs::write(dest, content)
    }

    fn read_plist(&self, dest: &str) -> io::Result<Option<String>> {
        match fs::read_to_string(dest) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn acquire_lock(&self, path: &str) -> io::Result<LockGuard> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(path)?;
        Ok(LockGuard::new(file))
    }

    fn launchctl_bootout(&self, label: &str) -> io::Result<()> {
        let status = Command::new("launchctl")
            .args(["bootout", &format!("system/{label}")])
            .status()?;
        // Exit code 113: service was not loaded — treat as success so
        // bootout is idempotent when the daemon was never started.
        if !status.success() {
            let code = status.code().unwrap_or(-1);
            if code != 113 {
                return Err(io::Error::other(format!("launchctl bootout exited {code}")));
            }
        }
        Ok(())
    }

    fn launchctl_bootstrap(&self, plist_path: &str) -> io::Result<()> {
        let status = Command::new("launchctl")
            .args(["bootstrap", "system", plist_path])
            .status()?;
        if !status.success() {
            let code = status.code().unwrap_or(-1);
            return Err(io::Error::other(format!(
                "launchctl bootstrap exited {code}"
            )));
        }
        Ok(())
    }
}

/// Install (or idempotently refresh) the dev LaunchDaemon plist.
///
/// # Algorithm
///
/// 1. Render the plist from `vars`.
/// 2. Acquire the advisory lock at `LOCK_PATH` to serialize concurrent
///    `launchctl` operations.
/// 3. Read the currently-installed plist at `PLIST_DEST` (if any).
/// 4. If content is identical → return `Ok(false)` (no-op).
/// 5. If content differs (or the file is absent) → write the new content,
///    then `bootout` the old service (idempotent), then `bootstrap` the new
///    plist → return `Ok(true)`.
///
/// # Returns
///
/// `Ok(true)` if the plist was written and `launchctl` was restarted.
/// `Ok(false)` if the existing plist was already up to date (no-op).
/// `Err(_)` on any I/O or launchctl failure.
pub fn install_plist(vars: &DevInstallVars) -> io::Result<bool> {
    install_plist_with(vars, &RealInstallOps, PLIST_DEST, LOCK_PATH, PLIST_LABEL)
}

/// Testable variant of [`install_plist`] — caller supplies the operations
/// adapter, destination path, lock path, and label. Tests inject a
/// `StubInstallOps` and direct writes to a temp directory.
pub fn install_plist_with(
    vars: &DevInstallVars,
    ops: &dyn InstallOps,
    dest: &str,
    lock_path: &str,
    label: &str,
) -> io::Result<bool> {
    let rendered = render_plist(vars);

    let _lock = ops.acquire_lock(lock_path)?;

    let current = ops.read_plist(dest)?;
    if current.as_deref() == Some(rendered.as_str()) {
        return Ok(false);
    }

    ops.write_plist(dest, &rendered)?;
    ops.launchctl_bootout(label)?;
    ops.launchctl_bootstrap(dest)?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn test_vars() -> DevInstallVars {
        DevInstallVars {
            label: "sh.emberlink.daemon.dev.worktree-a-123456789abc".to_string(),
            ember_dev_bin: "/home/test-operator/.ember-dev/envs/worktree-a-123456789abc/binaries/emberd".to_string(),
            trust_roots: "sha256:abc123def456".to_string(),
            home: "/home/test-operator".to_string(),
            config_path: "/home/test-operator/.ember-dev/envs/worktree-a-123456789abc/config.toml".to_string(),
            socket_path: "/home/test-operator/.ember-dev/envs/worktree-a-123456789abc/run/daemon.sock".to_string(),
            gh_app_env_path: "/home/test-operator/.config/emberlink-dev/github.env".to_string(),
            gh_app_pem_path: "/home/test-operator/.config/emberlink-dev/github-app.pem"
                .to_string(),
            vault_dir: "/home/test-operator/.ember-dev/envs/worktree-a-123456789abc/vault"
                .to_string(),
            manifest_path:
                "/home/test-operator/.ember-dev/envs/worktree-a-123456789abc/binaries/manifest.toml"
                    .to_string(),
            stderr_path: "/var/log/emberd.dev.worktree-a-123456789abc.err".to_string(),
        }
    }

    // --- render_plist tests ---

    #[test]
    fn render_substitutes_all_placeholders() {
        let vars = test_vars();
        let rendered = render_plist(&vars);

        assert!(
            !rendered.contains("{{EMBER_DEV_BIN}}"),
            "EMBER_DEV_BIN placeholder not substituted"
        );
        assert!(
            !rendered.contains("{{TRUST_ROOTS}}"),
            "TRUST_ROOTS placeholder not substituted"
        );
        assert!(
            !rendered.contains("{{HOME}}"),
            "HOME placeholder not substituted"
        );
    }

    #[test]
    fn render_inserts_correct_values() {
        let vars = test_vars();
        let rendered = render_plist(&vars);

        assert!(
            rendered.contains(
                "/home/test-operator/.ember-dev/envs/worktree-a-123456789abc/binaries/emberd"
            ),
            "binary path missing from rendered plist"
        );
        assert!(
            rendered.contains("sha256:abc123def456"),
            "trust roots missing from rendered plist"
        );
        assert!(
            rendered.contains("/home/test-operator/.ember-dev/envs/worktree-a-123456789abc/vault"),
            "HOME-derived vault path missing from rendered plist"
        );
        assert!(
            rendered.contains(
                "/home/test-operator/.ember-dev/envs/worktree-a-123456789abc/run/daemon.sock"
            ),
            "explicit socket path missing from rendered plist"
        );
        assert!(
            rendered.contains(
                "/home/test-operator/.ember-dev/envs/worktree-a-123456789abc/config.toml"
            ),
            "explicit config path missing from rendered plist"
        );
        assert!(
            rendered.contains("/home/test-operator/.config/emberlink-dev/github.env"),
            "explicit GitHub env path missing from rendered plist"
        );
        assert!(
            rendered.contains("/home/test-operator/.config/emberlink-dev/github-app.pem"),
            "explicit GitHub PEM path missing from rendered plist"
        );
    }

    #[test]
    fn render_inserts_dynamic_label() {
        let vars = test_vars();
        let rendered = render_plist(&vars);
        assert!(
            rendered.contains("sh.emberlink.daemon.dev.worktree-a-123456789abc"),
            "plist label missing from rendered output"
        );
    }

    #[test]
    fn render_preserves_static_fields() {
        let vars = test_vars();
        let rendered = render_plist(&vars);
        // UserName / GroupName
        assert!(rendered.contains("_ember_dev"), "system user missing");
        // EMBER_DAEMON_FLAVOR
        assert!(rendered.contains("<string>dev</string>"), "flavor missing");
        // StandardErrorPath
        assert!(
            rendered.contains("/var/log/emberd.dev.worktree-a-123456789abc.err"),
            "stderr log path missing"
        );
        // KeepAlive
        assert!(rendered.contains("<true/>"), "KeepAlive missing");
        // ADR 197 §security-req-5: restart-cadence throttle.
        assert!(
            rendered.contains("<key>ThrottleInterval</key>"),
            "ThrottleInterval missing"
        );
    }

    // --- install_plist idempotency tests ---

    /// Stub [`InstallOps`] that records calls and drives content from an
    /// in-memory map. No real filesystem or launchctl calls are made.
    struct StubInstallOps {
        stored: RefCell<Option<String>>,
        calls: RefCell<Vec<String>>,
        lock_fails: bool,
        write_fails: bool,
        bootout_fails: bool,
        bootstrap_fails: bool,
    }

    impl StubInstallOps {
        fn new() -> Self {
            Self {
                stored: RefCell::new(None),
                calls: RefCell::new(Vec::new()),
                lock_fails: false,
                write_fails: false,
                bootout_fails: false,
                bootstrap_fails: false,
            }
        }

        fn with_existing(content: &str) -> Self {
            let s = Self::new();
            *s.stored.borrow_mut() = Some(content.to_string());
            s
        }

        fn recorded_calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl InstallOps for StubInstallOps {
        fn write_plist(&self, _dest: &str, content: &str) -> io::Result<()> {
            if self.write_fails {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "write denied",
                ));
            }
            self.calls.borrow_mut().push("write_plist".to_string());
            *self.stored.borrow_mut() = Some(content.to_string());
            Ok(())
        }

        fn read_plist(&self, _dest: &str) -> io::Result<Option<String>> {
            Ok(self.stored.borrow().clone())
        }

        fn acquire_lock(&self, _path: &str) -> io::Result<LockGuard> {
            if self.lock_fails {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "lock denied",
                ));
            }
            self.calls.borrow_mut().push("acquire_lock".to_string());
            // Create a real throwaway file for the guard.
            let dir = tempfile::tempdir().unwrap();
            let f = fs::File::create(dir.path().join("lock")).unwrap();
            Ok(LockGuard::new(f))
        }

        fn launchctl_bootout(&self, label: &str) -> io::Result<()> {
            if self.bootout_fails {
                return Err(io::Error::other("bootout failed"));
            }
            self.calls
                .borrow_mut()
                .push(format!("launchctl_bootout:{label}"));
            Ok(())
        }

        fn launchctl_bootstrap(&self, plist_path: &str) -> io::Result<()> {
            if self.bootstrap_fails {
                return Err(io::Error::other("bootstrap failed"));
            }
            self.calls
                .borrow_mut()
                .push(format!("launchctl_bootstrap:{plist_path}"));
            Ok(())
        }
    }

    #[test]
    fn idempotent_no_op_when_content_unchanged() {
        let vars = test_vars();
        let rendered = render_plist(&vars);
        let ops = StubInstallOps::with_existing(&rendered);

        let changed = install_plist_with(
            &vars,
            &ops,
            "/fake/dest",
            "/fake/lock",
            "sh.emberlink.daemon.dev",
        )
        .expect("install_plist_with should succeed");

        assert!(
            !changed,
            "should be a no-op when content is already current"
        );
        // launchctl must NOT have been called
        let calls = ops.recorded_calls();
        assert!(
            !calls.iter().any(|c| c.starts_with("launchctl_bootout")),
            "bootout must not fire on no-op: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c.starts_with("launchctl_bootstrap")),
            "bootstrap must not fire on no-op: {calls:?}"
        );
    }

    #[test]
    fn installs_when_plist_absent() {
        let vars = test_vars();
        let ops = StubInstallOps::new(); // no existing plist

        let changed = install_plist_with(
            &vars,
            &ops,
            "/fake/dest",
            "/fake/lock",
            "sh.emberlink.daemon.dev",
        )
        .expect("install_plist_with should succeed");

        assert!(changed, "should return true when plist is newly installed");
        let calls = ops.recorded_calls();
        assert!(
            calls.iter().any(|c| c == "write_plist"),
            "write_plist must fire: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c.starts_with("launchctl_bootout")),
            "bootout must fire: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c.starts_with("launchctl_bootstrap")),
            "bootstrap must fire: {calls:?}"
        );
    }

    #[test]
    fn restarts_when_content_changed() {
        let vars = test_vars();
        let ops = StubInstallOps::with_existing("stale plist content");

        let changed = install_plist_with(
            &vars,
            &ops,
            "/fake/dest",
            "/fake/lock",
            "sh.emberlink.daemon.dev",
        )
        .expect("install_plist_with should succeed");

        assert!(changed, "should return true when content changed");
        let calls = ops.recorded_calls();
        assert!(
            calls.iter().any(|c| c == "write_plist"),
            "write_plist must fire on change: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c.starts_with("launchctl_bootout")),
            "bootout must fire on change: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c.starts_with("launchctl_bootstrap")),
            "bootstrap must fire on change: {calls:?}"
        );
    }

    #[test]
    fn propagates_lock_failure() {
        let vars = test_vars();
        let mut ops = StubInstallOps::new();
        ops.lock_fails = true;

        let result = install_plist_with(
            &vars,
            &ops,
            "/fake/dest",
            "/fake/lock",
            "sh.emberlink.daemon.dev",
        );
        assert!(result.is_err(), "should propagate lock failure");
    }

    #[test]
    fn propagates_bootout_failure() {
        let vars = test_vars();
        let mut ops = StubInstallOps::new();
        ops.bootout_fails = true;

        let result = install_plist_with(
            &vars,
            &ops,
            "/fake/dest",
            "/fake/lock",
            "sh.emberlink.daemon.dev",
        );
        assert!(result.is_err(), "should propagate bootout failure");
    }

    #[test]
    fn propagates_bootstrap_failure() {
        let vars = test_vars();
        let mut ops = StubInstallOps::new();
        ops.bootstrap_fails = true;

        let result = install_plist_with(
            &vars,
            &ops,
            "/fake/dest",
            "/fake/lock",
            "sh.emberlink.daemon.dev",
        );
        assert!(result.is_err(), "should propagate bootstrap failure");
    }
}
