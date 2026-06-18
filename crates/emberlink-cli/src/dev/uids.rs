//! ADR 157 Phase 4 steps 3 + 4: macOS uid + group provisioning via dscl.
//!
//! Provisions the `_ember_dev` system user (UID 503) and the
//! `_ember_clients_dev` group (GID 503), then adds the operator to the group.
//! All dscl operations require sudo; this module structures the commands so
//! the operator can review and the CLI can invoke them with a clear argv trace.
//!
//! Uses a `CommandRunner` trait so tests can inject a stub without actually
//! calling dscl.
//!
//! CLASSIFICATION: PUBLIC

use std::process::Command;

/// dscl uid for the dev daemon (`_ember_dev`).
/// Canonical UID 503 (below the 500 reserved system bound is acceptable;
/// 503 is empirically free on most dev workstations).
pub const DEV_DAEMON_UID: u32 = 503;

/// Start of the dscl pool uid range for ember-exec dev (ADR 131).
/// 1024 entries from DEV_EXEC_POOL_UID_START to DEV_EXEC_POOL_UID_END inclusive.
pub const DEV_EXEC_POOL_UID_START: u32 = 1724;

/// End of the dscl pool uid range for ember-exec dev (ADR 131).
pub const DEV_EXEC_POOL_UID_END: u32 = 2747;

/// dscl gid for the dev clients group (`_ember_clients_dev`).
pub const CLIENTS_DEV_GID: u32 = 503;

pub const DEV_DAEMON_USER: &str = "_ember_dev";
pub const CLIENTS_DEV_GROUP: &str = "_ember_clients_dev";

/// Abstraction over `dscl` invocations so tests can inject a stub.
pub trait CommandRunner {
    /// Run a command with the given argv. Returns `Ok(())` on zero exit,
    /// or `Err` on non-zero exit or spawn failure.
    fn run(&self, argv: &[&str]) -> Result<(), String>;

    /// Check whether a dscl record exists by running a `-read` command.
    /// A non-zero exit is interpreted as "does not exist".
    fn exists(&self, argv: &[&str]) -> bool;
}

/// Production runner: shells out to the real binary.
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, argv: &[&str]) -> Result<(), String> {
        if argv.is_empty() {
            return Err("empty argv".to_string());
        }
        let status = Command::new(argv[0])
            .args(&argv[1..])
            .status()
            .map_err(|e| format!("failed to spawn {:?}: {e}", argv[0]))?;
        if !status.success() {
            return Err(format!("{} exited with code {:?}", argv[0], status.code()));
        }
        Ok(())
    }

    fn exists(&self, argv: &[&str]) -> bool {
        if argv.is_empty() {
            return false;
        }
        Command::new(argv[0])
            .args(&argv[1..])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Idempotent: provision the `_ember_dev` system user via dscl.
///
/// If the user already exists (`dscl . -read /Users/_ember_dev` succeeds),
/// returns `Ok(())` immediately. Otherwise runs the required `sudo dscl`
/// sequence.
///
/// Note: exec-pool provisioning (UIDs 1724–2747) is deferred to phase 4b.
pub fn ensure_dev_daemon_user(runner: &dyn CommandRunner) -> Result<(), String> {
    if runner.exists(&["dscl", ".", "-read", "/Users/_ember_dev"]) {
        return Ok(());
    }

    let uid_str = DEV_DAEMON_UID.to_string();

    runner.run(&["sudo", "dscl", ".", "-create", "/Users/_ember_dev"])?;
    runner.run(&[
        "sudo",
        "dscl",
        ".",
        "-create",
        "/Users/_ember_dev",
        "UserShell",
        "/usr/bin/false",
    ])?;
    runner.run(&[
        "sudo",
        "dscl",
        ".",
        "-create",
        "/Users/_ember_dev",
        "RealName",
        "ember-dev daemon",
    ])?;
    runner.run(&[
        "sudo",
        "dscl",
        ".",
        "-create",
        "/Users/_ember_dev",
        "UniqueID",
        &uid_str,
    ])?;
    runner.run(&[
        "sudo",
        "dscl",
        ".",
        "-create",
        "/Users/_ember_dev",
        "PrimaryGroupID",
        &uid_str,
    ])?;
    runner.run(&[
        "sudo",
        "dscl",
        ".",
        "-create",
        "/Users/_ember_dev",
        "NFSHomeDirectory",
        "/var/empty",
    ])?;

    // Exec pool: phase 4b stub.
    eprintln!(
        "  TODO: exec pool provisioning (UIDs {}–{}) is phase 4b",
        DEV_EXEC_POOL_UID_START, DEV_EXEC_POOL_UID_END
    );

    Ok(())
}

/// Idempotent: provision the `_ember_clients_dev` group via dscl and add the
/// operator to it.
///
/// If the group already exists, skip the create step. Either way, appends the
/// operator to the group's membership list (macOS dscl `-append` is idempotent
/// for existing members).
pub fn ensure_clients_dev_group(runner: &dyn CommandRunner) -> Result<(), String> {
    let gid_str = CLIENTS_DEV_GID.to_string();

    if !runner.exists(&["dscl", ".", "-read", "/Groups/_ember_clients_dev"]) {
        runner.run(&["sudo", "dscl", ".", "-create", "/Groups/_ember_clients_dev"])?;
        runner.run(&[
            "sudo",
            "dscl",
            ".",
            "-create",
            "/Groups/_ember_clients_dev",
            "UniqueID",
            &gid_str,
        ])?;
    }

    // Get the operator's username.
    let whoami_out = Command::new("whoami")
        .output()
        .map_err(|e| format!("failed to run whoami: {e}"))?;
    let operator = String::from_utf8_lossy(&whoami_out.stdout)
        .trim()
        .to_string();

    if operator.is_empty() {
        return Err("whoami returned empty username".to_string());
    }

    runner.run(&[
        "sudo",
        "dscl",
        ".",
        "-append",
        "/Groups/_ember_clients_dev",
        "GroupMembership",
        &operator,
    ])?;

    Ok(())
}

/// Production wrappers — call through `RealCommandRunner`.
pub fn ensure_dev_daemon_user_real() -> Result<(), String> {
    ensure_dev_daemon_user(&RealCommandRunner)
}

pub fn ensure_clients_dev_group_real() -> Result<(), String> {
    ensure_clients_dev_group(&RealCommandRunner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Stub runner that records argv slices and returns controlled outcomes.
    struct StubRunner {
        calls: RefCell<Vec<Vec<String>>>,
        existing: Vec<String>,
    }

    impl StubRunner {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                existing: Vec::new(),
            }
        }

        fn with_existing(path: &str) -> Self {
            let mut s = Self::new();
            s.existing.push(path.to_string());
            s
        }

        fn recorded(&self) -> Vec<Vec<String>> {
            self.calls.borrow().clone()
        }
    }

    impl CommandRunner for StubRunner {
        fn run(&self, argv: &[&str]) -> Result<(), String> {
            let call: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
            self.calls.borrow_mut().push(call);
            Ok(())
        }

        fn exists(&self, argv: &[&str]) -> bool {
            argv.get(3)
                .map(|path| self.existing.iter().any(|e| e == *path))
                .unwrap_or(false)
        }
    }

    #[test]
    fn ensure_dev_daemon_user_skips_when_exists() {
        let runner = StubRunner::with_existing("/Users/_ember_dev");
        ensure_dev_daemon_user(&runner).unwrap();
        assert!(
            runner.recorded().is_empty(),
            "no dscl run calls expected when user already exists: {:?}",
            runner.recorded()
        );
    }

    #[test]
    fn ensure_dev_daemon_user_creates_user_with_correct_argv() {
        let runner = StubRunner::new();
        ensure_dev_daemon_user(&runner).unwrap();

        let calls = runner.recorded();
        assert!(
            calls.len() >= 6,
            "expected at least 6 dscl calls: {calls:?}"
        );

        assert_eq!(
            calls[0],
            vec!["sudo", "dscl", ".", "-create", "/Users/_ember_dev"],
            "first call must create user record"
        );

        let has_shell = calls.iter().any(|c| {
            c.contains(&"UserShell".to_string()) && c.contains(&"/usr/bin/false".to_string())
        });
        assert!(has_shell, "must set UserShell /usr/bin/false: {calls:?}");

        let has_uid = calls.iter().any(|c| {
            c.contains(&"UniqueID".to_string()) && c.contains(&DEV_DAEMON_UID.to_string())
        });
        assert!(has_uid, "must set UniqueID {DEV_DAEMON_UID}: {calls:?}");

        let has_gid = calls.iter().any(|c| {
            c.contains(&"PrimaryGroupID".to_string()) && c.contains(&DEV_DAEMON_UID.to_string())
        });
        assert!(has_gid, "must set PrimaryGroupID: {calls:?}");

        let has_home = calls.iter().any(|c| {
            c.contains(&"NFSHomeDirectory".to_string()) && c.contains(&"/var/empty".to_string())
        });
        assert!(has_home, "must set NFSHomeDirectory /var/empty: {calls:?}");
    }

    #[test]
    fn ensure_clients_dev_group_creates_group_when_absent() {
        let runner = StubRunner::new();
        // whoami is a real call; allow the result to succeed or fail based on environment.
        let result = ensure_clients_dev_group(&runner);
        let calls = runner.recorded();

        let created_group = calls.iter().any(|c| {
            c.contains(&"-create".to_string())
                && c.contains(&"/Groups/_ember_clients_dev".to_string())
        });
        assert!(
            created_group,
            "must create _ember_clients_dev group: {calls:?}"
        );

        let has_gid = calls.iter().any(|c| {
            c.contains(&"/Groups/_ember_clients_dev".to_string())
                && c.contains(&"UniqueID".to_string())
                && c.contains(&CLIENTS_DEV_GID.to_string())
        });
        assert!(
            has_gid,
            "must set UniqueID {CLIENTS_DEV_GID} on group: {calls:?}"
        );

        if result.is_ok() {
            let appended = calls.iter().any(|c| {
                c.contains(&"-append".to_string())
                    && c.contains(&"/Groups/_ember_clients_dev".to_string())
                    && c.contains(&"GroupMembership".to_string())
            });
            assert!(appended, "must append operator to group: {calls:?}");
        }
    }

    #[test]
    fn ensure_clients_dev_group_skips_create_when_group_exists() {
        let runner = StubRunner::with_existing("/Groups/_ember_clients_dev");
        let _ = ensure_clients_dev_group(&runner);
        let calls = runner.recorded();

        let created_group = calls.iter().any(|c| {
            c.contains(&"-create".to_string())
                && c.contains(&"/Groups/_ember_clients_dev".to_string())
        });
        assert!(
            !created_group,
            "must NOT create group that already exists: {calls:?}"
        );
    }

    #[test]
    fn uid_and_gid_constants_are_correct() {
        assert_eq!(DEV_DAEMON_UID, 503);
        assert_eq!(CLIENTS_DEV_GID, 503);
        assert_eq!(DEV_EXEC_POOL_UID_START, 1724);
        assert_eq!(DEV_EXEC_POOL_UID_END, 2747);
        assert!(
            DEV_EXEC_POOL_UID_END >= DEV_EXEC_POOL_UID_START,
            "pool end must be >= start"
        );
    }

    #[test]
    fn dev_daemon_user_name_is_ember_dev() {
        assert_eq!(DEV_DAEMON_USER, "_ember_dev");
    }

    #[test]
    fn clients_dev_group_name_is_correct() {
        assert_eq!(CLIENTS_DEV_GROUP, "_ember_clients_dev");
    }
}
