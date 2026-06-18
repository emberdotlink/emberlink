//! `emberd` per-OS filesystem layout — the daemon-side counterpart to
//! `crates/internal-automation/src/engine/paths.rs::EnginePaths`.
//!
//! The daemon-owned at-rest state, runtime socket, pid file, and config land
//! at **OS system paths**, not under any user's `$HOME`:
//!
//! | OS    | At-rest state                              | Runtime (socket, pid)                              | Config                |
//! |-------|--------------------------------------------|----------------------------------------------------|-----------------------|
//! | macOS | `/Library/Application Support/Emberlink/`  | `/Library/Application Support/Emberlink/run/`      | `<state>/config/`     |
//! | Linux | `/var/lib/ember/`                          | `/run/ember/`                                      | `/etc/ember/`         |
//!
//! The boundary rule (per ADR 218 §"The boundary rule"): **no daemon data
//! under any user's `$HOME`**. The pre-ADR-218 layout that ADR 131 originally
//! shipped (HOME baked into the LaunchDaemon plist; socket at
//! `~/.ember/run/daemon.sock`) is superseded; only the auth model
//! (`SO_PEERCRED` + `ember-clients` group ACL + per-method gate) is
//! preserved verbatim from ADR 131. Only the path the ACL applies to
//! moves.
//!
//! ## Sentinels
//!
//! - `data_dir_split_doctrine_v1` — ADR 218's canon checkpoint; anchors
//!   the contract in this module.
//! - `daemon_paths_system_root_macos` / `daemon_paths_system_root_linux`
//!   — the system root constants below. Grep these to find every site
//!   that should consume them rather than hardcoding the literal.

use std::path::{Path, PathBuf};

/// macOS system root for daemon-owned data per ADR 218. The
/// LaunchDaemon plist installs the daemon under this tree;
/// `chown_ember_data_dirs` chowns it to `ember:ember-clients`;
/// `<root>/run/daemon.sock` is the production socket path.
///
/// Anchor: `daemon_paths_system_root_macos`.
pub const SYSTEM_ROOT_MACOS: &str = "/Library/Application Support/Emberlink";

/// Linux system root for daemon at-rest state per ADR 218. systemd
/// `StateDirectory=ember` resolves to this path; the daemon writes the
/// SQLite event store, sealed vault blobs, sessions, etc. here.
///
/// Anchor: `daemon_paths_system_root_linux`.
pub const SYSTEM_STATE_ROOT_LINUX: &str = "/var/lib/ember";

/// Linux runtime root per ADR 218. systemd `RuntimeDirectory=ember`
/// resolves to this path; the daemon socket and pid file live here.
/// Kernel manages creation/teardown with the correct ownership.
pub const SYSTEM_RUNTIME_ROOT_LINUX: &str = "/run/ember";

/// Linux config root per ADR 218 / FHS. Operator-set daemon
/// configuration (`config.toml`, `policy.toml`) lives here.
pub const SYSTEM_CONFIG_ROOT_LINUX: &str = "/etc/ember";

/// macOS config subdirectory under [`SYSTEM_ROOT_MACOS`].
pub const MACOS_CONFIG_SUBDIR: &str = "config";

/// Runtime subdirectory name (used for the macOS layout where socket
/// and pid live at `<state>/run/`; on Linux runtime has its own root).
pub const RUN_SUBDIR: &str = "run";

/// Production socket filename. Matches the daemon's
/// `socket_dir.join(DAEMON_SOCKET_FILE)` convention.
pub const DAEMON_SOCKET_FILE: &str = "daemon.sock";

/// Production pid filename.
pub const DAEMON_PID_FILE: &str = "emberd.pid";

/// Production primary config filename inside the config root.
pub const DAEMON_CONFIG_FILE: &str = "config.toml";

/// Production policy filename inside the config root.
pub const DAEMON_POLICY_FILE: &str = "policy.toml";

/// Resolved daemon-side filesystem layout. The fields mirror
/// [`crate::infra::config::DaemonConfig`]'s path-bearing fields so
/// `DaemonConfig::load_defaults` can map directly onto them in the
/// follow-on PR that wires this module into the config loader.
///
/// This struct is intentionally OS-symmetric — both macOS and Linux
/// resolvers populate the same six fields. The values themselves differ
/// per the table in this module's doc-comment; the schema does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPaths {
    /// Top-level daemon state root. macOS:
    /// `/Library/Application Support/Emberlink/`. Linux: `/var/lib/ember/`.
    pub state_root: PathBuf,
    /// At-rest data dir (SQLite event store, sealed vault blobs,
    /// sessions, codex-sessions, locks, etc.). On both OSes this maps
    /// to `state_root` directly — the daemon's `data_dir` IS the state
    /// root. (The legacy layout split `<home>/.ember/data/` from
    /// `<home>/.ember/run/`; the system layout collapses the data dir
    /// onto the state root since FHS/Apple-HIG do not need a `data/`
    /// subdir under an already-app-scoped root.)
    pub data_dir: PathBuf,
    /// Runtime dir (socket, pid). macOS:
    /// `/Library/Application Support/Emberlink/run/`. Linux:
    /// `/run/ember/` (managed by systemd `RuntimeDirectory=ember`).
    pub run_dir: PathBuf,
    /// Config dir. macOS: `<state_root>/config/` or `/etc/ember/`.
    /// Linux: `/etc/ember/`. This module's default uses the per-OS
    /// canonical primary location; operators with `/etc/ember/` on
    /// macOS override via `EMBER_CONFIG_DIR`.
    pub config_dir: PathBuf,
    /// Absolute path to the daemon socket
    /// (`run_dir.join(DAEMON_SOCKET_FILE)`).
    pub socket_path: PathBuf,
    /// Absolute path to the pid file
    /// (`run_dir.join(DAEMON_PID_FILE)`).
    pub pid_file: PathBuf,
}

impl DaemonPaths {
    /// Production resolver per ADR 218.
    ///
    /// - macOS: state under [`SYSTEM_ROOT_MACOS`]; runtime under
    ///   `<state_root>/run/`; config under `<state_root>/config/`.
    /// - Linux: state under [`SYSTEM_STATE_ROOT_LINUX`]; runtime under
    ///   [`SYSTEM_RUNTIME_ROOT_LINUX`]; config under
    ///   [`SYSTEM_CONFIG_ROOT_LINUX`].
    ///
    /// On other Unix targets (BSD, illumos) the Linux layout is the
    /// safe FHS default. Non-Unix targets are not supported by the
    /// daemon and will surface a build-time gate at the consumer site.
    pub fn system() -> Self {
        #[cfg(target_os = "macos")]
        {
            let state_root = PathBuf::from(SYSTEM_ROOT_MACOS);
            let run_dir = state_root.join(RUN_SUBDIR);
            let config_dir = state_root.join(MACOS_CONFIG_SUBDIR);
            Self {
                socket_path: run_dir.join(DAEMON_SOCKET_FILE),
                pid_file: run_dir.join(DAEMON_PID_FILE),
                data_dir: state_root.clone(),
                state_root,
                run_dir,
                config_dir,
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let state_root = PathBuf::from(SYSTEM_STATE_ROOT_LINUX);
            let run_dir = PathBuf::from(SYSTEM_RUNTIME_ROOT_LINUX);
            let config_dir = PathBuf::from(SYSTEM_CONFIG_ROOT_LINUX);
            Self {
                socket_path: run_dir.join(DAEMON_SOCKET_FILE),
                pid_file: run_dir.join(DAEMON_PID_FILE),
                data_dir: state_root.clone(),
                state_root,
                run_dir,
                config_dir,
            }
        }
    }

    /// Test-fixture constructor. Maps every path under a single
    /// tempdir root so unit/integration tests can exercise the
    /// daemon's path-handling without touching real system paths.
    /// Schema-equivalent to [`Self::system`] (same six fields populated)
    /// but with all paths under `root`.
    ///
    /// Layout under `root`:
    /// - `state_root` = `root` itself (mirrors `system()` where
    ///   `data_dir` equals `state_root`)
    /// - `data_dir` = `root` (same)
    /// - `run_dir` = `root/run`
    /// - `config_dir` = `root/config`
    /// - `socket_path` = `root/run/daemon.sock`
    /// - `pid_file` = `root/run/emberd.pid`
    pub fn for_test(root: &Path) -> Self {
        let run_dir = root.join(RUN_SUBDIR);
        let config_dir = root.join(MACOS_CONFIG_SUBDIR);
        Self {
            socket_path: run_dir.join(DAEMON_SOCKET_FILE),
            pid_file: run_dir.join(DAEMON_PID_FILE),
            data_dir: root.to_path_buf(),
            state_root: root.to_path_buf(),
            run_dir,
            config_dir,
        }
    }

    /// Absolute config-file path (`config_dir.join(DAEMON_CONFIG_FILE)`).
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join(DAEMON_CONFIG_FILE)
    }

    /// Absolute policy-file path (`config_dir.join(DAEMON_POLICY_FILE)`).
    pub fn policy_file(&self) -> PathBuf {
        self.config_dir.join(DAEMON_POLICY_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn system_paths_land_under_os_conventional_roots() {
        let paths = DaemonPaths::system();
        let state_str = paths.state_root.to_string_lossy().to_string();

        // ADR 218 boundary rule: no daemon data under any user's $HOME.
        assert!(
            !state_str.starts_with("/Users/") && !state_str.starts_with("/home/"),
            "ADR 218 boundary violated: state_root at {state_str} is under a user HOME"
        );
        assert!(
            !state_str.contains("/.ember/"),
            "legacy ~/.ember/ layout leaked into system paths: {state_str}"
        );

        #[cfg(target_os = "macos")]
        {
            assert_eq!(paths.state_root, PathBuf::from(SYSTEM_ROOT_MACOS));
            assert_eq!(
                paths.run_dir,
                PathBuf::from(SYSTEM_ROOT_MACOS).join(RUN_SUBDIR)
            );
            assert_eq!(
                paths.config_dir,
                PathBuf::from(SYSTEM_ROOT_MACOS).join(MACOS_CONFIG_SUBDIR)
            );
        }
        #[cfg(not(target_os = "macos"))]
        {
            assert_eq!(paths.state_root, PathBuf::from(SYSTEM_STATE_ROOT_LINUX));
            assert_eq!(paths.run_dir, PathBuf::from(SYSTEM_RUNTIME_ROOT_LINUX));
            assert_eq!(paths.config_dir, PathBuf::from(SYSTEM_CONFIG_ROOT_LINUX));
        }
    }

    #[test]
    fn socket_and_pid_land_under_run_dir() {
        let paths = DaemonPaths::system();
        assert_eq!(paths.socket_path, paths.run_dir.join(DAEMON_SOCKET_FILE));
        assert_eq!(paths.pid_file, paths.run_dir.join(DAEMON_PID_FILE));
    }

    #[test]
    fn data_dir_equals_state_root_on_both_oses() {
        // ADR 218 collapses the legacy <home>/.ember/data split onto
        // an already-app-scoped state root — the data IS the state root.
        let paths = DaemonPaths::system();
        assert_eq!(paths.data_dir, paths.state_root);
    }

    #[test]
    fn for_test_mounts_full_layout_under_tempdir() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = DaemonPaths::for_test(tmp.path());
        assert_eq!(paths.state_root, tmp.path());
        assert_eq!(paths.data_dir, tmp.path());
        assert_eq!(paths.run_dir, tmp.path().join(RUN_SUBDIR));
        assert_eq!(paths.config_dir, tmp.path().join(MACOS_CONFIG_SUBDIR));
        assert_eq!(
            paths.socket_path,
            tmp.path().join(RUN_SUBDIR).join(DAEMON_SOCKET_FILE)
        );
        assert_eq!(
            paths.pid_file,
            tmp.path().join(RUN_SUBDIR).join(DAEMON_PID_FILE)
        );
    }

    #[test]
    fn config_and_policy_files_resolve_under_config_dir() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = DaemonPaths::for_test(tmp.path());
        assert_eq!(
            paths.config_file(),
            paths.config_dir.join(DAEMON_CONFIG_FILE)
        );
        assert_eq!(
            paths.policy_file(),
            paths.config_dir.join(DAEMON_POLICY_FILE)
        );
    }

    /// Cross-OS schema invariant — both `system()` resolvers must
    /// populate the same field-set with the same internal relationships.
    /// If a future OS branch forgets to set `socket_path`, this test
    /// catches it.
    #[test]
    fn system_schema_is_consistent() {
        let paths = DaemonPaths::system();
        assert!(
            paths.state_root.is_absolute(),
            "state_root must be absolute"
        );
        assert!(paths.run_dir.is_absolute(), "run_dir must be absolute");
        assert!(
            paths.config_dir.is_absolute(),
            "config_dir must be absolute"
        );
        assert!(paths.socket_path.starts_with(&paths.run_dir));
        assert!(paths.pid_file.starts_with(&paths.run_dir));
    }
}
