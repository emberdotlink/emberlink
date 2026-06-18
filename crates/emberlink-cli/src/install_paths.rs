//! Install-path constants for prod and dev daemons.
//!
//! Per ADR 157 §Component 3 (Dev/Prod Parity — Parallel Install Paths):
//! the dev daemon and prod daemon use **disjoint resource names** across every
//! file/socket/uid axis. No global resource is shared between the two flavors
//! except the host's filesystem root.
//!
//! This module is the canonical source-of-truth for those path constants. It
//! is consumed by:
//! - `ember dev install` (META-DEV-PROD-PARITY-EMBER-DEV-INSTALL) — provisions
//!   the dev daemon end-to-end
//! - `ember daemon install` — provisions the prod daemon
//! - `dev_install::install_plist` (META-DEV-PROD-PARITY-DEV-LAUNCHDAEMON-PLIST) —
//!   renders the dev LaunchDaemon plist with these paths
//! - `dev-install.sh` developer-loop script (deprecated in this PR; pointer to
//!   `ember dev install` instead of the old `/usr/local/bin/emberd` symlink)
//!
//! Anchor: `dev_prod_parity_parallel_install_paths_landed`

/// Prod daemon install root. Binary lives at
/// `{PROD_INSTALL_ROOT}/emberd.app/Contents/MacOS/emberd` on macOS.
pub const PROD_INSTALL_ROOT: &str = "/usr/local/lib/ember";

/// Dev daemon install root. Binary lives at
/// `{DEV_INSTALL_ROOT}/emberd.app/Contents/MacOS/emberd` on macOS.
pub const DEV_INSTALL_ROOT: &str = "/usr/local/lib/ember-dev";

/// Prod daemon Unix-domain socket — absolute system path.
/// macOS: `/Library/Application Support/Emberlink/run/daemon.sock`.
/// Linux: `/run/ember/daemon.sock`.
///
/// Delegates to [`ember_daemon::paths::DaemonPaths::system`] so the
/// per-OS system-path map lives in exactly one place; replaces the
/// pre-ADR-218 `~/.ember/run/daemon.sock` relative constant that
/// callers used to join against the operator's `$HOME`.
pub fn prod_daemon_socket_path() -> std::path::PathBuf {
    ember_daemon::paths::DaemonPaths::system().socket_path
}

/// Prod daemon at-rest state root per ADR 218 — same delegation as
/// [`prod_daemon_socket_path`]. Callers that previously did
/// `home.join(".ember").join("data")` get this instead.
pub fn prod_state_root() -> std::path::PathBuf {
    ember_daemon::paths::DaemonPaths::system().state_root
}

/// Dev daemon Unix-domain socket path (relative to operator home).
/// Absolute path is `~/.ember/run/daemon.dev.sock`.
///
/// Note: the dev socket sits under `~/.ember/run/` (same parent dir as prod)
/// to keep per-user discovery simple — only the filename differs.
pub const DEV_DAEMON_SOCKET_REL: &str = ".ember/run/daemon.dev.sock";

/// Prod daemon credentials directory. System-wide; readable only by the
/// daemon uid (`ember`).
pub const PROD_CREDS_DIR: &str = "/etc/emberlink";

/// Dev daemon credentials directory (relative to operator home).
/// Absolute path is `~/.config/emberlink-dev/`.
pub const DEV_CREDS_DIR_REL: &str = ".config/emberlink-dev";

/// Prod manifest path. Holds the signed binary manifest the daemon verifies
/// against on startup. Absolute: `/usr/local/lib/ember/binaries/manifest.toml(.sig)`.
pub const PROD_MANIFEST_PATH: &str = "/usr/local/lib/ember/binaries/manifest.toml";

/// Dev manifest path (relative to operator home).
/// Absolute: `~/.ember-dev/binaries/manifest.toml(.sig)`.
pub const DEV_MANIFEST_PATH_REL: &str = ".ember-dev/binaries/manifest.toml";

/// Prod LaunchDaemon plist label.
pub const PROD_PLIST_LABEL: &str = "sh.emberlink.daemon";

/// Dev LaunchDaemon plist label.
pub const DEV_PLIST_LABEL: &str = "sh.emberlink.daemon.dev";

/// Prod daemon uid (created by the prod installer; system service).
pub const PROD_DAEMON_USER: &str = "_ember";

/// Dev daemon uid (created by the dev installer; per-developer).
pub const DEV_DAEMON_USER: &str = "_ember_dev";

/// Prod daemon clients group (members can connect to the prod socket).
pub const PROD_CLIENTS_GROUP: &str = "_ember_clients";

/// Dev daemon clients group (members can connect to the dev socket).
pub const DEV_CLIENTS_GROUP: &str = "_ember_clients_dev";

/// Checkpoint for `target_state_anchor` — `dev_prod_parity_parallel_install_paths_landed`.
/// The grep gate fires when this string appears in the codebase.
#[doc(hidden)]
pub const SENTINEL_DEV_PROD_PARITY_PARALLEL_INSTALL_PATHS_LANDED: &str =
    "dev_prod_parity_parallel_install_paths_landed";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prod_and_dev_install_roots_are_disjoint() {
        assert_ne!(PROD_INSTALL_ROOT, DEV_INSTALL_ROOT);
        // Path-segment disjoint: neither is a parent dir of the other.
        let prod_with_sep = format!("{PROD_INSTALL_ROOT}/");
        let dev_with_sep = format!("{DEV_INSTALL_ROOT}/");
        assert!(!PROD_INSTALL_ROOT.starts_with(&dev_with_sep));
        assert!(!DEV_INSTALL_ROOT.starts_with(&prod_with_sep));
    }

    #[test]
    fn prod_and_dev_socket_paths_are_disjoint() {
        let prod = prod_daemon_socket_path();
        let dev = DEV_DAEMON_SOCKET_REL;
        assert_ne!(prod.to_string_lossy(), dev);
        // ADR 218 boundary: prod is an absolute system path, NOT under
        // any user's $HOME. Dev still lives under operator HOME pending
        // its own follow-up ADR-218 rewire.
        assert!(prod.is_absolute(), "prod socket must be absolute: {prod:?}");
        let prod_str = prod.to_string_lossy();
        assert!(
            !prod_str.starts_with("/Users/") && !prod_str.starts_with("/home/"),
            "ADR 218 boundary violated: prod socket at {prod_str} is under a user HOME"
        );
        assert!(
            !prod_str.contains("/.ember/"),
            "legacy ~/.ember/run/ leaked into prod socket: {prod_str}"
        );
    }

    #[test]
    fn prod_and_dev_uids_are_disjoint() {
        assert_ne!(PROD_DAEMON_USER, DEV_DAEMON_USER);
        assert_ne!(PROD_CLIENTS_GROUP, DEV_CLIENTS_GROUP);
    }

    #[test]
    fn prod_and_dev_plist_labels_are_disjoint() {
        assert_ne!(PROD_PLIST_LABEL, DEV_PLIST_LABEL);
        assert!(DEV_PLIST_LABEL.starts_with(PROD_PLIST_LABEL));
    }

    #[test]
    fn prod_and_dev_creds_dirs_are_disjoint() {
        assert_ne!(PROD_CREDS_DIR, DEV_CREDS_DIR_REL);
    }

    #[test]
    fn prod_and_dev_manifests_are_disjoint() {
        assert_ne!(PROD_MANIFEST_PATH, DEV_MANIFEST_PATH_REL);
    }
}
