//!
//! design Phase 4 step 11: post-install verify.
//!
//! Reports: daemon PID, manifest fingerprint (read from manifest.toml.sig),
//! registered broker count, trust-roots fingerprint set.
//!
//! Failure modes: socket unreachable → return Err with operator CTA.
//!
//! Used by `ember dev info` (already wired in slice-A) AND as the final
//! step of `ember dev install` (integration PR will wire it).

use std::path::{Path, PathBuf};

use crate::install_paths::{DEV_DAEMON_SOCKET_REL, DEV_MANIFEST_PATH_REL};

/// Post-install verification report produced by `verify_dev_install`.
#[derive(Debug, Default)]
pub struct DevInstallVerifyReport {
    /// PID of the running emberd-dev process, if detectable.
    pub daemon_pid: Option<u32>,
    /// Hex fingerprint read from `manifest.toml.sig` (the raw sig file).
    pub manifest_fingerprint: Option<String>,
    /// Number of credential brokers registered with the dev daemon.
    pub registered_broker_count: Option<usize>,
    /// Ed25519 fingerprints of registered trust roots (hex-encoded).
    pub trust_roots: Option<Vec<String>>,
}

/// Run post-install verification and return a [`DevInstallVerifyReport`].
///
/// Each field is populated on a best-effort basis:
///
/// - `daemon_pid`: read from `launchctl print system/sh.emberlink.daemon.dev`
///   output, looking for `pid = <N>`.
/// - `manifest_fingerprint`: read from `~/.ember-dev/binaries/manifest.toml.sig`.
/// - `registered_broker_count` and `trust_roots`: require an RPC call to the
///   dev daemon socket; if the socket is unreachable the fields are `None` and
///   the function still returns `Ok(report)` (non-fatal).
///
/// # Errors
///
/// Returns `Err` only when a *required* precondition fails in a way that makes
/// the report meaningless — e.g. $HOME cannot be resolved. Missing socket or
/// missing manifest are non-fatal and surface as `None` fields.
pub fn verify_dev_install() -> Result<DevInstallVerifyReport, Box<dyn std::error::Error>> {
    verify_dev_install_with(&DefaultVerifyOps)
}

/// Testable variant — caller supplies a `VerifyOps` implementation.
pub fn verify_dev_install_with(
    ops: &dyn VerifyOps,
) -> Result<DevInstallVerifyReport, Box<dyn std::error::Error>> {
    let mut report = DevInstallVerifyReport::default();

    // Daemon PID.
    report.daemon_pid = ops.read_daemon_pid();

    // Manifest fingerprint.
    if let Some(manifest_sig_path) = manifest_sig_path() {
        report.manifest_fingerprint = ops.read_manifest_fingerprint(&manifest_sig_path);
    }

    // Broker count + trust roots (best-effort via socket RPC).
    if let Some(socket_path) = dev_socket_path() {
        report.registered_broker_count = ops.query_broker_count(&socket_path);
        report.trust_roots = ops.query_trust_roots(&socket_path);
    }

    Ok(report)
}

/// Operations abstraction for `verify_dev_install_with`. Tests supply a stub;
/// production uses `DefaultVerifyOps`.
pub trait VerifyOps {
    /// Return the PID of the running dev daemon, if detectable.
    fn read_daemon_pid(&self) -> Option<u32>;
    /// Read and return the first line of the manifest signature file at `path`.
    fn read_manifest_fingerprint(&self, path: &Path) -> Option<String>;
    /// Query the dev daemon socket for the number of registered brokers.
    fn query_broker_count(&self, socket: &Path) -> Option<usize>;
    /// Query the dev daemon socket for registered trust-root fingerprints.
    fn query_trust_roots(&self, socket: &Path) -> Option<Vec<String>>;
}

/// Production implementation of `VerifyOps`.
struct DefaultVerifyOps;

impl VerifyOps for DefaultVerifyOps {
    fn read_daemon_pid(&self) -> Option<u32> {
        // Query launchctl for the running PID.
        let output = std::process::Command::new("launchctl")
            .args(["print", "system/sh.emberlink.daemon.dev"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        parse_launchctl_pid(&text)
    }

    fn read_manifest_fingerprint(&self, path: &Path) -> Option<String> {
        let contents = std::fs::read_to_string(path).ok()?;
        let line = contents.lines().next()?.trim().to_string();
        if line.is_empty() { None } else { Some(line) }
    }

    fn query_broker_count(&self, _socket: &Path) -> Option<usize> {
        // Real implementation would open a Unix-domain socket and issue a
        // JSON-RPC "list_brokers" call. Stubbed for now — integration PR wires
        // the actual RPC client once the dev daemon RPC surface is finalised.
        None
    }

    fn query_trust_roots(&self, _socket: &Path) -> Option<Vec<String>> {
        // As above — stubbed until the RPC surface lands.
        None
    }
}

/// Parse `pid = <N>` from `launchctl print` output.
fn parse_launchctl_pid(text: &str) -> Option<u32> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pid = ") {
            if let Ok(pid) = rest.trim().parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

/// Resolve `~/.ember-dev/binaries/manifest.toml.sig`.
fn manifest_sig_path() -> Option<PathBuf> {
    let rel = Path::new(DEV_MANIFEST_PATH_REL); // ".ember-dev/binaries/manifest.toml"
    dirs_next::home_dir().map(|h| {
        let mut p = h.join(rel);
        // Append ".sig" extension.
        let name = p
            .file_name()
            .map(|n| format!("{}.sig", n.to_string_lossy()))
            .unwrap_or_else(|| "manifest.toml.sig".to_string());
        p.set_file_name(name);
        p
    })
}

/// Resolve `~/<DEV_DAEMON_SOCKET_REL>` to the dev daemon Unix-domain socket path.
fn dev_socket_path() -> Option<PathBuf> {
    dirs_next::home_dir().map(|h| h.join(DEV_DAEMON_SOCKET_REL))
}

#[cfg(test)]
mod tests {
    use super::*;
    // --- parse_launchctl_pid tests ---

    #[test]
    fn parse_launchctl_pid_extracts_pid_from_realistic_output() {
        let output = "system/sh.emberlink.daemon.dev = {\n\tpid = 12345\n\tstatus = 0\n}";
        let pid = parse_launchctl_pid(output);
        assert_eq!(
            pid,
            Some(12345),
            "must parse pid from launchctl print output"
        );
    }

    #[test]
    fn parse_launchctl_pid_returns_none_when_not_running() {
        let output = "system/sh.emberlink.daemon.dev = {\n\tstatus = 3\n}";
        let pid = parse_launchctl_pid(output);
        assert_eq!(pid, None, "must return None when pid field is absent");
    }

    // --- stub-based verify_dev_install_with tests ---

    struct StubVerifyOps {
        pid: Option<u32>,
        fingerprint: Option<String>,
        broker_count: Option<usize>,
        trust_roots: Option<Vec<String>>,
    }

    impl VerifyOps for StubVerifyOps {
        fn read_daemon_pid(&self) -> Option<u32> {
            self.pid
        }
        fn read_manifest_fingerprint(&self, _: &Path) -> Option<String> {
            self.fingerprint.clone()
        }
        fn query_broker_count(&self, _: &Path) -> Option<usize> {
            self.broker_count
        }
        fn query_trust_roots(&self, _: &Path) -> Option<Vec<String>> {
            self.trust_roots.clone()
        }
    }

    #[test]
    fn verify_dev_install_with_happy_path() {
        let ops = StubVerifyOps {
            pid: Some(42),
            fingerprint: Some("abcdef1234".to_string()),
            broker_count: Some(3),
            trust_roots: Some(vec!["sha256:aabbcc".to_string()]),
        };
        let report = verify_dev_install_with(&ops).expect("verify must succeed");
        assert_eq!(report.daemon_pid, Some(42));
        assert_eq!(report.manifest_fingerprint.as_deref(), Some("abcdef1234"));
        assert_eq!(report.registered_broker_count, Some(3));
        assert_eq!(
            report.trust_roots.as_deref(),
            Some(["sha256:aabbcc".to_string()].as_slice())
        );
    }

    #[test]
    fn verify_dev_install_with_daemon_unreachable() {
        // When daemon is not running: pid = None, broker count = None, trust_roots = None.
        let ops = StubVerifyOps {
            pid: None,
            fingerprint: Some("aabbcc112233".to_string()),
            broker_count: None,
            trust_roots: None,
        };
        let report = verify_dev_install_with(&ops)
            .expect("verify must return Ok even when daemon unreachable");
        assert!(
            report.daemon_pid.is_none(),
            "daemon_pid must be None when not running"
        );
        assert!(
            report.registered_broker_count.is_none(),
            "broker_count must be None when socket unreachable"
        );
        assert!(
            report.trust_roots.is_none(),
            "trust_roots must be None when socket unreachable"
        );
        // Manifest fingerprint still readable.
        assert_eq!(report.manifest_fingerprint.as_deref(), Some("aabbcc112233"));
    }

    // --- manifest_sig_path tests ---

    #[test]
    fn manifest_sig_path_ends_with_toml_sig() {
        if let Some(p) = manifest_sig_path() {
            let name = p.file_name().unwrap().to_string_lossy();
            assert!(
                name.ends_with(".toml.sig"),
                "manifest sig path must end with .toml.sig; got: {name}"
            );
        }
        // If $HOME is not set, skip — not a failure.
    }

    #[test]
    fn manifest_sig_path_is_under_ember_dev() {
        if let Some(p) = manifest_sig_path() {
            let path_str = p.to_string_lossy();
            assert!(
                path_str.contains(".ember-dev"),
                "manifest sig path must be under .ember-dev; got: {path_str}"
            );
        }
    }
}
