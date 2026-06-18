//! CLASSIFICATION: PUBLIC
//!
//! ADR 157 Phase 4 step 11: post-install verify.
//!
//! Reports: daemon PID, manifest fingerprint (read from manifest.toml.sig),
//! registered broker count, trust-roots fingerprint set.
//!
//! Failure modes: socket unreachable → return Err with operator CTA.
//!
//! Used by `ember dev info` and as the final step of `ember dev install`.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::dev_runtime::DevRuntimeEnv;
use crate::dev_runtime_artifacts::runtime_artifacts;

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
    /// Runtime binaries expected under the dev install root but absent.
    pub missing_runtime_artifacts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BrokerRegistryStatusResponse {
    provider_count: usize,
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
    let runtime = crate::dev_runtime::resolve_current_dev_runtime()?;
    verify_dev_install_with(&DefaultVerifyOps, &runtime)
}

pub fn verify_dev_install_for(
    runtime: &DevRuntimeEnv,
) -> Result<DevInstallVerifyReport, Box<dyn std::error::Error>> {
    verify_dev_install_with(&DefaultVerifyOps, runtime)
}

/// Testable variant — caller supplies a `VerifyOps` implementation.
pub fn verify_dev_install_with(
    ops: &dyn VerifyOps,
    runtime: &DevRuntimeEnv,
) -> Result<DevInstallVerifyReport, Box<dyn std::error::Error>> {
    let mut report = DevInstallVerifyReport {
        daemon_pid: ops.read_daemon_pid(&runtime.plist_label),
        ..DevInstallVerifyReport::default()
    };

    // Manifest fingerprint.
    if let Some(manifest_sig_path) = manifest_sig_path(runtime) {
        report.manifest_fingerprint = ops.read_manifest_fingerprint(&manifest_sig_path);
    }

    // Broker count + trust roots (best-effort via socket RPC).
    if let Some(socket_path) = dev_socket_path(runtime) {
        report.registered_broker_count = ops.query_broker_count(&socket_path);
        report.trust_roots = ops.query_trust_roots(&socket_path);
    }

    report.missing_runtime_artifacts = runtime_artifact_paths(runtime)
        .into_iter()
        .filter_map(|(binary_name, path)| (!ops.path_exists(&path)).then_some(binary_name))
        .collect();

    Ok(report)
}

/// Return the readiness gaps that still block the dev install from being
/// treated as fully usable.
pub fn readiness_issues(report: &DevInstallVerifyReport) -> Vec<String> {
    let mut issues = Vec::new();

    if report.daemon_pid.is_none() {
        issues.push("dev daemon PID not detectable".to_string());
    }
    if report.manifest_fingerprint.is_none() {
        issues.push("dev manifest signature missing".to_string());
    }
    match report.registered_broker_count {
        None => issues.push("registered broker count unavailable".to_string()),
        Some(0) => issues.push("no credential brokers registered".to_string()),
        Some(_) => {}
    }
    match report.trust_roots.as_ref() {
        None => issues.push("trust roots unavailable".to_string()),
        Some(roots) if roots.is_empty() => issues.push("trust root set is empty".to_string()),
        Some(_) => {}
    }
    if !report.missing_runtime_artifacts.is_empty() {
        issues.push(format!(
            "missing staged runtime artifacts: {}",
            report.missing_runtime_artifacts.join(", ")
        ));
    }

    issues
}

/// Operations abstraction for `verify_dev_install_with`. Tests supply a stub;
/// production uses `DefaultVerifyOps`.
pub trait VerifyOps {
    /// Return the PID of the running dev daemon, if detectable.
    fn read_daemon_pid(&self, plist_label: &str) -> Option<u32>;
    /// Read and return the first line of the manifest signature file at `path`.
    fn read_manifest_fingerprint(&self, path: &Path) -> Option<String>;
    /// Query the dev daemon socket for the number of registered brokers.
    fn query_broker_count(&self, socket: &Path) -> Option<usize>;
    /// Query the dev daemon socket for registered trust-root fingerprints.
    fn query_trust_roots(&self, socket: &Path) -> Option<Vec<String>>;
    /// Check whether an expected staged runtime path exists.
    fn path_exists(&self, path: &Path) -> bool;
}

/// Production implementation of `VerifyOps`.
struct DefaultVerifyOps;

impl VerifyOps for DefaultVerifyOps {
    fn read_daemon_pid(&self, plist_label: &str) -> Option<u32> {
        // Query launchctl for the running PID.
        let output = std::process::Command::new("launchctl")
            .args(["print", &format!("system/{plist_label}")])
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

    fn query_broker_count(&self, socket: &Path) -> Option<usize> {
        fetch_broker_registry_status(socket)
            .ok()
            .map(|resp| resp.provider_count)
    }

    fn query_trust_roots(&self, socket: &Path) -> Option<Vec<String>> {
        crate::trust::list::fetch_trust_list(socket)
            .ok()
            .map(|resp| {
                resp.roots
                    .into_iter()
                    .map(|root| root.fingerprint_hex)
                    .collect()
            })
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

fn fetch_broker_registry_status(
    socket_path: &Path,
) -> Result<BrokerRegistryStatusResponse, String> {
    let body = call_daemon(
        socket_path,
        "broker.registry_status",
        &Value::Object(Default::default()),
    )?;
    parse_broker_registry_status_response(&body)
}

fn parse_broker_registry_status_response(
    body: &Value,
) -> Result<BrokerRegistryStatusResponse, String> {
    serde_json::from_value(body.clone())
        .map_err(|e| format!("decode broker.registry_status response: {e}"))
}

fn call_daemon(socket_path: &Path, method: &str, params: &Value) -> Result<Value, String> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path)
        .map_err(|e| format!("connect {method}: {e}"))?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| format!("clone socket for {method}: {e}"))?;
    let mut reader = BufReader::new(stream);

    let request = json!({
        "id": "1",
        "method": method,
        "params": params,
    });
    let mut line =
        serde_json::to_string(&request).map_err(|e| format!("serialize {method} request: {e}"))?;
    line.push('\n');

    writer
        .write_all(line.as_bytes())
        .map_err(|e| format!("write {method} request: {e}"))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| format!("read {method} response: {e}"))?;

    let response: Value = serde_json::from_str(response_line.trim())
        .map_err(|e| format!("parse {method} response JSON: {e}"))?;
    if let Some(err) = response.get("error").filter(|value| !value.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000);
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown daemon error");
        return Err(format!("{method} daemon error {code}: {message}"));
    }
    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

/// Parse `pid = <N>` from `launchctl print` output.
fn parse_launchctl_pid(text: &str) -> Option<u32> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pid = ")
            && let Ok(pid) = rest.trim().parse::<u32>()
        {
            return Some(pid);
        }
    }
    None
}

/// Resolve the worktree-scoped manifest signature sidecar path.
fn manifest_sig_path(runtime: &DevRuntimeEnv) -> Option<PathBuf> {
    let mut p = runtime.manifest_path.clone();
    let name = p
        .file_name()
        .map(|n| format!("{}.sig", n.to_string_lossy()))
        .unwrap_or_else(|| "manifest.toml.sig".to_string());
    p.set_file_name(name);
    Some(p)
}

/// Resolve the worktree-scoped dev daemon Unix-domain socket path.
fn dev_socket_path(runtime: &DevRuntimeEnv) -> Option<PathBuf> {
    Some(runtime.socket_path.clone())
}

fn runtime_artifact_paths(runtime: &DevRuntimeEnv) -> Vec<(String, PathBuf)> {
    runtime_artifacts()
        .into_iter()
        .map(|artifact| {
            let binary_name = artifact.binary_name.clone();
            let path = artifact.installed_path(runtime);
            (binary_name, path)
        })
        .collect()
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

    #[test]
    fn parse_broker_registry_status_extracts_provider_count() {
        let body = json!({"provider_count": 7});
        let parsed = parse_broker_registry_status_response(&body).expect("valid response");
        assert_eq!(parsed.provider_count, 7);
    }

    #[test]
    fn parse_broker_registry_status_rejects_missing_provider_count() {
        let body = json!({});
        let err = parse_broker_registry_status_response(&body)
            .expect_err("missing field must be rejected");
        assert!(
            err.contains("provider_count"),
            "unexpected parse error: {err}"
        );
    }

    // --- stub-based verify_dev_install_with tests ---

    struct StubVerifyOps {
        pid: Option<u32>,
        fingerprint: Option<String>,
        broker_count: Option<usize>,
        trust_roots: Option<Vec<String>>,
        runtime_artifacts_present: bool,
    }

    impl VerifyOps for StubVerifyOps {
        fn read_daemon_pid(&self, _: &str) -> Option<u32> {
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

        fn path_exists(&self, _: &Path) -> bool {
            self.runtime_artifacts_present
        }
    }

    #[test]
    fn verify_dev_install_with_happy_path() {
        let runtime = crate::dev_runtime::derive_dev_runtime_env(
            Path::new("/home/tester"),
            Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        let ops = StubVerifyOps {
            pid: Some(42),
            fingerprint: Some("abcdef1234".to_string()),
            broker_count: Some(3),
            trust_roots: Some(vec!["sha256:aabbcc".to_string()]),
            runtime_artifacts_present: true,
        };
        let report = verify_dev_install_with(&ops, &runtime).expect("verify must succeed");
        assert_eq!(report.daemon_pid, Some(42));
        assert_eq!(report.manifest_fingerprint.as_deref(), Some("abcdef1234"));
        assert_eq!(report.registered_broker_count, Some(3));
        assert_eq!(
            report.trust_roots.as_deref(),
            Some(["sha256:aabbcc".to_string()].as_slice())
        );
        assert!(
            report.missing_runtime_artifacts.is_empty(),
            "happy path should not report missing staged runtime artifacts"
        );
    }

    #[test]
    fn verify_dev_install_with_daemon_unreachable() {
        let runtime = crate::dev_runtime::derive_dev_runtime_env(
            Path::new("/home/tester"),
            Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        // When daemon is not running: pid = None, broker count = None, trust_roots = None.
        let ops = StubVerifyOps {
            pid: None,
            fingerprint: Some("aabbcc112233".to_string()),
            broker_count: None,
            trust_roots: None,
            runtime_artifacts_present: true,
        };
        let report = verify_dev_install_with(&ops, &runtime)
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
        assert!(
            report.missing_runtime_artifacts.is_empty(),
            "daemon reachability should not imply missing staged artifacts"
        );
    }

    #[test]
    fn readiness_issues_flags_missing_runtime_truth() {
        let report = DevInstallVerifyReport {
            daemon_pid: None,
            manifest_fingerprint: Some("abc".to_string()),
            registered_broker_count: None,
            trust_roots: Some(Vec::new()),
            missing_runtime_artifacts: Vec::new(),
        };
        let issues = readiness_issues(&report);
        assert!(issues.iter().any(|item| item.contains("PID")));
        assert!(
            issues
                .iter()
                .any(|item| item.contains("registered broker count unavailable"))
        );
        assert!(
            issues
                .iter()
                .any(|item| item.contains("trust root set is empty"))
        );
    }

    #[test]
    fn readiness_issues_accepts_populated_report() {
        let report = DevInstallVerifyReport {
            daemon_pid: Some(7),
            manifest_fingerprint: Some("abc".to_string()),
            registered_broker_count: Some(3),
            trust_roots: Some(vec!["root".to_string()]),
            missing_runtime_artifacts: Vec::new(),
        };
        assert!(
            readiness_issues(&report).is_empty(),
            "fully-populated report must be ready"
        );
    }

    #[test]
    fn readiness_issues_flags_missing_runtime_artifacts() {
        let report = DevInstallVerifyReport {
            daemon_pid: Some(7),
            manifest_fingerprint: Some("abc".to_string()),
            registered_broker_count: Some(3),
            trust_roots: Some(vec!["root".to_string()]),
            missing_runtime_artifacts: vec!["ember".to_string(), "ember-gh".to_string()],
        };
        let issues = readiness_issues(&report);
        assert!(
            issues
                .iter()
                .any(|item| item.contains("missing staged runtime artifacts")),
            "expected runtime artifact gap, got: {issues:?}"
        );
    }

    // --- manifest_sig_path tests ---

    #[test]
    fn manifest_sig_path_ends_with_toml_sig() {
        let runtime = crate::dev_runtime::derive_dev_runtime_env(
            Path::new("/home/tester"),
            Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        let p = manifest_sig_path(&runtime).expect("manifest sig path");
        let name = p.file_name().unwrap().to_string_lossy();
        assert!(
            name.ends_with(".toml.sig"),
            "manifest sig path must end with .toml.sig; got: {name}"
        );
    }

    #[test]
    fn manifest_sig_path_is_under_worktree_env() {
        let runtime = crate::dev_runtime::derive_dev_runtime_env(
            Path::new("/home/tester"),
            Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        let p = manifest_sig_path(&runtime).expect("manifest sig path");
        let path_str = p.to_string_lossy();
        assert!(
            path_str.contains(".ember-dev/envs/"),
            "manifest sig path must be under a worktree env: {path_str}"
        );
    }
}
