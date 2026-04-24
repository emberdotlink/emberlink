use std::path::{Path, PathBuf};

use chrono::Utc;
use uuid::Uuid;

use crate::store::{DaemonStore, StoreError};

#[derive(Debug)]
pub struct SandboxInfo {
    pub id: String,
    pub name: String,
    pub persona_id: String,
    pub container_id: Option<String>,
    pub image: String,
    pub status: String,
    pub created_at: String,
    pub workspace_path: Option<String>,
}

/// Options carried into `create_sandbox`. Covers all operator-settable flags
/// that are subject to the MVS-A hardening invariants (design §Hardening
/// invariants — Refused at sandbox create).
#[derive(Debug, Clone, Default)]
pub struct SandboxCreateOpts {
    pub name: String,
    pub image: String,
    /// Refused unless `unsafe_root` is true. `--privileged` in docker-speak.
    pub privileged: bool,
    /// Mount specs in `host:container[:ro]` form. Each host path is resolved
    /// (canonicalized when it exists) and checked against the denylist.
    pub volumes: Vec<String>,
    /// User override. `"0"` or `"root"` are refused unless `unsafe_root`.
    pub user: Option<String>,
    /// Network mode. `Some("host")` is refused unconditionally. `None` means
    /// bridge (the MVS default); `Some("none")` is available for tests.
    pub network: Option<String>,
    /// Explicit opt-in to run as root. Required to bypass the root-user refusal.
    pub unsafe_root: bool,
    /// Git URL to clone into `<data_dir>/sandboxes/<id>/workspace/`.
    pub workspace_from: Option<String>,
    /// Additional `KEY=VAL` env vars to pass into the container.
    pub extra_env: Vec<(String, String)>,
}

/// Host paths that must never appear in a mount source, per design
/// §Hardening invariants. Checked as substring match on the resolved absolute
/// path of the mount source.
const FORBIDDEN_MOUNT_SUBSTRINGS: &[&str] = &[
    "/var/run/docker.sock",
    "/.ssh",
    "/.aws",
    "/.kube",
    "/.gnupg",
];

/// Resolve tilde + $HOME in a path-like string. Returns the canonicalized
/// absolute path if it exists, or the logically resolved path if it doesn't.
fn resolve_host_path(raw: &str) -> PathBuf {
    let expanded = if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if raw == "~" {
            home
        } else if let Some(rest) = raw.strip_prefix("~/") {
            home.join(rest)
        } else if let Some(rest) = raw.strip_prefix("$HOME/") {
            home.join(rest)
        } else if raw == "$HOME" {
            home
        } else {
            PathBuf::from(raw)
        }
    } else {
        PathBuf::from(raw)
    };
    std::fs::canonicalize(&expanded).unwrap_or(expanded)
}

/// Parse a docker-style mount spec (`host:container[:opts]`) and return the
/// host source portion. Everything after the second `:` is options; only the
/// first `:` separates host from container.
fn mount_source(spec: &str) -> &str {
    spec.split(':').next().unwrap_or(spec)
}

/// Validate an `SandboxCreateOpts` against the MVS-A hardening invariants.
/// Returns `Err(StoreError::InvalidInput("sandbox invariant violated: <slug>"))`
/// on first violation. Invariant slugs are stable identifiers — callers and
/// tests depend on them.
pub(crate) fn validate_sandbox_opts(opts: &SandboxCreateOpts) -> Result<(), StoreError> {
    if opts.privileged {
        return Err(StoreError::InvalidInput(
            "sandbox invariant violated: no-privileged".into(),
        ));
    }

    if matches!(opts.network.as_deref(), Some("host")) {
        return Err(StoreError::InvalidInput(
            "sandbox invariant violated: no-host-network".into(),
        ));
    }

    if let Some(user) = opts.user.as_deref()
        && !opts.unsafe_root
        && (user == "0" || user == "root" || user.starts_with("0:"))
    {
        return Err(StoreError::InvalidInput(
            "sandbox invariant violated: no-root-user".into(),
        ));
    }

    let home = std::env::var("HOME").ok();
    for v in &opts.volumes {
        let raw = mount_source(v);
        let resolved = resolve_host_path(raw);
        let as_str = resolved.to_string_lossy().to_string();

        if as_str.contains("/var/run/docker.sock") || raw.contains("/var/run/docker.sock") {
            return Err(StoreError::InvalidInput(
                "sandbox invariant violated: no-docker-socket-mount".into(),
            ));
        }

        if let Some(ref h) = home {
            let h_trim = h.trim_end_matches('/');
            if !h_trim.is_empty() && (as_str == *h_trim || as_str.starts_with(&format!("{h_trim}/")))
            {
                // Any mount under $HOME — refused. Covers $HOME itself,
                // ~/.ssh, ~/.aws, ~/.kube, ~/.gnupg, etc.
                if as_str == *h_trim {
                    return Err(StoreError::InvalidInput(
                        "sandbox invariant violated: no-home-mount".into(),
                    ));
                }
                // Fall through to the sensitive-subpath check for a more
                // specific slug when applicable.
            }
        }

        for forbidden in FORBIDDEN_MOUNT_SUBSTRINGS {
            if as_str.contains(forbidden) || raw.contains(forbidden) {
                let slug = match *forbidden {
                    "/var/run/docker.sock" => "no-docker-socket-mount",
                    "/.ssh" => "no-ssh-mount",
                    "/.aws" => "no-aws-mount",
                    "/.kube" => "no-kube-mount",
                    "/.gnupg" => "no-gnupg-mount",
                    _ => "no-sensitive-mount",
                };
                return Err(StoreError::InvalidInput(format!(
                    "sandbox invariant violated: {slug}"
                )));
            }
        }

        // Final $HOME check after sensitive-subpath pass — catches $HOME itself
        // and any arbitrary subdir not already named above.
        if let Some(ref h) = home {
            let h_trim = h.trim_end_matches('/');
            if !h_trim.is_empty()
                && (as_str == *h_trim || as_str.starts_with(&format!("{h_trim}/")))
            {
                return Err(StoreError::InvalidInput(
                    "sandbox invariant violated: no-home-mount".into(),
                ));
            }
        }
    }

    Ok(())
}

/// Pure helper: compose the `docker run` argument vector from the sandbox
/// configuration. Kept separate from the subprocess call so tests can assert
/// the exact argument shape without spawning docker.
pub(crate) fn build_run_args(
    name: &str,
    image: &str,
    socket_dir: &Path,
    network: Option<&str>,
    extra_env: &[(String, String)],
    workspace_host_path: Option<&Path>,
) -> Vec<String> {
    let net = network.unwrap_or("bridge");
    let socket_mount = format!(
        "{}:/run/ember/daemon.sock:ro",
        socket_dir.join("daemon.sock").display()
    );

    let mut args: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        name.into(),
        format!("--network={net}"),
        "--cap-drop=ALL".into(),
        "--read-only".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--user".into(),
        "1000:1000".into(),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,size=1g".into(),
        "--tmpfs".into(),
        "/home/agent:rw,nosuid,uid=1000,gid=1000,size=100m".into(),
        "-v".into(),
        socket_mount,
    ];

    if let Some(ws) = workspace_host_path {
        args.push("-v".into());
        args.push(format!("{}:/workspace:rw", ws.display()));
    }

    for (k, v) in extra_env {
        args.push("-e".into());
        args.push(format!("{k}={v}"));
    }

    args.push(image.into());
    args.push("sleep".into());
    args.push("infinity".into());

    args
}

impl DaemonStore {
    /// Legacy two-arg constructor. Creates a sandbox with default
    /// hardening (no privileged, no overrides). New callers should use
    /// [`create_sandbox_with_opts`] to carry volumes/env/workspace.
    pub fn create_sandbox(&self, name: &str, image: &str) -> Result<SandboxInfo, StoreError> {
        let opts = SandboxCreateOpts {
            name: name.to_string(),
            image: image.to_string(),
            ..Default::default()
        };
        self.create_sandbox_with_opts(&opts, None)
    }

    /// Create a sandbox, enforcing all refusal invariants and provisioning a
    /// fresh-clone workspace when `opts.workspace_from` is set.
    ///
    /// `data_dir` is the daemon's persistent data directory — required when a
    /// workspace clone is requested (the clone target is
    /// `<data_dir>/sandboxes/<id>/workspace/`). Pass `None` when callers know
    /// no workspace is requested (tests, legacy two-arg path).
    pub fn create_sandbox_with_opts(
        &self,
        opts: &SandboxCreateOpts,
        data_dir: Option<&Path>,
    ) -> Result<SandboxInfo, StoreError> {
        validate_sandbox_opts(opts)?;

        if opts.workspace_from.is_some() && data_dir.is_none() {
            return Err(StoreError::InvalidInput(
                "workspace_from requires data_dir".into(),
            ));
        }

        let persona = self.create_persona(&opts.name)?;
        let id = format!("sandbox-{}", Uuid::new_v4());
        let created_at = Utc::now().to_rfc3339();

        // Clone workspace if requested. Must happen before DB insert so a
        // clone failure aborts the whole create.
        let workspace_path: Option<PathBuf> = if let Some(url) = opts.workspace_from.as_deref() {
            let dd = data_dir.expect("checked above");
            let target = dd.join("sandboxes").join(&id).join("workspace");
            if let Some(parent) = target.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                return Err(StoreError::InvalidInput(format!(
                    "workspace parent create failed: {e}"
                )));
            }
            clone_workspace(url, &target)?;
            chown_workspace_best_effort(&target);
            Some(target)
        } else {
            None
        };

        let workspace_str = workspace_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string());

        self.conn().execute(
            "INSERT INTO sandboxes (id, name, persona_id, container_id, image, status, created_at, workspace_path)
             VALUES (?1, ?2, ?3, NULL, ?4, 'created', ?5, ?6)",
            rusqlite::params![id, opts.name, persona.id, opts.image, created_at, workspace_str],
        )?;

        Ok(SandboxInfo {
            id,
            name: opts.name.clone(),
            persona_id: persona.id,
            container_id: None,
            image: opts.image.clone(),
            status: "created".to_string(),
            created_at,
            workspace_path: workspace_str,
        })
    }

    /// Start the container for a previously-created sandbox.
    ///
    /// `network` defaults to bridge (MVS-A default) when `None`; tests pass
    /// `Some("none")` to keep the docker path fast and offline. `extra_env`
    /// is passed through as `-e KEY=VAL` to the container — the daemon also
    /// injects `EMBER_PERSONA_ID`, `EMBER_DAEMON_SOCKET`, `EMBER_PROXY_URL`
    /// (pass-through from the daemon env, if set), and `ANTHROPIC_API_KEY`
    /// (pass-through from the daemon env, if set).
    pub fn start_container(
        &self,
        sandbox_id: &str,
        socket_dir: &Path,
        network: Option<&str>,
        extra_env: &[(String, String)],
    ) -> Result<String, StoreError> {
        let (name, image, persona_id, workspace_path): (String, String, String, Option<String>) =
            self.conn()
                .query_row(
                    "SELECT name, image, persona_id, workspace_path FROM sandboxes WHERE id = ?1",
                    rusqlite::params![sandbox_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, Option<String>>(3)?,
                        ))
                    },
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
                    other => StoreError::Sqlite(other),
                })?;

        // Compose the env block: caller-provided vars first, then the daemon's
        // mandatory trio, then pass-through vars from the daemon env if set.
        let mut env: Vec<(String, String)> = extra_env.to_vec();
        env.push(("EMBER_PERSONA_ID".to_string(), persona_id));
        env.push((
            "EMBER_DAEMON_SOCKET".to_string(),
            "/run/ember/daemon.sock".to_string(),
        ));
        if let Ok(url) = std::env::var("EMBER_PROXY_URL")
            && !url.is_empty()
        {
            env.push(("EMBER_PROXY_URL".to_string(), url));
        }
        if let Ok(key) = std::env::var("ANTHROPIC_API_KEY")
            && !key.is_empty()
        {
            env.push(("ANTHROPIC_API_KEY".to_string(), key));
        }

        let workspace_buf = workspace_path.as_ref().map(PathBuf::from);
        let args = build_run_args(
            &name,
            &image,
            socket_dir,
            network,
            &env,
            workspace_buf.as_deref(),
        );

        let output = std::process::Command::new("docker")
            .args(&args)
            .output()
            .map_err(|e| StoreError::InvalidInput(format!("docker not available: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            tracing::warn!(
                cmd = "docker run",
                sandbox_id = %sandbox_id,
                exit = output.status.code().unwrap_or(-1),
                stderr = %stderr,
                "subprocess failed"
            );
            self.conn().execute(
                "UPDATE sandboxes SET status = 'error' WHERE id = ?1",
                rusqlite::params![sandbox_id],
            )?;
            return Err(StoreError::InvalidInput(format!(
                "docker run failed: {stderr}"
            )));
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

        self.conn().execute(
            "UPDATE sandboxes SET container_id = ?1, status = 'running' WHERE id = ?2",
            rusqlite::params![container_id, sandbox_id],
        )?;

        Ok(container_id)
    }

    pub fn list_sandboxes(&self) -> Result<Vec<SandboxInfo>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, name, persona_id, container_id, image, status, created_at, workspace_path
             FROM sandboxes ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SandboxInfo {
                id: row.get(0)?,
                name: row.get(1)?,
                persona_id: row.get(2)?,
                container_id: row.get(3)?,
                image: row.get(4)?,
                status: row.get(5)?,
                created_at: row.get(6)?,
                workspace_path: row.get(7)?,
            })
        })?;
        let mut sandboxes = Vec::new();
        for row in rows {
            sandboxes.push(row?);
        }
        Ok(sandboxes)
    }

    /// Resolve a sandbox name-or-id argument to the canonical UUID.
    ///
    /// Accepts either a full sandbox UUID or a human-readable name.  Returns
    /// `StoreError::NotFound` when no sandbox matches either field.
    pub fn resolve_sandbox_id(&self, name_or_id: &str) -> Result<String, StoreError> {
        self.conn()
            .query_row(
                "SELECT id FROM sandboxes WHERE id = ?1 OR name = ?1 LIMIT 1",
                rusqlite::params![name_or_id],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
                other => StoreError::Sqlite(other),
            })
    }

    pub fn stop_sandbox(&self, id: &str) -> Result<(), StoreError> {
        let (persona_id, container_id, workspace_path): (String, Option<String>, Option<String>) =
            self.conn()
                .query_row(
                    "SELECT persona_id, container_id, workspace_path FROM sandboxes WHERE id = ?1",
                    rusqlite::params![id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
                    other => StoreError::Sqlite(other),
                })?;

        if let Some(ref cid) = container_id {
            match std::process::Command::new("docker")
                .args(["stop", cid.as_str()])
                .output()
            {
                Ok(out) if !out.status.success() => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    tracing::warn!(
                        cmd = "docker stop",
                        container_id = %cid,
                        exit = out.status.code().unwrap_or(-1),
                        stderr = %stderr.trim(),
                        "subprocess failed"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(cmd = "docker stop", container_id = %cid, error = %e, "subprocess spawn failed");
                }
            }
            match std::process::Command::new("docker")
                .args(["rm", cid.as_str()])
                .output()
            {
                Ok(out) if !out.status.success() => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    tracing::warn!(
                        cmd = "docker rm",
                        container_id = %cid,
                        exit = out.status.code().unwrap_or(-1),
                        stderr = %stderr.trim(),
                        "subprocess failed"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(cmd = "docker rm", container_id = %cid, error = %e, "subprocess spawn failed");
                }
            }
        }

        // Clean up fresh-clone workspace, if any. Container must be removed
        // first (above) so the bind mount is released.
        if let Some(ref ws) = workspace_path {
            let ws_path = PathBuf::from(ws);
            match std::fs::remove_dir_all(&ws_path) {
                Ok(()) => tracing::info!(workspace = %ws, "workspace removed"),
                Err(e) => tracing::warn!(workspace = %ws, error = %e, "workspace remove failed"),
            }
        }

        let _ = self.revoke_persona(&persona_id);

        let stopped_at = Utc::now().to_rfc3339();
        self.conn().execute(
            "UPDATE sandboxes SET status = 'stopped', stopped_at = ?1 WHERE id = ?2",
            rusqlite::params![stopped_at, id],
        )?;

        Ok(())
    }

    pub fn exec_sandbox(&self, id: &str, command: &[&str]) -> Result<String, StoreError> {
        let (container_id, status): (Option<String>, String) = self
            .conn()
            .query_row(
                "SELECT container_id, status FROM sandboxes WHERE id = ?1",
                rusqlite::params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
                other => StoreError::Sqlite(other),
            })?;

        if status != "running" {
            return Err(StoreError::InvalidInput(format!(
                "sandbox is not running (status: {status})"
            )));
        }

        let cid = container_id
            .ok_or_else(|| StoreError::InvalidInput("sandbox has no container".to_string()))?;

        let mut args = vec!["exec", &cid];
        args.extend_from_slice(command);

        let output = std::process::Command::new("docker")
            .args(&args)
            .output()
            .map_err(|e| StoreError::InvalidInput(format!("docker not available: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            tracing::warn!(
                cmd = "docker exec",
                container_id = %cid,
                exit = output.status.code().unwrap_or(-1),
                stderr = %stderr,
                "subprocess failed"
            );
            return Err(StoreError::InvalidInput(format!(
                "docker exec failed: {stderr}"
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

/// Shallow-clone a git URL into `target`. Host-side operation — the clone
/// happens as the daemon user; `chown_workspace_best_effort` follows up to
/// make the tree readable/writable by UID 1000 inside the container.
fn clone_workspace(url: &str, target: &Path) -> Result<(), StoreError> {
    let output = std::process::Command::new("git")
        .args([
            "clone",
            "--depth=1",
            url,
            target.to_string_lossy().as_ref(),
        ])
        .output()
        .map_err(|e| StoreError::InvalidInput(format!("git not available: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        tracing::warn!(
            cmd = "git clone",
            url = %url,
            target = %target.display(),
            exit = output.status.code().unwrap_or(-1),
            stderr = %stderr,
            "subprocess failed"
        );
        return Err(StoreError::InvalidInput(format!(
            "git clone failed: {stderr}"
        )));
    }
    Ok(())
}

/// `chown -R 1000:1000 <target>`. Best-effort: logs a warning on failure
/// instead of aborting the create — macOS hosts without a matching UID still
/// let the container read the tree in practice, and the demo is
/// macOS + Linux-targeted. See design §Backoffs.
fn chown_workspace_best_effort(target: &Path) {
    match std::process::Command::new("chown")
        .args(["-R", "1000:1000", target.to_string_lossy().as_ref()])
        .output()
    {
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            tracing::warn!(
                cmd = "chown",
                target = %target.display(),
                exit = out.status.code().unwrap_or(-1),
                stderr = %stderr.trim(),
                "subprocess failed (workspace owner may not match container uid 1000; tolerated on macOS)"
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                cmd = "chown",
                target = %target.display(),
                error = %e,
                "subprocess spawn failed (tolerated)"
            );
        }
    }
}

#[cfg(test)]
fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn opts(name: &str) -> SandboxCreateOpts {
        SandboxCreateOpts {
            name: name.into(),
            image: "alpine:latest".into(),
            ..Default::default()
        }
    }

    // ---------- create_sandbox existing behavior ----------

    #[test]
    fn create_sandbox_appears_in_list() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.create_sandbox("test-box", "alpine:latest").unwrap();
        let list = store.list_sandboxes().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "test-box");
        assert_eq!(list[0].image, "alpine:latest");
        assert!(list[0].container_id.is_none());
    }

    #[test]
    fn create_sandbox_auto_creates_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store.create_sandbox("persona-box", "ubuntu:22.04").unwrap();
        let persona = store.get_persona(&sandbox.persona_id).unwrap();
        assert_eq!(persona.name, "persona-box");
        assert_eq!(persona.status, "active");
    }

    #[test]
    fn stop_sandbox_without_container_changes_status_and_revokes_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store
            .create_sandbox("no-container-box", "alpine:latest")
            .unwrap();
        store.stop_sandbox(&sandbox.id).unwrap();

        let list = store.list_sandboxes().unwrap();
        assert_eq!(list[0].status, "stopped");

        let persona = store.get_persona(&sandbox.persona_id).unwrap();
        assert_eq!(persona.status, "revoked");
    }

    #[test]
    fn create_duplicate_sandbox_name_returns_error() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.create_sandbox("dup-box", "alpine:latest").unwrap();
        let result = store.create_sandbox("dup-box", "alpine:latest");
        assert!(result.is_err());
    }

    // ---------- 69J.3: start_container hardening invariants ----------

    fn args_for(env: &[(String, String)], network: Option<&str>) -> Vec<String> {
        build_run_args(
            "test-name",
            "alpine:latest",
            &PathBuf::from("/tmp/ember-test/run"),
            network,
            env,
            None,
        )
    }

    #[test]
    fn start_container_applies_no_new_privileges() {
        let args = args_for(&[], Some("none"));
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--security-opt" && w[1] == "no-new-privileges"),
            "missing --security-opt no-new-privileges in {args:?}"
        );
    }

    #[test]
    fn start_container_applies_user_1000() {
        let args = args_for(&[], Some("none"));
        assert!(
            args.windows(2).any(|w| w[0] == "--user" && w[1] == "1000:1000"),
            "missing --user 1000:1000 in {args:?}"
        );
    }

    #[test]
    fn start_container_applies_tmpfs_flags() {
        let args = args_for(&[], Some("none"));
        let mut saw_tmp = false;
        let mut saw_home = false;
        for w in args.windows(2) {
            if w[0] == "--tmpfs" {
                if w[1] == "/tmp:rw,noexec,nosuid,size=1g" {
                    saw_tmp = true;
                }
                if w[1] == "/home/agent:rw,nosuid,uid=1000,gid=1000,size=100m" {
                    saw_home = true;
                }
            }
        }
        assert!(saw_tmp, "missing tmpfs /tmp with full flags in {args:?}");
        assert!(saw_home, "missing tmpfs /home/agent with full flags in {args:?}");
    }

    #[test]
    fn start_container_applies_readonly_root_and_cap_drop_all() {
        let args = args_for(&[], Some("none"));
        assert!(
            args.iter().any(|a| a == "--read-only"),
            "missing --read-only"
        );
        assert!(
            args.iter().any(|a| a == "--cap-drop=ALL"),
            "missing --cap-drop=ALL"
        );
    }

    #[test]
    fn start_container_default_network_is_bridge() {
        let args = args_for(&[], None);
        assert!(
            args.iter().any(|a| a == "--network=bridge"),
            "expected --network=bridge when network is None, got {args:?}"
        );
    }

    #[test]
    fn start_container_test_override_none() {
        let args = args_for(&[], Some("none"));
        assert!(
            args.iter().any(|a| a == "--network=none"),
            "expected --network=none when explicitly set, got {args:?}"
        );
    }

    #[test]
    fn start_container_mounts_daemon_socket_readonly() {
        let args = args_for(&[], Some("none"));
        let mut saw = false;
        for w in args.windows(2) {
            if w[0] == "-v" && w[1].ends_with(":/run/ember/daemon.sock:ro") {
                saw = true;
                break;
            }
        }
        assert!(saw, "missing -v <host>:/run/ember/daemon.sock:ro in {args:?}");
    }

    #[test]
    fn start_container_passes_persona_id_env() {
        let args = args_for(
            &[("EMBER_PERSONA_ID".into(), "persona-xyz".into())],
            Some("none"),
        );
        let mut saw = false;
        for w in args.windows(2) {
            if w[0] == "-e" && w[1] == "EMBER_PERSONA_ID=persona-xyz" {
                saw = true;
                break;
            }
        }
        assert!(saw, "missing -e EMBER_PERSONA_ID=persona-xyz in {args:?}");
    }

    #[test]
    fn start_container_passes_daemon_socket_env() {
        let args = args_for(
            &[(
                "EMBER_DAEMON_SOCKET".into(),
                "/run/ember/daemon.sock".into(),
            )],
            Some("none"),
        );
        let mut saw = false;
        for w in args.windows(2) {
            if w[0] == "-e" && w[1] == "EMBER_DAEMON_SOCKET=/run/ember/daemon.sock" {
                saw = true;
                break;
            }
        }
        assert!(
            saw,
            "missing -e EMBER_DAEMON_SOCKET=/run/ember/daemon.sock in {args:?}"
        );
    }

    #[test]
    fn start_container_passes_anthropic_key_when_set_and_omits_when_unset() {
        // With key
        let args = args_for(
            &[("ANTHROPIC_API_KEY".into(), "sk-test".into())],
            Some("none"),
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-e" && w[1] == "ANTHROPIC_API_KEY=sk-test"),
            "expected ANTHROPIC_API_KEY pass-through in {args:?}"
        );

        // Without key — env slice does not contain the var
        let args = args_for(&[], Some("none"));
        assert!(
            !args.iter().any(|a| a.starts_with("ANTHROPIC_API_KEY=")),
            "expected no ANTHROPIC_API_KEY when unset, got {args:?}"
        );
    }

    #[test]
    fn start_container_passes_proxy_url_when_set() {
        // When EMBER_PROXY_URL is in the env slice it should appear as -e EMBER_PROXY_URL=...
        let args = args_for(
            &[("EMBER_PROXY_URL".into(), "http://127.0.0.1:4141".into())],
            Some("none"),
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-e" && w[1] == "EMBER_PROXY_URL=http://127.0.0.1:4141"),
            "expected EMBER_PROXY_URL pass-through in {args:?}"
        );

        // When the env slice does not contain the var it must not leak in.
        let args = args_for(&[], Some("none"));
        assert!(
            !args.iter().any(|a| a.starts_with("EMBER_PROXY_URL=")),
            "expected no EMBER_PROXY_URL when unset, got {args:?}"
        );
    }

    #[test]
    fn start_container_mounts_workspace_when_set() {
        let args = build_run_args(
            "test-name",
            "alpine:latest",
            &PathBuf::from("/tmp/ember-test/run"),
            Some("none"),
            &[],
            Some(&PathBuf::from("/var/data/ws")),
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-v" && w[1] == "/var/data/ws:/workspace:rw"),
            "missing workspace bind mount in {args:?}"
        );
    }

    // ---------- 69J.4: refused-input invariants ----------

    #[test]
    fn create_sandbox_refuses_privileged() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("priv-box");
        o.privileged = true;
        let err = store.create_sandbox_with_opts(&o, None).unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.starts_with("sandbox invariant violated: no-privileged"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn create_sandbox_refuses_docker_socket_mount() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("dsock-box");
        o.volumes = vec!["/var/run/docker.sock:/var/run/docker.sock".into()];
        let err = store.create_sandbox_with_opts(&o, None).unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.starts_with("sandbox invariant violated: no-docker-socket-mount"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn create_sandbox_refuses_home_mount() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("home-box");
        o.volumes = vec!["$HOME:/mnt".into()];
        let err = store.create_sandbox_with_opts(&o, None).unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.starts_with("sandbox invariant violated: no-home-mount"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn create_sandbox_refuses_ssh_aws_kube_gnupg_mounts() {
        for (path, slug) in [
            ("~/.ssh:/mnt/ssh", "no-ssh-mount"),
            ("~/.aws:/mnt/aws", "no-aws-mount"),
            ("~/.kube:/mnt/kube", "no-kube-mount"),
            ("~/.gnupg:/mnt/gnupg", "no-gnupg-mount"),
        ] {
            let store = DaemonStore::open_in_memory().unwrap();
            let mut o = opts(&format!("secret-{slug}"));
            o.volumes = vec![path.into()];
            let err = store.create_sandbox_with_opts(&o, None).unwrap_err();
            match err {
                StoreError::InvalidInput(msg) => {
                    assert!(
                        msg.starts_with(&format!("sandbox invariant violated: {slug}")),
                        "path {path} expected slug {slug}, got msg: {msg}"
                    );
                }
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }
    }

    #[test]
    fn create_sandbox_refuses_root_user() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("root-box");
        o.user = Some("0".into());
        let err = store.create_sandbox_with_opts(&o, None).unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.starts_with("sandbox invariant violated: no-root-user"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }

        // user=root also refused
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("root-named-box");
        o.user = Some("root".into());
        assert!(matches!(
            store.create_sandbox_with_opts(&o, None),
            Err(StoreError::InvalidInput(_))
        ));

        // With unsafe_root=true, user=0 is allowed
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("unsafe-root-box");
        o.user = Some("0".into());
        o.unsafe_root = true;
        assert!(store.create_sandbox_with_opts(&o, None).is_ok());
    }

    #[test]
    fn create_sandbox_refuses_host_network() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("host-net-box");
        o.network = Some("host".into());
        let err = store.create_sandbox_with_opts(&o, None).unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.starts_with("sandbox invariant violated: no-host-network"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    // ---------- 69J.6: fresh-clone workspace ----------

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn make_bare_repo(base: &Path) -> PathBuf {
        // Create a source repo with one commit, then clone --bare to produce
        // a clonable URL (file path).
        let src = base.join("src-repo");
        std::fs::create_dir_all(&src).unwrap();
        let run = |args: &[&str], cwd: &Path| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(cwd)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run(&["init", "-q", "-b", "main"], &src);
        run(&["config", "user.email", "t@t"], &src);
        run(&["config", "user.name", "t"], &src);
        std::fs::write(src.join("README.md"), "hello\n").unwrap();
        run(&["add", "."], &src);
        run(&["commit", "-q", "-m", "init"], &src);

        let bare = base.join("bare-repo.git");
        let out = std::process::Command::new("git")
            .args([
                "clone",
                "--bare",
                src.to_string_lossy().as_ref(),
                bare.to_string_lossy().as_ref(),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "bare clone failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        bare
    }

    #[test]
    fn create_sandbox_with_workspace_from_clones_repo() {
        if !git_available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let bare = make_bare_repo(tmp.path());
        let data_dir = tmp.path().join("data");

        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("ws-box");
        o.workspace_from = Some(bare.to_string_lossy().to_string());
        let sandbox = store
            .create_sandbox_with_opts(&o, Some(&data_dir))
            .unwrap();

        let ws = sandbox
            .workspace_path
            .as_deref()
            .expect("workspace_path should be set");
        let ws_path = PathBuf::from(ws);
        assert!(ws_path.exists(), "workspace dir {ws_path:?} should exist");
        assert!(
            ws_path.join("README.md").exists(),
            "cloned README.md should exist"
        );
    }

    #[test]
    fn stop_sandbox_removes_workspace_dir() {
        if !git_available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let bare = make_bare_repo(tmp.path());
        let data_dir = tmp.path().join("data");

        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("ws-stop-box");
        o.workspace_from = Some(bare.to_string_lossy().to_string());
        let sandbox = store
            .create_sandbox_with_opts(&o, Some(&data_dir))
            .unwrap();
        let ws = PathBuf::from(sandbox.workspace_path.unwrap());
        assert!(ws.exists());

        store.stop_sandbox(&sandbox.id).unwrap();
        assert!(!ws.exists(), "workspace dir should be removed after stop");
    }

    // ---------- existing docker-gated integration tests ----------

    #[test]
    fn start_container_docker_available() {
        if !docker_available() {
            return;
        }
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store
            .create_sandbox("start-test-box", "alpine:latest")
            .unwrap();
        let socket_dir = PathBuf::from("/tmp/ember-test/run");
        // Use --network=none so this test doesn't need to pull a bridge image.
        let container_id = store
            .start_container(&sandbox.id, &socket_dir, Some("none"), &[])
            .unwrap();
        assert!(!container_id.is_empty());

        let list = store.list_sandboxes().unwrap();
        assert_eq!(list[0].container_id.as_deref(), Some(container_id.as_str()));
        assert_eq!(list[0].status, "running");

        // Clean up
        store.stop_sandbox(&sandbox.id).unwrap();
    }

    #[test]
    fn exec_in_running_container_docker_available() {
        if !docker_available() {
            return;
        }
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store
            .create_sandbox("exec-test-box", "alpine:latest")
            .unwrap();
        let socket_dir = PathBuf::from("/tmp/ember-test/run");
        store
            .start_container(&sandbox.id, &socket_dir, Some("none"), &[])
            .unwrap();

        let output = store.exec_sandbox(&sandbox.id, &["echo", "hello"]).unwrap();
        assert!(output.contains("hello"));

        // Clean up
        store.stop_sandbox(&sandbox.id).unwrap();
    }

    #[test]
    fn stop_sandbox_cascades_grant_revocation() {
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store
            .create_sandbox("grant-cascade-box", "alpine:latest")
            .unwrap();

        // Create a grant for the sandbox's persona
        store
            .create_grant(&sandbox.persona_id, "api-key", "read", None)
            .unwrap();

        // Verify grant is active
        let grant = store
            .evaluate_grant(&sandbox.persona_id, "api-key")
            .unwrap();
        assert_eq!(grant.status, "active");

        // Stop sandbox
        store.stop_sandbox(&sandbox.id).unwrap();

        // Grant should be revoked
        let result = store.evaluate_grant(&sandbox.persona_id, "api-key");
        assert!(result.is_err()); // NotFound because revoked
    }

    #[test]
    fn sandbox_full_lifecycle() {
        let store = DaemonStore::open_in_memory().unwrap();

        // Create
        let sandbox = store
            .create_sandbox("lifecycle-box", "alpine:latest")
            .unwrap();
        assert_eq!(sandbox.status, "created");

        // List
        let list = store.list_sandboxes().unwrap();
        assert_eq!(list.len(), 1);

        // Stop
        store.stop_sandbox(&sandbox.id).unwrap();
        let list = store.list_sandboxes().unwrap();
        assert_eq!(list[0].status, "stopped");

        // Persona revoked
        let persona = store.get_persona(&sandbox.persona_id).unwrap();
        assert_eq!(persona.status, "revoked");
    }
}
