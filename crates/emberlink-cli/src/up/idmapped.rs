//! CLASSIFICATION: PUBLIC
//!
//! idmapped bind-mount detection and spec rendering for per-agent worktrees.
//!
//! ADR 166 Component 4 — each agent container gets its own worktree at
//! `.claude/worktrees/agent-<id>/` bind-mounted at `/work/repo:rw` using
//! idmapped mounts so that host-operator UID ↔ container `agent` UID 1000
//! are translated at the mount layer. No chown; no `safe.directory`; no
//! global userns-remap.
//!
//! Kernel support: Linux 5.12+ (idmapped mounts merged 2021-04-25).
//! Runtime support:
//!   Docker  ≥ 23.0  (--mount type=bind,bind-propagation=shared,uid-map=…)
//!   Podman  ≥ 4.0   (--userns=keep-id or idmap= mount option)
//!   OrbStack any 2024+ version (Docker-compat layer, handles transparently)
//!
//! Older runtimes fall back to `safe.directory` + chown-on-flush per
//! `ARCH-COMPOSE-IDMAPPED-FALLBACK-OLDER-RUNTIMES`.

use std::path::Path;

/// Returns `true` when both the running kernel and the container runtime
/// support idmapped bind-mounts.
///
/// Detection strategy (conservative — any detection failure returns `false`):
///   1. On non-Linux platforms, return `false` immediately (no kernel support).
///   2. Parse `uname -r` for a kernel version ≥ 5.12.
///   3. Probe `docker --version` for Docker ≥ 23.0 OR `podman --version`
///      for Podman ≥ 4.0. Either runtime suffices.
///
/// Returns `false` on any I/O or parse error so the caller always gets a
/// safe fallback rather than a panic.
pub fn supports_idmapped_mounts() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }

    if !kernel_supports_idmapped() {
        return false;
    }

    runtime_supports_idmapped()
}

/// Checks whether the running kernel version is ≥ 5.12.
///
/// Idmapped mounts were merged in Linux 5.12 (mainline, 2021-04-25).
/// Returns `false` on any parse error.
fn kernel_supports_idmapped() -> bool {
    let output = match std::process::Command::new("uname").arg("-r").output() {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };
    let release = match std::str::from_utf8(&output.stdout) {
        Ok(s) => s.trim(),
        Err(_) => return false,
    };
    // Release string: "5.15.0-91-generic" or "6.1.0-orbstack-…"
    // Split on '.' and '-'; we only need MAJOR.MINOR.
    let parts: Vec<&str> = release.splitn(3, '.').collect();
    if parts.len() < 2 {
        return false;
    }
    let major: u32 = match parts[0].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    // Strip any suffix from minor (e.g. "12-generic" → "12").
    let minor_str = parts[1].split('-').next().unwrap_or("");
    let minor: u32 = match minor_str.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    (major, minor) >= (5, 12)
}

/// Returns `true` when Docker ≥ 23.0 or Podman ≥ 4.0 is available.
///
/// Both runtimes expose idmapped mount syntax in Compose by 23.0 / 4.0
/// respectively. OrbStack's Docker-compat layer ≥ any 2024 version passes
/// the Docker ≥ 23.0 check because it reports a Docker-compatible version.
fn runtime_supports_idmapped() -> bool {
    if docker_version_at_least(23, 0) {
        return true;
    }
    if podman_version_at_least(4, 0) {
        return true;
    }
    false
}

/// Parse `docker --version` and return `true` when Docker is ≥ `major.minor`.
///
/// Example output: "Docker version 25.0.3, build 4debf41"
fn docker_version_at_least(need_major: u32, need_minor: u32) -> bool {
    let output = match std::process::Command::new("docker")
        .arg("--version")
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };
    let s = match std::str::from_utf8(&output.stdout) {
        Ok(s) => s,
        Err(_) => return false,
    };
    parse_version_at_least(s, need_major, need_minor)
}

/// Parse `podman --version` and return `true` when Podman is ≥ `major.minor`.
///
/// Example output: "podman version 4.9.3"
fn podman_version_at_least(need_major: u32, need_minor: u32) -> bool {
    let output = match std::process::Command::new("podman")
        .arg("--version")
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };
    let s = match std::str::from_utf8(&output.stdout) {
        Ok(s) => s,
        Err(_) => return false,
    };
    parse_version_at_least(s, need_major, need_minor)
}

/// Extract the first `X.Y` or `X.Y.Z` version token from `text` and compare
/// against `(need_major, need_minor)`. Returns `false` on any parse failure.
fn parse_version_at_least(text: &str, need_major: u32, need_minor: u32) -> bool {
    for token in text.split_whitespace() {
        let digits: Vec<&str> = token.split('.').collect();
        if digits.len() < 2 {
            continue;
        }
        let major: u32 = match digits[0].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let minor_str = digits[1].split('-').next().unwrap_or("");
        let minor: u32 = match minor_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        return (major, minor) >= (need_major, need_minor);
    }
    false
}

/// Produce a Compose-compatible idmapped volume spec string for a per-agent
/// worktree bind-mount.
///
/// `host_path` — absolute path to the agent's worktree on the host (e.g.
///   `/home/operator/.claude/worktrees/agent-abc123/`).
/// `container_path` — mount point inside the container (e.g. `/work/repo`).
/// `host_uid` — the host operator's UID; translated to container UID 1000
///   (`agent` user) at the mount layer.
///
/// Returns a Docker Compose long-form bind spec string, e.g.:
/// ```text
/// type: bind
/// source: /home/operator/.claude/worktrees/agent-abc123
/// target: /work/repo
/// bind:
///   create_host_path: true
///   idmap:
///     uids:
///       - host_uid: 1000
///         container_uid: 1000
///         range: 1
///     gids:
///       - host_gid: 1000
///         container_gid: 1000
///         range: 1
/// ```
///
/// # Podman equivalent
/// Podman uses `--userns=keep-id` or the `:idmap=u:<host_uid>:1000:1` mount
/// suffix: `podman run -v /host/path:/work/repo:idmap=u:<host_uid>:1000:1`.
///
/// # OrbStack equivalent
/// OrbStack's Docker-compat layer passes the Docker idmap spec transparently;
/// no special syntax is required.
pub fn render_idmap_volume_spec(host_path: &Path, container_path: &str, host_uid: u32) -> String {
    let host_path_str = host_path.display();
    format!(
        "type: bind\n\
         source: {host_path_str}\n\
         target: {container_path}\n\
         bind:\n\
           create_host_path: true\n\
           idmap:\n\
             uids:\n\
               - host_uid: {host_uid}\n\
                 container_uid: 1000\n\
                 range: 1\n\
             gids:\n\
               - host_gid: {host_uid}\n\
                 container_gid: 1000\n\
                 range: 1"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn render_idmap_volume_spec_contains_idmapped_keyword() {
        let spec = render_idmap_volume_spec(
            Path::new("/home/operator/.claude/worktrees/agent-abc123"),
            "/work/repo",
            1001,
        );
        assert!(
            spec.contains("idmap"),
            "spec must contain 'idmap' keyword: {spec}"
        );
    }

    #[test]
    fn render_idmap_volume_spec_host_path_present() {
        let host = Path::new("/home/operator/.claude/worktrees/agent-abc123");
        let spec = render_idmap_volume_spec(host, "/work/repo", 1001);
        assert!(
            spec.contains("/home/operator/.claude/worktrees/agent-abc123"),
            "spec must contain host_path: {spec}"
        );
    }

    #[test]
    fn render_idmap_volume_spec_container_path_present() {
        let spec = render_idmap_volume_spec(Path::new("/tmp/worktree"), "/work/repo", 1000);
        assert!(
            spec.contains("/work/repo"),
            "spec must contain container_path: {spec}"
        );
    }

    #[test]
    fn render_idmap_volume_spec_host_uid_mapped_to_1000() {
        let spec = render_idmap_volume_spec(Path::new("/tmp/worktree"), "/work/repo", 5000);
        assert!(
            spec.contains("host_uid: 5000"),
            "spec must contain host_uid: {spec}"
        );
        assert!(
            spec.contains("container_uid: 1000"),
            "spec must contain container_uid 1000: {spec}"
        );
    }

    #[test]
    fn parse_version_at_least_docker_format() {
        assert!(parse_version_at_least(
            "Docker version 25.0.3, build 4debf41",
            23,
            0
        ));
        assert!(parse_version_at_least(
            "Docker version 23.0.0, build abc",
            23,
            0
        ));
        assert!(!parse_version_at_least(
            "Docker version 22.9.0, build abc",
            23,
            0
        ));
    }

    #[test]
    fn parse_version_at_least_podman_format() {
        assert!(parse_version_at_least("podman version 4.9.3", 4, 0));
        assert!(!parse_version_at_least("podman version 3.4.7", 4, 0));
    }

    #[test]
    fn parse_version_at_least_returns_false_on_garbage() {
        assert!(!parse_version_at_least("no version here", 1, 0));
        assert!(!parse_version_at_least("", 1, 0));
    }

    #[test]
    fn parse_version_at_least_boundary() {
        assert!(parse_version_at_least("5.12.0", 5, 12));
        assert!(parse_version_at_least("5.13.0", 5, 12));
        assert!(!parse_version_at_least("5.11.0", 5, 12));
    }
}
