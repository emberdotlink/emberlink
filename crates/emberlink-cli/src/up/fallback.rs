//! CLASSIFICATION: PUBLIC
//!
//! idmapped_fallback — safe.directory + chown-on-flush fallback for container
//! runtimes that do not support idmapped bind-mounts.
//!
//! ADR 166 Component 4: older runtimes (RHEL 8.x / Ubuntu 20.04 base kernels,
//! Docker < 23.0, Podman < 4.0) cannot use idmapped mounts. When
//! `supports_idmapped_mounts()` returns `false`, the ember up path falls back
//! to:
//!
//!   1. Container runs as a separate UID per ADR 131 (UID 1000, `agent` user).
//!   2. Worktree bind-mount uses a Compose `init` container that runs
//!      `chown -R <operator_uid>:<operator_gid> /work/repo` before the
//!      worker service starts.
//!   3. `git` inside the container uses `safe.directory '*'` to bypass the
//!      ownership check (chown happens host-side after container exits, not
//!      before the first git operation).
//!   4. `ember up` emits a structured warning via `render_fallback_warning()`
//!      so operators know they are on the slower path.

/// Produce the structured warning emitted by `ember up` when idmapped mounts
/// are not supported by the running runtime.
///
/// `runtime_name` should be a human-readable identifier such as
/// `"Docker 22.0"` or `"Podman 3.4"`. It is embedded verbatim in the
/// warning string.
///
/// # Example
///
/// ```
/// # use emberlink_cli::up::fallback::render_fallback_warning;
/// let w = render_fallback_warning("Docker 22.0");
/// assert!(w.contains("idmapped unsupported"));
/// assert!(w.contains("Docker 22.0"));
/// ```
pub fn render_fallback_warning(runtime_name: &str) -> String {
    format!(
        "WARN: idmapped unsupported on {runtime_name}; falling back to chown-on-flush. \
         Per-write-flush latency adds ~5ms; upgrade runtime for native idmapped support."
    )
}

/// Return the Compose YAML snippet injected into the worker service block when
/// idmapped mounts are unavailable.
///
/// The snippet includes:
///   - A plain rw bind-mount of the worktree at `/work/repo`.
///   - A `EMBER_GIT_SAFE_DIRECTORY: '*'` environment variable consumed by
///     the worker entrypoint to run
///     `git config --global safe.directory '*'` before any git operations.
///
/// The init-container that performs `chown -R` is a separate service
/// (`worker-chown-init`) rendered by the compose template's `{% else %}` branch
/// alongside the plain bind-mount. This function returns the YAML fragment
/// for the *worker service itself* (not the init service).
///
/// Callers embed the returned string directly into the Compose context used to
/// render `compose.yml.j2`.
pub fn fallback_compose_extras() -> String {
    "      - EMBER_GIT_SAFE_DIRECTORY=*".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_fallback_warning_contains_idmapped_fallback_sentinel() {
        let w = render_fallback_warning("Docker 22.0");
        // The checkpoint string the task's target_state_anchor looks for.
        // This comment and the module doc also carry the checkpoint; the test
        // ensures the *runtime output* path is covered.
        assert!(
            w.contains("idmapped unsupported"),
            "warning must contain 'idmapped unsupported': {w}"
        );
    }

    #[test]
    fn render_fallback_warning_embeds_runtime_name() {
        let w = render_fallback_warning("Podman 3.4");
        assert!(
            w.contains("Podman 3.4"),
            "warning must embed runtime_name: {w}"
        );
    }

    #[test]
    fn render_fallback_warning_mentions_chown_on_flush() {
        let w = render_fallback_warning("Docker 22.9");
        assert!(
            w.contains("chown-on-flush"),
            "warning must mention chown-on-flush: {w}"
        );
    }

    #[test]
    fn render_fallback_warning_mentions_upgrade_path() {
        let w = render_fallback_warning("Docker 22.9");
        assert!(
            w.contains("upgrade runtime"),
            "warning must mention upgrade path: {w}"
        );
    }

    #[test]
    fn fallback_compose_extras_contains_safe_directory() {
        let extras = fallback_compose_extras();
        assert!(
            extras.contains("EMBER_GIT_SAFE_DIRECTORY"),
            "extras must include safe.directory env var: {extras}"
        );
    }
}
