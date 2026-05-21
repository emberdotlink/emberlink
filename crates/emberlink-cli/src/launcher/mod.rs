//! Subprocess launchers for friendly-dev integrations (`ember claude-code`).
//!
//! Per design §2 / implementation-note-478: thin wrappers that register a session with
//! the daemon, inject the appropriate env vars, and `exec` the upstream
//! binary. Today the daemon round-trip is stubbed (real RPC lands in
//! implementation-note-87 / implementation-note-334); the env shape and exit semantics are locked
//! here so the rest of the cohort A flow can call this surface from day
//! one without re-shaping the launcher when the stubs are filled in.

pub mod banner;
pub mod claude_code;
pub mod path_shadow;
pub mod presence;
pub mod session_prefs;

/// Default persona id for a runtime in the locked 2-slot Persona schema
/// (CONTEXT.md "Identity surface" §Persona ID schema): `<runtime>-<context>`.
///
/// `runtime` names the launcher surface (`claude-code`, `headless`).
/// `ctx` is the worktree directory name when the caller resolved one
/// (e.g. via the future `-w` flag), or `None` when no worktree-specific
/// context applies — yielding the suffix `default`.
///
/// implementation-note-483 checkpoint.
pub fn default_persona_id_for_runtime(runtime: &str, ctx: Option<&str>) -> String {
    format!("{}-{}", runtime, ctx.unwrap_or("default"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_persona_id_for_runtime_uses_default_when_ctx_none() {
        assert_eq!(
            default_persona_id_for_runtime("claude-code", None),
            "claude-code-default"
        );
        assert_eq!(
            default_persona_id_for_runtime("headless", None),
            "headless-default"
        );
    }

    #[test]
    fn default_persona_id_for_runtime_uses_ctx_when_present() {
        assert_eq!(
            default_persona_id_for_runtime("claude-code", Some("headless")),
            "claude-code-headless"
        );
        assert_eq!(
            default_persona_id_for_runtime("headless", Some("review-branch")),
            "headless-review-branch"
        );
    }

    #[test]
    fn default_persona_id_for_runtime_preserves_runtime_verbatim() {
        // The runtime slot is emitted as-is — callers own normalization.
        assert_eq!(
            default_persona_id_for_runtime("Claude-Code", None),
            "Claude-Code-default"
        );
    }
}
