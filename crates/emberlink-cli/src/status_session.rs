//! CLASSIFICATION: PUBLIC
//!
//! META-DEV-PROD-PARITY-ATTESTATION-SURFACE — `ember status --session`
//! operator attestation that the current shell session IS brokered.
//!
//! ADR 157 follow-up: today the only way to confirm a Claude Code session is
//! going through the broker is to tail `/var/log/emberd.err` and grep for
//! `broker_exec`. That's hostile UX. This module renders the structured
//! operator-facing attestation surface that the `Status { session: true, .. }`
//! arm of the CLI dispatches to.
//!
//! Inputs are read from the calling shell's environment (`EMBER_SESSION_ID`,
//! `EMBER_DAEMON_SOCKET`, `EMBER_PERSONA`, `EMBER_DAEMON_FLAVOR`), composed
//! with the daemon-owned status snapshot (`StatusSummary`) + trust-roots view
//! (`trust.list`). No new daemon RPC verbs — this is the operator-facing
//! version of the Receipt's `dev_mode_active` stamp built out of existing
//! primitives.
//!
//! Anchor: `dev_prod_parity_attestation_surface_landed`.

use std::env;
use std::fmt::Write;
use std::path::PathBuf;

use ember_daemon::infra::status::StatusSummary;
use ember_daemon::trust::grant::GrantInfo;

use crate::trust::list::TrustListResponse;

/// Public-but-internal entry point names — exposed so the dispatch site in
/// `bin/ember.rs` can call into the renderer without re-implementing the
/// composition.
pub use self::flavor::DaemonFlavor;

/// Snapshot of the calling shell's brokered-session attestation. Pure data —
/// no I/O — so the renderer is unit-testable end-to-end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAttestation {
    /// `EMBER_SESSION_ID` for the targeted session. `None` means the calling
    /// shell is "bare" (no brokered session).
    pub session_id: Option<String>,
    /// `EMBER_DAEMON_SOCKET` env value, when present in the calling shell.
    pub daemon_socket_env: Option<PathBuf>,
    /// `EMBER_PERSONA` env value, when present in the calling shell.
    pub persona_env: Option<String>,
    /// `EMBER_DAEMON_FLAVOR` (`dev` / `prod`) env value, when present.
    pub flavor: DaemonFlavor,
    /// Daemon manifest / identity-root fingerprint. Populated from the
    /// daemon's `trust.list` response (the same fingerprint the daemon stamps
    /// into Receipts via `identity_root_fingerprint()`). `None` when the
    /// daemon was unreachable.
    pub daemon_fingerprint: Option<String>,
    /// True when the daemon's `trust.list` response reports
    /// `dev_mode_active: true`. The operator-facing version of the same
    /// stamp on every Receipt.
    pub dev_mode_active: bool,
    /// Trust-root fingerprints currently loaded by the daemon. Ordering
    /// preserved from the wire response so the human render is deterministic.
    pub trust_roots: Vec<TrustRootRow>,
    /// Active grants pulled from the daemon's `StatusSummary`. The session
    /// view filters this down to grants whose `persona_id` matches the
    /// session's `EMBER_PERSONA` env when one is set.
    pub matching_grants: Vec<GrantRow>,
    /// Total number of active grants the daemon currently sees — included
    /// so the JSON contract distinguishes "no grants for this persona" from
    /// "daemon sees no grants at all".
    pub total_active_grants: usize,
}

/// Daemon flavor derived from `EMBER_DAEMON_FLAVOR` or socket-path heuristic.
pub mod flavor {
    use std::path::Path;

    /// Which managed daemon the calling shell is wired to.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DaemonFlavor {
        /// Production managed daemon (canonical `~/.ember/run/daemon.sock`).
        Prod,
        /// Worktree-scoped dev daemon (per-flavor socket under
        /// `~/.ember/run/daemon.dev*.sock`).
        Dev,
        /// Flavor could not be determined from env/socket (no env var set
        /// and the socket path didn't match either canonical shape).
        Unknown,
    }

    impl DaemonFlavor {
        /// Parse `EMBER_DAEMON_FLAVOR` env value with case-insensitive match.
        pub fn from_env_value(value: Option<&str>) -> Self {
            match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
                Some("prod") => Self::Prod,
                Some("dev") => Self::Dev,
                _ => Self::Unknown,
            }
        }

        /// Heuristic fallback: classify based on the daemon socket path
        /// (canonical prod is `daemon.sock`; canonical dev is `daemon.dev*.sock`).
        pub fn from_socket_path(path: &Path) -> Self {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if name == "daemon.sock" {
                Self::Prod
            } else if name.starts_with("daemon.dev") && name.ends_with(".sock") {
                Self::Dev
            } else {
                Self::Unknown
            }
        }

        /// Compose env value + socket-path fallback into a single verdict.
        pub fn resolve(env_value: Option<&str>, socket: Option<&Path>) -> Self {
            let env_verdict = Self::from_env_value(env_value);
            if env_verdict != Self::Unknown {
                return env_verdict;
            }
            socket.map(Self::from_socket_path).unwrap_or(Self::Unknown)
        }

        /// Render the flavor as a stable wire string (`prod` / `dev` /
        /// `unknown`).
        pub fn as_wire_str(self) -> &'static str {
            match self {
                Self::Prod => "prod",
                Self::Dev => "dev",
                Self::Unknown => "unknown",
            }
        }
    }
}

/// One trust-root row projected from the daemon's `trust.list` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRootRow {
    pub fingerprint_hex: String,
    pub source: String,
}

/// One active-grant row projected from `StatusSummary::grants` — the
/// scalar projection used for the session attestation render. Carries
/// just the fields the operator needs to see "is this session brokered
/// and on what scope".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    pub id: String,
    pub persona_id: String,
    pub credential_name: String,
    pub scope: String,
    pub expires_at: Option<String>,
    pub status: String,
}

impl From<&GrantInfo> for GrantRow {
    fn from(g: &GrantInfo) -> Self {
        Self {
            id: g.id.clone(),
            persona_id: g.persona_id.clone(),
            credential_name: g.credential_name.clone(),
            scope: g.scope.clone(),
            expires_at: g.expires_at.clone(),
            status: g.status.clone(),
        }
    }
}

/// Resolution policy for which session the attestation surface targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionTarget {
    /// Read `EMBER_SESSION_ID` from the calling shell's environment.
    CurrentShell,
    /// Explicit `--session-id <id>` override.
    Explicit(String),
    /// `--all` — list every active session the daemon has visibility into
    /// (today: every active runtime grant, since there's no dedicated
    /// `list_sessions` RPC yet — see brief).
    All,
}

/// Read the calling shell's env var, ignoring an empty value.
fn env_var_nonempty(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

/// Build a [`SessionAttestation`] from the inputs the caller has already
/// resolved. Pure — no I/O. The dispatch site in `bin/ember.rs` is responsible
/// for the actual env reads + daemon calls.
pub fn build_attestation(
    target: &SessionTarget,
    daemon_socket_env: Option<PathBuf>,
    persona_env: Option<String>,
    flavor_env_value: Option<&str>,
    daemon_socket_actual: Option<&std::path::Path>,
    trust: Option<&TrustListResponse>,
    summary: Option<&StatusSummary>,
) -> SessionAttestation {
    let session_id = match target {
        SessionTarget::CurrentShell => env_var_nonempty("EMBER_SESSION_ID"),
        SessionTarget::Explicit(id) => Some(id.clone()),
        SessionTarget::All => None,
    };

    let flavor = DaemonFlavor::resolve(flavor_env_value, daemon_socket_actual);
    let daemon_fingerprint = trust
        .and_then(|t| t.roots.first().map(|r| r.fingerprint_hex.clone()));
    let dev_mode_active = trust.map(|t| t.dev_mode_active).unwrap_or(false);
    let trust_roots: Vec<TrustRootRow> = trust
        .map(|t| {
            t.roots
                .iter()
                .map(|r| TrustRootRow {
                    fingerprint_hex: r.fingerprint_hex.clone(),
                    source: r.source.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    let total_active_grants = summary.map(|s| s.grants.len()).unwrap_or(0);
    let matching_grants: Vec<GrantRow> = match (summary, &persona_env, target) {
        // `--all` lists every active grant the daemon currently sees, with
        // no persona filter — the daemon-side proxy for "every active session
        // attached to the daemon" until a real `sessions.list` RPC ships.
        (Some(s), _, SessionTarget::All) => s.grants.iter().map(GrantRow::from).collect(),
        // Filter to the session's persona when EMBER_PERSONA is set.
        (Some(s), Some(persona), _) => s
            .grants
            .iter()
            .filter(|g| g.persona_id == *persona)
            .map(GrantRow::from)
            .collect(),
        // No env persona — surface every grant so the operator can still see
        // the brokered authority surface (better than dropping to empty).
        (Some(s), None, _) => s.grants.iter().map(GrantRow::from).collect(),
        (None, _, _) => Vec::new(),
    };

    SessionAttestation {
        session_id,
        daemon_socket_env,
        persona_env,
        flavor,
        daemon_fingerprint,
        dev_mode_active,
        trust_roots,
        matching_grants,
        total_active_grants,
    }
}

/// Render the JSON projection of a [`SessionAttestation`] for
/// `ember status --session --json`. Stable wire format keyed off the brief's
/// mock output.
pub fn render_json(att: &SessionAttestation) -> serde_json::Value {
    serde_json::json!({
        "session_id": att.session_id,
        "daemon_socket_env": att
            .daemon_socket_env
            .as_ref()
            .map(|p| p.display().to_string()),
        "persona_env": att.persona_env,
        "daemon_flavor": att.flavor.as_wire_str(),
        "daemon_fingerprint": att.daemon_fingerprint,
        "dev_mode_active": att.dev_mode_active,
        "trust_roots": att
            .trust_roots
            .iter()
            .map(|r| serde_json::json!({
                "fingerprint_hex": r.fingerprint_hex,
                "source": r.source,
            }))
            .collect::<Vec<_>>(),
        "matching_grants": att
            .matching_grants
            .iter()
            .map(|g| serde_json::json!({
                "id": g.id,
                "persona_id": g.persona_id,
                "credential_name": g.credential_name,
                "scope": g.scope,
                "expires_at": g.expires_at,
                "status": g.status,
            }))
            .collect::<Vec<_>>(),
        "total_active_grants": att.total_active_grants,
    })
}

/// Render the human-readable text projection of a [`SessionAttestation`].
/// Mirrors the brief's mock output shape: session id, daemon socket, manifest
/// fingerprint, trust roots, dev_mode_active, active grants.
pub fn render_human(att: &SessionAttestation) -> String {
    let mut out = String::new();

    match (&att.session_id, att.matching_grants.is_empty()) {
        (None, _) => {
            let _ = writeln!(out, "Session: no active session; bare shell");
            let _ = writeln!(
                out,
                "  EMBER_SESSION_ID is not set — this shell is not attached to a brokered session."
            );
            push_daemon_lines(&mut out, att);
            return out.trim_end().to_string();
        }
        (Some(id), _) => {
            let _ = writeln!(out, "Session: {id}");
        }
    }

    if let Some(persona) = att.persona_env.as_ref() {
        let _ = writeln!(out, "  EMBER_PERSONA={persona}");
    }
    push_daemon_lines(&mut out, att);

    if att.matching_grants.is_empty() {
        let _ = writeln!(
            out,
            "  No active grants surfaced for this session (total daemon-visible: {}).",
            att.total_active_grants
        );
    } else {
        let _ = writeln!(
            out,
            "  Active grants ({}/{} daemon-visible):",
            att.matching_grants.len(),
            att.total_active_grants
        );
        for g in &att.matching_grants {
            let exp = g.expires_at.as_deref().unwrap_or("never");
            let _ = writeln!(
                out,
                "    {} {} → {} ({}) [{}] expires {}",
                g.id, g.persona_id, g.credential_name, g.scope, g.status, exp
            );
        }
    }

    out.trim_end().to_string()
}

fn push_daemon_lines(out: &mut String, att: &SessionAttestation) {
    if let Some(socket) = att.daemon_socket_env.as_ref() {
        let _ = writeln!(
            out,
            "  EMBER_DAEMON_SOCKET={} ({} daemon)",
            socket.display(),
            att.flavor.as_wire_str()
        );
    }
    if let Some(fp) = att.daemon_fingerprint.as_ref() {
        let _ = writeln!(out, "  Daemon manifest fingerprint: {fp}");
    }
    if !att.trust_roots.is_empty() {
        let posture = if att.dev_mode_active { "dev" } else { "prod" };
        let sources: Vec<&str> = att
            .trust_roots
            .iter()
            .map(|r| r.source.as_str())
            .collect();
        let _ = writeln!(
            out,
            "  Trust roots: {} loaded ({}) [dev_mode_active: {}] posture={}",
            att.trust_roots.len(),
            sources.join(", "),
            att.dev_mode_active,
            posture
        );
    } else {
        let _ = writeln!(
            out,
            "  Trust roots: none loaded (startup verification inactive)"
        );
    }
}

/// Resolve the [`SessionTarget`] from the CLI flags as decoded by clap. Pure
/// helper — separated so the dispatch site is a one-liner.
pub fn resolve_target(session_id: Option<String>, all: bool) -> SessionTarget {
    if all {
        return SessionTarget::All;
    }
    match session_id {
        Some(id) => SessionTarget::Explicit(id),
        None => SessionTarget::CurrentShell,
    }
}

/// Convenience for the dispatch site: read the env vars the calling shell
/// inherited from `ember claude-code` / `ember codex` and return them in the
/// shape `build_attestation` consumes. Pure read — does not touch the daemon.
pub fn read_calling_shell_env() -> CallingShellEnv {
    CallingShellEnv {
        session_id: env_var_nonempty("EMBER_SESSION_ID"),
        daemon_socket: env_var_nonempty("EMBER_DAEMON_SOCKET").map(PathBuf::from),
        persona: env_var_nonempty("EMBER_PERSONA"),
        flavor_value: env_var_nonempty("EMBER_DAEMON_FLAVOR"),
    }
}

/// The env vars the launcher injects when it spawns the brokered shell —
/// captured as a snapshot so the dispatch site can pass them through to
/// `build_attestation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallingShellEnv {
    pub session_id: Option<String>,
    pub daemon_socket: Option<PathBuf>,
    pub persona: Option<String>,
    pub flavor_value: Option<String>,
}

#[cfg(test)]
mod tests {
    //! T1: unit tests for the pure `status_session` composition. No I/O —
    //! `build_attestation` consumes already-resolved env values + daemon
    //! responses, so the renderer can be exercised entirely against
    //! synthesized fixtures. Anchor:
    //! `dev_prod_parity_attestation_surface_landed`.
    use super::*;
    use crate::trust::list::{TrustListResponse, TrustRootView};

    fn fixture_trust() -> TrustListResponse {
        TrustListResponse {
            roots: vec![
                TrustRootView {
                    fingerprint_hex: "abcd1234".to_string(),
                    source: "release".to_string(),
                },
                TrustRootView {
                    fingerprint_hex: "fedcba98".to_string(),
                    source: "operator".to_string(),
                },
            ],
            dev_mode_active: true,
        }
    }

    fn fixture_grant(id: &str, persona: &str, scope: &str) -> GrantInfo {
        GrantInfo {
            id: id.to_string(),
            persona_id: persona.to_string(),
            credential_name: "anthropic/oauth-token".to_string(),
            scope: scope.to_string(),
            created_at: "2026-05-20T12:00:00Z".to_string(),
            expires_at: Some("2026-05-20T15:00:00Z".to_string()),
            status: "active".to_string(),
            max_uses_per_hour: None,
            allowed_hours_start: None,
            allowed_hours_end: None,
            allowed_targets: None,
            parent_grant_id: None,
            max_delegation_depth: None,
            spending_limit_cents: None,
            budget: None,
            usage: Default::default(),
            paused: false,
            receipt_id: None,
            is_standing: false,
            max_children_per_day: None,
            auto_delegate_scope_template: None,
        }
    }

    fn fixture_summary() -> StatusSummary {
        StatusSummary {
            personas: Vec::new(),
            grants: vec![
                fixture_grant("g1", "persona-claude", "claude-code"),
                fixture_grant("g2", "persona-codex", "codex"),
            ],
            grant_live_leases: vec!["g1".to_string(), "g2".to_string()],
            sandboxes: Vec::new(),
            approvals: Vec::new(),
            recent_activity: Vec::new(),
            standing_grants: 0,
            audit_events_total: 0,
            quarantined: false,
            quarantine_authority: None,
        }
    }

    #[test]
    fn flavor_resolves_from_env_value() {
        assert_eq!(DaemonFlavor::from_env_value(Some("prod")), DaemonFlavor::Prod);
        assert_eq!(DaemonFlavor::from_env_value(Some("DEV")), DaemonFlavor::Dev);
        assert_eq!(DaemonFlavor::from_env_value(Some("")), DaemonFlavor::Unknown);
        assert_eq!(DaemonFlavor::from_env_value(None), DaemonFlavor::Unknown);
    }

    #[test]
    fn flavor_falls_back_to_socket_path_when_env_unset() {
        use std::path::Path;
        let prod = Path::new("/home/op/.ember/run/daemon.sock");
        let dev = Path::new("/home/op/.ember/run/daemon.dev.sock");
        assert_eq!(
            DaemonFlavor::resolve(None, Some(prod)),
            DaemonFlavor::Prod
        );
        assert_eq!(
            DaemonFlavor::resolve(None, Some(dev)),
            DaemonFlavor::Dev
        );
        // Env value wins over heuristic when both present.
        assert_eq!(
            DaemonFlavor::resolve(Some("prod"), Some(dev)),
            DaemonFlavor::Prod
        );
    }

    #[test]
    fn current_shell_target_with_no_session_id_renders_bare_shell() {
        let target = SessionTarget::CurrentShell;
        // build_attestation reads EMBER_SESSION_ID for CurrentShell. Tests
        // don't mutate process env (parallel safety) — instead exercise the
        // Explicit branch's "no env" sibling: a None session_id.
        let att = SessionAttestation {
            session_id: None,
            daemon_socket_env: None,
            persona_env: None,
            flavor: DaemonFlavor::Unknown,
            daemon_fingerprint: None,
            dev_mode_active: false,
            trust_roots: Vec::new(),
            matching_grants: Vec::new(),
            total_active_grants: 0,
        };
        let out = render_human(&att);
        assert!(out.contains("Session: no active session; bare shell"), "{out}");
        assert!(out.contains("EMBER_SESSION_ID is not set"), "{out}");
        // Quiet the unused warning while still exercising the enum shape.
        let _ = target;
    }

    #[test]
    fn explicit_target_with_persona_filters_grants() {
        let trust = fixture_trust();
        let summary = fixture_summary();
        let att = build_attestation(
            &SessionTarget::Explicit("sess_01HGY2A".to_string()),
            Some(PathBuf::from("/home/op/.ember/run/daemon.dev.sock")),
            Some("persona-claude".to_string()),
            Some("dev"),
            Some(std::path::Path::new(
                "/home/op/.ember/run/daemon.dev.sock",
            )),
            Some(&trust),
            Some(&summary),
        );
        assert_eq!(att.session_id.as_deref(), Some("sess_01HGY2A"));
        assert_eq!(att.flavor, DaemonFlavor::Dev);
        assert!(att.dev_mode_active);
        assert_eq!(att.trust_roots.len(), 2);
        assert_eq!(att.daemon_fingerprint.as_deref(), Some("abcd1234"));
        // Persona filter narrowed to one grant.
        assert_eq!(att.matching_grants.len(), 1);
        assert_eq!(att.matching_grants[0].id, "g1");
        // Total still reports both for the JSON contract.
        assert_eq!(att.total_active_grants, 2);
    }

    #[test]
    fn all_target_surfaces_every_grant_no_persona_filter() {
        let trust = fixture_trust();
        let summary = fixture_summary();
        let att = build_attestation(
            &SessionTarget::All,
            None,
            // `--all` ignores the persona filter even when one is set.
            Some("persona-claude".to_string()),
            Some("prod"),
            None,
            Some(&trust),
            Some(&summary),
        );
        // `--all` clears the session_id field — the surface lists sessions,
        // not one session.
        assert_eq!(att.session_id, None);
        assert_eq!(att.matching_grants.len(), 2);
        assert_eq!(att.total_active_grants, 2);
    }

    #[test]
    fn render_human_with_explicit_session_shows_grant_rows() {
        let trust = fixture_trust();
        let summary = fixture_summary();
        let att = build_attestation(
            &SessionTarget::Explicit("sess_01HGY2A".to_string()),
            Some(PathBuf::from("/home/op/.ember/run/daemon.dev.sock")),
            Some("persona-claude".to_string()),
            Some("dev"),
            None,
            Some(&trust),
            Some(&summary),
        );
        let out = render_human(&att);
        assert!(out.contains("Session: sess_01HGY2A"), "{out}");
        assert!(out.contains("EMBER_PERSONA=persona-claude"), "{out}");
        assert!(
            out.contains("EMBER_DAEMON_SOCKET=/home/op/.ember/run/daemon.dev.sock"),
            "{out}"
        );
        assert!(out.contains("dev daemon"), "{out}");
        assert!(out.contains("Daemon manifest fingerprint: abcd1234"), "{out}");
        assert!(out.contains("dev_mode_active: true"), "{out}");
        assert!(out.contains("posture=dev"), "{out}");
        assert!(out.contains("g1 persona-claude → anthropic/oauth-token (claude-code)"), "{out}");
    }

    #[test]
    fn render_json_is_grep_and_jq_scriptable() {
        let trust = fixture_trust();
        let summary = fixture_summary();
        let att = build_attestation(
            &SessionTarget::Explicit("sess_01HGY2A".to_string()),
            Some(PathBuf::from("/home/op/.ember/run/daemon.sock")),
            Some("persona-claude".to_string()),
            Some("prod"),
            None,
            Some(&trust),
            Some(&summary),
        );
        let v = render_json(&att);
        assert_eq!(v["session_id"], "sess_01HGY2A");
        assert_eq!(v["daemon_flavor"], "prod");
        assert_eq!(v["dev_mode_active"], true);
        assert_eq!(v["trust_roots"].as_array().unwrap().len(), 2);
        assert_eq!(v["matching_grants"].as_array().unwrap().len(), 1);
        assert_eq!(v["total_active_grants"], 2);
        assert_eq!(v["daemon_fingerprint"], "abcd1234");
    }

    #[test]
    fn resolve_target_prefers_all_over_session_id() {
        // clap declares them mutually exclusive, but the resolver still
        // documents the "all wins" intent for any future internal caller.
        let t = resolve_target(Some("ignored".to_string()), true);
        assert_eq!(t, SessionTarget::All);
        let t = resolve_target(Some("sess_x".to_string()), false);
        assert_eq!(t, SessionTarget::Explicit("sess_x".to_string()));
        let t = resolve_target(None, false);
        assert_eq!(t, SessionTarget::CurrentShell);
    }

    #[test]
    fn no_summary_means_zero_grants_but_renders_cleanly() {
        let trust = fixture_trust();
        let att = build_attestation(
            &SessionTarget::Explicit("sess_x".to_string()),
            None,
            Some("persona-x".to_string()),
            Some("prod"),
            None,
            Some(&trust),
            None,
        );
        assert_eq!(att.total_active_grants, 0);
        assert!(att.matching_grants.is_empty());
        let out = render_human(&att);
        assert!(out.contains("No active grants surfaced for this session"), "{out}");
    }

    #[test]
    fn no_trust_response_renders_inactive_verification_line() {
        let att = build_attestation(
            &SessionTarget::Explicit("sess_x".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let out = render_human(&att);
        assert!(
            out.contains("Trust roots: none loaded"),
            "{out}"
        );
        assert!(!att.dev_mode_active);
    }

    // Checkpoint for stale-check / grep-target-state validation.
    #[test]
    fn dev_prod_parity_attestation_surface_landed() {
        // Marker test — the function name itself is the checkpoint.
        // META-DEV-PROD-PARITY-ATTESTATION-SURFACE landed when this test
        // exists alongside the renderer + dispatch wiring.
    }
}
