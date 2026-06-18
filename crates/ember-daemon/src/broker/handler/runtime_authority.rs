//! Runtime authority handlers for live broker attachment state.
//!
//! This Module owns authority state that changes with a live caller or
//! runtime: PID watcher auto-revocation, credential-binding admin RPCs,
//! Operator Presence failure handling, per-cohort presence fallback decisions,
//! the retired presence-proof dispatcher, and the refresh-cert denial shape.
//! Keeping these seams out of `handler.rs` gives future work a focused test
//! surface for live authority behavior without loading the broker_exec body.

use std::cell::RefCell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use core_broker::BrokerIssueParams;
use core_personas::MtlsPrincipal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::infra::rate_limit::RateLimiter;
use crate::infra::store::DaemonStore;
use crate::infra::store::StoreError;

use super::{
    BrokerRegistry, check_principal_against_persona, check_principal_namespace_inodes,
    current_registry, log_legacy_socket_resolution, revoke_with_registry,
};

// ---------------------------------------------------------------------------
// PID watcher — auto-revoke grants on child shell exit
// ---------------------------------------------------------------------------

/// In-flight PID watcher entries. Each entry maps a watched OS PID to the
/// set of materialization IDs that should be revoked when that PID exits.
static PID_WATCHERS: once_cell::sync::Lazy<std::sync::Mutex<Vec<PidWatcherEntry>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(Vec::new()));

#[derive(Debug, Clone)]
struct PidWatcherEntry {
    pid: u32,
}

/// Wire shape for `broker_register_pid_watcher` RPC params.
#[derive(Debug, serde::Deserialize)]
pub struct RegisterPidWatcherRequest {
    /// OS PID of the child shell to watch.
    pub pid: u32,
    /// Materialization IDs to revoke when `pid` exits.
    pub materialization_ids: Vec<String>,
}

/// Handle the `broker_register_pid_watcher` socket RPC.
///
/// Registers a child shell PID with the daemon. A background task polls
/// `/proc/<pid>` (Linux) or uses `kill(pid, 0)` (portable) to detect
/// process exit; on exit, the daemon calls `broker_revoke` for all listed
/// materialization IDs and removes the entry.
///
/// This is the daemon-side half of `ember broker issue --inject`. The CLI
/// spawns the child shell, then calls this RPC to register it. When the
/// shell exits the daemon auto-revokes the grants, recorded via
/// `broker_revocation` Receipt events.
///
/// // ember broker issue --grants-file
pub async fn handle_broker_register_pid_watcher(
    _store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let req: RegisterPidWatcherRequest = serde_json::from_value(params.clone()).map_err(|e| {
        (
            -32602,
            format!("invalid broker_register_pid_watcher params: {e}"),
        )
    })?;

    if req.materialization_ids.is_empty() {
        return Err((-32602, "materialization_ids must not be empty".to_string()));
    }

    let entry = PidWatcherEntry { pid: req.pid };

    {
        let mut watchers = PID_WATCHERS.lock().expect("pid_watchers mutex");
        // De-duplicate: replace any existing entry for the same PID.
        watchers.retain(|w| w.pid != req.pid);
        watchers.push(entry);
    }

    // Spawn a background polling task on the LocalSet. The task runs
    // independently and auto-revokes when it detects the PID has exited.
    // DaemonStore is not Clone/Send, so the task opens a fresh in-memory
    // store for receipt emission; the registry state is cleaned up correctly.
    let mat_ids = req.materialization_ids.clone();
    let pid = req.pid;
    tokio::task::spawn_local(async move {
        poll_pid_until_exit(pid, &mat_ids).await;
        // Remove from watcher list after revocation.
        let mut watchers = PID_WATCHERS.lock().expect("pid_watchers mutex");
        watchers.retain(|w| w.pid != pid);
    });

    tracing::info!(
        pid = pid,
        count = req.materialization_ids.len(),
        "broker_register_pid_watcher: watching PID for auto-revoke"
    );

    Ok(serde_json::json!({
        "registered": true,
        "pid": pid,
        "materialization_ids": req.materialization_ids,
    }))
}

/// Poll until `pid` is no longer alive, then revoke all associated
/// materializations via the registry.
///
/// Opens a fresh in-memory `DaemonStore` for receipt emission in the
/// background task. The registry state is cleaned up correctly regardless;
/// production receipt persistence uses the primary store via the main handler.
async fn poll_pid_until_exit(pid: u32, mat_ids: &[String]) {
    use tokio::time::{Duration, sleep};

    // Poll every 500 ms. For a user shell this is imperceptible latency.
    let poll_interval = Duration::from_millis(500);

    loop {
        sleep(poll_interval).await;
        if !pid_is_alive(pid) {
            break;
        }
    }

    tracing::info!(
        pid = pid,
        "broker pid_watcher: PID exited — revoking {} grants",
        mat_ids.len()
    );

    // Open a transient in-memory store for receipt emission in this
    // background task. The registry cleanup (drop_active) is what matters
    // for state correctness; the receipt row goes to this ephemeral store.
    let ephemeral_store = match DaemonStore::open_in_memory() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                pid = pid,
                error = %e,
                "broker pid_watcher: could not open ephemeral store; revocation receipt skipped"
            );
            // Still clean up the registry entries even without a store.
            if let Some(registry) = current_registry() {
                for mid in mat_ids {
                    registry.drop_active(mid);
                }
            }
            return;
        }
    };

    // Revoke each materialization. Best-effort: continue on individual failures.
    if let Some(registry) = current_registry() {
        for mid in mat_ids {
            let params = serde_json::json!({ "materialization_id": mid });
            match revoke_with_registry(registry, &ephemeral_store, &params).await {
                Ok(_) => {
                    tracing::info!(
                        materialization_id = %mid,
                        pid = pid,
                        "broker pid_watcher: auto-revoked grant"
                    );
                }
                Err((code, msg)) => {
                    tracing::warn!(
                        materialization_id = %mid,
                        pid = pid,
                        code = code,
                        error = %msg,
                        "broker pid_watcher: auto-revoke failed (may already be revoked)"
                    );
                }
            }
        }
    } else {
        tracing::warn!(
            pid = pid,
            "broker pid_watcher: registry not available; skipping auto-revoke"
        );
    }
}

// ---------------------------------------------------------------------------
// Credential-binding admin RPCs.
//
// `ember bind {register, list, remove, move}` invokes these handlers via the
// daemon's JSON-lines socket. The admin path does NOT require biometric:
// the operator has already authenticated to the daemon via the kernel-
// attested PeerCred principal, and this verb is an EXPLICIT admin action.
// (Biometric will gate the TOFU flow shipped in DCC-3, not this verb.)
//
// Each handler:
//   1. Pulls `caller_persona` from the payload and refuses on missing /
//      nil / un-parseable UUID with `-32602` (Invalid params).
//   2. Calls the CRUD helper in `crate::broker::bindings`.
//   3. Emits an audit event via `store.log_event` so the operator can
//      reconstruct the binding-mutation timeline alongside other broker
//      audit rows.
//
// ---------------------------------------------------------------------------

/// Pull `caller_persona` from a JSON params object, validate it is a
/// non-nil parseable UUID, and return it as a String. Used by every
/// `bindings.*` admin handler so the persona-id surface stays
/// consistent.
fn extract_caller_persona(params: &Value) -> Result<String, (i32, String)> {
    let caller = params
        .get("caller_persona")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (-32602, "caller_persona is required".to_string()))?;
    let parsed = uuid::Uuid::parse_str(caller).map_err(|_| {
        (
            -32602,
            format!("caller_persona is not a valid UUID: {caller}"),
        )
    })?;
    if parsed.is_nil() {
        return Err((
            -32602,
            "caller_persona must not be the nil UUID".to_string(),
        ));
    }
    Ok(caller.to_string())
}

/// Handle the `broker.bindings.register` socket RPC.
///
/// Params:
/// ```json
/// {
///   "caller_persona":   "<persona uuid>",
///   "working_tree_id":  "<canonical absolute path>",
///   "remote_name":      "<e.g. origin>",
///   "remote_url":       "<full git remote url>"
/// }
/// ```
///
/// Response: `{ "registered": true }`. Idempotent — re-registering the
/// same `(persona, tree, remote)` triple with a new URL is an in-place
/// update (the CRUD helper uses `INSERT OR REPLACE`).
pub async fn handle_broker_bindings_register(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Classify shared-socket caller against the enrollment surface.
    log_legacy_socket_resolution(
        principal,
        store,
        params,
        "caller_persona",
        "broker.bindings.register",
    );
    check_principal_against_persona(principal, store, params, "caller_persona")?;
    let principal_id = extract_caller_persona(params)?;

    let working_tree_id = params
        .get("working_tree_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (-32602, "working_tree_id is required".to_string()))?
        .to_string();
    let remote_name = params
        .get("remote_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (-32602, "remote_name is required".to_string()))?
        .to_string();
    let remote_url = params
        .get("remote_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (-32602, "remote_url is required".to_string()))?
        .to_string();

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let binding = crate::broker::bindings::Binding {
        principal_id: principal_id.clone(),
        working_tree_id: working_tree_id.clone(),
        remote_name: remote_name.clone(),
        remote_url: remote_url.clone(),
        created_at,
    };
    crate::broker::bindings::insert(store, &binding)
        .map_err(|e| (-32603, format!("bindings.register: insert failed: {e}")))?;

    let details = json!({
        "principal_id": principal_id,
        "working_tree_id": working_tree_id,
        "remote_name": remote_name,
        "remote_url": remote_url,
        "created_at": created_at,
    });
    if let Err(e) = store.log_event(
        Some(&principal_id),
        "broker.bindings.register",
        None,
        "registered",
        Some(&details.to_string()),
    ) {
        tracing::warn!(
            error = %e,
            "broker.bindings.register: audit log row failed"
        );
    }

    Ok(json!({
        "registered": true,
        "principal_id": principal_id,
        "working_tree_id": working_tree_id,
        "remote_name": remote_name,
        "remote_url": remote_url,
        "created_at": created_at,
    }))
}

/// Handle the `broker.bindings.list` socket RPC.
///
/// Params:
/// ```json
/// {
///   "caller_persona":   "<persona uuid>",
///   "working_tree_id":  "<optional path filter>"
/// }
/// ```
///
/// Response: `{ "bindings": [ ...rows... ] }` — every row owned by the
/// caller persona (optionally filtered by `working_tree_id`). Read-only;
/// no audit row is emitted.
pub async fn handle_broker_bindings_list(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Classify shared-socket caller against the enrollment surface.
    log_legacy_socket_resolution(
        principal,
        store,
        params,
        "caller_persona",
        "broker.bindings.list",
    );
    check_principal_against_persona(principal, store, params, "caller_persona")?;
    let principal_id = extract_caller_persona(params)?;

    let working_tree_filter = params
        .get("working_tree_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let rows = crate::broker::bindings::list_for_principal(store, &principal_id)
        .map_err(|e| (-32603, format!("bindings.list: query failed: {e}")))?;

    let filtered: Vec<Value> = rows
        .into_iter()
        .filter(|b| match &working_tree_filter {
            Some(want) => &b.working_tree_id == want,
            None => true,
        })
        .map(|b| {
            json!({
                "principal_id": b.principal_id,
                "working_tree_id": b.working_tree_id,
                "remote_name": b.remote_name,
                "remote_url": b.remote_url,
                "created_at": b.created_at,
            })
        })
        .collect();

    Ok(json!({"bindings": filtered}))
}

/// Handle the `broker.bindings.remove` socket RPC.
///
/// Params:
/// ```json
/// {
///   "caller_persona":   "<persona uuid>",
///   "working_tree_id":  "<canonical absolute path>",
///   "remote_name":      "<e.g. origin>"
/// }
/// ```
///
/// Response: `{ "removed": <bool> }` — `true` when a row was deleted,
/// `false` when no matching row existed. The audit row is emitted on
/// both branches so the operator can distinguish "no-op delete" from
/// "successful delete" without re-querying.
pub async fn handle_broker_bindings_remove(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Classify shared-socket caller against the enrollment surface.
    log_legacy_socket_resolution(
        principal,
        store,
        params,
        "caller_persona",
        "broker.bindings.remove",
    );
    check_principal_against_persona(principal, store, params, "caller_persona")?;
    let principal_id = extract_caller_persona(params)?;

    let working_tree_id = params
        .get("working_tree_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (-32602, "working_tree_id is required".to_string()))?
        .to_string();
    let remote_name = params
        .get("remote_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (-32602, "remote_name is required".to_string()))?
        .to_string();

    let key = crate::broker::bindings::BindingKey {
        principal_id: principal_id.clone(),
        working_tree_id: working_tree_id.clone(),
        remote_name: remote_name.clone(),
    };
    let removed = crate::broker::bindings::remove(store, &key)
        .map_err(|e| (-32603, format!("bindings.remove: delete failed: {e}")))?;

    let details = json!({
        "principal_id": principal_id,
        "working_tree_id": working_tree_id,
        "remote_name": remote_name,
        "removed": removed,
    });
    if let Err(e) = store.log_event(
        Some(&principal_id),
        "broker.bindings.remove",
        None,
        if removed { "removed" } else { "noop" },
        Some(&details.to_string()),
    ) {
        tracing::warn!(
            error = %e,
            "broker.bindings.remove: audit log row failed"
        );
    }

    Ok(json!({
        "removed": removed,
        "principal_id": principal_id,
        "working_tree_id": working_tree_id,
        "remote_name": remote_name,
    }))
}

/// Handle the `broker.bindings.move` socket RPC.
///
/// Params:
/// ```json
/// {
///   "caller_persona": "<persona uuid>",
///   "old_path":       "<previous working_tree_id>",
///   "new_path":       "<new working_tree_id>"
/// }
/// ```
///
/// Response: `{ "moved": <count> }` — the number of rows re-rooted.
/// Used to recover from rename/repo-move scenarios without re-issuing
/// every binding manually.
pub async fn handle_broker_bindings_move(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Classify shared-socket caller against the enrollment surface.
    log_legacy_socket_resolution(
        principal,
        store,
        params,
        "caller_persona",
        "broker.bindings.move",
    );
    check_principal_against_persona(principal, store, params, "caller_persona")?;
    let principal_id = extract_caller_persona(params)?;

    let old_path = params
        .get("old_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (-32602, "old_path is required".to_string()))?
        .to_string();
    let new_path = params
        .get("new_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (-32602, "new_path is required".to_string()))?
        .to_string();

    if old_path == new_path {
        return Err((-32602, "old_path and new_path must differ".to_string()));
    }

    let moved = crate::broker::bindings::move_path(store, &principal_id, &old_path, &new_path)
        .map_err(|e| (-32603, format!("bindings.move: update failed: {e}")))?;

    let details = json!({
        "principal_id": principal_id,
        "old_path": old_path,
        "new_path": new_path,
        "moved": moved,
    });
    if let Err(e) = store.log_event(
        Some(&principal_id),
        "broker.bindings.move",
        None,
        "moved",
        Some(&details.to_string()),
    ) {
        tracing::warn!(
            error = %e,
            "broker.bindings.move: audit log row failed"
        );
    }

    Ok(json!({
        "moved": moved,
        "principal_id": principal_id,
        "old_path": old_path,
        "new_path": new_path,
    }))
}

/// Returns true if a process with the given PID is still alive.
///
/// On Linux uses `/proc/<pid>` existence check. On other Unix platforms
/// falls back to `kill(pid, 0)` which returns 0 (or EPERM for owned proc)
/// when alive, ESRCH when dead.
fn pid_is_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // kill(pid, 0) probes existence without sending a signal.
        let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
        // ret == 0  → alive (we own the process)
        // ret == -1, errno == EPERM → alive (exists, not our process)
        // ret == -1, errno == ESRCH → dead (no such process)
        if ret == 0 {
            return true;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        errno != libc::ESRCH
    }
}

// ---------------------------------------------------------------------------
// Presence-bridge verification-failure response
// (ADR-DRAFT-BROWSER-AS-TOUCH-ID-PROMPTER D7)
// ---------------------------------------------------------------------------

/// Context supplied to [`handle_presence_verification_failure`] by the
/// dashboard's WebAuthn assertion handler when `WebauthnGate::finish_auth`
/// returns an error.
pub struct PresenceVerificationFailureCtx<'a> {
    /// Registry to revoke materializations from and to freeze issuance on.
    pub registry: &'a BrokerRegistry,
    /// Store to enumerate and revoke active grants from.
    pub store: &'a DaemonStore,
}

/// Handle a WebAuthn presence-verification failure for `persona_id`.
///
/// Per ADR-DRAFT-BROWSER-AS-TOUCH-ID-PROMPTER D7:
///
/// 1. **Revoke all active grants** for the persona — calls `store.revoke_grant`
///    for every grant returned by `list_active_grants` that belongs to the
///    persona. Individual revocation errors are logged and skipped so a
///    partially-revoked set does not block the freeze step.
///
/// 2. **Freeze new issuance** — marks the persona in
///    `registry.frozen_personas` so subsequent `issue_with_registry` calls
///    for this persona are refused with `-32011` until the operator completes
///    the dashboard recovery flow.
///
/// 3. The dashboard is expected to display a recovery banner (see
///    `ember_dashboard::components::recovery_banner`) that offers the PAM
///    passphrase fallback for session-open recovery. Mid-session recovery is
///    UNAVAILABLE and fails closed across all cohorts.
///
/// Returns the count of grants that were successfully revoked. The count is
/// informational; callers should not branch on it — the freeze is the
/// authoritative gate.
pub fn handle_presence_verification_failure(
    ctx: &PresenceVerificationFailureCtx<'_>,
    persona_id: &str,
) -> usize {
    tracing::warn!(
        persona_id = %persona_id,
        "presence: WebAuthn verification failure — revoking all grants and freezing issuance"
    );

    // Step 1: revoke all active grants for this persona.
    let grants = ctx.store.list_active_grants().unwrap_or_else(|e| {
        tracing::error!(
            persona_id = %persona_id,
            error = %e,
            "presence: failed to list active grants during verification-failure response; \
             proceeding to freeze without full revocation"
        );
        vec![]
    });

    let mut revoked = 0usize;
    for grant in grants {
        if grant.persona_id != persona_id {
            continue;
        }
        match ctx.store.revoke_grant(&grant.id) {
            Ok(()) => {
                tracing::info!(
                    persona_id = %persona_id,
                    grant_id = %grant.id,
                    "presence: revoked grant as part of verification-failure response"
                );
                revoked += 1;
            }
            Err(e) => {
                tracing::error!(
                    persona_id = %persona_id,
                    grant_id = %grant.id,
                    error = %e,
                    "presence: failed to revoke grant during verification-failure response; \
                     freezing will still proceed"
                );
            }
        }
    }

    // Step 2: freeze new issuance for this persona.
    ctx.registry.freeze_persona(persona_id);

    tracing::warn!(
        persona_id = %persona_id,
        revoked_count = revoked,
        "presence: persona frozen — new credential issuance is refused; \
         operator must complete dashboard recovery (PAM passphrase) to unfreeze"
    );

    revoked
}

// ---------------------------------------------------------------------------
// Per-cohort presence fallback ladder (ADR 158)
// ---------------------------------------------------------------------------

/// Session phase classification supplied by the issuance caller. Determines
/// whether PAM-passphrase fallback is admissible for the cohorts that allow
/// it on session-open (dev0) — mid-session recovery is UNAVAILABLE across
/// the board per ADR-DRAFT-BROWSER-AS-TOUCH-ID-PROMPTER D7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    /// Session-open / first-prompt context. PAM passphrase fallback is
    /// admissible for cohorts that opt into it.
    Open,
    /// Mid-session re-prompt. PAM fallback is refused; the only acceptable
    /// re-attestation is the registered second factor itself.
    MidSession,
}

impl SessionPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::MidSession => "mid_session",
        }
    }
}

/// Decision returned by [`presence_fallback_ladder`] for a given cohort +
/// session phase tuple. Encodes the per-cohort policy table from ADR 158.
///
/// - [`LadderDecision::Fido2Required`] — FIDO2/WebAuthn is the primary
///   factor; `fallback_pam` indicates whether PAM passphrase is admissible
///   as a recovery path on this session phase.
/// - [`LadderDecision::Fido2RequiredNoFallback`] — FIDO2 only; no recovery
///   fallback is offered.
/// - [`LadderDecision::Fido2PlusAuditLog`] — FIDO2 plus an emitted
///   second-factor audit record (ent0 compliance posture).
/// - [`LadderDecision::FailClosed`] — refuse issuance; either the cohort is
///   unknown, or the presence subsystem is UNAVAILABLE mid-session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LadderDecision {
    /// FIDO2/WebAuthn required; PAM passphrase fallback permitted only when
    /// `fallback_pam` is true (dev0 / session-open only).
    Fido2Required {
        /// True when PAM passphrase fallback is admissible for recovery.
        fallback_pam: bool,
    },
    /// FIDO2/WebAuthn required; no fallback path. team0 across all phases.
    Fido2RequiredNoFallback,
    /// FIDO2/WebAuthn plus a written audit-log entry for the second-factor
    /// event. ent0 compliance posture across all phases.
    Fido2PlusAuditLog,
    /// Refuse issuance. Returned for unknown cohorts and for any cohort
    /// when the presence subsystem reports UNAVAILABLE mid-session.
    FailClosed,
}

impl LadderDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fido2Required { fallback_pam: true } => "fido2_required_pam_fallback",
            Self::Fido2Required {
                fallback_pam: false,
            } => "fido2_required_no_pam_fallback",
            Self::Fido2RequiredNoFallback => "fido2_required_no_fallback",
            Self::Fido2PlusAuditLog => "fido2_plus_audit_log",
            Self::FailClosed => "fail_closed",
        }
    }
}

fn parse_session_phase_param(params: &Value) -> Result<SessionPhase, (i32, String)> {
    let Some(raw) = params.get("session_phase").and_then(|v| v.as_str()) else {
        return Ok(SessionPhase::MidSession);
    };
    match raw {
        "open" | "session_open" | "session-open" => Ok(SessionPhase::Open),
        "mid_session" | "mid-session" | "mid" => Ok(SessionPhase::MidSession),
        other => Err((
            -32602,
            format!(
                "invalid session_phase {other:?}; expected open or mid_session for broker issue"
            ),
        )),
    }
}

pub(super) fn issue_presence_ladder_decision(
    params: &Value,
) -> Result<(String, SessionPhase, LadderDecision), (i32, String)> {
    let cohort = params
        .get("cohort")
        .or_else(|| params.get("presence_cohort"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            crate::infra::handler::current_dispatch_deployment_tier()
                .as_str()
                .to_string()
        });
    let session_phase = parse_session_phase_param(params)?;
    let decision = if params
        .get("presence_unavailable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        presence_fallback_ladder_unavailable(&cohort, session_phase)
    } else {
        presence_fallback_ladder(&cohort, session_phase)
    };
    Ok((cohort, session_phase, decision))
}

pub(super) fn consume_issue_presence_ladder_decision(
    store: &DaemonStore,
    req: &BrokerIssueParams,
    cohort: &str,
    session_phase: SessionPhase,
    decision: LadderDecision,
) -> Result<(), (i32, String)> {
    // ladder_decision_consumed: issue_with_registry gates issuance on the
    // resolved per-cohort ladder instead of the old fail-closed placeholder.
    match decision {
        LadderDecision::FailClosed => Err((
            -32012,
            format!(
                "presence fallback ladder refused broker issue for cohort={cohort} phase={}",
                session_phase.as_str()
            ),
        )),
        LadderDecision::Fido2PlusAuditLog => {
            let details = json!({
                "kind": "broker_presence_ladder",
                "checkpoint": "ladder_decision_consumed",
                "cohort": cohort,
                "session_phase": session_phase.as_str(),
                "decision": decision.as_str(),
                "provider": req.provider.as_str(),
                "caller_persona": req.caller_persona.as_deref(),
            });
            if let Err(e) = store.log_event(
                req.caller_persona.as_deref(),
                "broker.presence_ladder.audit_required",
                Some(req.provider.as_str()),
                "required",
                Some(&details.to_string()),
            ) {
                tracing::warn!(
                    error = %e,
                    provider = req.provider.as_str(),
                    cohort = %cohort,
                    session_phase = %session_phase.as_str(),
                    "broker: failed to persist presence ladder audit event"
                );
            }
            Ok(())
        }
        LadderDecision::Fido2Required { .. } | LadderDecision::Fido2RequiredNoFallback => Ok(()),
    }
}

/// Resolve the per-cohort presence-ladder decision for `(cohort,
/// session_phase)` per ADR 158 §"Per-cohort defaults principle".
///
/// Cohort table:
///
/// | Cohort | Open                            | MidSession                       |
/// |--------|---------------------------------|----------------------------------|
/// | dev0   | `Fido2Required{fallback_pam:true}`  | `Fido2Required{fallback_pam:false}` |
/// | team0  | `Fido2RequiredNoFallback`           | `Fido2RequiredNoFallback`           |
/// | ent0   | `Fido2PlusAuditLog`                 | `Fido2PlusAuditLog`                 |
/// | other  | `FailClosed`                        | `FailClosed`                        |
///
/// **Mid-session UNAVAILABLE override.** When the presence subsystem
/// reports UNAVAILABLE during a `MidSession` re-prompt the caller is
/// expected to substitute the cohort argument with the checkpoint
/// `"__unavailable__"` so this function returns [`LadderDecision::FailClosed`]
/// for every cohort. The override is also exercised explicitly by
/// [`presence_fallback_ladder_unavailable`].
///
/// This function is pure — no I/O, no clock, no mutex — so it is safe to
/// call from any context (broker handler, dashboard policy preview,
/// debug-only diagnostics).
pub fn presence_fallback_ladder(cohort: &str, session_phase: SessionPhase) -> LadderDecision {
    match cohort {
        "dev0" => match session_phase {
            SessionPhase::Open => LadderDecision::Fido2Required { fallback_pam: true },
            SessionPhase::MidSession => LadderDecision::Fido2Required {
                fallback_pam: false,
            },
        },
        "team0" => LadderDecision::Fido2RequiredNoFallback,
        "ent0" => LadderDecision::Fido2PlusAuditLog,
        _ => LadderDecision::FailClosed,
    }
}

/// Mid-session UNAVAILABLE override: when the presence subsystem reports
/// UNAVAILABLE during a `MidSession` re-prompt, the answer is always
/// [`LadderDecision::FailClosed`] regardless of cohort. Wrapper kept
/// separate from [`presence_fallback_ladder`] so callers can opt into the
/// fail-closed path explicitly rather than encoding the override as a magic
/// cohort string at every call site.
pub fn presence_fallback_ladder_unavailable(
    _cohort: &str,
    _session_phase: SessionPhase,
) -> LadderDecision {
    LadderDecision::FailClosed
}

// ---------------------------------------------------------------------------
// (ADR 200 §5) The old presence-bridge first-run enrollment handler
// (`presence/enroll` → `handle_first_run_enrollment`) was RETIRED in G2 Slice
// 1b. It minted non-attested WebAuthn passkeys that are structurally barred from
// the `presence` custody class, so a live stub was a footgun. Operator
// presence-device enrollment now goes through the `identity.device.enroll`
// daemon RPC (prepare→commit over `operator_identity`), which the daemon never
// signs for. The dashboard passkey ceremony / `webauthn-rs` machinery is kept
// for the future `genuine_app` attested-passkey lane; only this
// operator-enrollment entry point is gone. `deferred_presence_rpc` survives
// below for the other intentionally-deferred presence bridge RPC.

fn deferred_presence_rpc(method: &str, detail: &str) -> (i32, String) {
    (-32601, format!("{method}: {detail}"))
}

/// JSON-RPC dispatcher entry point for `presence/request_proof`.
///
/// ADR 206 slice 4 C retired the forgeable WebAuthn-assertion → `DaemonSignedHandle`
/// presence-proof bridge (`issue_presence_proof` + `TabChannel` +
/// `AssertionVerifier` + `issue_daemon_signed_handle`). That bridge minted a
/// daemon-signed envelope a compromised daemon could fabricate; operator presence
/// is now sourced from the §4 presence-as-decryption unlock (`ember vault
/// se-unlock`), and widening verifies a REAL enrolled-device signature via
/// `presence_gate::verify_presence_signature`. This dispatcher therefore returns
/// a clean `-32601 not_implemented` rather than wiring the deleted bridge.
pub async fn handle_request_presence_proof(
    _principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    _store: &DaemonStore,
    _params: &Value,
) -> Result<Value, (i32, String)> {
    Err(deferred_presence_rpc(
        "presence/request_proof",
        "retired — the forgeable daemon-signed presence-proof bridge was deleted \
         (ADR 206 slice 4 C). Use the §4 presence-as-decryption unlock \
         (`ember vault se-unlock`); widening verifies a real enrolled-device signature",
    ))
}

// ---------------------------------------------------------------------------
// refresh_cert RPC (M3-A of ADR 173)
//
// Anchor: refresh_cert_dispatch_landed
//
// M3-A shipped the dispatch skeleton + error types + authority_class
// registration. This handler now implements the M3 identity-proof and
// mint/update path; rate limit (M3-D) and Receipt emission (M3-E) remain
// separate follow-up slices.
//
// Per ADR 173 §Component 2/3/4 + ADR 118 Extension 5: refresh_cert lets
// a holder of a valid mTLS cert request a new one before expiry,
// authorized via cert + SPIFFE SAN + grant-active 3-way check, minted
// via `core_crypto::mint_per_agent_client_cert`, atomic on the persona
// row, rate-limited per (persona_id, container_id) chain, audited via
// `bridge.cert_refreshed` / `bridge.cert_refresh_failed` Receipts.
// ---------------------------------------------------------------------------

/// Per-failure-mode enum carried on every [`RefreshDenied`] response.
/// Lock matches ADR 118 Extension 5; future variants land as the
/// follow-up M3 slices add their specific check sites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshFailureCause {
    /// Network or transport-layer failure (peer disconnect mid-handshake,
    /// TLS read error). Reserved for M3-D wiring.
    TransportError,
    /// The grant identified by the caller's mTLS cert has been revoked.
    /// Populated by M3-B's grant-active check.
    AuthFailureRevoked,
    /// The caller's mTLS cert is past its `not_after`. Populated by
    /// M3-B's cert-expiry check.
    AuthFailureExpired,
    /// No persona row matches the caller's SPIFFE SAN container_id, or
    /// the row exists but the SAN cross-check fails. Populated by M3-B.
    AuthFailurePersonaUnknown,
    /// Vault is sealed at refresh time; mint cannot proceed. Reserved
    /// for M3-C wiring.
    MintFailureVaultSealed,
    /// Mint failed for an internal reason (rcgen error, etc.). Reserved
    /// for M3-C wiring.
    MintFailureInternal,
    /// Caller exceeded the per-(persona_id, container_id) 60s rate-limit
    /// window.
    RateLimited,
    /// Refresh train exhausted all client retries before a new cert was minted.
    ExhaustedRetries,
    /// Slice A only — the dispatch arm landed but the underlying mint
    /// machinery hasn't shipped yet. M3-B/C/D/E replace this variant
    /// with specific causes as each lands.
    NotImplemented,
}

/// Returned by the `refresh_cert` RPC on any denial. Carries a human-
/// readable `reason` plus a machine-readable `failure_cause` enum so
/// callers can branch on the specific check that fired.
///
/// Per ADR 173 §Component 5 the wire shape is a flat JSON object with
/// `denied: true` discriminator plus the two fields below — the
/// success path returns the new cert payload (M3-C wires that).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshDenied {
    pub reason: String,
    pub failure_cause: RefreshFailureCause,
}

impl RefreshDenied {
    /// Convenience constructor for the M3-A stub path; the
    /// follow-up slices will introduce per-cause helpers.
    pub fn not_implemented() -> Self {
        Self {
            reason: "refresh_cert: M3-A dispatch landed; M3-B/C/D/E pending".to_string(),
            failure_cause: RefreshFailureCause::NotImplemented,
        }
    }

    pub fn new(failure_cause: RefreshFailureCause, reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            failure_cause,
        }
    }
}

/// Handle the `refresh_cert` socket RPC.
///
/// ADR 173 M3 refresh handler.
///
/// Identity proof is the mTLS principal stamped by the bridge listener plus
/// the daemon's persona/grant state: the persona row must exist, be active,
/// be bound to the cert's container SAN, have a non-legacy pinned cert row,
/// and reference an active, non-expired, non-SID-revoked parent grant. Refresh
/// then mints a new bridge client cert with TTL
/// `min(tier_default, grant.not_after - now - 60s)` and updates
/// `client_cert_fingerprint`, `client_cert_not_after`, and
/// `client_cert_refresh_seq` in one SQL statement.
///
/// Anchor: `refresh_cert_dispatch_landed`.
/// Anchor: `refresh_cert_identity_proof_landed`.
/// Anchor: `refresh_cert_mint_landed`.
/// Anchor: `refresh_cert_rate_limit_landed`.
/// Anchor: `refresh_cert_receipts_landed`.
pub async fn handle_refresh_cert(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    mtls_principal: Option<&MtlsPrincipal>,
    store: &DaemonStore,
    rate_limiter: &RefCell<RateLimiter>,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // daemon_refresh_cert_rpc_landed
    // Wire the container-binding gate
    // ahead of the M3-B stub. Even with the rest of the surface
    // unimplemented, a caller whose namespace inodes have drifted from
    // their enrollment row must be refused at the broker boundary so
    // the gate stack is uniform across every broker dispatch site.
    check_principal_namespace_inodes(principal, store)?;

    let Some(mtls) = mtls_principal else {
        return Ok(refresh_denied_value(RefreshDenied::new(
            RefreshFailureCause::AuthFailurePersonaUnknown,
            "refresh_cert requires an mTLS-authenticated bridge caller",
        ))?);
    };

    let persona = match store.get_persona(&mtls.persona_id) {
        Ok(persona) => persona,
        Err(StoreError::NotFound) => {
            return Ok(refresh_denied_value(RefreshDenied::new(
                RefreshFailureCause::AuthFailurePersonaUnknown,
                "mTLS persona SAN does not resolve to a known persona",
            ))?);
        }
        Err(e) => return Err((-32603, format!("refresh_cert persona lookup failed: {e}"))),
    };

    if persona.status != "active" {
        return Ok(refresh_denied_value(RefreshDenied::new(
            RefreshFailureCause::AuthFailurePersonaUnknown,
            format!("persona '{}' is not active", persona.id),
        ))?);
    }

    let Some(bound_container) = persona.container_id.as_deref() else {
        return Ok(refresh_denied_value(RefreshDenied::new(
            RefreshFailureCause::AuthFailurePersonaUnknown,
            "refresh_cert requires a container-bound persona",
        ))?);
    };
    if bound_container != mtls.container_id {
        return Ok(refresh_denied_value(RefreshDenied::new(
            RefreshFailureCause::AuthFailurePersonaUnknown,
            "mTLS container SAN does not match the persona container binding",
        ))?);
    }

    let cert_state = match store.get_persona_client_cert_state(&persona.id) {
        Ok(state) => state,
        Err(StoreError::NotFound) => {
            return Ok(refresh_denied_value(RefreshDenied::new(
                RefreshFailureCause::AuthFailurePersonaUnknown,
                "persona cert pin row is missing",
            ))?);
        }
        Err(e) => {
            return Err((
                -32603,
                format!("refresh_cert cert-state lookup failed: {e}"),
            ));
        }
    };

    // Legacy-row policy: refuse empty spawn-time cert pins. Lazy migration would
    // trust a presented cert without an existing daemon-side pin, so M3 locks the
    // safer Option A from the task brief.
    if cert_state.fingerprint_hex.is_empty() || cert_state.not_after_unix <= 0 {
        return Ok(refresh_terminal_denied_value(
            store,
            &persona.id,
            &mtls.container_id,
            persona.parent_grant_id.as_deref().unwrap_or(""),
            cert_state.refresh_seq.saturating_add(1),
            params,
            RefreshFailureCause::AuthFailurePersonaUnknown,
            "persona has no pinned bridge client cert; refresh denied for legacy row",
            None,
        )?);
    }
    let presented_fingerprint = hex::encode(mtls.cert_fingerprint);
    if !cert_state
        .fingerprint_hex
        .eq_ignore_ascii_case(&presented_fingerprint)
    {
        return Ok(refresh_terminal_denied_value(
            store,
            &persona.id,
            &mtls.container_id,
            persona.parent_grant_id.as_deref().unwrap_or(""),
            cert_state.refresh_seq.saturating_add(1),
            params,
            RefreshFailureCause::AuthFailurePersonaUnknown,
            "presented mTLS cert fingerprint does not match the persona cert pin",
            None,
        )?);
    }
    let now = Utc::now();
    if cert_state.not_after_unix <= now.timestamp() {
        return Ok(refresh_terminal_denied_value(
            store,
            &persona.id,
            &mtls.container_id,
            persona.parent_grant_id.as_deref().unwrap_or(""),
            cert_state.refresh_seq.saturating_add(1),
            params,
            RefreshFailureCause::AuthFailureExpired,
            "pinned bridge client cert is expired",
            None,
        )?);
    }

    let Some(row_parent_grant_id) = persona.parent_grant_id.as_deref() else {
        return Ok(refresh_denied_value(RefreshDenied::new(
            RefreshFailureCause::AuthFailurePersonaUnknown,
            "container persona is missing parent_grant_id",
        ))?);
    };
    if let Some(claimed_grant_id) = optional_refresh_grant_id(params)
        && claimed_grant_id != row_parent_grant_id
    {
        return Ok(refresh_terminal_denied_value(
            store,
            &persona.id,
            &mtls.container_id,
            row_parent_grant_id,
            cert_state.refresh_seq.saturating_add(1),
            params,
            RefreshFailureCause::AuthFailurePersonaUnknown,
            "caller grant id does not match persona parent_grant_id",
            None,
        )?);
    }

    let grant = match store.get_grant(row_parent_grant_id) {
        Ok(grant) => grant,
        Err(StoreError::NotFound) => {
            return Ok(refresh_terminal_denied_value(
                store,
                &persona.id,
                &mtls.container_id,
                row_parent_grant_id,
                cert_state.refresh_seq.saturating_add(1),
                params,
                RefreshFailureCause::AuthFailureRevoked,
                "parent grant no longer exists",
                None,
            )?);
        }
        Err(e) => return Err((-32603, format!("refresh_cert grant lookup failed: {e}"))),
    };
    if grant.status != "active" {
        return Ok(refresh_terminal_denied_value(
            store,
            &persona.id,
            &mtls.container_id,
            &grant.id,
            cert_state.refresh_seq.saturating_add(1),
            params,
            RefreshFailureCause::AuthFailureRevoked,
            format!("parent grant '{}' is not active", grant.id),
            None,
        )?);
    }
    let grant_not_after = match grant_not_after(&grant) {
        Ok(not_after) => not_after,
        Err(RefreshDenied {
            reason,
            failure_cause,
        }) => {
            return Ok(refresh_terminal_denied_value(
                store,
                &persona.id,
                &mtls.container_id,
                &grant.id,
                cert_state.refresh_seq.saturating_add(1),
                params,
                failure_cause,
                reason,
                None,
            )?);
        }
    };

    let revoked_sids = store.get_revoked_sids(&grant.id).map_err(|e| {
        (
            -32603,
            format!("refresh_cert revoked-sid lookup failed: {e}"),
        )
    })?;
    if !revoked_sids.is_empty() {
        return Ok(refresh_terminal_denied_value(
            store,
            &persona.id,
            &mtls.container_id,
            &grant.id,
            cert_state.refresh_seq.saturating_add(1),
            params,
            RefreshFailureCause::AuthFailureRevoked,
            "parent grant has revoked statement authority",
            None,
        )?);
    }

    let rate_limit_key = format!("refresh_cert:{}", mtls.container_id);
    if !rate_limiter.borrow_mut().check_action_min_interval(
        &persona.id,
        &rate_limit_key,
        REFRESH_CERT_RATE_LIMIT_SECS,
    ) {
        return Ok(refresh_denied_value(RefreshDenied::new(
            RefreshFailureCause::RateLimited,
            "refresh_cert is rate-limited for this persona/container cert chain",
        ))?);
    }

    let ttl = match refresh_ttl(now, grant_not_after) {
        Ok(ttl) => ttl,
        Err(denied) => {
            return Ok(refresh_terminal_denied_value_from_denied(
                store,
                &persona.id,
                &mtls.container_id,
                &grant.id,
                cert_state.refresh_seq.saturating_add(1),
                params,
                denied,
                None,
            )?);
        }
    };

    let Some(bridge_ca) = store.bridge_ca() else {
        return Ok(refresh_terminal_denied_value(
            store,
            &persona.id,
            &mtls.container_id,
            &grant.id,
            cert_state.refresh_seq.saturating_add(1),
            params,
            RefreshFailureCause::MintFailureVaultSealed,
            "bridge CA is not loaded; vault is sealed or daemon has not unlocked cert minting",
            Some(60),
        )?);
    };

    // ADR 173 names core_crypto::mint_per_agent_client_cert, but the shipped
    // daemon bridge path wraps the same cert shape behind BridgeCa::sign_client_cert:
    // it uses the persisted Bridge CA trust root and wall-clock validity,
    // whereas core_crypto's low-level helper needs raw rcgen issuer material and
    // anchors not_after at Unix epoch. Reuse the live bridge primitive here so
    // the refreshed cert is trusted by the running listener.
    let (client_cert_pem, client_key_pem) =
        match bridge_ca.sign_client_cert(&persona.id, Some(&mtls.container_id), ttl) {
            Ok(bundle) => bundle,
            Err(e) => {
                return Ok(refresh_terminal_denied_value(
                    store,
                    &persona.id,
                    &mtls.container_id,
                    &grant.id,
                    cert_state.refresh_seq.saturating_add(1),
                    params,
                    RefreshFailureCause::MintFailureInternal,
                    format!("bridge client cert mint failed: {e}"),
                    Some(60),
                )?);
            }
        };
    let ca_cert_pem = match bridge_ca.trust_root_cert_pem() {
        Ok(ca) => ca,
        Err(e) => {
            return Ok(refresh_terminal_denied_value(
                store,
                &persona.id,
                &mtls.container_id,
                &grant.id,
                cert_state.refresh_seq.saturating_add(1),
                params,
                RefreshFailureCause::MintFailureInternal,
                format!("bridge trust root render failed: {e}"),
                Some(60),
            )?);
        }
    };
    let (new_fingerprint, new_not_after) =
        match crate::infra::persona::client_cert_fingerprint_and_not_after_from_pem(
            client_cert_pem.as_str(),
        ) {
            Ok(parsed) => parsed,
            Err(e) => {
                return Ok(refresh_terminal_denied_value(
                    store,
                    &persona.id,
                    &mtls.container_id,
                    &grant.id,
                    cert_state.refresh_seq.saturating_add(1),
                    params,
                    RefreshFailureCause::MintFailureInternal,
                    format!("minted bridge client cert parse failed: {e}"),
                    Some(60),
                )?);
            }
        };

    let refresh_seq = match store.replace_persona_client_cert_for_refresh(
        &persona.id,
        &new_fingerprint,
        new_not_after,
    ) {
        Ok(seq) => seq,
        Err(StoreError::NotFound) => {
            return Ok(refresh_terminal_denied_value(
                store,
                &persona.id,
                &mtls.container_id,
                &grant.id,
                cert_state.refresh_seq.saturating_add(1),
                params,
                RefreshFailureCause::AuthFailurePersonaUnknown,
                "persona disappeared before refresh UPDATE",
                None,
            )?);
        }
        Err(e) => return Err((-32603, format!("refresh_cert update failed: {e}"))),
    };
    let receipt_id = emit_refresh_cert_refreshed_receipt(
        store,
        &persona.id,
        &mtls.container_id,
        &grant.id,
        &cert_state.fingerprint_hex,
        &new_fingerprint,
        refresh_seq,
        params,
    );

    // ADR 118 Extension 6 / ADR 173 M4 — deprecation half of the lifecycle pair.
    // Lossy-acceptable companion to `bridge.cert_refreshed`; emitted immediately
    // after the persona-row UPDATE so audit can correlate refresh → old-cert
    // deprecated even if a downstream consumer indexes only `cert_superseded`.
    // Anchor: daemon_bridge_cert_superseded_event_emitted
    emit_refresh_cert_superseded_receipt(
        store,
        &persona.id,
        &grant.id,
        &cert_state.fingerprint_hex,
        &new_fingerprint,
    );

    Ok(json!({
        "denied": false,
        "persona_id": persona.id,
        "container_id": mtls.container_id,
        "grant_id": grant.id,
        "client_cert_pem": client_cert_pem.as_str(),
        "client_key_pem": client_key_pem.as_str(),
        "ca_cert_pem": ca_cert_pem.as_str(),
        "client_cert_fingerprint": new_fingerprint,
        "client_cert_not_after": new_not_after,
        "refresh_seq": refresh_seq,
        "previous_refresh_seq": cert_state.refresh_seq,
        "receipt_id": receipt_id,
    }))
}

fn refresh_terminal_denied_value(
    store: &DaemonStore,
    persona_id: &str,
    container_id: &str,
    grant_id: &str,
    refresh_seq: u32,
    params: &Value,
    failure_cause: RefreshFailureCause,
    reason: impl Into<String>,
    retry_after_seconds: Option<u32>,
) -> Result<Value, (i32, String)> {
    refresh_terminal_denied_value_from_denied(
        store,
        persona_id,
        container_id,
        grant_id,
        refresh_seq,
        params,
        RefreshDenied::new(failure_cause, reason),
        retry_after_seconds,
    )
}

fn refresh_terminal_denied_value_from_denied(
    store: &DaemonStore,
    persona_id: &str,
    container_id: &str,
    grant_id: &str,
    refresh_seq: u32,
    params: &Value,
    denied: RefreshDenied,
    retry_after_seconds: Option<u32>,
) -> Result<Value, (i32, String)> {
    if denied.failure_cause != RefreshFailureCause::RateLimited && !grant_id.is_empty() {
        emit_refresh_cert_failed_receipt(
            store,
            persona_id,
            container_id,
            grant_id,
            refresh_seq,
            params,
            &denied,
            retry_after_seconds,
        );
    }
    refresh_denied_value(denied)
}

fn refresh_denied_value(denied: RefreshDenied) -> Result<Value, (i32, String)> {
    let body = serde_json::to_value(&denied)
        .map_err(|e| (-32603, format!("failed to encode RefreshDenied: {e}")))?;
    Ok(json!({
        "denied": true,
        "reason": body["reason"],
        "failure_cause": body["failure_cause"],
    }))
}

const REFRESH_CERT_RATE_LIMIT_SECS: u64 = 60;

fn emit_refresh_cert_refreshed_receipt(
    store: &DaemonStore,
    persona_id: &str,
    container_id: &str,
    grant_id: &str,
    old_cert_fingerprint: &str,
    new_cert_fingerprint: &str,
    refresh_seq: u32,
    params: &Value,
) -> Option<String> {
    let body = core_events::receipt::BridgeCertRefreshedBody {
        old_cert_fingerprint: old_cert_fingerprint.to_string(),
        new_cert_fingerprint: new_cert_fingerprint.to_string(),
        persona_id: persona_id.to_string(),
        container_id: container_id.to_string(),
        grant_id: grant_id.to_string(),
        refresh_seq,
        parent_receipt_id: refresh_parent_receipt_id(params),
        trigger_reason: refresh_trigger_reason(params),
        recovered_from_failure_count: refresh_recovered_failure_count(params),
    };
    emit_refresh_cert_receipt(
        store,
        core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_REFRESHED,
        grant_id,
        persona_id,
        "cert_refreshed",
        &body,
    )
}

fn emit_refresh_cert_failed_receipt(
    store: &DaemonStore,
    persona_id: &str,
    container_id: &str,
    grant_id: &str,
    refresh_seq: u32,
    params: &Value,
    denied: &RefreshDenied,
    retry_after_seconds: Option<u32>,
) -> Option<String> {
    let body = core_events::receipt::BridgeCertRefreshFailedBody {
        persona_id: persona_id.to_string(),
        container_id: container_id.to_string(),
        grant_id: grant_id.to_string(),
        refresh_seq,
        attempt_count: refresh_attempt_count(params),
        failure_cause: refresh_failure_cause_wire(&denied.failure_cause),
        reason: denied.reason.clone(),
        retry_after_seconds,
    };
    emit_refresh_cert_receipt(
        store,
        core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_REFRESH_FAILED,
        grant_id,
        persona_id,
        "cert_refresh_failed",
        &body,
    )
}

/// ADR 118 Extension 6 / ADR 173 M4 — emit the `bridge.cert_superseded`
/// event after a successful `refresh_cert` UPDATE commits.
///
/// The signed `bridge.cert_refreshed` receipt records the new-cert
/// authority half; this kind records the old-cert deprecation half. Audit
/// consumers walking either half resolve the refresh lifecycle.
///
/// The body intentionally omits `container_id` — the brief's ADR 118
/// Extension 6 shape pins `(old_cert_fingerprint, new_cert_fingerprint,
/// persona_id)` only; the container is recoverable via the paired
/// `bridge.cert_refreshed` receipt's `container_id` field.
///
/// Anchor: `daemon_bridge_cert_superseded_event_emitted`.
fn emit_refresh_cert_superseded_receipt(
    store: &DaemonStore,
    persona_id: &str,
    grant_id: &str,
    old_cert_fingerprint: &str,
    new_cert_fingerprint: &str,
) -> Option<String> {
    let body = core_events::receipt::BridgeCertSupersededBody {
        old_cert_fingerprint: old_cert_fingerprint.to_string(),
        new_cert_fingerprint: new_cert_fingerprint.to_string(),
        persona_id: persona_id.to_string(),
    };
    emit_refresh_cert_receipt(
        store,
        core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_SUPERSEDED,
        grant_id,
        persona_id,
        "cert_superseded",
        &body,
    )
}

fn emit_refresh_cert_receipt<T: Serialize>(
    store: &DaemonStore,
    kind: &str,
    grant_id: &str,
    persona_id: &str,
    terminal_reason: &str,
    body: &T,
) -> Option<String> {
    let Some(identity) = crate::infra::receipt::current_identity() else {
        tracing::warn!(
            grant_id = %grant_id,
            kind = %kind,
            "refresh_cert receipt emission skipped — daemon identity not initialised"
        );
        return None;
    };
    let body = match serde_json::to_value(body) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(grant_id = %grant_id, kind = %kind, %error, "refresh_cert receipt body serialize failed");
            return None;
        }
    };
    let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
    let mut envelope = core_events::receipt::ReceiptEnvelope {
        version: core_events::receipt::ReceiptVersion::default(),
        kind: kind.to_string(),
        receipt_id: String::new(),
        daemon_root_id: identity.pubkey_hex(),
        traceparent: None,
        termination_authority: core_events::receipt::TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body,
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    if let Err(error) = core_events::receipt::sign_receipt_v2(&mut envelope, &signer) {
        tracing::warn!(grant_id = %grant_id, kind = %kind, %error, "refresh_cert receipt sign failed");
        return None;
    }
    if let Err(error) =
        store.store_atomic_receipt_v2(&envelope, grant_id, persona_id, terminal_reason)
    {
        tracing::warn!(grant_id = %grant_id, kind = %kind, %error, "refresh_cert receipt persistence failed");
        return None;
    }
    Some(envelope.receipt_id)
}

fn refresh_failure_cause_wire(cause: &RefreshFailureCause) -> String {
    serde_json::to_value(cause)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_string())
}

fn refresh_attempt_count(params: &Value) -> u32 {
    params
        .get("attempt_count")
        .or_else(|| params.get("attempt_seq"))
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(1)
}

fn refresh_recovered_failure_count(params: &Value) -> u32 {
    params
        .get("recovered_from_failure_count")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0)
}

fn refresh_parent_receipt_id(params: &Value) -> Option<String> {
    params
        .get("parent_receipt_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn refresh_trigger_reason(params: &Value) -> core_events::receipt::BridgeCertRefreshTriggerReason {
    match params.get("trigger_reason").and_then(Value::as_str) {
        Some("retry_after_failure") => {
            core_events::receipt::BridgeCertRefreshTriggerReason::RetryAfterFailure
        }
        Some("operator_induced") => {
            core_events::receipt::BridgeCertRefreshTriggerReason::OperatorInduced
        }
        _ => core_events::receipt::BridgeCertRefreshTriggerReason::TimerTriggered,
    }
}

fn optional_refresh_grant_id(params: &Value) -> Option<&str> {
    params
        .get("caller_grant_id")
        .and_then(Value::as_str)
        .or_else(|| params.get("grant_id").and_then(Value::as_str))
}

fn grant_not_after(grant: &crate::trust::grant::GrantInfo) -> Result<DateTime<Utc>, RefreshDenied> {
    let Some(expires_at) = grant.expires_at.as_deref() else {
        return Err(RefreshDenied::new(
            RefreshFailureCause::AuthFailureExpired,
            "parent grant is unbounded; refresh requires a bounded grant not_after",
        ));
    };
    DateTime::parse_from_rfc3339(expires_at)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            RefreshDenied::new(
                RefreshFailureCause::AuthFailureExpired,
                format!("parent grant not_after is invalid: {e}"),
            )
        })
}

fn refresh_ttl(
    now: DateTime<Utc>,
    grant_not_after: DateTime<Utc>,
) -> Result<Duration, RefreshDenied> {
    let remaining_after_floor = grant_not_after
        .signed_duration_since(now)
        .num_seconds()
        .saturating_sub(60);
    if remaining_after_floor <= 0 {
        return Err(RefreshDenied::new(
            RefreshFailureCause::AuthFailureExpired,
            "parent grant expires too soon to mint a useful refreshed cert",
        ));
    }
    let tier_default_secs = match crate::infra::handler::current_dispatch_deployment_tier().as_str()
    {
        "dev0" => 24 * 60 * 60,
        "team0" | "ent0" => 4 * 60 * 60,
        _ => 4 * 60 * 60,
    };
    Ok(Duration::from_secs(
        remaining_after_floor.min(tier_default_secs) as u64,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_broker::{BrokerProvider, MockBroker};
    use serde_json::{Value, json};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::Duration;

    use super::super::issue_with_registry;
    use crate::infra::persona::{agent_persona_two_phase_commit, pin_persona_client_cert_from_pem};
    use crate::infra::vault::Vault;
    use crate::trust::bridge_ca::BridgeCa;

    fn fresh_registry() -> BrokerRegistry {
        let mut reg = BrokerRegistry::new();
        reg.register(Box::new(MockBroker::new(BrokerProvider::Cloudflare)));
        reg.register(Box::new(MockBroker::new(BrokerProvider::Anthropic)));
        reg
    }

    const REFRESH_TEST_VAULT_KEY: [u8; 32] = [0xA5; 32];

    struct RefreshFixture {
        store: DaemonStore,
        mtls: MtlsPrincipal,
        parent_grant_id: String,
        persona_id: String,
        initial_fingerprint: String,
    }

    fn refresh_fixture(container_id: &str) -> RefreshFixture {
        refresh_fixture_with_loaded_bridge_ca(container_id, true)
    }

    fn refresh_fixture_with_loaded_bridge_ca(
        container_id: &str,
        load_bridge_ca: bool,
    ) -> RefreshFixture {
        let store = DaemonStore::open_in_memory().expect("open in-memory store");
        let vault = Rc::new(Vault::new(REFRESH_TEST_VAULT_KEY));
        store.set_vault(Rc::clone(&vault));
        let bridge_ca = Arc::new(BridgeCa::mint());
        if load_bridge_ca {
            store.set_bridge_ca(Arc::clone(&bridge_ca));
        }

        let parent = store.create_persona("refresh-cert-parent").unwrap();
        let parent_grant = store
            .create_grant(&parent.id, "delegate-key", "*", Some(7_200))
            .unwrap();
        store
            .conn()
            .execute(
                "UPDATE grants SET max_delegation_depth = 2 WHERE id = ?1",
                rusqlite::params![&parent_grant.id],
            )
            .unwrap();

        let persona =
            agent_persona_two_phase_commit(&store, vault.as_ref(), container_id, &parent_grant.id)
                .expect("mint active container persona");
        let (client_cert_pem, _client_key_pem) = bridge_ca
            .sign_client_cert(&persona.id, Some(container_id), Duration::from_secs(3_600))
            .expect("mint initial client cert");
        let (initial_fingerprint, _) =
            pin_persona_client_cert_from_pem(&store, &persona.id, client_cert_pem.as_str())
                .expect("pin initial cert");

        RefreshFixture {
            store,
            mtls: MtlsPrincipal {
                persona_id: persona.id.clone(),
                container_id: container_id.to_string(),
                cert_fingerprint: hex_to_fingerprint(&initial_fingerprint),
            },
            parent_grant_id: parent_grant.id,
            persona_id: persona.id,
            initial_fingerprint,
        }
    }

    fn hex_to_fingerprint(hex_value: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = hex::decode(hex_value).expect("fingerprint hex decodes");
        assert_eq!(bytes.len(), 32, "fingerprint is 32 bytes");
        out.copy_from_slice(&bytes);
        out
    }

    fn denial_cause(value: &Value) -> &str {
        value["failure_cause"]
            .as_str()
            .expect("failure_cause string")
    }

    fn refresh_test_rate_limiter() -> RefCell<RateLimiter> {
        RefCell::new(RateLimiter::default())
    }

    async fn handle_refresh_once(
        store: &DaemonStore,
        mtls: Option<&MtlsPrincipal>,
        params: Value,
    ) -> Value {
        let rate_limiter = refresh_test_rate_limiter();
        handle_refresh_cert(None, mtls, store, &rate_limiter, &params)
            .await
            .expect("refresh_cert response")
    }

    fn init_refresh_receipt_identity() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir for daemon identity");
        let _ = crate::infra::receipt::init_identity(dir.path());
        dir
    }

    fn refresh_receipt_envelopes(
        store: &DaemonStore,
        grant_id: &str,
    ) -> Vec<(
        String,
        String,
        String,
        core_events::receipt::ReceiptEnvelope,
    )> {
        store
            .list_receipts_v2_envelopes(&[grant_id.to_string()])
            .expect("list refresh receipt envelopes")
    }

    fn verify_refresh_receipt(envelope: &core_events::receipt::ReceiptEnvelope) {
        let identity = crate::infra::receipt::current_identity().expect("identity loaded");
        let public_key = core_crypto::PublicKey(format!("ed25519:{}", identity.pubkey_hex()));
        core_events::receipt::verify_receipt_v2(
            envelope,
            &public_key,
            &core_crypto::FixtureVerifier,
        )
        .expect("refresh receipt verifies under daemon identity");
    }

    /// A `broker_issue` request for the **anthropic** provider — the only
    /// provider with a derive-gated `broker_issue` path (ADR 204 BKR-1).
    fn issue_params(ttl_secs: u64, reason: &str) -> Value {
        json!({
            "provider": "anthropic",
            "scope": {"name": "caller-attempt-IGNORED"},
            "ttl": ttl_secs,
            "reason": reason,
        })
    }

    fn create_budgeted_anthropic_grant(store: &DaemonStore, persona_id: &str) {
        store
            .create_grant_with_budget(
                persona_id,
                "anthropic",
                "dns:edit",
                None,
                Some(core_grant_types::Budget {
                    requests: Some(100),
                    ..core_grant_types::Budget::default()
                }),
            )
            .expect("create budgeted anthropic grant");
    }

    /// Return a `PolicyEngine` whose default for `credential.access.*` is
    /// `Auto` so tests that do not exercise HITL flow skip the poll loop.
    fn auto_policy() -> crate::trust::policy::PolicyEngine {
        use crate::trust::policy::ApprovalRequirement;
        use core_approval::policy::{PolicyConfig, PolicyRule, RiskLevel};
        crate::trust::policy::PolicyEngine::new(PolicyConfig {
            rules: vec![PolicyRule {
                action: core_approval::policy::ActionSelector::named("*"),
                risk: RiskLevel::Low,
                requirement: ApprovalRequirement::Auto,
                tier: None,
            }],
            default_requirement: ApprovalRequirement::Auto,
            default_risk: RiskLevel::Low,
        })
    }

    // -----------------------------------------------------------------------
    // Admin RPCs for managing
    // credential bindings. The admin path does NOT require biometric;
    // callers authenticate to the daemon via PeerCred.
    // -----------------------------------------------------------------------

    /// `handle_broker_bindings_register` + `handle_broker_bindings_list`
    /// round-trip — registering a binding and listing it back returns
    /// the same remote URL.
    #[tokio::test]
    async fn bindings_register_then_list_roundtrip() {
        let store = DaemonStore::open_in_memory().unwrap();
        let principal_id = "00000000-0000-0000-0000-000000000001";
        let params = json!({
            "caller_persona": principal_id,
            "working_tree_id": "/tmp/test-repo",
            "remote_name": "origin",
            "remote_url": "git@github.com:foo/bar.git",
        });
        handle_broker_bindings_register(None, &store, &params)
            .await
            .unwrap();

        let list_params = json!({"caller_persona": principal_id});
        let list_result = handle_broker_bindings_list(None, &store, &list_params)
            .await
            .unwrap();
        let bindings: Vec<Value> = serde_json::from_value(list_result["bindings"].clone()).unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0]["remote_url"], "git@github.com:foo/bar.git");
        assert_eq!(bindings[0]["working_tree_id"], "/tmp/test-repo");
        assert_eq!(bindings[0]["remote_name"], "origin");
    }

    /// `handle_broker_bindings_remove` returns `true` when a row was
    /// deleted, `false` on a second remove of the same key.
    #[tokio::test]
    async fn bindings_remove_reports_true_then_false() {
        let store = DaemonStore::open_in_memory().unwrap();
        let principal_id = "00000000-0000-0000-0000-000000000001";
        let register_params = json!({
            "caller_persona": principal_id,
            "working_tree_id": "/tmp/remove-me",
            "remote_name": "origin",
            "remote_url": "git@github.com:foo/bar.git",
        });
        handle_broker_bindings_register(None, &store, &register_params)
            .await
            .unwrap();

        let remove_params = json!({
            "caller_persona": principal_id,
            "working_tree_id": "/tmp/remove-me",
            "remote_name": "origin",
        });
        let first = handle_broker_bindings_remove(None, &store, &remove_params)
            .await
            .unwrap();
        assert_eq!(first["removed"], true);

        let second = handle_broker_bindings_remove(None, &store, &remove_params)
            .await
            .unwrap();
        assert_eq!(second["removed"], false);
    }

    /// `handle_broker_bindings_move` updates `working_tree_id` for
    /// every row owned by the persona at the old path.
    #[tokio::test]
    async fn bindings_move_updates_working_tree_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let principal_id = "00000000-0000-0000-0000-000000000001";

        for remote_name in &["origin", "upstream"] {
            let params = json!({
                "caller_persona": principal_id,
                "working_tree_id": "/old/path",
                "remote_name": remote_name,
                "remote_url": format!("git@github.com:foo/{remote_name}.git"),
            });
            handle_broker_bindings_register(None, &store, &params)
                .await
                .unwrap();
        }

        let move_params = json!({
            "caller_persona": principal_id,
            "old_path": "/old/path",
            "new_path": "/new/path",
        });
        let result = handle_broker_bindings_move(None, &store, &move_params)
            .await
            .unwrap();
        assert_eq!(result["moved"], 2);

        let list_params = json!({"caller_persona": principal_id});
        let list_result = handle_broker_bindings_list(None, &store, &list_params)
            .await
            .unwrap();
        let bindings: Vec<Value> = serde_json::from_value(list_result["bindings"].clone()).unwrap();
        assert_eq!(bindings.len(), 2);
        for b in &bindings {
            assert_eq!(b["working_tree_id"], "/new/path");
        }
    }

    /// `handle_broker_bindings_register` refuses a nil caller_persona —
    /// the admin verb requires a real persona id, not the zero UUID.
    #[tokio::test]
    async fn bindings_register_refuses_nil_caller_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let params = json!({
            "caller_persona": "00000000-0000-0000-0000-000000000000",
            "working_tree_id": "/tmp/test-repo",
            "remote_name": "origin",
            "remote_url": "git@github.com:foo/bar.git",
        });
        let (code, msg) = handle_broker_bindings_register(None, &store, &params)
            .await
            .expect_err("nil caller_persona must be refused");
        assert_eq!(code, -32602);
        assert!(
            msg.to_lowercase().contains("nil"),
            "error must mention nil UUID, got: {msg}"
        );
    }

    /// `handle_broker_bindings_register` refuses a missing caller_persona
    /// — every admin verb requires the persona id.
    #[tokio::test]
    async fn bindings_register_refuses_missing_caller_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let params = json!({
            "working_tree_id": "/tmp/test-repo",
            "remote_name": "origin",
            "remote_url": "git@github.com:foo/bar.git",
        });
        let (code, _) = handle_broker_bindings_register(None, &store, &params)
            .await
            .expect_err("missing caller_persona must be refused");
        assert_eq!(code, -32602);
    }

    /// `handle_broker_bindings_list` returns only the caller persona's
    /// rows — bindings owned by a different principal are not visible.
    #[tokio::test]
    async fn bindings_list_filters_by_caller_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let persona_a = "00000000-0000-0000-0000-0000000000aa";
        let persona_b = "00000000-0000-0000-0000-0000000000bb";

        for (persona, tree) in &[(persona_a, "/tmp/a"), (persona_b, "/tmp/b")] {
            let params = json!({
                "caller_persona": persona,
                "working_tree_id": tree,
                "remote_name": "origin",
                "remote_url": "git@github.com:foo/bar.git",
            });
            handle_broker_bindings_register(None, &store, &params)
                .await
                .unwrap();
        }

        let list_a =
            handle_broker_bindings_list(None, &store, &json!({"caller_persona": persona_a}))
                .await
                .unwrap();
        let rows: Vec<Value> = serde_json::from_value(list_a["bindings"].clone()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["working_tree_id"], "/tmp/a");
    }

    /// `handle_broker_bindings_move` refuses identical paths — the
    /// no-op case is an operator error, not a silent success.
    #[tokio::test]
    async fn bindings_move_refuses_identical_paths() {
        let store = DaemonStore::open_in_memory().unwrap();
        let principal_id = "00000000-0000-0000-0000-000000000001";
        let params = json!({
            "caller_persona": principal_id,
            "old_path": "/same/path",
            "new_path": "/same/path",
        });
        let (code, _) = handle_broker_bindings_move(None, &store, &params)
            .await
            .expect_err("identical paths must be refused");
        assert_eq!(code, -32602);
    }

    // -----------------------------------------------------------------------
    // T3: presence_verification_failure — revoke all + freeze + issuance gate
    // -----------------------------------------------------------------------

    /// Calling `handle_presence_verification_failure` for a persona must
    /// add that persona to `frozen_personas` in the registry. No grants are
    /// present in this store so the revocation loop is a no-op; the freeze
    /// is the authoritative postcondition.
    #[test]
    fn presence_verification_failure_freezes_persona() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let ctx = PresenceVerificationFailureCtx {
            registry: &reg,
            store: &store,
        };

        assert!(
            !reg.is_persona_frozen("persona-frozen-test"),
            "persona must not be frozen before failure handler"
        );

        handle_presence_verification_failure(&ctx, "persona-frozen-test");

        assert!(
            reg.is_persona_frozen("persona-frozen-test"),
            "persona must be in frozen_personas after verification failure"
        );
    }

    /// Freezing a persona must cause `issue_with_registry` to return -32011
    /// for that persona while a different persona (not frozen) can still issue.
    #[tokio::test]
    async fn frozen_persona_cannot_issue_credentials() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let ctx = PresenceVerificationFailureCtx {
            registry: &reg,
            store: &store,
        };

        // Freeze "frozen-persona".
        handle_presence_verification_failure(&ctx, "frozen-persona");

        // Attempt to issue with the frozen persona — must be refused.
        let params = json!({
            "provider": "cloudflare",
            "scope": {"zone": "emberlink.dev", "permissions": ["dns:edit"]},
            "ttl": 900,
            "reason": "frozen-persona test",
            "caller_persona": "frozen-persona",
        });
        let err = issue_with_registry(&reg, &store, &params, &auto_policy())
            .await
            .expect_err("frozen persona must not be allowed to issue");
        assert_eq!(
            err.0, -32011,
            "expected frozen-persona error code -32011, got: {err:?}"
        );
        assert!(
            err.1.contains("frozen"),
            "error message must mention frozen: {}",
            err.1
        );

        // A different persona with an active budgeted grant can still issue.
        let open_persona = store.create_persona("unfrozen-issuer-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &open_persona.id);
        let mut open_params = issue_params(900, "unfrozen issuer");
        open_params["caller_persona"] = serde_json::json!(open_persona.id);
        issue_with_registry(&reg, &store, &open_params, &auto_policy())
            .await
            .expect("unfrozen persona with a budgeted grant must be able to issue");
    }

    /// `handle_presence_verification_failure` returns the count of revoked
    /// grants; when no grants exist the count is 0 and the persona is still
    /// frozen (freeze is unconditional regardless of revocation outcome).
    #[test]
    fn presence_verification_failure_returns_zero_when_no_grants() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let ctx = PresenceVerificationFailureCtx {
            registry: &reg,
            store: &store,
        };

        let revoked = handle_presence_verification_failure(&ctx, "persona-no-grants");
        assert_eq!(revoked, 0, "no grants to revoke — count must be 0");
        assert!(
            reg.is_persona_frozen("persona-no-grants"),
            "persona must be frozen even when no grants were present"
        );
    }

    /// `handle_request_presence_proof` MUST exist with the canonical dispatcher
    /// signature `(principal, store, params) -> Result<Value, (i32, String)>` so
    /// the JSON-RPC dispatch wiring is auditable.
    ///
    /// ADR 206 slice 4 C posture: the forgeable daemon-signed presence-proof
    /// bridge was deleted, so even a well-formed proof request is refused cleanly
    /// with `-32601 not_implemented`.
    #[tokio::test]
    async fn request_proof_dispatch_exists_and_refuses_well_formed_request() {
        let store = DaemonStore::open_in_memory().unwrap();
        let params = json!({
            "delegation_id": "wf-dispatch-checkpoint",
            "action_ref": {
                "plugin_address": "registry.ember.systems/ember-systems/ember-presence",
                "action_key": "approve-grant",
                "action_version": "v1"
            },
            "spiffe_uri": "spiffe://emberlink.dev/agent/presence-test",
            "nonce_hex": hex::encode([0x11u8, 0x22, 0x33, 0x44]),
            "persona_id": "persona-dispatch-checkpoint",
            "caller_persona": null,
            "ttl_ms": null,
        });
        let result = handle_request_presence_proof(None, &store, &params).await;
        let (code, msg) = result.expect_err(
            "production wiring deferred — dispatcher must return -32601 not_implemented",
        );
        assert_eq!(
            code, -32601,
            "until production TabChannel/AssertionVerifier wiring lands, \
             dispatcher must surface -32601 not_implemented (checkpoint for the \
             follow-up wiring task)"
        );
        assert!(
            msg.contains("retired") || msg.contains("se-unlock") || msg.contains("deleted"),
            "refusal must explain that the forgeable presence-proof bridge was retired: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // (ADR 200 §5) The T5 `presence/enroll` first-run WebAuthn enrollment tests
    // were removed when `handle_first_run_enrollment` was retired in G2 Slice 1b.
    // Operator presence-device enrollment is now the `identity.device.enroll`
    // daemon RPC (prepare→commit over `operator_identity`); its tests live in
    // `infra/handler.rs` and `infra/operator_identity.rs`.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Per-cohort presence fallback ladder (ADR 158)
    // -----------------------------------------------------------------------

    /// dev0 + Open: PAM passphrase fallback is admissible alongside the
    /// FIDO2 primary factor. Friction-first dev0 cohort gets the recovery
    /// path on session-open.
    #[test]
    fn dev0_open_allows_pam_fallback() {
        let decision = presence_fallback_ladder("dev0", SessionPhase::Open);
        assert_eq!(
            decision,
            LadderDecision::Fido2Required { fallback_pam: true },
            "dev0 + Open must allow PAM fallback"
        );
    }

    /// dev0 + MidSession: PAM passphrase fallback is REFUSED — mid-session
    /// recovery is UNAVAILABLE across all cohorts per
    /// ADR-DRAFT-BROWSER-AS-TOUCH-ID-PROMPTER D7.
    #[test]
    fn dev0_midsession_refuses_pam_fallback() {
        let decision = presence_fallback_ladder("dev0", SessionPhase::MidSession);
        assert_eq!(
            decision,
            LadderDecision::Fido2Required {
                fallback_pam: false
            },
            "dev0 + MidSession must refuse PAM fallback"
        );
    }

    /// team0: no fallback path on either phase. Security-first cohort —
    /// only the registered FIDO2 factor satisfies the gate.
    #[test]
    fn team0_no_fallback_any_phase() {
        assert_eq!(
            presence_fallback_ladder("team0", SessionPhase::Open),
            LadderDecision::Fido2RequiredNoFallback,
            "team0 + Open must be no-fallback"
        );
        assert_eq!(
            presence_fallback_ladder("team0", SessionPhase::MidSession),
            LadderDecision::Fido2RequiredNoFallback,
            "team0 + MidSession must be no-fallback"
        );
    }

    /// ent0: FIDO2 plus an audit-log entry on every prompt, regardless of
    /// phase. Compliance posture — every second-factor event is recorded.
    #[test]
    fn ent0_audits_second_factor_any_phase() {
        assert_eq!(
            presence_fallback_ladder("ent0", SessionPhase::Open),
            LadderDecision::Fido2PlusAuditLog,
            "ent0 + Open must audit second factor"
        );
        assert_eq!(
            presence_fallback_ladder("ent0", SessionPhase::MidSession),
            LadderDecision::Fido2PlusAuditLog,
            "ent0 + MidSession must audit second factor"
        );
    }

    /// Unknown cohort: fails closed. Defense in depth — an unrecognized
    /// cohort string (typo, future cohort that has not been added to the
    /// policy table) must refuse rather than fall through to a permissive
    /// default.
    #[test]
    fn unknown_cohort_fails_closed() {
        assert_eq!(
            presence_fallback_ladder("contractor0", SessionPhase::Open),
            LadderDecision::FailClosed,
            "unknown cohort + Open must fail closed"
        );
        assert_eq!(
            presence_fallback_ladder("", SessionPhase::MidSession),
            LadderDecision::FailClosed,
            "empty cohort must fail closed"
        );
    }

    /// Mid-session UNAVAILABLE override: when the presence subsystem
    /// reports UNAVAILABLE during a `MidSession` re-prompt, the answer is
    /// always `FailClosed` regardless of cohort. Exercised here for the
    /// dev0 cohort to anchor the contract; the override wrapper is
    /// cohort-agnostic.
    #[test]
    fn unavailable_midsession_fails_closed_for_dev0() {
        assert_eq!(
            presence_fallback_ladder_unavailable("dev0", SessionPhase::MidSession),
            LadderDecision::FailClosed,
            "dev0 + MidSession + UNAVAILABLE must fail closed"
        );
        // Also confirm the override applies to other cohorts — UNAVAILABLE
        // mid-session is a global gate, not a dev0-specific one.
        assert_eq!(
            presence_fallback_ladder_unavailable("team0", SessionPhase::MidSession),
            LadderDecision::FailClosed,
            "team0 + MidSession + UNAVAILABLE must fail closed"
        );
        assert_eq!(
            presence_fallback_ladder_unavailable("ent0", SessionPhase::MidSession),
            LadderDecision::FailClosed,
            "ent0 + MidSession + UNAVAILABLE must fail closed"
        );
    }

    // ----- refresh_cert RPC dispatch tests -----

    /// T1: non-bridge callers cannot refresh because the current cert proof is
    /// the mTLS principal stamped by the bridge listener.
    #[tokio::test]
    async fn refresh_cert_without_mtls_principal_is_denied() {
        let store = DaemonStore::open_in_memory().unwrap();
        let params = json!({});

        let res = handle_refresh_once(&store, None, params).await.clone();

        assert_eq!(
            res["denied"],
            json!(true),
            "shape carries denied discriminator"
        );
        assert_eq!(
            res["failure_cause"],
            json!("auth_failure_persona_unknown"),
            "non-mTLS callers cannot satisfy the current-cert proof"
        );
        assert!(
            res["reason"].as_str().unwrap().contains("mTLS"),
            "reason names the missing proof: {res}"
        );
    }

    /// T1: RefreshDenied::not_implemented constructor produces a typed
    /// instance round-trippable through serde.
    #[test]
    fn refresh_denied_not_implemented_round_trip() {
        let denied = RefreshDenied::not_implemented();
        assert_eq!(denied.failure_cause, RefreshFailureCause::NotImplemented);

        let custom = RefreshDenied::new(RefreshFailureCause::AuthFailureExpired, "expired");
        assert_eq!(custom.reason, "expired");
        assert_eq!(
            custom.failure_cause,
            RefreshFailureCause::AuthFailureExpired
        );

        let json_val = serde_json::to_value(&denied).expect("serialize");
        assert_eq!(json_val["failure_cause"], json!("not_implemented"));

        let parsed: RefreshDenied = serde_json::from_value(json_val).expect("deserialize");
        assert_eq!(parsed, denied);
    }

    /// T1: all M3-A failure cause variants serialize as expected
    /// snake_case strings per the ADR 118 Extension 5 lock.
    #[test]
    fn refresh_failure_cause_serde_shape_is_snake_case() {
        let cases = [
            (RefreshFailureCause::TransportError, "transport_error"),
            (
                RefreshFailureCause::AuthFailureRevoked,
                "auth_failure_revoked",
            ),
            (
                RefreshFailureCause::AuthFailureExpired,
                "auth_failure_expired",
            ),
            (
                RefreshFailureCause::AuthFailurePersonaUnknown,
                "auth_failure_persona_unknown",
            ),
            (
                RefreshFailureCause::MintFailureVaultSealed,
                "mint_failure_vault_sealed",
            ),
            (
                RefreshFailureCause::MintFailureInternal,
                "mint_failure_internal",
            ),
            (RefreshFailureCause::ExhaustedRetries, "exhausted_retries"),
            (RefreshFailureCause::RateLimited, "rate_limited"),
            (RefreshFailureCause::NotImplemented, "not_implemented"),
        ];
        for (cause, expected) in cases {
            let v = serde_json::to_value(&cause).expect("serialize");
            assert_eq!(v, json!(expected), "variant {cause:?} expected {expected}");
        }
    }

    #[tokio::test]
    async fn refresh_cert_identity_denies_container_san_mismatch() {
        let mut fx = refresh_fixture("ctr-refresh-a");
        fx.mtls.container_id = "ctr-refresh-b".to_string();

        let res = handle_refresh_once(&fx.store, Some(&fx.mtls), json!({})).await;

        assert_eq!(res["denied"], json!(true));
        assert_eq!(denial_cause(&res), "auth_failure_persona_unknown");
        assert!(
            res["reason"].as_str().unwrap().contains("container"),
            "reason should name container mismatch: {res}"
        );
    }

    #[tokio::test]
    async fn refresh_cert_identity_denies_presented_cert_fingerprint_mismatch() {
        let mut fx = refresh_fixture("ctr-refresh-fingerprint-mismatch");
        fx.mtls.cert_fingerprint = [0x44; 32];

        let res = handle_refresh_once(&fx.store, Some(&fx.mtls), json!({})).await;

        assert_eq!(res["denied"], json!(true));
        assert_eq!(denial_cause(&res), "auth_failure_persona_unknown");
        assert!(
            res["reason"].as_str().unwrap().contains("fingerprint"),
            "reason should name cert fingerprint mismatch: {res}"
        );
    }

    #[tokio::test]
    async fn refresh_cert_identity_denies_revoked_parent_grant() {
        let fx = refresh_fixture("ctr-refresh-revoked");
        fx.store.revoke_grant(&fx.parent_grant_id).unwrap();

        let res = handle_refresh_once(&fx.store, Some(&fx.mtls), json!({})).await;

        assert_eq!(res["denied"], json!(true));
        assert_eq!(denial_cause(&res), "auth_failure_revoked");
    }

    #[tokio::test]
    async fn refresh_cert_identity_denies_revoked_persona() {
        let fx = refresh_fixture("ctr-refresh-revoked-persona");
        fx.store.revoke_persona(&fx.persona_id).unwrap();

        let res = handle_refresh_once(&fx.store, Some(&fx.mtls), json!({})).await;

        assert_eq!(res["denied"], json!(true));
        assert_eq!(denial_cause(&res), "auth_failure_persona_unknown");
        assert!(
            res["reason"].as_str().unwrap().contains("not active"),
            "reason should name inactive persona state: {res}"
        );
    }

    #[tokio::test]
    async fn refresh_cert_identity_denies_expired_pinned_cert() {
        let fx = refresh_fixture("ctr-refresh-expired");
        fx.store
            .set_persona_client_cert(&fx.persona_id, &fx.initial_fingerprint, 1)
            .unwrap();

        let res = handle_refresh_once(&fx.store, Some(&fx.mtls), json!({})).await;

        assert_eq!(res["denied"], json!(true));
        assert_eq!(denial_cause(&res), "auth_failure_expired");
    }

    #[tokio::test]
    async fn refresh_cert_denies_legacy_empty_fingerprint_row() {
        let fx = refresh_fixture("ctr-refresh-legacy");
        fx.store
            .set_persona_client_cert(&fx.persona_id, "", 0)
            .unwrap();

        let res = handle_refresh_once(&fx.store, Some(&fx.mtls), json!({})).await;

        assert_eq!(res["denied"], json!(true));
        assert_eq!(denial_cause(&res), "auth_failure_persona_unknown");
        assert!(
            res["reason"].as_str().unwrap().contains("legacy"),
            "reason locks legacy-row refusal policy: {res}"
        );
    }

    #[tokio::test]
    async fn refresh_cert_mints_and_updates_persona_cert_state() {
        let fx = refresh_fixture("ctr-refresh-success");

        let res = handle_refresh_once(
            &fx.store,
            Some(&fx.mtls),
            json!({"caller_grant_id": fx.parent_grant_id.clone()}),
        )
        .await;

        assert_eq!(res["denied"], json!(false));
        assert_eq!(res["persona_id"], json!(fx.persona_id));
        assert_eq!(res["container_id"], json!("ctr-refresh-success"));
        assert_eq!(res["refresh_seq"], json!(1));
        assert_eq!(res["previous_refresh_seq"], json!(0));
        assert!(
            res["client_cert_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        assert!(
            res["client_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PRIVATE KEY")
        );

        let state = fx
            .store
            .get_persona_client_cert_state(
                res["persona_id"].as_str().expect("persona id in response"),
            )
            .unwrap();
        assert_eq!(
            state.fingerprint_hex,
            res["client_cert_fingerprint"].as_str().unwrap()
        );
        assert_ne!(
            state.fingerprint_hex, fx.initial_fingerprint,
            "refresh must immediate-replace the spawn-time cert pin"
        );
        assert_eq!(
            state.not_after_unix,
            res["client_cert_not_after"].as_i64().unwrap()
        );
        assert_eq!(state.refresh_seq, 1);
    }

    #[tokio::test]
    async fn refresh_cert_denies_old_cert_after_success_without_mutating_row() {
        let fx = refresh_fixture("ctr-refresh-old-cert");
        let first = handle_refresh_once(
            &fx.store,
            Some(&fx.mtls),
            json!({"caller_grant_id": fx.parent_grant_id.clone()}),
        )
        .await;
        assert_eq!(first["denied"], json!(false));
        let refreshed_state = fx
            .store
            .get_persona_client_cert_state(&fx.persona_id)
            .unwrap();
        assert_eq!(refreshed_state.refresh_seq, 1);

        let stale = handle_refresh_once(
            &fx.store,
            Some(&fx.mtls),
            json!({"caller_grant_id": fx.parent_grant_id.clone()}),
        )
        .await;

        assert_eq!(stale["denied"], json!(true));
        assert_eq!(denial_cause(&stale), "auth_failure_persona_unknown");
        assert!(
            stale["reason"].as_str().unwrap().contains("fingerprint"),
            "old cert denial must name the stale fingerprint binding: {stale}"
        );
        let after_stale = fx
            .store
            .get_persona_client_cert_state(&fx.persona_id)
            .unwrap();
        assert_eq!(
            after_stale, refreshed_state,
            "stale old-cert refresh must not mint, update, or bump refresh_seq"
        );
    }

    #[tokio::test]
    async fn refresh_cert_success_emits_signed_cert_refreshed_receipt() {
        let _identity_dir = init_refresh_receipt_identity();
        let fx = refresh_fixture("ctr-refresh-receipt-success");

        let res = handle_refresh_once(
            &fx.store,
            Some(&fx.mtls),
            json!({
                "caller_grant_id": fx.parent_grant_id.clone(),
                "trigger_reason": "retry_after_failure",
                "recovered_from_failure_count": 2,
                "parent_receipt_id": "rct-parent"
            }),
        )
        .await;

        let receipt_id = res["receipt_id"].as_str().expect("success receipt id");
        let receipts = refresh_receipt_envelopes(&fx.store, &fx.parent_grant_id);
        let (_, kind, grant_id, envelope) = receipts
            .iter()
            .find(|(_, kind, _, _)| {
                kind == core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_REFRESHED
            })
            .expect("cert_refreshed receipt row");
        assert_eq!(
            kind,
            core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_REFRESHED
        );
        assert_eq!(grant_id, &fx.parent_grant_id);
        assert_eq!(envelope.receipt_id, receipt_id);
        verify_refresh_receipt(envelope);

        let body: core_events::receipt::BridgeCertRefreshedBody =
            serde_json::from_value(envelope.body.clone()).expect("cert_refreshed body parses");
        assert_eq!(body.old_cert_fingerprint, fx.initial_fingerprint);
        assert_eq!(
            body.new_cert_fingerprint,
            res["client_cert_fingerprint"].as_str().unwrap()
        );
        assert_eq!(body.persona_id, fx.persona_id);
        assert_eq!(body.container_id, "ctr-refresh-receipt-success");
        assert_eq!(body.refresh_seq, 1);
        assert_eq!(body.parent_receipt_id.as_deref(), Some("rct-parent"));
        assert_eq!(
            body.trigger_reason,
            core_events::receipt::BridgeCertRefreshTriggerReason::RetryAfterFailure
        );
        assert_eq!(body.recovered_from_failure_count, 2);
    }

    // ADR 118 Extension 6 / ADR 173 M4 — successful refresh emits
    // `bridge.cert_superseded` alongside `bridge.cert_refreshed`. Anchor:
    // `daemon_bridge_cert_superseded_event_emitted`.
    #[tokio::test]
    async fn refresh_cert_success_emits_cert_superseded_event() {
        let _identity_dir = init_refresh_receipt_identity();
        let fx = refresh_fixture("ctr-refresh-superseded-success");

        let res = handle_refresh_once(
            &fx.store,
            Some(&fx.mtls),
            json!({ "caller_grant_id": fx.parent_grant_id.clone() }),
        )
        .await;
        assert_eq!(res["denied"], json!(false));

        let receipts = refresh_receipt_envelopes(&fx.store, &fx.parent_grant_id);
        let (_, kind, grant_id, envelope) = receipts
            .iter()
            .find(|(_, kind, _, _)| {
                kind == core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_SUPERSEDED
            })
            .expect("cert_superseded receipt row");
        assert_eq!(
            kind,
            core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_SUPERSEDED
        );
        assert_eq!(grant_id, &fx.parent_grant_id);
        verify_refresh_receipt(envelope);

        let body: core_events::receipt::BridgeCertSupersededBody =
            serde_json::from_value(envelope.body.clone())
                .expect("cert_superseded body parses round-trip");
        assert_eq!(body.old_cert_fingerprint, fx.initial_fingerprint);
        assert_eq!(
            body.new_cert_fingerprint,
            res["client_cert_fingerprint"].as_str().unwrap()
        );
        assert_eq!(body.persona_id, fx.persona_id);
        assert_ne!(
            body.old_cert_fingerprint, body.new_cert_fingerprint,
            "supersede must mark a real cert change"
        );

        // Both halves of the lifecycle pair land on the same UPDATE: an
        // audit walker keyed on either kind resolves the refresh.
        let has_refreshed = receipts.iter().any(|(_, k, _, _)| {
            k == core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_REFRESHED
        });
        assert!(
            has_refreshed,
            "cert_superseded must accompany cert_refreshed, not replace it"
        );
    }

    // ADR 173 M4 — `bridge.cert_superseded` MUST NOT be emitted when the
    // refresh denies (auth failure here). The persona row's cert pin did not
    // change, so there is nothing to mark superseded; emitting would lie to
    // the audit log. Anchor: `daemon_bridge_cert_superseded_event_emitted`.
    #[tokio::test]
    async fn refresh_cert_failure_does_not_emit_cert_superseded_event() {
        let _identity_dir = init_refresh_receipt_identity();
        let mut fx = refresh_fixture("ctr-refresh-superseded-failure");
        fx.mtls.cert_fingerprint = [0x44; 32];

        let res = handle_refresh_once(
            &fx.store,
            Some(&fx.mtls),
            json!({ "caller_grant_id": fx.parent_grant_id.clone() }),
        )
        .await;
        assert_eq!(res["denied"], json!(true));
        assert_eq!(denial_cause(&res), "auth_failure_persona_unknown");

        let receipts = refresh_receipt_envelopes(&fx.store, &fx.parent_grant_id);
        let superseded = receipts.iter().find(|(_, k, _, _)| {
            k == core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_SUPERSEDED
        });
        assert!(
            superseded.is_none(),
            "failed refresh must not emit cert_superseded: {:?}",
            superseded.map(|r| &r.1)
        );
    }

    #[tokio::test]
    async fn refresh_cert_identity_failure_emits_signed_failed_receipt() {
        let _identity_dir = init_refresh_receipt_identity();
        let mut fx = refresh_fixture("ctr-refresh-receipt-failure");
        fx.mtls.cert_fingerprint = [0x44; 32];

        let res = handle_refresh_once(
            &fx.store,
            Some(&fx.mtls),
            json!({
                "caller_grant_id": fx.parent_grant_id.clone(),
                "attempt_count": 3
            }),
        )
        .await;
        assert_eq!(res["denied"], json!(true));
        assert_eq!(denial_cause(&res), "auth_failure_persona_unknown");

        let receipts = refresh_receipt_envelopes(&fx.store, &fx.parent_grant_id);
        let (_, kind, grant_id, envelope) = receipts
            .iter()
            .find(|(_, kind, _, _)| {
                kind == core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_REFRESH_FAILED
            })
            .expect("cert_refresh_failed receipt row");
        assert_eq!(
            kind,
            core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_REFRESH_FAILED
        );
        assert_eq!(grant_id, &fx.parent_grant_id);
        verify_refresh_receipt(envelope);

        let body: core_events::receipt::BridgeCertRefreshFailedBody =
            serde_json::from_value(envelope.body.clone()).expect("failed body parses");
        assert_eq!(body.persona_id, fx.persona_id);
        assert_eq!(body.container_id, "ctr-refresh-receipt-failure");
        assert_eq!(body.grant_id, fx.parent_grant_id);
        assert_eq!(body.refresh_seq, 1);
        assert_eq!(body.attempt_count, 3);
        assert_eq!(body.failure_cause, "auth_failure_persona_unknown");
        assert!(body.reason.contains("fingerprint"));
        assert_eq!(body.retry_after_seconds, None);
    }

    #[tokio::test]
    async fn refresh_cert_mint_failure_preserves_persona_cert_state() {
        let fx = refresh_fixture_with_loaded_bridge_ca("ctr-refresh-vault-sealed", false);
        let before = fx
            .store
            .get_persona_client_cert_state(&fx.persona_id)
            .unwrap();

        let res = handle_refresh_once(&fx.store, Some(&fx.mtls), json!({}))
            .await
            .clone();

        assert_eq!(res["denied"], json!(true));
        assert_eq!(denial_cause(&res), "mint_failure_vault_sealed");
        let after = fx
            .store
            .get_persona_client_cert_state(&fx.persona_id)
            .unwrap();
        assert_eq!(
            after, before,
            "mint failures must not partially mutate persona cert columns"
        );
    }

    #[tokio::test]
    async fn refresh_cert_rate_limits_second_valid_refresh_for_same_chain() {
        let fx = refresh_fixture("ctr-refresh-rate-limited");
        let rate_limiter = refresh_test_rate_limiter();
        let first_params = json!({"caller_grant_id": fx.parent_grant_id.clone()});
        let first = handle_refresh_cert(
            None,
            Some(&fx.mtls),
            &fx.store,
            &rate_limiter,
            &first_params,
        )
        .await
        .expect("first refresh succeeds");
        assert_eq!(first["denied"], json!(false));

        let mut refreshed_mtls = fx.mtls.clone();
        refreshed_mtls.cert_fingerprint =
            hex_to_fingerprint(first["client_cert_fingerprint"].as_str().unwrap());
        let second_params = json!({"caller_grant_id": fx.parent_grant_id});
        let second = handle_refresh_cert(
            None,
            Some(&refreshed_mtls),
            &fx.store,
            &rate_limiter,
            &second_params,
        )
        .await
        .expect("second refresh returns denial body");

        assert_eq!(second["denied"], json!(true));
        assert_eq!(denial_cause(&second), "rate_limited");
        assert_eq!(
            fx.store
                .get_persona_client_cert_state(&fx.persona_id)
                .unwrap()
                .refresh_seq,
            1,
            "rate-limited refresh must not mint or update the persona row"
        );
    }
}
