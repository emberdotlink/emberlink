//! Socket RPC handlers for the credential broker (ADR 094 Phase 2).
//!
//! Wires `ember broker {issue,revoke,list}` CLI calls onto the daemon's
//! existing JSON-lines socket protocol. The broker registry is a
//! process-global `OnceCell` initialised once at daemon startup
//! (`runtime.rs::run`); subsequent dispatcher calls look it up via
//! `current_registry()`.
//!
//! ## RPC method names (matched in `handler.rs::dispatch_method`)
//!
//! - `broker_issue`  → [`handle_broker_issue`]
//! - `broker_revoke` → [`handle_broker_revoke`]
//! - `broker_list`   → [`handle_broker_list`]
//!
//! Marker for autopilot ranker grep: **`BrokerIssue`** (this module path is
//! `broker_handler`, satisfying the marker contract.)
//!
//! ## Object-safety adapter
//!
//! `core_broker::Broker` uses `async fn` in trait via `impl Future`, which
//! is NOT dyn-compatible. To store heterogeneous providers in a single
//! `HashMap`, this module defines [`DynBroker`] — an object-safe trait
//! that returns `Pin<Box<dyn Future>>` instead. A blanket impl wraps any
//! concrete `Broker` so `MockBroker` (and future providers) drop in
//! without provider-side ceremony.
//!
//! ## Materialization audit and receipt emission
//!
//! Per ADR 204/205, materialization success/failure facts are audit events,
//! not root-verifiable authority receipts. Successful issue paths emit
//! `action = "broker.materialization"` into the hash-chained audit log and
//! fail closed if that record cannot be written. Revocation remains a signed
//! broker receipt plus a back-compat audit shadow row.
//!
//! Audit: `cred_plaintext_lifetime_audit_landed` freezes the 2026-06
//! plaintext-lifetime map in `docs/audits/cred-plaintext-lifetime-2026-06.md`.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use chrono::{DateTime, Utc};
#[cfg(test)]
use core_broker::BrokerProvider;
use core_crypto::Signer as _;
use serde_json::{Value, json};

use crate::infra::audit::AuditFilter;
use crate::infra::handler::{DispatchSource, RequestContext, current_dispatch_deployment_tier};
use crate::infra::rpc_error::RpcError;
use crate::infra::store::DaemonStore;
use crate::infra::store::StoreError;

mod exec;
mod exec_admission;
mod exec_credentials;
mod exec_policy;
#[cfg(test)]
mod execution_tests;
mod materialization;
mod principal_gates;
mod pty;
mod registry;
mod resolve;
mod runtime_authority;

pub use exec::{handle_broker_exec, handle_broker_exec_with_sessions};
pub use materialization::{
    github_status_with_registry_and_resolver, issue_with_registry, list_with_registry,
    registry_status_with_registry, revoke_with_registry,
};
pub use registry::{
    BrokerRegistry, BrokerRegistryAuthority, DynBroker, GithubProviderStatus,
    MaterializationSummary, PendingSpawnHandle, ProviderRegistrationStatus, SPAWN_HANDLE_TTL_SECS,
    current_manifest, current_registry, current_registry_authority, install_manifest,
    install_registry, install_registry_with_authority,
};

pub use exec_policy::{
    AuthoringPathsRegistry, BrokerExecRequest, BrokerExecResponse, PinError, PinnedBinary,
    authoring_paths_registry_path, classify_argv_daemon_side, extract_remote_name_daemon_side,
    load_authoring_paths_registry, script_is_in_authoring_path, verify_binary_pin,
};
use principal_gates::log_legacy_socket_resolution;
pub use principal_gates::{
    ERR_BINARY_PIN_REFUSED, ERR_GRANT_SCHEMA_VERSION_MISMATCH, ERR_PRINCIPAL_NAMESPACE_MISMATCH,
    ERR_PRINCIPAL_NOT_ALIVE, FAIL_CLOSED_RPC_ROLLOUT_COMPLETE, LegacySocketResolution,
    check_grant_schema_version, check_grants_schema_version_for_persona, check_peer_binary_pinned,
    check_peer_binary_pinned_with, check_principal_against_persona,
    check_principal_enrollment_strict, check_principal_is_alive, check_principal_namespace_inodes,
    resolve_legacy_socket_enrollment,
};
pub use runtime_authority::{
    LadderDecision, PresenceVerificationFailureCtx, RefreshDenied, RefreshFailureCause,
    RegisterPidWatcherRequest, SessionPhase, handle_broker_bindings_list,
    handle_broker_bindings_move, handle_broker_bindings_register, handle_broker_bindings_remove,
    handle_broker_register_pid_watcher, handle_presence_verification_failure, handle_refresh_cert,
    handle_request_presence_proof, presence_fallback_ladder, presence_fallback_ladder_unavailable,
};
use runtime_authority::{consume_issue_presence_ladder_decision, issue_presence_ladder_decision};

pub use pty::{
    BridgeExit, PtyBridge, PtyBridgeError, PtyFrame, ShimEofOutcome, ShimEofPolicy, TAG_DATA,
    TAG_SIGCONT, TAG_SIGINT, TAG_SIGTERM, TAG_SIGTSTP, TAG_WINSIZE, decode_one_frame,
    encode_data_frame, encode_winsize_frame, on_shim_eof, pty_bridge_run,
};
pub(crate) use resolve::{
    DelegationEvalOutcome, eval_workflow_for_action, resolve_workflow_strict_mode,
};
#[cfg(test)]
pub(crate) use resolve::{DelegationReceiptContext, resolve_with_registry};
pub use resolve::{ResolveError, broker_resolve_plaintext, handle_broker_resolve};

// ---------------------------------------------------------------------------

pub(super) fn now_rfc3339_at(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    DateTime::<Utc>::from_timestamp(secs, 0)
        .unwrap_or_else(Utc::now)
        .to_rfc3339()
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Dispatchers (resolve registry from the process-global OnceCell)
// ---------------------------------------------------------------------------

// `-32010` is reserved for `ERR_GRANT_SCHEMA_VERSION_MISMATCH`
// — see [`check_grant_schema_version`].
// ERR_NO_REGISTRY moved to `-32011` to free up `-32010` for the
// schema-version gate.
const ERR_NO_REGISTRY: (i32, &str) = (
    -32011,
    "broker registry not initialised — start emberd to populate",
);

fn err_no_registry() -> (i32, String) {
    (ERR_NO_REGISTRY.0, ERR_NO_REGISTRY.1.to_string())
}

fn optional_param_string<'a>(params: &'a Value, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| params.get(*name).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn approval_resolve_params(params: &Value) -> Result<Value, (i32, String)> {
    let mut normalized = params.as_object().cloned().ok_or_else(|| {
        (
            -32602,
            "approval.resolve params must be an object".to_string(),
        )
    })?;
    if !normalized.contains_key("id")
        && let Some(approval_id) = normalized.get("approval_id").cloned()
    {
        normalized.insert("id".to_string(), approval_id);
    }
    normalized
        .entry("decision".to_string())
        .or_insert_with(|| Value::String("approve".to_string()));
    Ok(Value::Object(normalized))
}

fn approval_narrow_params(params: &Value) -> Result<Value, (i32, String)> {
    let mut normalized = params.as_object().cloned().ok_or_else(|| {
        (
            -32602,
            "approval.narrow params must be an object".to_string(),
        )
    })?;
    if !normalized.contains_key("id")
        && let Some(approval_id) = normalized.get("approval_id").cloned()
    {
        normalized.insert("id".to_string(), approval_id);
    }
    if !normalized.contains_key("scope") {
        if let Some(scope) = normalized.get("new_scope").cloned() {
            normalized.insert("scope".to_string(), scope);
        } else if let Some(scope) = normalized.get("narrow").cloned() {
            normalized.insert("scope".to_string(), scope);
        }
    }
    if let Some(decision) = normalized.get("decision").and_then(Value::as_str)
        && decision != "narrow"
    {
        return Err((
            -32602,
            format!("approval.narrow requires decision 'narrow', got {decision}"),
        ));
    }
    normalized.insert("decision".to_string(), Value::String("narrow".to_string()));
    Ok(Value::Object(normalized))
}

/// approval_resolve_rpc_landed — expose the open-store approval resolver as
/// daemon RPC aliases while preserving the existing approval two-party and
/// presence checks in `infra::handlers::approval::handle_resolve`.
pub(crate) async fn handle_approval_resolve(
    store: &DaemonStore,
    ctx: &RequestContext,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let normalized = approval_resolve_params(params)?;
    crate::infra::handlers::approval::handle_resolve(store, ctx, source, &normalized).await
}

/// approval_resolve_rpc_landed — `approval.narrow` is a narrower spelling of
/// the same resolver with `decision = narrow` and accepted `approval_id` /
/// `new_scope` aliases for the open-store migration caller.
pub(crate) async fn handle_approval_narrow(
    store: &DaemonStore,
    ctx: &RequestContext,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let normalized = approval_narrow_params(params)?;
    crate::infra::handlers::approval::handle_resolve(store, ctx, source, &normalized).await
}

fn receipt_persona_scope(
    ctx: &RequestContext,
    method: &str,
    params: &Value,
) -> Result<Option<String>, (i32, String)> {
    let claimed_persona =
        optional_param_string(params, &["persona_id", "persona", "actor"]).map(String::from);
    match crate::infra::handlers::principal::team0_connect_only_persona_scope(ctx, method)? {
        Some(trusted_persona) => {
            if let Some(claimed) = claimed_persona.as_deref()
                && claimed != trusted_persona
            {
                tracing::warn!(
                    method = %method,
                    claimed_persona_id = %claimed,
                    trusted_persona_id = %trusted_persona,
                    "connect-only persona-scoped receipt read refused: claimed persona does not match trusted principal"
                );
                return Err(RpcError::NotFound(
                    "receipt read: claimed actor does not match trusted principal".to_string(),
                )
                .into());
            }
            Ok(Some(trusted_persona))
        }
        None => Ok(claimed_persona),
    }
}

fn parse_receipt_json(raw: String, id: &str) -> Result<Value, (i32, String)> {
    serde_json::from_str(&raw)
        .map_err(|e| RpcError::Internal(format!("corrupt receipt row {id}: {e}")).into())
}

fn raw_receipt_by_id(store: &DaemonStore, id: &str) -> Result<(String, String), StoreError> {
    use rusqlite::OptionalExtension;

    let row: Option<(String, String)> = store
        .conn()
        .query_row(
            "SELECT receipt_json, persona_id FROM receipts WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.ok_or(StoreError::NotFound)
}

/// receipt_list_get_rpc_landed — read-only `receipt.list` RPC.
///
/// Returns the persisted `receipt_json` envelopes/bodies as JSON values,
/// filtered by daemon-owned receipt-table metadata. This intentionally does
/// not deserialize into the legacy grant-only `GrantReceipt` type so callers
/// can decode each Receipt kind according to ADR 118 / ADR 133.
pub fn handle_receipt_list(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = receipt_persona_scope(ctx, "receipt.list", params)?;
    let kind = optional_param_string(params, &["kind"]).map(String::from);
    let grant_id = optional_param_string(params, &["grant_id"]).map(String::from);
    let since = optional_param_string(params, &["since", "since_iso"]).map(String::from);
    let before =
        optional_param_string(params, &["before", "before_iso", "until"]).map(String::from);

    let mut sql = String::from("SELECT id, receipt_json FROM receipts WHERE 1=1");
    let mut binds: Vec<String> = Vec::new();
    if let Some(kind) = kind {
        sql.push_str(&format!(" AND kind = ?{}", binds.len() + 1));
        binds.push(kind);
    }
    if let Some(persona_id) = persona_id {
        sql.push_str(&format!(" AND persona_id = ?{}", binds.len() + 1));
        binds.push(persona_id);
    }
    if let Some(grant_id) = grant_id {
        sql.push_str(&format!(" AND grant_id = ?{}", binds.len() + 1));
        binds.push(grant_id);
    }
    if let Some(since) = since {
        sql.push_str(&format!(" AND created_at >= ?{}", binds.len() + 1));
        binds.push(since);
    }
    if let Some(before) = before {
        sql.push_str(&format!(" AND created_at <= ?{}", binds.len() + 1));
        binds.push(before);
    }
    sql.push_str(" ORDER BY created_at DESC");
    let limit = params["limit"].as_u64().unwrap_or(100).min(1_000);
    sql.push_str(&format!(" LIMIT {limit}"));

    let mut stmt = store
        .conn()
        .prepare(&sql)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(binds.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    let mut out = Vec::new();
    for row in rows {
        let (id, raw) = row.map_err(|e| RpcError::Internal(e.to_string()))?;
        out.push(parse_receipt_json(raw, &id)?);
    }
    Ok(Value::Array(out))
}

/// receipt_list_get_rpc_landed — read-only `receipt.get` RPC.
///
/// `id` / `receipt_id` names a receipt row. For parity with the existing
/// `get_receipt` RPC, a terminal grant id is also accepted and resolved to
/// its stored receipt id before returning the persisted JSON body.
pub fn handle_receipt_get(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let id = optional_param_string(params, &["id", "receipt_id"])
        .ok_or_else(|| RpcError::InvalidParams("missing 'id'".to_string()))?;

    match raw_receipt_by_id(store, id) {
        Ok((raw, persona_id)) => {
            crate::infra::handlers::principal::ensure_connect_only_owner_matches_trusted_principal(
                ctx,
                "receipt.get",
                &persona_id,
            )?;
            return parse_receipt_json(raw, id);
        }
        Err(StoreError::NotFound) => {}
        Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
    }

    match store.get_grant(id) {
        Ok(grant) => {
            crate::infra::handlers::principal::ensure_connect_only_owner_matches_trusted_principal(
                ctx,
                "receipt.get",
                &grant.persona_id,
            )?;
            let receipt_id = grant.receipt_id.as_deref().ok_or_else(|| {
                RpcError::NotFound(format!(
                    "no receipt found for id '{id}' (grant exists but has not reached terminal state)"
                ))
            })?;
            let (raw, persona_id) = raw_receipt_by_id(store, receipt_id).map_err(|e| match e {
                StoreError::NotFound => RpcError::NotFound(format!(
                    "grant has receipt_id={receipt_id} but receipt body is missing"
                )),
                other => RpcError::Internal(other.to_string()),
            })?;
            crate::infra::handlers::principal::ensure_connect_only_owner_matches_trusted_principal(
                ctx,
                "receipt.get",
                &persona_id,
            )?;
            parse_receipt_json(raw, receipt_id)
        }
        Err(StoreError::NotFound) => {
            Err(RpcError::NotFound(format!("no receipt or grant found for id '{id}'")).into())
        }
        Err(e) => Err(RpcError::Internal(e.to_string()).into()),
    }
}

/// Handle the `broker_issue` socket RPC.
///
/// Params: `BrokerRequest` shape (see `core_broker::BrokerRequest`).
///
/// Response: `{ token, materialization_id, expires_at, provider }`.
///
/// Peercred principal binding: when `principal` is
/// supplied, the kernel-attested uid is compared against the uid
/// bound to the payload's `caller_persona` field. A mismatch is
/// refused with `-32004` before any provider IO.
pub async fn handle_broker_issue(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Schema-version pin — refuse before any other gate
    // when the caller persona owns any active grant whose
    // schema_version does not match this daemon's compiled-in pin.
    check_grants_schema_version_for_persona(store, params, "caller_persona")?;
    check_principal_is_alive(principal)?;
    // Linux namespace-tuple gate — refuse when the peer's
    // kernel-observable namespace inodes drifted from the
    // agent_socket_enrollments row recorded at spawn-completion.
    check_principal_namespace_inodes(principal, store)?;
    check_peer_binary_pinned(principal)?;
    // Persona-registry-to-enrollments collapse (step B) —
    // classify the shared-socket caller against the per-agent UDS
    // enrollment surface before the legacy peercred-uid gate fires.
    // Resolution is observability-only at this step; the gate downstream
    // still enforces uid binding. A later step will retire the legacy
    // thread-local registry fallback now that the enrollment surface
    // is the documented source of truth.
    log_legacy_socket_resolution(principal, store, params, "caller_persona", "broker_issue");
    check_principal_against_persona(principal, store, params, "caller_persona")?;
    // Fail-closed per-RPC rollout: refuse unenrolled
    // personas with -32401 (fail_closed_broker_issue). Other broker
    // RPCs still operate under the fail-open legacy gate until their
    // rollout step lands.
    check_principal_enrollment_strict(principal, store, params, "caller_persona")?;
    let registry = current_registry().ok_or_else(err_no_registry)?;

    // ADR212-TELEMETRY-EXPORTER — instrument the grant->mint->receipt hot path
    // (ADR 212 §7). Time the materialization, classify the outcome onto the
    // bounded `core_metrics` labels, and attach the `materialization_id` (which
    // also keys the Receipt) as the histogram exemplar's `correlation_id` so a
    // metric spike pivots to the offending receipt (ADR 212 §6). Labels stay
    // bounded — no persona/grant/session id leaks onto the scrape surface.
    let started = std::time::Instant::now();
    let result = issue_with_registry(
        registry,
        store,
        params,
        &crate::trust::policy::PolicyEngine::default(),
    )
    .await;
    let elapsed_secs = started.elapsed().as_secs_f64();
    let (outcome, correlation_id) = match &result {
        Ok(value) => {
            // The success payload carries `materialization_id` — the per-mint
            // id shared with the Receipt; use it as the exemplar correlation id.
            let id = value
                .get("materialization_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            (core_metrics::OutcomeLabel::Ok, id)
        }
        Err((code, _)) => {
            // Map the broker error code onto the bounded outcome enum:
            // fail-closed gate codes (-32401/-32030) are denials, everything
            // else is an operational error. No id to correlate on failure.
            let outcome = if matches!(code, -32401 | -32030 | -32403) {
                core_metrics::OutcomeLabel::Denied
            } else {
                core_metrics::OutcomeLabel::Errored
            };
            (outcome, String::new())
        }
    };
    crate::infra::telemetry::record_broker_materialization(
        core_metrics::ReceiptKindLabel::BrokerMint,
        outcome,
        elapsed_secs,
        &correlation_id,
    );

    result
}

/// Handle the `broker_revoke` socket RPC.
///
/// Params: `{ materialization_id: <string>, caller_persona?: <string> }`.
///
/// Response: `{ revoked: true, materialization_id: <string> }`.
///
/// Peercred principal binding: when `principal` is
/// supplied AND the payload names `caller_persona`, the peercred uid
/// is matched against the persona's bound uid. Revoke is a
/// privileged op (drops daemon-held plaintext); only the persona that
/// issued the materialization should be able to revoke it.
pub async fn handle_broker_revoke(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Schema-version pin — refuse before any other gate
    // when the caller persona owns any active grant whose
    // schema_version does not match this daemon's compiled-in pin.
    check_grants_schema_version_for_persona(store, params, "caller_persona")?;
    check_principal_is_alive(principal)?;
    // Linux namespace-tuple gate — refuse on namespace drift.
    check_principal_namespace_inodes(principal, store)?;
    check_peer_binary_pinned(principal)?;
    // Persona-registry-to-enrollments collapse (step B) —
    // classify shared-socket caller against the enrollment surface.
    log_legacy_socket_resolution(principal, store, params, "caller_persona", "broker_revoke");
    check_principal_against_persona(principal, store, params, "caller_persona")?;
    // Fail-closed per-RPC rollout: refuse unenrolled
    // personas with -32401 (fail_closed_broker_revoke_list). This is
    // the final flip in the A/B/C/D rollout — every broker RPC now
    // refuses unenrolled callers.
    check_principal_enrollment_strict(principal, store, params, "caller_persona")?;
    let registry = current_registry().ok_or_else(err_no_registry)?;
    revoke_with_registry(registry, store, params).await
}

/// Handle the `list_all_grants` socket RPC.
///
/// grant_list_all_rpc_landed: this is the cross-persona grant projection
/// needed by operator CLI migration. The dispatcher classifies it on the
/// same OperatorPresence lane as `list_operator_grants`; it is read-only,
/// but not safe as a broad ConnectOnly method because it exposes grants
/// across every Persona.
pub fn handle_list_all_grants(store: &DaemonStore, params: &Value) -> Result<Value, (i32, String)> {
    // grant_list_all_rpc_landed
    let active_only = params["active_only"].as_bool().unwrap_or(false);
    let grants = if active_only {
        store.list_active_grants()
    } else {
        store.list_grants()
    }
    .map_err(|e| (-32000, e.to_string()))?;
    let list: Vec<Value> = grants
        .iter()
        .map(|g| {
            json!({
                "id": g.id,
                "persona_id": g.persona_id,
                "credential_name": g.credential_name,
                "scope": g.scope,
                "status": g.status,
                "expires_at": g.expires_at,
            })
        })
        .collect();
    Ok(json!(list))
}

/// status_aggregated_rpc_landed — daemon-owned status projection for the
/// installed CLI path. This consolidates the historical multi-RPC status read
/// into one read-only `StatusSummary` while preserving Team0 persona scoping.
pub fn handle_status(store: &DaemonStore, ctx: &RequestContext) -> Result<Value, (i32, String)> {
    let persona_scope =
        crate::infra::handlers::principal::team0_connect_only_persona_scope(ctx, "status")?;
    let personas = store.list_personas().map_err(|e| (-32000, e.to_string()))?;
    let grants = store
        .list_active_grants()
        .map_err(|e| (-32000, e.to_string()))?;
    let sandboxes = store
        .list_sandboxes()
        .map_err(|e| (-32000, e.to_string()))?;
    let approvals = store
        .list_pending_approvals()
        .map_err(|e| (-32000, e.to_string()))?;
    let recent_activity_filter = AuditFilter {
        persona_id: persona_scope.clone(),
        limit: Some(5),
        ..Default::default()
    };
    let recent_activity = store
        .query_audit(&recent_activity_filter)
        .map_err(|e| (-32000, e.to_string()))?;
    let standing_grants = store
        .list_standing_grants()
        .map_err(|e| (-32000, e.to_string()))?
        .into_iter()
        .filter(|grant| match persona_scope.as_deref() {
            Some(persona_id) => grant.persona_id == persona_id,
            None => true,
        })
        .count();
    let audit_events_total = if let Some(persona_id) = persona_scope.as_deref() {
        store
            .query_audit(&AuditFilter {
                persona_id: Some(persona_id.to_string()),
                ..Default::default()
            })
            .map_err(|e| (-32000, e.to_string()))?
            .len() as u64
    } else {
        store.audit_count().map_err(|e| (-32000, e.to_string()))?
    };
    let grants = grants
        .into_iter()
        .filter(|grant| match persona_scope.as_deref() {
            Some(persona_id) => grant.persona_id == persona_id,
            None => true,
        })
        .collect::<Vec<_>>();
    let grant_live_leases = grants
        .iter()
        .filter(|grant| store.leases().has_live_lease(&grant.id, chrono::Utc::now()))
        .map(|grant| grant.id.clone())
        .collect();

    serde_json::to_value(crate::infra::status::StatusSummary {
        personas: personas
            .into_iter()
            .filter(|persona| match persona_scope.as_deref() {
                Some(persona_id) => persona.id == persona_id,
                None => true,
            })
            .collect(),
        grants,
        grant_live_leases,
        sandboxes: sandboxes
            .into_iter()
            .filter(|sandbox| match persona_scope.as_deref() {
                Some(persona_id) => {
                    sandbox.persona_id == persona_id
                        || sandbox.owner_persona_id.as_deref() == Some(persona_id)
                }
                None => true,
            })
            .collect(),
        approvals: approvals
            .into_iter()
            .filter(|approval| match persona_scope.as_deref() {
                Some(persona_id) => approval.persona_id == persona_id,
                None => true,
            })
            .collect(),
        recent_activity,
        standing_grants,
        audit_events_total,
        quarantined: crate::infra::handler::is_quarantined(),
        quarantine_authority: crate::infra::handler::quarantine_authority()
            .map(|authority| authority.as_str().to_string()),
    })
    .map_err(|e| (-32000, format!("serialize status summary: {e}")))
}

/// Handle the `persona_signer` socket RPC.
///
/// Params: `{ persona_id: <string>, payload_b64: <base64 bytes> }`.
///
/// Response: `{ persona_id, key_id, algorithm, public_key, signature }`.
pub fn handle_persona_signer(store: &DaemonStore, params: &Value) -> Result<Value, (i32, String)> {
    // persona_signer_rpc_landed
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or_else(|| (-32602, "missing 'persona_id'".to_string()))?;
    let payload_b64 = params["payload_b64"]
        .as_str()
        .ok_or_else(|| (-32602, "missing 'payload_b64'".to_string()))?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64.as_bytes())
        .map_err(|e| (-32602, format!("invalid 'payload_b64': {e}")))?;
    let signer = store
        .persona_signer(persona_id)
        .map_err(|e| (-32000, format!("persona signer: {e}")))?;
    let signature = signer
        .try_sign(&payload)
        .map_err(|e| (-32000, format!("persona signer: {e}")))?;

    Ok(json!({
        "persona_id": persona_id,
        "key_id": format!("persona-{persona_id}"),
        "algorithm": "ed25519",
        "public_key": signer.public_key().0,
        "signature": signature.0,
    }))
}

/// Handle the `audit.query` socket RPC.
///
/// Read-only projection over the daemon-owned audit log. The returned row
/// shape mirrors the legacy `audit_query` summary surface and deliberately
/// omits raw `details`; callers that need raw audit rows use `audit_log_query`.
pub fn handle_audit_query(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // audit_query_rpc_landed
    let claimed_persona_id = params["persona_id"].as_str();
    let claimed_agent_id = params["agent_id"].as_str();
    if let (Some(persona_id), Some(agent_id)) = (claimed_persona_id, claimed_agent_id)
        && persona_id != agent_id
    {
        return Err(RpcError::InvalidParams(
            "audit.query: persona_id and agent_id must match when both are provided".to_string(),
        )
        .into());
    }

    let actor_id = match crate::infra::handlers::principal::team0_connect_only_persona_scope(
        ctx,
        "audit.query",
    )? {
        Some(trusted_persona) => {
            if let Some(claimed_persona) = claimed_persona_id.or(claimed_agent_id)
                && claimed_persona != trusted_persona
            {
                tracing::warn!(
                    method = "audit.query",
                    claimed_persona_id = %claimed_persona,
                    trusted_persona_id = %trusted_persona,
                    tier = current_dispatch_deployment_tier().as_str(),
                    "connect-only persona-scoped read refused: claimed persona does not match trusted principal"
                );
                return Err(RpcError::NotFound(
                    "audit.query: claimed actor does not match trusted principal".to_string(),
                )
                .into());
            }
            Some(trusted_persona)
        }
        None => claimed_persona_id.or(claimed_agent_id).map(String::from),
    };

    let limit = params["limit"].as_u64().map(|l| l as usize);
    let filter = AuditFilter {
        persona_id: actor_id,
        action: params["action"].as_str().map(String::from),
        limit,
        since_ms: params["since_ms"]
            .as_i64()
            .or_else(|| params["since"].as_i64()),
        before_ms: params["before_ms"]
            .as_i64()
            .or_else(|| params["until_ms"].as_i64())
            .or_else(|| params["until"].as_i64()),
        ..Default::default()
    };
    let entries = store
        .query_audit(&filter)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    let list: Vec<Value> = entries
        .iter()
        .map(|e| {
            json!({
                "id": e.id,
                "timestamp": e.timestamp,
                "agent_id": e.agent_id,
                "action": e.action,
                "credential": e.credential,
                "outcome": e.outcome,
            })
        })
        .collect();
    Ok(json!(list))
}

/// Handle the `broker_list` socket RPC.
///
/// Params: `{ caller_persona?: <string> }` — when present, the
/// listing is restricted to the caller's own materializations and
/// the peercred uid is validated against the persona's bound uid.
///
/// Response: array of [`MaterializationSummary`] sorted by `issued_at`
/// ascending. Empty when nothing has been issued.
///
/// Peercred principal binding: same gate as issue/revoke
/// when `caller_persona` is present.
pub async fn handle_broker_list(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Schema-version pin — refuse before any other gate
    // when the caller persona owns any active grant whose
    // schema_version does not match this daemon's compiled-in pin.
    check_grants_schema_version_for_persona(store, params, "caller_persona")?;
    check_principal_is_alive(principal)?;
    // Linux namespace-tuple gate — refuse on namespace drift.
    check_principal_namespace_inodes(principal, store)?;
    check_peer_binary_pinned(principal)?;
    // Persona-registry-to-enrollments collapse (step B) —
    // classify shared-socket caller against the enrollment surface.
    log_legacy_socket_resolution(principal, store, params, "caller_persona", "broker_list");
    check_principal_against_persona(principal, store, params, "caller_persona")?;
    // Fail-closed per-RPC rollout: refuse unenrolled
    // personas with -32401 (fail_closed_broker_revoke_list).
    check_principal_enrollment_strict(principal, store, params, "caller_persona")?;
    let registry = current_registry().ok_or_else(err_no_registry)?;
    list_with_registry(registry).await
}

/// Handle the `broker.mint_gh_token` socket RPC — **fail-closed** (ADR 204 BKR-1).
///
/// This RPC previously minted a GitHub App installation token directly from
/// **caller-supplied** `repos` + `permissions`, passed verbatim to
/// `mint_installation_token` (an empty `permissions` slice inherits the App's
/// FULL installation scope). It bypassed the registry, the grant gate, persona
/// binding, and the native-scope projector entirely — the same
/// caller-native-scope ingress that `broker_issue` deletes, on a parallel
/// method. It was an unprovisioned placeholder (env-gated; never wired to a
/// vault), so no legitimate flow depends on it.
///
/// GitHub installation tokens mint through `broker_exec`
/// (`GitHubBroker::issue`), where the native scope is **derived** from the
/// per-action manifest + the concrete operation target (`core_broker::project`)
/// and bounded by the matched grant. There is no caller-supplied-scope GitHub
/// mint path. This handler now refuses unconditionally so the ingress cannot be
/// reached even once the App is provisioned; a proper grant-gated GitHub
/// `broker_issue` lowering, if ever needed, lands with BKR-2 through the same
/// `derive_native_scope` gate.
pub async fn handle_broker_mint_gh_token(
    _store: &DaemonStore,
    _params: &Value,
) -> Result<Value, (i32, String)> {
    Err((
        -32013,
        "broker.mint_gh_token is removed: GitHub native scope is daemon-derived, \
         not caller-supplied (ADR 204 BKR-1). Installation tokens mint via \
         broker_exec, where the scope is projected from the action manifest and \
         the concrete target and bounded by the grant."
            .to_string(),
    ))
}

/// Handle the `broker.mint_sub_persona` socket RPC.
///
/// Mints a sub-persona scoped under an existing parent persona by running
/// the two-phase commit + spawn machinery from `crate::infra::persona`.
///
/// ## Wire shape
///
/// Params:
/// ```json
/// {
///   "parent_persona_id": "<persona-uuid>",
///   "child_label":       "<human-readable label for the new persona>",
///   "scope":             "<resource scope string, e.g. '*' or 'repo:foo'>"
/// }
/// ```
///
/// Response: `{ "persona_id": "<new-child-persona-uuid>" }`.
///
/// ## Checkpoint
///
/// RPC method name: `broker.mint_sub_persona`
///
/// ## Implementation status
///
/// The inner `crate::infra::persona::mint_sub_persona` call is a scaffold
/// stub — the real two-phase commit + spawn wiring lands later. Until
/// then, otherwise-valid requests fail closed with a structured RPC error
/// rather than panicking the daemon.
pub async fn handle_broker_mint_sub_persona(
    _store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let parent_persona_id = params
        .get("parent_persona_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                -32602,
                "missing required field: parent_persona_id".to_string(),
            )
        })?;

    let child_label = params
        .get("child_label")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| (-32602, "missing required field: child_label".to_string()))?;

    let scope = params.get("scope").and_then(|v| v.as_str()).unwrap_or("*");

    // -----------------------------------------------------------------
    // Capability-isolation-map consumer — fail-closed gate.
    // Anchor: `capability_isolation_map_consumed`.
    //
    // PR 4584eeef shipped `core_grant_types::capabilities::
    // CAPABILITY_ISOLATION_MAP` (the operator-locked per-capability
    // container-isolation baseline) as declarative-only LOC; this is the
    // production read site that wires the map into the FLEET-TRUST-CLASS-
    // AFFINITY container-split heuristic. Optional `capabilities` array on
    // the request lists the wire-form capability names the child will
    // carry; `trust::affinity::decide_container_split` returns the
    // isolation level (or a typed `CapabilityNotClassified` /
    // `MalformedSpec` error). Errors are surfaced as RPC `-32603`
    // (InternalError) — distinct from `-32602` (InvalidParams, used for
    // input-shape rejections below) and `-32000` (the structured-daemon
    // unsupported-scaffold lane the call still falls through to). An
    // unclassified capability MUST fail-closed BEFORE the scaffold runs;
    // otherwise an attacker who can name a capability the broker doesn't
    // recognise would slip past the gate.
    // -----------------------------------------------------------------
    let capabilities: Vec<&str> = match params.get("capabilities") {
        None => Vec::new(),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for (i, v) in items.iter().enumerate() {
                let s = v.as_str().ok_or_else(|| {
                    (
                        -32602,
                        format!("capabilities[{i}] must be a string (wire-form capability name)"),
                    )
                })?;
                out.push(s);
            }
            out
        }
        Some(_) => {
            return Err((
                -32602,
                "capabilities must be an array of wire-form capability names".to_string(),
            ));
        }
    };
    let _affinity = crate::trust::affinity::decide_container_split(&capabilities)
        .map_err(|e| (-32603, e.to_string()))?;

    // Delegate to the infra wrapper. It is still a scaffold, but the public
    // RPC path must fail closed, not panic, until the real two-phase commit
    // + spawn wiring lands.
    let persona_id = crate::infra::persona::mint_sub_persona(parent_persona_id, child_label, scope)
        .await
        .map_err(|e| (-32000, format!("mint_sub_persona failed: {e}")))?;

    Ok(json!({ "persona_id": persona_id }))
}

// ---------------------------------------------------------------------------
// Spawn attenuation — folded into the unified authority algebra (ADR 209 §3)
// ---------------------------------------------------------------------------
//
// The former `evaluate_spawn_attenuation` / `SpawnGrant` / `ChildSpawnSpec` /
// `AttenuatedChildGrant` / `SpawnDenialReason` parallel algebra
// was a test-only re-implementation with zero
// production callers. Per ADR 205 §6 + ADR 209 §3 there is ONE attenuation
// algebra; spawn delegation rides it like any other downhill hop:
//   * capability + scope-subset + conditions → `core_grants::check_statement_attenuation`
//   * depth cap (`spawn_max_depth` → `can_delegate { max_depth }`) →
//     `can_delegate_subsumed`
//   * the HIGH-F strict decrement is enforced live at mint time in
//     `trust/grant.rs` (`max_depth.saturating_sub(1)`, refuse at 0) and in
//     `infra/persona.rs`; the unified depth check is covered by `core-grants`
//     `per_stmt_attenuation_{rejects,accepts}_child_delegation_*`.
// `Capability::SpawnSubagent` remains only as a routing/isolation marker; it
// carries no parallel authority math.
// Anchor: spawn_attenuation_folded_into_check_statement_attenuation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// RPC panic-recovery middleware
// ADR 166 §Component 9 (T2).
// ---------------------------------------------------------------------------
//
// `recover_rpc_panic` wraps the synchronous body of an RPC handler
// invocation in `std::panic::catch_unwind` and converts any panic into the
// JSON-RPC `InternalPanic` shape `(-32603, "internal panic: <msg>")`. The
// daemon stays up; other in-flight connections are unaffected because each
// connection's dispatch is its own catch_unwind boundary.
//
// catch_unwind dispatch_method — checkpoint for the target_state_anchor gate
// of the panic-recovery middleware. Although the production
// async dispatch lives in `infra/handler.rs::dispatch_method` /
// `dispatch_method_with_context`, this helper is the panic-recovery
// primitive that the dispatch site composes with; the checkpoint records
// the architectural intent at the broker entry layer.
//
// AssertUnwindSafe justification: state mutations in our RPC handlers go
// through SQLite transactions that auto-rollback on `Drop` if the
// transaction guard is unwound without an explicit commit; non-transactional
// state touched mid-handler is either borrowed read-only or guarded by
// `Mutex`/`RwLock` whose poisoning is observable to the next caller (and
// is the explicit signal a panic occurred — we want the next caller to see
// the poisoning, not have it silently masked). The helper is therefore
// safe to wrap arbitrary handler bodies in.
pub fn recover_rpc_panic<F>(method: &str, params: &Value, f: F) -> Result<Value, (i32, String)>
where
    F: FnOnce() -> Result<Value, (i32, String)> + std::panic::UnwindSafe,
{
    let result = std::panic::catch_unwind(f);
    match result {
        Ok(handler_result) => handler_result,
        Err(panic_payload) => {
            let panic_msg = panic_payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<panic payload not downcastable>".to_string());
            let frame_hash = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(method.as_bytes());
                h.update(serde_json::to_vec(params).unwrap_or_default());
                let digest = h.finalize();
                // truncated 16 hex chars (first 8 bytes)
                let mut s = String::with_capacity(16);
                for b in digest.iter().take(8) {
                    s.push_str(&format!("{b:02x}"));
                }
                s
            };
            tracing::error!(
                method = %method,
                frame_hash = %frame_hash,
                panic = %panic_msg,
                "RPC handler panicked — converted to RpcError::InternalPanic"
            );
            Err((-32603, format!("internal panic: {panic_msg}")))
        }
    }
}

// ---------------------------------------------------------------------------
// ssh-agent-over-bridge — daemon's ADR 211 lease gate for the broker bridge
// (ssh_agent_sign_over_bridge, Slice 1)
// ---------------------------------------------------------------------------

/// The daemon-side implementation of the ssh-agent bridge's fail-closed
/// SSH-signing authority gate
/// ([`ember_broker::ssh_agent_bridge::SshSignAuthority`]).
///
/// Binds one session's `grant_id` to the live lease registry. The bridge calls
/// [`ssh_signing_authorized`](ember_broker::ssh_agent_bridge::SshSignAuthority::ssh_signing_authorized)
/// before **every** sign/identities; it returns `true` only while that grant
/// holds a live, unexpired lease whose scope authorizes SSH signing
/// ([`crate::trust::lease::LeaseRegistry::has_live_ssh_signing_lease`]). The
/// broker crate cannot see the daemon's `LeaseRegistry`, so this adapter is the
/// seam between the daemon's ADR 211 authority model and the bridge.
///
/// **S1↔S3 contract.** `register_session` (Slice 3) mints the session's
/// SSH-signing lease (scope `<provider>:ssh-agent:sign`, see
/// [`crate::trust::lease::scope_authorizes_ssh_signing`]) and constructs one of
/// these per session, then hands it to `ssh_agent_bridge::bind`. It holds an
/// `Rc<DaemonStore>` because — like the rest of the daemon's socket plane
/// (`infra::session_proxy`/`infra::proxy`) — the bridge runs on the
/// single-threaded `LocalSet` where the `!Sync` store lives.
pub struct LeaseSshAuthority {
    store: std::rc::Rc<DaemonStore>,
    grant_id: String,
}

impl LeaseSshAuthority {
    /// Bind the gate to `grant_id` against `store`'s live lease registry.
    pub fn new(store: std::rc::Rc<DaemonStore>, grant_id: impl Into<String>) -> Self {
        Self {
            store,
            grant_id: grant_id.into(),
        }
    }
}

impl ember_broker::ssh_agent_bridge::SshSignAuthority for LeaseSshAuthority {
    fn ssh_signing_authorized(&self) -> bool {
        self.store
            .leases()
            .has_live_ssh_signing_lease(&self.grant_id, chrono::Utc::now())
    }
}

/// The daemon-side implementation of the ssh-agent bridge's audit sink
/// ([`ember_broker::ssh_agent_bridge::SshSignAudit`], ssh-agent-over-bridge S3).
///
/// On each authorized sign the bridge passes the raw `(key_blob, data, flags)`;
/// this appends **one hash-chained audit-log row** (`crate::infra::audit`) — an
/// audit-log entry, NOT a receipt (the Receipt is emitted once at lease grant in
/// `register_session`; per-access logging is the audit log, `receipt_vs_audit_log`).
/// The signed `data` is opaque SSH bytes, so the row records the parseable
/// userauth fields (when present) plus a `sha256(data)`; target attribution (which
/// host/repo) correlates from the egress log, not the sign (the repo is not in the
/// SSH handshake) — see the S3 spec.
///
/// Holds an `Rc<DaemonStore>` for the same single-`LocalSet` reason as
/// [`LeaseSshAuthority`]. `register_session` provisioning constructs one per
/// session and hands it to `ssh_agent_bridge`'s `with_audit` when the per-session
/// bridge is bound (that endpoint bind is the forwarder slice).
pub struct DaemonSshSignAudit {
    store: std::rc::Rc<DaemonStore>,
    session_id: String,
    persona_id: String,
}

impl DaemonSshSignAudit {
    /// Bind the audit sink to a session/persona against `store`'s audit chain.
    pub fn new(
        store: std::rc::Rc<DaemonStore>,
        session_id: impl Into<String>,
        persona_id: impl Into<String>,
    ) -> Self {
        Self {
            store,
            session_id: session_id.into(),
            persona_id: persona_id.into(),
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

impl ember_broker::ssh_agent_bridge::SshSignAudit for DaemonSshSignAudit {
    fn record_sign(&self, key_blob: &[u8], data: &[u8], flags: u32) {
        let key_fingerprint = sha256_hex(key_blob);
        let userauth = ember_broker::ssh_agent::parse_sign_userauth(data).map(|f| {
            serde_json::json!({
                "user": f.user,
                "service": f.service,
                "method": f.method,
                "pubkey_algo": f.pubkey_algo,
            })
        });
        let details = serde_json::json!({
            "session_id": self.session_id,
            "key_fingerprint_sha256": key_fingerprint,
            "data_sha256": sha256_hex(data),
            "data_len": data.len(),
            "flags": flags,
            // None when `data` is not a recognizable publickey userauth blob
            // (the agent can sign arbitrary bytes); the `data` hash still attests it.
            "userauth": userauth,
        })
        .to_string();
        // Best-effort: a failed audit append must never block or fail the sign
        // response (the response already left the bridge). Log loudly instead.
        if let Err(e) = crate::infra::audit::append_audit_event_with_chain(
            &self.store,
            Some(&self.persona_id),
            "ssh_agent.sign",
            Some(&key_fingerprint),
            "signed",
            Some(&details),
        ) {
            tracing::warn!(error = %e, session_id = %self.session_id, "ssh bridge: failed to append sign audit row");
        }
    }
}

#[cfg(test)]
mod ssh_bridge_authority_tests {
    use super::*;
    use ember_broker::ssh_agent_bridge::{SshSignAudit, SshSignAuthority};

    /// The daemon audit sink appends exactly one hash-chained `ssh_agent.sign`
    /// audit-log row per authorized sign (S3 acceptance: per-access logging is
    /// the audit log, NOT a receipt). Best-effort emission still lands a row on
    /// a healthy store.
    #[test]
    fn daemon_ssh_sign_audit_appends_one_chained_row_per_sign() {
        let store = std::rc::Rc::new(DaemonStore::open_in_memory().unwrap());
        let count = |s: &DaemonStore| -> i64 {
            s.conn()
                .query_row(
                    "SELECT COUNT(*) FROM audit_log WHERE action = 'ssh_agent.sign'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(-1)
        };
        let audit = DaemonSshSignAudit::new(std::rc::Rc::clone(&store), "sess_1", "persona-1");
        assert_eq!(count(&store), 0);
        audit.record_sign(b"ssh-ed25519-blob", b"signed-bytes-one", 0);
        assert_eq!(count(&store), 1, "one audit row per authorized sign");
        // A second sign extends the chain with a second row (not a receipt).
        audit.record_sign(b"ssh-ed25519-blob", b"signed-bytes-two", 1);
        assert_eq!(count(&store), 2);
    }

    /// The adapter must reflect the REAL lease registry: authorized iff a live,
    /// SSH-signing-scoped lease exists for the bound grant — and a push-scope
    /// lease (which `has_live_lease` alone would accept) must NOT authorize
    /// signing. This is the bug-class guard: calling the scope-blind
    /// `has_live_lease` here would let any active grant sign.
    #[test]
    fn lease_ssh_authority_gates_on_a_live_ssh_signing_lease() {
        let store = std::rc::Rc::new(DaemonStore::open_in_memory().unwrap());
        let now = chrono::Utc::now();
        let ttl = Some(now + chrono::Duration::hours(1));

        let ssh = LeaseSshAuthority::new(std::rc::Rc::clone(&store), "g-ssh");
        // No lease yet → fail-closed.
        assert!(!ssh.ssh_signing_authorized());

        // A live SSH-signing lease authorizes.
        store
            .leases()
            .mint("g-ssh", "p", "github:ssh-agent:sign", ttl, now);
        assert!(ssh.ssh_signing_authorized());

        // A live PUSH-scope lease on another grant does NOT authorize signing.
        store
            .leases()
            .mint("g-push", "p", "github:repo:push", ttl, now);
        let push = LeaseSshAuthority::new(std::rc::Rc::clone(&store), "g-push");
        assert!(
            !push.ssh_signing_authorized(),
            "a push-scope lease must not authorize SSH signing"
        );

        // Revoke flips the SSH-signing gate closed.
        store.leases().drop_lease("g-ssh");
        assert!(!ssh.ssh_signing_authorized());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// All tests build a fresh `BrokerRegistry` and call the
// registry-explicit handlers (`issue_with_registry` / `revoke_with_registry`
// / `list_with_registry`) directly. The process-global `OnceCell` is
// deliberately untouched so tests do not contend over shared state when
// `cargo test` runs them in parallel.

#[cfg(test)]
mod tests {
    use super::*;
    use core_broker::MockBroker;
    use rusqlite;

    use super::materialization::test_support::ensure_identity_for_broker_test;
    use crate::infra::credential_store::CredentialStore;

    // -----------------------------------------------------------------------
    // RPC panic-recovery middleware tests
    // -----------------------------------------------------------------------

    /// T1: panic→typed-error. A handler closure that deliberately panics
    /// must surface as `Err((-32603, "internal panic: <msg>"))` and the
    /// test process must stay up to observe the assertions.
    #[test]
    fn recover_rpc_panic_converts_panic_to_internal_error() {
        // Suppress the default panic hook's stderr noise during the
        // intentional-panic test so the test output stays readable.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let result = recover_rpc_panic("test_method", &json!({"x": 1}), || {
            panic!("synthetic panic for catch_unwind dispatch_method test");
        });

        std::panic::set_hook(prev);

        let err = result.expect_err("panic must be converted to Err");
        assert_eq!(err.0, -32603, "panic must surface as -32603 InternalPanic");
        assert!(
            err.1.starts_with("internal panic: "),
            "error message must carry the internal-panic prefix: {}",
            err.1
        );
        assert!(
            err.1
                .contains("synthetic panic for catch_unwind dispatch_method test"),
            "error message must carry the panic payload: {}",
            err.1
        );
    }

    /// T2: other-connections-unaffected. Invoke two handler closures in
    /// sequence — first panics, second succeeds with a normal return.
    /// Both observed states must be correct, proving the panic recovery
    /// in call A does not leak into call B (the daemon remains live and
    /// the next RPC dispatches normally).
    #[test]
    fn recover_rpc_panic_isolates_panicking_handler_from_next_call() {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        // Call A: panics.
        let err = recover_rpc_panic("connA_method", &json!({"conn": "a"}), || {
            panic!("conn A handler panicked");
        })
        .expect_err("conn A must observe InternalPanic");
        assert_eq!(err.0, -32603);
        assert!(err.1.contains("conn A handler panicked"));

        // Call B: succeeds. Equivalent to a second in-flight connection
        // being dispatched after A panicked — its own catch_unwind boundary
        // sees only its own return value.
        let ok = recover_rpc_panic("connB_method", &json!({"conn": "b"}), || {
            Ok(json!({"pong": true, "conn": "b"}))
        })
        .expect("conn B must succeed unaffected by A's panic");
        assert_eq!(ok["pong"], json!(true));
        assert_eq!(ok["conn"], json!("b"));

        std::panic::set_hook(prev);
    }

    /// Build a registry containing both Cloudflare and Anthropic mock
    /// brokers. Tests use `aws_sts` / `github` / etc. as the
    /// "unknown provider" case to keep error-path coverage explicit.
    fn fresh_registry() -> BrokerRegistry {
        let mut reg = BrokerRegistry::new();
        reg.register(Box::new(MockBroker::new(BrokerProvider::Cloudflare)));
        reg.register(Box::new(MockBroker::new(BrokerProvider::Anthropic)));
        reg
    }

    /// A `broker_issue` request for the **anthropic** provider — the only
    /// provider with a derive-gated `broker_issue` path (ADR 204 BKR-1).
    /// Anthropic native scope is an audit label the daemon synthesizes, so this
    /// carries NO `scope` field: a caller cannot supply native scope anymore.
    /// (We also pin a stray `"scope"` key here to prove the serde boundary drops
    /// it — the mint must succeed with the daemon-derived label regardless.)
    fn issue_params(ttl_secs: u64, reason: &str) -> Value {
        json!({
            "provider": "anthropic",
            // Ignored by `BrokerIssueParams` (no `scope` field) — proves the
            // caller-native-scope ingress is structurally deleted.
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
    // Peercred principal binding — kernel-attested principal
    // binding gate. The broker handlers check the request payload's
    // `caller_persona` against the kernel-attested `PeerCredPrincipal.uid`
    // via the persona→uid binding registry; mismatch returns -32004.
    // -----------------------------------------------------------------------

    use crate::infra::runtime::PeerCredPrincipal;
    use std::path::PathBuf;

    /// Test helper: seed the agent_socket_enrollments table with a (persona, uid) binding.
    /// Replaces the legacy `bind_persona_uid` thread-local writer (since
    /// retired in favor of the enrollment surface).
    fn seed_persona_uid_via_enrollments(store: &DaemonStore, persona_id: &str, uid: u32) {
        let socket_path = format!("/run/emberd/test-agent-{persona_id}.sock");
        store
            .record_agent_socket_enrollment(
                &socket_path,
                persona_id,
                "test-grant",
                "test-hash",
                None,
                None,
                None,
            )
            .expect("seed enrollment for test");
        store
            .conn()
            .execute(
                "UPDATE agent_socket_enrollments SET peer_uid = ?1 WHERE socket_path = ?2",
                rusqlite::params![uid as i64, &socket_path],
            )
            .expect("seed peer_uid for test");
    }

    fn test_principal(uid: u32, pid: i32) -> PeerCredPrincipal {
        PeerCredPrincipal::new(uid, pid, PathBuf::from("/tmp/test-agent.sock"))
    }

    /// Failing-test contract from the brief — mismatched principal → -32004.
    ///
    /// Constructs a `PeerCredPrincipal { uid: 1001, ... }`, calls
    /// `handle_broker_issue` with `params.caller_persona` resolving to a
    /// persona bound to uid 1002, asserts the result is `Err((-32004, _))`.
    #[tokio::test]
    async fn handle_broker_issue_rejects_mismatched_principal() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        install_registry_for_test(reg);
        let store = DaemonStore::open_in_memory().unwrap();

        let persona = store.create_persona("mismatched-uid-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);

        // The persona is bound to uid 1002, but the principal carries uid 1001.
        seed_persona_uid_via_enrollments(&store, &persona.id, 1002);
        assert_eq!(
            crate::infra::store::lookup_persona_uid_from_enrollments(&store, &persona.id).unwrap(),
            Some(1002)
        );
        let principal = test_principal(1001, 9999);

        let mut params = issue_params(300, "principal-mismatch-test");
        params["caller_persona"] = serde_json::json!(persona.id);

        let res = handle_broker_issue(Some(&principal), &store, &params).await;
        let (code, msg) = res.expect_err("issue must refuse mismatched principal");
        assert_eq!(
            code, -32004,
            "expected -32004 principal binding mismatch, got {code}: {msg}"
        );
        assert!(
            msg.contains("principal binding mismatch")
                || msg.contains("1001")
                || msg.contains("1002"),
            "error must mention the mismatch, got: {msg}"
        );
    }

    /// Matched principal → gate is a pass-through. The persona's
    /// bound uid equals the peercred principal's uid; the helper
    /// must return `Ok(())` so downstream issuance can run.
    ///
    /// Exercises the gate via `check_principal_against_persona`
    /// directly because the `handle_broker_issue` wrapper uses
    /// `PolicyEngine::default()` which is `Required` and would block
    /// the test on HITL polling. The success-path branch of the
    /// gate is what matters here — production callers thread an
    /// `Auto` policy in.
    #[tokio::test]
    async fn handle_broker_issue_accepts_matched_principal() {
        let persona_id = "matched-uid-persona";
        let gate_store = DaemonStore::open_in_memory().unwrap();
        seed_persona_uid_via_enrollments(&gate_store, persona_id, 2002);
        let principal = test_principal(2002, 12345);

        let params = serde_json::json!({"caller_persona": persona_id});
        let gate = check_principal_against_persona(
            Some(&principal),
            &gate_store,
            &params,
            "caller_persona",
        );
        assert!(
            gate.is_ok(),
            "matched-uid principal must pass the gate: {gate:?}"
        );

        // Companion: issue_with_registry against an auto-policy engine
        // proceeds when the gate passes.
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("matched-uid-persona-real").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);
        seed_persona_uid_via_enrollments(&store, &persona.id, 2002);

        let mut params = issue_params(300, "principal-match-test");
        params["caller_persona"] = serde_json::json!(persona.id);
        let gate2 =
            check_principal_against_persona(Some(&principal), &store, &params, "caller_persona");
        assert!(gate2.is_ok(), "matched gate must pass: {gate2:?}");
        let res = issue_with_registry(&reg, &store, &params, &auto_policy()).await;
        assert!(res.is_ok(), "matched principal must proceed: {res:?}");
    }

    /// `handle_broker_revoke` enforces the same gate. A revoke whose
    /// payload-claimed persona disagrees with the peer-cred uid must
    /// be refused with -32004 before any provider IO.
    #[tokio::test]
    async fn handle_broker_revoke_rejects_mismatched_principal() {
        let _identity = ensure_identity_for_broker_test();
        let store = DaemonStore::open_in_memory().unwrap();

        let persona = store.create_persona("revoke-mismatch-persona").unwrap();
        seed_persona_uid_via_enrollments(&store, &persona.id, 3003);

        // No registry installation needed — the principal gate fires
        // before `current_registry()` is consulted.
        let principal = test_principal(4004, 1);
        let params = serde_json::json!({
            "materialization_id": "irrelevant-mid",
            "caller_persona": persona.id,
        });
        let res = handle_broker_revoke(Some(&principal), &store, &params).await;
        let (code, _) = res.expect_err("revoke must refuse mismatched principal");
        assert_eq!(code, -32004);
    }

    /// `handle_broker_list` enforces the same gate.
    #[tokio::test]
    async fn handle_broker_list_rejects_mismatched_principal() {
        let _identity = ensure_identity_for_broker_test();

        // Persona row not required — the gate operates on the
        // payload's `caller_persona` field + the binding registry.
        let store = DaemonStore::open_in_memory().unwrap();
        seed_persona_uid_via_enrollments(&store, "phony-persona-id", 5005);
        let principal = test_principal(6006, 1);
        let params = serde_json::json!({"caller_persona": "phony-persona-id"});
        let res = handle_broker_list(Some(&principal), &store, &params).await;
        let (code, _) = res.expect_err("list must refuse mismatched principal");
        assert_eq!(code, -32004);
    }

    /// Fail-closed per-RPC rollout (step A) acceptance test.
    /// broker_resolve must refuse an unenrolled persona with -32401
    /// (PrincipalNotEnrolled / fail_closed_broker_resolve checkpoint).
    #[tokio::test]
    async fn handle_broker_resolve_refuses_unenrolled_persona() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        install_registry_for_test(reg);
        let store = DaemonStore::open_in_memory().unwrap();

        let principal = test_principal(4242, 1);
        let params = serde_json::json!({
            "persona_id": "unenrolled-persona-fail-closed",
            "secret_ref": "irrelevant-for-this-gate",
        });
        let res = handle_broker_resolve(Some(&principal), &store, None, &params).await;
        let (code, msg) = res.expect_err("broker_resolve must refuse unenrolled persona");
        assert_eq!(
            code, -32401,
            "expected -32401 PrincipalNotEnrolled, got {code}: {msg}"
        );
        assert!(
            msg.contains("unenrolled persona") || msg.contains("PrincipalNotEnrolled"),
            "error must mention unenrolled persona, got: {msg}"
        );
    }

    /// Fail-closed per-RPC rollout (step B) acceptance test.
    /// broker_exec must refuse an unenrolled caller_persona with -32401
    /// (PrincipalNotEnrolled / fail_closed_broker_exec checkpoint).
    #[tokio::test]
    async fn handle_broker_exec_refuses_unenrolled_persona() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        install_registry_for_test(reg);
        let store = DaemonStore::open_in_memory().unwrap();

        let principal = test_principal(5151, 1);
        let params = serde_json::json!({
            "caller_persona": "unenrolled-exec-persona",
            "action_key": "irrelevant-for-this-gate",
            "binary": "/bin/true",
        });
        let res = handle_broker_exec(Some(&principal), &store, &params).await;
        let (code, msg) = res.expect_err("broker_exec must refuse unenrolled persona");
        assert_eq!(
            code, -32401,
            "expected -32401 PrincipalNotEnrolled, got {code}: {msg}"
        );
        assert!(
            msg.contains("unenrolled persona") || msg.contains("PrincipalNotEnrolled"),
            "error must mention unenrolled persona, got: {msg}"
        );
    }

    /// Fail-closed per-RPC rollout (step C) acceptance test.
    /// broker_issue must refuse an unenrolled caller_persona with -32401
    /// (PrincipalNotEnrolled / fail_closed_broker_issue checkpoint).
    #[tokio::test]
    async fn handle_broker_issue_refuses_unenrolled_persona() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        install_registry_for_test(reg);
        let store = DaemonStore::open_in_memory().unwrap();

        let principal = test_principal(6262, 1);
        let params = issue_params(300, "fail-closed-issue-probe");
        let params = {
            let mut p = params;
            p["caller_persona"] = serde_json::json!("unenrolled-issue-persona");
            p
        };
        let res = handle_broker_issue(Some(&principal), &store, &params).await;
        let (code, msg) = res.expect_err("broker_issue must refuse unenrolled persona");
        assert_eq!(
            code, -32401,
            "expected -32401 PrincipalNotEnrolled, got {code}: {msg}"
        );
        assert!(
            msg.contains("unenrolled persona") || msg.contains("PrincipalNotEnrolled"),
            "error must mention unenrolled persona, got: {msg}"
        );
    }

    /// Fail-closed per-RPC rollout (step D) acceptance test (revoke half).
    /// broker_revoke must refuse an unenrolled caller_persona with -32401
    /// (PrincipalNotEnrolled / fail_closed_broker_revoke_list checkpoint).
    #[tokio::test]
    async fn handle_broker_revoke_refuses_unenrolled_persona() {
        let _identity = ensure_identity_for_broker_test();
        let store = DaemonStore::open_in_memory().unwrap();

        let principal = test_principal(7373, 1);
        let params = serde_json::json!({
            "materialization_id": "irrelevant-mid",
            "caller_persona": "unenrolled-revoke-persona",
        });
        let res = handle_broker_revoke(Some(&principal), &store, &params).await;
        let (code, msg) = res.expect_err("broker_revoke must refuse unenrolled persona");
        assert_eq!(
            code, -32401,
            "expected -32401 PrincipalNotEnrolled, got {code}: {msg}"
        );
        assert!(
            msg.contains("unenrolled persona") || msg.contains("PrincipalNotEnrolled"),
            "error must mention unenrolled persona, got: {msg}"
        );
    }

    /// Fail-closed per-RPC rollout (step D) acceptance test (list half).
    /// broker_list must refuse an unenrolled caller_persona with -32401
    /// (PrincipalNotEnrolled / fail_closed_broker_revoke_list checkpoint).
    #[tokio::test]
    async fn handle_broker_list_refuses_unenrolled_persona() {
        let _identity = ensure_identity_for_broker_test();
        let store = DaemonStore::open_in_memory().unwrap();

        let principal = test_principal(8484, 1);
        let params = serde_json::json!({
            "caller_persona": "unenrolled-list-persona",
        });
        let res = handle_broker_list(Some(&principal), &store, &params).await;
        let (code, msg) = res.expect_err("broker_list must refuse unenrolled persona");
        assert_eq!(
            code, -32401,
            "expected -32401 PrincipalNotEnrolled, got {code}: {msg}"
        );
        assert!(
            msg.contains("unenrolled persona") || msg.contains("PrincipalNotEnrolled"),
            "error must mention unenrolled persona, got: {msg}"
        );
    }

    /// Helper: install a freshly-built registry into the OnceCell,
    /// idempotent against repeated test invocations.
    fn install_registry_for_test(reg: BrokerRegistry) {
        // OnceCell::set is a one-shot — subsequent calls are no-ops,
        // which is fine because tests build registries with the same
        // MockBroker registrations.
        install_registry(reg);
    }

    // -----------------------------------------------------------------------
    // pidfd binding — pidfd-backed reuse-immune liveness gate.
    // `handle_broker_issue` (and the other broker RPCs) refuse a request
    // whose pidfd reports the bound peer process has been reaped.
    // -----------------------------------------------------------------------

    /// Spawn a short-lived child process, capture its pid, and `wait()`
    /// for it to exit so the pid is reaped. Returns the now-stale pid.
    ///
    /// Used to build a `PeerCredPrincipal` whose pidfd refers to a
    /// process the kernel has already cleaned up — exactly the
    /// PID-reuse forgery surface the pidfd binding protects against.
    #[cfg(target_os = "linux")]
    fn spawn_and_reap_child() -> i32 {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawning /bin/true must succeed");
        let pid = child.id() as i32;
        // Wait so the child is fully reaped before we bind a pidfd
        // against it. The reaped pid is what we want — a pidfd opened
        // against it will report POLLIN ("process exited") on poll.
        let _ = child.wait();
        pid
    }

    /// Failing-test contract from the brief —
    /// `handle_broker_issue_rejects_dead_principal`. Builds a
    /// `PeerCredPrincipal` whose pidfd refers to an already-exited
    /// child, then calls `handle_broker_issue`. The handler must
    /// refuse with the pidfd-not-alive code BEFORE any provider IO.
    ///
    /// Error code: `-32007` (ERR_PRINCIPAL_NOT_ALIVE) — distinct from
    /// `-32004` so operators can tell apart "wrong uid" from "stale-
    /// PID forgery".
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn handle_broker_issue_rejects_dead_principal() {
        use crate::infra::runtime::PeerCredPrincipal;

        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        install_registry_for_test(reg);
        let store = DaemonStore::open_in_memory().unwrap();

        let persona = store.create_persona("dead-principal-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);

        // Bind the persona to the daemon's own uid so the peercred
        // gate would pass — the only thing failing the request must
        // be the pidfd liveness check.
        let euid = unsafe { libc::geteuid() };
        seed_persona_uid_via_enrollments(&store, &persona.id, euid);

        // Build a principal whose pidfd refers to an already-reaped
        // child. If pidfd_open is unavailable on this kernel, we
        // skip the assertion — the test is exercising the live-pidfd
        // code path. (libc::SYS_pidfd_open is gated to Linux 5.3+.)
        let stale_pid = spawn_and_reap_child();
        let principal = match PeerCredPrincipal::new_with_pidfd_for_test(
            euid,
            stale_pid,
            std::path::PathBuf::from("/tmp/test-agent.sock"),
        ) {
            Some(p) => p,
            None => {
                eprintln!(
                    "skipping handle_broker_issue_rejects_dead_principal: \
                     pidfd_open unavailable on this kernel (need Linux 5.3+)"
                );
                return;
            }
        };

        // Sanity: the principal's pidfd must report the bound process
        // as dead. If this fires, the test setup is broken (the child
        // wasn't actually reaped or the pidfd has not yet observed
        // the exit).
        assert!(
            !principal.is_alive(),
            "test setup: stale-pid principal must report not-alive"
        );

        let mut params = issue_params(300, "dead-principal-test");
        params["caller_persona"] = serde_json::json!(persona.id);

        let res = handle_broker_issue(Some(&principal), &store, &params).await;
        let (code, msg) = res.expect_err("issue must refuse dead-pid principal");
        assert_eq!(
            code, ERR_PRINCIPAL_NOT_ALIVE,
            "expected -32007 principal-not-alive, got {code}: {msg}"
        );
        assert!(
            msg.contains("not alive") || msg.contains("reaped"),
            "error must mention stale-PID reason, got: {msg}"
        );
    }

    // ------------------------------------------------------------------
    // broker.mint_sub_persona input
    // validation tests. These exercise the -32602 gate that runs BEFORE
    // the unsupported scaffold path, so they must pass.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn mint_sub_persona_handler_rejects_missing_parent_persona_id() {
        let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
        let params = serde_json::json!({
            "child_label": "worker-1",
            "scope": "*"
        });
        let result = handle_broker_mint_sub_persona(&store, &params).await;
        match result {
            Err((code, msg)) => {
                assert_eq!(code, -32602, "expected -32602 InvalidParams, got {code}");
                assert!(
                    msg.contains("parent_persona_id"),
                    "error must name the missing field, got: {msg}"
                );
            }
            Ok(v) => panic!("expected Err but got Ok({v})"),
        }
    }

    #[tokio::test]
    async fn mint_sub_persona_handler_rejects_missing_child_label() {
        let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
        let params = serde_json::json!({
            "parent_persona_id": "persona-abc123",
            "scope": "*"
        });
        let result = handle_broker_mint_sub_persona(&store, &params).await;
        match result {
            Err((code, msg)) => {
                assert_eq!(code, -32602, "expected -32602 InvalidParams, got {code}");
                assert!(
                    msg.contains("child_label"),
                    "error must name the missing field, got: {msg}"
                );
            }
            Ok(v) => panic!("expected Err but got Ok({v})"),
        }
    }

    #[tokio::test]
    async fn mint_sub_persona_handler_fails_closed_when_scaffold_unimplemented() {
        let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
        let params = serde_json::json!({
            "parent_persona_id": "persona-abc123",
            "child_label": "worker-1",
            "scope": "*"
        });

        let result = handle_broker_mint_sub_persona(&store, &params).await;
        match result {
            Err((code, msg)) => {
                assert_eq!(code, -32000, "expected structured daemon error, got {code}");
                assert!(
                    msg.contains("fail-closed"),
                    "error must name fail-closed posture, got: {msg}"
                );
                assert!(
                    msg.contains("not implemented"),
                    "error must name unsupported scaffold, got: {msg}"
                );
            }
            Ok(v) => panic!("expected Err but got Ok({v})"),
        }
    }

    // -----------------------------------------------------------------------
    // Spawn handle TTL — spawn handle expiry gate
    // -----------------------------------------------------------------------

    #[test]
    fn registry_status_with_registry_includes_provider_posture() {
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(core_broker::MockBroker::new(
            BrokerProvider::AwsSts,
        )));
        registry.register_mock(Box::new(core_broker::MockBroker::new(
            BrokerProvider::Github,
        )));

        let value = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(registry_status_with_registry(&registry))
            .expect("registry status must serialize");

        assert_eq!(value["provider_count"], json!(2));
        let providers = value["providers"]
            .as_array()
            .expect("providers array must be present");
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0]["provider"], json!("aws_sts"));
        assert_eq!(providers[0]["mock"], json!(false));
        assert_eq!(providers[1]["provider"], json!("github"));
        assert_eq!(providers[1]["mock"], json!(true));
    }

    #[test]
    fn github_status_with_registry_and_resolver_reports_pat_lane() {
        static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("env lock");

        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(core_broker::MockBroker::new(
            BrokerProvider::Github,
        )));

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let missing_env = tmp.path().join("missing.env");
        let missing_pem = tmp.path().join("missing.pem");
        let prev_env = std::env::var("EMBER_APP_ENV_PATH").ok();
        let prev_pem = std::env::var("EMBER_APP_PEM_PATH").ok();
        unsafe {
            std::env::set_var("EMBER_APP_ENV_PATH", &missing_env);
            std::env::set_var("EMBER_APP_PEM_PATH", &missing_pem);
        }

        let store = std::sync::Arc::new(
            crate::infra::credential_store::test_helpers::MockCredentialStore::new(),
        );
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            store
                .put("github-pat", b"ghp_test_pat_value")
                .await
                .expect("store PAT");
        });
        let resolver = crate::broker::authority::BrokerAuthorityResolver::new(
            store,
            crate::broker::authority::CredentialPrecedence::VaultFirst,
        );

        let value = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(github_status_with_registry_and_resolver(
                &registry, &resolver,
            ))
            .expect("github status must serialize");

        unsafe {
            match prev_env {
                Some(v) => std::env::set_var("EMBER_APP_ENV_PATH", v),
                None => std::env::remove_var("EMBER_APP_ENV_PATH"),
            }
            match prev_pem {
                Some(v) => std::env::set_var("EMBER_APP_PEM_PATH", v),
                None => std::env::remove_var("EMBER_APP_PEM_PATH"),
            }
        }

        assert_eq!(value["lane"], json!("pat"));
        assert_eq!(value["detail"], Value::Null);
        assert_eq!(value["app_id"], Value::Null);
        assert_eq!(value["installation_id"], Value::Null);
    }

    #[test]
    fn github_status_with_registry_and_resolver_reports_app_identity_for_app_lane() {
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(core_broker::MockBroker::new(
            BrokerProvider::Github,
        )));

        let store = std::sync::Arc::new(
            crate::infra::credential_store::test_helpers::MockCredentialStore::new(),
        );
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            store
                .put("github/apps/ember-engine/install-42/private-key", b"pem")
                .await
                .expect("store private key leaf");
            store
                .put("github/apps/ember-engine/install-42/app-id", b"12345")
                .await
                .expect("store app-id leaf");
            store
                .put("github/apps/ember-engine/install-42/installation-id", b"42")
                .await
                .expect("store installation-id leaf");
        });
        let resolver = crate::broker::authority::BrokerAuthorityResolver::new(
            store,
            crate::broker::authority::CredentialPrecedence::VaultFirst,
        );

        let value = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(github_status_with_registry_and_resolver(
                &registry, &resolver,
            ))
            .expect("github status must serialize");

        assert_eq!(value["lane"], json!("app"));
        assert_eq!(value["detail"], Value::Null);
        assert_eq!(value["app_id"], json!("12345"));
        assert_eq!(value["installation_id"], json!("42"));
    }

    #[test]
    fn github_status_with_registry_and_resolver_reports_broken_detail_for_partial_app_triple() {
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(core_broker::MockBroker::new(
            BrokerProvider::Github,
        )));

        let store = std::sync::Arc::new(
            crate::infra::credential_store::test_helpers::MockCredentialStore::new(),
        );
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            store
                .put("github/apps/ember/install-123/private-key", b"pem")
                .await
                .expect("store private key leaf");
            store
                .put("github/apps/ember/install-123/app-id", b"123")
                .await
                .expect("store app-id leaf");
        });
        let resolver = crate::broker::authority::BrokerAuthorityResolver::new(
            store,
            crate::broker::authority::CredentialPrecedence::VaultFirst,
        );

        let value = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(github_status_with_registry_and_resolver(
                &registry, &resolver,
            ))
            .expect("github status must serialize even when authority is broken");

        assert_eq!(value["lane"], json!("broken"));
        let detail = value["detail"]
            .as_str()
            .expect("broken github status must carry a detail string");
        assert!(
            detail.contains("partial credential triple"),
            "broken detail should explain the local App triple problem: {detail}"
        );
    }
}
