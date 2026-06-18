use super::*;
use crate::infra::rpc_error::RpcError;
use core_grants::GrantState as CoreGrantState;

/// `binding.delete` JSON-RPC verb — graceful delete of a workload Persona binding.
///
/// Per ADR 119 §"binding.delete":
///   1. Revoke the workload Persona's Grant (cascade via `revoke_persona`).
///      Active grants flip to `revoked`; in-flight broker requests holding
///      a still-cached grant ref drain to completion. New `use_credential` /
///      broker lookups fail loudly because they hit the revoked-grant guard.
///   2. Emit a `binding.deleted` audit event so the reconciler + receipt
///      pipeline can correlate the lifecycle transition with the originating
///      `binding_request_id`. The receipt envelope (signed by the EIC Daemon
///      Persona) is layered on top of this audit event by the Receipt v2
///      pipeline (`crate::infra::receipt`); this handler's job is the
///      audit-log row + the state mutation.
///
/// Idempotency: re-deleting an already-revoked persona is a no-op success
/// path — the audit row still gets written so the reconciler sees a fresh
/// receipt for its retry. `revoke_persona` returns `NotFound` for a never-
/// registered persona; we surface that as `-32004`.
///
/// Drain semantics (graceful path): the cascade revoke flips the SQL row
/// state but does NOT actively cancel a tokio future already executing
/// inside `broker_issue` / `use_credential`. Those callers complete using
/// the locally-bound `core_grants::Grant` they captured at request entry.
/// New requests fail because lookup runs after the SQL flip.
///
/// `binding_revoke_urgent` (a separate verb)
/// will skip the in-flight drain by also poisoning the in-process
/// grant cache — that path is intentionally NOT reused here because it
/// inverts the contract callers rely on for the graceful path.
pub async fn binding_delete(store: &DaemonStore, params: &Value) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id' parameter".to_string()))?;
    // `binding_request_id` is optional but recommended — the reconciler
    // uses it for idempotent retries. We log it through to the audit row
    // so an operator can trace a delete back to a specific reconcile pass.
    let binding_request_id = params["binding_request_id"].as_str();

    // Step 1 — graceful drain via cascade revoke. `revoke_persona` flips
    // the persona row to `revoked` and marks every active grant under it
    // as `revoked` in the same transaction. In-flight broker calls that
    // already loaded the grant complete with their cached copy; new
    // lookups hit the revoked guard.
    match store.revoke_persona(persona_id) {
        Ok(()) => {}
        Err(crate::infra::store::StoreError::NotFound) => {
            return Err(RpcError::NotFound(format!("binding {persona_id} not found")).into());
        }
        Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
    }

    // Step 2 — audit-log emission. Action mirrors the receipt kind from
    // `core_events::receipt::atomic::RECEIPT_KIND_BINDING_DELETED` so the
    // Receipt v2 pipeline can correlate audit rows with envelopes.
    let details = serde_json::json!({
        "persona_id": persona_id,
        "binding_request_id": binding_request_id,
    })
    .to_string();
    let _ = store.log_event(
        Some(persona_id),
        core_events::receipt::atomic::RECEIPT_KIND_BINDING_DELETED,
        None,
        "allowed",
        Some(&details),
    );

    Ok(json!({
        "deleted": true,
        "persona_id": persona_id,
        "binding_request_id": binding_request_id,
    }))
}

/// `binding.revoke_urgent` JSON-RPC verb — compromise-response revocation
/// of a workload Persona binding.
///
/// Per ADR 119 §"binding.revoke_urgent":
///   1. Revoke the workload Persona's Grant (cascade via `revoke_persona`).
///      Same SQL transition as `binding.delete` — persona row flips to
///      `revoked` and every active grant under it flips to `revoked` in
///      the same statement.
///   2. Emit a `binding.revoke_urgent` audit row with outcome `"urgent"`
///      so alerting pipelines can fire on the high-severity event
///      without re-parsing the details JSON. Unlike the graceful
///      `binding.deleted` event, this row is the trigger for compromise-
///      response automation: rotate the credential, sweep the audit log
///      for the persona, page the on-call rotation.
///
/// Difference from `binding.delete`: this verb does NOT promise
/// graceful drain semantics. Today the SQL flip is synchronous and the
/// daemon does not maintain an in-process grant cache, so an in-flight
/// `use_credential` call holding a `core_grants::Grant` value at request
/// entry will still complete with that cached value. When the in-process
/// cache lands (planned with the broker materialization layer), this
/// verb is the one that will additionally poison the cache so urgent
/// revocations actually cancel in-flight callers.
///
/// Idempotency: re-revoking an already-revoked persona is a NotFound
/// (mirrors `binding.delete`). The compromise-response runbook is
/// expected to be idempotent at the orchestration layer — the reconciler
/// retries with the same `binding_request_id` and treats `-32004` as
/// "already revoked, no further action needed".
pub async fn binding_revoke_urgent(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id' parameter".to_string()))?;
    // `binding_request_id` is optional but recommended — the reconciler
    // uses it for idempotent retries. We log it through to the audit row
    // so an operator can trace an urgent revocation back to a specific
    // compromise-response pass.
    let binding_request_id = params["binding_request_id"].as_str();
    // `reason` is optional but strongly recommended for compromise
    // response — it lands in the audit details JSON so the SOC2 evidence
    // export captures why the urgent revocation fired.
    let reason = params["reason"].as_str();

    // Step 1 — cascade revoke. Same SQL transition as `binding.delete`;
    // the wedge that distinguishes urgent from graceful is the audit
    // event row (action + outcome), NOT the storage layer.
    match store.revoke_persona(persona_id) {
        Ok(()) => {}
        Err(crate::infra::store::StoreError::NotFound) => {
            return Err(RpcError::NotFound(format!("binding {persona_id} not found")).into());
        }
        Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
    }

    // Step 2 — audit-log emission. Action is the literal
    // `"binding.revoke_urgent"` (NOT the `RECEIPT_KIND_BINDING_REVOKED`
    // constant — that one is for the graceful-revoke pipeline, this
    // verb is the urgent-only path). Outcome `"urgent"` makes alerting
    // queries trivial: `WHERE outcome = 'urgent'`.
    let details = serde_json::json!({
        "persona_id": persona_id,
        "binding_request_id": binding_request_id,
        "reason": reason,
    })
    .to_string();
    let _ = store.log_event(
        Some(persona_id),
        "binding.revoke_urgent",
        None,
        "urgent",
        Some(&details),
    );

    Ok(json!({
        "revoked_urgent": true,
        "persona_id": persona_id,
        "binding_request_id": binding_request_id,
    }))
}

/// `binding.update` JSON-RPC verb — mutate metadata on an existing
/// workload Persona binding without revoking it.
///
/// Per ADR 119 §"binding.update":
///   1. Look up the existing binding (persona row). Return `-32004` if
///      the binding does not exist.
///   2. Apply each mutable field in turn — today only `name` is
///      surfaced as a SQL column, but the wire shape accepts the
///      broader binding-metadata fields (`cred_class_allowlist`,
///      `lease_duration_cap`, etc.) so callers can already speak the
///      ADR 119 contract; those fields land in the audit details JSON
///      until the schema lands columns for them.
///   3. Emit a `binding.updated` audit row keyed on
///      `RECEIPT_KIND_BINDING_UPDATED` with a before/after snapshot
///      so the reconciler + receipt pipeline can correlate the
///      mutation with its originating `binding_request_id`.
///
/// JSON-RPC params shape (all fields after `binding_id` are optional;
/// at least one mutable field SHOULD be present):
/// ```json
/// {
///   "binding_id":          "persona-...",          // required
///   "binding_request_id":  "br-...",               // optional, recommended
///   "name":                "new-name",             // optional, SQL-mutated
///   "cred_class_allowlist": ["llm:*", ...],        // optional, audit-only
///   "lease_duration_cap":  3600,                   // optional, audit-only
///   "metadata":            { ... }                 // optional, audit-only
/// }
/// ```
///
/// Backwards-compat: `persona_id` is accepted as a synonym for
/// `binding_id` so the verb composes with the same callers that drive
/// `binding.delete` / `binding.revoke_urgent`.
///
/// Idempotency: replaying the same params is safe. The SQL UPDATE is
/// a write of the exact same value when nothing changed; the audit
/// row is appended each call so the reconciler always sees a fresh
/// receipt for its retry. The orchestration layer is expected to
/// dedupe via `binding_request_id` if it cares about exactly-once
/// audit emission.
pub async fn binding_update(store: &DaemonStore, params: &Value) -> Result<Value, (i32, String)> {
    // Accept either `binding_id` (canonical per ADR 119) or
    // `persona_id` (for symmetry with the delete/revoke verbs that
    // still speak persona_id). At least one must resolve to a string.
    let binding_id = params["binding_id"]
        .as_str()
        .or_else(|| params["persona_id"].as_str())
        .ok_or_else(|| RpcError::InvalidParams("missing 'binding_id' parameter".to_string()))?;
    let binding_request_id = params["binding_request_id"].as_str();

    // Step 1 — load the existing binding so we can build a "before"
    // snapshot for the audit row AND surface NotFound as -32004.
    let before = match store.get_persona(binding_id) {
        Ok(p) => p,
        Err(crate::infra::store::StoreError::NotFound) => {
            return Err(RpcError::NotFound(format!("binding {binding_id} not found")).into());
        }
        Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
    };

    // Step 2 — apply mutable fields. Today only `name` lives in SQL.
    // The remaining fields (cred_class_allowlist, lease_duration_cap,
    // metadata) are audit-only until the schema lands columns for
    // them; they still flow through the wire contract so callers can
    // forward-compatibly drive ADR 119 today.
    let new_name = params["name"].as_str();
    if let Some(name) = new_name
        && name != before.name
    {
        // SQLite UNIQUE-constraint violations come back as
        // `Sqlite(SqliteFailure { code: ConstraintViolation, .. })`;
        // surface as -32005 to give callers an actionable signal
        // distinct from the generic -32000 "internal" bucket.
        match store.conn().execute(
            "UPDATE personas SET name = ?1 WHERE id = ?2",
            rusqlite::params![name, binding_id],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(RpcError::Conflict(format!("name '{name}' already in use")).into());
            }
            Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    // Step 3 — capture the after-snapshot. We re-read so the audit
    // reflects whatever SQLite actually committed (in particular, if
    // a future migration adds defaulted columns, the audit row picks
    // them up automatically).
    let after = store
        .get_persona(binding_id)
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    // Step 4 — audit-log emission. Action mirrors
    // `RECEIPT_KIND_BINDING_UPDATED` so the Receipt v2 pipeline can
    // correlate audit rows with envelopes. The details JSON carries
    // both the before/after persona snapshots AND the audit-only
    // metadata fields the caller passed (so the reconciler can apply
    // them to its in-memory model even before the schema lands).
    let details = serde_json::json!({
        "binding_id": binding_id,
        "binding_request_id": binding_request_id,
        "before": {
            "name": before.name,
            "status": before.status,
        },
        "after": {
            "name": after.name,
            "status": after.status,
        },
        "requested": {
            "name": new_name,
            "cred_class_allowlist": params.get("cred_class_allowlist"),
            "lease_duration_cap": params.get("lease_duration_cap"),
            "metadata": params.get("metadata"),
        },
    })
    .to_string();
    let _ = store.log_event(
        Some(binding_id),
        core_events::receipt::atomic::RECEIPT_KIND_BINDING_UPDATED,
        None,
        "allowed",
        Some(&details),
    );

    Ok(json!({
        "updated": true,
        "binding_id": binding_id,
        "binding_request_id": binding_request_id,
        "name": after.name,
    }))
}

/// `binding.upsert` JSON-RPC verb — idempotent insert-or-update for a
/// workload Persona binding.
///
/// Per ADR 119 §"binding.upsert": this is the steady-state verb
/// `ember-kernel`'s EmberServiceAccount reconciler calls every pass.
/// Today it ships as a thin compose of `get_persona` + `create_persona`
/// plus the SQL `UPDATE` from `binding.update`. The audit row records a
/// `binding.upserted` event keyed on the (final) persona id with a
/// before/after diff so the reconciler and receipt pipeline can tell
/// "first registration" apart from "no-op refresh" without re-parsing
/// the persona row.
///
/// JSON-RPC params shape (all fields optional except either `persona_id`
/// or `name` MUST be present so the verb has a binding to anchor on):
/// ```json
/// {
///   "namespace":            "ns-prod",                    // optional, audit-only
///   "name":                 "ml-eval",                    // required when creating
///   "persona_id":           "persona-...",                // optional, identifier when updating
///   "binding_request_id":   "br-...",                     // optional, recommended
///   "cred_class_allowlist": ["llm:*", ...],               // optional, audit-only
///   "lease_duration_cap":   3600,                         // optional, audit-only
///   "metadata":             { ... }                       // optional, audit-only
/// }
/// ```
///
/// Idempotency: replaying the same params is safe. If the persona
/// already exists with the requested name, the UPDATE is a no-op write
/// and the audit row records `before == after` (the reconciler still
/// gets a fresh receipt). If the row does not exist, a fresh persona
/// is created and the audit row carries `before: null`.
///
/// Returns `{ persona_id, created, updated }`. `persona_id` is always
/// the canonical id the daemon uses (which may differ from the caller's
/// `persona_id` if the caller asked for a fresh registration). Exactly
/// one of `created` / `updated` is `true`.
pub async fn binding_upsert(store: &DaemonStore, params: &Value) -> Result<Value, (i32, String)> {
    // Either `persona_id` (canonical, looks up an existing binding) or
    // `name` (required when creating fresh) MUST be present. Mirrors
    // the `binding.update` `binding_id`/`persona_id` synonym shape.
    let requested_persona_id = params["persona_id"]
        .as_str()
        .or_else(|| params["binding_id"].as_str());
    let name = params["name"].as_str();
    let binding_request_id = params["binding_request_id"].as_str();

    if requested_persona_id.is_none() && name.is_none() {
        return Err(RpcError::InvalidParams(
            "binding.upsert requires either 'persona_id' or 'name'".to_string(),
        )
        .into());
    }

    // Step 1 — try to load the existing binding so we can branch on
    // create-vs-update. NotFound on a caller-supplied `persona_id`
    // routes to the create path (idempotent insert); other errors
    // surface as -32000.
    let existing = match requested_persona_id {
        Some(pid) => match store.get_persona(pid) {
            Ok(p) => Some(p),
            Err(crate::infra::store::StoreError::NotFound) => None,
            Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
        },
        None => None,
    };

    // Step 2 — branch.
    let (canonical_id, created, before_snapshot, after) = match existing {
        // ── Update path ──
        Some(before) => {
            // Apply the only mutable SQL column today (`name`). Deeper
            // metadata mutations land in audit-only details JSON until
            // the schema lands columns for them — same shape as
            // `binding.update`.
            if let Some(new_name) = name
                && new_name != before.name
            {
                match store.conn().execute(
                    "UPDATE personas SET name = ?1 WHERE id = ?2",
                    rusqlite::params![new_name, before.id],
                ) {
                    Ok(_) => {}
                    Err(rusqlite::Error::SqliteFailure(err, _))
                        if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        return Err(RpcError::Conflict(format!(
                            "name '{new_name}' already in use"
                        ))
                        .into());
                    }
                    Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
                }
            }
            let after = store
                .get_persona(&before.id)
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            let before_snapshot = json!({
                "name": before.name,
                "status": before.status,
            });
            (before.id.clone(), false, before_snapshot, after)
        }
        // ── Create path ──
        None => {
            // Creating a fresh persona requires a name — caller
            // either passed `persona_id` for a row that doesn't
            // exist (snapshot drift, fresh cluster) or passed `name`
            // for a never-registered SA.
            let create_name = name.ok_or_else(|| {
                RpcError::InvalidParams("binding.upsert create path requires 'name'".to_string())
            })?;
            let new_persona = match store.create_persona(create_name) {
                Ok(p) => p,
                Err(crate::infra::store::StoreError::Sqlite(rusqlite::Error::SqliteFailure(
                    err,
                    _,
                ))) if err.code == rusqlite::ErrorCode::ConstraintViolation => {
                    return Err(
                        RpcError::Conflict(format!("name '{create_name}' already in use")).into(),
                    );
                }
                Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
            };
            (new_persona.id.clone(), true, Value::Null, new_persona)
        }
    };

    // Step 3 — audit-log emission. Action `"binding.upserted"` mirrors
    // the existing `binding.deleted` / `binding.updated` literals —
    // the kind constant for upsert is not yet locked in
    // `core_events::receipt::atomic`, so we emit the literal here and
    // tighten to a constant when ADR 118 lands the discriminator.
    let details = serde_json::json!({
        "persona_id": canonical_id,
        "binding_request_id": binding_request_id,
        "created": created,
        "before": before_snapshot,
        "after": {
            "name": after.name,
            "status": after.status,
        },
        "requested": {
            "namespace": params.get("namespace"),
            "name": name,
            "cred_class_allowlist": params.get("cred_class_allowlist"),
            "lease_duration_cap": params.get("lease_duration_cap"),
            "metadata": params.get("metadata"),
        },
    })
    .to_string();
    let _ = store.log_event(
        Some(&canonical_id),
        "binding.upserted",
        None,
        "allowed",
        Some(&details),
    );

    Ok(json!({
        "persona_id": canonical_id,
        "binding_request_id": binding_request_id,
        "created": created,
        "updated": !created,
        "name": after.name,
    }))
}

/// Per ADR 140 §9 + §6 — atomic
/// `create_agent_persona` RPC handler.
///
/// Replaces the two-call sequence `create_persona` + `delegate_grant`
/// with a single state-machine'd verb whose lifecycle is:
///
/// 1. **Phase 1 — enrolling.** Insert a workload persona row with
///    `status = 'enrolling'`, bind it to the requested `container_id`
///    and `parent_grant_id`. Refuses if a previous spawn already
///    bound the same container slot (CRIT-4: one in-flight key per
///    container).
/// 2. **Phase 2 — delegate.** Call `delegate_grant_full` against the
///    parent grant, producing an attenuated child grant scoped to
///    `child_scope` (and optionally narrowed budget / TTL).
/// 3. **Phase 3 — activate.** Flip the persona row from `enrolling`
///    to `active`. The row is now usable by `use_credential`,
///    `delegate_grant`, etc.
///
/// If the daemon crashes between phase 1 and phase 3, the persona row
/// remains `enrolling` forever; the reconciler's idempotency check
/// (`DaemonStore::enrolling_persona_for_container`) surfaces the
/// poisoned slot, and the reconciler refuses to spawn a second
/// container into the same enrolling slot (the test
/// `agent_persona_enrolling_blocks_reconciler_spawn` covers this).
///
/// The container binding is persisted in BOTH the `personas` table
/// (via the `container_id` column) AND the audit log (via an
/// `agent_persona.created` event with the full binding metadata in
/// `details`), so reconcilers can reconstruct the binding from either
/// source even if one is rolled back by a future migration.
///
/// JSON-RPC params shape:
/// ```json
/// {
///   "name":             "ml-eval-worker",       // required, persona display name
///   "container_id":     "ctr-abc123",            // required, container identity
///   "parent_grant_id":  "grant-...",             // required, grant being attenuated
///   "child_scope":      "credential.access.gh",  // required, scope of attenuated grant
///   "ttl_secs":         3600,                    // optional, child grant TTL
///   "budget":           { ... },                 // optional, narrowed budget
///   "agent_id":         "scion-agent-...",       // optional, audit-only
///   "binding_request_id": "br-..."               // optional, audit-only
/// }
/// ```
///
/// Returns `{ persona_id, attenuated_grant_id, container_id, status }`.
/// `status` is always `"active"` on success — callers do not see the
/// `enrolling` intermediate state because phase 3 is part of the same
/// RPC's success path.
pub async fn create_agent_persona(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let name = params["name"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'name' parameter".to_string()))?;
    let container_id = params["container_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'container_id' parameter".to_string()))?;
    let parent_grant_id = params["parent_grant_id"].as_str().ok_or_else(|| {
        RpcError::InvalidParams("missing 'parent_grant_id' parameter".to_string())
    })?;
    let child_scope = params["child_scope"]
        .as_str()
        .or_else(|| params["scope"].as_str())
        .ok_or_else(|| RpcError::InvalidParams("missing 'child_scope' parameter".to_string()))?;
    let ttl_secs = params["ttl_secs"].as_u64();
    let child_budget: Option<core_grant_types::Budget> = if params["budget"].is_object() {
        Some(
            serde_json::from_value(params["budget"].clone())
                .map_err(|e| RpcError::InvalidParams(format!("invalid 'budget': {e}")))?,
        )
    } else {
        None
    };
    let binding_request_id = params["binding_request_id"].as_str();
    let agent_id = params["agent_id"].as_str();
    // Per ADR 209 §2 — when the orchestrator spawns a SCION worker it requests the
    // daemon-minted ADR 154 bridge client bundle (the container's mTLS identity
    // per ADR 209 §2) in the same daemon-owned spawn call. The daemon owns this
    // mint (it holds the bridge CA, mlock'd, never on disk); the orchestrator
    // never mints locally. Reuses the one register_session bundle primitive so
    // there is a single cert-mint contract, not a parallel per-agent CA.
    let want_bridge_client_bundle = params["bridge_client_bundle"].as_bool().unwrap_or(false);

    // Validate the parent grant exists and is active BEFORE inserting
    // the enrolling persona row. A bad parent grant means the whole
    // two-phase commit will fail; bailing out here avoids a poisoned
    // enrollment slot that only exists because phase-2 was never going
    // to succeed.
    let parent_grant = store
        .grant_store()
        .load_grant(parent_grant_id)
        .map_err(|e| match e {
            crate::infra::store::StoreError::NotFound => {
                RpcError::NotFound(format!("parent grant '{parent_grant_id}' not found"))
            }
            // Malformed grant id (e.g. not a valid uuid) is functionally
            // equivalent to "no such grant" from the caller's POV — surface
            // it as -32004 so callers don't have to special-case parse
            // failures vs miss-by-id.
            crate::infra::store::StoreError::InvalidInput(_) => {
                RpcError::NotFound(format!("parent grant '{parent_grant_id}' not found"))
            }
            other => RpcError::Internal(other.to_string()),
        })?;
    if parent_grant.state != CoreGrantState::Active {
        return Err(RpcError::Conflict(format!(
            "parent grant '{parent_grant_id}' is not active and cannot be \
                 delegated from"
        ))
        .into());
    }

    // ── Phase 1: insert persona row in `enrolling` state ──
    //
    // This both creates the row AND binds it to `container_id` in a
    // single SQL statement. The uniqueness check inside
    // `create_agent_persona_enrolling` rejects a second spawn into the
    // same container slot — CRIT-4 mitigation.
    let enrolling = store
        .create_agent_persona_enrolling(name, container_id, parent_grant_id)
        .map_err(|e| match e {
            crate::infra::store::StoreError::InvalidInput(msg) => RpcError::Conflict(msg),
            crate::infra::store::StoreError::Sqlite(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                RpcError::Conflict(format!("name '{name}' already in use"))
            }
            other => RpcError::Internal(other.to_string()),
        })?;
    let new_persona_id = enrolling.id.clone();

    // ── Phase 2: delegate the parent grant to the new persona ──
    //
    // If this fails, the persona row stays in `enrolling`. The
    // reconciler's enrolling-slot check refuses to spawn a duplicate
    // container against the poisoned binding; an operator can clean
    // up the orphan row out-of-band. We intentionally do NOT auto-
    // rollback phase 1 — leaving the row visible is the audit trail
    // for the failed spawn.
    let grant = match store.delegate_grant_full(
        parent_grant_id,
        &new_persona_id,
        child_scope,
        ttl_secs,
        child_budget,
    ) {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(
                container_id = %container_id,
                parent_grant_id = %parent_grant_id,
                new_persona_id = %new_persona_id,
                error = %e,
                "create_agent_persona: phase-2 delegate_grant failed; \
                 persona left in 'enrolling' state for reconciler reaping"
            );
            // Audit-log the phase-2 failure so the reconciler can
            // distinguish "daemon crashed" from "delegate rejected".
            let details = serde_json::json!({
                "persona_id": new_persona_id,
                "container_id": container_id,
                "parent_grant_id": parent_grant_id,
                "phase": "delegate",
                "error": e.to_string(),
                "binding_request_id": binding_request_id,
                "agent_id": agent_id,
            })
            .to_string();
            let _ = store.log_event(
                Some(&new_persona_id),
                "agent_persona.enroll_failed",
                None,
                "denied",
                Some(&details),
            );
            return Err(RpcError::Internal(format!("delegate_grant failed: {e}")).into());
        }
    };

    // ── Phase 3: flip persona enrolling → active ──
    //
    // Same crash-safety story as phase 2: if this UPDATE fails, the
    // row stays in `enrolling`. The reconciler refuses to spawn into
    // the slot until an operator reaps the orphan.
    if let Err(e) = store.activate_persona(&new_persona_id) {
        tracing::warn!(
            container_id = %container_id,
            new_persona_id = %new_persona_id,
            error = %e,
            "create_agent_persona: phase-3 activate_persona failed; \
             persona left in 'enrolling' state for reconciler reaping"
        );
        let details = serde_json::json!({
            "persona_id": new_persona_id,
            "container_id": container_id,
            "parent_grant_id": parent_grant_id,
            "child_grant_id": grant.id,
            "phase": "activate",
            "error": e.to_string(),
            "binding_request_id": binding_request_id,
            "agent_id": agent_id,
        })
        .to_string();
        let _ = store.log_event(
            Some(&new_persona_id),
            "agent_persona.enroll_failed",
            None,
            "denied",
            Some(&details),
        );
        return Err(RpcError::Internal(format!("activate_persona failed: {e}")).into());
    }

    // ── Phase 4 (audit): persist the binding event in the SQLite event log ──
    //
    // The personas table column is the steady-state binding source of
    // truth; this audit row is the temporally-ordered event-log entry
    // demanded by ADR 140 §6 "container-id binding persisted in
    // SQLite event log". A reconciler that has lost its persona-table
    // index can replay the audit log to reconstruct the binding map.
    let details = serde_json::json!({
        "persona_id": new_persona_id,
        "container_id": container_id,
        "parent_grant_id": parent_grant_id,
        "child_grant_id": grant.id,
        "child_scope": child_scope,
        "ttl_secs": ttl_secs,
        "binding_request_id": binding_request_id,
        "agent_id": agent_id,
        "name": name,
    })
    .to_string();
    let _ = store.log_event(
        Some(&new_persona_id),
        "agent_persona.created",
        None,
        "allowed",
        Some(&details),
    );

    // ── Phase 5 (optional): mint the ADR 154 bridge client bundle ──
    //
    // The bundle is the container's mTLS identity (SPIFFE SAN
    // `spiffe://emberd/persona/<persona>` + `spiffe://emberd/container/<id>`,
    // ADR 209 §2), minted daemon-side via the shared register_session bundle
    // primitive. FAIL-SOFT and SEPARATE from the spawn success above: a bridge
    // failure (e.g. `[daemon].bridge_bind` unconfigured → -32030) must NOT undo
    // the minted persona/grant — the worker simply starts without an emberd
    // control plane, mirroring the daemon-sandbox lane's posture.
    let mut response = json!({
        "persona_id": new_persona_id,
        "attenuated_grant_id": grant.id,
        "container_id": container_id,
        "parent_grant_id": parent_grant_id,
        "child_scope": child_scope,
        "status": "active",
        "name": enrolling.name,
        "public_key": enrolling.public_key,
        "expires_at": grant.expires_at,
    });
    if want_bridge_client_bundle {
        // MED-1 (review): the container_id becomes the cert's SPIFFE container
        // SAN, so reject a value that won't fit the SAN grammar
        // (`[a-z0-9:_-]`, ≤128) up front with a clear -32602 rather than minting
        // a cert the bridge would refuse at handshake. The orchestrator passes a
        // v4 UUID, which fits.
        let container_san_ok = !container_id.is_empty()
            && container_id.len() <= 128
            && container_id.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'_' | b'-')
            });
        if !container_san_ok {
            return Err(RpcError::InvalidParams(
                "container_id has characters not allowed in a SPIFFE container SAN \
                 (expected [a-z0-9:_-], 1..=128 chars)"
                    .to_string(),
            )
            .into());
        }
        match crate::infra::interactive_unlock::ensure_vault_for_session_open(store) {
            Ok(vault) => {
                match crate::infra::handlers::session::mint_register_session_bridge_client_bundle(
                    &vault,
                    &new_persona_id,
                    // No session in the spawn lane; the container id is the SAN
                    // ref, so the session-id fallback slot is unused here.
                    container_id,
                    Some(container_id),
                ) {
                    Ok(bundle) => {
                        // spawn_time_cert_write_landed
                        // (ADR 173 CRIT-2). Pin the freshly-minted client cert's
                        // blake3-hex fingerprint + Unix `not_after` onto the
                        // persona row in a single UPDATE so the M3 `refresh_cert`
                        // 3-way grant-active / SPIFFE / cert-fingerprint check
                        // can compare against the spawn-time value. Fail-soft
                        // and SEPARATE from the spawn success: if the column
                        // write fails the persona/grant stay minted and the
                        // bundle stays returned — the next `refresh_cert` call
                        // will rebuild the row (M3-B's `AuthFailurePersonaUnknown`
                        // surfaces an empty fingerprint as the same recoverable
                        // class as a legacy pre-(d) row). See
                        // `infra/persona.rs::pin_persona_client_cert_from_pem`
                        // for the fingerprint shape (matches ADR 173 §C2's
                        // "blake3 of leaf cert DER").
                        match crate::infra::persona::pin_persona_client_cert_from_pem(
                            store,
                            &new_persona_id,
                            &bundle.client_cert_pem,
                        ) {
                            Ok((fingerprint_hex, not_after_unix)) => {
                                tracing::debug!(
                                    persona_id = %new_persona_id,
                                    container_id = %container_id,
                                    fingerprint = %fingerprint_hex,
                                    not_after_unix,
                                    "create_agent_persona: pinned client cert columns at spawn-enrollment time"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    persona_id = %new_persona_id,
                                    container_id = %container_id,
                                    error = %e,
                                    "create_agent_persona: failed to pin client cert columns; \
                                     persona row left at default empty-string fingerprint"
                                );
                            }
                        }
                        response["bridge_client_bundle"] =
                            serde_json::to_value(bundle).map_err(|e| {
                                RpcError::Internal(format!("encode bridge bundle: {e}"))
                            })?;
                    }
                    Err((code, msg)) => {
                        tracing::debug!(
                            code,
                            error = %msg,
                            container_id = %container_id,
                            persona_id = %new_persona_id,
                            "create_agent_persona: bridge bundle unavailable; worker starts without an emberd control plane"
                        );
                    }
                }
            }
            Err(msg) => {
                tracing::debug!(
                    error = %msg,
                    container_id = %container_id,
                    "create_agent_persona: vault unavailable for bridge bundle mint; skipping"
                );
            }
        }
    }

    Ok(response)
}
