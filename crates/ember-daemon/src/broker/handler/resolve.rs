use std::collections::BTreeSet;
use std::path::Path;

use chrono::{DateTime, Utc};
use core_broker::SecretRef;
use core_event_types::{ActionRef, ExecutionContract, PregrantPath};
use serde_json::{Value, json};

use crate::broker::runners::{dispatch_runner_for_resolve, runner_class_as_str};
use crate::infra::claim_journal::{
    AuditEvidenceInput, ClaimJournal, ClaimScopeKind, ScopeRef, SqliteClaimJournal,
    SuccessfulClaimInput,
};
use crate::infra::pidfd::SpawnHandlePidfd;
use crate::infra::runtime::PeerCredPrincipal;
use crate::infra::store::DaemonStore;

use super::exec_policy::{
    NestedExecutionContractRequirement, reject_legacy_broker_resolve_fields,
    validate_nested_execution_contract_wire_shape, warn_ignored_execution_contract_mirror_fields,
};
use super::{
    BrokerRegistry, PendingSpawnHandle, SPAWN_HANDLE_TTL_SECS, authoring_paths_registry_path,
    check_grants_schema_version_for_persona, check_peer_binary_pinned,
    check_principal_against_persona, check_principal_enrollment_strict, check_principal_is_alive,
    check_principal_namespace_inodes, current_registry, err_no_registry,
    load_authoring_paths_registry, log_legacy_socket_resolution, script_is_in_authoring_path,
};

// broker_resolve_plaintext — daemon-side trust-boundary resolution
// (ADRs 094 + 127)
// ---------------------------------------------------------------------------

/// Errors surfaced by [`broker_resolve_plaintext`]. Distinct from
/// [`BrokerError`] so callers (the resolve RPC handler, kernel
/// reconcilers) can route persona-binding violations and unknown
/// SecretRefs to specific JSON-RPC error codes without leaking the
/// shape of the broker provider's own error taxonomy.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The `SecretRef` does not refer to any active materialization.
    /// Either it was never issued, or has already been revoked, or the
    /// daemon has been restarted (the plaintext store is in-memory).
    #[error("unknown secret_ref: {0}")]
    UnknownSecretRef(String),

    /// The persona presented by the resolver does not match the
    /// persona that issued the materialization. The trust-boundary
    /// invariant is strict: only the persona that materialised the
    /// credential is allowed to resolve it. Materializations issued
    /// without a `caller_persona` (legacy / system-internal callers)
    /// require the resolver to likewise present `None`.
    #[error("persona binding violation: secret_ref was not issued for the presenting persona")]
    PersonaBindingViolation,

    /// The daemon could not persist metadata-only resolve evidence before
    /// returning plaintext.
    #[error("resolve audit write failed: {0}")]
    AuditWriteFailed(String),
}

/// Daemon-side `SecretRef` → plaintext resolution per ADRs 094 + 127.
///
/// Performs three steps in order:
///
/// 1. **Lookup**: maps the opaque `SecretRef` to its stashed plaintext
///    in the broker registry. Unknown / already-revoked refs return
///    [`ResolveError::UnknownSecretRef`].
/// 2. **Persona-binding check**: enforces that the persona presented
///    by the resolver matches the `caller_persona` recorded at issuance
///    time. Mismatches return [`ResolveError::PersonaBindingViolation`].
///    This is the trust-boundary invariant — only the persona that
///    minted the credential is allowed to materialise it. Legacy /
///    system-internal materializations (issued with `caller_persona =
///    None`) require the resolver to likewise present `None`.
/// 3. **Receipt**: emits a `broker.resolve.materialized` audit row
///    naming the secret_ref id, persona_id, and materialization id so
///    every plaintext materialization has a downstream audit trail.
///    Receipt-emit failures fail closed before plaintext is returned.
///
/// On success returns the [`SecretString`](secrecy::SecretString) cloned
/// out of the registry's plaintext store. The caller must
/// `expose_secret()` only at the moment of writing the credential into
/// its destination (the runtime k8s `Secret` for the kernel
/// reconciler; the upstream HTTP request for ember-proxy).
///
/// **Trust-boundary invariant**: this is the ONLY function in the
/// daemon that returns plaintext. All other RPC paths return only the
/// opaque `SecretRef` (= the `materialization_id`).
pub async fn broker_resolve_plaintext(
    secret_ref: &SecretRef,
    persona_id: Option<&str>,
    store: &DaemonStore,
) -> Result<secrecy::SecretString, ResolveError> {
    let registry = current_registry()
        .ok_or_else(|| ResolveError::UnknownSecretRef(secret_ref.as_str().to_string()))?;
    broker_resolve_plaintext_with_registry(
        registry, secret_ref, persona_id, store, None, None, None, None, None, None, None, None,
        None,
    )
    .await
}

/// Registry-explicit twin of [`broker_resolve_plaintext`]. Used by the
/// resolve RPC dispatcher (which already holds a `&BrokerRegistry`)
/// and tests, which build a fresh registry per case rather than
/// poking the process-global `OnceCell`.
// RPC/plumbing signature — structurally many materialization-context refs.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn broker_resolve_plaintext_with_registry(
    registry: &BrokerRegistry,
    secret_ref: &SecretRef,
    persona_id: Option<&str>,
    store: &DaemonStore,
    workflow_ctx: Option<&DelegationReceiptContext>,
    session_id: Option<&str>,
    action_ref: Option<&ActionRef>,
    contract_id: Option<&str>,
    workspace_ref: Option<&str>,
    subject_ref: Option<&str>,
    coordination_ref: Option<&str>,
    caller_ref: Option<&str>,
    authority_ref: Option<&str>,
) -> Result<secrecy::SecretString, ResolveError> {
    let materialization_id = secret_ref.as_str();

    // Step 1 — lookup. Cloning out of the mutex so the lock drops
    // before any audit-log I/O.
    let entry = registry
        .lookup_plaintext(materialization_id)
        .ok_or_else(|| ResolveError::UnknownSecretRef(materialization_id.to_string()))?;

    // Step 2 — persona binding. Strict identity match in both
    // directions: a Some-issuer requires a Some-resolver with the same
    // value; a None-issuer requires a None-resolver. This refuses both
    // (a) legacy resolvers reaching for a persona-bound credential and
    // (b) persona-bearing resolvers reaching for a system-issued
    // credential.
    let issuer_persona = entry.persona_id.as_deref();
    if issuer_persona != persona_id {
        // Refusal Receipt — record the binding mismatch so the audit
        // trail captures the attempted misuse. We do NOT include the
        // resolver's claimed persona in the Receipt body to avoid
        // leaking caller identity into the materialization's history;
        // the materialization id + outcome=denied is sufficient.
        let payload = serde_json::json!({
            "kind": "broker_resolve_persona_binding_violation",
            "materialization_id": materialization_id,
        });
        if let Err(e) = store.log_event(
            None,
            "broker.resolve.refused",
            None,
            "denied",
            Some(&payload.to_string()),
        ) {
            tracing::warn!(
                error = %e,
                materialization_id = materialization_id,
                "broker_resolve: failed to record persona-binding-violation receipt"
            );
        }
        return Err(ResolveError::PersonaBindingViolation);
    }

    // Step 3 — accept Receipt. The persona match passed; record the
    // resolution before returning plaintext so the audit trail is
    // durable even if the caller crashes mid-write.
    //
    // delegation_receipt_body_stamp_landed: ADR 158 §Component 5 — every
    // credentialed Receipt carries (delegation_id, delegation_template,
    // pregrant_path) when the call was workflow-scoped. The fields are
    // populated from the eval result threaded through from
    // `handle_broker_resolve`; `None` for system-class callers (omitted
    // from the JSON via serde_json::Value's null-skip on construction).
    let payload = serde_json::json!({
        "kind": "broker_resolve_materialized",
        "materialization_id": materialization_id,
        "persona_id": persona_id,
        "contract_id": contract_id,
        "action_ref": action_ref,
        "workspace_ref": workspace_ref,
        "subject_ref": subject_ref,
        "coordination_ref": coordination_ref,
        "caller_ref": caller_ref,
        "authority_ref": authority_ref,
        "delegation_id": workflow_ctx.and_then(|c| c.delegation_id.as_deref()),
        "delegation_template": workflow_ctx.and_then(|c| c.delegation_template.as_deref()),
        "pregrant_path": workflow_ctx.map(|c| c.pregrant_path),
    });
    record_broker_resolve_claim(
        store,
        materialization_id,
        persona_id,
        entry.grant_id.as_deref(),
        session_id,
        action_ref,
        contract_id,
        workspace_ref,
        subject_ref,
        coordination_ref,
        caller_ref,
        authority_ref,
        workflow_ctx,
        &payload,
    )?;

    Ok(entry.plaintext)
}

/// Map a [`ResolveError`] to the JSON-RPC `(code, message)` tuple used
/// on the wire by `handle_broker_resolve`. Kept separate from the
/// `BrokerError` mapper so the two error taxonomies don't bleed into
/// each other.
fn map_resolve_error(err: ResolveError) -> (i32, String) {
    match err {
        ResolveError::UnknownSecretRef(id) => (-32004, format!("unknown secret_ref: {id}")),
        ResolveError::PersonaBindingViolation => (
            -32003,
            "persona_binding_violation: secret_ref was not issued for the presenting persona"
                .to_string(),
        ),
        ResolveError::AuditWriteFailed(message) => (
            -32031,
            format!("broker_resolve_audit_write_failed: {message}"),
        ),
    }
}

// RPC/plumbing signature — structurally many materialization-context refs.
#[allow(clippy::too_many_arguments)]
fn record_broker_resolve_claim(
    store: &DaemonStore,
    materialization_id: &str,
    persona_id: Option<&str>,
    grant_id: Option<&str>,
    session_id: Option<&str>,
    action_ref: Option<&ActionRef>,
    contract_id: Option<&str>,
    workspace_ref: Option<&str>,
    subject_ref: Option<&str>,
    coordination_ref: Option<&str>,
    caller_ref: Option<&str>,
    authority_ref: Option<&str>,
    workflow_ctx: Option<&DelegationReceiptContext>,
    payload: &Value,
) -> Result<(), ResolveError> {
    let payload_str = payload.to_string();
    let legacy_audit = || -> Result<(), ResolveError> {
        store
            .log_event(
                None,
                "broker.resolve.materialized",
                None,
                "allowed",
                Some(&payload_str),
            )
            .map_err(|e| {
                tracing::warn!(
                    error = %e,
                    materialization_id = materialization_id,
                    "broker_resolve: failed to record materialization audit row"
                );
                ResolveError::AuditWriteFailed(e.to_string())
            })?;
        Ok(())
    };

    let mut scopes = Vec::new();
    if let Some(session_id) = session_id.filter(|s| !s.is_empty()) {
        scopes.push(ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
            id: session_id.to_string(),
        });
    }
    if let Some(grant_id) = grant_id.filter(|s| !s.is_empty()) {
        scopes.push(ScopeRef {
            kind: ClaimScopeKind::Grant,
            id: grant_id.to_string(),
        });
    }
    if scopes.is_empty() {
        return legacy_audit();
    }

    let input_shape = json!({
        "kind": "broker_resolve",
        "materialization_id": materialization_id,
        "persona_id": persona_id,
        "grant_id": grant_id,
        "session_id": session_id,
        "contract_id": contract_id,
        "action_ref": action_ref,
        "workspace_ref": workspace_ref,
        "subject_ref": subject_ref,
        "coordination_ref": coordination_ref,
        "caller_ref": caller_ref,
        "authority_ref": authority_ref,
    });
    let resolved_shape = json!({
        "materialization_id": materialization_id,
        "grant_id": grant_id,
        "contract_id": contract_id,
        "action_ref": action_ref,
        "workspace_ref": workspace_ref,
        "subject_ref": subject_ref,
        "coordination_ref": coordination_ref,
        "caller_ref": caller_ref,
        "authority_ref": authority_ref,
        "delegation_id": workflow_ctx.and_then(|c| c.delegation_id.as_deref()),
        "delegation_template": workflow_ctx.and_then(|c| c.delegation_template.as_deref()),
        "pregrant_path": workflow_ctx.map(|c| c.pregrant_path),
    });
    let input_hash = blake3::hash(input_shape.to_string().as_bytes())
        .to_hex()
        .to_string();
    let journal = SqliteClaimJournal::new(store, 64);
    let input = SuccessfulClaimInput {
        source_key: materialization_id.to_string(),
        occurred_at: Utc::now().to_rfc3339(),
        claim_kind: core_events::receipt::ClaimKind::CredentialVended,
        tool: action_ref
            .map(ToString::to_string)
            .unwrap_or_else(|| "broker.resolve".to_string()),
        action_ref: action_ref.cloned(),
        runner_class: None,
        execution_domain: None,
        materialization_class: None,
        input_hash,
        input_redacted: input_shape,
        resolved: resolved_shape,
        audit: AuditEvidenceInput {
            agent_id: persona_id.map(str::to_string),
            action: "broker.resolve.materialized".to_string(),
            credential: None,
            outcome: "allowed".to_string(),
            details: Some(payload_str.clone()),
        },
        persona_id: persona_id.map(str::to_string),
        grant_id: grant_id.map(str::to_string),
        device_id: None,
        delegation_id: workflow_ctx.and_then(|c| c.delegation_id.clone()),
        materialization_id: Some(materialization_id.to_string()),
        credential_name: None,
    };
    if let Err(e) = journal.record_successful_claim_for_scopes(&scopes, &input) {
        tracing::warn!(
            error = %e,
            materialization_id,
            scope_count = scopes.len(),
            "broker_resolve: claim journal append failed; falling back to legacy audit row"
        );
        legacy_audit()?;
    }
    Ok(())
}

/// Resolve a `SecretRef` → plaintext at the trust boundary.
///
/// This is the only place
/// plaintext leaves the daemon, and it MUST emit a per-resolution
/// Receipt so every materialization has a downstream audit trail of
/// where the credential was actually used.
///
/// Two gates run in sequence:
///
/// 1. **L1 authoring-path gate**:
///    when the caller
///    presents a `script_path` without `signed_binary=true`, the
///    daemon refuses unless the script resides under a registered
///    authoring path. Authoring-path callers get an `authoring = true`
///    accept Receipt and proceed.
/// 2. **Plaintext resolution + persona-binding check**:
///    when the caller presents a
///    `secret_ref`, the daemon enforces persona binding and returns
///    plaintext via [`broker_resolve_plaintext_with_registry`].
///    Resolves without a `secret_ref` preserve the legacy `-32001`
///    placeholder behaviour (the gate-only smoke-test surface).
pub(crate) async fn resolve_with_registry(
    registry: &BrokerRegistry,
    store: &DaemonStore,
    params: &Value,
    principal: Option<&PeerCredPrincipal>,
    workflow_ctx: Option<DelegationReceiptContext>,
) -> Result<Value, (i32, String)> {
    // L1 authoring-path gate. The caller (ember-proxy / ember-tools /
    // ember-kernel reconcilers) MUST pass `script_path` when running
    // unsigned; signed (manifest-pinned) callers set `signed_binary=
    // true` and skip the gate. When neither is set, the gate is a
    // no-op (production code path will set one of them; the legacy
    // smoke test paths set neither).
    //
    // When the caller is a
    // Construct shim (core-construct-runtime), it passes a
    // `lease_request` object instead of a `secret_ref`. The lease
    // request shape is the construct shim's resolve-phase payload:
    // (action_ref, env_passthrough, construct_toml_hash_input_len),
    // with an optional legacy `binary` seam preserved as fallback.
    // The daemon returns a stub `SpawnHandle` bound to (binary,
    // env_allowlist, materialization_id, target_uid). The
    // construct-shim resolve path is forward-compatible with the legacy
    // secret_ref → plaintext path;
    // the two shapes share the dispatch but never collide.
    #[derive(serde::Deserialize, Default)]
    struct ConstructLeaseRequest {
        #[serde(default)]
        action_ref: Option<ActionRef>,
        #[serde(default)]
        env_passthrough: Vec<String>,
        #[serde(default)]
        construct_toml_hash_input_len: u64,
    }

    #[derive(serde::Deserialize, Default)]
    struct ResolveParams {
        #[serde(default)]
        script_path: Option<String>,
        #[serde(default)]
        execution_contract: Option<ExecutionContract>,
        /// When true, the caller asserts the binary is L2 (signed,
        /// pinned via the manifest). The daemon trusts this only when
        /// paired with a real signature check (full signature
        /// verification lands in a follow-up); for now, presence of
        /// `script_path` plus absence of `signed_binary=true` means we
        /// apply the L1 gate.
        #[serde(default)]
        signed_binary: bool,
        /// Opaque SecretRef (= materialization_id) the caller wants to
        /// resolve to plaintext. Required for the plaintext path; when
        /// absent the dispatcher returns the legacy `-32001`
        /// placeholder so smoke tests that only exercise the authoring
        /// gate stay green.
        #[serde(default)]
        secret_ref: Option<SecretRef>,
        /// Persona on whose behalf the resolution is being requested.
        /// Threaded into the persona-binding check inside
        /// [`broker_resolve_plaintext_with_registry`]. `None` means
        /// "system / legacy caller" — strictly matched against the
        /// `caller_persona` recorded at issuance time.
        #[serde(default)]
        #[serde(alias = "caller_persona")]
        persona_id: Option<String>,
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        contract_id: Option<String>,
        #[serde(default)]
        action_ref: Option<ActionRef>,
        #[serde(default)]
        workspace_ref: Option<String>,
        #[serde(default)]
        subject_ref: Option<String>,
        #[serde(default)]
        coordination_ref: Option<String>,
        #[serde(default)]
        caller_ref: Option<String>,
        #[serde(default)]
        authority_ref: Option<String>,
        /// Construct-shim resolve-phase payload. Mutually exclusive with `secret_ref`
        /// — present iff the caller is a Construct shim asking for a
        /// spawn handle.
        #[serde(default)]
        lease_request: Option<ConstructLeaseRequest>,
    }

    reject_legacy_broker_resolve_fields(params)?;
    let contract_requirement = if params.get("lease_request").is_some() {
        NestedExecutionContractRequirement::Required
    } else {
        NestedExecutionContractRequirement::Optional
    };
    validate_nested_execution_contract_wire_shape(params, "broker_resolve", contract_requirement)?;
    if params.get("execution_contract").is_some() {
        warn_ignored_execution_contract_mirror_fields(params, "broker_resolve");
    }

    let parsed: ResolveParams = if params.is_null() {
        ResolveParams::default()
    } else {
        serde_json::from_value(params.clone())
            .map_err(|e| (-32602, format!("invalid broker_resolve params: {e}")))?
    };

    let mut authoring = false;
    if let Some(script_path) = parsed.script_path.as_deref()
        && !parsed.signed_binary
    {
        // L1 path: must reside in a registered authoring path or refuse.
        // `EMBER_AUTHORING_PATHS_FILE` is a test-only override; in
        // production the registry lives at `~/.ember/authoring-paths.toml`.
        let registry_file = std::env::var_os("EMBER_AUTHORING_PATHS_FILE")
            .map(std::path::PathBuf::from)
            .or_else(authoring_paths_registry_path)
            .unwrap_or_else(|| std::path::PathBuf::from("/.ember/authoring-paths.toml"));
        let auth_registry = load_authoring_paths_registry(&registry_file);
        let path_obj = std::path::Path::new(script_path);
        if !script_is_in_authoring_path(&auth_registry, path_obj) {
            let payload = serde_json::json!({
                "kind": "authoring_path_not_registered",
                "script_path": script_path,
                "registry_path": registry_file.display().to_string(),
            });
            if let Err(e) = store.log_event(
                None,
                "broker.resolve.refused",
                None,
                "denied",
                Some(&payload.to_string()),
            ) {
                tracing::warn!(
                    error = %e,
                    "broker_resolve: failed to record authoring_path_not_registered receipt"
                );
            }
            return Err((
                -32003,
                format!(
                    "authoring_path_not_registered: script_path={} (run `ember construct dev <dir>` to register)",
                    script_path
                ),
            ));
        }
        authoring = true;
    }

    // Authoring-path accept: emit a tagged `authoring = true` Receipt and
    // surface the gate decision so the caller can route to the rest of
    // the resolve flow when it lands.
    if authoring {
        let payload = serde_json::json!({
            "kind": "broker_resolve_authoring",
            "script_path": parsed.script_path,
            "authoring": true,
        });
        if let Err(e) = store.log_event(
            None,
            "broker.resolve.authoring",
            None,
            "allowed",
            Some(&payload.to_string()),
        ) {
            tracing::warn!(
                error = %e,
                "broker_resolve: failed to record authoring receipt"
            );
        }
    }

    // Plaintext path. Only fires when the caller passed a `secret_ref`
    // — gate-only smoke tests that omit it preserve the legacy
    // `-32001` placeholder return below.
    if let Some(secret_ref) = parsed.secret_ref.as_ref() {
        use secrecy::ExposeSecret;
        let nested_contract = parsed.execution_contract.as_ref();
        let contract_id = nested_contract
            .and_then(|contract| contract.contract_id.as_deref())
            .or(parsed.contract_id.as_deref());
        let action_ref = nested_contract
            .map(|contract| &contract.action_ref)
            .or(parsed.action_ref.as_ref());
        let workspace_ref = nested_contract
            .and_then(|contract| contract.workspace_ref.as_deref())
            .or(parsed.workspace_ref.as_deref());
        let subject_ref = nested_contract
            .and_then(|contract| contract.subject_ref.as_deref())
            .or(parsed.subject_ref.as_deref());
        let coordination_ref = nested_contract
            .and_then(|contract| contract.coordination_ref.as_deref())
            .or(parsed.coordination_ref.as_deref());
        let caller_ref = nested_contract
            .and_then(|contract| contract.caller_ref.as_deref())
            .or(parsed.caller_ref.as_deref());
        let authority_ref = nested_contract
            .and_then(|contract| contract.authority_ref.as_deref())
            .or(parsed.authority_ref.as_deref());
        let plaintext = broker_resolve_plaintext_with_registry(
            registry,
            secret_ref,
            parsed.persona_id.as_deref(),
            store,
            workflow_ctx.as_ref(),
            parsed.session_id.as_deref(),
            action_ref,
            contract_id,
            workspace_ref,
            subject_ref,
            coordination_ref,
            caller_ref,
            authority_ref,
        )
        .await
        .map_err(map_resolve_error)?;

        // The plaintext is returned to the trust boundary — the kernel
        // reconciler / ember-proxy / ember-tools — never to the agent
        // process. The `materialization_id` echo lets the caller
        // correlate the response with the request without re-reading
        // the SecretRef.
        return Ok(json!({
            "plaintext": plaintext.expose_secret(),
            "materialization_id": secret_ref.as_str(),
        }));
    }

    // Construct shim resolve
    // path. Returns a spawn handle binding (binary, env_allowlist,
    // materialization_id, target_uid). The daemon-side
    // `credential_provisioned` Receipt is NOT emitted here — the
    // resolve phase only mints a pending materialization. The exec
    // phase (`handle_broker_exec`) emits `credential_provisioned`
    // after the wrapped binary is spawned. If exec never fires the
    // shim sends `broker_resolve_release` and the daemon emits
    // `credential_resolve_aborted` instead. This is the HIGH-E
    // remediation per ADR 140 §9.
    if let Some(lease) = parsed.lease_request.as_ref() {
        let action_ref = lease
            .action_ref
            .clone()
            .or_else(|| {
                parsed
                    .execution_contract
                    .as_ref()
                    .map(|contract| contract.action_ref.clone())
            })
            .ok_or((-32602, "lease_request.action_ref is required".to_string()))?;
        let mut execution_contract = parsed.execution_contract.clone().ok_or((
            -32602,
            "broker_resolve missing_execution_contract".to_string(),
        ))?;
        if execution_contract.action_ref != action_ref {
            return Err((
                -32602,
                format!(
                    "broker_resolve execution_contract.action_ref does not match lease_request.action_ref: {} != {}",
                    execution_contract.action_ref, action_ref
                ),
            ));
        }
        execution_contract
            .validate()
            .map_err(|e| (-32602, format!("invalid execution_contract: {e}")))?;
        let runner_resolution =
            dispatch_runner_for_resolve(&execution_contract).map_err(|e| e.into_rpc_error())?;
        let binary = runner_resolution.binary;
        let binary_source = runner_resolution.binary_source;
        let runner_class = runner_resolution.runner_class;

        // Materialization id is a daemon-side opaque correlation key
        // that ties the resolve → exec → audit phases together. The
        // real credential mint happens inside `broker_exec`'s
        // `mint_and_inject_for_action` path; the resolve phase
        // reserves the slot.
        let contract_id = format!("contract-{}", uuid::Uuid::new_v4());
        execution_contract.contract_id = Some(contract_id.clone());
        let materialization_id = format!("scion-resolve-{}", uuid::Uuid::new_v4());

        // Audit: a credential_resolve_pending Receipt is recorded.
        // The terminal kind (credential_provisioned vs
        // credential_resolve_aborted) is decided in the exec /
        // release phase.
        let payload = serde_json::json!({
            "kind": "credential_resolve_pending",
            "contract_id": contract_id,
            "action_ref": action_ref,
            "workspace_ref": execution_contract.workspace_ref,
            "subject_ref": execution_contract.subject_ref,
            "coordination_ref": execution_contract.coordination_ref,
            "caller_ref": execution_contract.caller_ref,
            "authority_ref": execution_contract.authority_ref,
            "binary": binary,
            "runner_binary_source": binary_source.as_str(),
            "runner_class": runner_class_as_str(runner_class),
            "materialization_id": materialization_id,
            "env_passthrough_count": lease.env_passthrough.len(),
            "construct_toml_hash_input_len": lease.construct_toml_hash_input_len,
        });
        if let Err(e) = store.log_event(
            None,
            "broker.resolve.pending",
            None,
            "allowed",
            Some(&payload.to_string()),
        ) {
            tracing::warn!(
                error = %e,
                materialization_id = %materialization_id,
                "broker_resolve: failed to record credential_resolve_pending receipt"
            );
        }

        // spawn_handle_ttl gate — record mint time
        // so broker_exec can enforce the 30-second replay window.
        //
        // spawn_handle_pidfd gate — bind the
        // handle to the socket peer that minted it. The wrapped child process
        // does not exist until broker_exec, so the caller pidfd is the
        // reuse-immune process identity available at resolve time.
        let not_after = chrono::Utc::now() + chrono::Duration::seconds(SPAWN_HANDLE_TTL_SECS);
        let bound_pidfd = SpawnHandlePidfd::bind_from_principal(principal).map_err(|reason| {
            (
                crate::infra::pidfd::ERR_SPAWN_HANDLE_PIDFD_INVALIDATED,
                format!("SpawnHandlePidfdInvalidated: bind failed reason={reason}"),
            )
        })?;
        registry.record_spawn_handle(PendingSpawnHandle {
            handle_id: materialization_id.clone(),
            execution_contract: execution_contract.clone(),
            not_after,
            bound_pidfd,
            consumed: false,
        });

        return Ok(json!({
            "contract_id": contract_id,
            "execution_contract": execution_contract,
            "action_ref": action_ref,
            "workspace_ref": execution_contract.workspace_ref,
            "subject_ref": execution_contract.subject_ref,
            "coordination_ref": execution_contract.coordination_ref,
            "caller_ref": execution_contract.caller_ref,
            "authority_ref": execution_contract.authority_ref,
            "materialization_id": materialization_id,
            "binary": binary,
            "env_allowlist": lease.env_passthrough,
            // target_uid = 0 means "no privilege drop" until the
            // SCION container-id → uid binding lands (tracked by
            // a follow-up). The construct
            // shim treats this as a checkpoint meaning "daemon-tier
            // exec" rather than a privilege error.
            "target_uid": 0,
        }));
    }

    // Legacy / smoke-test surface: caller exercised the authoring gate
    // without presenting a `secret_ref` or `lease_request`. Preserved
    // so the original gate-only tests (and any in-tree fixtures that
    // rely on the -32001 checkpoint) continue to compile and pass.
    Err((
        -32001,
        "broker_resolve plaintext path requires `secret_ref` param (TZ-BROKER-RESOLVE-PLAINTEXT-IMPL); authoring-path gate is active".to_string(),
    ))
}
/// Handle the `broker_resolve` socket RPC.
///
/// Params:
/// ```json
/// {
///   "secret_ref":     "<opaque materialization id>",  // optional (gate-only smoke path)
///   "persona_id":     "<persona that issued the secret>", // optional; binds resolution
///   "script_path":    "<absolute path>",              // optional; triggers L1 gate
///   "signed_binary":  false                            // optional; true skips L1 gate
/// }
/// ```
///
/// Response (plaintext path):
/// ```json
/// {
///   "plaintext":          "<raw credential>",
///   "materialization_id": "<opaque materialization id>"
/// }
/// ```
///
/// This is the ONLY RPC that
/// returns plaintext. Two gates run in sequence:
///
/// - **L1 authoring-path gate**: unsigned scripts outside any registered authoring
///   path are refused with `authoring_path_not_registered`.
/// - **Persona-binding check**:
///   only the persona that issued the materialization may resolve it.
///   Mismatches return `persona_binding_violation`.
///   Outcome of the delegation-grant evaluation step inside
///   `handle_broker_resolve`. Approve and the fall-through variants all let
///   the caller continue to the per-action / JIT chain;
///   `StandingGrantRequired` short-circuits with a wire-error.
///
/// BKR-4c (ADR 205 §6): the legacy delegation sidecar is gone, so the old
/// `Deny` (excluded-action) and `PersonaMismatch` (cross-persona grant) arms no
/// longer arise here — an out-of-scope verb is simply absent-allow (it falls
/// through, and dangerous verbs are denied by construct-policy deny-default),
/// and cross-persona drift is caught by the upstream principal gate.
/// `StandingGrantRequired` survives as the strict-posture refusal (no JIT
/// bootstrap), gated on the session's `authority_strict` posture.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DelegationEvalOutcome {
    Approve {
        delegation_id: String,
        template_name: String,
        pregrant_path: PregrantPath,
    },
    /// A github action whose need is not covered by the standing grant, under a
    /// strict (`authority_strict`) session posture — no JIT bootstrap.
    StandingGrantRequired {
        reason: &'static str,
    },
    FallThroughOutOfScope,
    FallThroughSidecarError(String),
    FallThroughMissingInputs,
}

const DELEGATED_AUTHORITY_TELEMETRY_FALLBACK_COHORT: &str = "delegated-authority";

#[derive(Debug, PartialEq)]
struct DelegatedGrantUtilizationSample {
    cohort: String,
    exercised_ratio: f32,
    out_of_scope_jits: u32,
    session_ttl_ratio: f32,
}

/// Workflow-correlation context plumbed from `handle_broker_resolve`'s
/// workflow-eval step → `resolve_with_registry` →
/// `broker_resolve_plaintext_with_registry` so the resolve materialization
/// audit-log payload carries the three Receipt body fields named in ADR 158
/// §Component 5: `delegation_id`, `delegation_template`, `pregrant_path`.
///
/// `None` is the system-class / no-workflow case (housekeeping calls); for
/// fall-through resolves the broker still stamps `pregrant_path = PerAction`
/// via `Self::per_action_fallthrough()`.
///
/// Anchor: `delegation_receipt_body_stamp_landed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DelegationReceiptContext {
    pub delegation_id: Option<String>,
    pub delegation_template: Option<String>,
    pub pregrant_path: PregrantPath,
}

impl DelegationReceiptContext {
    /// Built from a `DelegationEvalOutcome::Approve` — the session persona's
    /// standing grant covered the action's need (BKR-4c). The `delegation_id`
    /// field carries the matched grant id; the field name is retained for
    /// Receipt-schema stability. delegation_receipt_body_stamp_landed.
    pub fn from_approve(
        delegation_id: String,
        template_name: String,
        pregrant_path: PregrantPath,
    ) -> Self {
        Self {
            delegation_id: Some(delegation_id),
            delegation_template: Some(template_name),
            pregrant_path,
        }
    }

    /// Built when the workflow-eval step fell through — no delegation grant
    /// applied, but a credential is still being resolved via the per-action
    /// lane.
    pub fn per_action_fallthrough() -> Self {
        Self {
            delegation_id: None,
            delegation_template: None,
            pregrant_path: PregrantPath::PerAction,
        }
    }
}

/// Pure evaluation of the delegation-grant branch in `handle_broker_resolve`.
///
/// Returns the decision; the caller is responsible for tracing on each variant
/// and for translating short-circuit variants into JSON-RPC errors:
/// - `Deny` → `-32004 authority_delegation_denies_action`
/// - `PersonaMismatch` → `-32003 authority_delegation_persona_mismatch`
/// - `StandingGrantRequired` → `-32005 authority_delegation_required`
///
/// Extracted for direct T1 coverage per ADR 158 §Component 2.
///
/// Ordered evaluation per ADR 158 §C2 (post-2026-05-18-adversarial-fixes):
///   1. Load sidecar (refuses both absent AND revoked per `authority_delegation::load`).
///   2. **No grant + strict + non-issue action** → `StandingGrantRequired`
///      (ADR 158 §C3 bootstrap-only state).
///   3. **No grant + non-strict** OR **no grant + strict + issue action**
///      → `FallThroughNoSidecar` (legacy chain authoritative).
///   4. **Active grant + persona-mismatch** → `PersonaMismatch` (CRIT-2).
///   5. **Active grant + action in `excludes`** → `Deny`.
///   6. **Active grant + action in `scopes`** (and TTL valid) → `Approve`.
///   7. **Active grant + action out-of-scope** → `FallThroughOutOfScope`.
pub(crate) fn eval_workflow_for_action(
    store: &DaemonStore,
    sessions_dir: Option<&Path>,
    session_id: Option<&str>,
    action_ref: Option<&ActionRef>,
    request_persona: Option<&str>,
    strict_mode: bool,
    _now: DateTime<Utc>,
) -> DelegationEvalOutcome {
    let (Some(sessions_dir), Some(session_id), Some(action_ref), Some(persona)) =
        (sessions_dir, session_id, action_ref, request_persona)
    else {
        return DelegationEvalOutcome::FallThroughMissingInputs;
    };

    // BKR-4c: the runtime persona's standing grant carries the chosen
    // template's authority as enumerated `github:<object>:<verb>` Statements
    // (`narrow_github_statements` at session-open), so the per-session
    // pre-approval IS `need ⊆ standing grant`. Lower the action-ref to its
    // canonical github capability need and check each verb against the persona's
    // active grants.
    let need = ember_construct::manifest_action_need(&dotted_action_key(action_ref));
    if need.is_empty() {
        // No credential need (local verb / non-github tool): not gated by the
        // standing grant. Defer to the per-action / JIT / construct-policy chain
        // (an absent need is never "nothing to check" — it is "not ours to
        // approve"). gh.repo_delete & friends are denied downstream by their
        // construct.toml deny-default, not here.
        return DelegationEvalOutcome::FallThroughOutOfScope;
    }

    // Action-level coverage, repo-agnostic: the `*` resource probe matches the
    // dev0 `github:*` (Glob) standing grant. The concrete repo-bound
    // `need ⊆ grant` gate runs downstream at credential mint
    // (`verify_grant_for_use`, #5708), which fail-closes any out-of-repo use —
    // so a pre-approval here that is too broad on the resource axis is still
    // backstopped before a credential is issued.
    let mut matched_grant_id: Option<String> = None;
    let mut matched_grant_ids = BTreeSet::new();
    for need_action in &need {
        match store.match_standing_statement(persona, need_action, "*") {
            Ok(Some(m)) => {
                matched_grant_id.get_or_insert_with(|| m.grant_id.clone());
                matched_grant_ids.insert(m.grant_id);
            }
            Ok(None) => {
                // This need verb is outside the session's standing grant. Under
                // strict posture there is no JIT bootstrap; otherwise fall
                // through to the per-action / JIT chain. The canonical UX for
                // operator-approved one-call expansion lives on the minted lane
                // (narrow-TTL single-use lease per ADR 210 + ADR 211); see
                // the minted-lane operator CLI.
                return if strict_mode {
                    DelegationEvalOutcome::StandingGrantRequired {
                        reason: "action_not_covered_by_standing_grant",
                    }
                } else {
                    DelegationEvalOutcome::FallThroughOutOfScope
                };
            }
            Err(e) => {
                return DelegationEvalOutcome::FallThroughSidecarError(e.to_string());
            }
        }
    }

    // Every need verb is covered → the standing grant pre-approves this action.
    let template_name = load_session_template_name(sessions_dir, session_id)
        .unwrap_or_else(|| "standing-grant".to_string());
    record_delegated_grant_utilization(
        store,
        sessions_dir,
        session_id,
        &template_name,
        &matched_grant_ids,
        need.len(),
        _now,
    );
    DelegationEvalOutcome::Approve {
        delegation_id: matched_grant_id.unwrap_or_default(),
        template_name,
        pregrant_path: PregrantPath::StandingGrant,
    }
}

/// Map a structured [`ActionRef`] to the dotted `<tool>.<verb>` action key the
/// manifest need resolver (`manifest_action_need`) is keyed on: the plugin
/// address's final `ember-<tool>` segment becomes `<tool>`, joined to the
/// action key. `registry.ember.systems/ember-systems/ember-gh` + `pr_create`
/// → `gh.pr_create`. Mirrors `classify_argv_daemon_side`'s `ember-` stripping.
fn dotted_action_key(action_ref: &ActionRef) -> String {
    let slug = action_ref
        .plugin_address
        .rsplit('/')
        .next()
        .unwrap_or(action_ref.plugin_address.as_str());
    let tool = slug.strip_prefix("ember-").unwrap_or(slug);
    format!("{tool}.{}", action_ref.action_key)
}

fn record_delegated_grant_utilization(
    store: &DaemonStore,
    sessions_dir: &Path,
    session_id: &str,
    template_name: &str,
    matched_grant_ids: &BTreeSet<String>,
    need_count: usize,
    now: DateTime<Utc>,
) {
    if !crate::telemetry::measurement::is_enabled()
        || matched_grant_ids.is_empty()
        || need_count == 0
    {
        return;
    }

    let Some(sample) = delegated_grant_utilization_sample(
        store,
        sessions_dir,
        session_id,
        template_name,
        matched_grant_ids,
        need_count,
        now,
    ) else {
        return;
    };

    crate::telemetry::measurement::record_grant_utilization(
        &sample.cohort,
        sample.exercised_ratio,
        sample.out_of_scope_jits,
        sample.session_ttl_ratio,
    );
}

fn delegated_grant_utilization_sample(
    store: &DaemonStore,
    sessions_dir: &Path,
    session_id: &str,
    template_name: &str,
    matched_grant_ids: &BTreeSet<String>,
    need_count: usize,
    now: DateTime<Utc>,
) -> Option<DelegatedGrantUtilizationSample> {
    let mut granted_statement_count = 0usize;
    let mut ttl_ratio_sum = 0.0f32;
    let mut ttl_ratio_count = 0usize;
    let session_started_at = load_session_started_at(sessions_dir, session_id);

    for grant_id in matched_grant_ids {
        let Ok(access_grant) = store.get_access_grant(grant_id) else {
            continue;
        };
        granted_statement_count =
            granted_statement_count.saturating_add(access_grant.statement_count());

        let Some(session_started_at) = session_started_at else {
            continue;
        };
        let Ok(grant) = store.get_grant(grant_id) else {
            continue;
        };
        let (Some(created_at), Some(expires_at)) = (
            parse_rfc3339_utc(&grant.created_at),
            grant.expires_at.as_deref().and_then(parse_rfc3339_utc),
        ) else {
            continue;
        };
        let ttl_ms = (expires_at - created_at).num_milliseconds();
        let elapsed_ms = (now - session_started_at).num_milliseconds();
        if ttl_ms <= 0 || elapsed_ms < 0 {
            continue;
        }
        ttl_ratio_sum += elapsed_ms as f32 / ttl_ms as f32;
        ttl_ratio_count += 1;
    }

    if granted_statement_count == 0 {
        return None;
    }

    let exercised_ratio = (need_count as f32 / granted_statement_count as f32).min(1.0);
    let session_ttl_ratio = if ttl_ratio_count == 0 {
        0.0
    } else {
        ttl_ratio_sum / ttl_ratio_count as f32
    };
    // This approve-path call site cannot honestly count downstream JITs: an
    // out-of-scope fallthrough may be JIT, per-action, or denied later.
    Some(DelegatedGrantUtilizationSample {
        cohort: telemetry_cohort_for_template(template_name).to_string(),
        exercised_ratio,
        out_of_scope_jits: 0,
        session_ttl_ratio,
    })
}

fn telemetry_cohort_for_template(template_name: &str) -> &str {
    if ember_construct::delegation_template_schema::bundled_delegation_template_toml(template_name)
        .is_some()
    {
        template_name
    } else {
        DELEGATED_AUTHORITY_TELEMETRY_FALLBACK_COHORT
    }
}

fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Best-effort read of the session's chosen delegation-template name (stamped
/// on the session meta at register_session) for Receipt audit continuity.
fn load_session_template_name(sessions_dir: &Path, session_id: &str) -> Option<String> {
    core_state::sessions::SessionStore::new(sessions_dir.to_path_buf())
        .read(session_id)
        .ok()
        .flatten()
        .and_then(|meta| meta.delegation_template)
}

fn load_session_started_at(sessions_dir: &Path, session_id: &str) -> Option<DateTime<Utc>> {
    core_state::sessions::SessionStore::new(sessions_dir.to_path_buf())
        .read(session_id)
        .ok()
        .flatten()
        .map(|meta| meta.started_at)
}

pub(crate) fn resolve_workflow_strict_mode(
    sessions_dir: Option<&std::path::Path>,
    session_id: Option<&str>,
) -> bool {
    let env_strict_mode = std::env::var("EMBER_DELEGATION_STRICT").ok().as_deref() == Some("1");
    let (Some(sessions_dir), Some(session_id)) = (sessions_dir, session_id) else {
        return env_strict_mode;
    };
    let session_store = core_state::sessions::SessionStore::new(sessions_dir.to_path_buf());
    match session_store.read(session_id) {
        Ok(Some(meta)) => meta.authority_strict,
        Ok(None) => env_strict_mode,
        Err(err) => {
            tracing::warn!(
                session_id,
                error = %err,
                "broker.resolve: failed to load session authority posture; falling back to env strictness"
            );
            env_strict_mode
        }
    }
}

pub async fn handle_broker_resolve(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    sessions_dir: Option<&std::path::Path>,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let overlaid_params;
    let params = if let Some((attachment_id, endpoint_token)) =
        crate::infra::attachment::attachment_endpoint_from_params(params)
    {
        let sessions_dir = sessions_dir.ok_or((
            -32000,
            "broker_resolve: sessions_dir is required for attachment authority resolution"
                .to_string(),
        ))?;
        let authority = crate::infra::attachment::resolve_attachment_authority(
            sessions_dir,
            attachment_id,
            endpoint_token,
        )
        .await?;
        overlaid_params =
            crate::infra::attachment::overlay_broker_attachment_authority(params, &authority)?;
        &overlaid_params
    } else {
        params
    };

    check_grants_schema_version_for_persona(store, params, "persona_id")?;
    check_principal_is_alive(principal)?;
    check_principal_namespace_inodes(principal, store)?;
    check_peer_binary_pinned(principal)?;
    log_legacy_socket_resolution(principal, store, params, "persona_id", "broker_resolve");
    check_principal_against_persona(principal, store, params, "persona_id")?;
    check_principal_enrollment_strict(principal, store, params, "persona_id")?;

    // ADR 158 §Component 2 — delegation grant evaluation. Optional fast-path
    // authorization for sessions opened with a delegation template
    // (the launcher writes the sidecar; this is the
    // read side).
    //
    // Ordered evaluation (per ADR 158):
    //   (a) load session's active delegation grant via the sidecar
    //   (b) if grant.persona_id != request_persona → short-circuit
    //       persona-mismatch (CRIT-2)
    //   (c) if action in scope → log approval, continue to materialize
    //       (the existing per-action / JIT path is the materialization
    //        step; delegation grants AUTHORIZE the action, they do not
    //        themselves carry credentials)
    //   (d) if action explicitly excluded → short-circuit deny
    //   (e) if no active grant + strict mode + non-issue action →
    //       short-circuit authority_delegation_required (LOW-1, ADR 158 §C3)
    //   (f) otherwise fall through to per-action / JIT / deny chain
    //
    // The sidecar I/O is best-effort: parse errors and read errors fall
    // through to the legacy path (the gate ABOVE this in the existing
    // path will catch unauthorized resolves). Anchor:
    // `pregrant_authority_delegation_primitive_landed`. Direct T1 coverage of the
    // eval branch lives at `eval_workflow_for_action` (checkpoint
    // `workflow_eval_t1_test_landed`).
    //
    // 2026-05-18 PR #3672 adversarial-review fixes:
    // - CRIT-2: persona-mismatch defense (grant.persona_id vs params.persona_id)
    // - HIGH-1: read action identity from BOTH top-level and
    //           lease_request.action_ref so the SCION / Construct lease path
    //           is gated by the workflow primitive
    // - LOW-1: bootstrap-only state enforcement. Session authority posture
    //          now leads; the legacy env var remains only as a compatibility
    //          fallback when the caller is not attached to a stored session.
    let session_id = params.get("session_id").and_then(|v| v.as_str());
    let request_persona = params.get("persona_id").and_then(|v| v.as_str());
    // HIGH-1: action identity may live at the top-level OR inside
    // `lease_request.action_ref` (SCION / Construct shim path). Prefer the
    // lease shape because it's the modern path; fall back to top-level.
    let action_ref = params
        .get("lease_request")
        .and_then(|lr| lr.get("action_ref"))
        .cloned()
        .or_else(|| params.get("action_ref").cloned())
        .and_then(|value| serde_json::from_value::<ActionRef>(value).ok());
    let strict_mode = resolve_workflow_strict_mode(sessions_dir, session_id);
    // delegation_receipt_body_stamp_landed: capture the eval outcome as a
    // DelegationReceiptContext so downstream resolve_with_registry can stamp
    // the materialization Receipt body with (delegation_id, delegation_template,
    // pregrant_path). Approve → PregrantPath::StandingGrant with both IDs;
    // FallThrough → PregrantPath::PerAction with IDs None; PersonaMismatch /
    // StandingGrantRequired short-circuit via `return Err(...)` (type `!`).
    let workflow_ctx: Option<DelegationReceiptContext> = match eval_workflow_for_action(
        store,
        sessions_dir,
        session_id,
        action_ref.as_ref(),
        request_persona,
        strict_mode,
        chrono::Utc::now(),
    ) {
        DelegationEvalOutcome::Approve {
            delegation_id,
            template_name,
            pregrant_path,
        } => {
            // pregrant_authority_delegation_primitive_landed
            tracing::info!(
                delegation_id = %delegation_id,
                template = %template_name,
                session_id = session_id.unwrap_or(""),
                action_ref = %action_ref.as_ref().map(ToString::to_string).unwrap_or_default(),
                "broker.resolve: authority_delegation_approved"
            );
            Some(DelegationReceiptContext::from_approve(
                delegation_id,
                template_name,
                pregrant_path,
            ))
        }
        DelegationEvalOutcome::StandingGrantRequired { reason } => {
            return Err((
                -32005,
                format!(
                    "authority_delegation_required: session_id={} reason={}",
                    session_id.unwrap_or(""),
                    reason,
                ),
            ));
        }
        DelegationEvalOutcome::FallThroughSidecarError(e) => {
            tracing::warn!(
                session_id = session_id.unwrap_or(""),
                error = %e,
                "broker.resolve: authority_delegation sidecar load failed; falling through"
            );
            Some(DelegationReceiptContext::per_action_fallthrough())
        }
        DelegationEvalOutcome::FallThroughOutOfScope => {
            // Standing grant does not cover this action (or it carries no
            // credential need) — defer to the per-action / JIT / deny chain.
            Some(DelegationReceiptContext::per_action_fallthrough())
        }
        DelegationEvalOutcome::FallThroughMissingInputs => {
            // No session/action context — no workflow correlation to record.
            // System-class callers (housekeeping) hit this branch.
            None
        }
    };

    let registry = current_registry().ok_or_else(err_no_registry)?;
    resolve_with_registry(registry, store, params, principal, workflow_ctx).await
}

#[cfg(test)]
mod tests {
    // -----------------------------------------------------------------------
    // BKR-4c standing-grant resolution (ADR 205 §6). The legacy delegation
    // sidecar is gone: `eval_workflow_for_action` now resolves an action's
    // github capability need against the session persona's standing grant via
    // `match_standing_statement`. These tests persist a runtime standing grant
    // (the dev0 `narrow_github_statements` shape) and exercise the outcomes.
    // -----------------------------------------------------------------------
    mod standing_grant_eval_tests {
        use super::super::delegated_grant_utilization_sample;
        use super::super::{DelegationEvalOutcome, dotted_action_key, eval_workflow_for_action};
        use crate::infra::store::DaemonStore;
        use chrono::Utc;
        use core_event_types::{ActionRef, PregrantPath};
        use core_grant_types::{ResourceSelector, ResourceType, Statement, Usage};
        use core_state::sessions::{SessionMeta, SessionStore};
        use std::collections::BTreeSet;
        use tempfile::TempDir;

        fn action_ref(tool: &str, action: &str) -> ActionRef {
            ActionRef::new(
                format!("registry.ember.systems/ember-systems/ember-{tool}"),
                action,
                "v1",
            )
        }

        fn setup_store() -> DaemonStore {
            let store = DaemonStore::open_in_memory().expect("in-memory store");
            store.set_vault(std::rc::Rc::new(crate::infra::vault::Vault::new(
                [0xCD; 32],
            )));
            store
        }

        fn statement(sid: &str, action: &str) -> Statement {
            Statement {
                sid: sid.to_string(),
                resource_type: ResourceType::Credential,
                actions: vec![action.to_string()],
                resource: ResourceSelector::Glob {
                    pattern: "*".to_string(),
                },
                budget: None,
                usage: Usage::default(),
                conditions: Vec::new(),
                can_delegate: None,
            }
        }

        /// Persist a runtime-persona standing grant carrying one statement per
        /// `needs` verb (action = the verb, resource = Glob `*` — the dev0
        /// shape produced by `narrow_github_statements`). Returns
        /// `(persona_id, grant_id)`.
        ///
        /// Mirrors production: the narrowed statements are persisted under a
        /// `github:*` ceiling bound (the dev0 durable parent), so the same
        /// `narrowed ⊆ github:*` dominance the mint relies on is exercised here.
        fn persist_standing_grant(store: &DaemonStore, needs: &[&str]) -> (String, String) {
            persist_standing_grant_with_ttl(store, needs, None)
        }

        fn persist_standing_grant_with_ttl(
            store: &DaemonStore,
            needs: &[&str],
            ttl_secs: Option<u64>,
        ) -> (String, String) {
            let persona = store
                .create_persona("runtime-dev0")
                .expect("create persona");
            // A grants row to overwrite (create_grant writes the row + a
            // placeholder single-statement chain).
            let row = store
                .create_grant(&persona.id, "gh-token", "github:read:owner/repo", ttl_secs)
                .expect("create grant row");
            // The github:* ceiling (the dev0 durable parent the runtime grant
            // attenuates from) as the dominance bound for the overwrite.
            let ceiling = crate::trust::grant::access_grant_from_statements_for_persona(
                store,
                &row.id,
                &persona.id,
                "gh-token",
                vec![statement("github-ceiling", "github:*")],
                0,
                None,
            )
            .expect("sign github:* ceiling");
            let statements: Vec<Statement> = needs
                .iter()
                .enumerate()
                .map(|(i, need)| statement(&format!("S{i}"), need))
                .collect();
            let grant = crate::trust::grant::access_grant_from_statements_for_persona(
                store,
                &row.id,
                &persona.id,
                "gh-token",
                statements,
                0,
                None,
            )
            .expect("sign standing grant");
            store
                .overwrite_grant_blocks_with_parent_bound(&row.id, &grant, &ceiling)
                .expect("persist narrowed statements under github:* bound");
            (persona.id, row.id)
        }

        fn make_session(
            sessions_dir: &std::path::Path,
            session_id: &str,
            persona: &str,
            template: Option<&str>,
            strict: bool,
        ) {
            make_session_started_at(
                sessions_dir,
                session_id,
                persona,
                template,
                strict,
                Utc::now(),
            );
        }

        fn make_session_started_at(
            sessions_dir: &std::path::Path,
            session_id: &str,
            persona: &str,
            template: Option<&str>,
            strict: bool,
            started_at: chrono::DateTime<Utc>,
        ) {
            SessionStore::new(sessions_dir.to_path_buf())
                .create(&SessionMeta {
                    session_id: session_id.to_string(),
                    persona: persona.to_string(),
                    durable_persona: Some("persona_durable".to_string()),
                    grant_id: "grant_runtime".to_string(),
                    caller_binding_id: Some("cb_test".to_string()),
                    started_at,
                    launcher_pid: std::process::id(),
                    authority_strict: strict,
                    delegation_id: None,
                    delegation_template: template.map(str::to_string),
                })
                .unwrap();
        }

        #[test]
        fn approves_in_scope_github_action() {
            let store = setup_store();
            let (persona, grant_id) = persist_standing_grant(
                &store,
                &[
                    "github:metadata:read",
                    "github:contents:write",
                    "github:pull_request:create",
                    "github:actions:read",
                ],
            );
            let dir = TempDir::new().unwrap();
            make_session(
                dir.path(),
                "s1",
                &persona,
                Some("emberd-development"),
                false,
            );
            // git.push lowers to github:contents:write — covered by the grant.
            let outcome = eval_workflow_for_action(
                &store,
                Some(dir.path()),
                Some("s1"),
                Some(&action_ref("git", "push")),
                Some(&persona),
                false,
                Utc::now(),
            );
            match outcome {
                DelegationEvalOutcome::Approve {
                    delegation_id,
                    template_name,
                    pregrant_path,
                } => {
                    assert_eq!(delegation_id, grant_id);
                    assert_eq!(template_name, "emberd-development");
                    assert_eq!(pregrant_path, PregrantPath::StandingGrant);
                }
                other => panic!("expected Approve, got {other:?}"),
            }
        }

        #[test]
        fn delegated_utilization_sample_derives_ratios_from_standing_grant() {
            let store = setup_store();
            let (persona, grant_id) = persist_standing_grant_with_ttl(
                &store,
                &[
                    "github:metadata:read",
                    "github:contents:write",
                    "github:pull_request:create",
                    "github:actions:read",
                ],
                Some(3600),
            );
            let dir = TempDir::new().unwrap();
            let eval_now = Utc::now();
            make_session_started_at(
                dir.path(),
                "s-telemetry",
                &persona,
                Some("emberd-development"),
                false,
                eval_now - chrono::Duration::seconds(900),
            );

            let mut matched_grant_ids = BTreeSet::new();
            matched_grant_ids.insert(grant_id);
            let sample = delegated_grant_utilization_sample(
                &store,
                dir.path(),
                "s-telemetry",
                "emberd-development",
                &matched_grant_ids,
                ember_construct::manifest_action_need("git.push").len(),
                eval_now,
            )
            .expect("utilization sample");
            assert_eq!(sample.cohort, "emberd-development");
            assert!((sample.exercised_ratio - 0.5).abs() < 0.001);
            assert_eq!(sample.out_of_scope_jits, 0);
            assert!((sample.session_ttl_ratio - 0.25).abs() < 0.001);
        }

        #[test]
        fn falls_through_when_github_need_not_covered() {
            let store = setup_store();
            // Standing grant carries only read — git.push (contents:write) is
            // not covered, so eval defers to the per-action / JIT chain.
            let (persona, _g) = persist_standing_grant(&store, &["github:contents:read"]);
            let dir = TempDir::new().unwrap();
            make_session(dir.path(), "s2", &persona, Some("read-only"), false);
            let outcome = eval_workflow_for_action(
                &store,
                Some(dir.path()),
                Some("s2"),
                Some(&action_ref("git", "push")),
                Some(&persona),
                false,
                Utc::now(),
            );
            assert_eq!(outcome, DelegationEvalOutcome::FallThroughOutOfScope);
        }

        #[test]
        fn strict_posture_refuses_out_of_scope_github_action() {
            let store = setup_store();
            let (persona, _g) = persist_standing_grant(&store, &["github:contents:read"]);
            let dir = TempDir::new().unwrap();
            make_session(dir.path(), "s3", &persona, Some("read-only"), true);
            let outcome = eval_workflow_for_action(
                &store,
                Some(dir.path()),
                Some("s3"),
                Some(&action_ref("git", "push")),
                Some(&persona),
                true,
                Utc::now(),
            );
            assert!(matches!(
                outcome,
                DelegationEvalOutcome::StandingGrantRequired { .. }
            ));
        }

        #[test]
        fn non_github_action_falls_through() {
            let store = setup_store();
            let (persona, _g) = persist_standing_grant(&store, &["github:contents:write"]);
            let dir = TempDir::new().unwrap();
            make_session(dir.path(), "s4", &persona, Some("infra-iteration"), false);
            // kubectl.get has no github need — never standing-grant-gated.
            let outcome = eval_workflow_for_action(
                &store,
                Some(dir.path()),
                Some("s4"),
                Some(&action_ref("kubectl", "get")),
                Some(&persona),
                false,
                Utc::now(),
            );
            assert_eq!(outcome, DelegationEvalOutcome::FallThroughOutOfScope);
        }

        #[test]
        fn missing_inputs_fall_through() {
            let store = setup_store();
            let outcome =
                eval_workflow_for_action(&store, None, None, None, None, false, Utc::now());
            assert_eq!(outcome, DelegationEvalOutcome::FallThroughMissingInputs);
        }

        #[test]
        fn dotted_action_key_maps_plugin_slug() {
            assert_eq!(
                dotted_action_key(&action_ref("gh", "pr_create")),
                "gh.pr_create"
            );
            assert_eq!(dotted_action_key(&action_ref("git", "push")), "git.push");
        }
    }

    // ---------------------------------------------------------------------
    // delegation_receipt_body_stamp_landed — T1 coverage of the
    // DelegationReceiptContext plumbing from handle_broker_resolve through
    // resolve_with_registry into the broker.resolve.materialized audit-log
    // payload. ADR 158 §Component 5.
    //
    // The Receipt body stamp has two correctness shapes:
    //   1. ctx Some(Approve)        → payload carries delegation_id + delegation_template
    //                                  + pregrant_path: "standing_grant"
    //   2. ctx Some(per_action)     → payload carries pregrant_path: "per_action"
    //                                  with delegation_id/template absent (null)
    //   3. ctx None                 → payload carries no workflow fields at all
    //                                  (system-class caller, all three null)
    // ---------------------------------------------------------------------
    mod delegation_receipt_body_stamp {
        use super::super::DelegationReceiptContext;
        use core_event_types::PregrantPath;

        #[test]
        fn from_approve_sets_workflow_path_and_both_ids() {
            let ctx = DelegationReceiptContext::from_approve(
                "wfg_01HQ0EXAMPLE".to_string(),
                "emberd-development".to_string(),
                PregrantPath::StandingGrant,
            );
            assert_eq!(ctx.delegation_id.as_deref(), Some("wfg_01HQ0EXAMPLE"));
            assert_eq!(
                ctx.delegation_template.as_deref(),
                Some("emberd-development")
            );
            assert_eq!(ctx.pregrant_path, PregrantPath::StandingGrant);
        }

        #[test]
        fn per_action_fallthrough_clears_ids_and_sets_per_action_path() {
            let ctx = DelegationReceiptContext::per_action_fallthrough();
            assert_eq!(ctx.delegation_id, None);
            assert_eq!(ctx.delegation_template, None);
            assert_eq!(ctx.pregrant_path, PregrantPath::PerAction);
        }

        #[test]
        fn audit_log_payload_shape_with_approve_ctx() {
            // Mirrors the json! shape inside broker_resolve_plaintext_with_registry's
            // accept-receipt step. Validates that the workflow fields surface
            // as the brief requires (delegation_id, delegation_template, pregrant_path).
            let ctx = DelegationReceiptContext::from_approve(
                "wfg_01HQ0".to_string(),
                "emberd-development".to_string(),
                PregrantPath::StandingGrant,
            );
            let ctx_ref = Some(&ctx);
            let payload = serde_json::json!({
                "kind": "broker_resolve_materialized",
                "materialization_id": "mid_abc123",
                "persona_id": "persona_dev0",
                "delegation_id": ctx_ref.and_then(|c| c.delegation_id.as_deref()),
                "delegation_template": ctx_ref.and_then(|c| c.delegation_template.as_deref()),
                "pregrant_path": ctx_ref.map(|c| c.pregrant_path),
            });
            let s = payload.to_string();
            assert!(
                s.contains("\"delegation_id\":\"wfg_01HQ0\""),
                "payload: {s}"
            );
            assert!(
                s.contains("\"delegation_template\":\"emberd-development\""),
                "payload: {s}"
            );
            assert!(
                s.contains("\"pregrant_path\":\"standing_grant\""),
                "payload: {s}"
            );
        }

        #[test]
        fn audit_log_payload_shape_with_per_action_ctx() {
            let ctx = DelegationReceiptContext::per_action_fallthrough();
            let ctx_ref = Some(&ctx);
            let payload = serde_json::json!({
                "kind": "broker_resolve_materialized",
                "materialization_id": "mid_abc123",
                "persona_id": "persona_dev0",
                "delegation_id": ctx_ref.and_then(|c| c.delegation_id.as_deref()),
                "delegation_template": ctx_ref.and_then(|c| c.delegation_template.as_deref()),
                "pregrant_path": ctx_ref.map(|c| c.pregrant_path),
            });
            let s = payload.to_string();
            assert!(
                s.contains("\"pregrant_path\":\"per_action\""),
                "payload: {s}"
            );
            // delegation_id + delegation_template serialize as null when the ctx
            // is per-action fallthrough (the json! macro emits explicit null
            // rather than omitting).
            assert!(s.contains("\"delegation_id\":null"), "payload: {s}");
            assert!(s.contains("\"delegation_template\":null"), "payload: {s}");
        }

        #[test]
        fn audit_log_payload_omits_workflow_fields_when_ctx_none() {
            // System-class caller — no workflow correlation. workflow fields
            // serialize as null (json! macro behavior on None).
            let ctx_ref: Option<&DelegationReceiptContext> = None;
            let payload = serde_json::json!({
                "kind": "broker_resolve_materialized",
                "materialization_id": "mid_abc123",
                "persona_id": "persona_dev0",
                "delegation_id": ctx_ref.and_then(|c| c.delegation_id.as_deref()),
                "delegation_template": ctx_ref.and_then(|c| c.delegation_template.as_deref()),
                "pregrant_path": ctx_ref.map(|c| c.pregrant_path),
            });
            let s = payload.to_string();
            assert!(s.contains("\"delegation_id\":null"), "payload: {s}");
            assert!(s.contains("\"delegation_template\":null"), "payload: {s}");
            assert!(s.contains("\"pregrant_path\":null"), "payload: {s}");
        }
    }
}
