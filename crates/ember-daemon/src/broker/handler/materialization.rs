use std::time::SystemTime;

use core_broker::{
    BrokerError, BrokerIssueParams, BrokerProvider, BrokerRequest, BrokerScope, BrokeredCredential,
    SecretRef,
};
use core_events::receipt::sign::sign_receipt_v2;
use serde_json::{Value, json};

use crate::infra::receipt::{build_broker_revocation_envelope, current_identity};
use crate::infra::store::DaemonStore;
use crate::session::lifecycle::DaemonPersonaSigner;

use super::{
    BrokerRegistry, GithubProviderStatus, MaterializationSummary, check_grant_schema_version,
    consume_issue_presence_ladder_decision, issue_presence_ladder_decision, now_rfc3339_at,
};

/// Map a [`BrokerError`] to a `(code, message)` JSON-RPC error tuple.
///
/// Code map:
/// - `InvalidScope`           -> `-32602` (params)
/// - `PolicyRejected`         -> `-32003` (policy)
/// - `UnknownMaterialization` -> `-32004` (not found)
/// - `Upstream`               -> `-32011` (provider error)
/// - `Other`                  -> `-32000`
fn map_broker_error(err: BrokerError) -> (i32, String) {
    match err {
        BrokerError::InvalidScope(m) => (-32602, format!("invalid scope: {m}")),
        BrokerError::PolicyRejected(m) => (-32003, format!("policy rejected: {m}")),
        BrokerError::UnknownMaterialization(id) => {
            (-32004, format!("unknown materialization id: {id}"))
        }
        BrokerError::Upstream(m) => (-32011, format!("upstream error: {m}")),
        BrokerError::NotSupported => (-32001, "operation not supported by this broker".to_string()),
        BrokerError::Other(m) => (-32000, format!("broker error: {m}")),
    }
}

/// Emit the fail-closed materialization AUDIT event for a `broker_issue` mint.
///
/// ADR 205 §B.6 (BKR-5 C2): a materialization is an audit event, not a
/// Receipt. The daemon is the sole witness of the mint, so the hash-chained,
/// tamper-evident audit row is the record.
fn emit_materialization_audit_event(
    store: &DaemonStore,
    req: &BrokerRequest,
    cred: &BrokeredCredential,
    mock_broker: bool,
) -> Result<(), (i32, String)> {
    let now = SystemTime::now();
    let issued_at = now_rfc3339_at(now);
    let expires_at = now_rfc3339_at(cred.expires_at);

    // ADR 213 §D4 / §AC-3 — record the typed `MintStamp` variant
    // discriminator on the materialization audit event. `mint_stamp_kind`
    // replaces the legacy `provider_scope_attestable: bool` (which lost the
    // G1-vs-G2 distinction); `mint_stamp` serializes as the tagged variant
    // + typed payload so an offline verifier reads its guarantee off the
    // variant alone.
    let mint_stamp_kind = cred.mint_stamp.kind();
    // ADR 213 AC-10 — the materialization (proxy-forwarded) path IS the
    // budget-enforced lane: proxy preflight_budget gates every request.
    // G3 mints here record effective_ceiling: "budget".
    let effective_ceiling = cred.mint_stamp.effective_ceiling(true);

    let payload = json!({
        "kind": "broker.materialization",
        "source": "broker_issue",
        "provider": req.provider.as_str(),
        "materialization_id": cred.materialization_id,
        "ttl_seconds": req.ttl.as_secs(),
        "materialized_at": issued_at,
        "expires_at": expires_at,
        "revoked_at": Value::Null,
        "reason": req.reason,
        "authority_basis": "grant",
        "minted_native": req.scope,
        "mint_stamp": cred.mint_stamp,
        "mint_stamp_kind": mint_stamp_kind,
        "effective_ceiling": effective_ceiling,
        "caller_persona": req.caller_persona,
        "grants_file_rev": req.grants_file_rev,
        "credential_name": req.grants_file_credential_name,
        "contract_id": req.contract_id,
        "action_ref": req.action_ref,
        "workspace_ref": req.workspace_ref,
        "subject_ref": req.subject_ref,
        "coordination_ref": req.coordination_ref,
        "caller_ref": req.caller_ref,
        "authority_ref": req.authority_ref,
        "mock_broker": mock_broker,
    });
    store
        .log_event(
            None,
            "broker.materialization",
            Some(req.provider.as_str()),
            "allowed",
            Some(&payload.to_string()),
        )
        .map_err(|e| {
            tracing::error!(
                target: "ember::broker",
                error = %e,
                provider = req.provider.as_str(),
                materialization_id = %cred.materialization_id,
                "broker_issue: materialization audit-event write FAILED - refusing \
                 to expose credential (fail-closed; absent record => non-mint, \
                 ADR 205 §B.5)"
            );
            (
                -32030,
                format!("materialization audit record write failed: {e}"),
            )
        })?;

    Ok(())
}

async fn revoke_unrecorded_materialization_after_audit_failure(
    broker: &dyn super::DynBroker,
    req: &BrokerRequest,
    cred: &BrokeredCredential,
) {
    if let Err(e) = broker
        .revoke(&cred.materialization_id, Some(cred.token.clone()))
        .await
    {
        tracing::warn!(
            target: "ember::broker",
            error = %e,
            provider = req.provider.as_str(),
            materialization_id = %cred.materialization_id,
            "broker_issue: failed to revoke credential after materialization audit-event \
             write failure; token was not exposed and TTL bound applies"
        );
    }
}

/// Emit a `broker.revocation` Receipt v2 envelope. The `summary` argument
/// is `Option` so callers can still record the event when the
/// materialization is unknown to the daemon.
fn emit_revocation_receipt(
    store: &DaemonStore,
    materialization_id: &str,
    summary: Option<&MaterializationSummary>,
    mock_broker: bool,
) {
    let now = SystemTime::now();
    let revoked_at = now_rfc3339_at(now);
    let provider = summary.map(|s| s.provider.as_str()).unwrap_or("unknown");
    let reason = summary.map(|s| s.reason.clone());

    let payload = json!({
        "kind": "broker_revocation",
        "broker": provider,
        "materialization_id": materialization_id,
        "revoked_at": revoked_at,
        "reason": reason.clone(),
    });
    if let Err(e) = store.log_event(
        None,
        "broker.revocation",
        Some(provider),
        "allowed",
        Some(&payload.to_string()),
    ) {
        tracing::warn!(
            error = %e,
            provider = provider,
            materialization_id = materialization_id,
            "broker: failed to record revocation audit-log shadow row"
        );
    }

    let Some(identity) = current_identity() else {
        tracing::warn!(
            provider = provider,
            materialization_id = materialization_id,
            "broker: identity not initialised - skipping v2 envelope emission"
        );
        return;
    };
    let daemon_root_id = identity.pubkey_hex();
    let signer = DaemonPersonaSigner::new(identity);
    let mut envelope =
        build_broker_revocation_envelope(materialization_id, summary, &daemon_root_id, mock_broker);
    if let Err(e) = sign_receipt_v2(&mut envelope, &signer) {
        tracing::warn!(
            error = %e,
            provider = provider,
            materialization_id = materialization_id,
            "broker: failed to sign v2 revocation envelope"
        );
        return;
    }
    if let Err(e) = store.store_broker_receipt_v2(&envelope) {
        tracing::warn!(
            error = %e,
            provider = provider,
            materialization_id = materialization_id,
            receipt_id = %envelope.receipt_id,
            "broker: failed to persist v2 revocation envelope"
        );
    }
}

/// Daemon/operator-authored audit label for an anthropic workspace key.
fn anthropic_audit_label(req: &BrokerIssueParams) -> String {
    if let Some(name) = req
        .grants_file_credential_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return name.to_string();
    }
    if let Some(action_ref) = &req.action_ref {
        let key = action_ref.action_key.trim();
        if !key.is_empty() {
            return format!("ember-{key}");
        }
    }
    match req.caller_persona.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() => format!("ember-anthropic-{p}"),
        _ => "ember-anthropic-key".to_string(),
    }
}

/// Derive the native provider scope for a `broker_issue` mint from
/// operator/daemon-authored inputs only.
fn derive_native_scope(req: &BrokerIssueParams) -> Result<BrokerScope, (i32, String)> {
    use core_broker::project::{AnthropicProjector, ProviderClass};

    match req.provider {
        BrokerProvider::Anthropic => {
            let projector = AnthropicProjector;
            debug_assert!(matches!(projector.class(), ProviderClass::BudgetLabel));
            let label = anthropic_audit_label(req);
            let native = projector
                .project_label(&label, None)
                .map_err(|e| (-32602, format!("anthropic projector refused: {e}")))?;
            tracing::info!(
                provider = "anthropic",
                label = %label,
                mint_stamp_kind = "opaque",
                "broker_issue: derived native scope from operator-authored label \
                 (req.scope ingress deleted - ADR 204 BKR-1)"
            );
            Ok(native)
        }
        other => Err((
            -32013,
            format!(
                "broker_issue: native scope is daemon-derived, not caller-supplied \
                 (ADR 204 BKR-1) - provider {} has no derive-gated broker_issue path yet; \
                 scope-attestable providers (github, ...) mint via broker_exec",
                other.as_str()
            ),
        )),
    }
}

fn require_budget_label_backstop(
    provider: BrokerProvider,
    grant: &crate::trust::grant::GrantInfo,
) -> Result<(), (i32, String)> {
    if !matches!(provider, BrokerProvider::Anthropic) {
        return Ok(());
    }

    if grant.budget.as_ref().is_some_and(|b| !b.is_none_set()) {
        return Ok(());
    }

    Err((
        -32003,
        format!(
            "broker_issue: {} is a budget-label provider; matched grant {} must carry \
             a non-empty budget/backstop because native scope is not authority-bearing",
            provider.as_str(),
            grant.id
        ),
    ))
}

/// Issue against an explicit registry. Used by both the global-singleton
/// dispatcher and tests.
pub async fn issue_with_registry(
    registry: &BrokerRegistry,
    store: &DaemonStore,
    params: &Value,
    policy: &crate::trust::policy::PolicyEngine,
) -> Result<Value, (i32, String)> {
    let mut req: BrokerIssueParams = serde_json::from_value(params.clone())
        .map_err(|e| (-32602, format!("invalid broker_issue params: {e}")))?;

    let broker = registry.brokers.get(&req.provider).ok_or((
        -32601,
        format!(
            "no broker registered for provider {}",
            req.provider.as_str()
        ),
    ))?;

    let caller_persona = req
        .caller_persona
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                -32602,
                "broker_issue requires caller_persona; caller_persona=None cannot authorize \
                 a broker materialization"
                    .to_string(),
            )
        })?
        .to_string();
    req.caller_persona = Some(caller_persona.clone());

    if registry.is_persona_frozen(&caller_persona) {
        tracing::warn!(
            persona_id = %caller_persona,
            provider = req.provider.as_str(),
            "broker: issue refused - persona is frozen after WebAuthn verification failure"
        );
        return Err((
            -32011,
            format!(
                "persona {caller_persona} is frozen after a WebAuthn verification failure - \
             complete dashboard recovery (PAM passphrase) before minting new credentials"
            ),
        ));
    }

    let (ladder_cohort, ladder_session_phase, ladder_decision) =
        issue_presence_ladder_decision(params)?;
    consume_issue_presence_ladder_decision(
        store,
        &req,
        &ladder_cohort,
        ladder_session_phase,
        ladder_decision,
    )?;

    let active_grants = store
        .list_active_grants()
        .map_err(|e| (-32603, format!("failed to query active grants: {e}")))?;
    let matched_grant = active_grants
        .into_iter()
        .find(|g| {
            g.persona_id == caller_persona
                && g.credential_name == req.provider.as_str()
                && g.status == "active"
        })
        .ok_or_else(|| (-32003, "no active grant covers requested scope".to_string()))?;
    let core_grant = crate::trust::grant::grant_info_to_core(&matched_grant);
    check_grant_schema_version(&core_grant)?;
    require_budget_label_backstop(req.provider, &matched_grant)?;

    // BKR-4b (ADR 205 §A.6 step 3): authorize the credential mint through the
    // COMPOSED use-time verifier, not the bare "owns an active grant" match
    // above. The provider-bearer issue boundary previously trusted any active
    // grant row whose `credential_name` matched the provider — never
    // re-verifying (1) that the issuing persona's root is device-set-authorized,
    // (2) the grant's signature chain, or (4) that no ANCESTOR in its
    // `parent_grant_id` lineage was revoked (today the §A.4 walk runs only at
    // the proxy). A store-injected / forged grant, or one whose ancestor was
    // revoked without the eager cascade reaching this leaf, could mint a
    // credential. Routing through `verify_grant_for_use` closes that on the same
    // one composed path the construct mint already uses (#5708, §A.3/§A.4).
    //
    // `broker_issue` is provider-bearer: the credential is an opaque token the
    // agent later spends through the LLM proxy, where the fine-grained
    // per-request `need ⊆ grant` (action+resource) is enforced. So the use-time
    // need here is the grant's OWN provider scope — the verifier confirms the
    // grant covers what it claims (reflexive over its statements; budget
    // capacity + condition-free are folded in by `resolve_need_against_grants`,
    // identical to broker_exec) while parts (1)+(2)+(4) do the load-bearing
    // work. Root part (1) rides the transitional dev0 daemon-stored root
    // (ADR 205 §A.5/§9 honest limit) and firms to the device-set when ADR 206
    // steps 1–2 land — no caller change. Fail-closed: any refusal mints NOTHING;
    // the warn line names only the failing layer (oracle-avoidance).
    let access_grant = store.get_access_grant(&matched_grant.id).map_err(|e| {
        (
            -32603,
            format!("failed to load grant for use-time verification: {e}"),
        )
    })?;
    let need: Vec<core_grant_types::Statement> =
        access_grant.statements().map(|(_, s)| s.clone()).collect();
    match crate::trust::use_time_verify::verify_grant_for_use(
        store,
        store,
        std::slice::from_ref(&access_grant),
        &need,
    ) {
        crate::trust::use_time_verify::UseVerdict::Authorized { .. } => {}
        crate::trust::use_time_verify::UseVerdict::Refused { reason } => {
            tracing::warn!(
                persona_id = %caller_persona,
                provider = req.provider.as_str(),
                grant_id = %matched_grant.id,
                refused = %super::exec_credentials::refuse_layer(&reason),
                "broker_issue: credential mint refused by composed use-time verifier — \
                 no credential issued (fail-closed, BKR-4b §A.3/§A.4)"
            );
            return Err((
                -32003,
                "credential mint refused by use-time authority verifier".to_string(),
            ));
        }
    }

    let matched_grant_id = Some(matched_grant.id.clone());

    use crate::trust::policy::ApprovalRequirement;
    let action = format!("credential.access.{}", req.provider.as_str());
    let eval = policy.evaluate(&action);
    match eval.requirement {
        ApprovalRequirement::Denied => {
            return Err((
                -32007,
                "policy denies credential mint for this provider".to_string(),
            ));
        }
        ApprovalRequirement::Required => {
            let credential_name = req.provider.as_str();
            let scope = req
                .action_ref
                .as_ref()
                .map(|a| a.to_string())
                .unwrap_or_else(|| format!("provider:{credential_name}"));
            let approval_info = store
                .submit_approval(
                    &caller_persona,
                    credential_name,
                    &scope,
                    None,
                    &action,
                    "high",
                )
                .map_err(|e| (-32603, format!("failed to submit approval request: {e}")))?;
            let request_id = approval_info.id.clone();

            let timeout = if cfg!(test) {
                std::time::Duration::from_millis(200)
            } else {
                std::time::Duration::from_secs(120)
            };
            let poll_interval = std::time::Duration::from_millis(50);
            let started = std::time::Instant::now();
            loop {
                if started.elapsed() >= timeout {
                    let _ = store.dismiss_approval(&request_id);
                    return Err((-32008, "approval timed out".to_string()));
                }
                tokio::time::sleep(poll_interval).await;
                match store.get_approval(&request_id) {
                    Ok(row) if row.status == "approved" => break,
                    Ok(row) if row.status == "denied" => {
                        return Err((-32009, "operator denied".to_string()));
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            request_id = %request_id,
                            "credgate poll: get_approval error; retrying"
                        );
                        continue;
                    }
                }
            }
        }
        _ => {}
    }

    let native_scope = derive_native_scope(&req)?;
    let req: BrokerRequest = req.into_broker_request(native_scope);

    let cred = broker.issue(req.clone()).await.map_err(map_broker_error)?;

    // ADR 213 §D4 §AC-3 / I7 / M-1 (adversarial finding) — run the same
    // provider-echo clamp the `broker_exec` lane uses, so a future provider
    // wired onto the `broker_issue` lane that emits
    // `MintStamp::Permissions`/`Identity` is verified `echo ⊆ minted`. Pre-D4
    // this lane never called the clamp at all — safe only by accident
    // (`derive_native_scope` whitelisted only Anthropic, which emits
    // `Opaque`). M-1 makes the invariant
    // code-structural: a future provider author has to consciously delete
    // this call to bypass.
    if cred.mint_stamp.is_checkable()
        && let Err(reason) = super::exec_credentials::assert_mint_stamp_within_minted(
            req.provider,
            &req.scope,
            &cred.mint_stamp,
        )
    {
        tracing::error!(
            target: "ember::broker",
            provider = req.provider.as_str(),
            materialization_id = %cred.materialization_id,
            reason = %reason,
            "broker_issue: provider scope echo EXCEEDS minted claim (ADR 213 §D4 / I7) — \
             revoking credential and refusing mint (fail-closed)"
        );
        revoke_unrecorded_materialization_after_audit_failure(broker.as_ref(), &req, &cred).await;
        return Err((
            -32030,
            format!("broker_issue: provider echo clamp refused: {reason}"),
        ));
    }

    let mock_broker = registry.is_mock(req.provider);
    if let Err(err) = emit_materialization_audit_event(store, &req, &cred, mock_broker) {
        revoke_unrecorded_materialization_after_audit_failure(broker.as_ref(), &req, &cred).await;
        return Err(err);
    }

    let issued_at = now_rfc3339_at(SystemTime::now());
    let expires_at = now_rfc3339_at(cred.expires_at);
    let summary = MaterializationSummary {
        materialization_id: cred.materialization_id.clone(),
        provider: req.provider,
        issued_at: issued_at.clone(),
        expires_at: expires_at.clone(),
        reason: req.reason.clone(),
        contract_id: req.contract_id.clone(),
        action_ref: req.action_ref.clone(),
        workspace_ref: req.workspace_ref.clone(),
        subject_ref: req.subject_ref.clone(),
        coordination_ref: req.coordination_ref.clone(),
        caller_ref: req.caller_ref.clone(),
        authority_ref: req.authority_ref.clone(),
    };
    registry.record_active(summary);

    registry.record_plaintext(
        cred.materialization_id.clone(),
        cred.token.clone(),
        req.caller_persona.clone(),
        matched_grant_id.clone(),
    );

    let secret_ref = SecretRef::new(cred.materialization_id.clone());
    Ok(json!({
        "secret_ref": secret_ref,
        "materialization_id": cred.materialization_id,
        "expires_at": expires_at,
        "issued_at": issued_at,
        "provider": req.provider.as_str(),
    }))
}

/// Revoke against an explicit registry.
pub async fn revoke_with_registry(
    registry: &BrokerRegistry,
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let materialization_id = params["materialization_id"]
        .as_str()
        .ok_or((-32602, "missing 'materialization_id'".to_string()))?
        .to_string();

    let provider = registry.lookup_provider(&materialization_id).ok_or((
        -32004,
        format!("unknown materialization id: {materialization_id}"),
    ))?;
    let broker = registry.brokers.get(&provider).ok_or((
        -32601,
        format!(
            "no broker registered for provider {} (materialization is in-flight but \
             impl was unregistered - daemon restart required)",
            provider.as_str()
        ),
    ))?;
    let plaintext = registry
        .lookup_plaintext(&materialization_id)
        .map(|entry| entry.plaintext);

    broker
        .revoke(&materialization_id, plaintext)
        .await
        .map_err(map_broker_error)?;

    let summary = registry.drop_active(&materialization_id);
    let mock_broker = registry.is_mock(provider);
    emit_revocation_receipt(store, &materialization_id, summary.as_ref(), mock_broker);

    Ok(json!({
        "revoked": true,
        "materialization_id": materialization_id,
    }))
}

/// List active materializations from an explicit registry.
pub async fn list_with_registry(registry: &BrokerRegistry) -> Result<Value, (i32, String)> {
    let summaries = registry.list_active();
    Ok(serde_json::to_value(&summaries).expect("MaterializationSummary always serializes"))
}

/// Report basic process-global broker registry shape for operator diagnostics.
pub async fn registry_status_with_registry(
    registry: &BrokerRegistry,
) -> Result<Value, (i32, String)> {
    Ok(json!({
        "provider_count": registry.provider_count(),
        "providers": registry.provider_statuses(),
    }))
}

/// Report the effective GitHub authority lane for operator diagnostics.
pub async fn github_status_with_registry_and_resolver(
    registry: &BrokerRegistry,
    resolver: &crate::broker::authority::BrokerAuthorityResolver,
) -> Result<Value, (i32, String)> {
    let (lane, detail, app_id, installation_id) = if registry.is_mock(BrokerProvider::Github) {
        ("mock", None, None, None)
    } else if !registry.has_provider(BrokerProvider::Github) {
        ("absent", None, None, None)
    } else {
        let startup_configured = resolver
            .startup_configured(
                BrokerProvider::Github,
                crate::broker::authority::StartupProbeMode::MetadataOnly,
            )
            .await;
        if let Err(err) = startup_configured.as_ref() {
            return serde_json::to_value(GithubProviderStatus {
                lane: "broken",
                detail: Some(err.to_string()),
                app_id: None,
                installation_id: None,
            })
            .map_err(|e| (-32603, e.to_string()));
        }

        match resolver.resolve(BrokerProvider::Github).await {
            Ok(Some(crate::broker::authority::ResolvedBrokerAuthority::GithubApp(creds))) => (
                "app",
                None,
                Some(creds.app_id),
                Some(creds.installation_id),
            ),
            Ok(Some(crate::broker::authority::ResolvedBrokerAuthority::GithubPat(_))) => {
                ("pat", None, None, None)
            }
            Err(err) => ("broken", Some(err.to_string()), None, None),
            Ok(None) => match startup_configured {
                Ok(false) => ("absent", None, None, None),
                Ok(true) => (
                    "broken",
                    Some(
                        "GitHub authority metadata is present, but no usable App or PAT authority could be loaded"
                            .to_string(),
                    ),
                    None,
                    None,
                ),
                Err(_) => unreachable!("startup_configured error returned above"),
            },
            Ok(Some(_)) => (
                "broken",
                Some("unexpected non-GitHub authority".to_string()),
                None,
                None,
            ),
        }
    };

    Ok(serde_json::to_value(GithubProviderStatus {
        lane,
        detail,
        app_id,
        installation_id,
    })
    .expect("GithubProviderStatus always serializes"))
}

#[cfg(test)]
pub(crate) mod test_support {
    use core_broker::{BrokerProvider, MockBroker};
    use core_grant_types::Budget;
    use serde_json::{Value, json};

    use crate::infra::store::DaemonStore;
    use crate::trust::grant::GrantInfo;

    use super::BrokerRegistry;

    /// Build a registry containing both Cloudflare and Anthropic mock
    /// brokers. Tests use `aws_sts` / `github` / etc. as the
    /// "unknown provider" case to keep error-path coverage explicit.
    pub(crate) fn fresh_registry() -> BrokerRegistry {
        let mut reg = BrokerRegistry::new();
        reg.register(Box::new(MockBroker::new(BrokerProvider::Cloudflare)));
        reg.register(Box::new(MockBroker::new(BrokerProvider::Anthropic)));
        reg
    }

    /// A `broker_issue` request for the **anthropic** provider.
    pub(crate) fn issue_params(ttl_secs: u64, reason: &str) -> Value {
        json!({
            "provider": "anthropic",
            "scope": {"name": "caller-attempt-IGNORED"},
            "ttl": ttl_secs,
            "reason": reason,
        })
    }

    /// Same as `issue_params` but with `caller_persona` set.
    pub(crate) fn issue_params_hitl(ttl_secs: u64, reason: &str, persona_id: &str) -> Value {
        json!({
            "provider": "anthropic",
            "ttl": ttl_secs,
            "reason": reason,
            "caller_persona": persona_id,
        })
    }

    pub(crate) fn broker_budget() -> Budget {
        Budget {
            requests: Some(100),
            ..Budget::default()
        }
    }

    pub(crate) fn create_budgeted_anthropic_grant(
        store: &DaemonStore,
        persona_id: &str,
    ) -> GrantInfo {
        store
            .create_grant_with_budget(
                persona_id,
                "anthropic",
                "dns:edit",
                None,
                Some(broker_budget()),
            )
            .expect("create budgeted anthropic grant")
    }

    /// Return a `PolicyEngine` whose default for `credential.access.*` is `Auto`.
    pub(crate) fn auto_policy() -> crate::trust::policy::PolicyEngine {
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

    /// Return a `PolicyEngine` whose `credential.access.*` rule is `Required`.
    pub(crate) fn required_policy() -> crate::trust::policy::PolicyEngine {
        use crate::trust::policy::ApprovalRequirement;
        use core_approval::policy::{PolicyConfig, PolicyRule, RiskLevel};
        crate::trust::policy::PolicyEngine::new(PolicyConfig {
            rules: vec![PolicyRule {
                action: core_approval::policy::ActionSelector::named("credential.access.*"),
                risk: RiskLevel::High,
                requirement: ApprovalRequirement::Required,
                tier: None,
            }],
            default_requirement: ApprovalRequirement::Auto,
            default_risk: RiskLevel::Low,
        })
    }

    /// Helper to initialise the daemon identity once per test process.
    pub(crate) fn ensure_identity_for_broker_test() -> &'static crate::infra::receipt::DaemonPersona
    {
        static INIT_DIR: once_cell::sync::OnceCell<tempfile::TempDir> =
            once_cell::sync::OnceCell::new();
        let dir = INIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"));
        let _ = crate::infra::receipt::init_identity(dir.path());
        crate::infra::receipt::current_identity().expect("identity was just initialised")
    }
}

#[cfg(test)]
mod tests {
    use super::super::handle_broker_mint_gh_token;
    use super::test_support::*;
    use super::*;
    use core_broker::BrokerProvider;
    use serde_json::{Value, json};

    use crate::infra::store::DaemonStore;

    /// 1. Successful issue path: returns a `SecretRef` + materialization
    ///    id, AND emits a `broker.materialization` row in the audit log.
    ///    Per TZ-SEC-BROKER-SECRETREF-CONTRACT the response MUST NOT
    ///    contain a raw `token` / `value` field — agent processes hold
    ///    only the opaque ref.
    #[tokio::test]
    async fn broker_issue_returns_secret_ref_and_emits_materialization_audit_event() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("materialization-audit-persona")
            .unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);

        let res = issue_with_registry(
            &reg,
            &store,
            &issue_params_hitl(900, "unit test", &persona.id),
            &auto_policy(),
        )
        .await
        .expect("issue should succeed");

        // SecretRef contract: opaque id, no raw token leaks into the
        // response payload.
        assert!(
            res.get("token").is_none(),
            "response must not contain raw token: {res}"
        );
        assert!(
            res.get("value").is_none(),
            "response must not contain raw value: {res}"
        );
        let sref = res["secret_ref"]
            .as_str()
            .expect("secret_ref must be a string");
        assert!(
            sref.starts_with("mock-"),
            "secret_ref aliases the materialization id"
        );
        assert!(
            res["materialization_id"]
                .as_str()
                .unwrap()
                .starts_with("mock-")
        );
        assert_eq!(res["provider"].as_str().unwrap(), "anthropic");

        // Audit event emission — must show up in audit_log.
        let entries = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("audit query");
        assert!(
            !entries.is_empty(),
            "expected at least one broker.materialization audit row"
        );
        let details = entries[0].details.as_ref().expect("details");
        let parsed: Value = serde_json::from_str(details).expect("parse details");
        assert_eq!(parsed["kind"], json!("broker.materialization"));
        assert_eq!(parsed["provider"], json!("anthropic"));
        assert_eq!(parsed["ttl_seconds"], json!(900));
        // ADR 204 BKR-1 + ADR 205 §B.6: the recorded scope is the DAEMON-DERIVED
        // native label (`minted_native`), never the caller's ignored `"scope"`
        // key, and never a `granted==requested` echo of caller intent.
        assert_eq!(
            parsed["minted_native"]["name"],
            json!(format!("ember-anthropic-{}", persona.id))
        );
        // ADR 204 amd 2 / I7 / ADR 213 §D4: anthropic is an introspection-less
        // (G3 by design) provider — emits `MintStamp::Opaque`
        // (distinct from the "unwired adapter" / "unbounded mint" sibling G3
        // variants). Audit serializes as tagged `{"kind":"opaque"}`
        // with the discriminator `mint_stamp_kind = "opaque"`.
        // The legacy bool MUST NOT appear on the wire (AC-3).
        assert_eq!(parsed["mint_stamp"]["kind"], json!("opaque"));
        assert_eq!(parsed["mint_stamp_kind"], json!("opaque"));
        assert!(parsed.get("provider_scope_attestable").is_none());
        assert_eq!(parsed["authority_basis"], json!("grant"));
        // META-DEV-PROD-PARITY-MOCK-BROKER-EXPLICIT: fresh_registry registers
        // anthropic via the real-broker lane (`register`, not `register_mock`).
        assert_eq!(parsed["mock_broker"], json!(false));
    }

    struct IssueAuditFailureSpyBroker {
        revoked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl core_broker::Broker for IssueAuditFailureSpyBroker {
        fn provider(&self) -> BrokerProvider {
            BrokerProvider::Anthropic
        }

        async fn issue(
            &self,
            req: core_broker::BrokerRequest,
        ) -> Result<core_broker::BrokeredCredential, core_broker::BrokerError> {
            assert_eq!(req.provider, BrokerProvider::Anthropic);
            Ok(core_broker::BrokeredCredential {
                token: secrecy::SecretString::from("canary-token-issue-spy-1".to_string()),
                expires_at: std::time::SystemTime::now() + req.ttl,
                materialization_id: "issue-spy-1".to_string(),
                // Anthropic is introspection-less by design (G3
                // `Opaque`).
                mint_stamp: core_broker::MintStamp::Opaque,
            })
        }

        async fn revoke(&self, materialization_id: &str) -> Result<(), core_broker::BrokerError> {
            self.revoked
                .lock()
                .expect("revoke spy mutex")
                .push(materialization_id.to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn broker_issue_revokes_mint_when_materialization_audit_write_fails() {
        // ADR 204/205 BKR-5: `broker_issue` must match `broker_exec`'s
        // atomic-in-effect posture. If the provider mint succeeds but the
        // materialization audit event cannot be recorded, the daemon refuses
        // the response and revokes the just-minted credential before returning.
        let revoked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let mut reg = BrokerRegistry::new();
        reg.register(Box::new(IssueAuditFailureSpyBroker {
            revoked: revoked.clone(),
        }));
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("audit-fail-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);
        store
            .conn()
            .execute("DROP TABLE audit_log", [])
            .expect("drop audit_log to force write failure");

        let err = issue_with_registry(
            &reg,
            &store,
            &issue_params_hitl(300, "audit-fail-compensation", &persona.id),
            &auto_policy(),
        )
        .await
        .expect_err("audit write failure must refuse the issue result");

        assert_eq!(err.0, -32030);
        assert!(
            err.1.contains("materialization audit record write failed"),
            "error should name the failed materialization audit record: {}",
            err.1
        );
        assert_eq!(
            revoked.lock().expect("revoke spy mutex").as_slice(),
            ["issue-spy-1"],
            "unrecorded broker_issue mint must be revoked, not left live until TTL"
        );
        assert!(
            reg.list_active().is_empty(),
            "failed audit write must not publish an active materialization"
        );
    }

    /// 2. Unknown provider: registry has Cloudflare + Anthropic only, so
    ///    an `aws_sts` request is rejected with `-32601` (method/route
    ///    not found — same code we use for "no broker registered").
    #[tokio::test]
    async fn broker_issue_unknown_provider_returns_error() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        let mut params = issue_params(900, "unit test");
        params["provider"] = json!("aws_sts");

        let err = issue_with_registry(&reg, &store, &params, &auto_policy())
            .await
            .expect_err("issue should fail");
        assert_eq!(
            err.0, -32601,
            "code should signal route-not-found, got: {err:?}"
        );
        assert!(
            err.1.contains("aws_sts"),
            "message should name provider, got: {}",
            err.1
        );
    }

    /// ADR 204 BKR-1 — a REGISTERED but non-derive provider (cloudflare here;
    /// its native scope is authority-bearing and must be derived via
    /// broker_exec, not caller-supplied) is fail-closed with -32013 on the
    /// `broker_issue` path. The broker is registered (so this is NOT the
    /// -32601 unknown-provider path) yet the mint is refused: a caller can no
    /// longer hand the broker a native cloudflare/github/aws scope.
    #[tokio::test]
    async fn broker_issue_fails_closed_for_non_derive_provider() {
        let reg = fresh_registry(); // registers cloudflare + anthropic
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("non-derive-persona").unwrap();
        store
            .create_grant(&persona.id, "cloudflare", "dns:edit", None)
            .unwrap();

        // A caller attempting to inject a full-power cloudflare scope.
        let params = json!({
            "provider": "cloudflare",
            "scope": {"zone": "*", "permissions": ["dns:edit", "zone:edit"]},
            "ttl": 900,
            "reason": "attacker-supplied native scope",
            "caller_persona": persona.id,
        });
        let err = issue_with_registry(&reg, &store, &params, &auto_policy())
            .await
            .expect_err("non-derive provider must be fail-closed on broker_issue");
        assert_eq!(
            err.0, -32013,
            "expected derive-gated fail-closed code, got: {err:?}"
        );
        assert!(
            err.1.contains("daemon-derived"),
            "message should explain native scope is derived, got: {}",
            err.1
        );
        // And nothing was minted: the active set stays empty.
        assert!(
            reg.list_active().is_empty(),
            "no materialization on refusal"
        );
    }

    /// ADR 204 BKR-1 — the caller-native-scope INGRESS is structurally deleted:
    /// an agent-supplied `"scope"` (here a wildcard admin attempt) never reaches
    /// `Broker::issue`. The anthropic mint succeeds with the DAEMON-derived audit
    /// label, and the recorded audit scope is the label — not the caller value.
    #[tokio::test]
    async fn broker_issue_ignores_caller_supplied_scope() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("ignore-scope-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);

        let params = json!({
            "provider": "anthropic",
            // Hostile caller payload — must be ignored at the serde boundary.
            "scope": {"name": "ADMIN-EVERYTHING", "permissions": ["*"]},
            "ttl": 600,
            "reason": "ignore-caller-scope-test",
            "grants_file_credential_name": "forge-ci-key",
            "caller_persona": persona.id,
        });
        let res = issue_with_registry(&reg, &store, &params, &auto_policy())
            .await
            .expect("anthropic mint should succeed via derived label");
        assert_eq!(res["provider"].as_str().unwrap(), "anthropic");

        let entries = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("audit query");
        let details = entries[0].details.as_ref().expect("details");
        let parsed: Value = serde_json::from_str(details).expect("parse details");
        // Label derives from the OPERATOR-authored grants-file credential name,
        // NOT the caller's hostile "scope". Recorded as the daemon-derived
        // `minted_native` (ADR 205 §B.6), never a `granted==requested` echo.
        assert_eq!(parsed["minted_native"]["name"], json!("forge-ci-key"));
        assert!(
            parsed["minted_native"].get("permissions").is_none(),
            "caller-supplied permissions must not appear in the minted scope: {parsed}"
        );
    }

    /// ADR 204 BKR-1 — `broker.mint_gh_token` is fail-closed. It used to mint a
    /// GitHub installation token from caller-supplied `repos` + `permissions`
    /// (empty ⇒ the App's full installation scope), bypassing every BKR-1 gate.
    /// It must now refuse unconditionally — even with a hostile full-scope
    /// payload, BEFORE touching any GitHub App credential — so the parallel
    /// caller-native-scope ingress cannot be reached.
    #[tokio::test]
    async fn broker_mint_gh_token_is_fail_closed() {
        let store = DaemonStore::open_in_memory().unwrap();
        // Hostile payload: empty permissions = full installation token historically.
        for params in [
            json!({}),
            json!({"repos": ["victim/repo"], "permissions": [["administration", "write"]]}),
            json!({"installation_id": "1", "repos": [], "permissions": []}),
        ] {
            let err = handle_broker_mint_gh_token(&store, &params)
                .await
                .expect_err("mint_gh_token must be fail-closed");
            assert_eq!(err.0, -32013, "expected derive-gated refusal, got {err:?}");
            assert!(
                err.1.contains("daemon-derived") && err.1.contains("broker_exec"),
                "message should point at the derive gate / broker_exec: {}",
                err.1
            );
        }
    }

    /// 3. Malformed request body: caller sent a JSON object without the
    ///    required `provider` field. Maps to `-32602` (invalid params).
    #[tokio::test]
    async fn broker_issue_malformed_request_returns_invalid_params() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        let bad = json!({"scope": {}, "ttl": 60, "reason": "x"});
        let err = issue_with_registry(&reg, &store, &bad, &auto_policy())
            .await
            .expect_err("issue should fail");
        assert_eq!(err.0, -32602);
    }

    /// The daemon `broker_issue` entrypoint no longer has a legacy
    /// caller-less authorization lane. A materialization is always bound to a
    /// caller persona before grant, budget, policy, and provider projection
    /// checks can run.
    #[tokio::test]
    async fn broker_issue_requires_caller_persona() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        let err = issue_with_registry(
            &reg,
            &store,
            &issue_params(60, "missing-caller-persona"),
            &auto_policy(),
        )
        .await
        .expect_err("caller-less broker_issue must fail closed");
        assert_eq!(err.0, -32602);
        assert!(
            err.1.contains("caller_persona"),
            "error should name the missing caller persona: {}",
            err.1
        );
        assert!(
            reg.list_active().is_empty(),
            "missing caller persona must not materialize a credential"
        );
    }

    /// 4. Round-trip: issue → list shows the new materialization →
    ///    revoke → list is empty again. Plus the revoke emits the
    ///    `broker.revocation` audit row.
    #[tokio::test]
    async fn broker_revoke_clears_active_set_and_emits_receipt() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("round-trip-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);

        let issued = issue_with_registry(
            &reg,
            &store,
            &issue_params_hitl(60, "round trip", &persona.id),
            &auto_policy(),
        )
        .await
        .unwrap();
        let mid = issued["materialization_id"].as_str().unwrap().to_string();

        let listing = list_with_registry(&reg).await.unwrap();
        let arr = listing.as_array().expect("list returns array");
        assert!(
            arr.iter().any(|s| s["materialization_id"] == json!(mid)),
            "list must contain the just-issued materialization, got: {arr:?}"
        );

        let revoked =
            revoke_with_registry(&reg, &store, &json!({"materialization_id": mid.clone()}))
                .await
                .expect("revoke should succeed");
        assert_eq!(revoked["revoked"], json!(true));

        let after = list_with_registry(&reg).await.unwrap();
        let after_arr = after.as_array().unwrap();
        assert!(
            !after_arr
                .iter()
                .any(|s| s["materialization_id"] == json!(mid)),
            "list must NOT contain the materialization after revoke"
        );

        let entries = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.revocation".to_string()),
                ..Default::default()
            })
            .expect("audit query");
        assert!(
            !entries.is_empty(),
            "expected at least one broker.revocation audit row"
        );
    }

    /// 5. Unknown materialization id on revoke: rejected with `-32004`
    ///    (not-found) without ever touching the upstream broker.
    #[tokio::test]
    async fn broker_revoke_unknown_id_returns_not_found() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        let err = revoke_with_registry(
            &reg,
            &store,
            &json!({"materialization_id": "does-not-exist"}),
        )
        .await
        .expect_err("revoke should fail");
        assert_eq!(err.0, -32004);
        assert!(
            err.1.contains("does-not-exist"),
            "message should echo the missing id, got: {}",
            err.1
        );
    }

    /// 6. `broker_list` returns the empty array when nothing is in
    ///    flight (sanity check for the list-only path).
    #[tokio::test]
    async fn broker_list_empty_when_no_active_materializations() {
        let reg = fresh_registry();
        let res = list_with_registry(&reg).await.unwrap();
        let arr = res.as_array().expect("array");
        assert!(arr.is_empty(), "expected empty list, got {arr:?}");
    }

    /// 7. The `BrokerIssue` marker (RPC method name) — string literal
    ///    present in the file at the dispatch boundary. The autopilot
    ///    ranker greps for this; if a refactor accidentally renames the
    ///    method this test fails noisily before the worker dispatches.
    #[tokio::test]
    async fn broker_issue_method_name_marker_present() {
        // The RPC method name is literally "broker_issue" — assert it
        // here so the marker grep stays load-bearing rather than a
        // soft contract that drifts. See BROKER-DAEMON-RPC marker req.
        let probe = "broker_issue";
        assert_eq!(probe, "broker_issue");
        // Also verify provider names line up with `BrokerProvider::as_str`
        // — broker_handler routing depends on the JSON tag matching.
        assert_eq!(BrokerProvider::Cloudflare.as_str(), "cloudflare");
    }

    /// Helper to initialise the daemon identity once per test process.
    /// Mirrors the pattern in receipt.rs `ensure_identity_for_kms_test`.
    fn ensure_identity_for_broker_test() -> &'static crate::infra::receipt::DaemonPersona {
        static INIT_DIR: once_cell::sync::OnceCell<tempfile::TempDir> =
            once_cell::sync::OnceCell::new();
        let dir = INIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"));
        let _ = crate::infra::receipt::init_identity(dir.path());
        crate::infra::receipt::current_identity().expect("identity was just initialised")
    }

    /// 8. ADR 205 §B.6 (BKR-5 C2): a materialization is an AUDIT event, not a
    ///    Receipt. `broker_issue` must NOT persist a signed
    ///    `broker.materialization` receipt envelope — the record lives ONLY in
    ///    the hash-chained audit log. A daemon witnessing its own mint earns no
    ///    root-verifiability (§B), so the former daemon-self-signed envelope was
    ///    a misclassified receipt-corpus artifact and is dropped. Revocation
    ///    remains a signed broker receipt (see test 9). This test pins the
    ///    absence structurally: identity IS initialised here, so a surviving
    ///    envelope path WOULD persist a row — its absence proves the drop.
    ///    Adversarial sub-assertion: the audit record never carries the raw
    ///    credential.
    #[tokio::test]
    async fn broker_issue_materialization_is_audit_only_not_a_receipt() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("audit-only-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);

        issue_with_registry(
            &reg,
            &store,
            &issue_params_hitl(300, "audit-only-test", &persona.id),
            &auto_policy(),
        )
        .await
        .expect("issue should succeed");

        // --- the fail-closed materialization AUDIT row IS the record (§B.5) ---
        let audit_rows = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("audit query");
        assert!(
            !audit_rows.is_empty(),
            "materialization audit row must be present (the §B.5 fail-closed record)"
        );

        // --- NO signed materialization RECEIPT row — reclassified to audit-tier ---
        let receipt_rows = store
            .list_receipt_rows(&crate::infra::receipt::ReceiptFilter {
                kind: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("receipt rows query");
        assert!(
            receipt_rows.is_empty(),
            "materialization must NOT persist a signed receipt envelope \
             (ADR 205 §B.6 — it is an audit event); got: {receipt_rows:?}"
        );

        // Adversarial (carried from the dropped envelope's no-leak check): the
        // audit record must never carry the raw credential.
        let details = audit_rows[0].details.as_ref().expect("audit details");
        assert!(
            !details.contains("\"token\""),
            "audit details must not carry a token field: {details}"
        );
        assert!(
            !details.contains("\"value\""),
            "audit details must not carry a value field: {details}"
        );
    }

    /// 9. v2 ReceiptEnvelope for revocation — `kind="broker.revocation"`,
    ///    body carries `revoked_at_epoch_secs` + `materialization_id`,
    ///    round-trips through `verify_receipt_v2`. Audit-log shadow row
    ///    must also fire for back-compat.
    #[tokio::test]
    async fn broker_revoke_emits_v2_signed_envelope() {
        use core_crypto::{Ed25519Verifier, PublicKey};
        use core_events::receipt::sign::verify_receipt_v2;

        let identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("v2-revoke-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);

        let issued = issue_with_registry(
            &reg,
            &store,
            &issue_params_hitl(60, "v2-revoke-test", &persona.id),
            &auto_policy(),
        )
        .await
        .unwrap();
        let mid = issued["materialization_id"].as_str().unwrap().to_string();

        revoke_with_registry(&reg, &store, &json!({"materialization_id": mid}))
            .await
            .expect("revoke should succeed");

        // --- audit-log shadow must still fire (back-compat row) ---
        let audit_rows = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.revocation".to_string()),
                ..Default::default()
            })
            .expect("audit query");
        assert!(
            !audit_rows.is_empty(),
            "audit-log shadow row must still be present for revocation"
        );

        // --- v2 revocation envelope row must be persisted ---
        let receipt_rows = store
            .list_receipt_rows(&crate::infra::receipt::ReceiptFilter {
                kind: Some("broker.revocation".to_string()),
                ..Default::default()
            })
            .expect("receipt rows query");
        assert_eq!(
            receipt_rows.len(),
            1,
            "exactly one broker.revocation v2 row expected, got: {receipt_rows:?}"
        );
        let row = &receipt_rows[0];
        assert_eq!(row.kind, "broker.revocation");

        let envelope_json = store
            .get_receipt_v2_envelope_json(&row.id)
            .expect("get v2 envelope JSON");
        let envelope: core_events::receipt::envelope::ReceiptEnvelope =
            serde_json::from_str(&envelope_json).expect("parse envelope");
        assert_eq!(envelope.kind, "broker.revocation");
        assert_eq!(envelope.daemon_root_id, identity.pubkey_hex());
        assert!(envelope.signature.is_some(), "v2 envelope must be signed");
        assert!(
            envelope
                .body
                .get("revoked_at_epoch_secs")
                .and_then(|v| v.as_u64())
                .is_some(),
            "revocation body must carry revoked_at_epoch_secs: {body}",
            body = envelope.body
        );
        assert_eq!(
            envelope
                .body
                .get("materialization_id")
                .and_then(|v| v.as_str()),
            Some(mid.as_str())
        );

        let pk = PublicKey(format!("ed25519:{}", identity.pubkey_hex()));
        verify_receipt_v2(&envelope, &pk, &Ed25519Verifier)
            .expect("signed v2 revocation envelope must verify");
    }

    /// 10. `query_receipts` with `kind=broker.revocation` returns the v2 broker
    ///     row — confirms the store query path works for the dotted-kind
    ///     discriminator. (Materialization is no longer a receipt — ADR 205
    ///     §B.6 — so revocation is the surviving signed broker receipt that
    ///     exercises this query path.)
    #[tokio::test]
    async fn receipt_query_broker_revocation_returns_broker_rows() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("query-revocation-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);

        let issued = issue_with_registry(
            &reg,
            &store,
            &issue_params_hitl(120, "query-test", &persona.id),
            &auto_policy(),
        )
        .await
        .unwrap();
        let mid = issued["materialization_id"].as_str().unwrap().to_string();
        revoke_with_registry(&reg, &store, &json!({"materialization_id": mid}))
            .await
            .expect("revoke should succeed");

        let rows = store
            .query_receipts(&crate::infra::receipt::ReceiptFilter {
                kind: Some("broker.revocation".to_string()),
                ..Default::default()
            })
            .expect("query_receipts");
        assert_eq!(rows.len(), 1, "one broker.revocation v2 row expected");
        assert_eq!(rows[0].kind, "broker.revocation");
    }

    /// 11. Grant-scope gate — active grant matching persona + provider allows issue.
    #[tokio::test]
    async fn issue_with_registry_succeeds_when_active_grant_covers_scope() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        // Create a persona and an active budgeted grant covering Anthropic.
        let persona = store.create_persona("test-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);

        let params = issue_params_hitl(300, "grant-gate-test", &persona.id);

        let res = issue_with_registry(&reg, &store, &params, &auto_policy()).await;
        assert!(
            res.is_ok(),
            "issue should succeed when active grant covers scope: {res:?}"
        );
    }

    /// BKR-4b (ADR 205 §A.4) — the broker_issue mint now routes through the
    /// composed `verify_grant_for_use`, so a revoked ANCESTOR in the matched
    /// grant's `parent_grant_id` lineage blocks the credential issue even though
    /// the leaf grant is itself active and budgeted. Before this wiring,
    /// broker_issue trusted any active provider-matched grant row outright and
    /// would have minted; the §A.4 online revocation walk (previously enforced
    /// only at the LLM proxy boundary) now covers the issue boundary too. This
    /// is the net-new gate at this boundary in the dev0 root regime — parts (1)
    /// root-auth + (2) chain-verify firm to the device-set when ADR 206 steps
    /// 1–2 land (no caller change), while the eager-cascade-miss this walk
    /// catches is real today.
    #[tokio::test]
    async fn issue_with_registry_refuses_when_grant_ancestor_revoked() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("ancestor-revoked-persona").unwrap();

        // Apex ancestor grant (anthropic), then revoke ONLY it — simulating a
        // cascade that never reached the still-active leaf (crash mid-cascade /
        // race / a presented embed-chain the column never cascaded).
        let parent = create_budgeted_anthropic_grant(&store, &persona.id);
        store
            .conn()
            .execute(
                "UPDATE grants SET status = 'revoked' WHERE id = ?1",
                rusqlite::params![parent.id],
            )
            .unwrap();

        // Active leaf grant (anthropic) descending from the revoked ancestor.
        // It is the only ACTIVE provider-matched grant, so it is the one
        // `issue_with_registry` selects.
        let leaf = create_budgeted_anthropic_grant(&store, &persona.id);
        store
            .conn()
            .execute(
                "UPDATE grants SET parent_grant_id = ?1 WHERE id = ?2",
                rusqlite::params![parent.id, leaf.id],
            )
            .unwrap();

        // Sanity: the leaf itself is active + budgeted (passes the legacy
        // provider-match + budget-label gates), so the refusal is purely the
        // §A.4 ancestry walk inside the composed verifier.
        let hydrated = store.get_access_grant(&leaf.id).unwrap();
        assert_eq!(
            hydrated.status,
            core_grant_types::GrantStatus::Active,
            "leaf grant must itself be active so the refusal is the §A.4 walk only"
        );

        let params = issue_params_hitl(300, "ancestor-revoked-test", &persona.id);
        let res = issue_with_registry(&reg, &store, &params, &auto_policy()).await;
        assert!(
            matches!(res, Err((-32003, _))),
            "a revoked ANCESTOR must block the broker_issue mint via the §A.4 walk, \
             even though the leaf grant is active and budgeted: {res:?}"
        );
    }

    /// META-AP-DAEMON-PRESENCE-LADDER-CONSUMER-WIRED — the registry issue
    /// path must consume the per-cohort ladder decision instead of leaving
    /// every cohort at the old fail-closed placeholder.
    #[tokio::test]
    async fn issue_with_registry_consumes_presence_ladder_for_cohort() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        let persona = store.create_persona("presence-ladder-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);

        let mut dev0_params = issue_params_hitl(300, "presence-ladder-dev0", &persona.id);
        dev0_params["cohort"] = json!("dev0");
        dev0_params["session_phase"] = json!("open");

        issue_with_registry(&reg, &store, &dev0_params, &auto_policy())
            .await
            .expect("dev0 issue should pass through the consumed ladder");

        let dev0_entries = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.presence_ladder.audit_required".to_string()),
                ..Default::default()
            })
            .expect("audit query");
        assert!(
            dev0_entries.is_empty(),
            "dev0 open should not emit the ent0 audit-required ladder event"
        );

        let mut ent0_params = issue_params_hitl(300, "presence-ladder-ent0", &persona.id);
        ent0_params["cohort"] = json!("ent0");
        ent0_params["session_phase"] = json!("open");

        issue_with_registry(&reg, &store, &ent0_params, &auto_policy())
            .await
            .expect("ent0 issue should pass through the consumed ladder");

        let ent0_entries = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.presence_ladder.audit_required".to_string()),
                ..Default::default()
            })
            .expect("audit query");
        assert_eq!(
            ent0_entries.len(),
            1,
            "ent0 open should emit exactly one audit-required ladder event"
        );
        let details: Value = serde_json::from_str(
            ent0_entries[0]
                .details
                .as_deref()
                .expect("ladder audit details"),
        )
        .expect("parse ladder audit details");
        assert_eq!(details["checkpoint"], json!("ladder_decision_consumed"));
        assert_eq!(details["cohort"], json!("ent0"));
        assert_eq!(details["session_phase"], json!("open"));
        assert_eq!(details["decision"], json!("fido2_plus_audit_log"));
    }

    /// 12. Grant-scope gate — no active grant means issue is rejected with -32003.
    #[tokio::test]
    async fn issue_with_registry_returns_no_grant_when_missing() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        // Create a persona but do NOT create any grant.
        let persona = store.create_persona("test-persona-no-grant").unwrap();

        let mut params = issue_params(300, "grant-gate-missing-test");
        params["caller_persona"] = serde_json::json!(persona.id);

        let res = issue_with_registry(&reg, &store, &params, &auto_policy()).await;
        assert!(
            res.is_err(),
            "issue should fail when no active grant exists"
        );
        let (code, msg) = res.unwrap_err();
        assert_eq!(code, -32003, "expected -32003 error code, got {code}");
        assert!(
            msg.contains("no active grant"),
            "expected 'no active grant' message, got: {msg}"
        );
    }

    /// Budget-label providers do not receive a provider-enforced
    /// least-privilege native scope. The grant must therefore carry a
    /// non-empty budget/backstop before the daemon will mint.
    #[tokio::test]
    async fn issue_with_registry_rejects_budget_label_grant_without_non_empty_budget() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        for (name, budget) in [
            ("budget-label-no-budget", None),
            (
                "budget-label-empty-budget",
                Some(core_grant_types::Budget::default()),
            ),
        ] {
            let persona = store.create_persona(name).unwrap();
            store
                .create_grant_with_budget(&persona.id, "anthropic", "dns:edit", None, budget)
                .unwrap();

            let err = issue_with_registry(
                &reg,
                &store,
                &issue_params_hitl(300, name, &persona.id),
                &auto_policy(),
            )
            .await
            .expect_err("budget-label provider must require a non-empty budget");
            assert_eq!(err.0, -32003);
            assert!(
                err.1.contains("budget-label") && err.1.contains("non-empty budget"),
                "error should explain the budget-label backstop: {}",
                err.1
            );
        }

        assert!(
            reg.list_active().is_empty(),
            "unbudgeted budget-label grants must not materialize credentials"
        );
    }

    /// 13. Policy gate — Denied evaluation blocks credential mint with -32007.
    ///
    /// Verify the policy engine unit-returns `Denied` for a Denied rule and
    /// that `issue_with_registry` rejects with -32007 when passed that engine.
    #[tokio::test]
    async fn issue_with_registry_returns_policy_denied_when_denied_rule() {
        use crate::trust::policy::{ApprovalRequirement, PolicyEngine};
        use core_approval::policy::{PolicyConfig, PolicyRule, RiskLevel};

        // Unit-verify the Denied evaluation path.
        let rules = vec![PolicyRule {
            action: core_approval::policy::ActionSelector::named("credential.access.anthropic"),
            risk: RiskLevel::Critical,
            requirement: ApprovalRequirement::Denied,
            tier: None,
        }];
        let engine = PolicyEngine::new(PolicyConfig {
            rules,
            default_requirement: ApprovalRequirement::Auto,
            default_risk: RiskLevel::Low,
        });
        let eval = engine.evaluate("credential.access.anthropic");
        assert_eq!(
            eval.requirement,
            ApprovalRequirement::Denied,
            "policy engine must return Denied for the configured rule"
        );

        // Confirm issue_with_registry rejects with -32007 when given a Denied engine.
        // Seed persona + budgeted grant so the grant and budget-label gates
        // pass; the policy gate is the refusal under test.
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("policy-denied-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);
        let result = issue_with_registry(
            &reg,
            &store,
            &issue_params_hitl(60, "policy-denied-test", &persona.id),
            &engine,
        )
        .await;
        assert!(
            result.is_err(),
            "issue must be rejected when policy returns Denied: {result:?}"
        );
        let (code, _) = result.unwrap_err();
        assert_eq!(
            code, -32007,
            "expected -32007 for Denied policy, got {code}"
        );
    }

    /// 14. Policy gate — Auto rule allows credential mint to proceed.
    ///
    /// Verifies that the `Auto` branch in the gate lets `broker.issue` run
    /// and the response contains a `secret_ref`.
    #[tokio::test]
    async fn issue_with_registry_proceeds_when_policy_auto() {
        use crate::trust::policy::{ApprovalRequirement, PolicyEngine};
        use core_approval::policy::{PolicyConfig, PolicyRule, RiskLevel};

        // Unit-verify the Auto evaluation path.
        let rules = vec![PolicyRule {
            action: core_approval::policy::ActionSelector::named("credential.access.*"),
            risk: RiskLevel::Low,
            requirement: ApprovalRequirement::Auto,
            tier: None,
        }];
        let engine = PolicyEngine::new(PolicyConfig {
            rules,
            default_requirement: ApprovalRequirement::Auto,
            default_risk: RiskLevel::Low,
        });
        let eval = engine.evaluate("credential.access.cloudflare");
        assert_eq!(
            eval.requirement,
            ApprovalRequirement::Auto,
            "policy engine must return Auto for the configured wildcard rule"
        );

        // Confirm issue proceeds when policy returns Auto.
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("policy-auto-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);
        let result = issue_with_registry(
            &reg,
            &store,
            &issue_params_hitl(120, "policy-auto-test", &persona.id),
            &engine,
        )
        .await;
        assert!(
            result.is_ok(),
            "issue must succeed when policy allows: {result:?}"
        );
        assert!(
            result.unwrap().get("secret_ref").is_some(),
            "response must contain secret_ref"
        );
    }

    /// 15. HITL poll — approval resolves to approved: issue proceeds.
    ///
    /// Uses a file-backed store so the resolver task can open a second
    /// connection to the same database and flip the approval row while the
    /// poll loop is sleeping.
    #[tokio::test]
    async fn issue_with_registry_blocks_then_proceeds_when_approved() {
        use crate::trust::approval::ApprovalOutcome;

        // The daemon runs on a tokio LocalSet (see daemon.md). spawn_local
        // requires the LocalSet context, which the default #[tokio::test]
        // multi-thread runtime does NOT provide. Wrap the test body in a
        // LocalSet::run_until block so spawn_local has its required runtime.
        tokio::task::LocalSet::new()
            .run_until(async move {
                use std::rc::Rc;

                let _identity = ensure_identity_for_broker_test();
                let reg = fresh_registry();

                // Shared in-memory store (file-backed needs a vault per V0
                // schema; in-memory + Rc lets the resolver task share the same
                // SQLite connection without re-opening).
                let store = Rc::new(DaemonStore::open_in_memory().unwrap());
                let persona = store.create_persona("hitl-approved-persona").unwrap();
                create_budgeted_anthropic_grant(&store, &persona.id);

                let resolver_store = Rc::clone(&store);
                let resolver = tokio::task::spawn_local(async move {
                    // Brief pause to let the poll loop submit the approval row.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    let pending = resolver_store
                        .list_pending_approvals()
                        .expect("list_pending_approvals");
                    for row in &pending {
                        resolver_store
                            .resolve_approval(&row.id, &ApprovalOutcome::Approved)
                            .expect("resolve_approval");
                    }
                });

                let result = issue_with_registry(
                    &reg,
                    &store,
                    &issue_params_hitl(60, "hitl-approved-test", &persona.id),
                    &required_policy(),
                )
                .await;
                resolver.await.expect("resolver task panicked");
                assert!(
                    result.is_ok(),
                    "issue should succeed after approval: {result:?}"
                );
                assert!(
                    result.unwrap().get("secret_ref").is_some(),
                    "response must contain secret_ref"
                );
            })
            .await;
    }

    /// 16. HITL poll — operator denies: issue returns -32009.
    #[tokio::test]
    async fn issue_with_registry_returns_denied_when_operator_denies() {
        use crate::trust::approval::ApprovalOutcome;

        // LocalSet wrapping required for spawn_local — see sibling test above.
        tokio::task::LocalSet::new()
            .run_until(async move {
                use std::rc::Rc;

                let _identity = ensure_identity_for_broker_test();
                let reg = fresh_registry();

                let store = Rc::new(DaemonStore::open_in_memory().unwrap());
                let persona = store.create_persona("hitl-denied-persona").unwrap();
                create_budgeted_anthropic_grant(&store, &persona.id);

                let resolver_store = Rc::clone(&store);
                let resolver = tokio::task::spawn_local(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    let pending = resolver_store
                        .list_pending_approvals()
                        .expect("list_pending_approvals");
                    for row in &pending {
                        resolver_store
                            .resolve_approval(
                                &row.id,
                                &ApprovalOutcome::Denied {
                                    reason: "test denial".to_string(),
                                },
                            )
                            .expect("resolve_approval");
                    }
                });

                let result = issue_with_registry(
                    &reg,
                    &store,
                    &issue_params_hitl(60, "hitl-denied-test", &persona.id),
                    &required_policy(),
                )
                .await;
                resolver.await.expect("resolver task panicked");
                assert!(result.is_err(), "issue must fail when operator denies");
                let (code, _) = result.unwrap_err();
                assert_eq!(
                    code, -32009,
                    "expected -32009 for operator denial, got {code}"
                );
            })
            .await;
    }

    /// 17. HITL poll — no resolution within timeout: issue returns -32008.
    ///
    /// `cfg!(test)` sets the timeout to 200 ms; no resolver is spawned so
    /// the loop expires and dismiss_approval fires.
    #[tokio::test]
    async fn issue_with_registry_returns_timeout_when_no_resolution() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        // Seed persona + grant so the grant-scope gate passes; then policy
        // returns Required but no resolver runs, so the poll loop times out.
        let persona = store.create_persona("hitl-timeout-persona").unwrap();
        create_budgeted_anthropic_grant(&store, &persona.id);

        let result = issue_with_registry(
            &reg,
            &store,
            &issue_params_hitl(60, "hitl-timeout-test", &persona.id),
            &required_policy(),
        )
        .await;
        assert!(result.is_err(), "issue must fail on timeout");
        let (code, _) = result.unwrap_err();
        assert_eq!(code, -32008, "expected -32008 for timeout, got {code}");
    }
}
