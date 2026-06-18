use std::cell::RefCell;
use std::time;

use core_event_types::ActionRef;
use core_grant_types::{ResourceSelector, ResourceType, Statement, Usage};
use serde_json::{Value, json};

use crate::infra::handlers::principal::ensure_connect_only_owner_matches_trusted_principal;
use crate::infra::rate_limit::RateLimiter;
use crate::infra::store::{DaemonStore, StoreError};
use crate::trust::policy::{ApprovalRequirement, PolicyEngine};

use super::{RequestContext, notify_require_approval};

#[derive(Debug, Clone)]
struct AccessRequestIntent {
    persona_id: String,
    credential_name: String,
    policy_action: String,
    grant_scope: String,
    ttl_secs: Option<u64>,
    action_ref: Option<ActionRef>,
    need: Vec<String>,
    resource_selector: Option<ResourceSelector>,
    target_source: &'static str,
}

impl AccessRequestIntent {
    fn manifest_statements(&self) -> Option<Vec<Statement>> {
        let selector = self.resource_selector.clone()?;
        Some(
            self.need
                .iter()
                .enumerate()
                .map(|(idx, action)| Statement {
                    sid: format!("need{idx}"),
                    resource_type: ResourceType::Credential,
                    actions: vec![action.clone()],
                    resource: selector.clone(),
                    budget: None,
                    usage: Usage::default(),
                    conditions: Vec::new(),
                    can_delegate: None,
                })
                .collect(),
        )
    }

    fn manifest_scope_display(&self) -> String {
        self.need.join(" ")
    }

    fn resource_for_matching(&self) -> String {
        match self.resource_selector.as_ref() {
            Some(ResourceSelector::Exact { value }) => value.clone(),
            Some(ResourceSelector::Glob { pattern }) => pattern.clone(),
            Some(ResourceSelector::GlobWithSubtarget { primary_glob, .. }) => primary_glob.clone(),
            Some(ResourceSelector::Regex { pattern }) => pattern.clone(),
            Some(ResourceSelector::Any) | None => "*".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct ManifestActionProjection {
    need: Vec<String>,
}

fn parse_access_request_intent(params: &Value) -> Result<AccessRequestIntent, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or((-32602, "missing 'persona_id'".to_string()))?
        .to_string();
    let credential_name = params["credential_name"]
        .as_str()
        .ok_or((-32602, "missing 'credential_name'".to_string()))?
        .to_string();
    let ttl_secs = params["ttl_secs"].as_u64();

    reject_removed_access_request_fields(params)?;

    let action_ref_raw = params["action_ref"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or((-32602, "access.request requires 'action_ref'".to_string()))?;
    let action_ref = ActionRef::parse(action_ref_raw)
        .map_err(|e| (-32602, format!("invalid action_ref: {e}")))?;
    let projection = resolve_manifest_action_projection(&action_ref)?;
    if projection.need.is_empty() {
        return Err((
            -32602,
            format!("action_ref {action_ref} declares no need in bundled manifest"),
        ));
    }
    let (resource_selector, target_source) = manifest_resource_selector(params)?;
    Ok(AccessRequestIntent {
        persona_id,
        credential_name,
        policy_action: action_ref.to_string(),
        grant_scope: projection.need.join(" "),
        ttl_secs,
        action_ref: Some(action_ref),
        need: projection.need,
        resource_selector: Some(resource_selector),
        target_source,
    })
}

fn reject_removed_access_request_fields(params: &Value) -> Result<(), (i32, String)> {
    if params.get("action").is_some() {
        return Err((
            -32602,
            "access.request no longer accepts 'action'; use 'action_ref'".to_string(),
        ));
    }
    if params.get("scope").is_some() {
        return Err((
            -32602,
            "access.request no longer accepts 'scope'; use 'resource_id' or typed 'target'"
                .to_string(),
        ));
    }
    Ok(())
}

fn resolve_manifest_action_projection(
    action_ref: &ActionRef,
) -> Result<ManifestActionProjection, (i32, String)> {
    let registry = super::preflight::bundled_construct_registry().map_err(|e| {
        (
            -32000,
            format!("load bundled construct manifest registry: {e}"),
        )
    })?;

    for manifest in registry.values() {
        if manifest.plugin_address.as_deref() != Some(action_ref.plugin_address.as_str()) {
            continue;
        }
        for action in &manifest.actions {
            if action.key == action_ref.action_key
                && action.action_version.as_deref() == Some(action_ref.action_version.as_str())
            {
                return Ok(ManifestActionProjection {
                    need: action.need.clone(),
                });
            }
        }
    }

    Err((
        -32602,
        format!("action_ref {action_ref} is not declared in bundled construct manifests"),
    ))
}

fn manifest_resource_selector(
    params: &Value,
) -> Result<(ResourceSelector, &'static str), (i32, String)> {
    if let Some(resource_id) = params["resource_id"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok((
            resource_selector_from_resource_id(resource_id),
            "resource_id",
        ));
    }

    if let Some(target) = params.get("target") {
        return target_resource_selector(target);
    }

    Err((
        -32602,
        "access.request requires 'resource_id' or typed 'target'".to_string(),
    ))
}

fn target_resource_selector(
    target: &Value,
) -> Result<(ResourceSelector, &'static str), (i32, String)> {
    let object = target
        .as_object()
        .ok_or((-32602, "'target' must be an object".to_string()))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or((-32602, "'target.kind' is required".to_string()))?;
    match kind {
        "github_repo" => {
            if let Some(provider) = object
                .get("provider")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if provider != "github" {
                    return Err((
                        -32602,
                        "target.kind 'github_repo' requires provider 'github' when provider is set"
                            .to_string(),
                    ));
                }
            }
            let repo = object
                .get("repo")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or((
                    -32602,
                    "'target.repo' is required for github_repo".to_string(),
                ))?;
            validate_github_repo_target(repo)?;
            Ok((
                ResourceSelector::Exact {
                    value: repo.to_string(),
                },
                "target.github_repo",
            ))
        }
        other => Err((
            -32602,
            format!("unsupported target.kind '{other}' for access.request"),
        )),
    }
}

fn validate_github_repo_target(repo: &str) -> Result<(), (i32, String)> {
    let mut parts = repo.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if owner.is_empty()
        || name.is_empty()
        || parts.next().is_some()
        || repo.contains('*')
        || repo.chars().any(char::is_whitespace)
    {
        return Err((
            -32602,
            "target.repo must be an exact GitHub repository in 'owner/name' form".to_string(),
        ));
    }
    Ok(())
}

fn resource_selector_from_resource_id(resource_id: &str) -> ResourceSelector {
    if resource_id == "*" {
        ResourceSelector::Any
    } else if resource_id.contains('*') {
        ResourceSelector::Glob {
            pattern: resource_id.to_string(),
        }
    } else {
        ResourceSelector::Exact {
            value: resource_id.to_string(),
        }
    }
}

fn manifest_standing_covered(
    store: &DaemonStore,
    intent: &AccessRequestIntent,
) -> Result<bool, StoreError> {
    if let Some(action_ref) = intent.action_ref.as_ref() {
        if store.check_standing_grant_action_ref(&intent.persona_id, action_ref)? {
            return Ok(true);
        }
    }

    let resource = intent.resource_for_matching();
    for need in &intent.need {
        if store
            .match_standing_statement(&intent.persona_id, need, &resource)?
            .is_none()
        {
            return Ok(false);
        }
    }
    Ok(!intent.need.is_empty())
}

fn issue_manifest_grant(
    store: &DaemonStore,
    intent: &AccessRequestIntent,
    source: &str,
) -> Result<crate::trust::grant::GrantInfo, StoreError> {
    let statements = intent
        .manifest_statements()
        .ok_or_else(|| StoreError::InvalidInput("manifest request missing statements".into()))?;
    let grant = store.create_grant_with_budget_suppress_minted_event(
        &intent.persona_id,
        &intent.credential_name,
        &intent.grant_scope,
        intent.ttl_secs,
        None,
    )?;
    store.mint_composite_chain_for_grant(
        &grant.id,
        &intent.persona_id,
        &intent.credential_name,
        statements,
        intent.ttl_secs,
    )?;
    let _ = store.log_event(
        Some(&intent.persona_id),
        "grant.issued",
        Some(&intent.credential_name),
        "allowed",
        Some(
            &json!({
                "grant_id": grant.id,
                "action_ref": intent.action_ref.as_ref().map(ToString::to_string),
                "need": intent.need,
                "need_source": "manifest",
                "resource_selector": intent.resource_selector,
                "target_source": intent.target_source,
                "ttl_secs": intent.ttl_secs,
                "source": source,
                "composite": true,
            })
            .to_string(),
        ),
    );
    Ok(grant)
}

fn append_manifest_response_fields(value: &mut Value, intent: &AccessRequestIntent) {
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "action_ref".to_string(),
            intent
                .action_ref
                .as_ref()
                .map(ToString::to_string)
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        obj.insert("need".to_string(), json!(intent.need));
        obj.insert(
            "need_source".to_string(),
            Value::String("manifest".to_string()),
        );
        obj.insert(
            "target_source".to_string(),
            Value::String(intent.target_source.to_string()),
        );
        obj.insert(
            "resource_selector".to_string(),
            serde_json::to_value(&intent.resource_selector).unwrap_or(Value::Null),
        );
    }
}

pub(crate) async fn handle_request(
    store: &DaemonStore,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let intent = parse_access_request_intent(params)?;

    // Pre-evaluation rate limit check (#69C.4). Runs before standing
    // grant lookup and policy evaluation. On rejection the response
    // intentionally avoids disclosing which rule would have matched:
    // only the rate-limit fact is surfaced.
    if !rate_limiter
        .borrow_mut()
        .check_action(&intent.persona_id, &intent.policy_action)
    {
        let mut response = json!({
            "status": "denied",
            "decision": "deny",
            "reason": "rate_spike",
        });
        append_manifest_response_fields(&mut response, &intent);
        return Ok(response);
    }

    // Check standing grants first.
    let standing_grant_hit =
        manifest_standing_covered(store, &intent).map_err(|e| (-32000, e.to_string()))?;
    if standing_grant_hit {
        let grant = issue_manifest_grant(store, &intent, "standing_grant")
            .map_err(|e| (-32000, e.to_string()))?;
        let mut response = json!({
            "status": "approved",
            "source": "standing_grant",
            "grant_id": grant.id,
        });
        append_manifest_response_fields(&mut response, &intent);
        return Ok(response);
    }

    let eval = policy.evaluate(&intent.policy_action);
    let risk_str = format!("{:?}", eval.risk).to_lowercase();

    match eval.requirement {
        ApprovalRequirement::Auto => {
            let grant = issue_manifest_grant(store, &intent, "request_access")
                .map_err(|e| (-32000, e.to_string()))?;
            let mut response = json!({
                "status": "approved",
                "grant_id": grant.id,
                "decision": "auto_approve",
                "risk": risk_str,
            });
            append_manifest_response_fields(&mut response, &intent);
            Ok(response)
        }
        ApprovalRequirement::Required => {
            let statements = intent
                .manifest_statements()
                .ok_or_else(|| (-32000, "manifest request missing statements".to_string()))?;
            let req = store
                .propose_grant_with_notify(
                    &intent.persona_id,
                    &intent.credential_name,
                    &intent.manifest_scope_display(),
                    intent.ttl_secs,
                    &intent.policy_action,
                    &risk_str,
                    statements,
                    params["tool_name"].as_str().map(str::to_owned),
                    params["target_host"].as_str().map(str::to_owned),
                    params["target_url"].as_str().map(str::to_owned),
                    params["agent_framework"].as_str().map(str::to_owned),
                )
                .map_err(|e| (-32000, e.to_string()))?;
            notify_require_approval(store, &req);
            let mut response = json!({
                "status": "pending",
                "approval_id": req.id,
                "decision": "require_approval",
                "risk": risk_str,
            });
            append_manifest_response_fields(&mut response, &intent);
            Ok(response)
        }
        ApprovalRequirement::Denied => {
            let mut response = json!({
                "status": "denied",
                "decision": "deny",
                "risk": risk_str,
                "reason": format!(
                    "policy denies action: {}",
                    eval.matched_rule.unwrap_or_default()
                ),
            });
            append_manifest_response_fields(&mut response, &intent);
            Ok(response)
        }
    }
}

pub(crate) async fn handle_await_approval(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let request_id = params["request_id"]
        .as_str()
        .ok_or((-32602, "missing 'request_id' parameter".to_string()))?
        .to_string();
    let timeout_secs = params["timeout_secs"].as_u64().unwrap_or(300);

    let deadline = tokio::time::Instant::now() + time::Duration::from_secs(timeout_secs);

    loop {
        let info = store.get_approval(&request_id).map_err(|e| match e {
            StoreError::NotFound => (-32004, format!("approval {request_id} not found")),
            other => (-32000, other.to_string()),
        })?;
        ensure_connect_only_owner_matches_trusted_principal(
            ctx,
            "await_approval",
            &info.persona_id,
        )?;

        let decision_json: Option<Value> = match info.status.as_str() {
            "pending" => None,
            "approved" | "narrowed" | "narrowed_and_approved" => {
                Some(json!({"decision": {"kind": "approved"}}))
            }
            "denied" | "dismissed" => Some(json!({
                "decision": {
                    "kind": "denied",
                    "reason": info
                        .reason
                        .clone()
                        .unwrap_or_else(|| format!("approval {}", info.status)),
                }
            })),
            "timed_out" | "expired" => Some(json!({"decision": {"kind": "timed_out"}})),
            other => Some(json!({
                "decision": {
                    "kind": "denied",
                    "reason": format!("unknown approval status: {other}"),
                }
            })),
        };

        if let Some(v) = decision_json {
            return Ok(v);
        }

        if tokio::time::Instant::now() >= deadline {
            return Ok(json!({"decision": {"kind": "timed_out"}}));
        }

        tokio::time::sleep(time::Duration::from_millis(500)).await;
    }
}
