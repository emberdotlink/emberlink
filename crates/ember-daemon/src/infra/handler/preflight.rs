use std::collections::HashMap;

use super::*;
use core_event_types::ActionRef;
use core_grant_types::{ResourceSelector, ResourceType, StatementProposal};
use serde::Serialize;

/// HEADLESS-PREFLIGHT-LAYER1-CONSTRUCTS-PHASE2 — Layer 1 pre-flight handler.
///
/// PREFLIGHT-LAYER1-WIRED
///
/// Parses the caller-supplied `tasks` + optional `template`, resolves each
/// task's declared constructs through the bundled cohort-A manifest registry
/// via `core_construct_runtime::preflight::resolve_queued_task_permissions`, diffs
/// against the template via `cross_reference`, and returns the gap list as
/// JSON. Unknown constructs and unknown actions are skipped silently per the
/// resolver's "best-effort predictive layer" contract — Layer 2
/// (`headless_preflight_gaps`) catches the runtime gap.
///
/// Pulled into a free function so the dispatch arm stays narrow and the
/// param-parsing logic is unit-testable without spinning up a full daemon
/// store.
pub(super) type ParsedHeadlessTaskInput = Vec<(String, Vec<String>)>;

pub(super) fn parse_headless_task_input(
    tasks_value: &Value,
) -> Result<ParsedHeadlessTaskInput, (i32, String)> {
    let tasks_array = tasks_value
        .as_array()
        .ok_or((-32602, "'tasks' parameter must be a JSON array".to_string()))?;
    let mut tasks: Vec<(String, Vec<String>)> = Vec::with_capacity(tasks_array.len());
    for (idx, raw) in tasks_array.iter().enumerate() {
        let task_id = raw
            .get("task_id")
            .and_then(|v| v.as_str())
            .ok_or((-32602, format!("tasks[{idx}]: missing string 'task_id'")))?
            .to_string();
        let constructs_value = raw.get("constructs").cloned().unwrap_or(json!([]));
        let constructs_array = constructs_value.as_array().ok_or((
            -32602,
            format!("tasks[{idx}].constructs must be a JSON array of strings"),
        ))?;
        let mut declarations: Vec<String> = Vec::with_capacity(constructs_array.len());
        for (d_idx, decl) in constructs_array.iter().enumerate() {
            let s = decl.as_str().ok_or((
                -32602,
                format!("tasks[{idx}].constructs[{d_idx}] must be a string"),
            ))?;
            declarations.push(s.to_string());
        }
        tasks.push((task_id, declarations));
    }
    Ok(tasks)
}

pub(super) fn handle_headless_preflight_layer1(params: &Value) -> Result<Value, (i32, String)> {
    use core_construct_runtime::preflight::{
        Permission, Template, cross_reference, resolve_queued_task_permissions,
    };

    // Parse `tasks` — required. Each entry is { task_id, constructs }.
    let tasks_value = params.get("tasks").ok_or((
        -32602,
        "missing 'tasks' parameter (array of { task_id, constructs })".to_string(),
    ))?;
    let tasks = parse_headless_task_input(tasks_value)?;

    // Parse optional `template`. Absent or empty → fail-open default of
    // "no permissions allowed", which is the dev0 fail-closed posture.
    let template_value = params.get("template").cloned().unwrap_or(json!([]));
    let template_array = template_value.as_array().ok_or((
        -32602,
        "'template' parameter must be a JSON array of strings".to_string(),
    ))?;
    let mut allowed: Vec<Permission> = Vec::with_capacity(template_array.len());
    for (idx, entry) in template_array.iter().enumerate() {
        let identifier = entry
            .as_str()
            .ok_or((-32602, format!("template[{idx}] must be a string")))?;
        allowed.push(Permission {
            identifier: identifier.to_string(),
            scope: None,
        });
    }
    let template = Template { allowed };

    // Build the bundled cohort-A manifest registry. Per ADR 124 §2 every
    // bundled Construct's `construct.toml` is shipped under
    // `crates/ember-construct/construct/*.toml`; the registry needs them
    // available without a filesystem read so the daemon can answer the
    // RPC even on a fresh install. `include_str!` is the canonical pattern
    // already used in `crates/core-construct-runtime/src/manifest.rs` tests.
    let registry = bundled_construct_registry().map_err(|e| {
        (
            -32000,
            format!("load bundled construct manifest registry: {e}"),
        )
    })?;

    let needed = resolve_queued_task_permissions(&tasks, &registry);
    let gaps = cross_reference(&needed, &template);

    // Wire shape: { task_id, identifier, scope }.
    let payload: Vec<Value> = gaps
        .into_iter()
        .map(|g| {
            json!({
                "task_id": g.task_id,
                "identifier": g.permission.identifier,
                "scope": g.permission.scope,
            })
        })
        .collect();
    Ok(Value::Array(payload))
}

/// Build the cohort-A bundled `construct.toml` manifest registry by parsing
/// each `crates/ember-construct/construct/*.toml` via `include_str!`. Used
/// by [`handle_headless_preflight_layer1`].
///
/// Returns `Err` only when one of the bundled manifests fails to parse —
/// which would indicate a corrupt source tree (the parser is exercised by
/// `crates/core-construct-runtime/src/manifest.rs::parses_real_bundled_*`
/// tests on every workspace build).
pub(super) fn bundled_construct_registry()
-> Result<HashMap<String, core_construct_runtime::manifest::ConstructManifest>, toml::de::Error> {
    use core_construct_runtime::manifest::parse_construct_manifest_str;
    const BUNDLED: &[&str] = &[
        include_str!("../../../../ember-construct/construct/aws.toml"),
        include_str!("../../../../ember-construct/construct/az.toml"),
        include_str!("../../../../ember-construct/construct/docker.toml"),
        include_str!("../../../../ember-construct/construct/flyctl.toml"),
        include_str!("../../../../ember-construct/construct/gcloud.toml"),
        include_str!("../../../../ember-construct/construct/gh.toml"),
        include_str!("../../../../ember-construct/construct/git.toml"),
        include_str!("../../../../ember-construct/construct/kubectl.toml"),
        include_str!("../../../../ember-construct/construct/npm.toml"),
        include_str!("../../../../ember-construct/construct/okta.toml"),
        include_str!("../../../../ember-construct/construct/pulumi.toml"),
        include_str!("../../../../ember-construct/construct/terraform.toml"),
        include_str!("../../../../ember-construct/construct/tofu.toml"),
        include_str!("../../../../ember-construct/construct/vercel.toml"),
        include_str!("../../../../ember-construct/construct/wrangler.toml"),
    ];
    let mut registry = HashMap::with_capacity(BUNDLED.len());
    for raw in BUNDLED {
        let m = parse_construct_manifest_str(raw)?;
        registry.insert(m.name.clone(), m);
    }
    Ok(registry)
}

pub(super) fn handle_catalog_search_actions(params: &Value) -> Result<Value, (i32, String)> {
    let query = params
        .get("query")
        .or_else(|| params.get("q"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("")
        .to_ascii_lowercase();
    let service_filter = params
        .get("service")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .clamp(1, 100) as usize;

    let mut registry = bundled_construct_registry().map_err(|e| {
        (
            -32000,
            format!("load bundled construct manifest registry: {e}"),
        )
    })?;
    let mut manifests = registry
        .drain()
        .map(|(_, manifest)| manifest)
        .collect::<Vec<_>>();
    manifests.sort_by(|left, right| left.name.cmp(&right.name));

    let mut rows = Vec::new();
    'manifest: for manifest in manifests {
        if let Some(service_filter) = service_filter.as_deref() {
            let service_matches = manifest.name.to_ascii_lowercase().contains(service_filter)
                || manifest
                    .plugin_address
                    .as_deref()
                    .map(|value| value.to_ascii_lowercase().contains(service_filter))
                    .unwrap_or(false);
            if !service_matches {
                continue 'manifest;
            }
        }

        for action in manifest.actions {
            let action_ref = match (&manifest.plugin_address, action.action_version.as_deref()) {
                (Some(plugin_address), Some(action_version)) => Some(
                    ActionRef::new(plugin_address.clone(), action.key.clone(), action_version)
                        .to_string(),
                ),
                _ => None,
            };
            let authority_refs = if action.authority_refs.is_empty() {
                manifest.authority_refs.clone()
            } else {
                action.authority_refs.clone()
            };
            let semantic_labels = action.semantic_labels.join(" ");
            let need_text = action.need.join(" ");
            let authority_refs_text = authority_refs.join(" ");
            let haystack = [
                manifest.name.as_str(),
                manifest.plugin_address.as_deref().unwrap_or(""),
                action.key.as_str(),
                action_ref.as_deref().unwrap_or(""),
                semantic_labels.as_str(),
                need_text.as_str(),
                authority_refs_text.as_str(),
            ]
            .join(" ")
            .to_ascii_lowercase();
            if !query.is_empty() && !haystack.contains(&query) {
                continue;
            }
            rows.push(json!({
                "service": manifest.name,
                "plugin_address": manifest.plugin_address,
                "plugin_version": manifest.plugin_version,
                "description": manifest.description,
                "action_key": action.key,
                "action_version": action.action_version,
                "action_ref": action_ref,
                "default_policy": action.default_policy,
                "risk_tier": action.risk_tier,
                "semantic_labels": action.semantic_labels,
                "need": action.need,
                "authority_refs": authority_refs,
            }));
            if rows.len() >= limit {
                return Ok(json!({ "actions": rows }));
            }
        }
    }

    Ok(json!({ "actions": rows }))
}

// ---------------------------------------------------------------------------
// P10-S3 — preflight authority coverage
//
// Gives the operator a before-launch answer: for each planned action, is it
// already covered, will it prompt, will it deny, or is it missing prerequisites?
// Design: deterministic authority coverage for each requested action.
//
// First principle: the daemon (authority root) owns the verdict. The CLI sends
// only the static catalog action set (action_ref / default_policy /
// authority_refs read from bundled manifests — no authority decision); every
// covered/prompt/deny/missing call is made here against the daemon's own active
// grant statements. Coverage mirrors `emberlink_cli::catalog::statement_targets_service`
// so `ember preflight` stays consistent with `ember catalog show`.
// ---------------------------------------------------------------------------

/// The stable four-category operator-facing preflight verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreflightStatus {
    Covered,
    Prompt,
    Deny,
    Missing,
}

impl PreflightStatus {
    fn as_str(self) -> &'static str {
        match self {
            PreflightStatus::Covered => "covered",
            PreflightStatus::Prompt => "prompt",
            PreflightStatus::Deny => "deny",
            PreflightStatus::Missing => "missing",
        }
    }
}

/// Posture intent the operator is previewing for the lane.
#[derive(Debug, Clone, Copy)]
struct PreflightPosture {
    /// `strict` fallback denies out-of-scope actions instead of prompting.
    strict: bool,
    /// `headless`/unattended context cannot prompt at all.
    headless: bool,
}

/// One normalized planned action sent by the CLI from the catalog projection.
#[derive(Debug, Clone)]
struct PlannedAction {
    service: String,
    /// Canonical structured `plugin_address/action_key@action_version`. `None`
    /// when the manifest predates the structured-action-ref cutover.
    action_ref: Option<String>,
    plugin_address: Option<String>,
    /// Manifest `default = "permit" | "prompt" | "deny"` for this action.
    default_policy: Option<String>,
    /// Service/action broker-provider names (`github`, `aws_sts`, ...).
    authority_refs: Vec<String>,
    /// Optional concrete GitHub target evidence for action-intent previews.
    target_repo: Option<String>,
    /// Optional concrete branch/subtarget evidence for action-intent previews.
    target_branch: Option<String>,
    /// Optional provider on the typed target, used only for advisory Service
    /// discovery when the installed Service manifest is absent.
    target_provider: Option<String>,
    /// Non-secret action labels supplied by a planner/proxy intent. These let
    /// the Available Service Index suggest a Service without trusting native
    /// provider scope as authority.
    semantic_labels: Vec<String>,
    /// False when target evidence comes from an untrusted/plugin-self-certified source.
    target_evidence_trusted: bool,
    /// True when the target was supplied as native provider scope instead of a typed target.
    target_native_scope: bool,
    /// Service Connection breadth, when the caller can describe it.
    service_connection_scope: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AccessResolutionPlan {
    denied_action: String,
    target: TypedTargetSelector,
    target_evidence: TargetEvidence,
    steps: Vec<AccessResolutionStep>,
    collapse_eligibility: CollapseEligibility,
    reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct TypedTargetSelector {
    kind: &'static str,
    provider: &'static str,
    repo: String,
    branch: String,
}

#[derive(Debug, Clone, Serialize)]
struct TargetEvidence {
    source: &'static str,
    extractor: &'static str,
    confidence: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AccessResolutionStep {
    InstallService {
        service_ref: ServiceRef,
        publisher_trust: TrustVerdict,
    },
    ConnectService {
        service_ref: ServiceRef,
        envelope: MaterializationEnvelope,
    },
    IssueGrant {
        grant_delta: GrantDelta,
    },
}

#[derive(Debug, Clone, Serialize)]
struct ServiceRef {
    name: &'static str,
    plugin_address: &'static str,
    display_name: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct TrustVerdict {
    trusted: bool,
    provenance: &'static str,
    reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct MaterializationEnvelope {
    service_connection: &'static str,
    readiness: &'static str,
    reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct GrantDelta {
    statements: Vec<StatementProposal>,
    ttl_secs: u64,
    delegation: Option<DelegationBounds>,
}

#[derive(Debug, Clone, Serialize)]
struct DelegationBounds {
    max_depth: u32,
}

#[derive(Debug, Clone, Serialize)]
struct CollapseEligibility {
    eligible: bool,
    reason: String,
}

/// True when any active grant statement targets the action's service.
///
/// Transitional service-level granularity per ADR 187 §10 — identical to the
/// catalog's standing-grant matcher, so the two surfaces never disagree. It
/// additionally honors a global-wildcard (`*`) statement, matching the runtime
/// payment-lane predicate.
fn preflight_action_is_covered(
    action: &PlannedAction,
    statement_action_lists: &[Vec<String>],
) -> bool {
    statement_action_lists.iter().any(|actions| {
        actions.iter().any(|stmt_action| {
            preflight_statement_action_targets(
                stmt_action,
                action.plugin_address.as_deref(),
                &action.authority_refs,
            )
        })
    })
}

fn preflight_statement_action_targets(
    stmt_action: &str,
    plugin_address: Option<&str>,
    authority_refs: &[String],
) -> bool {
    if stmt_action == "*" {
        return true;
    }
    // Structured action_ref: match on plugin_address (service identity).
    if let Some(pa) = plugin_address
        && let Ok(action_ref) = core_event_types::ActionRef::parse(stmt_action)
        && action_ref.plugin_address == pa
    {
        return true;
    }
    // Legacy named/dot-segmented action: prefix before `:`/`.` is the
    // service/authority-ref, matched against the action's authority refs.
    let prefix = stmt_action
        .split_once(':')
        .map(|(p, _)| p)
        .or_else(|| stmt_action.split_once('.').map(|(p, _)| p))
        .unwrap_or(stmt_action);
    authority_refs.iter().any(|r| r == prefix)
}

/// Map a catalog `authority_ref` string (`github`, `aws_sts`, ...) back to its
/// [`core_broker::BrokerProvider`] variant. Reuses the provider enum's
/// `snake_case` serde mapping so the single source of truth stays in
/// `core-broker`. Returns `None` for refs that name no known broker provider.
fn broker_provider_from_authority_ref(r: &str) -> Option<core_broker::BrokerProvider> {
    serde_json::from_value(Value::String(r.to_string())).ok()
}

fn planned_target_string(raw: &Value, object_field: &str, flat_field: &str) -> Option<String> {
    raw.get("target")
        .and_then(|target| target.get(object_field))
        .and_then(|v| v.as_str())
        .or_else(|| raw.get(flat_field).and_then(|v| v.as_str()))
        .map(str::to_string)
}

fn planned_bool(raw: &Value, object_field: &str, flat_field: &str, default: bool) -> bool {
    raw.get("target")
        .and_then(|target| target.get(object_field))
        .and_then(|v| v.as_bool())
        .or_else(|| raw.get(flat_field).and_then(|v| v.as_bool()))
        .unwrap_or(default)
}

fn planned_service_connection_scope(raw: &Value) -> Option<String> {
    raw.get("service_connection")
        .and_then(|connection| connection.get("scope"))
        .and_then(|v| v.as_str())
        .or_else(|| raw.get("service_connection_scope").and_then(|v| v.as_str()))
        .map(str::to_string)
}

fn planned_target_has_native_scope(raw: &Value) -> bool {
    raw.get("native_scope").is_some()
        || raw.get("provider_scope").is_some()
        || raw.get("target").is_some_and(|target| {
            target.get("native_scope").is_some()
                || target.get("provider_scope").is_some()
                || target.get("oauth_scope").is_some()
                || target.get("oauth_scopes").is_some()
        })
}

fn github_action_key(action_ref: &str) -> Option<&'static str> {
    if action_ref.ends_with("/pr_create@v1") {
        Some("pr_create")
    } else if action_ref.ends_with("/pr_merge@v1") {
        Some("pr_merge")
    } else {
        None
    }
}

fn is_bundled_github_action(action: &PlannedAction) -> bool {
    action.plugin_address.as_deref() == Some("registry.ember.systems/ember-systems/ember-gh")
        && action
            .action_ref
            .as_deref()
            .is_some_and(|r| r.starts_with("registry.ember.systems/ember-systems/ember-gh/"))
}

fn github_repo_blocker(repo: Option<&str>) -> Option<&'static str> {
    let Some(repo) = repo.map(str::trim) else {
        return Some("Target must name one GitHub repository before a Grant can be proposed");
    };
    if repo.is_empty() {
        return Some("Target must name one GitHub repository before a Grant can be proposed");
    }
    if matches!(
        repo,
        "*" | "all" | "all_repos" | "all-repos" | "all repositories"
    ) {
        return Some(
            "Target covers all GitHub repositories, so Resolve Access requires separate review",
        );
    }
    if repo.ends_with("/*") {
        return Some("Target covers every repository in a GitHub owner or org");
    }
    if repo.contains('*') || repo.contains('?') {
        return Some("Target uses a wildcard repository selector");
    }
    let Some((owner, name)) = repo.split_once('/') else {
        return Some("Target must name one GitHub repository before a Grant can be proposed");
    };
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        return Some("Target must name one GitHub repository before a Grant can be proposed");
    }
    None
}

fn github_branch_blocker(branch: Option<&str>) -> Option<&'static str> {
    let Some(branch) = branch.map(str::trim) else {
        return Some("Target branch must be exact before a Grant can be proposed");
    };
    if branch.is_empty() {
        return Some("Target branch must be exact before a Grant can be proposed");
    }
    if branch.contains('*') || branch.contains('?') {
        return Some("Target branch must be exact before Resolve Access can collapse");
    }
    if matches!(
        branch,
        "main" | "master" | "default" | "prod" | "production"
    ) || branch.starts_with("release/")
    {
        return Some("Target is a protected or production branch and needs separate review");
    }
    None
}

fn broad_service_connection_blocker(scope: Option<&str>) -> Option<&'static str> {
    let scope = scope?.trim();
    if matches!(
        scope,
        "all" | "account" | "org" | "organization" | "all_repos" | "all-repos" | "all repositories"
    ) || scope.ends_with("/*")
    {
        return Some("Service Connection is broader than this Action target");
    }
    None
}

const GH_SERVICE_NAME: &str = "ember-gh";
const GH_SERVICE_DISPLAY_NAME: &str = "GitHub Service";
const GH_SERVICE_CONNECTION: &str = "GitHub Service Connection";
const GH_PLUGIN_ADDRESS: &str = "registry.ember.systems/ember-systems/ember-gh";
const GH_PR_CREATE_ACTION_REF: &str = "registry.ember.systems/ember-systems/ember-gh/pr_create@v1";

#[derive(Debug, Clone, Copy)]
struct AvailableServiceCandidate {
    installed: bool,
    action_key: &'static str,
}

fn github_service_ref() -> ServiceRef {
    ServiceRef {
        name: GH_SERVICE_NAME,
        plugin_address: GH_PLUGIN_ADDRESS,
        display_name: GH_SERVICE_DISPLAY_NAME,
    }
}

fn github_publisher_trust() -> TrustVerdict {
    TrustVerdict {
        trusted: true,
        provenance: "bundled Ember Systems Service manifest",
        reason: "bundled Service manifests are core-vetted before advisory discovery",
    }
}

fn github_service_connection_envelope() -> MaterializationEnvelope {
    MaterializationEnvelope {
        service_connection: GH_SERVICE_CONNECTION,
        readiness: "missing",
        reason: "connect the GitHub Service before Ember can mint a scoped credential",
    }
}

fn available_github_service_candidate(action: &PlannedAction) -> Option<AvailableServiceCandidate> {
    let github_like_action =
        action.service == "ember-gh" || action.authority_refs.iter().any(|r| r == "github");
    if github_like_action
        && let Some(action_key) = action.action_ref.as_deref().and_then(github_action_key)
    {
        return Some(AvailableServiceCandidate {
            installed: true,
            action_key,
        });
    }

    let target_is_github = action.target_provider.as_deref() == Some("github")
        || action.authority_refs.iter().any(|r| r == "github");
    let semantic_match = action.semantic_labels.iter().any(|label| {
        matches!(
            label.as_str(),
            "github.pull_request.create"
                | "github.pull_request.write"
                | "scm.pull_request.create"
                | "scm.pull_request.write"
        )
    });
    if target_is_github && semantic_match {
        return Some(AvailableServiceCandidate {
            installed: false,
            action_key: "pr_create",
        });
    }

    None
}

fn github_connection_missing(
    action: &PlannedAction,
    configured: &HashMap<core_broker::BrokerProvider, bool>,
) -> bool {
    action.authority_refs.iter().any(|r| {
        broker_provider_from_authority_ref(r)
            .is_some_and(|provider| configured.get(&provider) == Some(&false))
    })
}

fn resolve_access_plan_for_action(
    action: &PlannedAction,
    status: PreflightStatus,
    configured: &HashMap<core_broker::BrokerProvider, bool>,
) -> Option<AccessResolutionPlan> {
    if !matches!(status, PreflightStatus::Prompt | PreflightStatus::Missing) {
        return None;
    }
    let candidate = available_github_service_candidate(action)?;
    let has_target_signal = action.target_repo.is_some()
        || action.target_branch.is_some()
        || action.target_native_scope
        || !action.target_evidence_trusted
        || action.service_connection_scope.is_some()
        || !candidate.installed;
    if !has_target_signal {
        return None;
    }

    let mut blockers: Vec<&'static str> = Vec::new();
    if candidate.installed && !is_bundled_github_action(action) {
        blockers.push("Action proof is not from the bundled GitHub Service");
    }
    if !candidate.installed {
        blockers
            .push("GitHub Service must be installed before this Resolve Access plan can collapse");
        blockers.push(
            "advisory Service candidates cannot mint credentials before Service installation",
        );
    }
    if !action.target_evidence_trusted {
        blockers.push("Target evidence is not from a trusted extractor");
    }
    if action.target_native_scope {
        blockers.push("Target is provider-native scope, not a typed GitHub Target");
    }
    if let Some(blocker) = github_repo_blocker(action.target_repo.as_deref()) {
        blockers.push(blocker);
    }
    if let Some(blocker) = github_branch_blocker(action.target_branch.as_deref()) {
        blockers.push(blocker);
    }
    if let Some(blocker) =
        broad_service_connection_blocker(action.service_connection_scope.as_deref())
    {
        blockers.push(blocker);
    }
    if candidate.action_key == "pr_merge" {
        blockers.push("Action pr_merge@v1 changes repository state and requires separate review");
    }

    let repo = action
        .target_repo
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let branch = action
        .target_branch
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    let denied_action = action
        .action_ref
        .clone()
        .unwrap_or_else(|| GH_PR_CREATE_ACTION_REF.to_string());
    let connection_missing = !candidate.installed || github_connection_missing(action, configured);
    if candidate.installed && connection_missing {
        blockers
            .push("GitHub Service Connection must be connected before this Resolve Access plan can collapse");
    }

    let need_key = format!("gh.{}", candidate.action_key);
    let need = ember_construct::manifest_action_need(&need_key);
    let statements: Vec<StatementProposal> = need
        .into_iter()
        .map(|action| StatementProposal {
            resource_type: ResourceType::Credential,
            credential_name: "github".to_string(),
            actions: vec![action],
            // GitHub installation tokens are repo/permission scoped, not
            // branch scoped. Branch remains target evidence for collapse
            // eligibility, but the GrantDelta must match what the current
            // materialization path can prove at mint time.
            resource: ResourceSelector::Exact {
                value: repo.clone(),
            },
            budget: None,
            conditions: Vec::new(),
        })
        .collect();

    let mut steps = Vec::new();
    if !candidate.installed {
        steps.push(AccessResolutionStep::InstallService {
            service_ref: github_service_ref(),
            publisher_trust: github_publisher_trust(),
        });
    }
    if connection_missing {
        steps.push(AccessResolutionStep::ConnectService {
            service_ref: github_service_ref(),
            envelope: github_service_connection_envelope(),
        });
    }
    if !statements.is_empty() {
        steps.push(AccessResolutionStep::IssueGrant {
            grant_delta: GrantDelta {
                statements,
                // Narrow dev workflow default: short enough for a working
                // session, explicit enough for the operator to shorten later.
                ttl_secs: 4 * 60 * 60,
                delegation: None,
            },
        });
    }

    let eligible = blockers.is_empty()
        && candidate.installed
        && !connection_missing
        && status == PreflightStatus::Prompt;
    let reason = if eligible {
        "core-vetted GitHub PR creation with one concrete repository and exact feature branch target evidence"
    } else {
        blockers[0]
    };
    let mut reasons = Vec::new();
    if eligible {
        reasons.extend([
            "signed bundled ember-gh action manifest".to_string(),
            "trusted target evidence names one GitHub repository".to_string(),
            "exact non-protected branch target evidence".to_string(),
            "grant delta projected from bundled manifest need".to_string(),
            "credential materialization remains daemon-side until approval".to_string(),
        ]);
    } else {
        reasons.extend(blockers.iter().map(|b| (*b).to_string()));
        if !candidate.installed {
            reasons.push(
                "Available Service Index matched the bundled GitHub Service from non-secret action metadata"
                    .to_string(),
            );
        }
    }

    Some(AccessResolutionPlan {
        denied_action,
        target: TypedTargetSelector {
            kind: "github_repository_branch",
            provider: "github",
            repo,
            branch,
        },
        target_evidence: TargetEvidence {
            source: if candidate.installed {
                "planned_action_target"
            } else {
                "available_service_index_candidate"
            },
            extractor: if !candidate.installed {
                "available_service_index_github_pr_create"
            } else if action.target_evidence_trusted {
                "core_vetted_ember_gh"
            } else {
                "untrusted_action_evidence"
            },
            confidence: if !candidate.installed {
                "advisory"
            } else if action.target_evidence_trusted {
                "trusted"
            } else {
                "untrusted"
            },
        },
        steps,
        collapse_eligibility: CollapseEligibility {
            eligible,
            reason: reason.to_string(),
        },
        reasons,
    })
}

/// Pure verdict for one planned action. Extracted from the handler so the
/// covered/prompt/deny/missing decision tree is unit-testable without a store.
fn classify_preflight_action(
    action: &PlannedAction,
    statement_action_lists: &[Vec<String>],
    template_scope_lists: Option<&[Vec<String>]>,
    posture: &PreflightPosture,
    configured: &HashMap<core_broker::BrokerProvider, bool>,
) -> (PreflightStatus, String, Option<String>) {
    // `missing` — Ember cannot evaluate honestly because the action is not
    // fully declared (no structured action ref). Distinct from `deny`.
    if action.action_ref.is_none() || action.plugin_address.is_none() {
        return (
            PreflightStatus::Missing,
            "service action is not fully declared (no structured action ref); reinstall or update the service".to_string(),
            Some(format!("ember service show {}", action.service)),
        );
    }

    // `missing` — broker credential not provisioned. An action whose broker
    // provider has no real credential cannot mint at runtime even if a grant
    // covers it, so the absent prerequisite takes precedence over coverage.
    // Generalized across every BrokerProvider: any referenced provider that the
    // resolver probed as unconfigured trips `missing` with a per-provider setup
    // hint. Providers absent from the map (unreferenced, or resolver
    // unavailable) default to configured, so we never raise a false `missing`.
    for r in &action.authority_refs {
        if let Some(provider) = broker_provider_from_authority_ref(r)
            && configured.get(&provider) == Some(&false)
        {
            return (
                PreflightStatus::Missing,
                format!("{r} brokering is not configured, so this action cannot mint a credential"),
                Some(format!("run `ember {r} setup` to provision {r}")),
            );
        }
    }

    // `covered` — an active grant authorizes this service. For a delegated lane
    // (`template_scope_lists` present) the lane authority is the parent
    // delegable grant *narrowed by* the delegation template, so coverage requires
    // BOTH the standing parent grant AND the template to admit the service
    // (intersection, service-level per ADR 187 §10). When no template is in
    // play the standing-grant match alone decides coverage.
    let covered = preflight_action_is_covered(action, statement_action_lists)
        && match template_scope_lists {
            Some(template_lists) => preflight_action_is_covered(action, template_lists),
            None => true,
        };
    if covered {
        let reason = if template_scope_lists.is_some() {
            "the delegable grant and the delegation template both authorize this service"
        } else {
            "an active grant already authorizes this service"
        };
        return (PreflightStatus::Covered, reason.to_string(), None);
    }

    // Manifest deny-by-default is never approvable.
    if action.default_policy.as_deref() == Some("deny") {
        return (
            PreflightStatus::Deny,
            "the service marks this action deny-by-default".to_string(),
            None,
        );
    }

    // `prompt` must never appear for strict or unattended lanes.
    if posture.strict {
        return (
            PreflightStatus::Deny,
            "strict lane denies out-of-scope actions instead of prompting".to_string(),
            Some(
                "pre-grant the scope before launch (ember grant ...) or launch without --strict"
                    .to_string(),
            ),
        );
    }
    if posture.headless {
        return (
            PreflightStatus::Deny,
            "unattended lane cannot prompt; out-of-scope actions fail closed".to_string(),
            Some("widen the headless template or pre-grant the scope before enrolling".to_string()),
        );
    }

    (
        PreflightStatus::Prompt,
        "out of scope now; the jit lane will ask to Approve once at first use".to_string(),
        Some("approve at runtime, or pre-grant ahead of time with ember grant ...".to_string()),
    )
}

/// `preflight_authority_coverage` JSON-RPC handler (ConnectOnly, read-only).
///
/// Params:
///   { "persona"?: "<id>",
///     "posture"?: { "fallback": "jit"|"strict", "context": "interactive"|"headless" },
///     "delegation_template"?: "<name>",
///     "inline_template_scope"?: ["<action_ref>", ...],
///     "actions": [ { "service", "action_ref"?, "plugin_address"?,
///                    "default_policy"?, "authority_refs"?: [..] }, ... ] }
///
/// When `delegation_template` or `inline_template_scope` is supplied the lane is a
/// delegated launch: coverage is computed against the parent delegable grant
/// *narrowed by* the template scope (intersection), mirroring the grant the
/// launcher will mint, so the operator sees the lane-effective answer rather than
/// the durable persona's full standing-grant rollup (which would over-count).
/// `inline_template_scope` is the ad-hoc form `ember catalog plan` uses to
/// preview a lane it is shaping before any template is saved; it takes
/// precedence over `delegation_template`.
///
/// Result: JSON array of rows
///   { "service", "action_ref", "status": "covered"|"prompt"|"deny"|"missing",
///     "reason", "material_summary"?, "next_action"? }.
pub(super) async fn handle_preflight_authority_coverage(
    ctx: &RequestContext,
    params: &Value,
    store: &DaemonStore,
) -> Result<Value, (i32, String)> {
    // Optional persona filter; persona-scoped + fail-closed on multi-uid tiers.
    let persona = crate::infra::handlers::principal::persona_scoped_param_for_connect_only(
        ctx,
        params,
        "preflight_authority_coverage",
        "persona",
        false,
    )?;

    let posture = PreflightPosture {
        strict: params
            .get("posture")
            .and_then(|p| p.get("fallback"))
            .and_then(|v| v.as_str())
            == Some("strict"),
        headless: params
            .get("posture")
            .and_then(|p| p.get("context"))
            .and_then(|v| v.as_str())
            == Some("headless"),
    };

    // Optional delegated-lane signal: the delegation template the launcher will
    // mint the session grant from. Present ⇒ compute lane-effective (parent ∩
    // template) coverage; absent ⇒ standing-grant coverage.
    let delegation_template_name = params
        .get("delegation_template")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string);

    // Optional inline delegated scope: an ad-hoc list of action-ref strings that
    // stands in for a named template. `ember catalog plan` (ADR 194) uses this to
    // preview a delegated lane it is *shaping* — the plan has no saved template
    // yet, so it passes its proposed scope inline and the daemon runs the same
    // parent-delegable-grant ∩ scope intersection. Takes precedence over
    // `delegation_template` when both are supplied.
    let inline_template_scope: Option<Vec<String>> = params
        .get("inline_template_scope")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        });

    let actions_value = params.get("actions").and_then(|v| v.as_array()).ok_or((
        -32602,
        "missing 'actions' parameter (array of planned actions)".to_string(),
    ))?;
    let mut actions: Vec<PlannedAction> = Vec::with_capacity(actions_value.len());
    for (idx, raw) in actions_value.iter().enumerate() {
        let service = raw
            .get("service")
            .and_then(|v| v.as_str())
            .ok_or((-32602, format!("actions[{idx}]: missing string 'service'")))?
            .to_string();
        let action_ref = raw
            .get("action_ref")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let plugin_address = raw
            .get("plugin_address")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let default_policy = raw
            .get("default_policy")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let authority_refs = raw
            .get("authority_refs")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        actions.push(PlannedAction {
            service,
            action_ref,
            plugin_address,
            default_policy,
            authority_refs,
            target_repo: planned_target_string(raw, "repo", "target_repo"),
            target_branch: planned_target_string(raw, "branch", "target_branch"),
            target_provider: planned_target_string(raw, "provider", "target_provider"),
            semantic_labels: raw
                .get("semantic_labels")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            target_evidence_trusted: planned_bool(
                raw,
                "evidence_trusted",
                "target_evidence_trusted",
                true,
            ),
            target_native_scope: planned_target_has_native_scope(raw),
            service_connection_scope: planned_service_connection_scope(raw),
        });
    }

    // Probe whether each referenced broker provider is really provisioned (App,
    // PAT, long-lived creds, ...) so the verdict can mark provider-backed actions
    // `missing` when the credential is absent. Mint-free: `resolve` loads config
    // without issuing a token. Best-effort — when the resolver is unavailable or
    // a probe errors we default to "configured" so we never raise a false
    // `missing`. Only providers referenced by the planned actions are probed.
    let mut configured: HashMap<core_broker::BrokerProvider, bool> = HashMap::new();
    if let Some(resolver) = crate::broker::authority::BrokerAuthorityResolver::current() {
        let mut referenced: Vec<core_broker::BrokerProvider> = actions
            .iter()
            .flat_map(|a| a.authority_refs.iter())
            .filter_map(|r| broker_provider_from_authority_ref(r))
            .collect();
        referenced.sort_by_key(|p| p.as_str());
        referenced.dedup();
        for provider in referenced {
            let is_configured = resolver
                .resolve(provider)
                .await
                .map(|opt| opt.is_some())
                .unwrap_or(true);
            configured.insert(provider, is_configured);
        }
    }

    // Collect active grant statement actions (optionally persona-filtered) from
    // the daemon's own store — the authority root owns the coverage truth.
    // `delegable_statement_action_lists` is the subset minted from grants that
    // can be delegated (`max_delegation_depth > 0`) — the parent authority a
    // delegated launch narrows, mirroring `resolve_register_session_active_grant`.
    let grants = store
        .list_active_grants()
        .map_err(|e| (-32000, format!("list active grants: {e}")))?;
    let mut statement_action_lists: Vec<Vec<String>> = Vec::new();
    let mut delegable_statement_action_lists: Vec<Vec<String>> = Vec::new();
    for grant in &grants {
        if let Some(ref p) = persona
            && &grant.persona_id != p
        {
            continue;
        }
        let is_delegable = grant.max_delegation_depth.unwrap_or(0) > 0;
        let grant_lists: Vec<Vec<String>> = match store.get_access_grant(&grant.id) {
            Ok(access_grant) => access_grant
                .statements()
                .map(|(_, stmt)| stmt.actions.clone())
                .collect(),
            // Fall back to the flat scope column when the signed chain is
            // unavailable so the grant still contributes to coverage.
            Err(_) => vec![vec![grant.scope.clone()]],
        };
        if is_delegable {
            delegable_statement_action_lists.extend(grant_lists.iter().cloned());
        }
        statement_action_lists.extend(grant_lists);
    }

    // Resolve the delegated-lane template scope (best-effort): on success the
    // coverage source switches to the parent delegable grant intersected with
    // the template; on failure (missing/unreadable) we log and fall back to
    // standing-grant coverage so preflight never hard-fails the launch preview.
    // An inline scope (the plan's proposed action refs) takes precedence over a
    // named template — the catalog planner shapes a lane that has no saved
    // template yet, so it carries its own scope.
    let template_scope_lists: Option<Vec<Vec<String>>> = if let Some(inline) = inline_template_scope
    {
        Some(
            inline
                .into_iter()
                .map(|action_ref| vec![action_ref])
                .collect(),
        )
    } else {
        delegation_template_name.as_deref().and_then(|name| {
            match crate::infra::handlers::session::resolve_delegation_template(name) {
                Ok(template) => Some(
                    template
                        .scopes
                        .iter()
                        .map(|scope| vec![scope.to_string()])
                        .collect(),
                ),
                Err((code, msg)) => {
                    tracing::warn!(
                        template = %name,
                        code,
                        reason = %msg,
                        "preflight: delegated-authority template unresolved; falling back to standing-grant coverage",
                    );
                    None
                }
            }
        })
    };

    // For a delegated lane the parent authority is the delegable grant set; for
    // a standing lane it is every active grant. The template (when resolved)
    // narrows the parent via intersection inside `classify_preflight_action`.
    let (base_statement_action_lists, template_scope_slice) = match template_scope_lists.as_deref()
    {
        Some(template_lists) => (
            delegable_statement_action_lists.as_slice(),
            Some(template_lists),
        ),
        None => (statement_action_lists.as_slice(), None),
    };

    let rows: Vec<Value> = actions
        .iter()
        .map(|action| {
            let (status, reason, next_action) = classify_preflight_action(
                action,
                base_statement_action_lists,
                template_scope_slice,
                &posture,
                &configured,
            );
            let material_summary = (!action.authority_refs.is_empty())
                .then(|| format!("broker: {}", action.authority_refs.join(", ")));
            let mut row = json!({
                "service": action.service,
                "action_ref": action.action_ref,
                "status": status.as_str(),
                "reason": reason,
                "material_summary": material_summary,
                "next_action": next_action,
            });
            if let Some(plan) = resolve_access_plan_for_action(action, status, &configured) {
                row["access_resolution_plan"] = serde_json::to_value(plan)
                    .expect("AccessResolutionPlan serialization is infallible");
            }
            row
        })
        .collect();

    Ok(Value::Array(rows))
}

#[cfg(test)]
mod catalog_search_actions_tests {
    use super::handle_catalog_search_actions;
    use serde_json::json;

    #[test]
    fn projects_action_manifest_identity_need_and_policy() {
        let result =
            handle_catalog_search_actions(&json!({"service": "ember-gh", "query": "pr_list"}))
                .expect("catalog search succeeds");
        let actions = result["actions"].as_array().expect("actions array");
        let row = actions
            .iter()
            .find(|row| row["action_key"] == "pr_list")
            .expect("pr_list row");

        assert_eq!(row["service"], "ember-gh");
        assert_eq!(
            row["action_ref"],
            "registry.ember.systems/ember-systems/ember-gh/pr_list@v1"
        );
        assert_eq!(row["default_policy"], "permit");
        assert_eq!(row["risk_tier"], "low");
        assert_eq!(
            row["need"],
            json!(["github:metadata:read", "github:pull_request:read"])
        );
        assert_eq!(row["authority_refs"], json!(["github"]));
    }

    #[test]
    fn applies_limit_and_does_not_project_invocation_tools() {
        let result = handle_catalog_search_actions(&json!({"query": "github", "limit": 2}))
            .expect("catalog search succeeds");
        let actions = result["actions"].as_array().expect("actions array");
        assert_eq!(actions.len(), 2);
        assert!(
            actions
                .iter()
                .all(|row| row.get("invoke").is_none() && row.get("tool_name").is_none()),
            "catalog rows are metadata projections, not dynamic action.invoke shims"
        );
    }
}

#[cfg(test)]
mod preflight_authority_coverage_tests {
    use super::{
        AccessResolutionStep, PlannedAction, PreflightPosture, PreflightStatus,
        classify_preflight_action,
    };
    use core_broker::BrokerProvider;
    use core_grant_types::{ResourceSelector, ResourceType};
    use std::collections::HashMap;

    /// Empty map — no provider was probed as unconfigured, so every action is
    /// treated as having its broker credential provisioned (the resolver-absent
    /// / all-configured default).
    fn all_configured() -> HashMap<BrokerProvider, bool> {
        HashMap::new()
    }

    /// GitHub probed as unconfigured; every other provider defaults to configured.
    fn github_unconfigured() -> HashMap<BrokerProvider, bool> {
        HashMap::from([(BrokerProvider::Github, false)])
    }

    fn action(
        service: &str,
        action_ref: Option<&str>,
        plugin_address: Option<&str>,
        default_policy: Option<&str>,
        authority_refs: &[&str],
    ) -> PlannedAction {
        PlannedAction {
            service: service.to_string(),
            action_ref: action_ref.map(str::to_string),
            plugin_address: plugin_address.map(str::to_string),
            default_policy: default_policy.map(str::to_string),
            authority_refs: authority_refs.iter().map(|s| s.to_string()).collect(),
            target_repo: None,
            target_branch: None,
            target_provider: None,
            semantic_labels: Vec::new(),
            target_evidence_trusted: true,
            target_native_scope: false,
            service_connection_scope: None,
        }
    }

    const JIT: PreflightPosture = PreflightPosture {
        strict: false,
        headless: false,
    };
    const STRICT: PreflightPosture = PreflightPosture {
        strict: true,
        headless: false,
    };
    const HEADLESS: PreflightPosture = PreflightPosture {
        strict: false,
        headless: true,
    };

    fn gh_pr_create() -> PlannedAction {
        action(
            "ember-gh",
            Some("registry.ember.systems/ember-systems/ember-gh/pr_create@v1"),
            Some("registry.ember.systems/ember-systems/ember-gh"),
            Some("prompt"),
            &["github"],
        )
    }

    fn gh_pr_create_with_target(repo: &str, branch: &str) -> PlannedAction {
        let mut action = gh_pr_create();
        action.target_repo = Some(repo.to_string());
        action.target_branch = Some(branch.to_string());
        action.target_provider = Some("github".to_string());
        action
    }

    fn gh_pr_merge_with_target(repo: &str, branch: &str) -> PlannedAction {
        let mut action = action(
            "ember-gh",
            Some("registry.ember.systems/ember-systems/ember-gh/pr_merge@v1"),
            Some("registry.ember.systems/ember-systems/ember-gh"),
            Some("prompt"),
            &["github"],
        );
        action.target_repo = Some(repo.to_string());
        action.target_branch = Some(branch.to_string());
        action.target_provider = Some("github".to_string());
        action
    }

    fn missing_github_pr_create_candidate_with_target(repo: &str, branch: &str) -> PlannedAction {
        PlannedAction {
            service: "github".to_string(),
            action_ref: None,
            plugin_address: None,
            default_policy: Some("prompt".to_string()),
            authority_refs: Vec::new(),
            target_repo: Some(repo.to_string()),
            target_branch: Some(branch.to_string()),
            target_provider: Some("github".to_string()),
            semantic_labels: vec!["github.pull_request.write".to_string()],
            target_evidence_trusted: true,
            target_native_scope: false,
            service_connection_scope: None,
        }
    }

    #[test]
    fn covered_when_legacy_authority_ref_grant_targets_service() {
        let stmts = vec![vec!["github:pull_request:create".to_string()]];
        let (status, _, _) =
            classify_preflight_action(&gh_pr_create(), &stmts, None, &JIT, &all_configured());
        assert_eq!(status, PreflightStatus::Covered);
    }

    #[test]
    fn covered_when_structured_action_ref_grant_targets_plugin_address() {
        let stmts = vec![vec![
            "registry.ember.systems/ember-systems/ember-gh/pr_merge@v1".to_string(),
        ]];
        let (status, _, _) =
            classify_preflight_action(&gh_pr_create(), &stmts, None, &STRICT, &all_configured());
        assert_eq!(status, PreflightStatus::Covered);
    }

    #[test]
    fn covered_by_global_wildcard_statement() {
        let stmts = vec![vec!["*".to_string()]];
        let (status, _, _) =
            classify_preflight_action(&gh_pr_create(), &stmts, None, &HEADLESS, &all_configured());
        assert_eq!(status, PreflightStatus::Covered);
    }

    #[test]
    fn prompt_when_uncovered_under_jit_interactive() {
        let (status, _, next) =
            classify_preflight_action(&gh_pr_create(), &[], None, &JIT, &all_configured());
        assert_eq!(status, PreflightStatus::Prompt);
        assert!(next.is_some());
    }

    #[test]
    fn resolve_access_plan_for_narrow_gh_pr_create_projects_grant_delta() {
        let action = gh_pr_create_with_target("emberdotlink/emberlink-dev", "feat/resolve-access");
        let plan = super::resolve_access_plan_for_action(
            &action,
            PreflightStatus::Prompt,
            &all_configured(),
        )
        .expect("narrow core-vetted gh pr create should produce a collapsed plan");

        assert_eq!(
            plan.denied_action,
            "registry.ember.systems/ember-systems/ember-gh/pr_create@v1"
        );
        assert!(plan.collapse_eligibility.eligible);
        assert_eq!(plan.target.repo, "emberdotlink/emberlink-dev");
        assert_eq!(plan.target.branch, "feat/resolve-access");
        let AccessResolutionStep::IssueGrant { grant_delta } = &plan.steps[0] else {
            panic!("first collapsed step should issue the grant");
        };
        assert_eq!(
            grant_delta
                .statements
                .iter()
                .flat_map(|s| s.actions.iter())
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "github:metadata:read".to_string(),
                "github:contents:write".to_string(),
                "github:pull_request:create".to_string(),
            ]
        );
        assert!(grant_delta.delegation.is_none());
        assert_eq!(grant_delta.ttl_secs, 4 * 60 * 60);
        for stmt in &grant_delta.statements {
            assert_eq!(stmt.credential_name, "github");
            assert_eq!(stmt.resource_type, ResourceType::Credential);
            assert_eq!(
                stmt.resource,
                ResourceSelector::Exact {
                    value: "emberdotlink/emberlink-dev".to_string(),
                }
            );
        }
    }

    #[test]
    fn resolve_access_plan_requires_concrete_feature_branch_target() {
        assert!(
            super::resolve_access_plan_for_action(
                &gh_pr_create(),
                PreflightStatus::Prompt,
                &all_configured(),
            )
            .is_none(),
            "static catalog preflight without target evidence is not an action-intent plan"
        );

        let mut missing_branch = gh_pr_create();
        missing_branch.target_repo = Some("emberdotlink/emberlink-dev".to_string());
        missing_branch.target_provider = Some("github".to_string());
        let plan = super::resolve_access_plan_for_action(
            &missing_branch,
            PreflightStatus::Prompt,
            &all_configured(),
        )
        .expect("partial GitHub target evidence should produce a blocked plan");
        assert!(!plan.collapse_eligibility.eligible);
        assert!(plan.collapse_eligibility.reason.contains("branch"));

        let main_branch = gh_pr_create_with_target("emberdotlink/emberlink-dev", "main");
        let plan = super::resolve_access_plan_for_action(
            &main_branch,
            PreflightStatus::Prompt,
            &all_configured(),
        )
        .expect("unsafe GitHub intent still gets a structured plan");
        assert!(!plan.collapse_eligibility.eligible);
        assert!(plan.collapse_eligibility.reason.contains("protected"));

        let wildcard_repo = gh_pr_create_with_target("emberdotlink/*", "feat/resolve-access");
        let plan = super::resolve_access_plan_for_action(
            &wildcard_repo,
            PreflightStatus::Prompt,
            &all_configured(),
        )
        .expect("unsafe GitHub intent still gets a structured plan");
        assert!(!plan.collapse_eligibility.eligible);
        assert!(
            plan.collapse_eligibility
                .reason
                .contains("every repository")
        );

        let already_covered =
            gh_pr_create_with_target("emberdotlink/emberlink-dev", "feat/resolve-access");
        assert!(
            super::resolve_access_plan_for_action(
                &already_covered,
                PreflightStatus::Covered,
                &all_configured(),
            )
            .is_none()
        );
    }

    #[test]
    fn resolve_access_plan_rejects_unsafe_github_collapse() {
        let cases = [
            (
                gh_pr_create_with_target("*", "feat/resolve-access"),
                "all GitHub repositories",
            ),
            (
                gh_pr_create_with_target("all_repos", "feat/resolve-access"),
                "all GitHub repositories",
            ),
            (
                gh_pr_create_with_target("emberdotlink/emberlink-dev", "production"),
                "protected or production branch",
            ),
            (
                gh_pr_merge_with_target("emberdotlink/emberlink-dev", "feat/resolve-access"),
                "pr_merge@v1",
            ),
        ];

        for (action, reason) in cases {
            let plan = super::resolve_access_plan_for_action(
                &action,
                PreflightStatus::Prompt,
                &all_configured(),
            )
            .expect("unsafe GitHub intent should still have a Resolve Access plan");
            assert!(!plan.collapse_eligibility.eligible, "{reason}");
            assert!(
                plan.collapse_eligibility.reason.contains(reason),
                "reason {:?} should contain {reason}",
                plan.collapse_eligibility.reason
            );
        }

        let mut opaque_scope =
            gh_pr_create_with_target("emberdotlink/emberlink-dev", "feat/resolve-access");
        opaque_scope.target_native_scope = true;
        let plan = super::resolve_access_plan_for_action(
            &opaque_scope,
            PreflightStatus::Prompt,
            &all_configured(),
        )
        .expect("opaque native-scope target still gets a blocked plan");
        assert!(!plan.collapse_eligibility.eligible);
        assert!(
            plan.collapse_eligibility
                .reason
                .contains("provider-native scope")
        );

        let mut broad_connection =
            gh_pr_create_with_target("emberdotlink/emberlink-dev", "feat/resolve-access");
        broad_connection.service_connection_scope = Some("all_repos".to_string());
        let plan = super::resolve_access_plan_for_action(
            &broad_connection,
            PreflightStatus::Prompt,
            &all_configured(),
        )
        .expect("broad Service Connection still gets a blocked plan");
        assert!(!plan.collapse_eligibility.eligible);
        assert!(
            plan.collapse_eligibility
                .reason
                .contains("Service Connection")
        );

        let mut untrusted =
            gh_pr_create_with_target("emberdotlink/emberlink-dev", "feat/resolve-access");
        untrusted.plugin_address = Some("registry.example.test/acme/gh".to_string());
        untrusted.action_ref = Some("registry.example.test/acme/gh/pr_create@v1".to_string());
        untrusted.target_evidence_trusted = false;
        let plan = super::resolve_access_plan_for_action(
            &untrusted,
            PreflightStatus::Prompt,
            &all_configured(),
        )
        .expect("untrusted action evidence still gets a blocked plan");
        assert!(!plan.collapse_eligibility.eligible);
        assert!(plan.reasons.iter().any(|r| r.contains("Action proof")));
        assert!(plan.reasons.iter().any(|r| r.contains("Target evidence")));
    }

    #[test]
    fn resolve_access_plan_discovers_missing_github_service_before_grant() {
        let action = missing_github_pr_create_candidate_with_target(
            "emberdotlink/emberlink-dev",
            "feat/resolve-access",
        );
        let plan = super::resolve_access_plan_for_action(
            &action,
            PreflightStatus::Missing,
            &all_configured(),
        )
        .expect("Available Service Index should suggest bundled GitHub Service");

        assert!(!plan.collapse_eligibility.eligible);
        assert!(plan.collapse_eligibility.reason.contains("installed"));
        assert_eq!(plan.target_evidence.confidence, "advisory");
        assert_eq!(plan.steps.len(), 3);
        assert!(matches!(
            &plan.steps[0],
            AccessResolutionStep::InstallService { .. }
        ));
        assert!(matches!(
            &plan.steps[1],
            AccessResolutionStep::ConnectService { .. }
        ));
        let AccessResolutionStep::IssueGrant { grant_delta } = &plan.steps[2] else {
            panic!("grant should remain last after install/connect readiness");
        };
        assert_eq!(grant_delta.statements.len(), 3);
        assert!(
            plan.reasons
                .iter()
                .any(|r| r.contains("Available Service Index"))
        );
    }

    #[test]
    fn broad_service_connection_envelope_does_not_collapse_without_policy_permission() {
        let mut action =
            gh_pr_create_with_target("emberdotlink/emberlink-dev", "feat/resolve-access");
        action.service_connection_scope = Some("all_repos".to_string());

        let plan = super::resolve_access_plan_for_action(
            &action,
            PreflightStatus::Prompt,
            &all_configured(),
        )
        .expect("broad Service Connection still gets a blocked plan");

        assert!(!plan.collapse_eligibility.eligible);
        assert!(
            plan.reasons
                .iter()
                .any(|reason| reason.contains("Service Connection is broader")),
            "broad Service Connection envelope must not collapse into Action authority: {plan:?}"
        );
    }

    #[test]
    fn resolve_access_plan_connects_installed_github_service_before_grant() {
        let action = gh_pr_create_with_target("emberdotlink/emberlink-dev", "feat/resolve-access");
        let plan = super::resolve_access_plan_for_action(
            &action,
            PreflightStatus::Missing,
            &github_unconfigured(),
        )
        .expect("installed GitHub Service with missing connection should still produce plan");

        assert!(!plan.collapse_eligibility.eligible);
        assert!(
            plan.collapse_eligibility
                .reason
                .contains("Service Connection")
        );
        assert_eq!(plan.steps.len(), 2);
        assert!(matches!(
            &plan.steps[0],
            AccessResolutionStep::ConnectService { .. }
        ));
        assert!(matches!(
            &plan.steps[1],
            AccessResolutionStep::IssueGrant { .. }
        ));
    }

    #[test]
    fn deny_when_uncovered_under_strict() {
        let (status, _, _) =
            classify_preflight_action(&gh_pr_create(), &[], None, &STRICT, &all_configured());
        assert_eq!(status, PreflightStatus::Deny);
    }

    #[test]
    fn deny_when_uncovered_under_headless() {
        let (status, _, _) =
            classify_preflight_action(&gh_pr_create(), &[], None, &HEADLESS, &all_configured());
        assert_eq!(status, PreflightStatus::Deny);
    }

    #[test]
    fn deny_when_manifest_default_policy_is_deny() {
        let act = action(
            "ember-gh",
            Some("registry.ember.systems/ember-systems/ember-gh/pr_create@v1"),
            Some("registry.ember.systems/ember-systems/ember-gh"),
            Some("deny"),
            &["github"],
        );
        let (status, _, _) = classify_preflight_action(&act, &[], None, &JIT, &all_configured());
        assert_eq!(status, PreflightStatus::Deny);
    }

    #[test]
    fn missing_when_action_ref_not_declared() {
        let act = action("legacy-svc", None, None, Some("permit"), &[]);
        let (status, _, next) = classify_preflight_action(&act, &[], None, &JIT, &all_configured());
        assert_eq!(status, PreflightStatus::Missing);
        assert!(next.is_some());
    }

    #[test]
    fn unrelated_grant_does_not_cover() {
        let stmts = vec![vec!["aws_sts:assume_role".to_string()]];
        let (status, _, _) =
            classify_preflight_action(&gh_pr_create(), &stmts, None, &JIT, &all_configured());
        assert_eq!(status, PreflightStatus::Prompt);
    }

    #[test]
    fn missing_when_github_not_configured_takes_precedence_over_grant() {
        // A grant targets github, but the broker credential isn't provisioned,
        // so the action can't mint at runtime — `missing` beats `covered`.
        let stmts = vec![vec!["github:pull_request:create".to_string()]];
        let (status, _, next) =
            classify_preflight_action(&gh_pr_create(), &stmts, None, &JIT, &github_unconfigured());
        assert_eq!(status, PreflightStatus::Missing);
        assert!(next.is_some_and(|n| n.contains("ember github setup")));
    }

    #[test]
    fn github_unconfigured_does_not_affect_non_github_service() {
        let act = action(
            "ember-aws",
            Some("registry.ember.systems/ember-systems/ember-aws/assume_role@v1"),
            Some("registry.ember.systems/ember-systems/ember-aws"),
            Some("prompt"),
            &["aws_sts"],
        );
        let (status, _, _) =
            classify_preflight_action(&act, &[], None, &JIT, &github_unconfigured());
        assert_eq!(status, PreflightStatus::Prompt);
    }

    #[test]
    fn missing_for_non_github_provider_when_unconfigured() {
        let act = action(
            "ember-aws",
            Some("registry.ember.systems/ember-systems/ember-aws/assume_role@v1"),
            Some("registry.ember.systems/ember-systems/ember-aws"),
            Some("prompt"),
            &["aws_sts"],
        );
        let configured = HashMap::from([(BrokerProvider::AwsSts, false)]);
        let (status, _, next) = classify_preflight_action(&act, &[], None, &JIT, &configured);
        assert_eq!(status, PreflightStatus::Missing);
        assert!(next.is_some_and(|n| n.contains("ember aws_sts setup")));
    }

    // --- delegated lane: parent delegable grant ∩ delegation template ---

    fn gh_template() -> Vec<Vec<String>> {
        vec![vec![
            "registry.ember.systems/ember-systems/ember-gh/*@v1".to_string(),
        ]]
    }
    fn git_template() -> Vec<Vec<String>> {
        vec![vec![
            "registry.ember.systems/ember-systems/ember-git/*@v1".to_string(),
        ]]
    }

    #[test]
    fn delegated_covered_when_parent_and_template_both_admit_service() {
        let parent = vec![vec!["github:pull_request:create".to_string()]];
        let template = gh_template();
        let (status, reason, _) = classify_preflight_action(
            &gh_pr_create(),
            &parent,
            Some(&template),
            &STRICT,
            &all_configured(),
        );
        assert_eq!(status, PreflightStatus::Covered);
        assert!(
            reason.contains("delegation template"),
            "delegated covered reason should name the template: {reason}"
        );
    }

    #[test]
    fn delegated_deny_when_template_does_not_admit_service() {
        // Parent covers ember-gh, but the template narrows the lane to ember-git,
        // so a gh action is out of the intersection.
        let parent = vec![vec!["github:pull_request:create".to_string()]];
        let template = git_template();
        let (status, _, _) = classify_preflight_action(
            &gh_pr_create(),
            &parent,
            Some(&template),
            &STRICT,
            &all_configured(),
        );
        assert_eq!(status, PreflightStatus::Deny);
    }

    #[test]
    fn delegated_deny_when_parent_does_not_admit_service() {
        // The template admits ember-gh, but the parent delegable grant does not,
        // so the intersection is empty for a gh action.
        let parent = vec![vec!["aws_sts:assume_role".to_string()]];
        let template = gh_template();
        let (status, _, _) = classify_preflight_action(
            &gh_pr_create(),
            &parent,
            Some(&template),
            &STRICT,
            &all_configured(),
        );
        assert_eq!(status, PreflightStatus::Deny);
    }

    #[test]
    fn delegated_prompt_under_jit_when_intersection_empty() {
        // Out of the intersection under a jit lane prompts rather than denies,
        // same fallback ordering as the standing-grant path.
        let parent = vec![vec!["github:pull_request:create".to_string()]];
        let template = git_template();
        let (status, _, next) = classify_preflight_action(
            &gh_pr_create(),
            &parent,
            Some(&template),
            &JIT,
            &all_configured(),
        );
        assert_eq!(status, PreflightStatus::Prompt);
        assert!(next.is_some());
    }
}
