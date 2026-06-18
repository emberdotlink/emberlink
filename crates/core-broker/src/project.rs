//! Per-provider native-scope projectors (ADR 204 — materialization =
//! downhill projection of `(action-need ∩ grant)`).
//!
//! This module is the **only** code permitted to speak a provider's native
//! scope language. Native scope is never an input to a mint — it is a pure
//! derived projection of the grant-bounded, concrete *action-need*. A
//! [`NativeProjector`] takes a set of [`ResolvedNeed`]s (already verified
//! `⊆` the matched grant by the gate) and produces the provider's native
//! wire payload, fail-closed on anything it cannot represent — and it
//! **never emits empty/wildcard** (empty github repos/permissions = a full
//! installation token; that footgun cannot arise here).
//!
//! The inverse, [`NativeProjector::native_upper_bound`], reconstructs the
//! abstract envelope of a native payload. The *gate* — not the projector —
//! is the judge: it asserts (1) the original `owner/repo` needs `⊆ grant`
//! (authority, owner-aware) and (2) `native_upper_bound(native)` equals the
//! wire-space projection of those needs (faithfulness — the projector
//! neither widened nor invented). This second check is meaningful only
//! because [`GithubProjector::project`] is rectangular-or-refuse: a
//! non-rectangular merge that silently widened would be caught, not
//! round-tripped back to itself.
//!
//! An *adversarial* projector controls both halves of the round-trip and is
//! the compromised-daemon case (PR4c-bracketed — see ADR 204 §dev0); the
//! self-check defends against an *accidentally* widening projector.
//!
//! Pure, no I/O — wasm32-compatible, like the rest of the trait crate.

use std::collections::{BTreeMap, BTreeSet};

use core_grant_types::ResourceSelector;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{BrokerProvider, BrokerScope};

/// Access level on a capability. Totally ordered so a projector can take the
/// per-permission maximum when merging needs: `Read < Write < Admin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Read,
    Write,
    Admin,
}

impl Level {
    /// GitHub installation-permission level string.
    pub fn github_str(self) -> &'static str {
        match self {
            Level::Read => "read",
            Level::Write => "write",
            Level::Admin => "admin",
        }
    }

    pub fn parse_github(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Level::Read),
            // GitHub uses "write" for the read+write installation level.
            "write" => Some(Level::Write),
            "admin" => Some(Level::Admin),
            _ => None,
        }
    }
}

/// A GitHub installation permission — a **closed** vocabulary. An unknown
/// permission name is a parse-time refusal, never a silent passthrough.
/// Mirrors the GitHub App installation-token permission keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GithubPermission {
    Contents,
    PullRequests,
    Actions,
    Issues,
    Metadata,
    Workflows,
    Checks,
    Deployments,
    Statuses,
    Administration,
    Packages,
}

impl GithubPermission {
    /// The GitHub API permission key (snake_case, as the access-token
    /// endpoint expects).
    pub fn api_name(self) -> &'static str {
        match self {
            GithubPermission::Contents => "contents",
            GithubPermission::PullRequests => "pull_requests",
            GithubPermission::Actions => "actions",
            GithubPermission::Issues => "issues",
            GithubPermission::Metadata => "metadata",
            GithubPermission::Workflows => "workflows",
            GithubPermission::Checks => "checks",
            GithubPermission::Deployments => "deployments",
            GithubPermission::Statuses => "statuses",
            GithubPermission::Administration => "administration",
            GithubPermission::Packages => "packages",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "contents" => GithubPermission::Contents,
            "pull_requests" => GithubPermission::PullRequests,
            "actions" => GithubPermission::Actions,
            "issues" => GithubPermission::Issues,
            "metadata" => GithubPermission::Metadata,
            "workflows" => GithubPermission::Workflows,
            "checks" => GithubPermission::Checks,
            "deployments" => GithubPermission::Deployments,
            "statuses" => GithubPermission::Statuses,
            "administration" => GithubPermission::Administration,
            "packages" => GithubPermission::Packages,
            _ => return None,
        })
    }
}

/// How a provider's native scope relates to grant authority (ADR 204
/// amendment 2). Drives the materialization gate's per-provider behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderClass {
    /// Native scope encodes least-privilege authority (resource/action axes).
    /// The gate projects `(need ∩ grant) → native` and re-asserts
    /// `native_upper_bound(native) ⊆ grant`. (github)
    ScopeAttestable,
    /// Native scope carries **no** authority axes — it is an audit *label*
    /// only (e.g. the anthropic workspace-key name). The real enforcement
    /// boundary is budget + TTL + the proxy meter, so the receipt records
    /// `mint_stamp_kind = "none"` (ADR 213 §D4 G3) and the gate
    /// performs no `native_upper_bound ⊆ grant` check (there is nothing to
    /// bound). (anthropic)
    BudgetLabel,
}

/// A provider-agnostic capability verb. Each variant carries a **closed**
/// per-provider vocabulary. Additional providers (cloudflare, aws_sts,
/// anthropic) land their variants with their projectors (ADR 204 slices).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityVerb {
    /// A GitHub installation permission at a given level.
    Github {
        permission: GithubPermission,
        level: Level,
    },
}

impl CapabilityVerb {
    /// Lower a canonical `github:<object>:<verb>` authority-**need** string
    /// (ADR 205 §1, `provider:object:verb`) into the projector's typed
    /// capability. This is the single front door from the manifest-authored,
    /// grant-compared abstract-need vocabulary (ADR 204 Amendment 6; the
    /// manifest `need` field) into the projector's input — keeping I6 intact
    /// (only the projector speaks native, and `CapabilityVerb` is what it
    /// consumes).
    ///
    /// The need algebra's *object* is the singular GitHub resource noun
    /// (`pull_request`, `contents`, `actions`, …) and its *verb* is the intent
    /// (`read` / `write` / `create` / `merge` / `admin`), coarsened here to the
    /// installation-permission [`Level`] the projector emits — `create` and
    /// `merge` are write-level installation operations, so both map to
    /// [`Level::Write`]. The finer verb distinction is preserved on the
    /// grant-comparison axis (`need ⊆ grant`, exact-match string compare), not
    /// in the projection.
    ///
    /// Returns `None` (fail-closed) for a non-`github` provider, an unknown
    /// object or verb, or a malformed string (not exactly three
    /// colon-separated segments) — the caller treats an unparseable need as a
    /// refused mint, never a wider scope.
    pub fn parse_github_need(need: &str) -> Option<CapabilityVerb> {
        let [provider, object, verb] = *need.split(':').collect::<Vec<_>>().as_slice() else {
            return None;
        };
        if provider != "github" {
            return None;
        }
        let permission = match object {
            "contents" => GithubPermission::Contents,
            "pull_request" => GithubPermission::PullRequests,
            "actions" => GithubPermission::Actions,
            "issues" => GithubPermission::Issues,
            "metadata" => GithubPermission::Metadata,
            "workflows" => GithubPermission::Workflows,
            "checks" => GithubPermission::Checks,
            "deployments" => GithubPermission::Deployments,
            "statuses" => GithubPermission::Statuses,
            "administration" => GithubPermission::Administration,
            "packages" => GithubPermission::Packages,
            _ => return None,
        };
        let level = match verb {
            "read" => Level::Read,
            "write" | "create" | "merge" => Level::Write,
            "admin" => Level::Admin,
            _ => return None,
        };
        Some(CapabilityVerb::Github { permission, level })
    }
}

/// The concrete resource a single action operates on — supplied by the
/// operation itself (e.g. the actual repo being pushed), and checked
/// `⊆ grant.resource` by the gate. It is a *selector*, never a scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConcreteTarget {
    /// A GitHub `owner/repo` as supplied to [`NativeProjector::project`]; the
    /// projector strips the owner for the wire. [`NativeProjector::native_upper_bound`]
    /// returns the bare repo NAME here (the owner is not recoverable from the
    /// wire), so the two are compared in bare-name space.
    Repo(String),
}

/// One grant-bounded, concrete need the gate hands to a projector:
/// `(capability, concrete target)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNeed {
    pub capability: CapabilityVerb,
    pub target: ConcreteTarget,
}

/// Projector failure. Fail-closed: anything a projector cannot faithfully
/// (and narrowly) represent is a refusal, never a wider mint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProjectionError {
    /// The projector declined to emit native scope (e.g. empty needs that
    /// would widen to a full token, a non-rectangular/multi-owner need set,
    /// an unrepresentable target, or a native payload whose upper bound is
    /// unbounded).
    #[error("projector refused: {0}")]
    Refused(String),
    /// A native payload could not be parsed back to its abstract envelope.
    #[error("native scope unparseable: {0}")]
    Unparseable(String),
}

/// The trait every per-provider projector honors. The **only** code that
/// speaks native scope.
pub trait NativeProjector {
    fn provider(&self) -> BrokerProvider;

    /// Project grant-bounded, concrete needs into the provider's native wire
    /// payload. `needs` are already verified `⊆` the matched grant by the
    /// gate. Fail-closed; never emits empty/wildcard.
    fn project(&self, needs: &[ResolvedNeed]) -> Result<BrokerScope, ProjectionError>;

    /// The abstract upper bound of a native payload — the set of needs whose
    /// authority is at least as wide as `native`. The gate calls this on the
    /// projector's own output (and, per ADR 204 amendment 2, on the
    /// provider's scope echo) and re-asserts the result against the original
    /// needs / grant. Returns [`ProjectionError::Refused`] when the native
    /// payload is unbounded (e.g. empty github repositories ⇒ all repos), so
    /// an unbounded mint fails the self-check closed.
    fn native_upper_bound(
        &self,
        native: &BrokerScope,
    ) -> Result<Vec<ResolvedNeed>, ProjectionError>;
}

// ---------------------------------------------------------------------------
// GitHub native scope (shared wire type)
// ---------------------------------------------------------------------------

/// GitHub installation-token native scope — the wire shape
/// `ember_broker::github_broker::GitHubBroker::issue` consumes. Defined here,
/// in the lower crate, so the projector and the broker share **one** typed
/// shape and cannot drift; `ember-broker` re-exports this type.
///
/// - `repositories` are bare repo **names** (no owner prefix — an installation
///   token is owner-scoped). Empty ⇒ the App's full installation scope.
/// - `permissions` are `(name, level)` **tuples** (e.g. `("contents", "write")`),
///   NOT a JSON object. Empty ⇒ the App's installation-level permissions.
///
/// The projector never emits empty for either field; the empty-means-full
/// behaviour exists only for callers that bypass projection (closed by the
/// gate work — ADR 204).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubScope {
    #[serde(default)]
    pub repositories: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// AWS STS native scope (shared wire type)
// ---------------------------------------------------------------------------

/// Provider-specific scope payload for the AWS STS broker.
///
/// This is the wire shape `ember_broker::AwsStsBroker::issue` consumes. It
/// lives beside the projector so the daemon/projector and broker share one
/// typed native payload. The caller-facing `broker_issue` path still carries
/// no native `scope`; this type is daemon-computed output only.
///
/// Callers MUST include a `"mode"` discriminant
/// (`"assume_role"` / `"get_session_token"` / `"web_identity"`). The broker
/// no longer infers mode from `role_arn` presence; implicit fallback to
/// `GetSessionToken` is an empty-means-max footgun.
#[derive(Debug, Clone)]
pub enum AwsStsScope {
    /// `AssumeRole` request. SigV4-signed against the broker's long-lived
    /// credentials.
    AssumeRole {
        /// IAM role to assume. `None` falls back to the broker's configured
        /// default role. The ADR 204 permission-spec projector always emits an
        /// explicit role ARN; `None` is retained only for direct broker tests
        /// and non-projector internal paths.
        role_arn: Option<String>,
        /// `RoleSessionName` — also used as part of the materialization id so
        /// the audit trail names the session.
        session_name: String,
        /// Requested credential lifetime. STS clamps to provider min/max.
        ttl_seconds: u64,
        /// Managed policy ARNs to attach as a session-scope filter.
        policy_arns: Vec<String>,
        /// Inline IAM policy document (JSON string) to attach as the session
        /// policy. The AWS permission-spec projector is the only code that
        /// should synthesize this from typed need-side IR.
        inline_policy: Option<String>,
        /// `ExternalId` for cross-account AssumeRole.
        external_id: Option<String>,
    },
    /// `GetSessionToken` request. Returns session credentials with the same
    /// effective permissions as the long-lived IAM user.
    GetSessionToken {
        /// Used as part of the materialization id so the audit trail names the
        /// session.
        session_name: String,
        /// Requested credential lifetime. STS clamps to provider min/max.
        ttl_seconds: u64,
    },
    /// `AssumeRoleWithWebIdentity` request. Unsigned; the OIDC token is the
    /// authentication.
    WebIdentity {
        /// IAM role to assume.
        role_arn: String,
        /// OIDC token held as a secret so Debug output cannot leak it.
        oidc_token: SecretString,
        /// `RoleSessionName` — used as part of the materialization id.
        session_name: String,
        /// Requested credential lifetime. STS clamps to provider min/max.
        ttl_seconds: u64,
    },
}

/// JSON discriminant for [`AwsStsScope`]. Serialized as snake_case so the wire
/// shape is `"assume_role"` / `"get_session_token"` / `"web_identity"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsStsMode {
    AssumeRole,
    GetSessionToken,
    WebIdentity,
}

impl AwsStsScope {
    /// `session_name` accessor — every variant carries one.
    pub fn session_name(&self) -> &str {
        match self {
            AwsStsScope::AssumeRole { session_name, .. }
            | AwsStsScope::GetSessionToken { session_name, .. }
            | AwsStsScope::WebIdentity { session_name, .. } => session_name,
        }
    }

    /// `ttl_seconds` accessor — every variant carries one.
    pub fn ttl_seconds(&self) -> u64 {
        match self {
            AwsStsScope::AssumeRole { ttl_seconds, .. }
            | AwsStsScope::GetSessionToken { ttl_seconds, .. }
            | AwsStsScope::WebIdentity { ttl_seconds, .. } => *ttl_seconds,
        }
    }

    /// Discriminant — the [`AwsStsMode`] this variant corresponds to.
    pub fn mode(&self) -> AwsStsMode {
        match self {
            AwsStsScope::AssumeRole { .. } => AwsStsMode::AssumeRole,
            AwsStsScope::GetSessionToken { .. } => AwsStsMode::GetSessionToken,
            AwsStsScope::WebIdentity { .. } => AwsStsMode::WebIdentity,
        }
    }
}

/// Internal flat-JSON shape used by the custom [`Deserialize`] /
/// [`Serialize`] impls. Every field is optional except fields common enough to
/// validate after `mode`; the required `mode` discriminant selects the variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AwsStsScopeRaw {
    mode: AwsStsMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_arn: Option<String>,
    session_name: String,
    ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    policy_arns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inline_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    /// OIDC token for `web_identity` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oidc_token: Option<String>,
}

impl Serialize for AwsStsScope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw = match self {
            AwsStsScope::AssumeRole {
                role_arn,
                session_name,
                ttl_seconds,
                policy_arns,
                inline_policy,
                external_id,
            } => AwsStsScopeRaw {
                mode: AwsStsMode::AssumeRole,
                role_arn: role_arn.clone(),
                session_name: session_name.clone(),
                ttl_seconds: *ttl_seconds,
                policy_arns: policy_arns.clone(),
                inline_policy: inline_policy.clone(),
                external_id: external_id.clone(),
                oidc_token: None,
            },
            AwsStsScope::GetSessionToken {
                session_name,
                ttl_seconds,
            } => AwsStsScopeRaw {
                mode: AwsStsMode::GetSessionToken,
                role_arn: None,
                session_name: session_name.clone(),
                ttl_seconds: *ttl_seconds,
                policy_arns: Vec::new(),
                inline_policy: None,
                external_id: None,
                oidc_token: None,
            },
            AwsStsScope::WebIdentity {
                role_arn,
                oidc_token,
                session_name,
                ttl_seconds,
            } => AwsStsScopeRaw {
                mode: AwsStsMode::WebIdentity,
                role_arn: Some(role_arn.clone()),
                session_name: session_name.clone(),
                ttl_seconds: *ttl_seconds,
                policy_arns: Vec::new(),
                inline_policy: None,
                external_id: None,
                oidc_token: Some(oidc_token.expose_secret().to_string()),
            },
        };
        raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AwsStsScope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = AwsStsScopeRaw::deserialize(deserializer)?;
        match raw.mode {
            AwsStsMode::AssumeRole => Ok(AwsStsScope::AssumeRole {
                role_arn: raw.role_arn,
                session_name: raw.session_name,
                ttl_seconds: raw.ttl_seconds,
                policy_arns: raw.policy_arns,
                inline_policy: raw.inline_policy,
                external_id: raw.external_id,
            }),
            AwsStsMode::GetSessionToken => Ok(AwsStsScope::GetSessionToken {
                session_name: raw.session_name,
                ttl_seconds: raw.ttl_seconds,
            }),
            AwsStsMode::WebIdentity => {
                let role_arn = raw.role_arn.ok_or_else(|| {
                    serde::de::Error::custom("web_identity mode requires role_arn")
                })?;
                let oidc_token = raw.oidc_token.ok_or_else(|| {
                    serde::de::Error::custom("web_identity mode requires oidc_token")
                })?;
                Ok(AwsStsScope::WebIdentity {
                    role_arn,
                    oidc_token: SecretString::from(oidc_token),
                    session_name: raw.session_name,
                    ttl_seconds: raw.ttl_seconds,
                })
            }
        }
    }
}

/// Split a concrete `owner/repo` target into `(owner, repo_name)`. Fail-closed
/// on anything that is not exactly two non-empty, wildcard-free segments — a
/// glob/blank/multi-segment value would otherwise widen the mint.
fn split_owner_repo(target: &str) -> Result<(String, String), ProjectionError> {
    let parts: Vec<&str> = target.split('/').collect();
    if parts.len() != 2 || parts.iter().any(|p| p.is_empty()) || target.contains('*') {
        return Err(ProjectionError::Refused(format!(
            "github target is not a concrete owner/repo: {target:?}"
        )));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Canonicalize a GitHub native repository entry into the bare repository name
/// used by installation-token request scope. The daemon's minted native scope
/// sends bare names to GitHub, while GitHub's provider echo returns repository
/// `full_name` values (`owner/repo`). The clamp compares those two native
/// views in bare-name space.
fn github_native_repo_name(repo: &str) -> Result<String, ProjectionError> {
    if repo.is_empty() || repo.contains('*') || repo.chars().any(char::is_control) {
        return Err(ProjectionError::Refused(format!(
            "github native repository is not concrete: {repo:?}"
        )));
    }
    let parts: Vec<&str> = repo.split('/').collect();
    match parts.as_slice() {
        [name] if !name.is_empty() => Ok((*name).to_string()),
        [owner, name] if !owner.is_empty() && !name.is_empty() => Ok((*name).to_string()),
        _ => Err(ProjectionError::Refused(format!(
            "github native repository is malformed: {repo:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// GitHub projector
// ---------------------------------------------------------------------------

/// Projects GitHub installation-token needs into [`GithubScope`].
///
/// A GitHub installation token is **rectangular**: ONE permission map applies
/// to the WHOLE repository set. A single token therefore cannot express
/// per-repo-differing permissions, so this projector refuses a non-rectangular
/// need set (rather than silently minting the widening union) and refuses a
/// multi-owner set (bare repo names are ambiguous across owners). Empty needs,
/// and an empty projected repo/permission set, are refused — empty on the wire
/// means the App's full installation token.
pub struct GithubProjector;

impl NativeProjector for GithubProjector {
    fn provider(&self) -> BrokerProvider {
        BrokerProvider::Github
    }

    fn project(&self, needs: &[ResolvedNeed]) -> Result<BrokerScope, ProjectionError> {
        if needs.is_empty() {
            return Err(ProjectionError::Refused(
                "empty needs would mint a full installation token".into(),
            ));
        }

        // Per-repo permission map (max level per permission within a repo) plus
        // the owning org/user (an installation token is single-owner).
        let mut by_repo: BTreeMap<String, BTreeMap<GithubPermission, Level>> = BTreeMap::new();
        let mut owners: BTreeSet<String> = BTreeSet::new();
        for need in needs {
            // Irrefutable while github is the only variant. When a second
            // provider's `CapabilityVerb` lands this stops compiling, forcing
            // an explicit fail-closed arm for non-github capabilities.
            let CapabilityVerb::Github { permission, level } = &need.capability;
            let ConcreteTarget::Repo(owner_repo) = &need.target;
            let (owner, name) = split_owner_repo(owner_repo)?;
            owners.insert(owner);
            by_repo
                .entry(name)
                .or_default()
                .entry(*permission)
                .and_modify(|l| *l = (*l).max(*level))
                .or_insert(*level);
        }

        // Single-owner invariant: one installation token is scoped to one
        // owner, and bare repo names are ambiguous across owners.
        if owners.len() != 1 {
            return Err(ProjectionError::Refused(
                "github needs span multiple owners — one installation token is owner-scoped".into(),
            ));
        }

        // Rectangularity: every repo must carry the IDENTICAL permission
        // set/levels, or a single token would widen each repo to the union.
        let reference = by_repo
            .values()
            .next()
            .cloned()
            .expect("needs non-empty ⇒ at least one repo");
        if by_repo.values().any(|m| *m != reference) {
            return Err(ProjectionError::Refused(
                "non-rectangular github needs — repos require different permission sets; \
                 split into separate mints"
                    .into(),
            ));
        }
        if reference.is_empty() {
            return Err(ProjectionError::Refused(
                "projected github scope has no permissions (would widen to a full token)".into(),
            ));
        }

        let repositories: Vec<String> = by_repo.keys().cloned().collect();
        let permissions: Vec<(String, String)> = reference
            .iter()
            .map(|(p, l)| (p.api_name().to_string(), l.github_str().to_string()))
            .collect();

        let scope = GithubScope {
            repositories,
            permissions,
        };
        Ok(serde_json::to_value(scope).expect("GithubScope serializes to JSON"))
    }

    fn native_upper_bound(
        &self,
        native: &BrokerScope,
    ) -> Result<Vec<ResolvedNeed>, ProjectionError> {
        let scope: GithubScope = serde_json::from_value(native.clone())
            .map_err(|e| ProjectionError::Unparseable(format!("github native scope: {e}")))?;

        // Empty repositories OR permissions ⇒ the App's FULL installation
        // token (unbounded). Refuse so the gate's faithfulness / ⊆-grant
        // check fails closed.
        if scope.repositories.is_empty() {
            return Err(ProjectionError::Refused(
                "github native has empty repositories — unbounded (all repos)".into(),
            ));
        }
        if scope.permissions.is_empty() {
            return Err(ProjectionError::Refused(
                "github native has empty permissions — unbounded (all permissions)".into(),
            ));
        }

        // Reconstruct the wire-space need set. Request native scope carries
        // bare repo names, while GitHub's provider echo carries full
        // `owner/repo` names. Canonicalize both to bare names so the clamp
        // compares provider truth to the minted native request in the same
        // native target space.
        let mut needs = Vec::new();
        for (perm_name, level_str) in &scope.permissions {
            let permission = GithubPermission::parse(perm_name).ok_or_else(|| {
                ProjectionError::Unparseable(format!("unknown github permission: {perm_name}"))
            })?;
            let level = Level::parse_github(level_str).ok_or_else(|| {
                ProjectionError::Unparseable(format!("unknown github level: {level_str}"))
            })?;
            for repo in &scope.repositories {
                let repo_name = github_native_repo_name(repo)?;
                needs.push(ResolvedNeed {
                    capability: CapabilityVerb::Github { permission, level },
                    target: ConcreteTarget::Repo(repo_name),
                });
            }
        }
        Ok(needs)
    }
}

// ---------------------------------------------------------------------------
// Anthropic projector (budget/label class)
// ---------------------------------------------------------------------------

/// Anthropic workspace-key native scope — the wire shape
/// `core_broker::anthropic::AnthropicBroker::issue` consumes
/// (`{ name, expires_at? }`). Anthropic keys carry **no** provider-side
/// least-privilege scope: a workspace key's power is org-wide, bounded only by
/// budget + TTL + the proxy meter. `name` is therefore a daemon/operator-authored
/// **audit label**, never agent authority. Defined here so the projector and the
/// broker share one shape; `core_broker::anthropic::AnthropicScope` is the
/// native-only mirror the broker deserializes into.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnthropicLabelScope {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Projects an anthropic mint. Anthropic is [`ProviderClass::BudgetLabel`]: the
/// only native field is the audit label `name`, so there is no `project(needs)`
/// /`native_upper_bound` round-trip — instead the daemon supplies a
/// daemon/operator-authored label and this projector produces the `{ name }`
/// payload, refusing an empty label (no silent unnamed key). The mint's
/// authority is bounded by the grant budget + TTL elsewhere in the gate.
pub struct AnthropicProjector;

impl AnthropicProjector {
    pub fn provider(&self) -> BrokerProvider {
        BrokerProvider::Anthropic
    }

    pub fn class(&self) -> ProviderClass {
        ProviderClass::BudgetLabel
    }

    /// Build the native `{ name[, expires_at] }` payload from a
    /// daemon/operator-authored audit `label`. Fail-closed on an empty label.
    pub fn project_label(
        &self,
        label: &str,
        expires_at: Option<&str>,
    ) -> Result<BrokerScope, ProjectionError> {
        let label = label.trim();
        if label.is_empty() {
            return Err(ProjectionError::Refused(
                "anthropic label is empty — refusing to mint an unnamed workspace key".into(),
            ));
        }
        let scope = AnthropicLabelScope {
            name: label.to_string(),
            expires_at: expires_at.map(str::to_string),
        };
        Ok(serde_json::to_value(scope).expect("AnthropicLabelScope serializes to JSON"))
    }
}

// ---------------------------------------------------------------------------
// AWS STS projector (typed PermissionSpec -> inline session policy)
// ---------------------------------------------------------------------------

/// AWS IAM statement effect. Closed to IAM's two valid spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AwsPermissionEffect {
    Allow,
    Deny,
}

impl AwsPermissionEffect {
    pub fn iam_name(self) -> &'static str {
        match self {
            AwsPermissionEffect::Allow => "Allow",
            AwsPermissionEffect::Deny => "Deny",
        }
    }

    fn parse_iam(value: &str) -> Option<Self> {
        match value {
            "Allow" => Some(AwsPermissionEffect::Allow),
            "Deny" => Some(AwsPermissionEffect::Deny),
            _ => None,
        }
    }
}

/// Closed AWS action vocabulary for the current STS PermissionSpec projector.
/// Additions land here with tests; raw `s3:*` / caller-authored action strings
/// are intentionally not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AwsAction {
    S3GetObject,
    S3PutObject,
    S3DeleteObject,
    S3ListBucket,
    S3PutBucketPolicy,
    KmsEncrypt,
    KmsDecrypt,
    KmsScheduleKeyDeletion,
    LambdaInvokeFunction,
    LambdaUpdateFunctionCode,
    LambdaDeleteFunction,
    CloudFormationCreateChangeSet,
    CloudFormationExecuteChangeSet,
    CloudFormationDeleteStack,
    CloudFormationUpdateStack,
    SecretsManagerUpdateSecret,
    SecretsManagerDeleteSecret,
    SecretsManagerPutSecretValue,
}

impl AwsAction {
    pub fn iam_name(self) -> &'static str {
        match self {
            AwsAction::S3GetObject => "s3:GetObject",
            AwsAction::S3PutObject => "s3:PutObject",
            AwsAction::S3DeleteObject => "s3:DeleteObject",
            AwsAction::S3ListBucket => "s3:ListBucket",
            AwsAction::S3PutBucketPolicy => "s3:PutBucketPolicy",
            AwsAction::KmsEncrypt => "kms:Encrypt",
            AwsAction::KmsDecrypt => "kms:Decrypt",
            AwsAction::KmsScheduleKeyDeletion => "kms:ScheduleKeyDeletion",
            AwsAction::LambdaInvokeFunction => "lambda:InvokeFunction",
            AwsAction::LambdaUpdateFunctionCode => "lambda:UpdateFunctionCode",
            AwsAction::LambdaDeleteFunction => "lambda:DeleteFunction",
            AwsAction::CloudFormationCreateChangeSet => "cloudformation:CreateChangeSet",
            AwsAction::CloudFormationExecuteChangeSet => "cloudformation:ExecuteChangeSet",
            AwsAction::CloudFormationDeleteStack => "cloudformation:DeleteStack",
            AwsAction::CloudFormationUpdateStack => "cloudformation:UpdateStack",
            AwsAction::SecretsManagerUpdateSecret => "secretsmanager:UpdateSecret",
            AwsAction::SecretsManagerDeleteSecret => "secretsmanager:DeleteSecret",
            AwsAction::SecretsManagerPutSecretValue => "secretsmanager:PutSecretValue",
        }
    }

    fn parse_iam(value: &str) -> Option<Self> {
        Some(match value {
            "s3:GetObject" => AwsAction::S3GetObject,
            "s3:PutObject" => AwsAction::S3PutObject,
            "s3:DeleteObject" => AwsAction::S3DeleteObject,
            "s3:ListBucket" => AwsAction::S3ListBucket,
            "s3:PutBucketPolicy" => AwsAction::S3PutBucketPolicy,
            "kms:Encrypt" => AwsAction::KmsEncrypt,
            "kms:Decrypt" => AwsAction::KmsDecrypt,
            "kms:ScheduleKeyDeletion" => AwsAction::KmsScheduleKeyDeletion,
            "lambda:InvokeFunction" => AwsAction::LambdaInvokeFunction,
            "lambda:UpdateFunctionCode" => AwsAction::LambdaUpdateFunctionCode,
            "lambda:DeleteFunction" => AwsAction::LambdaDeleteFunction,
            "cloudformation:CreateChangeSet" => AwsAction::CloudFormationCreateChangeSet,
            "cloudformation:ExecuteChangeSet" => AwsAction::CloudFormationExecuteChangeSet,
            "cloudformation:DeleteStack" => AwsAction::CloudFormationDeleteStack,
            "cloudformation:UpdateStack" => AwsAction::CloudFormationUpdateStack,
            "secretsmanager:UpdateSecret" => AwsAction::SecretsManagerUpdateSecret,
            "secretsmanager:DeleteSecret" => AwsAction::SecretsManagerDeleteSecret,
            "secretsmanager:PutSecretValue" => AwsAction::SecretsManagerPutSecretValue,
            _ => return None,
        })
    }
}

/// Closed AWS condition-key vocabulary for the current projector. Each variant
/// maps to one IAM request-context key; custom strings are not accepted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AwsConditionKey {
    RequestedRegion,
    SourceIp,
    PrincipalArn,
    PrincipalTag { tag: String },
    S3Prefix,
}

impl AwsConditionKey {
    fn iam_name(&self) -> Result<String, ProjectionError> {
        Ok(match self {
            AwsConditionKey::RequestedRegion => "aws:RequestedRegion".to_string(),
            AwsConditionKey::SourceIp => "aws:SourceIp".to_string(),
            AwsConditionKey::PrincipalArn => "aws:PrincipalArn".to_string(),
            AwsConditionKey::PrincipalTag { tag } => {
                let tag = tag.trim();
                if tag.is_empty() || tag.contains('*') || tag.contains('/') {
                    return Err(ProjectionError::Refused(format!(
                        "invalid aws PrincipalTag key segment: {tag:?}"
                    )));
                }
                format!("aws:PrincipalTag/{tag}")
            }
            AwsConditionKey::S3Prefix => "s3:prefix".to_string(),
        })
    }

    fn parse_iam(value: &str) -> Option<Self> {
        Some(match value {
            "aws:RequestedRegion" => AwsConditionKey::RequestedRegion,
            "aws:SourceIp" => AwsConditionKey::SourceIp,
            "aws:PrincipalArn" => AwsConditionKey::PrincipalArn,
            "s3:prefix" => AwsConditionKey::S3Prefix,
            _ => {
                let tag = value.strip_prefix("aws:PrincipalTag/")?;
                if tag.is_empty() || tag.contains('*') || tag.contains('/') {
                    return None;
                }
                AwsConditionKey::PrincipalTag {
                    tag: tag.to_string(),
                }
            }
        })
    }
}

/// Closed IAM condition operators supported by the current AWS projector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AwsConditionOperator {
    StringEquals,
    StringLike,
    ArnLike,
    IpAddress,
}

impl AwsConditionOperator {
    fn iam_name(self) -> &'static str {
        match self {
            AwsConditionOperator::StringEquals => "StringEquals",
            AwsConditionOperator::StringLike => "StringLike",
            AwsConditionOperator::ArnLike => "ArnLike",
            AwsConditionOperator::IpAddress => "IpAddress",
        }
    }

    fn parse_iam(value: &str) -> Option<Self> {
        match value {
            "StringEquals" => Some(AwsConditionOperator::StringEquals),
            "StringLike" => Some(AwsConditionOperator::StringLike),
            "ArnLike" => Some(AwsConditionOperator::ArnLike),
            "IpAddress" => Some(AwsConditionOperator::IpAddress),
            _ => None,
        }
    }
}

/// One typed AWS IAM condition. Values stay explicit; there is no raw
/// condition JSON ingress.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AwsCondition {
    pub operator: AwsConditionOperator,
    pub key: AwsConditionKey,
    pub values: Vec<String>,
}

/// ADR 204 AWS need-side IR. This is not native IAM JSON; it is a closed,
/// typed statement shape the projector lowers to an STS inline session policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsPermissionSpec {
    pub effect: AwsPermissionEffect,
    pub actions: Vec<AwsAction>,
    pub resources: Vec<ResourceSelector>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<AwsCondition>,
}

/// Inputs needed to project a permission-spec-bounded STS `AssumeRole` scope.
/// The role/session metadata is daemon/operator-authored; the inline policy is
/// derived exclusively from [`AwsPermissionSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsStsAssumeRoleProjection {
    pub role_arn: String,
    pub session_name: String,
    pub ttl_seconds: u64,
    pub permissions: Vec<AwsPermissionSpec>,
    pub external_id: Option<String>,
}

/// Parsed abstract upper bound of a projected AWS STS native payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsStsUpperBound {
    pub role_arn: String,
    pub permissions: Vec<AwsPermissionSpec>,
}

/// Projects AWS STS `AssumeRole` mints from ADR 204's typed PermissionSpec.
///
/// This projector deliberately does not accept caller-authored `inline_policy`
/// strings, managed policy ARNs, omitted `mode`, `GetSessionToken`, or
/// unbounded `Resource = "*"`. Those shapes are native ingress or full-role
/// footguns; they stay outside the target materialization path.
pub struct AwsStsProjector;

impl AwsStsProjector {
    pub fn provider(&self) -> BrokerProvider {
        BrokerProvider::AwsSts
    }

    pub fn class(&self) -> ProviderClass {
        ProviderClass::ScopeAttestable
    }

    pub fn project_assume_role(
        &self,
        input: &AwsStsAssumeRoleProjection,
    ) -> Result<BrokerScope, ProjectionError> {
        validate_aws_role_arn(&input.role_arn)?;
        validate_aws_session_name(&input.session_name)?;
        if input.ttl_seconds == 0 {
            return Err(ProjectionError::Refused(
                "aws sts ttl_seconds must be > 0".to_string(),
            ));
        }
        if input.permissions.is_empty() {
            return Err(ProjectionError::Refused(
                "aws permission spec is empty — refusing full-role AssumeRole".to_string(),
            ));
        }

        let inline_policy = render_aws_permission_policy(&input.permissions)?;
        if inline_policy.len() > 2048 {
            return Err(ProjectionError::Refused(format!(
                "aws inline session policy exceeds STS 2048 byte limit: {}",
                inline_policy.len()
            )));
        }

        let scope = AwsStsScope::AssumeRole {
            role_arn: Some(input.role_arn.clone()),
            session_name: input.session_name.clone(),
            ttl_seconds: input.ttl_seconds,
            policy_arns: Vec::new(),
            inline_policy: Some(inline_policy),
            external_id: input.external_id.clone(),
        };
        Ok(serde_json::to_value(scope).expect("AwsStsScope serializes to JSON"))
    }

    pub fn native_upper_bound(
        &self,
        native: &BrokerScope,
    ) -> Result<AwsStsUpperBound, ProjectionError> {
        let scope: AwsStsScope = serde_json::from_value(native.clone())
            .map_err(|e| ProjectionError::Unparseable(format!("aws sts native scope: {e}")))?;
        match scope {
            AwsStsScope::AssumeRole {
                role_arn,
                policy_arns,
                inline_policy,
                ..
            } => {
                if !policy_arns.is_empty() {
                    return Err(ProjectionError::Refused(
                        "aws native scope carries managed policy ARNs — not PermissionSpec-derived"
                            .to_string(),
                    ));
                }
                let role_arn = role_arn.ok_or_else(|| {
                    ProjectionError::Refused(
                        "aws assume_role native scope omitted explicit role_arn".to_string(),
                    )
                })?;
                validate_aws_role_arn(&role_arn)?;
                let inline_policy = inline_policy.ok_or_else(|| {
                    ProjectionError::Refused(
                        "aws assume_role native scope omitted inline policy — full-role mint"
                            .to_string(),
                    )
                })?;
                let permissions = parse_aws_permission_policy(&inline_policy)?;
                Ok(AwsStsUpperBound {
                    role_arn,
                    permissions,
                })
            }
            AwsStsScope::GetSessionToken { .. } => Err(ProjectionError::Refused(
                "aws get_session_token has no PermissionSpec clamp".to_string(),
            )),
            AwsStsScope::WebIdentity { .. } => Err(ProjectionError::Refused(
                "aws web_identity PermissionSpec projection is not wired".to_string(),
            )),
        }
    }
}

fn validate_aws_role_arn(role_arn: &str) -> Result<(), ProjectionError> {
    if role_arn.trim() != role_arn
        || role_arn.is_empty()
        || role_arn.contains('*')
        || !role_arn.starts_with("arn:")
        || !role_arn.contains(":role/")
    {
        return Err(ProjectionError::Refused(format!(
            "aws role_arn is not a concrete IAM role ARN: {role_arn:?}"
        )));
    }
    Ok(())
}

fn validate_aws_session_name(session_name: &str) -> Result<(), ProjectionError> {
    let valid_chars = session_name.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'=' | b',' | b'.' | b'@' | b'-')
    });
    if session_name.is_empty() || session_name.len() > 64 || !valid_chars {
        return Err(ProjectionError::Refused(format!(
            "aws role session name is invalid: {session_name:?}"
        )));
    }
    Ok(())
}

fn validate_aws_condition_value(value: &str) -> Result<(), ProjectionError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(ProjectionError::Refused(format!(
            "aws condition value is empty or contains control characters: {value:?}"
        )));
    }
    Ok(())
}

fn aws_resource_to_iam(selector: &ResourceSelector) -> Result<String, ProjectionError> {
    match selector {
        ResourceSelector::Exact { value } => validate_aws_iam_resource(value, false),
        ResourceSelector::Glob { pattern } => validate_aws_iam_resource(pattern, true),
        ResourceSelector::GlobWithSubtarget { .. } => Err(ProjectionError::Refused(
            "aws PermissionSpec does not accept subtarget resource selectors".to_string(),
        )),
        ResourceSelector::Regex { .. } => Err(ProjectionError::Refused(
            "aws PermissionSpec does not accept regex resource selectors".to_string(),
        )),
        ResourceSelector::Any => Err(ProjectionError::Refused(
            "aws PermissionSpec refuses unbounded ResourceSelector::Any".to_string(),
        )),
    }
}

fn validate_aws_iam_resource(value: &str, allow_glob: bool) -> Result<String, ProjectionError> {
    if value.trim() != value
        || value.is_empty()
        || value == "*"
        || value.chars().any(char::is_control)
        || !value.starts_with("arn:")
        || (!allow_glob && value.contains('*'))
    {
        return Err(ProjectionError::Refused(format!(
            "aws IAM resource is not a bounded ARN selector: {value:?}"
        )));
    }
    Ok(value.to_string())
}

fn iam_resource_to_selector(value: &str) -> Result<ResourceSelector, ProjectionError> {
    if value == "*" {
        return Err(ProjectionError::Refused(
            "aws native policy contains unbounded Resource=\"*\"".to_string(),
        ));
    }
    validate_aws_iam_resource(value, true)?;
    if value.contains('*') {
        Ok(ResourceSelector::Glob {
            pattern: value.to_string(),
        })
    } else {
        Ok(ResourceSelector::Exact {
            value: value.to_string(),
        })
    }
}

#[derive(Debug, Serialize)]
struct AwsIamPolicyDocument {
    #[serde(rename = "Version")]
    version: &'static str,
    #[serde(rename = "Statement")]
    statement: Vec<AwsIamStatement>,
}

#[derive(Debug, Serialize)]
struct AwsIamStatement {
    #[serde(rename = "Effect")]
    effect: &'static str,
    #[serde(rename = "Action")]
    action: Vec<String>,
    #[serde(rename = "Resource")]
    resource: Vec<String>,
    #[serde(
        rename = "Condition",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    condition: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

fn render_aws_permission_policy(
    permissions: &[AwsPermissionSpec],
) -> Result<String, ProjectionError> {
    let mut statements = Vec::with_capacity(permissions.len());
    for spec in permissions {
        if spec.actions.is_empty() {
            return Err(ProjectionError::Refused(
                "aws PermissionSpec statement has no actions".to_string(),
            ));
        }
        if spec.resources.is_empty() {
            return Err(ProjectionError::Refused(
                "aws PermissionSpec statement has no resources".to_string(),
            ));
        }
        let action: Vec<String> = spec
            .actions
            .iter()
            .map(|a| a.iam_name().to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let resource: Vec<String> = spec
            .resources
            .iter()
            .map(aws_resource_to_iam)
            .collect::<Result<BTreeSet<_>, _>>()?
            .into_iter()
            .collect();
        let condition = render_aws_conditions(&spec.conditions)?;
        statements.push(AwsIamStatement {
            effect: spec.effect.iam_name(),
            action,
            resource,
            condition,
        });
    }

    let policy = AwsIamPolicyDocument {
        version: "2012-10-17",
        statement: statements,
    };
    serde_json::to_string(&policy)
        .map_err(|e| ProjectionError::Unparseable(format!("serialize aws policy: {e}")))
}

fn render_aws_conditions(
    conditions: &[AwsCondition],
) -> Result<BTreeMap<String, BTreeMap<String, Vec<String>>>, ProjectionError> {
    let mut by_operator: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for condition in conditions {
        if condition.values.is_empty() {
            return Err(ProjectionError::Refused(
                "aws condition has no values".to_string(),
            ));
        }
        let op = condition.operator.iam_name().to_string();
        let key = condition.key.iam_name()?;
        let values = by_operator.entry(op).or_default().entry(key).or_default();
        for value in &condition.values {
            validate_aws_condition_value(value)?;
            values.insert(value.clone());
        }
    }
    Ok(by_operator
        .into_iter()
        .map(|(op, keys)| {
            (
                op,
                keys.into_iter()
                    .map(|(key, values)| (key, values.into_iter().collect()))
                    .collect(),
            )
        })
        .collect())
}

#[derive(Debug, Deserialize)]
struct AwsIamPolicyDocumentRaw {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Statement")]
    statement: OneOrMany<AwsIamStatementRaw>,
}

#[derive(Debug, Deserialize)]
struct AwsIamStatementRaw {
    #[serde(rename = "Effect")]
    effect: String,
    #[serde(rename = "Action")]
    action: OneOrMany<String>,
    #[serde(rename = "Resource")]
    resource: OneOrMany<String>,
    #[serde(rename = "Condition", default)]
    condition: BTreeMap<String, BTreeMap<String, OneOrMany<String>>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            OneOrMany::One(value) => vec![value],
            OneOrMany::Many(values) => values,
        }
    }
}

fn parse_aws_permission_policy(policy: &str) -> Result<Vec<AwsPermissionSpec>, ProjectionError> {
    let raw: AwsIamPolicyDocumentRaw = serde_json::from_str(policy)
        .map_err(|e| ProjectionError::Unparseable(format!("aws inline policy JSON: {e}")))?;
    if raw.version != "2012-10-17" {
        return Err(ProjectionError::Unparseable(format!(
            "unsupported aws policy Version: {}",
            raw.version
        )));
    }
    let statements = raw.statement.into_vec();
    if statements.is_empty() {
        return Err(ProjectionError::Refused(
            "aws inline policy has no statements".to_string(),
        ));
    }

    statements
        .into_iter()
        .map(|stmt| {
            let effect = AwsPermissionEffect::parse_iam(&stmt.effect).ok_or_else(|| {
                ProjectionError::Unparseable(format!("unknown aws Effect: {}", stmt.effect))
            })?;
            let actions = stmt
                .action
                .into_vec()
                .into_iter()
                .map(|a| {
                    AwsAction::parse_iam(&a).ok_or_else(|| {
                        ProjectionError::Unparseable(format!("unknown aws Action: {a}"))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            if actions.is_empty() {
                return Err(ProjectionError::Refused(
                    "aws inline policy statement has no actions".to_string(),
                ));
            }
            let resources = stmt
                .resource
                .into_vec()
                .into_iter()
                .map(|r| iam_resource_to_selector(&r))
                .collect::<Result<Vec<_>, _>>()?;
            if resources.is_empty() {
                return Err(ProjectionError::Refused(
                    "aws inline policy statement has no resources".to_string(),
                ));
            }
            let conditions = parse_aws_conditions(stmt.condition)?;
            Ok(AwsPermissionSpec {
                effect,
                actions,
                resources,
                conditions,
            })
        })
        .collect()
}

fn parse_aws_conditions(
    raw: BTreeMap<String, BTreeMap<String, OneOrMany<String>>>,
) -> Result<Vec<AwsCondition>, ProjectionError> {
    let mut out = Vec::new();
    for (operator, by_key) in raw {
        let operator = AwsConditionOperator::parse_iam(&operator).ok_or_else(|| {
            ProjectionError::Unparseable(format!("unknown aws condition operator: {operator}"))
        })?;
        for (key, values) in by_key {
            let key = AwsConditionKey::parse_iam(&key).ok_or_else(|| {
                ProjectionError::Unparseable(format!("unknown aws condition key: {key}"))
            })?;
            let values = values.into_vec();
            if values.is_empty() {
                return Err(ProjectionError::Refused(
                    "aws condition has no values".to_string(),
                ));
            }
            for value in &values {
                validate_aws_condition_value(value)?;
            }
            out.push(AwsCondition {
                operator,
                key,
                values,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gh(permission: GithubPermission, level: Level, owner_repo: &str) -> ResolvedNeed {
        ResolvedNeed {
            capability: CapabilityVerb::Github { permission, level },
            target: ConcreteTarget::Repo(owner_repo.to_string()),
        }
    }

    fn aws_exact(value: &str) -> ResourceSelector {
        ResourceSelector::Exact {
            value: value.to_string(),
        }
    }

    fn aws_glob(pattern: &str) -> ResourceSelector {
        ResourceSelector::Glob {
            pattern: pattern.to_string(),
        }
    }

    fn aws_projection(resources: Vec<ResourceSelector>) -> AwsStsAssumeRoleProjection {
        AwsStsAssumeRoleProjection {
            role_arn: "arn:aws:iam::123456789012:role/ember-agent".to_string(),
            session_name: "ember-session".to_string(),
            ttl_seconds: 900,
            permissions: vec![AwsPermissionSpec {
                effect: AwsPermissionEffect::Allow,
                actions: vec![AwsAction::S3PutObject],
                resources,
                conditions: vec![AwsCondition {
                    operator: AwsConditionOperator::StringEquals,
                    key: AwsConditionKey::RequestedRegion,
                    values: vec!["us-east-1".to_string()],
                }],
            }],
            external_id: None,
        }
    }

    #[test]
    fn parse_github_need_lowers_canonical_need_strings() {
        use CapabilityVerb::Github;
        // The exact production cohort-A github need vocabulary (ADR 204
        // Amendment 6). These are what the bundled manifests declare.
        assert_eq!(
            CapabilityVerb::parse_github_need("github:contents:read"),
            Some(Github {
                permission: GithubPermission::Contents,
                level: Level::Read
            })
        );
        assert_eq!(
            CapabilityVerb::parse_github_need("github:contents:write"),
            Some(Github {
                permission: GithubPermission::Contents,
                level: Level::Write
            })
        );
        assert_eq!(
            CapabilityVerb::parse_github_need("github:pull_request:read"),
            Some(Github {
                permission: GithubPermission::PullRequests,
                level: Level::Read
            })
        );
        // `create` and `merge` are write-level installation operations.
        assert_eq!(
            CapabilityVerb::parse_github_need("github:pull_request:create"),
            Some(Github {
                permission: GithubPermission::PullRequests,
                level: Level::Write
            })
        );
        assert_eq!(
            CapabilityVerb::parse_github_need("github:pull_request:merge"),
            Some(Github {
                permission: GithubPermission::PullRequests,
                level: Level::Write
            })
        );
        assert_eq!(
            CapabilityVerb::parse_github_need("github:actions:read"),
            Some(Github {
                permission: GithubPermission::Actions,
                level: Level::Read
            })
        );
        assert_eq!(
            CapabilityVerb::parse_github_need("github:actions:write"),
            Some(Github {
                permission: GithubPermission::Actions,
                level: Level::Write
            })
        );
    }

    #[test]
    fn parse_github_need_fails_closed_on_malformed_or_unknown() {
        for bad in [
            "",                        // empty
            "github:contents",         // 2 segments
            "github:contents:write:x", // 4 segments
            "aws:s3:put_object",       // non-github provider
            "github:bogus:read",       // unknown object
            "github:contents:bogus",   // unknown verb
            "github::write",           // empty object
            "contents:write",          // missing provider
        ] {
            assert_eq!(
                CapabilityVerb::parse_github_need(bad),
                None,
                "{bad:?} must fail closed (no capability)"
            );
        }
    }

    #[test]
    fn project_emits_bare_repo_names_and_tuple_permissions() {
        let native = GithubProjector
            .project(&[
                gh(GithubPermission::Contents, Level::Write, "acme/widgets"),
                gh(GithubPermission::PullRequests, Level::Write, "acme/widgets"),
            ])
            .expect("project");
        // Bare repo name (owner stripped); permissions as a TUPLE array, in
        // GithubPermission declaration order (contents < pull_requests).
        assert_eq!(native["repositories"], serde_json::json!(["widgets"]));
        assert_eq!(
            native["permissions"],
            serde_json::json!([["contents", "write"], ["pull_requests", "write"]])
        );
    }

    #[test]
    fn project_max_level_within_repo_and_rectangular_multi_repo() {
        // a: contents read+write ⇒ write; b: contents write. Same map ⇒ rectangular.
        let native = GithubProjector
            .project(&[
                gh(GithubPermission::Contents, Level::Read, "acme/a"),
                gh(GithubPermission::Contents, Level::Write, "acme/a"),
                gh(GithubPermission::Contents, Level::Write, "acme/b"),
            ])
            .expect("project");
        assert_eq!(native["repositories"], serde_json::json!(["a", "b"]));
        assert_eq!(
            native["permissions"],
            serde_json::json!([["contents", "write"]])
        );
    }

    #[test]
    fn project_refuses_disjoint_repo_permission_needs() {
        // contents:write@a + issues:read@b — different permission sets per repo.
        let err = GithubProjector
            .project(&[
                gh(GithubPermission::Contents, Level::Write, "acme/a"),
                gh(GithubPermission::Issues, Level::Read, "acme/b"),
            ])
            .unwrap_err();
        assert!(matches!(err, ProjectionError::Refused(_)), "{err:?}");
    }

    #[test]
    fn project_refuses_per_repo_level_mismatch() {
        // Same permission, different level per repo — still non-rectangular.
        let err = GithubProjector
            .project(&[
                gh(GithubPermission::Contents, Level::Write, "acme/a"),
                gh(GithubPermission::Contents, Level::Read, "acme/b"),
            ])
            .unwrap_err();
        assert!(matches!(err, ProjectionError::Refused(_)), "{err:?}");
    }

    #[test]
    fn project_refuses_multi_owner() {
        let err = GithubProjector
            .project(&[
                gh(GithubPermission::Contents, Level::Read, "acme/x"),
                gh(GithubPermission::Contents, Level::Read, "other/x"),
            ])
            .unwrap_err();
        assert!(matches!(err, ProjectionError::Refused(_)), "{err:?}");
    }

    #[test]
    fn project_refuses_empty_needs() {
        let err = GithubProjector.project(&[]).unwrap_err();
        assert!(matches!(err, ProjectionError::Refused(_)), "{err:?}");
    }

    #[test]
    fn project_refuses_wildcard_or_non_concrete_repo() {
        for bad in ["acme/*", "acme", "", "a/b/c", "*"] {
            let err = GithubProjector
                .project(&[gh(GithubPermission::Contents, Level::Read, bad)])
                .unwrap_err();
            assert!(
                matches!(err, ProjectionError::Refused(_)),
                "{bad:?} -> {err:?}"
            );
        }
    }

    #[test]
    fn native_upper_bound_equals_bare_projection_of_needs() {
        let needs = vec![
            gh(GithubPermission::Contents, Level::Write, "acme/a"),
            gh(GithubPermission::PullRequests, Level::Read, "acme/a"),
        ];
        let native = GithubProjector.project(&needs).expect("project");
        let bound = GithubProjector
            .native_upper_bound(&native)
            .expect("upper bound");
        // Faithfulness: the reconstructed (wire-space, bare-name) need set must
        // equal exactly the bare-name projection of the originals — no phantom
        // cross-product entries from a non-rectangular widen.
        let expected: Vec<ResolvedNeed> = needs
            .iter()
            .map(|n| {
                let ConcreteTarget::Repo(owner_repo) = &n.target;
                let bare = owner_repo.split('/').nth(1).unwrap().to_string();
                ResolvedNeed {
                    capability: n.capability.clone(),
                    target: ConcreteTarget::Repo(bare),
                }
            })
            .collect();
        let as_set = |v: &[ResolvedNeed]| {
            v.iter()
                .map(|n| format!("{:?}", n))
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(as_set(&bound), as_set(&expected), "bound {bound:?}");
    }

    #[test]
    fn native_upper_bound_normalizes_provider_echo_full_names_to_bare_repos() {
        let native = serde_json::json!({
            "repositories": ["acme/widgets"],
            "permissions": [["metadata", "read"], ["pull_requests", "read"]],
        });
        let bound = GithubProjector
            .native_upper_bound(&native)
            .expect("provider echo full_name parses");
        let targets = bound
            .iter()
            .map(|need| {
                let ConcreteTarget::Repo(repo) = &need.target;
                repo.clone()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            targets,
            BTreeSet::from(["widgets".to_string()]),
            "github provider echo full_name must compare in bare-name native space"
        );
    }

    #[test]
    fn native_upper_bound_refuses_malformed_repo_names() {
        for bad in ["", "*", "acme/widgets/extra", "acme/", "/widgets"] {
            let malformed = serde_json::json!({
                "repositories": [bad],
                "permissions": [["contents", "read"]],
            });
            let err = GithubProjector.native_upper_bound(&malformed).unwrap_err();
            assert!(
                matches!(err, ProjectionError::Refused(_)),
                "{bad:?} -> {err:?}"
            );
        }
    }

    #[test]
    fn native_upper_bound_refuses_unbounded_empty_repositories() {
        let unbounded = serde_json::json!({
            "repositories": [],
            "permissions": [["contents", "write"]],
        });
        let err = GithubProjector.native_upper_bound(&unbounded).unwrap_err();
        assert!(matches!(err, ProjectionError::Refused(_)), "{err:?}");
    }

    #[test]
    fn native_upper_bound_refuses_unbounded_empty_permissions() {
        let unbounded = serde_json::json!({
            "repositories": ["a"],
            "permissions": [],
        });
        let err = GithubProjector.native_upper_bound(&unbounded).unwrap_err();
        assert!(matches!(err, ProjectionError::Refused(_)), "{err:?}");
    }

    #[test]
    fn native_upper_bound_rejects_unknown_permission() {
        let native = serde_json::json!({
            "repositories": ["a"],
            "permissions": [["nuclear_codes", "admin"]],
        });
        let err = GithubProjector.native_upper_bound(&native).unwrap_err();
        assert!(matches!(err, ProjectionError::Unparseable(_)), "{err:?}");
    }

    #[test]
    fn anthropic_projector_emits_name_label() {
        let native = AnthropicProjector
            .project_label("forge-bot-key", None)
            .expect("project label");
        assert_eq!(native["name"], serde_json::json!("forge-bot-key"));
        assert!(native.get("expires_at").is_none());
        assert_eq!(AnthropicProjector.class(), ProviderClass::BudgetLabel);
        assert_eq!(AnthropicProjector.provider(), BrokerProvider::Anthropic);
    }

    #[test]
    fn anthropic_projector_carries_optional_expiry() {
        let native = AnthropicProjector
            .project_label("k", Some("2026-12-31T23:59:59Z"))
            .expect("project label");
        assert_eq!(
            native["expires_at"],
            serde_json::json!("2026-12-31T23:59:59Z")
        );
        // Round-trips into the wire mirror.
        let scope: AnthropicLabelScope = serde_json::from_value(native).expect("deserialize");
        assert_eq!(scope.name, "k");
        assert_eq!(scope.expires_at.as_deref(), Some("2026-12-31T23:59:59Z"));
    }

    #[test]
    fn anthropic_projector_refuses_empty_or_blank_label() {
        for bad in ["", "   ", "\t"] {
            let err = AnthropicProjector.project_label(bad, None).unwrap_err();
            assert!(
                matches!(err, ProjectionError::Refused(_)),
                "{bad:?} -> {err:?}"
            );
        }
    }

    #[test]
    fn aws_sts_projector_emits_explicit_assume_role_with_inline_policy() {
        let native = AwsStsProjector
            .project_assume_role(&aws_projection(vec![aws_exact(
                "arn:aws:s3:::example-bucket/uploads/object.txt",
            )]))
            .expect("project aws");

        assert_eq!(native["mode"], serde_json::json!("assume_role"));
        assert_eq!(
            native["role_arn"],
            serde_json::json!("arn:aws:iam::123456789012:role/ember-agent")
        );
        assert_eq!(native["session_name"], serde_json::json!("ember-session"));
        assert_eq!(native["ttl_seconds"], serde_json::json!(900));
        assert!(native.get("policy_arns").is_none());

        let inline = native["inline_policy"]
            .as_str()
            .expect("inline policy string");
        let policy: serde_json::Value = serde_json::from_str(inline).expect("policy JSON");
        assert_eq!(policy["Version"], serde_json::json!("2012-10-17"));
        assert_eq!(policy["Statement"][0]["Effect"], serde_json::json!("Allow"));
        assert_eq!(
            policy["Statement"][0]["Action"],
            serde_json::json!(["s3:PutObject"])
        );
        assert_eq!(
            policy["Statement"][0]["Resource"],
            serde_json::json!(["arn:aws:s3:::example-bucket/uploads/object.txt"])
        );
        assert_eq!(
            policy["Statement"][0]["Condition"]["StringEquals"]["aws:RequestedRegion"],
            serde_json::json!(["us-east-1"])
        );

        let scope: AwsStsScope = serde_json::from_value(native).expect("shared AwsStsScope");
        assert_eq!(scope.mode(), AwsStsMode::AssumeRole);
    }

    #[test]
    fn aws_sts_native_upper_bound_round_trips_permission_spec() {
        let input = aws_projection(vec![aws_glob("arn:aws:s3:::example-bucket/uploads/*")]);
        let native = AwsStsProjector
            .project_assume_role(&input)
            .expect("project aws");

        let bound = AwsStsProjector
            .native_upper_bound(&native)
            .expect("upper bound");
        assert_eq!(bound.role_arn, "arn:aws:iam::123456789012:role/ember-agent");
        assert_eq!(bound.permissions, input.permissions);
    }

    #[test]
    fn aws_sts_projector_round_trips_secretsmanager_actions() {
        let secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db-AbCdEf";
        let input = AwsStsAssumeRoleProjection {
            role_arn: "arn:aws:iam::123456789012:role/ember-agent".to_string(),
            session_name: "ember-session".to_string(),
            ttl_seconds: 900,
            permissions: vec![AwsPermissionSpec {
                effect: AwsPermissionEffect::Allow,
                actions: vec![
                    AwsAction::SecretsManagerDeleteSecret,
                    AwsAction::SecretsManagerPutSecretValue,
                    AwsAction::SecretsManagerUpdateSecret,
                ],
                resources: vec![aws_exact(secret_arn)],
                conditions: Vec::new(),
            }],
            external_id: None,
        };
        let native = AwsStsProjector
            .project_assume_role(&input)
            .expect("project aws");
        let bound = AwsStsProjector
            .native_upper_bound(&native)
            .expect("upper bound");
        assert_eq!(bound.permissions, input.permissions);
    }

    #[test]
    fn aws_sts_projector_round_trips_kms_lifecycle_actions() {
        let key_arn = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234";
        let input = AwsStsAssumeRoleProjection {
            role_arn: "arn:aws:iam::123456789012:role/ember-agent".to_string(),
            session_name: "ember-session".to_string(),
            ttl_seconds: 900,
            permissions: vec![AwsPermissionSpec {
                effect: AwsPermissionEffect::Allow,
                actions: vec![AwsAction::KmsScheduleKeyDeletion],
                resources: vec![aws_exact(key_arn)],
                conditions: Vec::new(),
            }],
            external_id: None,
        };
        let native = AwsStsProjector
            .project_assume_role(&input)
            .expect("project aws");
        let bound = AwsStsProjector
            .native_upper_bound(&native)
            .expect("upper bound");
        assert_eq!(bound.permissions, input.permissions);
    }

    #[test]
    fn aws_sts_projector_refuses_unbounded_resources() {
        for selector in [
            ResourceSelector::Any,
            ResourceSelector::Glob {
                pattern: "*".to_string(),
            },
            ResourceSelector::Exact {
                value: "*".to_string(),
            },
        ] {
            let err = AwsStsProjector
                .project_assume_role(&aws_projection(vec![selector]))
                .unwrap_err();
            assert!(matches!(err, ProjectionError::Refused(_)), "{err:?}");
        }
    }

    #[test]
    fn aws_sts_upper_bound_refuses_full_role_shapes() {
        let get_session_token = serde_json::json!({
            "mode": "get_session_token",
            "session_name": "ember-session",
            "ttl_seconds": 900
        });
        let err = AwsStsProjector
            .native_upper_bound(&get_session_token)
            .unwrap_err();
        assert!(matches!(err, ProjectionError::Refused(_)), "{err:?}");

        let assume_role_no_policy = serde_json::json!({
            "mode": "assume_role",
            "role_arn": "arn:aws:iam::123456789012:role/ember-agent",
            "session_name": "ember-session",
            "ttl_seconds": 900
        });
        let err = AwsStsProjector
            .native_upper_bound(&assume_role_no_policy)
            .unwrap_err();
        assert!(matches!(err, ProjectionError::Refused(_)), "{err:?}");
    }

    #[test]
    fn aws_sts_scope_requires_explicit_mode() {
        let raw = serde_json::json!({
            "role_arn": "arn:aws:iam::123456789012:role/ember-agent",
            "session_name": "ember-session",
            "ttl_seconds": 900
        });
        let err = serde_json::from_value::<AwsStsScope>(raw).expect_err("mode is required");
        assert!(
            err.to_string().contains("missing field `mode`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn projected_scope_deserializes_into_github_scope() {
        // The projector output must round-trip into the shared typed shape the
        // broker consumes (object-vs-tuple / owner-prefix drift guard).
        let native = GithubProjector
            .project(&[gh(GithubPermission::Contents, Level::Write, "acme/widgets")])
            .expect("project");
        let scope: GithubScope = serde_json::from_value(native).expect("deserialize GithubScope");
        assert_eq!(scope.repositories, vec!["widgets".to_string()]);
        assert_eq!(
            scope.permissions,
            vec![("contents".to_string(), "write".to_string())]
        );
    }
}
