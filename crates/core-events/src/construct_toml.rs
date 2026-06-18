//! `construct.toml` schema parser + validator.
//!
//! Codifies the schema specified in [`docs/construct-toml-schema.md`](../../../docs/construct-toml-schema.md).
//! Every cohort A Construct binary embeds a `construct.toml` at compile time;
//! this module is the **single source of truth** for parsing + validating
//! that file across the publisher's build (rejects bad shapes at `cargo build`),
//! the daemon's manifest-load (refuses to register bad Constructs), and
//! `broker.exec` call sites (cached by blake3 per the wire spec).
//!
//! Tracks **AP-CONSTRUCT-TOML-SCHEMA** (P1/S). v0.1 here covers the parser +
//! current schema invariants; the cargo build-time hook + daemon manifest
//! integration land in follow-up PRs.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use thiserror::Error;

use core_event_types::{ActionRef, InteractionClass, RailTrustContract, RunnerClass};

/// Result alias for validator errors.
pub type Result<T> = std::result::Result<T, ConstructTomlError>;

/// Result alias for ADR 196 action-manifest parser errors.
pub type ActionManifestResult<T> = std::result::Result<T, ActionManifestError>;

/// `construct.toml` carrier schema for ADR 196.
pub const ACTION_MANIFEST_CARRIER_SCHEMA_V2: &str = "2";

/// Warning event type S4 can later flip into a typed refusal.
pub const DEPRECATED_EXEC_WARNING_EVENT_TYPE: &str = "construct_manifest.deprecated_exec";

/// Validator errors. Mapped one-to-one to the schema invariants from
/// the design doc, plus a transport-level `parse` variant.
#[derive(Debug, Error)]
pub enum ConstructTomlError {
    #[error("toml parse error: {0}")]
    Parse(String),
    #[error("invariant 1 violated: schema_version must be \"1\", got {0:?}")]
    UnknownSchemaVersion(String),
    #[error(
        "invariant 2 violated: meta.publisher must be a valid DID (did:method:identifier), got {0:?}"
    )]
    InvalidPublisherDid(String),
    #[error("invariant 3 violated: action identifier {0:?} appears in two [actions.X] blocks")]
    ActionIdCollision(String),
    #[error(
        "invariant 4 violated: action {action} mode {mode:?} not in {{auto_approve_if_pregranted, jit_approval, deny, auto_approve}}"
    )]
    InvalidMode { action: String, mode: String },
    #[error(
        "invariant 5 violated: action {action} classify_argv {argv:?} contains chars outside [a-zA-Z0-9._\\-* ]"
    )]
    InvalidClassifyArgv { action: String, argv: String },
    #[error(
        "invariant 6 violated: bundled publisher {0:?} cannot set unknown_action=auto_approve at top level (use tier_overrides.dev0)"
    )]
    BundledAutoApproveTopLevel(String),
    #[error("invariant 7 violated: meta.wraps_binary_min_version {0:?} is not parseable as semver")]
    InvalidMinVersion(String),
    #[error(
        "invariant 8 violated: action {action} budget_caps.{key} value {value} outside [1, 10000]"
    )]
    BudgetCapOutOfBounds {
        action: String,
        key: String,
        value: i64,
    },
    #[error(
        "invariant 9 violated: action {action} on_shim_eof {value:?} not in {{sigterm, drain}}"
    )]
    InvalidShimEofPolicy { action: String, value: String },
    #[error(
        "invariant 10 violated: action {action} env_passthrough name {name:?} fails ^[A-Z_][A-Z0-9_]*$ shape"
    )]
    InvalidEnvPassthroughName { action: String, name: String },
    #[error("invariant 11 violated: [rail] requires rail.trust_contract")]
    MissingRailTrustContract,
    #[error(
        "invariant 12 violated: rail.trust_contract {0:?} not in {{side_channel_reconciliation, ephemeral_sign}}"
    )]
    InvalidRailTrustContract(String),
}

/// Errors returned by the ADR 196 action-manifest parser.
#[derive(Debug, Error)]
pub enum ActionManifestError {
    #[error("toml parse error: {0}")]
    Parse(String),
    #[error("unknown action-manifest top-level field {0:?}")]
    UnknownTopLevelField(String),
    #[error("unknown action-manifest field {field:?} on action {action:?}")]
    UnknownActionField {
        action: Option<String>,
        field: String,
    },
    #[error("raw execution field {field:?} is invalid at {path}; use [deprecated_exec]")]
    RawExecFieldOutsideDeprecatedExec { path: String, field: String },
    #[error("schema_version must be \"2\", got {0:?}")]
    UnknownSchemaVersion(String),
    #[error("derived action_ref for action {action:?} is invalid: {reason}")]
    InvalidActionRef { action: String, reason: String },
    #[error("meta.mock = true is allowed only when provider_kind = \"mock_api\"")]
    MockFlagOutsideMockProvider,
    #[error("provider_kind = \"mock_api\" requires meta.mock = true")]
    MockProviderMissingMockFlag,
    #[error("[runtime.cli] is required when provider_kind = \"cli\"")]
    MissingCliRuntime,
    #[error("[runtime.cli] is invalid when provider_kind is {0:?}")]
    UnexpectedCliRuntime(ProviderKind),
    #[error("[deprecated_exec] is invalid when provider_kind is {0:?}")]
    DeprecatedExecForNonCli(ProviderKind),
    #[error("[deprecated_exec] is invalid without structured [[actions]]")]
    DeprecatedExecWithoutActions,
    #[error("[deprecated_exec] is no longer accepted after P11-S4")]
    DeprecatedExecDisallowed,
    #[error("action key {0:?} appears more than once")]
    DuplicateActionKey(String),
    #[error("authority_refs migration alias cannot be combined with material_classes at {scope}")]
    AuthorityRefsWithMaterialClasses { scope: String },
    #[error("authority_refs migration alias is no longer accepted after P11-S4 at {scope}")]
    AuthorityRefsAliasDisallowed { scope: String },
    #[error("action {action:?} has no effective default_runner_classes")]
    EmptyRunnerClasses { action: String },
    #[error("action {action:?} has no effective materialization_class")]
    MissingMaterializationClass { action: String },
    #[error("action {action:?} materialization_class {class:?} contradicts declared materials")]
    MaterializationClassMismatch {
        action: String,
        class: MaterializationClass,
    },
    #[error(
        "action {action:?} handler_ref {handler_ref:?} does not match provider_kind {provider_kind:?}"
    )]
    InvalidHandlerRef {
        action: String,
        handler_ref: String,
        provider_kind: ProviderKind,
    },
    #[error("action {action:?} {field} env name {name:?} fails ^[A-Z_][A-Z0-9_]*$ shape")]
    InvalidActionEnvName {
        action: String,
        field: &'static str,
        name: String,
    },
    #[error("{field} env name {name:?} fails ^[A-Z_][A-Z0-9_]*$ shape")]
    InvalidDefaultEnvName { field: &'static str, name: String },
    #[error("action {action:?} budget_caps.{key} value {value} outside [1, 10000]")]
    ActionBudgetCapOutOfBounds {
        action: String,
        key: String,
        value: i64,
    },
    #[error("action {action:?} need_ir is invalid: {reason}")]
    InvalidNeedIr { action: String, reason: String },
    /// Invariant 13 — `[settings_overlay]` carrier. The deny-only overlay
    /// declared by a Construct manifest projects into the Claude Code launcher's
    /// fresh settings.json via `settings_overlay.permissions_deny`. The
    /// `deny_unknown_fields` derive on `SettingsOverlay` structurally refuses any
    /// `permissions_allow` field at the schema layer; this variant carries the
    /// non-shape post-conditions (CLI runtime required, `Bash(...)` tool prefix
    /// only, absolute-path forms only, basename binds to the wrapped binary).
    /// See ADR 124 §3 and the V030-CLAUDE-OVERLAY adversarial review C5.1-C5.6.
    #[error("invariant 13 violated: [settings_overlay] is invalid: {reason}")]
    InvalidSettingsOverlay { reason: String },
}

/// Parsed ADR 196 action manifest plus loader-facing warnings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedActionManifest {
    pub manifest: ActionManifest,
    #[serde(default)]
    pub warnings: Vec<DeprecatedExecWarning>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeprecatedExecWarning {
    pub event_type: String,
    pub plugin_address: String,
    pub plugin_version: String,
    pub provider_kind: ProviderKind,
    pub fields: Vec<String>,
    pub sunset: String,
}

/// ADR 196 logical action-manifest schema carried in `construct.toml` v2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionManifest {
    pub schema_version: String,
    #[serde(default)]
    pub default: Option<ConstructExecDefaultPolicy>,
    pub meta: ActionManifestMeta,
    #[serde(default)]
    pub defaults: ActionManifestDefaults,
    #[serde(default)]
    pub runtime: ActionManifestRuntime,
    #[serde(default)]
    pub deprecated_exec: Option<DeprecatedExec>,
    pub actions: Vec<ActionManifestAction>,
    /// Optional rail-adapter carrier block. The v2 schema accepts it
    /// structurally; the rail trust-contract semantics are validated at the
    /// carrier-load seam (`resolve_action_manifest_identity`) per ADR 182.
    #[serde(default)]
    pub rail: Option<RailBlock>,
    /// Optional Claude Code per-Construct deny carrier (ADR 124 §3
    /// defense-in-depth; V030-CLAUDE-OVERLAY rework).
    ///
    /// Declares the `permissions.deny` entries this Construct contributes
    /// to the brokered Claude session's overlay `settings.json`. The
    /// launcher unions every installed bundled Construct's
    /// `settings_overlay.permissions_deny` into the policy-tier overlay so
    /// the brokered session refuses raw-binary invocations that would
    /// bypass the shadow shim (`gh`, `git push`, etc. via absolute paths
    /// or PATH-prefix overrides).
    ///
    /// **Invariant 13:** deny-only — there is no `permissions_allow`
    /// surface. A third-party Construct cannot widen Claude authority via
    /// the overlay; `deny_unknown_fields` on `SettingsOverlay` rejects any
    /// attempt at parse time. Per-entry shape and cross-tool binding are
    /// enforced post-parse (see [`InvalidSettingsOverlay`]).
    #[serde(default)]
    pub settings_overlay: Option<SettingsOverlay>,
}

/// Construct-authored deny carrier for the Claude Code `settings.json`
/// overlay (ADR 124 §3 / V030-CLAUDE-OVERLAY).
///
/// **Invariant 13b:** the struct intentionally has no `permissions_allow`
/// field. `deny_unknown_fields` makes that a structural refusal — a
/// third-party manifest that tries to declare an allow surface fails to
/// parse, blocking authority widening through the overlay path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SettingsOverlay {
    /// `Bash(...)`-shaped Claude permission-rule deny entries.
    ///
    /// Each entry must:
    /// - start with `Bash(` and end with `)` (invariant 13a — Bash-only),
    /// - place an absolute path (`/...`) as the first whitespace-separated
    ///   token inside the parentheses (invariant 13c — bare-name forms
    ///   refused; PATH-resolved binaries are ambiguous with the shadow
    ///   shim), and
    /// - have that absolute path's basename equal the manifest's
    ///   `runtime.cli.wrapped_binary` (invariant 13b — cross-tool denies
    ///   refused so `gh.toml` cannot author a deny that targets `curl`).
    #[serde(default)]
    pub permissions_deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionManifestMeta {
    pub name: String,
    pub plugin_address: String,
    pub plugin_version: String,
    pub publisher: String,
    pub provider_kind: ProviderKind,
    pub summary: String,
    pub description: String,
    #[serde(default)]
    pub mock: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Cli,
    Api,
    MockApi,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ActionManifestDefaults {
    #[serde(default)]
    pub materialization_class: Option<MaterializationClass>,
    #[serde(default)]
    pub material_classes: Vec<MaterialClass>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub default_runner_classes: Vec<RunnerClass>,
    #[serde(default)]
    pub vault_paths: Vec<String>,
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    #[serde(default)]
    pub file_env: Vec<String>,
    #[serde(default)]
    pub headless_requirements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ActionManifestRuntime {
    #[serde(default)]
    pub cli: Option<CliRuntime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliRuntime {
    pub wrapped_binary: String,
    #[serde(default)]
    pub wrapped_binary_min_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeprecatedExec {
    #[serde(default)]
    pub binary: Option<String>,
    #[serde(default)]
    pub cwd_policy: Option<String>,
    pub sunset: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionManifestAction {
    pub key: String,
    pub action_version: String,
    pub summary: String,
    pub input_schema: toml::Value,
    pub risk_tier: RiskTier,
    pub idempotency: Idempotency,
    pub interaction_class: InteractionClass,
    #[serde(default)]
    pub default: Option<ConstructExecDefaultPolicy>,
    #[serde(default)]
    pub mode: Option<ConstructExecMode>,
    #[serde(default)]
    pub biometric: Option<BiometricRequirement>,
    #[serde(default)]
    pub biometric_when_production_bucket: bool,
    #[serde(default)]
    pub budget_caps: HashMap<String, i64>,
    #[serde(default)]
    pub materialization_class: Option<MaterializationClass>,
    #[serde(default)]
    pub material_classes: Vec<MaterialClass>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub default_runner_classes: Vec<RunnerClass>,
    pub audit_fields: Vec<String>,
    pub handler_ref: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub output_schema: Option<toml::Value>,
    #[serde(default)]
    pub semantic_labels: Vec<String>,
    #[serde(default)]
    pub topology_hints: Vec<String>,
    #[serde(default)]
    pub attestation_hints: Vec<String>,
    #[serde(default)]
    pub cost_hints: Vec<String>,
    #[serde(default)]
    pub deprecation: Option<String>,
    #[serde(default)]
    pub headless_requirements: Vec<String>,
    #[serde(default)]
    pub vault_paths: Vec<String>,
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    #[serde(default)]
    pub file_env: Vec<String>,
    #[serde(default)]
    pub on_shim_eof: Option<ShimEofPolicy>,
    #[serde(default = "default_terminal_mode")]
    pub terminal_mode: TerminalMode,
    /// The action's least-privilege authority **need** in the canonical
    /// `provider:object:verb` algebra (ADR 204 §2/I6, ADR 205 §1) —
    /// e.g. `["github:contents:write", "github:pull_request:create"]`.
    /// `[]` (the default) means the action mints no provider credential.
    ///
    /// This is the manifest-sourced replacement for the daemon's formerly
    /// hardcoded `ember-construct::policy::github_action_need` map (ADR 204
    /// Amendment 6; checkpoint `action_need_is_manifest_sourced_not_hardcoded`).
    /// The daemon resolves the need from the **bundled** cohort-A manifest
    /// (`include_str!`-compiled — the same trust base as the former hardcode)
    /// keyed by the daemon-classified tool+action, then the audited projector
    /// derives native scope from it (I6 — only the projector speaks native).
    ///
    /// Static-need providers (github) declare their need here. AWS leaves this
    /// empty: its need is a dynamic per-argv `AwsPermissionSpec` (ADR 204
    /// amendment 1) computed at mint, not a static per-action string.
    #[serde(default)]
    pub need: Vec<String>,
    /// Optional ADR 213 O2 declarative provider need-IR archetype data.
    ///
    /// This is the sole current projection authoring surface for community
    /// constructs: inert data in the attested manifest, selected from a closed
    /// archetype vocabulary and validated by core. It is not native scope and
    /// no community code runs in the authority path.
    #[serde(default)]
    pub need_ir: Option<NeedIrArchetypeData>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Idempotency {
    Idempotent,
    ConditionallyIdempotent,
    NonIdempotent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstructExecDefaultPolicy {
    Permit,
    Prompt,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstructExecMode {
    Gate,
    Deny,
    AutoApprove,
    AutoApproveIfPregranted,
    JitApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalMode {
    Auto,
    Pty,
    Piped,
}

fn default_terminal_mode() -> TerminalMode {
    TerminalMode::Auto
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BiometricRequirement {
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationClass {
    None,
    BrokeredCredential,
    DeclaredHostMaterial,
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MaterialClass {
    Broker { authority_ref: String },
    Env { name: String },
    FileEnv { name: String },
    VaultPath { path: String },
}

/// ADR 213 O2 closed need-IR archetype vocabulary carried by `construct.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "archetype")]
pub enum NeedIrArchetypeData {
    #[serde(rename = "policy-document")]
    PolicyDocument(PolicyDocumentNeedIr),
    #[serde(rename = "OAuth-scope", alias = "oauth-scope")]
    OauthScope(OauthScopeNeedIr),
    #[serde(rename = "identity-only")]
    IdentityOnly(IdentityOnlyNeedIr),
    #[serde(rename = "registry-JWT", alias = "registry-jwt")]
    RegistryJwt(RegistryJwtNeedIr),
    #[serde(rename = "budget")]
    Budget(BudgetNeedIr),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocumentNeedIr {
    pub provider: String,
    pub policy_language: String,
    pub statements: Vec<PolicyDocumentStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocumentStatement {
    pub effect: PolicyEffect,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<PolicyCondition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCondition {
    pub key: String,
    pub operator: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OauthScopeNeedIr {
    pub provider: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityOnlyNeedIr {
    pub provider: String,
    pub identity: NeedIrIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeedIrIdentity {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryJwtNeedIr {
    pub provider: String,
    pub registry: String,
    pub audience: String,
    pub claims: Vec<RegistryJwtClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryJwtClaim {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetNeedIr {
    pub provider: String,
    #[serde(default)]
    pub tokens: Option<i64>,
    #[serde(default)]
    pub cents: Option<i64>,
    #[serde(default)]
    pub requests: Option<i64>,
    #[serde(default)]
    pub wall_clock_secs: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShimEofPolicy {
    Sigterm,
    Drain,
}

impl ActionManifestAction {
    pub fn action_ref(&self, manifest: &ActionManifest) -> ActionRef {
        ActionRef::new(
            manifest.meta.plugin_address.clone(),
            self.key.clone(),
            self.action_version.clone(),
        )
    }
}

/// Errors returned by the lightweight action-manifest extractor used by the
/// structured action-ref migration. This intentionally targets the live
/// bundled `construct.toml` carrier shape rather than the newer validator
/// surface above so authority-path callers can source `ActionRef` directly
/// from the embedded manifest bytes they already ship today.
#[derive(Debug, Error)]
pub enum ConstructActionRefError {
    #[error("construct.toml parse error: {0}")]
    Parse(String),
    #[error("meta.plugin_address is required for structured action refs")]
    MissingPluginAddress,
    #[error("meta.plugin_version or meta.version is required for structured action refs")]
    MissingPluginVersion,
    #[error("action {0:?} is not declared in construct.toml [[actions]]")]
    UnknownAction(String),
    #[error("action {0:?} is missing action_version")]
    MissingActionVersion(String),
    #[error("invalid structured action ref: {0}")]
    InvalidActionRef(String),
    #[error("[rail] requires rail.trust_contract")]
    MissingRailTrustContract,
    #[error(
        "invalid rail trust contract {0:?}; expected side_channel_reconciliation or ephemeral_sign"
    )]
    InvalidRailTrustContract(String),
    #[error("action manifest failed v2 schema validation at load: {0}")]
    ManifestSchema(String),
}

/// ADR 184 identity fields surfaced from the live `construct.toml` carrier.
///
/// This keeps the current CLI-style carrier load-bearing while making the
/// package-scoped identity fields Ember core needs explicit and typed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructActionManifestIdentity {
    pub plugin_address: String,
    pub plugin_version: String,
    pub action_key: String,
    pub action_version: String,
    #[serde(default)]
    pub semantic_labels: Vec<String>,
}

impl ConstructActionManifestIdentity {
    /// Recompose the canonical structured action ref from the surfaced fields.
    pub fn action_ref(&self) -> ActionRef {
        ActionRef::new(
            self.plugin_address.clone(),
            self.action_key.clone(),
            self.action_version.clone(),
        )
    }
}

/// Parsed + validated `construct.toml` envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructToml {
    pub schema_version: String,
    pub meta: Meta,
    #[serde(default)]
    pub default: DefaultBlock,
    #[serde(default)]
    pub actions: HashMap<String, ActionBlock>,
    /// Named credential-type definitions. Keys are credential type names
    /// (e.g. `"aws_iam"`, `"github_token"`); values describe which vault
    /// entries they consume and which broker implementation materialises them.
    /// Actions reference these by name via `needs_credentials = true` plus
    /// the action's own `credential_type` key (resolved at broker_exec time).
    #[serde(default)]
    pub credential_types: HashMap<String, CredentialType>,
    /// Optional rail-adapter metadata. When present, the daemon expects a
    /// declared trust contract so payment adapters fail closed.
    #[serde(default)]
    pub rail: Option<RailBlock>,
}

/// Descriptor for a named credential type declared in a `construct.toml`.
///
/// Each `[credential_types.<name>]` table declares:
/// - which vault entries (by path pattern) the credential consumes, and
/// - which broker implementation is responsible for materialising the
///   credential into env vars or files at `broker_exec` time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialType {
    /// Vault entry path patterns consumed by this credential type.
    /// Patterns follow the same syntax as vault path globs used in
    /// grant conditions (e.g. `"secret/data/aws/*"`).
    #[serde(default)]
    pub vault_entries: Vec<String>,
    /// Name of the broker plugin responsible for materialising this
    /// credential. Must be a non-empty string identifying a registered
    /// `BrokerImpl` variant (e.g. `"aws_iam_env"`, `"gh_token_env"`).
    pub broker_impl: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RailBlock {
    /// Required when `[rail]` is present. ADR 182 Component 6 only allows
    /// `side_channel_reconciliation` or `ephemeral_sign`. A typo'd key (e.g.
    /// `trust_contracts`) is rejected at parse rather than silently dropped and
    /// later misreported as a missing trust contract.
    #[serde(default)]
    pub trust_contract: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub wraps_binary: String,
    #[serde(default)]
    pub wraps_binary_min_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultBlock {
    #[serde(default = "default_unknown_action")]
    pub unknown_action: String,
    #[serde(default)]
    pub tier_overrides: HashMap<String, String>,
}

fn default_unknown_action() -> String {
    "deny".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionBlock {
    pub mode: String,
    pub classify_argv: String,
    #[serde(default)]
    pub allowed_branches_deny: Vec<String>,
    #[serde(default)]
    pub budget_caps: HashMap<String, i64>,
    #[serde(default)]
    pub receipt_redact: Vec<String>,
    /// Policy applied when the shim's UDS connection EOFs before the
    /// daemon-spawned child exits. ADR 124 §"Shim-EOF correctness" /
    /// `docs/adversarial/2026-05-07-daemon-supervisor-vs-shim-supervisor.md`
    /// axis C. Allowed values:
    ///
    /// - `"sigterm"` (default) — daemon SIGTERMs the child immediately.
    ///   Matches the wedge framing: the agent supervises its credential
    ///   lifecycle; if the agent's representative went away, the work it
    ///   requested should stop.
    /// - `"drain"` — child runs to natural completion (e.g. `pulumi up`
    ///   where mid-run interruption corrupts state). Cred is still revoked
    ///   on child exit via the normal path; the shim-side has no
    ///   visibility after disappearing.
    #[serde(default = "default_on_shim_eof")]
    pub on_shim_eof: String,
    /// Per-action env-passthrough allowlist. Only env names declared here
    /// are forwarded into the broker_exec child for this action; names
    /// not in this list are stripped silently and counted in the
    /// `env_passthrough_stripped` Receipt field for forensic visibility.
    /// ADR 124 axis A2 / `docs/adversarial/2026-05-07-daemon-supervisor-vs-shim-supervisor.md`.
    ///
    /// Each name must match the daemon's defense-in-depth shape regex
    /// `^[A-Z_][A-Z0-9_]*$`; bad shapes are rejected at construct.toml
    /// validate time (invariant 10).
    ///
    /// Default: empty list — i.e. zero env passthrough beyond the daemon's
    /// hardcoded baseline (PATH, HOME, USER, LANG, TERM). Cohort-A author
    /// intent is "declare what you need explicitly per action" so a
    /// careless top-level allowlist cannot leak credentials into actions
    /// that don't need them.
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    /// Whether this action requires credential injection at broker_exec time.
    ///
    /// When `true`, the broker resolves the action's `credential_type` key
    /// against the envelope's `[credential_types]` table and materialises
    /// the credential before handing control to the child process. When
    /// `false` (the default), no credential injection occurs regardless of
    /// what `[credential_types]` declares — the action runs with env
    /// passthrough only.
    ///
    /// Default: `false` — existing construct.toml files that omit this field
    /// behave identically to their current semantics (no credential injection).
    #[serde(default)]
    pub needs_credentials: bool,
}

fn default_on_shim_eof() -> String {
    "sigterm".to_string()
}

#[derive(Debug, Deserialize)]
struct ActionRefCarrierManifest {
    meta: ActionRefCarrierMeta,
    #[serde(default)]
    rail: Option<RailBlock>,
    #[serde(default)]
    actions: Vec<ActionRefCarrierAction>,
}

#[derive(Debug, Deserialize)]
struct ActionRefCarrierMeta {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    plugin_address: Option<String>,
    #[serde(default)]
    plugin_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ActionRefCarrierAction {
    key: String,
    #[serde(default)]
    action_version: Option<String>,
    #[serde(default)]
    semantic_labels: Vec<String>,
}

const ALLOWED_SHIM_EOF_POLICIES: &[&str] = &["sigterm", "drain"];

const ACTION_MANIFEST_TOP_LEVEL_FIELDS: &[&str] = &[
    "schema_version",
    "default",
    "meta",
    "defaults",
    "runtime",
    "deprecated_exec",
    "actions",
    "rail",
    "settings_overlay",
];

const ACTION_MANIFEST_ACTION_FIELDS: &[&str] = &[
    "key",
    "action_version",
    "summary",
    "input_schema",
    "risk_tier",
    "idempotency",
    "interaction_class",
    "default",
    "mode",
    "biometric",
    "biometric_when_production_bucket",
    "budget_caps",
    "materialization_class",
    "material_classes",
    "authority_refs",
    "default_runner_classes",
    "audit_fields",
    "handler_ref",
    "description",
    "output_schema",
    "semantic_labels",
    "topology_hints",
    "attestation_hints",
    "cost_hints",
    "deprecation",
    "headless_requirements",
    "vault_paths",
    "env_passthrough",
    "file_env",
    "on_shim_eof",
    "terminal_mode",
    "need",
    "need_ir",
];

const RAW_EXEC_FIELDS: &[&str] = &["binary", "cwd"];

const ALLOWED_MODES: &[&str] = &[
    "auto_approve_if_pregranted",
    "jit_approval",
    "deny",
    "auto_approve",
];

const BUNDLED_PUBLISHER: &str = "did:emberlink";

const BUDGET_CAP_MIN: i64 = 1;
const BUDGET_CAP_MAX: i64 = 10000;
const WALL_CLOCK_BUDGET_CAP_MAX: i64 = 86400;

/// Parse + validate a `construct.toml` from a string. Returns the parsed
/// envelope on success, or the first invariant violation encountered.
///
/// **Pre:** `text` is UTF-8 (caller's responsibility — `construct.toml` is
/// embedded via `include_str!` which guarantees this).
/// **Post:** on `Ok`, the returned `ConstructToml` satisfies all 8 invariants
/// from `docs/construct-toml-schema.md`; on `Err`, the violated invariant
/// is named in the error message.
pub fn parse_and_validate(text: &str) -> Result<ConstructToml> {
    let parsed: ConstructToml =
        toml::from_str(text).map_err(|e| ConstructTomlError::Parse(e.to_string()))?;
    validate(&parsed)?;
    Ok(parsed)
}

/// Parse + validate the ADR 196 action-manifest schema carried by
/// `construct.toml` schema_version = "2".
///
/// The old 12-invariant parser above intentionally remains unchanged for the
/// daemon's pre-migration manifest-load path. This entry point is the
/// fail-closed v2 surface S3/S4 can wire in as manifests migrate.
pub fn parse_action_manifest(text: &str) -> ActionManifestResult<ParsedActionManifest> {
    let value: toml::Value =
        toml::from_str(text).map_err(|e| ActionManifestError::Parse(e.to_string()))?;
    validate_action_manifest_field_surface(&value)?;
    let manifest: ActionManifest =
        toml::from_str(text).map_err(|e| ActionManifestError::Parse(e.to_string()))?;
    validate_action_manifest(&manifest)?;
    Ok(ParsedActionManifest {
        manifest,
        warnings: Vec::new(),
    })
}

fn validate_action_manifest_field_surface(value: &toml::Value) -> ActionManifestResult<()> {
    let Some(table) = value.as_table() else {
        return Err(ActionManifestError::Parse(
            "action manifest root must be a TOML table".to_string(),
        ));
    };

    for key in table.keys() {
        if RAW_EXEC_FIELDS.contains(&key.as_str()) {
            return Err(ActionManifestError::RawExecFieldOutsideDeprecatedExec {
                path: "$".to_string(),
                field: key.clone(),
            });
        }
        if !ACTION_MANIFEST_TOP_LEVEL_FIELDS.contains(&key.as_str()) {
            return Err(ActionManifestError::UnknownTopLevelField(key.clone()));
        }
    }

    if let Some(defaults) = table.get("defaults").and_then(toml::Value::as_table) {
        validate_material_alias_keys(defaults, "[defaults]")?;
    }

    let Some(actions) = table.get("actions") else {
        return Ok(());
    };
    let Some(actions) = actions.as_array() else {
        return Ok(());
    };
    for action in actions {
        let Some(action_table) = action.as_table() else {
            continue;
        };
        let action_key = action_table
            .get("key")
            .and_then(toml::Value::as_str)
            .map(str::to_string);
        validate_material_alias_keys(action_table, &format_action_path(action_key.as_deref()))?;
        for key in action_table.keys() {
            if RAW_EXEC_FIELDS.contains(&key.as_str()) {
                return Err(ActionManifestError::RawExecFieldOutsideDeprecatedExec {
                    path: format_action_path(action_key.as_deref()),
                    field: key.clone(),
                });
            }
            if !ACTION_MANIFEST_ACTION_FIELDS.contains(&key.as_str()) {
                return Err(ActionManifestError::UnknownActionField {
                    action: action_key.clone(),
                    field: key.clone(),
                });
            }
        }
    }

    Ok(())
}

fn validate_material_alias_keys(
    table: &toml::map::Map<String, toml::Value>,
    scope: &str,
) -> ActionManifestResult<()> {
    if table.contains_key("authority_refs") {
        return Err(ActionManifestError::AuthorityRefsAliasDisallowed {
            scope: scope.to_string(),
        });
    }
    Ok(())
}

fn format_action_path(action_key: Option<&str>) -> String {
    match action_key {
        Some(key) if !key.trim().is_empty() => format!("[[actions]] key={key:?}"),
        _ => "[[actions]]".to_string(),
    }
}

pub fn validate_action_manifest(manifest: &ActionManifest) -> ActionManifestResult<()> {
    if manifest.schema_version != ACTION_MANIFEST_CARRIER_SCHEMA_V2 {
        return Err(ActionManifestError::UnknownSchemaVersion(
            manifest.schema_version.clone(),
        ));
    }

    validate_action_manifest_provider(manifest)?;

    if manifest.deprecated_exec.is_some() {
        if manifest.actions.is_empty() {
            return Err(ActionManifestError::DeprecatedExecWithoutActions);
        }
        return Err(ActionManifestError::DeprecatedExecDisallowed);
    }

    validate_material_alias_surface(manifest)?;
    validate_default_material_env_names(&manifest.defaults)?;
    validate_action_manifest_settings_overlay(manifest)?;

    let mut seen = HashSet::new();
    for action in &manifest.actions {
        if !seen.insert(action.key.clone()) {
            return Err(ActionManifestError::DuplicateActionKey(action.key.clone()));
        }

        action.action_ref(manifest).validate().map_err(|reason| {
            ActionManifestError::InvalidActionRef {
                action: action.key.clone(),
                reason: reason.to_string(),
            }
        })?;

        if !handler_ref_matches_provider(&action.handler_ref, manifest.meta.provider_kind) {
            return Err(ActionManifestError::InvalidHandlerRef {
                action: action.key.clone(),
                handler_ref: action.handler_ref.clone(),
                provider_kind: manifest.meta.provider_kind,
            });
        }

        validate_action_material_env_names(action)?;
        validate_action_budget_caps(action)?;
        validate_action_need_ir(action)?;

        if effective_runner_classes(&manifest.defaults, action).is_empty() {
            return Err(ActionManifestError::EmptyRunnerClasses {
                action: action.key.clone(),
            });
        }

        let Some(materialization_class) =
            effective_materialization_class(&manifest.defaults, action)
        else {
            return Err(ActionManifestError::MissingMaterializationClass {
                action: action.key.clone(),
            });
        };

        let materials = effective_materials(&manifest.defaults, action);
        if !materialization_class_matches(materialization_class, &materials) {
            return Err(ActionManifestError::MaterializationClassMismatch {
                action: action.key.clone(),
                class: materialization_class,
            });
        }
    }

    Ok(())
}

fn validate_action_budget_caps(action: &ActionManifestAction) -> ActionManifestResult<()> {
    for (key, value) in &action.budget_caps {
        let max = if key == "wall_clock_secs" {
            WALL_CLOCK_BUDGET_CAP_MAX
        } else {
            BUDGET_CAP_MAX
        };
        if *value < BUDGET_CAP_MIN || *value > max {
            return Err(ActionManifestError::ActionBudgetCapOutOfBounds {
                action: action.key.clone(),
                key: key.clone(),
                value: *value,
            });
        }
    }
    Ok(())
}

fn validate_action_need_ir(action: &ActionManifestAction) -> ActionManifestResult<()> {
    let Some(need_ir) = &action.need_ir else {
        return Ok(());
    };

    validate_need_ir_archetype_data(need_ir)
        .and_then(|_| validate_need_ir_projection_within_declared_need(need_ir, &action.need))
        .map_err(|reason| ActionManifestError::InvalidNeedIr {
            action: action.key.clone(),
            reason,
        })
}

pub fn validate_need_ir_archetype_data(
    need_ir: &NeedIrArchetypeData,
) -> std::result::Result<(), String> {
    match need_ir {
        NeedIrArchetypeData::PolicyDocument(data) => {
            require_non_empty_string(&data.provider, "provider")?;
            require_non_empty_string(&data.policy_language, "policy_language")?;
            if data.statements.is_empty() {
                return Err("policy-document statements must be non-empty".to_string());
            }
            for (index, statement) in data.statements.iter().enumerate() {
                let label = format!("statements[{index}]");
                require_non_empty_strings(&statement.actions, &format!("{label}.actions"))?;
                require_non_empty_strings(&statement.resources, &format!("{label}.resources"))?;
                for (condition_index, condition) in statement.conditions.iter().enumerate() {
                    let condition_label = format!("{label}.conditions[{condition_index}]");
                    require_non_empty_string(&condition.key, &format!("{condition_label}.key"))?;
                    require_non_empty_string(
                        &condition.operator,
                        &format!("{condition_label}.operator"),
                    )?;
                    require_non_empty_strings(
                        &condition.values,
                        &format!("{condition_label}.values"),
                    )?;
                }
            }
        }
        NeedIrArchetypeData::OauthScope(data) => {
            require_non_empty_string(&data.provider, "provider")?;
            require_non_empty_strings(&data.scopes, "scopes")?;
            if let Some(audience) = &data.audience {
                require_non_empty_string(audience, "audience")?;
            }
            if let Some(resource) = &data.resource {
                require_non_empty_string(resource, "resource")?;
            }
        }
        NeedIrArchetypeData::IdentityOnly(data) => {
            require_non_empty_string(&data.provider, "provider")?;
            require_non_empty_string(&data.identity.kind, "identity.kind")?;
            require_non_empty_string(&data.identity.value, "identity.value")?;
        }
        NeedIrArchetypeData::RegistryJwt(data) => {
            require_non_empty_string(&data.provider, "provider")?;
            require_non_empty_string(&data.registry, "registry")?;
            require_non_empty_string(&data.audience, "audience")?;
            if data.claims.is_empty() {
                return Err("registry-JWT claims must be non-empty".to_string());
            }
            for (index, claim) in data.claims.iter().enumerate() {
                let label = format!("claims[{index}]");
                require_non_empty_string(&claim.name, &format!("{label}.name"))?;
                require_non_empty_strings(&claim.values, &format!("{label}.values"))?;
            }
        }
        NeedIrArchetypeData::Budget(data) => {
            require_non_empty_string(&data.provider, "provider")?;
            let axes = [
                ("tokens", data.tokens),
                ("cents", data.cents),
                ("requests", data.requests),
                ("wall_clock_secs", data.wall_clock_secs),
            ];
            if axes.iter().all(|(_, value)| value.is_none()) {
                return Err("budget must set at least one axis".to_string());
            }
            for (axis, value) in axes {
                if let Some(value) = value
                    && value <= 0
                {
                    return Err(format!("budget.{axis} must be positive"));
                }
            }
        }
    }

    Ok(())
}

/// Validate ADR 213 D5.3 monotonicity for inert need-IR archetype data.
///
/// `construct.toml`'s `need` list is the static action-axis declaration in
/// the canonical `provider:object:verb` algebra. This check proves that every
/// action/budget/identity atom projected from the closed `need_ir` shape is
/// covered by that declaration. Dynamic resource narrowing remains owned by
/// the factory target/need-template path.
pub fn validate_need_ir_projection_within_declared_need(
    need_ir: &NeedIrArchetypeData,
    declared_need: &[String],
) -> std::result::Result<(), String> {
    let projected = need_ir_projected_declared_need_atoms(need_ir);
    if projected.is_empty() {
        return Ok(());
    }
    if declared_need.is_empty() {
        return Err(format!(
            "need_ir projection is non-monotone: projected atom {} has no declared need",
            projected[0]
        ));
    }

    for atom in projected {
        if !declared_need
            .iter()
            .any(|declared| declared_need_atom_covers(declared, &atom))
        {
            return Err(format!(
                "need_ir projection is non-monotone: projected atom {atom} is not covered by declared need {:?}",
                declared_need
            ));
        }
    }

    Ok(())
}

/// Conservative action-axis projection used only for static monotonicity.
///
/// It deliberately does not emit native provider scope and does not try to
/// encode resource selectors that the current `need: Vec<String>` carrier
/// cannot represent. Provider projectors and factory need templates remain the
/// authority path for resource/target lowering.
pub fn need_ir_projected_declared_need_atoms(need_ir: &NeedIrArchetypeData) -> Vec<String> {
    let mut atoms = Vec::new();
    match need_ir {
        NeedIrArchetypeData::PolicyDocument(data) => {
            for statement in &data.statements {
                if statement.effect != PolicyEffect::Allow {
                    continue;
                }
                atoms.extend(
                    statement
                        .actions
                        .iter()
                        .map(|action| provider_scoped_need_atom(&data.provider, action)),
                );
            }
        }
        NeedIrArchetypeData::OauthScope(data) => {
            atoms.extend(
                data.scopes
                    .iter()
                    .map(|scope| provider_scoped_need_atom(&data.provider, scope)),
            );
        }
        NeedIrArchetypeData::IdentityOnly(data) => {
            atoms.push(format!(
                "{}:identity:{}:{}",
                data.provider, data.identity.kind, data.identity.value
            ));
        }
        NeedIrArchetypeData::RegistryJwt(data) => {
            atoms.push(format!("{}:registry:{}", data.provider, data.registry));
            atoms.push(format!("{}:audience:{}", data.provider, data.audience));
            for claim in &data.claims {
                atoms.extend(
                    claim
                        .values
                        .iter()
                        .map(|value| format!("{}:claim:{}:{value}", data.provider, claim.name)),
                );
            }
        }
        NeedIrArchetypeData::Budget(data) => {
            for (axis, value) in [
                ("tokens", data.tokens),
                ("cents", data.cents),
                ("requests", data.requests),
                ("wall_clock_secs", data.wall_clock_secs),
            ] {
                if value.is_some() {
                    atoms.push(format!("{}:budget:{axis}", data.provider));
                }
            }
        }
    }
    atoms
}

fn provider_scoped_need_atom(provider: &str, atom: &str) -> String {
    if atom
        .split_once(':')
        .is_some_and(|(atom_provider, _)| atom_provider == provider)
    {
        atom.to_string()
    } else {
        format!("{provider}:{atom}")
    }
}

fn declared_need_atom_covers(declared: &str, projected: &str) -> bool {
    if declared == "*" || declared == projected {
        return true;
    }

    let Some((declared_provider, declared_rest)) = declared.split_once(':') else {
        return false;
    };
    if declared_provider.is_empty() || declared_rest != "*" {
        return false;
    }

    projected
        .split_once(':')
        .is_some_and(|(projected_provider, _)| projected_provider == declared_provider)
}

fn require_non_empty_string(value: &str, field: &str) -> std::result::Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn require_non_empty_strings(values: &[String], field: &str) -> std::result::Result<(), String> {
    if values.is_empty() {
        return Err(format!("{field} must be non-empty"));
    }
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(format!("{field} entries must be non-empty"));
    }
    Ok(())
}

fn validate_action_manifest_provider(manifest: &ActionManifest) -> ActionManifestResult<()> {
    match manifest.meta.provider_kind {
        ProviderKind::Cli => {
            if manifest.meta.mock {
                return Err(ActionManifestError::MockFlagOutsideMockProvider);
            }
            if manifest.runtime.cli.is_none() {
                return Err(ActionManifestError::MissingCliRuntime);
            }
        }
        ProviderKind::Api => {
            if manifest.meta.mock {
                return Err(ActionManifestError::MockFlagOutsideMockProvider);
            }
            if manifest.runtime.cli.is_some() {
                return Err(ActionManifestError::UnexpectedCliRuntime(
                    manifest.meta.provider_kind,
                ));
            }
            if manifest.deprecated_exec.is_some() {
                return Err(ActionManifestError::DeprecatedExecForNonCli(
                    manifest.meta.provider_kind,
                ));
            }
        }
        ProviderKind::MockApi => {
            if !manifest.meta.mock {
                return Err(ActionManifestError::MockProviderMissingMockFlag);
            }
            if manifest.runtime.cli.is_some() {
                return Err(ActionManifestError::UnexpectedCliRuntime(
                    manifest.meta.provider_kind,
                ));
            }
            if manifest.deprecated_exec.is_some() {
                return Err(ActionManifestError::DeprecatedExecForNonCli(
                    manifest.meta.provider_kind,
                ));
            }
        }
    }
    Ok(())
}

/// Invariant 13 — validate the per-Construct Claude `settings.json` deny
/// overlay (ADR 124 §3 / V030-CLAUDE-OVERLAY).
///
/// Schema layer (13b — no `permissions_allow`) is enforced by
/// `#[serde(deny_unknown_fields)]` on `SettingsOverlay`; this function carries
/// the post-parse invariants:
///
/// - **13a — Bash-only.** Each entry must be a `Bash(...)` tool-prefix rule;
///   `Read(...)`, `Edit(...)`, etc. are refused (the host-lane bypass surface
///   the launcher overlay defends against is shell invocation).
/// - **13b — cross-tool binding.** The first whitespace-separated token inside
///   the parentheses must be an absolute path whose basename equals the
///   manifest's `runtime.cli.wrapped_binary`. Prevents a Construct from
///   authoring denies that scope across tools (e.g. `gh.toml` declaring
///   `Bash(/usr/bin/curl *)` would silently widen the gh manifest's blast
///   radius and could collide with another Construct's policy authorship).
/// - **13c — absolute-path only.** Bare-name forms (`Bash(gh *)`) are refused
///   because Claude's matcher semantics against the shadow PATH are ambiguous
///   — the shim and the PATH-resolved binary share the bare name. Operators
///   need a single unambiguous shape per absolute prefix.
///
/// A manifest without `[settings_overlay]` is a no-op here. A manifest that
/// declares `[settings_overlay]` without an attached CLI runtime is refused —
/// there is no `wrapped_binary` to bind against, and Bash-only denies for an
/// API/mock provider would not project meaningfully into the launcher.
fn validate_action_manifest_settings_overlay(
    manifest: &ActionManifest,
) -> ActionManifestResult<()> {
    let Some(overlay) = manifest.settings_overlay.as_ref() else {
        return Ok(());
    };

    let wrapped_binary = manifest
        .runtime
        .cli
        .as_ref()
        .map(|cli| cli.wrapped_binary.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ActionManifestError::InvalidSettingsOverlay {
            reason: "[settings_overlay] requires a CLI provider with `runtime.cli.wrapped_binary` \
                     set; API and mock providers have no shell-invocation surface to deny"
                .to_string(),
        })?;

    for entry in &overlay.permissions_deny {
        validate_settings_overlay_entry(entry, wrapped_binary)?;
    }

    Ok(())
}

fn validate_settings_overlay_entry(entry: &str, wrapped_binary: &str) -> ActionManifestResult<()> {
    // Invariant 13a — Bash(...) shape required.
    let body = entry
        .strip_prefix("Bash(")
        .and_then(|rest| rest.strip_suffix(')'))
        .ok_or_else(|| ActionManifestError::InvalidSettingsOverlay {
            reason: format!(
                "entry {entry:?} is not a `Bash(...)` rule; only Bash tool-prefix denies are accepted \
                 (invariant 13a — Read/Edit/WebFetch are not in scope for v0.3.0)"
            ),
        })?;

    // First whitespace-separated token = the binary the rule scopes against.
    let first_token = body.split_whitespace().next().ok_or_else(|| {
        ActionManifestError::InvalidSettingsOverlay {
            reason: format!("entry {entry:?} has no command token inside Bash(...)"),
        }
    })?;

    // Invariant 13c — absolute-path forms only (no bare-name forms like
    // `Bash(gh *)`). The shadow PATH shim and the PATH-resolved binary share
    // the bare name; Claude's matcher would treat them identically, so the
    // deny would either be vacuous (matches the shim too) or ambiguous.
    if !first_token.starts_with('/') {
        return Err(ActionManifestError::InvalidSettingsOverlay {
            reason: format!(
                "entry {entry:?} uses a bare-name form (first token {first_token:?}); \
                 only absolute-path forms (e.g. `Bash(/usr/bin/{wrapped_binary} *)`) are accepted \
                 (invariant 13c — bare-name is ambiguous against the shadow PATH shim)"
            ),
        });
    }

    // Invariant 13b — cross-tool binding. The absolute path's basename must
    // be exactly the wrapped_binary so a manifest cannot author denies that
    // scope across tools.
    let basename = first_token.rsplit('/').next().unwrap_or("");
    if basename != wrapped_binary {
        return Err(ActionManifestError::InvalidSettingsOverlay {
            reason: format!(
                "entry {entry:?} targets binary {basename:?}, but this manifest wraps \
                 {wrapped_binary:?} (invariant 13b — a Construct may only author denies for its \
                 own wrapped binary)"
            ),
        });
    }

    Ok(())
}

fn validate_material_alias_surface(manifest: &ActionManifest) -> ActionManifestResult<()> {
    if !manifest.defaults.authority_refs.is_empty() {
        return Err(ActionManifestError::AuthorityRefsAliasDisallowed {
            scope: "[defaults]".to_string(),
        });
    }
    for action in &manifest.actions {
        if !action.authority_refs.is_empty() {
            return Err(ActionManifestError::AuthorityRefsAliasDisallowed {
                scope: format_action_path(Some(&action.key)),
            });
        }
    }

    Ok(())
}

fn validate_default_material_env_names(
    defaults: &ActionManifestDefaults,
) -> ActionManifestResult<()> {
    validate_material_env_names("<defaults>", &defaults.material_classes, |field, name| {
        ActionManifestError::InvalidDefaultEnvName { field, name }
    })?;
    for name in &defaults.env_passthrough {
        if !is_valid_env_name(name) {
            return Err(ActionManifestError::InvalidDefaultEnvName {
                field: "env_passthrough",
                name: name.clone(),
            });
        }
    }
    for name in &defaults.file_env {
        if !is_valid_env_name(name) {
            return Err(ActionManifestError::InvalidDefaultEnvName {
                field: "file_env",
                name: name.clone(),
            });
        }
    }
    Ok(())
}

fn validate_action_material_env_names(action: &ActionManifestAction) -> ActionManifestResult<()> {
    validate_material_env_names(&action.key, &action.material_classes, |field, name| {
        ActionManifestError::InvalidActionEnvName {
            action: action.key.clone(),
            field,
            name,
        }
    })?;
    for name in &action.env_passthrough {
        if !is_valid_env_name(name) {
            return Err(ActionManifestError::InvalidActionEnvName {
                action: action.key.clone(),
                field: "env_passthrough",
                name: name.clone(),
            });
        }
    }
    for name in &action.file_env {
        if !is_valid_env_name(name) {
            return Err(ActionManifestError::InvalidActionEnvName {
                action: action.key.clone(),
                field: "file_env",
                name: name.clone(),
            });
        }
    }
    Ok(())
}

fn validate_material_env_names<E>(
    _scope: &str,
    materials: &[MaterialClass],
    error: impl Fn(&'static str, String) -> E,
) -> std::result::Result<(), E> {
    for material in materials {
        match material {
            MaterialClass::Env { name } => {
                if !is_valid_env_name(name) {
                    return Err(error("material_classes.env", name.clone()));
                }
            }
            MaterialClass::FileEnv { name } => {
                if !is_valid_env_name(name) {
                    return Err(error("material_classes.file_env", name.clone()));
                }
            }
            MaterialClass::Broker { .. } | MaterialClass::VaultPath { .. } => {}
        }
    }
    Ok(())
}

fn effective_runner_classes(
    defaults: &ActionManifestDefaults,
    action: &ActionManifestAction,
) -> Vec<RunnerClass> {
    if action.default_runner_classes.is_empty() {
        defaults.default_runner_classes.clone()
    } else {
        action.default_runner_classes.clone()
    }
}

fn effective_materialization_class(
    defaults: &ActionManifestDefaults,
    action: &ActionManifestAction,
) -> Option<MaterializationClass> {
    action
        .materialization_class
        .or(defaults.materialization_class)
}

fn effective_materials(
    defaults: &ActionManifestDefaults,
    action: &ActionManifestAction,
) -> Vec<MaterialClass> {
    let mut materials = Vec::new();
    append_materials(
        &mut materials,
        &defaults.material_classes,
        &defaults.authority_refs,
        &defaults.vault_paths,
        &defaults.env_passthrough,
        &defaults.file_env,
    );
    append_materials(
        &mut materials,
        &action.material_classes,
        &action.authority_refs,
        &action.vault_paths,
        &action.env_passthrough,
        &action.file_env,
    );
    materials
}

fn append_materials(
    materials: &mut Vec<MaterialClass>,
    material_classes: &[MaterialClass],
    authority_refs: &[String],
    vault_paths: &[String],
    env_passthrough: &[String],
    file_env: &[String],
) {
    if material_classes.is_empty() {
        materials.extend(
            authority_refs
                .iter()
                .cloned()
                .map(|authority_ref| MaterialClass::Broker { authority_ref }),
        );
    } else {
        materials.extend(material_classes.iter().cloned());
    }
    materials.extend(
        vault_paths
            .iter()
            .cloned()
            .map(|path| MaterialClass::VaultPath { path }),
    );
    materials.extend(
        env_passthrough
            .iter()
            .cloned()
            .map(|name| MaterialClass::Env { name }),
    );
    materials.extend(
        file_env
            .iter()
            .cloned()
            .map(|name| MaterialClass::FileEnv { name }),
    );
}

fn materialization_class_matches(class: MaterializationClass, materials: &[MaterialClass]) -> bool {
    let has_broker = materials
        .iter()
        .any(|material| matches!(material, MaterialClass::Broker { .. }));
    let has_host = materials.iter().any(|material| {
        matches!(
            material,
            MaterialClass::Env { .. }
                | MaterialClass::FileEnv { .. }
                | MaterialClass::VaultPath { .. }
        )
    });

    match class {
        MaterializationClass::None => !has_broker && !has_host,
        MaterializationClass::BrokeredCredential => has_broker && !has_host,
        MaterializationClass::DeclaredHostMaterial => !has_broker && has_host,
        MaterializationClass::Mixed => has_broker && has_host,
    }
}

fn handler_ref_matches_provider(handler_ref: &str, provider_kind: ProviderKind) -> bool {
    let expected_prefix = match provider_kind {
        ProviderKind::Cli => "cli:",
        ProviderKind::Api => "api:",
        ProviderKind::MockApi => "mock:",
    };
    handler_ref
        .strip_prefix(expected_prefix)
        .is_some_and(|suffix| !suffix.trim().is_empty())
}

/// Resolve ADR 184 identity fields for `action_key` from the embedded
/// `construct.toml` carrier bytes shipped with a construct binary.
///
/// The migration intentionally reads the live carrier shape directly instead of
/// reconstructing identity from publisher DID prefixes or wrapped-binary names.
pub fn resolve_action_manifest_identity(
    text: &str,
    action_key: &str,
) -> std::result::Result<ConstructActionManifestIdentity, ConstructActionRefError> {
    // Fail-closed load seam (ADR 184 §6 "one logical schema", ADR 196). The
    // carrier is the action manifest in fact, not only in name: a carrier that
    // is not a valid v2 manifest — e.g. one that declares only raw exec
    // metadata — is refused here, before any identity is extracted, rather than
    // being silently reduced to its `action_ref` tuple. This is the single
    // enforcement point that realizes P11's Definition of Success; the broker
    // boundary itself still carries only the structured `ActionRef` (ADR 192),
    // and the manifest's richer material/runner/risk policy stays the
    // plugin-side declaration distinct from the authority-side
    // `ExecutionContract` (ADR 184 §7/§8) — it is validated, not threaded.
    parse_action_manifest(text)
        .map_err(|e| ConstructActionRefError::ManifestSchema(e.to_string()))?;

    let manifest: ActionRefCarrierManifest =
        toml::from_str(text).map_err(|e| ConstructActionRefError::Parse(e.to_string()))?;
    validate_carrier_rail_block(manifest.rail.as_ref())?;
    let plugin_address = manifest
        .meta
        .plugin_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(ConstructActionRefError::MissingPluginAddress)?;

    let plugin_version = manifest
        .meta
        .plugin_version
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| manifest.meta.version.as_deref().map(str::trim))
        .filter(|s| !s.is_empty())
        .ok_or(ConstructActionRefError::MissingPluginVersion)?;

    let action = resolve_manifest_action(&manifest, plugin_address, action_key)
        .ok_or_else(|| ConstructActionRefError::UnknownAction(action_key.to_string()))?;
    let resolved_action_key = action.key.as_str();
    let action_version = action
        .action_version
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            ConstructActionRefError::MissingActionVersion(resolved_action_key.to_string())
        })?;

    let identity = ConstructActionManifestIdentity {
        plugin_address: plugin_address.to_string(),
        plugin_version: plugin_version.to_string(),
        action_key: resolved_action_key.to_string(),
        action_version: action_version.to_string(),
        semantic_labels: action.semantic_labels.clone(),
    };
    let action_ref = identity.action_ref();
    action_ref
        .validate()
        .map_err(|e| ConstructActionRefError::InvalidActionRef(e.to_string()))?;
    Ok(identity)
}

/// Resolve the canonical structured [`ActionRef`] for `action_key` from the
/// embedded `construct.toml` carrier bytes shipped with a construct binary.
pub fn resolve_action_ref(
    text: &str,
    action_key: &str,
) -> std::result::Result<ActionRef, ConstructActionRefError> {
    Ok(resolve_action_manifest_identity(text, action_key)?.action_ref())
}

/// Resolve an action's declared least-privilege authority **need** (canonical
/// `provider:object:verb`; ADR 204 Amendment 6, checkpoint
/// `action_need_is_manifest_sourced_not_hardcoded`) from a construct manifest's
/// bytes, keyed by the daemon-classified `action_key`.
///
/// This is the manifest-sourced replacement for the daemon's formerly hardcoded
/// `ember_construct::policy::github_action_need` map. The manifest is the
/// **attested authority input** (ADR 205 §10): the daemon resolves need from the
/// *bundled* manifest (`include_str!`-compiled — the same trust base as the old
/// hardcode), keyed by the daemon-classified tool+action, never from
/// shim-supplied bytes.
///
/// Matching mirrors [`resolve_action_ref`]: the manifest action is found by
/// exact `key` first, then the legacy dotted-key alias
/// ([`legacy_manifest_action_key`]: `gh.pr_list` → bare `pr_list`), so both the
/// bare-keyed `gh` manifest and the dotted-keyed `git` manifest resolve from the
/// classifiers' dotted action keys. Returns the action's `need` (`[]` when it
/// declares none); `Err` when the bytes are not a valid v2 manifest or the
/// action is unknown.
pub fn resolve_action_need(
    text: &str,
    action_key: &str,
) -> std::result::Result<Vec<String>, ConstructActionRefError> {
    let parsed = parse_action_manifest(text)
        .map_err(|e| ConstructActionRefError::ManifestSchema(e.to_string()))?;
    let plugin_address = parsed.manifest.meta.plugin_address.as_str();
    let action = parsed
        .manifest
        .actions
        .iter()
        .find(|action| action.key == action_key)
        .or_else(|| {
            let legacy_alias = legacy_manifest_action_key(plugin_address, action_key)?;
            parsed
                .manifest
                .actions
                .iter()
                .find(|action| action.key == legacy_alias)
        })
        .ok_or_else(|| ConstructActionRefError::UnknownAction(action_key.to_string()))?;
    Ok(action.need.clone())
}

pub fn resolve_action_terminal_mode(
    text: &str,
    action_key: &str,
) -> std::result::Result<TerminalMode, ConstructActionRefError> {
    let parsed = parse_action_manifest(text)
        .map_err(|e| ConstructActionRefError::ManifestSchema(e.to_string()))?;
    let plugin_address = parsed.manifest.meta.plugin_address.as_str();
    let action = parsed
        .manifest
        .actions
        .iter()
        .find(|action| action.key == action_key)
        .or_else(|| {
            let legacy_alias = legacy_manifest_action_key(plugin_address, action_key)?;
            parsed
                .manifest
                .actions
                .iter()
                .find(|action| action.key == legacy_alias)
        })
        .ok_or_else(|| ConstructActionRefError::UnknownAction(action_key.to_string()))?;
    Ok(action.terminal_mode)
}

fn resolve_manifest_action<'a>(
    manifest: &'a ActionRefCarrierManifest,
    plugin_address: &str,
    action_key: &str,
) -> Option<&'a ActionRefCarrierAction> {
    manifest
        .actions
        .iter()
        .find(|action| action.key == action_key)
        .or_else(|| {
            let legacy_alias = legacy_manifest_action_key(plugin_address, action_key)?;
            manifest
                .actions
                .iter()
                .find(|action| action.key == legacy_alias)
        })
}

// Cohort-A GitHub classifiers still emit legacy dotted action keys like
// `gh.pr_list`, while the bundled GH manifest's canonical action keys are the
// bare suffixes (`pr_list`). Resolve through the manifest's own namespace so
// legacy callers converge onto the structured canonical `ActionRef`.
fn legacy_manifest_action_key<'a>(plugin_address: &str, action_key: &'a str) -> Option<&'a str> {
    let plugin_name = plugin_address.rsplit('/').next()?.trim();
    let namespace = plugin_name.strip_prefix("ember-").unwrap_or(plugin_name);
    let (prefix, suffix) = action_key.split_once('.')?;
    (prefix == namespace).then_some(suffix)
}

/// Validate an already-parsed `ConstructToml`. Returns the first invariant
/// violation encountered, or `Ok(())` if the current schema invariants hold.
pub fn validate(c: &ConstructToml) -> Result<()> {
    // Invariant 1: schema_version must be "1".
    if c.schema_version != "1" {
        return Err(ConstructTomlError::UnknownSchemaVersion(
            c.schema_version.clone(),
        ));
    }

    // Invariant 2: meta.publisher must be a valid DID.
    if !is_valid_did(&c.meta.publisher) {
        return Err(ConstructTomlError::InvalidPublisherDid(
            c.meta.publisher.clone(),
        ));
    }

    // Invariant 3: action ID collision is impossible by HashMap construction
    // — toml::from_str rejects duplicate keys at parse time. We assert it
    // anyway via the action-id pattern check (defends manual construction).
    let mut seen = std::collections::HashSet::new();
    for id in c.actions.keys() {
        if !seen.insert(id.clone()) {
            return Err(ConstructTomlError::ActionIdCollision(id.clone()));
        }
    }

    // Invariant 4: every action's mode must be in the enum.
    for (id, block) in &c.actions {
        if !ALLOWED_MODES.contains(&block.mode.as_str()) {
            return Err(ConstructTomlError::InvalidMode {
                action: id.clone(),
                mode: block.mode.clone(),
            });
        }
    }

    // Invariant 5: classify_argv must contain only [a-zA-Z0-9._\- *] chars.
    for (id, block) in &c.actions {
        if !is_safe_classify_argv(&block.classify_argv) {
            return Err(ConstructTomlError::InvalidClassifyArgv {
                action: id.clone(),
                argv: block.classify_argv.clone(),
            });
        }
    }

    // Invariant 6: bundled publisher can't set unknown_action=auto_approve at
    // top level (must use tier_overrides.dev0 if needed).
    if c.meta.publisher == BUNDLED_PUBLISHER && c.default.unknown_action == "auto_approve" {
        return Err(ConstructTomlError::BundledAutoApproveTopLevel(
            c.meta.publisher.clone(),
        ));
    }

    // Invariant 7: wraps_binary_min_version, if set, must parse as semver.
    if let Some(v) = &c.meta.wraps_binary_min_version
        && !is_semver_parseable(v)
    {
        return Err(ConstructTomlError::InvalidMinVersion(v.clone()));
    }

    // Invariant 8: every budget_caps value is in [1, 10000].
    for (id, block) in &c.actions {
        for (key, value) in &block.budget_caps {
            if *value < BUDGET_CAP_MIN || *value > BUDGET_CAP_MAX {
                return Err(ConstructTomlError::BudgetCapOutOfBounds {
                    action: id.clone(),
                    key: key.clone(),
                    value: *value,
                });
            }
        }
    }

    // Invariant 9: on_shim_eof, if set, must be one of the allowed values.
    // (ADR 124 §"Shim-EOF correctness" axis C.) Default is "sigterm" via
    // `default_on_shim_eof`, so this catches explicit bad values.
    for (id, block) in &c.actions {
        if !ALLOWED_SHIM_EOF_POLICIES.contains(&block.on_shim_eof.as_str()) {
            return Err(ConstructTomlError::InvalidShimEofPolicy {
                action: id.clone(),
                value: block.on_shim_eof.clone(),
            });
        }
    }

    // Invariant 10: every env_passthrough name on every action must match
    // the env-name shape regex (ADR 124 axis A2). Names that pass here are
    // safe to compare against caller-supplied env names at broker_exec.
    for (id, block) in &c.actions {
        for name in &block.env_passthrough {
            if !is_valid_env_name(name) {
                return Err(ConstructTomlError::InvalidEnvPassthroughName {
                    action: id.clone(),
                    name: name.clone(),
                });
            }
        }
    }

    validate_schema_rail_block(c.rail.as_ref())?;

    Ok(())
}

fn validate_schema_rail_block(rail: Option<&RailBlock>) -> Result<()> {
    validate_rail_block(
        rail,
        || ConstructTomlError::MissingRailTrustContract,
        ConstructTomlError::InvalidRailTrustContract,
    )
}

fn validate_carrier_rail_block(
    rail: Option<&RailBlock>,
) -> std::result::Result<(), ConstructActionRefError> {
    validate_rail_block(
        rail,
        || ConstructActionRefError::MissingRailTrustContract,
        ConstructActionRefError::InvalidRailTrustContract,
    )
}

fn validate_rail_block<E>(
    rail: Option<&RailBlock>,
    missing: impl FnOnce() -> E,
    invalid: impl FnOnce(String) -> E,
) -> std::result::Result<(), E> {
    let Some(rail) = rail else {
        return Ok(());
    };
    let Some(raw_contract) = rail
        .trust_contract
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(missing());
    };
    RailTrustContract::from_str(raw_contract)
        .map(|_| ())
        .map_err(|_| invalid(raw_contract.to_string()))
}

/// Per-action env-passthrough name shape. Mirrors the daemon's
/// defense-in-depth regex (`^[A-Z_][A-Z0-9_]*$`) so the validate-time
/// check and the runtime broker_exec check can never disagree.
fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_uppercase() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Minimal DID validator. Accepts both `did:method` (informal 2-part shape
/// the codebase has been using for `did:emberlink`, `did:wrangler-team`)
/// and the formal W3C `did:method:identifier` shape. The trust-graph layer
/// does the full DID-method resolution; this validator just keeps junk out
/// of the publisher field.
fn is_valid_did(s: &str) -> bool {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() < 2 {
        return false;
    }
    if parts[0] != "did" {
        return false;
    }
    let method = parts[1];
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return false;
    }
    // Reject leading/trailing hyphens — keeps the method-name a clean token.
    if method.starts_with('-') || method.ends_with('-') {
        return false;
    }
    // If a method-specific identifier is present, require it non-empty.
    if parts.len() == 3 && parts[2].is_empty() {
        return false;
    }
    true
}

/// `classify_argv` allowed char class: `[a-zA-Z0-9._\- *]`. Defends regex
/// injection through the classifier.
fn is_safe_classify_argv(s: &str) -> bool {
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '*' || c == ' '
    })
}

/// Minimal semver parser: `MAJOR.MINOR.PATCH` with each component a
/// non-empty digit string. Permissive — full semver pre-release / build
/// metadata parsing is out of scope.
fn is_semver_parseable(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn valid_template() -> &'static str {
        r#"
schema_version = "1"

[meta]
name = "ember-gh"
version = "1.0.0"
publisher = "did:emberlink"
wraps_binary = "gh"
wraps_binary_min_version = "2.40.0"

[default]
unknown_action = "deny"

[default.tier_overrides]
dev0 = "auto_approve"
team0 = "deny"
ent0 = "deny"

[actions.pr_create]
mode = "auto_approve_if_pregranted"
classify_argv = "pr create *"

[actions.pr_merge]
mode = "jit_approval"
classify_argv = "pr merge *"
allowed_branches_deny = ["main", "release/*"]
budget_caps = { runs_per_session = 5, runs_per_hour = 30 }
"#
    }

    fn valid_action_manifest_v2() -> &'static str {
        r#"
schema_version = "2"

[meta]
name = "ember-gh"
plugin_address = "registry.ember.systems/ember-systems/ember-gh"
plugin_version = "0.1.0"
publisher = "did:emberlink"
provider_kind = "cli"
summary = "GitHub CLI Construct"
description = "Mediates GitHub CLI invocations through ember."

[defaults]
materialization_class = "brokered_credential"
material_classes = [{ kind = "broker", authority_ref = "github" }]
default_runner_classes = ["local_trusted"]

[runtime.cli]
wrapped_binary = "gh"
wrapped_binary_min_version = "2.40.0"

[[actions]]
key = "pr_create"
action_version = "v1"
summary = "Create a pull request"
input_schema = { kind = "argv", classifier = "pr create *" }
risk_tier = "medium"
idempotency = "non_idempotent"
interaction_class = "inline_interactive"
audit_fields = ["action_ref", "authority_ref", "runner_class", "materialization_class", "terminal_outcome"]
handler_ref = "cli:gh.pr_create"
semantic_labels = ["github.pull_request.write", "scm.pull_request.write"]
"#
    }

    fn valid_mock_action_manifest_v2() -> &'static str {
        r#"
schema_version = "2"

[meta]
name = "ember-anthropic-mock"
plugin_address = "registry.ember.systems/ember-systems/ember-anthropic-mock"
plugin_version = "0.1.0"
publisher = "did:emberlink"
provider_kind = "mock_api"
mock = true
summary = "Anthropic mock provider"
description = "Mock provider for local test lanes."

[defaults]
materialization_class = "none"
default_runner_classes = ["local_trusted"]

[[actions]]
key = "messages.create"
action_version = "v1"
summary = "Create a mock message"
input_schema = { kind = "json_schema", ref = "schemas/messages.create.input.json" }
risk_tier = "low"
idempotency = "idempotent"
interaction_class = "inline_interactive"
audit_fields = ["action_ref", "runner_class", "terminal_outcome"]
handler_ref = "mock:anthropic.messages.create"
"#
    }

    fn required_action_field_line(field: &str) -> &'static str {
        match field {
            "key" => "key = \"pr_create\"\n",
            "action_version" => "action_version = \"v1\"\n",
            "summary" => "summary = \"Create a pull request\"\n",
            "input_schema" => "input_schema = { kind = \"argv\", classifier = \"pr create *\" }\n",
            "risk_tier" => "risk_tier = \"medium\"\n",
            "idempotency" => "idempotency = \"non_idempotent\"\n",
            "interaction_class" => "interaction_class = \"inline_interactive\"\n",
            "audit_fields" => {
                "audit_fields = [\"action_ref\", \"authority_ref\", \"runner_class\", \"materialization_class\", \"terminal_outcome\"]\n"
            }
            "handler_ref" => "handler_ref = \"cli:gh.pr_create\"\n",
            _ => unreachable!("test supplies only required action fields"),
        }
    }

    #[test]
    fn action_manifest_v2_parses_and_derives_action_ref() {
        let parsed = parse_action_manifest(valid_action_manifest_v2()).expect("v2 manifest");
        assert!(parsed.warnings.is_empty());
        assert_eq!(parsed.manifest.meta.provider_kind, ProviderKind::Cli);
        let action = parsed.manifest.actions.first().expect("action");
        assert_eq!(
            action.action_ref(&parsed.manifest),
            ActionRef::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_create",
                "v1",
            )
        );
    }

    #[test]
    fn action_manifest_terminal_mode_defaults_auto_and_resolves_piped() {
        let parsed = parse_action_manifest(valid_action_manifest_v2()).expect("v2 manifest");
        let action = parsed.manifest.actions.first().expect("action");
        assert_eq!(action.terminal_mode, TerminalMode::Auto);
        assert_eq!(
            resolve_action_terminal_mode(valid_action_manifest_v2(), "pr_create")
                .expect("default terminal mode"),
            TerminalMode::Auto
        );

        let manifest = valid_action_manifest_v2().replace(
            "interaction_class = \"inline_interactive\"\n",
            "interaction_class = \"inline_interactive\"\nterminal_mode = \"piped\"\n",
        );

        assert_eq!(
            resolve_action_terminal_mode(&manifest, "pr_create").expect("exact action key"),
            TerminalMode::Piped
        );
        assert_eq!(
            resolve_action_terminal_mode(&manifest, "gh.pr_create")
                .expect("legacy dotted gh action key"),
            TerminalMode::Piped
        );
    }

    #[test]
    fn action_manifest_v2_rejects_authority_refs_alias_after_p11_s4() {
        let manifest = valid_action_manifest_v2().replace(
            "material_classes = [{ kind = \"broker\", authority_ref = \"github\" }]",
            "authority_refs = [\"github\"]",
        );
        let err = parse_action_manifest(&manifest).expect_err("authority_refs alias is retired");
        assert!(matches!(
            err,
            ActionManifestError::AuthorityRefsAliasDisallowed { scope } if scope == "[defaults]"
        ));
    }

    #[test]
    fn action_manifest_v2_accepts_live_construct_policy_fields() {
        let manifest = valid_action_manifest_v2()
            .replace("schema_version = \"2\"", "schema_version = \"2\"\ndefault = \"deny\"")
            .replace(
                "handler_ref = \"cli:gh.pr_create\"",
                "default = \"prompt\"\nmode = \"gate\"\nbiometric = \"required\"\nbiometric_when_production_bucket = true\nbudget_caps = { wall_clock_secs = 1800, cents = 500 }\nhandler_ref = \"cli:gh.pr_create\"",
            );
        let parsed = parse_action_manifest(&manifest).expect("live policy fields");
        let action = parsed.manifest.actions.first().expect("action");
        assert_eq!(
            parsed.manifest.default,
            Some(ConstructExecDefaultPolicy::Deny)
        );
        assert_eq!(action.default, Some(ConstructExecDefaultPolicy::Prompt));
        assert_eq!(action.mode, Some(ConstructExecMode::Gate));
        assert_eq!(action.biometric, Some(BiometricRequirement::Required));
        assert!(action.biometric_when_production_bucket);
        assert_eq!(action.budget_caps["wall_clock_secs"], 1800);
    }

    #[test]
    fn action_manifest_v2_parses_and_round_trips_need_field() {
        // ADR 204 Amendment 6: the action's least-privilege need is declared
        // in the manifest (`provider:object:verb`). Absent ⇒ empty (the action
        // mints no provider credential).
        let no_need = parse_action_manifest(valid_action_manifest_v2()).expect("v2 manifest");
        assert!(
            no_need.manifest.actions[0].need.is_empty(),
            "an action omitting `need` defaults to no credential need"
        );

        let with_need = valid_action_manifest_v2().replace(
            "handler_ref = \"cli:gh.pr_create\"",
            "handler_ref = \"cli:gh.pr_create\"\nneed = [\"github:contents:write\", \"github:pull_request:create\"]",
        );
        let parsed = parse_action_manifest(&with_need).expect("manifest with need");
        assert_eq!(
            parsed.manifest.actions[0].need,
            vec![
                "github:contents:write".to_string(),
                "github:pull_request:create".to_string(),
            ]
        );

        // Round-trips through serde (JSON is the universal round-trip target;
        // the TOML feature set here is parse-only). The `need` field survives
        // serialize → deserialize unchanged.
        let json = serde_json::to_string(&parsed.manifest).expect("serialize");
        let reparsed: ActionManifest = serde_json::from_str(&json).expect("reparse");
        assert_eq!(reparsed.actions[0].need, parsed.manifest.actions[0].need);
    }

    #[test]
    fn action_manifest_v2_parses_adr213_need_ir_archetypes() {
        for (label, need_ir, need) in [
            (
                "policy-document",
                r#"need_ir = { archetype = "policy-document", provider = "aws", policy_language = "aws-iam", statements = [{ effect = "allow", actions = ["s3:PutObject"], resources = ["arn:aws:s3:::assets/releases/*"] }] }"#,
                r#"need = ["aws:s3:PutObject"]"#,
            ),
            (
                "OAuth-scope",
                r#"need_ir = { archetype = "OAuth-scope", provider = "github", scopes = ["contents:write"], audience = "https://api.github.com" }"#,
                r#"need = ["github:contents:write"]"#,
            ),
            (
                "identity-only",
                r#"need_ir = { archetype = "identity-only", provider = "aws_sts", identity = { kind = "role_arn", value = "arn:aws:iam::123456789012:role/publish-site" } }"#,
                r#"need = ["aws_sts:identity:role_arn:arn:aws:iam::123456789012:role/publish-site"]"#,
            ),
            (
                "registry-JWT",
                r#"need_ir = { archetype = "registry-JWT", provider = "npm", registry = "registry.npmjs.org", audience = "npm", claims = [{ name = "package", values = ["@emberlink/cli"] }, { name = "access", values = ["publish"] }] }"#,
                r#"need = ["npm:registry:registry.npmjs.org", "npm:audience:npm", "npm:claim:package:@emberlink/cli", "npm:claim:access:publish"]"#,
            ),
            (
                "budget",
                r#"need_ir = { archetype = "budget", provider = "anthropic", requests = 25, cents = 100 }"#,
                r#"need = ["anthropic:budget:requests", "anthropic:budget:cents"]"#,
            ),
        ] {
            let manifest = valid_action_manifest_v2().replace(
                "handler_ref = \"cli:gh.pr_create\"",
                &format!("handler_ref = \"cli:gh.pr_create\"\n{need_ir}\n{need}"),
            );
            let parsed = parse_action_manifest(&manifest)
                .unwrap_or_else(|error| panic!("{label} need_ir should parse: {error}"));
            let action_need_ir = parsed.manifest.actions[0]
                .need_ir
                .as_ref()
                .expect("need_ir present");
            let matched = match label {
                "policy-document" => {
                    matches!(action_need_ir, NeedIrArchetypeData::PolicyDocument(_))
                }
                "OAuth-scope" => matches!(action_need_ir, NeedIrArchetypeData::OauthScope(_)),
                "identity-only" => {
                    matches!(action_need_ir, NeedIrArchetypeData::IdentityOnly(_))
                }
                "registry-JWT" => matches!(action_need_ir, NeedIrArchetypeData::RegistryJwt(_)),
                "budget" => matches!(action_need_ir, NeedIrArchetypeData::Budget(_)),
                _ => unreachable!("test labels are closed"),
            };
            assert!(matched, "{label} parsed as {action_need_ir:?}");
        }
    }

    #[test]
    fn action_manifest_v2_rejects_non_monotone_need_ir_projection() {
        let manifest = valid_action_manifest_v2().replace(
            "handler_ref = \"cli:gh.pr_create\"",
            "handler_ref = \"cli:gh.pr_create\"\nneed = [\"github:contents:write\"]\nneed_ir = { archetype = \"OAuth-scope\", provider = \"github\", scopes = [\"contents:write\", \"administration:write\"] }",
        );
        let err =
            parse_action_manifest(&manifest).expect_err("over-wide need_ir projection must fail");
        assert!(matches!(
            err,
            ActionManifestError::InvalidNeedIr { action, reason }
                if action == "pr_create"
                    && reason.contains("non-monotone")
                    && reason.contains("github:administration:write")
        ));
    }

    #[test]
    fn action_manifest_v2_allows_provider_wildcard_declared_need_for_need_ir() {
        let manifest = valid_action_manifest_v2().replace(
            "handler_ref = \"cli:gh.pr_create\"",
            "handler_ref = \"cli:gh.pr_create\"\nneed = [\"github:*\"]\nneed_ir = { archetype = \"OAuth-scope\", provider = \"github\", scopes = [\"contents:write\", \"pull_request:create\"] }",
        );
        parse_action_manifest(&manifest).expect("provider wildcard covers same-provider need_ir");
    }

    #[test]
    fn action_manifest_v2_rejects_need_ir_without_declared_need() {
        let manifest = valid_action_manifest_v2().replace(
            "handler_ref = \"cli:gh.pr_create\"",
            "handler_ref = \"cli:gh.pr_create\"\nneed_ir = { archetype = \"OAuth-scope\", provider = \"github\", scopes = [\"contents:write\"] }",
        );
        let err = parse_action_manifest(&manifest)
            .expect_err("non-empty need_ir must have declared need coverage");
        assert!(matches!(
            err,
            ActionManifestError::InvalidNeedIr { action, reason }
                if action == "pr_create"
                    && reason.contains("non-monotone")
                    && reason.contains("no declared need")
        ));
    }

    #[test]
    fn action_manifest_v2_rejects_invalid_need_ir() {
        let manifest = valid_action_manifest_v2().replace(
            "handler_ref = \"cli:gh.pr_create\"",
            "handler_ref = \"cli:gh.pr_create\"\nneed_ir = { archetype = \"budget\", provider = \"anthropic\" }",
        );
        let err = parse_action_manifest(&manifest).expect_err("empty budget need_ir must fail");
        assert!(matches!(
            err,
            ActionManifestError::InvalidNeedIr { action, reason }
                if action == "pr_create" && reason.contains("at least one axis")
        ));
    }

    #[test]
    fn bundled_construct_manifests_parse_without_warnings() {
        for (name, manifest) in [
            (
                "gh",
                include_str!("../../ember-construct/construct/gh.toml"),
            ),
            (
                "aws",
                include_str!("../../ember-construct/construct/aws.toml"),
            ),
            (
                "gcloud",
                include_str!("../../ember-construct/construct/gcloud.toml"),
            ),
            (
                "az",
                include_str!("../../ember-construct/construct/az.toml"),
            ),
            (
                "flyctl",
                include_str!("../../ember-construct/construct/flyctl.toml"),
            ),
            (
                "okta",
                include_str!("../../ember-construct/construct/okta.toml"),
            ),
            (
                "vercel",
                include_str!("../../ember-construct/construct/vercel.toml"),
            ),
            (
                "git",
                include_str!("../../ember-construct/construct/git.toml"),
            ),
            (
                "kubectl",
                include_str!("../../ember-construct/construct/kubectl.toml"),
            ),
            (
                "docker",
                include_str!("../../ember-construct/construct/docker.toml"),
            ),
            (
                "npm",
                include_str!("../../ember-construct/construct/npm.toml"),
            ),
            (
                "wrangler",
                include_str!("../../ember-construct/construct/wrangler.toml"),
            ),
            (
                "pulumi",
                include_str!("../../ember-construct/construct/pulumi.toml"),
            ),
            (
                "terraform",
                include_str!("../../ember-construct/construct/terraform.toml"),
            ),
            (
                "tofu",
                include_str!("../../ember-construct/construct/tofu.toml"),
            ),
            (
                "scion",
                include_str!("../../ember-construct/construct/scion.toml"),
            ),
            ("vault", include_str!("../../ember-vault/construct.toml")),
        ] {
            let parsed = parse_action_manifest(manifest)
                .unwrap_or_else(|e| panic!("{name} construct manifest must parse: {e}"));
            assert!(
                parsed.warnings.is_empty(),
                "{name} manifest should not use deprecated_exec"
            );
            assert_eq!(parsed.manifest.meta.provider_kind, ProviderKind::Cli);
            assert!(
                parsed.manifest.runtime.cli.is_some(),
                "{name} manifest should declare runtime.cli"
            );
        }
    }

    #[test]
    fn mock_provider_manifests_parse_without_cli_runtime() {
        for (name, manifest) in [
            (
                "anthropic",
                include_str!("../../core-broker/manifests/anthropic-mock.toml"),
            ),
            (
                "cloudflare",
                include_str!("../../core-broker/manifests/cloudflare-mock.toml"),
            ),
            (
                "tailscale",
                include_str!("../../core-broker/manifests/tailscale-mock.toml"),
            ),
        ] {
            let parsed = parse_action_manifest(manifest)
                .unwrap_or_else(|e| panic!("{name} mock manifest must parse: {e}"));
            assert!(parsed.warnings.is_empty());
            assert_eq!(parsed.manifest.meta.provider_kind, ProviderKind::MockApi);
            assert!(parsed.manifest.meta.mock);
            assert!(parsed.manifest.runtime.cli.is_none());
        }
    }

    // ── V030-CLAUDE-OVERLAY invariant 13 — [settings_overlay] tests ──

    /// AC-10 (parser-extension lands before manifest sweep): every bundled
    /// cohort-A manifest still parses successfully against the extended
    /// schema. The existing `bundled_construct_manifests_parse_without_warnings`
    /// already covers this in the absent-field case (none of the 16 manifests
    /// declare `[settings_overlay]` yet — PR2 adds them). This adds the
    /// positive case: when a manifest DOES declare a valid `[settings_overlay]`
    /// block, the parser accepts it.
    #[test]
    fn settings_overlay_valid_absolute_path_deny_accepted() {
        let manifest = valid_action_manifest_v2().replace(
            "[runtime.cli]",
            "[settings_overlay]\npermissions_deny = [\"Bash(/usr/bin/gh *)\", \"Bash(/opt/homebrew/bin/gh *)\"]\n\n[runtime.cli]",
        );
        let parsed = parse_action_manifest(&manifest)
            .expect("absolute-path Bash(...) deny entries must parse and validate");
        let overlay = parsed
            .manifest
            .settings_overlay
            .as_ref()
            .expect("settings_overlay must round-trip into the parsed manifest");
        assert_eq!(overlay.permissions_deny.len(), 2);
    }

    /// AC-7: third-party manifests that try to declare a `permissions_allow`
    /// surface fail at parse time. `deny_unknown_fields` on `SettingsOverlay`
    /// makes this structural — the schema has no allow field, so the parser
    /// cannot accept one regardless of validator logic.
    #[test]
    fn settings_overlay_rejects_permissions_allow_via_deny_unknown_fields() {
        let manifest = valid_action_manifest_v2().replace(
            "[runtime.cli]",
            "[settings_overlay]\npermissions_allow = [\"Bash(/usr/bin/gh *)\"]\n\n[runtime.cli]",
        );
        let err = parse_action_manifest(&manifest)
            .expect_err("permissions_allow on [settings_overlay] must be refused structurally");
        assert!(
            matches!(err, ActionManifestError::Parse(_)),
            "expected serde Parse error from deny_unknown_fields, got {err:?}"
        );
    }

    /// AC-8: cross-tool denies are refused. A `gh.toml`-shaped manifest
    /// declaring `Bash(/usr/bin/curl *)` is denied at validate time — the
    /// basename must match the wrapped binary.
    #[test]
    fn settings_overlay_rejects_cross_tool_deny() {
        let manifest = valid_action_manifest_v2().replace(
            "[runtime.cli]",
            "[settings_overlay]\npermissions_deny = [\"Bash(/usr/bin/curl *)\"]\n\n[runtime.cli]",
        );
        let err = parse_action_manifest(&manifest).expect_err("cross-tool deny must be refused");
        assert!(
            matches!(&err, ActionManifestError::InvalidSettingsOverlay { reason }
                if reason.contains("curl") && reason.contains("gh") && reason.contains("invariant 13b"))
        );
    }

    /// Invariant 13a — only `Bash(...)` tool-prefix rules are accepted.
    #[test]
    fn settings_overlay_rejects_non_bash_tool_prefix() {
        let manifest = valid_action_manifest_v2().replace(
            "[runtime.cli]",
            "[settings_overlay]\npermissions_deny = [\"Read(/usr/bin/gh *)\"]\n\n[runtime.cli]",
        );
        let err = parse_action_manifest(&manifest)
            .expect_err("non-Bash tool-prefix entries must be refused");
        assert!(
            matches!(&err, ActionManifestError::InvalidSettingsOverlay { reason }
                if reason.contains("invariant 13a") && reason.contains("Read"))
        );
    }

    /// Invariant 13c — bare-name forms are refused. The adversarial review
    /// (C5.5) shows bare-name and shadow-shim share the literal `gh`, so the
    /// deny is ambiguous and may be vacuous. Operators must author the
    /// absolute-path form, which is unambiguous against the shim.
    #[test]
    fn settings_overlay_rejects_bare_name_form() {
        let manifest = valid_action_manifest_v2().replace(
            "[runtime.cli]",
            "[settings_overlay]\npermissions_deny = [\"Bash(gh *)\"]\n\n[runtime.cli]",
        );
        let err = parse_action_manifest(&manifest)
            .expect_err("bare-name Bash(gh *) entries must be refused");
        assert!(
            matches!(&err, ActionManifestError::InvalidSettingsOverlay { reason }
                if reason.contains("invariant 13c") && reason.contains("bare-name"))
        );
    }

    /// Per-verb scoping (e.g. `Bash(/usr/bin/git push *)`) is accepted —
    /// the first token is the absolute path; subsequent tokens are part of
    /// the argv match shape Claude consumes verbatim.
    #[test]
    fn settings_overlay_accepts_per_verb_scoping_within_wrapped_binary() {
        let manifest = valid_action_manifest_v2()
            .replace("wrapped_binary = \"gh\"", "wrapped_binary = \"git\"")
            .replace(
                "[runtime.cli]",
                "[settings_overlay]\npermissions_deny = [\
                  \"Bash(/usr/bin/git push *)\", \
                  \"Bash(/usr/bin/git fetch *)\", \
                  \"Bash(/usr/bin/git pull *)\", \
                  \"Bash(/usr/bin/git clone *)\"\
                ]\n\n[runtime.cli]",
            );
        let parsed = parse_action_manifest(&manifest)
            .expect("per-verb deny entries within wrapped_binary must parse");
        let overlay = parsed
            .manifest
            .settings_overlay
            .as_ref()
            .expect("settings_overlay present");
        assert_eq!(overlay.permissions_deny.len(), 4);
    }

    /// A `[settings_overlay]` block on a non-CLI provider has no
    /// `wrapped_binary` to bind against. The validator refuses it so a mock
    /// or pure-API provider cannot smuggle in shell denies that would never
    /// project meaningfully into the launcher overlay.
    #[test]
    fn settings_overlay_requires_cli_runtime() {
        let manifest = valid_mock_action_manifest_v2().replace(
            "[[actions]]",
            "[settings_overlay]\npermissions_deny = [\"Bash(/usr/bin/whatever *)\"]\n\n[[actions]]",
        );
        let err = parse_action_manifest(&manifest)
            .expect_err("settings_overlay on a non-CLI provider must be refused");
        assert!(
            matches!(&err, ActionManifestError::InvalidSettingsOverlay { reason }
                if reason.contains("CLI provider") && reason.contains("wrapped_binary"))
        );
    }

    /// AC-10 — all bundled cohort-A manifests still parse successfully
    /// against the extended schema. PR2 will populate their
    /// `[settings_overlay]` blocks; this PR proves the schema lift is
    /// parse-stable on every current manifest.
    ///
    /// (The `bundled_construct_manifests_parse_without_warnings` test above
    /// already covers this for the absent-field case; this duplicate is the
    /// AC-named anchor so future test renames can find it.)
    #[test]
    fn cohort_a_construct_manifests_parse_against_extended_schema() {
        for (name, manifest) in [
            (
                "gh",
                include_str!("../../ember-construct/construct/gh.toml"),
            ),
            (
                "git",
                include_str!("../../ember-construct/construct/git.toml"),
            ),
            (
                "kubectl",
                include_str!("../../ember-construct/construct/kubectl.toml"),
            ),
            (
                "npm",
                include_str!("../../ember-construct/construct/npm.toml"),
            ),
            (
                "aws",
                include_str!("../../ember-construct/construct/aws.toml"),
            ),
            (
                "az",
                include_str!("../../ember-construct/construct/az.toml"),
            ),
            (
                "gcloud",
                include_str!("../../ember-construct/construct/gcloud.toml"),
            ),
            (
                "docker",
                include_str!("../../ember-construct/construct/docker.toml"),
            ),
            (
                "flyctl",
                include_str!("../../ember-construct/construct/flyctl.toml"),
            ),
            (
                "vercel",
                include_str!("../../ember-construct/construct/vercel.toml"),
            ),
            (
                "wrangler",
                include_str!("../../ember-construct/construct/wrangler.toml"),
            ),
            (
                "okta",
                include_str!("../../ember-construct/construct/okta.toml"),
            ),
            (
                "terraform",
                include_str!("../../ember-construct/construct/terraform.toml"),
            ),
            (
                "tofu",
                include_str!("../../ember-construct/construct/tofu.toml"),
            ),
            (
                "pulumi",
                include_str!("../../ember-construct/construct/pulumi.toml"),
            ),
            (
                "scion",
                include_str!("../../ember-construct/construct/scion.toml"),
            ),
        ] {
            let parsed = parse_action_manifest(manifest).unwrap_or_else(|e| {
                panic!("{name} construct manifest must parse against extended schema: {e}")
            });
            // No manifest in this PR declares [settings_overlay] yet — PR2
            // adds them. The extended schema must accept the absent-field
            // case identically.
            assert!(
                parsed.manifest.settings_overlay.is_none(),
                "{name} should not yet declare [settings_overlay] (PR2 adds it)"
            );
        }
    }

    #[test]
    fn action_manifest_v2_rejects_unknown_top_level_field() {
        let manifest = valid_action_manifest_v2().replace("[meta]", "legacy = true\n\n[meta]");
        let err = parse_action_manifest(&manifest).expect_err("unknown top-level field");
        assert!(matches!(
            err,
            ActionManifestError::UnknownTopLevelField(field) if field == "legacy"
        ));
    }

    #[test]
    fn action_manifest_v2_rejects_unknown_action_field() {
        let manifest = valid_action_manifest_v2().replace(
            "handler_ref = \"cli:gh.pr_create\"",
            "handler_ref = \"cli:gh.pr_create\"\nlegacy_mode = \"prompt\"",
        );
        let err = parse_action_manifest(&manifest).expect_err("unknown action field");
        assert!(matches!(
            err,
            ActionManifestError::UnknownActionField { action: Some(action), field }
                if action == "pr_create" && field == "legacy_mode"
        ));
    }

    #[test]
    fn action_manifest_v2_rejects_raw_exec_fields_outside_deprecated_exec() {
        let manifest = valid_action_manifest_v2().replace(
            "handler_ref = \"cli:gh.pr_create\"",
            "handler_ref = \"cli:gh.pr_create\"\nbinary = \"gh\"",
        );
        let err = parse_action_manifest(&manifest).expect_err("raw exec action field");
        assert!(matches!(
            err,
            ActionManifestError::RawExecFieldOutsideDeprecatedExec { field, .. }
                if field == "binary"
        ));
    }

    #[test]
    fn action_manifest_v2_deprecated_exec_is_fail_closed() {
        let manifest = format!(
            "{}\n[deprecated_exec]\nbinary = \"gh\"\ncwd_policy = \"runner_default\"\nsunset = \"P11-S4\"\n",
            valid_action_manifest_v2()
        );
        let err = parse_action_manifest(&manifest).expect_err("deprecated_exec is retired");
        assert!(matches!(err, ActionManifestError::DeprecatedExecDisallowed));
    }

    #[test]
    fn action_manifest_v2_mock_requires_mock_flag() {
        let manifest = valid_mock_action_manifest_v2().replace("\nmock = true", "");
        let err = parse_action_manifest(&manifest).expect_err("mock_api needs mock flag");
        assert!(matches!(
            err,
            ActionManifestError::MockProviderMissingMockFlag
        ));
    }

    #[test]
    fn action_manifest_v2_mock_rejects_cli_runtime() {
        let manifest = format!(
            "{}\n[runtime.cli]\nwrapped_binary = \"anthropic\"\n",
            valid_mock_action_manifest_v2()
        );
        let err = parse_action_manifest(&manifest).expect_err("mock_api cannot carry cli runtime");
        assert!(matches!(
            err,
            ActionManifestError::UnexpectedCliRuntime(ProviderKind::MockApi)
        ));
    }

    #[test]
    fn action_manifest_v2_rejects_empty_runner_classes() {
        let manifest =
            valid_action_manifest_v2().replace("default_runner_classes = [\"local_trusted\"]", "");
        let err = parse_action_manifest(&manifest).expect_err("missing runner classes");
        assert!(matches!(
            err,
            ActionManifestError::EmptyRunnerClasses { action } if action == "pr_create"
        ));
    }

    #[test]
    fn action_manifest_v2_rejects_materialization_mismatch() {
        let manifest = valid_action_manifest_v2().replace(
            "materialization_class = \"brokered_credential\"",
            "materialization_class = \"none\"",
        );
        let err = parse_action_manifest(&manifest).expect_err("material mismatch");
        assert!(matches!(
            err,
            ActionManifestError::MaterializationClassMismatch {
                action,
                class: MaterializationClass::None
            } if action == "pr_create"
        ));
    }

    #[test]
    fn action_manifest_v2_rejects_bad_env_name() {
        let manifest = valid_action_manifest_v2().replace(
            "semantic_labels = [\"github.pull_request.write\", \"scm.pull_request.write\"]",
            "env_passthrough = [\"gh_token\"]\nsemantic_labels = [\"github.pull_request.write\", \"scm.pull_request.write\"]",
        );
        let err = parse_action_manifest(&manifest).expect_err("bad env name");
        assert!(matches!(
            err,
            ActionManifestError::InvalidActionEnvName { action, field: "env_passthrough", name }
                if action == "pr_create" && name == "gh_token"
        ));
    }

    #[test]
    fn action_manifest_v2_rejects_authority_refs_when_material_classes_present() {
        let manifest = valid_action_manifest_v2().replace(
            "material_classes = [{ kind = \"broker\", authority_ref = \"github\" }]",
            "material_classes = [{ kind = \"broker\", authority_ref = \"github\" }]\nauthority_refs = [\"github\"]",
        );
        let err = parse_action_manifest(&manifest).expect_err("authority_refs alias is retired");
        assert!(matches!(
            err,
            ActionManifestError::AuthorityRefsAliasDisallowed { scope } if scope == "[defaults]"
        ));
    }

    #[test]
    fn action_manifest_v2_rejects_authority_refs_when_material_classes_explicit_empty() {
        let manifest = valid_action_manifest_v2().replace(
            "material_classes = [{ kind = \"broker\", authority_ref = \"github\" }]",
            "material_classes = []\nauthority_refs = [\"github\"]",
        );
        let err = parse_action_manifest(&manifest).expect_err("authority_refs alias is retired");
        assert!(matches!(
            err,
            ActionManifestError::AuthorityRefsAliasDisallowed { scope } if scope == "[defaults]"
        ));
    }

    proptest! {
        #[test]
        fn action_manifest_v2_unknown_top_level_fields_fail_closed(field in "[a-z_]{1,16}") {
            prop_assume!(!ACTION_MANIFEST_TOP_LEVEL_FIELDS.contains(&field.as_str()));
            prop_assume!(!RAW_EXEC_FIELDS.contains(&field.as_str()));

            let manifest = valid_action_manifest_v2()
                .replace("[meta]", &format!("{} = true\n\n[meta]", field));
            let err = parse_action_manifest(&manifest).expect_err("unknown top-level field");

            let matched = matches!(
                err,
                ActionManifestError::UnknownTopLevelField(got) if got == field
            );
            prop_assert!(matched);
        }

        #[test]
        fn action_manifest_v2_unknown_action_fields_fail_closed(field in "[a-z_]{1,16}") {
            prop_assume!(!ACTION_MANIFEST_ACTION_FIELDS.contains(&field.as_str()));
            prop_assume!(!RAW_EXEC_FIELDS.contains(&field.as_str()));

            let manifest = valid_action_manifest_v2().replace(
                "handler_ref = \"cli:gh.pr_create\"",
                &format!("handler_ref = \"cli:gh.pr_create\"\n{} = true", field),
            );
            let err = parse_action_manifest(&manifest).expect_err("unknown action field");

            let matched = matches!(
                err,
                ActionManifestError::UnknownActionField { action: Some(action), field: got }
                    if action == "pr_create" && got == field
            );
            prop_assert!(matched);
        }

        #[test]
        fn action_manifest_v2_missing_required_action_fields_fail_closed(
            field in prop::sample::select(vec![
                "key",
                "action_version",
                "summary",
                "input_schema",
                "risk_tier",
                "idempotency",
                "interaction_class",
                "audit_fields",
                "handler_ref",
            ])
        ) {
            let manifest = valid_action_manifest_v2()
                .replace(required_action_field_line(field), "");
            let err = parse_action_manifest(&manifest).expect_err("missing required field");

            prop_assert!(matches!(err, ActionManifestError::Parse(_)));
        }
    }

    #[test]
    fn valid_template_parses_and_validates() {
        let c = parse_and_validate(valid_template()).expect("valid template");
        assert_eq!(c.meta.name, "ember-gh");
        assert_eq!(c.actions.len(), 2);
    }

    #[test]
    fn invariant_1_unknown_schema_version() {
        let s = valid_template().replace(r#"schema_version = "1""#, r#"schema_version = "2""#);
        let err = parse_and_validate(&s).expect_err("expected UnknownSchemaVersion");
        assert!(matches!(err, ConstructTomlError::UnknownSchemaVersion(v) if v == "2"));
    }

    #[test]
    fn invariant_2_invalid_publisher_did() {
        let s = valid_template().replace(
            r#"publisher = "did:emberlink""#,
            r#"publisher = "ember-systems""#,
        );
        let err = parse_and_validate(&s).expect_err("expected InvalidPublisherDid");
        assert!(matches!(err, ConstructTomlError::InvalidPublisherDid(_)));
    }

    #[test]
    fn invariant_2_did_with_uppercase_method_rejected() {
        let s = valid_template().replace(
            r#"publisher = "did:emberlink""#,
            r#"publisher = "did:Ember-Systems""#,
        );
        let err = parse_and_validate(&s).expect_err("expected InvalidPublisherDid");
        assert!(matches!(err, ConstructTomlError::InvalidPublisherDid(_)));
    }

    #[test]
    fn invariant_3_action_id_collision_caught_by_toml_parser() {
        // toml's own parser rejects duplicate keys before our validator runs.
        let s = format!(
            "{}\n[actions.pr_create]\nmode = \"deny\"\nclassify_argv = \"pr create *\"\n",
            valid_template()
        );
        let err = parse_and_validate(&s).expect_err("expected duplicate-key parse error");
        assert!(matches!(err, ConstructTomlError::Parse(_)));
    }

    #[test]
    fn invariant_4_invalid_mode_rejected() {
        let s = valid_template().replace(r#"mode = "jit_approval""#, r#"mode = "yolo""#);
        let err = parse_and_validate(&s).expect_err("expected InvalidMode");
        assert!(
            matches!(err, ConstructTomlError::InvalidMode { ref action, ref mode }
            if action == "pr_merge" && mode == "yolo")
        );
    }

    #[test]
    fn invariant_5_classify_argv_with_pipe_rejected() {
        let s = valid_template().replace(
            r#"classify_argv = "pr merge *""#,
            r#"classify_argv = "pr merge|exec""#,
        );
        let err = parse_and_validate(&s).expect_err("expected InvalidClassifyArgv");
        assert!(
            matches!(err, ConstructTomlError::InvalidClassifyArgv { ref action, .. } if action == "pr_merge")
        );
    }

    #[test]
    fn invariant_5_classify_argv_with_dollar_rejected() {
        let s = valid_template().replace(
            r#"classify_argv = "pr merge *""#,
            r#"classify_argv = "pr merge $arg""#,
        );
        let err = parse_and_validate(&s).expect_err("expected InvalidClassifyArgv");
        assert!(matches!(
            err,
            ConstructTomlError::InvalidClassifyArgv { .. }
        ));
    }

    #[test]
    fn invariant_6_bundled_auto_approve_top_level_rejected() {
        let s = valid_template().replace(
            r#"unknown_action = "deny""#,
            r#"unknown_action = "auto_approve""#,
        );
        let err = parse_and_validate(&s).expect_err("expected BundledAutoApproveTopLevel");
        assert!(matches!(
            err,
            ConstructTomlError::BundledAutoApproveTopLevel(_)
        ));
    }

    #[test]
    fn invariant_6_third_party_auto_approve_top_level_allowed() {
        // Third-party publishers can choose dangerous defaults — that's their call.
        let s = valid_template()
            .replace(
                r#"publisher = "did:emberlink""#,
                r#"publisher = "did:wrangler-team""#,
            )
            .replace(
                r#"unknown_action = "deny""#,
                r#"unknown_action = "auto_approve""#,
            );
        let _ = parse_and_validate(&s).expect("third-party auto_approve should be allowed");
    }

    #[test]
    fn invariant_7_invalid_min_version_rejected() {
        let s = valid_template().replace(
            r#"wraps_binary_min_version = "2.40.0""#,
            r#"wraps_binary_min_version = "2.4""#,
        );
        let err = parse_and_validate(&s).expect_err("expected InvalidMinVersion");
        assert!(matches!(err, ConstructTomlError::InvalidMinVersion(v) if v == "2.4"));
    }

    #[test]
    fn invariant_7_min_version_omitted_is_ok() {
        let s = valid_template().replace("\nwraps_binary_min_version = \"2.40.0\"", "");
        let _ = parse_and_validate(&s).expect("omitted min_version should be allowed");
    }

    #[test]
    fn invariant_8_budget_cap_zero_rejected() {
        let s = valid_template().replace(
            "budget_caps = { runs_per_session = 5, runs_per_hour = 30 }",
            "budget_caps = { runs_per_session = 0, runs_per_hour = 30 }",
        );
        let err = parse_and_validate(&s).expect_err("expected BudgetCapOutOfBounds");
        assert!(
            matches!(err, ConstructTomlError::BudgetCapOutOfBounds { ref key, value, .. }
            if key == "runs_per_session" && value == 0)
        );
    }

    #[test]
    fn invariant_8_budget_cap_too_large_rejected() {
        let s = valid_template().replace(
            "budget_caps = { runs_per_session = 5, runs_per_hour = 30 }",
            "budget_caps = { runs_per_session = 99999, runs_per_hour = 30 }",
        );
        let err = parse_and_validate(&s).expect_err("expected BudgetCapOutOfBounds");
        assert!(
            matches!(err, ConstructTomlError::BudgetCapOutOfBounds { value, .. } if value == 99999)
        );
    }

    #[test]
    fn unparseable_toml_returns_parse_error() {
        let err = parse_and_validate("not toml at all [[[").expect_err("expected Parse");
        assert!(matches!(err, ConstructTomlError::Parse(_)));
    }

    #[test]
    fn missing_required_field_returns_parse_error() {
        let err = parse_and_validate(r#"schema_version = "1""#)
            .expect_err("expected Parse (missing meta)");
        assert!(matches!(err, ConstructTomlError::Parse(_)));
    }

    #[test]
    fn invariant_9_default_on_shim_eof_is_sigterm() {
        let c = parse_and_validate(valid_template()).expect("valid template");
        let pr_create = c.actions.get("pr_create").expect("pr_create block");
        assert_eq!(pr_create.on_shim_eof, "sigterm");
        let pr_merge = c.actions.get("pr_merge").expect("pr_merge block");
        assert_eq!(pr_merge.on_shim_eof, "sigterm");
    }

    #[test]
    fn invariant_9_drain_explicit_accepted() {
        let s = valid_template().replace(
            r#"[actions.pr_merge]
mode = "jit_approval""#,
            r#"[actions.pr_merge]
on_shim_eof = "drain"
mode = "jit_approval""#,
        );
        let c = parse_and_validate(&s).expect("drain override should validate");
        assert_eq!(c.actions.get("pr_merge").unwrap().on_shim_eof, "drain");
    }

    #[test]
    fn invariant_9_invalid_value_rejected() {
        let s = valid_template().replace(
            r#"[actions.pr_merge]
mode = "jit_approval""#,
            r#"[actions.pr_merge]
on_shim_eof = "ignore"
mode = "jit_approval""#,
        );
        let err = parse_and_validate(&s).expect_err("expected InvalidShimEofPolicy");
        assert!(
            matches!(err, ConstructTomlError::InvalidShimEofPolicy { ref action, ref value }
            if action == "pr_merge" && value == "ignore")
        );
    }

    #[test]
    fn invariant_10_env_passthrough_default_empty() {
        let c = parse_and_validate(valid_template()).expect("valid template");
        let pr_create = c.actions.get("pr_create").expect("pr_create block");
        assert!(pr_create.env_passthrough.is_empty());
    }

    #[test]
    fn invariant_10_env_passthrough_accepted() {
        let s = valid_template().replace(
            r#"[actions.pr_merge]
mode = "jit_approval""#,
            r#"[actions.pr_merge]
env_passthrough = ["GH_TOKEN", "GITHUB_TOKEN", "GH_HOST"]
mode = "jit_approval""#,
        );
        let c = parse_and_validate(&s).expect("env_passthrough should validate");
        let pr_merge = c.actions.get("pr_merge").unwrap();
        assert_eq!(
            pr_merge.env_passthrough,
            vec!["GH_TOKEN", "GITHUB_TOKEN", "GH_HOST"]
        );
    }

    #[test]
    fn invariant_10_env_passthrough_lowercase_rejected() {
        let s = valid_template().replace(
            r#"[actions.pr_merge]
mode = "jit_approval""#,
            r#"[actions.pr_merge]
env_passthrough = ["gh_token"]
mode = "jit_approval""#,
        );
        let err = parse_and_validate(&s).expect_err("expected InvalidEnvPassthroughName");
        assert!(
            matches!(err, ConstructTomlError::InvalidEnvPassthroughName { ref action, ref name }
            if action == "pr_merge" && name == "gh_token")
        );
    }

    #[test]
    fn invariant_10_env_passthrough_starting_digit_rejected() {
        let s = valid_template().replace(
            r#"[actions.pr_merge]
mode = "jit_approval""#,
            r#"[actions.pr_merge]
env_passthrough = ["1BAD"]
mode = "jit_approval""#,
        );
        let err = parse_and_validate(&s).expect_err("expected InvalidEnvPassthroughName");
        assert!(matches!(
            err,
            ConstructTomlError::InvalidEnvPassthroughName { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // needs_credentials + credential_types tests (ARCH-BROKER-VAULT-CUTOVER-PR2-MANIFEST-SCHEMA)
    // -----------------------------------------------------------------------

    #[test]
    fn needs_credentials_defaults_to_false() {
        let c = parse_and_validate(valid_template()).expect("valid template");
        let pr_create = c.actions.get("pr_create").expect("pr_create block");
        assert!(
            !pr_create.needs_credentials,
            "needs_credentials should default to false"
        );
        let pr_merge = c.actions.get("pr_merge").expect("pr_merge block");
        assert!(
            !pr_merge.needs_credentials,
            "needs_credentials should default to false"
        );
    }

    #[test]
    fn needs_credentials_true_parses() {
        let s = valid_template().replace(
            r#"[actions.pr_merge]
mode = "jit_approval""#,
            r#"[actions.pr_merge]
needs_credentials = true
mode = "jit_approval""#,
        );
        let c = parse_and_validate(&s).expect("needs_credentials = true should validate");
        let pr_merge = c.actions.get("pr_merge").unwrap();
        assert!(pr_merge.needs_credentials);
        // Other action retains false default.
        assert!(!c.actions.get("pr_create").unwrap().needs_credentials);
    }

    #[test]
    fn credential_types_absent_defaults_to_empty_map() {
        let c = parse_and_validate(valid_template()).expect("valid template");
        assert!(
            c.credential_types.is_empty(),
            "credential_types should default to empty map"
        );
    }

    #[test]
    fn credential_types_table_parses() {
        let s = format!(
            "{}\n\
[credential_types.github_token]\n\
vault_entries = [\"secret/data/github/*\"]\n\
broker_impl = \"gh_token_env\"\n\
\n\
[credential_types.aws_iam]\n\
vault_entries = [\"secret/data/aws/access_key\", \"secret/data/aws/secret_key\"]\n\
broker_impl = \"aws_iam_env\"\n",
            valid_template()
        );
        let c = parse_and_validate(&s).expect("credential_types table should validate");
        assert_eq!(c.credential_types.len(), 2);

        let gh = c
            .credential_types
            .get("github_token")
            .expect("github_token type");
        assert_eq!(gh.vault_entries, vec!["secret/data/github/*"]);
        assert_eq!(gh.broker_impl, "gh_token_env");

        let aws = c.credential_types.get("aws_iam").expect("aws_iam type");
        assert_eq!(
            aws.vault_entries,
            vec!["secret/data/aws/access_key", "secret/data/aws/secret_key"]
        );
        assert_eq!(aws.broker_impl, "aws_iam_env");
    }

    #[test]
    fn credential_type_vault_entries_defaults_to_empty() {
        let s = format!(
            "{}\n\
[credential_types.minimal]\n\
broker_impl = \"noop\"\n",
            valid_template()
        );
        let c =
            parse_and_validate(&s).expect("credential_type with no vault_entries should validate");
        let minimal = c.credential_types.get("minimal").expect("minimal type");
        assert!(minimal.vault_entries.is_empty());
        assert_eq!(minimal.broker_impl, "noop");
    }

    #[test]
    fn round_trip_parse_serialize_parse_stable() {
        // Round-trip via serde_json (JSON is a universal serde round-trip target;
        // the TOML feature set in this crate enables parse-only, not display).
        let s = format!(
            "{}\n\
[credential_types.github_token]\n\
vault_entries = [\"secret/data/github/*\"]\n\
broker_impl = \"gh_token_env\"\n",
            valid_template().replace(
                r#"[actions.pr_merge]
mode = "jit_approval""#,
                r#"[actions.pr_merge]
needs_credentials = true
mode = "jit_approval""#,
            )
        );
        let first: ConstructToml = parse_and_validate(&s).expect("first parse");
        let json = serde_json::to_string(&first).expect("serialize to json");
        let second: ConstructToml = serde_json::from_str(&json).expect("deserialize from json");

        // Structural equality checks.
        assert_eq!(first.schema_version, second.schema_version);
        assert_eq!(first.meta.name, second.meta.name);
        assert_eq!(first.meta.publisher, second.meta.publisher);
        assert_eq!(first.actions.len(), second.actions.len());
        assert_eq!(
            first.actions.get("pr_merge").unwrap().needs_credentials,
            second.actions.get("pr_merge").unwrap().needs_credentials,
        );
        assert_eq!(
            first.actions.get("pr_create").unwrap().needs_credentials,
            second.actions.get("pr_create").unwrap().needs_credentials,
        );
        assert_eq!(first.credential_types.len(), second.credential_types.len());
        let gh1 = first.credential_types.get("github_token").unwrap();
        let gh2 = second.credential_types.get("github_token").unwrap();
        assert_eq!(gh1.vault_entries, gh2.vault_entries);
        assert_eq!(gh1.broker_impl, gh2.broker_impl);
    }

    #[test]
    fn back_compat_existing_toml_without_new_fields_still_valid() {
        // The valid_template() fixture has no needs_credentials or credential_types —
        // this is the backward-compatibility contract: existing construct.toml files
        // that omit these fields must continue to parse and validate without error.
        let c = parse_and_validate(valid_template())
            .expect("back-compat: existing toml must still parse");
        assert!(c.credential_types.is_empty());
        for block in c.actions.values() {
            assert!(!block.needs_credentials);
        }
    }

    #[test]
    fn rail_side_channel_trust_contract_validates() {
        let s = format!(
            "{}\n[rail]\ntrust_contract = \"side_channel_reconciliation\"\n",
            valid_template()
        );
        let c = parse_and_validate(&s).expect("side-channel rail should validate");
        assert_eq!(
            c.rail.unwrap().trust_contract.as_deref(),
            Some("side_channel_reconciliation")
        );
    }

    #[test]
    fn rail_ephemeral_sign_trust_contract_validates() {
        let s = format!(
            "{}\n[rail]\ntrust_contract = \"ephemeral_sign\"\n",
            valid_template()
        );
        let c = parse_and_validate(&s).expect("ephemeral-sign rail should validate");
        assert_eq!(
            c.rail.unwrap().trust_contract.as_deref(),
            Some("ephemeral_sign")
        );
    }

    #[test]
    fn rail_block_missing_trust_contract_rejected() {
        let s = format!("{}\n[rail]\n", valid_template());
        let err = parse_and_validate(&s).expect_err("missing rail trust contract must fail");
        assert!(matches!(err, ConstructTomlError::MissingRailTrustContract));
    }

    #[test]
    fn rail_block_invalid_trust_contract_rejected() {
        let s = format!(
            "{}\n[rail]\ntrust_contract = \"callback_only\"\n",
            valid_template()
        );
        let err = parse_and_validate(&s).expect_err("invalid rail trust contract must fail");
        assert!(
            matches!(err, ConstructTomlError::InvalidRailTrustContract(ref value) if value == "callback_only")
        );
    }

    #[test]
    fn resolve_action_ref_reads_live_carrier_identity_fields() {
        // The load seam is fail-closed (ADR 196), so the carrier must be a full
        // v2 manifest, not a minimal identity-only stub.
        let identity = resolve_action_manifest_identity(valid_action_manifest_v2(), "pr_create")
            .expect("action identity");
        assert_eq!(
            identity.semantic_labels,
            vec![
                "github.pull_request.write".to_string(),
                "scm.pull_request.write".to_string()
            ]
        );
        assert_eq!(
            identity.action_ref(),
            ActionRef::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_create",
                "v1",
            )
        );
    }

    #[test]
    fn resolve_action_manifest_identity_reads_bundled_gh_semantic_labels() {
        let manifest = include_str!("../../ember-construct/construct/gh.toml");
        let identity =
            resolve_action_manifest_identity(manifest, "pr_create").expect("bundled identity");
        assert_eq!(
            identity.plugin_address,
            "registry.ember.systems/ember-systems/ember-gh"
        );
        assert_eq!(identity.plugin_version, "0.1.0");
        assert_eq!(
            identity.semantic_labels,
            vec![
                "github.pull_request.write".to_string(),
                "scm.pull_request.write".to_string()
            ]
        );
        assert_eq!(
            identity.action_ref(),
            ActionRef::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_create",
                "v1",
            )
        );
    }

    #[test]
    fn resolve_action_manifest_identity_rejects_missing_carrier_rail_contract() {
        // A full v2 carrier that declares a `[rail]` block but omits the trust
        // contract is refused at the carrier-load seam (rail semantics live in
        // the extractor; the v2 schema accepts the block structurally).
        let manifest = format!("{}\n[rail]\n", valid_action_manifest_v2());
        let err = resolve_action_manifest_identity(&manifest, "pr_create").expect_err("must fail");
        assert!(matches!(
            err,
            ConstructActionRefError::MissingRailTrustContract
        ));
    }

    #[test]
    fn resolve_action_manifest_identity_accepts_valid_carrier_rail_contract() {
        let manifest = format!(
            "{}\n[rail]\ntrust_contract = \"ephemeral_sign\"\n",
            valid_action_manifest_v2()
        );
        let identity =
            resolve_action_manifest_identity(&manifest, "pr_create").expect("valid rail");
        assert_eq!(
            identity.action_ref(),
            ActionRef::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_create",
                "v1",
            )
        );
    }

    #[test]
    fn resolve_action_ref_accepts_legacy_dotted_key_for_bare_manifest_action() {
        let manifest = r#"
schema_version = "2"

[meta]
name = "ember-gh"
plugin_address = "registry.ember.systems/ember-systems/ember-gh"
plugin_version = "0.1.0"
publisher = "did:emberlink"
provider_kind = "cli"
summary = "GitHub CLI Construct"
description = "Mediates GitHub CLI invocations through ember."

[defaults]
materialization_class = "brokered_credential"
material_classes = [{ kind = "broker", authority_ref = "github" }]
default_runner_classes = ["local_trusted"]

[runtime.cli]
wrapped_binary = "gh"

[[actions]]
key = "pr_list"
action_version = "v1"
summary = "List pull requests"
input_schema = { kind = "argv", classifier = "pr list *" }
risk_tier = "low"
idempotency = "idempotent"
interaction_class = "inline_interactive"
audit_fields = ["action_ref", "terminal_outcome"]
handler_ref = "cli:gh.pr_list"
"#;
        let action_ref = resolve_action_ref(manifest, "gh.pr_list").expect("action ref");
        assert_eq!(
            action_ref,
            ActionRef::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_list",
                "v1",
            )
        );
    }

    #[test]
    fn resolve_action_ref_rejects_carrier_missing_plugin_address() {
        // Fail-closed load seam: a carrier missing required v2 identity fields
        // (here `meta.plugin_address`) is refused at the schema gate rather than
        // silently reduced to an action_ref.
        let manifest = r#"
schema_version = "2"

[meta]
name = "ember-gh"
plugin_version = "0.1.0"
publisher = "did:emberlink"
provider_kind = "cli"
summary = "GitHub CLI Construct"
description = "Mediates GitHub CLI invocations through ember."

[[actions]]
key = "pr_create"
action_version = "v1"
summary = "Create a pull request"
input_schema = { kind = "argv", classifier = "pr create *" }
risk_tier = "medium"
idempotency = "non_idempotent"
interaction_class = "inline_interactive"
audit_fields = ["action_ref", "terminal_outcome"]
handler_ref = "cli:gh.pr_create"
"#;
        let err = resolve_action_ref(manifest, "pr_create").expect_err("missing plugin address");
        assert!(matches!(err, ConstructActionRefError::ManifestSchema(_)));
    }

    #[test]
    fn resolve_action_ref_rejects_carrier_missing_action_version() {
        // A v2 action without `action_version` is rejected at the schema gate.
        let manifest = r#"
schema_version = "2"

[meta]
name = "ember-gh"
plugin_address = "registry.ember.systems/ember-systems/ember-gh"
plugin_version = "0.1.0"
publisher = "did:emberlink"
provider_kind = "cli"
summary = "GitHub CLI Construct"
description = "Mediates GitHub CLI invocations through ember."

[[actions]]
key = "pr_create"
summary = "Create a pull request"
input_schema = { kind = "argv", classifier = "pr create *" }
risk_tier = "medium"
idempotency = "non_idempotent"
interaction_class = "inline_interactive"
audit_fields = ["action_ref", "terminal_outcome"]
handler_ref = "cli:gh.pr_create"
"#;
        let err = resolve_action_ref(manifest, "pr_create").expect_err("missing action version");
        assert!(matches!(err, ConstructActionRefError::ManifestSchema(_)));
    }

    #[test]
    fn resolve_action_ref_rejects_raw_exec_only_carrier() {
        // P11 Definition of Success: a carrier that declares only raw exec
        // metadata is refused at load — it is not a structured action manifest.
        let manifest = r#"
schema_version = "2"
binary = "/usr/bin/gh"

[meta]
name = "ember-gh"
plugin_address = "registry.ember.systems/ember-systems/ember-gh"
plugin_version = "0.1.0"
publisher = "did:emberlink"
provider_kind = "cli"
summary = "GitHub CLI Construct"
description = "Mediates GitHub CLI invocations through ember."

[[actions]]
key = "pr_create"
action_version = "v1"
summary = "Create a pull request"
input_schema = { kind = "argv", classifier = "pr create *" }
risk_tier = "medium"
idempotency = "non_idempotent"
interaction_class = "inline_interactive"
audit_fields = ["action_ref", "terminal_outcome"]
handler_ref = "cli:gh.pr_create"
"#;
        let err = resolve_action_ref(manifest, "pr_create").expect_err("raw exec field");
        assert!(matches!(err, ConstructActionRefError::ManifestSchema(_)));
    }
}
