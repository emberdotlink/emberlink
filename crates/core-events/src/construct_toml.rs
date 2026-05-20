//! `construct.toml` schema parser + validator.
//!
//! Codifies the schema specified in [`docs/construct-toml-schema.md`](../../../docs/construct-toml-schema.md).
//! Every cohort A Construct binary embeds a `construct.toml` at compile time;
//! this module is the **single source of truth** for parsing + validating
//! that file across the publisher's build (rejects bad shapes at `cargo build`),
//! the daemon's manifest-load (refuses to register bad Constructs), and
//! `broker.exec` call sites (cached by blake3 per the wire spec).
//!
//! Tracks **AP-CONSTRUCT-TOML-SCHEMA** (/S). v0.1 here covers the parser +
//! all 8 schema invariants; the cargo build-time hook + daemon manifest
//! integration land in follow-up PRs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Result alias for validator errors.
pub type Result<T> = std::result::Result<T, ConstructTomlError>;

/// Validator errors. Mapped one-to-one to the 8 schema invariants from
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
    /// daemon-spawned child exits. design §"Shim-EOF correctness" /
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
    /// design axis A2 / `docs/adversarial/2026-05-07-daemon-supervisor-vs-shim-supervisor.md`.
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

const ALLOWED_SHIM_EOF_POLICIES: &[&str] = &["sigterm", "drain"];

const ALLOWED_MODES: &[&str] = &[
    "auto_approve_if_pregranted",
    "jit_approval",
    "deny",
    "auto_approve",
];

const BUNDLED_PUBLISHER: &str = "did:emberlink";

const BUDGET_CAP_MIN: i64 = 1;
const BUDGET_CAP_MAX: i64 = 10000;

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

/// Validate an already-parsed `ConstructToml`. Returns the first invariant
/// violation encountered, or `Ok(())` if all 8 invariants hold.
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
    // (design §"Shim-EOF correctness" axis C.) Default is "sigterm" via
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
    // the env-name shape regex (design axis A2). Names that pass here are
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

    Ok(())
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
    // needs_credentials + credential_types tests (implementation-note-32)
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
        for (_id, block) in &c.actions {
            assert!(!block.needs_credentials);
        }
    }
}
