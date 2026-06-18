//! Provider-generic construct-factory contract.
//!
//! This module is the core-owned home for the P24 factory vocabulary around
//! the ADR 196 `construct.toml` v2 carrier: invocation grammar, target
//! extraction, need templates, dispositions, and conformance fixtures. Provider
//! crates implement these traits; core-owned projectors remain the only native
//! authority lowering path.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use core_event_types::ActionRef;
use core_events::construct_toml::parse_action_manifest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ActionKey;

pub use core_events::construct_toml::{
    ACTION_MANIFEST_CARRIER_SCHEMA_V2, ActionManifest, ActionManifestAction,
    ActionManifestDefaults, ActionManifestError, ActionManifestMeta, ActionManifestResult,
    ActionManifestRuntime, BudgetNeedIr, IdentityOnlyNeedIr, MaterialClass, MaterializationClass,
    NeedIrArchetypeData, NeedIrIdentity, OauthScopeNeedIr, ParsedActionManifest, PolicyCondition,
    PolicyDocumentNeedIr, PolicyDocumentStatement, PolicyEffect, ProviderKind, RegistryJwtClaim,
    RegistryJwtNeedIr, need_ir_projected_declared_need_atoms, validate_need_ir_archetype_data,
    validate_need_ir_projection_within_declared_need,
};

/// P24 factory disposition vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactoryDisposition {
    /// Target and need are proven locally; scoped materialization may be used.
    Mediated,
    /// The command is supported without provider credential injection.
    Credentialless,
    /// Argv is insufficient without a trusted provider resolver.
    ResolverRequired,
    /// Authority-bearing payloads must be parsed before materialization.
    PayloadAnalysisRequired,
    /// The shape is outside the declared contract and must fail closed.
    UnsupportedFailClosed,
}

impl FactoryDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            FactoryDisposition::Mediated => "mediated",
            FactoryDisposition::Credentialless => "credentialless",
            FactoryDisposition::ResolverRequired => "resolver_required",
            FactoryDisposition::PayloadAnalysisRequired => "payload_analysis_required",
            FactoryDisposition::UnsupportedFailClosed => "unsupported_fail_closed",
        }
    }

    pub fn allows_credential_injection(self) -> bool {
        matches!(self, FactoryDisposition::Mediated)
    }

    pub fn requires_reason(self) -> bool {
        matches!(
            self,
            FactoryDisposition::ResolverRequired
                | FactoryDisposition::PayloadAnalysisRequired
                | FactoryDisposition::UnsupportedFailClosed
        )
    }
}

impl fmt::Display for FactoryDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FactoryDisposition {
    type Err = FactoryDispositionParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "mediated" => Ok(FactoryDisposition::Mediated),
            "credentialless" => Ok(FactoryDisposition::Credentialless),
            "resolver_required" => Ok(FactoryDisposition::ResolverRequired),
            "payload_analysis_required" => Ok(FactoryDisposition::PayloadAnalysisRequired),
            "unsupported_fail_closed" => Ok(FactoryDisposition::UnsupportedFailClosed),
            other => Err(FactoryDispositionParseError(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown factory disposition {0:?}")]
pub struct FactoryDispositionParseError(String);

/// Declarative argv grammar for one construct/provider.
pub trait InvocationGrammar {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey>;
}

/// Provider-specific target extraction from a classified argv shape.
pub trait TargetExtractor {
    type Target;

    fn target_for_argv(&self, action_key: &ActionKey, argv: &[String]) -> Option<Self::Target>;
}

/// Provider-specific, need-side IR template derived from action + target.
pub trait NeedTemplate: TargetExtractor {
    type Need;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        target: &Self::Target,
        argv: &[String],
    ) -> Option<Self::Need>;
}

/// Complete provider-generic construct-factory contract.
pub trait ConstructFactory: InvocationGrammar + TargetExtractor + NeedTemplate {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> FactoryDisposition;

    /// Derive a target from environment state (cwd git config, kubeconfig,
    /// `package.json`, env vars) when the argv alone is insufficient.
    ///
    /// Returns `Some(synthesized_argv)` when a trusted env-derivation
    /// succeeded — the synthesized argv carries the derived target as an
    /// explicit flag the existing classifier and target extractor recognise
    /// (e.g. `gh pr list` → `gh pr list --repo acme/widgets`). The runtime
    /// re-runs disposition on the synthesized argv and threads it through
    /// the broker_exec RPC; the daemon re-classifies server-side and applies
    /// its existing `target ⊆ grant.resource` clamp.
    ///
    /// Returns `None` to fall through to the existing `ResolverRequired`
    /// refusal — the cwd has no usable env state, or no env-derive strategy
    /// exists for this construct.
    ///
    /// **Adversarial-cwd contract.** Implementations MUST treat `cwd` as
    /// attacker-owned (symlinked `.git`, `core.fsmonitor` execve tricks,
    /// malformed config). Any subprocess MUST be run against a path-pinned,
    /// content-hash-pinned binary with `PATH=""`, bounded output, bounded
    /// wall-clock, and never through a shell. The resolver's job ends at
    /// "produce a target candidate"; the daemon's clamp is the authority
    /// gate, not the resolver (per operator 2026-06-11 lock —
    /// `feedback_grant_clamp_is_security_argv_is_ux`).
    ///
    /// Default: `None` — no env-derivation; preserves the pre-resolver
    /// `ResolverRequired` behavior for any construct that doesn't opt in.
    ///
    /// Anchor: `factory_resolver_framework_landed`.
    fn resolve_target_from_environment(
        &self,
        _action_key: Option<&ActionKey>,
        _argv: &[String],
        _cwd: &Path,
    ) -> Option<Vec<String>> {
        None
    }
}

/// Parsed ADR 196 `construct.toml` v2 carrier.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionManifestV2Carrier {
    parsed: ParsedActionManifest,
}

impl ActionManifestV2Carrier {
    pub fn parse(text: &str) -> ActionManifestResult<Self> {
        Ok(Self {
            parsed: parse_action_manifest(text)?,
        })
    }

    pub fn manifest(&self) -> &ActionManifest {
        &self.parsed.manifest
    }

    pub fn parsed(&self) -> &ParsedActionManifest {
        &self.parsed
    }

    pub fn action_ref_for_key(&self, action_key: &str) -> Option<ActionRef> {
        self.parsed
            .manifest
            .actions
            .iter()
            .find(|action| action.key == action_key)
            .or_else(|| {
                let namespace = self
                    .parsed
                    .manifest
                    .meta
                    .plugin_address
                    .rsplit('/')
                    .next()?
                    .strip_prefix("ember-")?;
                let suffix = action_key.strip_prefix(namespace)?.strip_prefix('.')?;
                self.parsed
                    .manifest
                    .actions
                    .iter()
                    .find(|action| action.key == suffix)
            })
            .map(|action| action.action_ref(&self.parsed.manifest))
    }

    pub fn schema_version(&self) -> &str {
        &self.parsed.manifest.schema_version
    }

    pub fn is_v2(&self) -> bool {
        self.schema_version() == ACTION_MANIFEST_CARRIER_SCHEMA_V2
    }
}

impl TryFrom<&str> for ActionManifestV2Carrier {
    type Error = ActionManifestError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// Parsed factory fixture corpus.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryFixtureCorpus {
    pub fixtures: Vec<FactoryFixture>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryFixture {
    pub name: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub expected_action_ref: Option<String>,
    pub expected_disposition: FactoryDisposition,
    #[serde(default)]
    pub expected_target: Option<toml::Value>,
    #[serde(default)]
    pub expected_need: Option<toml::Value>,
    #[serde(default)]
    pub expected_need_ir: Option<NeedIrArchetypeData>,
    pub expected_credential_injection: bool,
    #[serde(default)]
    pub expected_ambient_credentials_stripped: Option<bool>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Error)]
pub enum FactoryFixtureParseError {
    #[error("toml parse error: {0}")]
    Parse(#[from] toml::de::Error),
}

pub fn parse_factory_fixture_corpus(
    text: &str,
) -> Result<FactoryFixtureCorpus, FactoryFixtureParseError> {
    Ok(toml::from_str(text)?)
}

pub fn validate_factory_fixture_corpus(corpus: &FactoryFixtureCorpus) -> Vec<String> {
    let mut errors = Vec::new();
    if corpus.fixtures.is_empty() {
        errors.push("expected non-empty [[fixtures]] array".to_string());
        return errors;
    }

    let mut names = std::collections::BTreeSet::new();
    let mut has_supported = false;
    let mut has_unsupported = false;

    for (index, fixture) in corpus.fixtures.iter().enumerate() {
        let fixture_label = if fixture.name.trim().is_empty() {
            format!("#{}", index + 1)
        } else {
            fixture.name.clone()
        };

        if fixture.name.trim().is_empty() {
            errors.push(format!("fixture {fixture_label:?}: name must be non-empty"));
        } else if !names.insert(fixture.name.clone()) {
            errors.push(format!("fixture {fixture_label:?}: duplicate fixture name"));
        }

        if fixture.argv.is_empty() {
            errors.push(format!(
                "fixture {fixture_label:?}: argv must be a non-empty string array"
            ));
        }

        if let Some(need_ir) = &fixture.expected_need_ir {
            if let Err(reason) = validate_need_ir_archetype_data(need_ir) {
                errors.push(format!(
                    "fixture {fixture_label:?}: expected_need_ir is invalid: {reason}"
                ));
            } else if let Err(reason) = validate_need_ir_projection_within_declared_need(
                need_ir,
                &expected_need_actions(&fixture.expected_need),
            ) {
                errors.push(format!(
                    "fixture {fixture_label:?}: expected_need_ir is non-monotone: {reason}"
                ));
            }
        }

        match fixture.expected_disposition {
            FactoryDisposition::Mediated => {
                has_supported = true;
                if !fixture.expected_credential_injection {
                    errors.push(format!(
                        "fixture {fixture_label:?}: mediated fixtures must expect credential injection"
                    ));
                }
                if !non_empty_optional_string(&fixture.expected_action_ref) {
                    errors.push(format!(
                        "fixture {fixture_label:?}: mediated fixtures need expected_action_ref"
                    ));
                }
                if !non_empty_table(&fixture.expected_target) {
                    errors.push(format!(
                        "fixture {fixture_label:?}: mediated fixtures need expected_target table"
                    ));
                }
                if !non_empty_table(&fixture.expected_need) && fixture.expected_need_ir.is_none() {
                    errors.push(format!(
                        "fixture {fixture_label:?}: mediated fixtures need expected_need table or expected_need_ir"
                    ));
                }
            }
            FactoryDisposition::Credentialless => {
                has_supported = true;
                if fixture.expected_credential_injection {
                    errors.push(format!(
                        "fixture {fixture_label:?}: credentialless fixtures must not inject credentials"
                    ));
                }
                if fixture.expected_ambient_credentials_stripped != Some(true) {
                    errors.push(format!(
                        "fixture {fixture_label:?}: credentialless fixtures must set expected_ambient_credentials_stripped = true"
                    ));
                }
                if !non_empty_optional_string(&fixture.expected_action_ref) {
                    errors.push(format!(
                        "fixture {fixture_label:?}: credentialless fixtures need expected_action_ref"
                    ));
                }
            }
            disposition => {
                if disposition == FactoryDisposition::UnsupportedFailClosed {
                    has_unsupported = true;
                }
                if fixture.expected_credential_injection {
                    errors.push(format!(
                        "fixture {fixture_label:?}: {disposition} fixtures must not inject credentials"
                    ));
                }
                if !non_empty_optional_string(&fixture.reason) {
                    errors.push(format!(
                        "fixture {fixture_label:?}: {disposition} fixtures need a reason"
                    ));
                }
            }
        }
    }

    if !has_supported {
        errors
            .push("include at least one supported mediated or credentialless fixture".to_string());
    }
    if !has_unsupported {
        errors.push("include at least one unsupported_fail_closed fixture".to_string());
    }

    errors
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactoryFixtureOutcome {
    pub fixture: String,
    pub action_key: Option<String>,
    pub disposition: FactoryDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FactoryConformanceReport {
    pub outcomes: Vec<FactoryFixtureOutcome>,
    pub failures: Vec<String>,
}

impl FactoryConformanceReport {
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }
}

pub fn run_factory_fixtures<C>(
    contract: &C,
    carrier: Option<&ActionManifestV2Carrier>,
    corpus: &FactoryFixtureCorpus,
) -> FactoryConformanceReport
where
    C: ConstructFactory,
{
    let mut report = FactoryConformanceReport::default();

    for fixture in &corpus.fixtures {
        let action_key = contract.action_key_for_argv(&fixture.argv);
        let disposition = contract.disposition_for_argv(action_key.as_ref(), &fixture.argv);
        report.outcomes.push(FactoryFixtureOutcome {
            fixture: fixture.name.clone(),
            action_key: action_key.as_ref().map(|key| key.0.clone()),
            disposition,
        });

        if disposition != fixture.expected_disposition {
            report.failures.push(format!(
                "fixture {:?}: expected disposition {}, got {}",
                fixture.name, fixture.expected_disposition, disposition
            ));
        }

        if disposition.allows_credential_injection() != fixture.expected_credential_injection {
            report.failures.push(format!(
                "fixture {:?}: expected credential injection {}, got {}",
                fixture.name,
                fixture.expected_credential_injection,
                disposition.allows_credential_injection()
            ));
        }

        if let Some(expected_action_ref) = fixture.expected_action_ref.as_deref()
            && let (Some(carrier), Some(action_key)) = (carrier, action_key.as_ref())
        {
            match carrier.action_ref_for_key(&action_key.0) {
                Some(action_ref) if action_ref.to_string() == expected_action_ref => {}
                Some(action_ref) => report.failures.push(format!(
                    "fixture {:?}: expected action_ref {}, got {}",
                    fixture.name, expected_action_ref, action_ref
                )),
                None if disposition == FactoryDisposition::Mediated => {
                    report.failures.push(format!(
                        "fixture {:?}: action {:?} missing from manifest v2 carrier",
                        fixture.name, action_key.0
                    ));
                }
                None => {}
            }
        }

        if disposition == FactoryDisposition::Mediated {
            match action_key.as_ref() {
                Some(action_key) => {
                    let target = contract.target_for_argv(action_key, &fixture.argv);
                    if fixture.expected_target.is_some() && target.is_none() {
                        report.failures.push(format!(
                            "fixture {:?}: expected target extraction",
                            fixture.name
                        ));
                    }
                    if fixture.expected_need.is_some() || fixture.expected_need_ir.is_some() {
                        match target.as_ref() {
                            Some(target)
                                if contract
                                    .need_for_target(action_key, target, &fixture.argv)
                                    .is_some() => {}
                            _ => report.failures.push(format!(
                                "fixture {:?}: expected need template resolution",
                                fixture.name
                            )),
                        }
                    }
                }
                None => report.failures.push(format!(
                    "fixture {:?}: mediated fixture did not classify to an action key",
                    fixture.name
                )),
            }
        }
    }

    report
}

fn non_empty_optional_string(value: &Option<String>) -> bool {
    value
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty())
}

fn non_empty_table(value: &Option<toml::Value>) -> bool {
    matches!(value, Some(toml::Value::Table(table)) if !table.is_empty())
}

fn expected_need_actions(value: &Option<toml::Value>) -> Vec<String> {
    let Some(toml::Value::Table(table)) = value else {
        return Vec::new();
    };
    let Some(toml::Value::Array(actions)) = table.get("actions") else {
        return Vec::new();
    };
    actions
        .iter()
        .filter_map(|action| action.as_str().map(ToOwned::to_owned))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const AWS_MANIFEST: &str = include_str!("../../ember-construct/construct/aws.toml");
    const AWS_FIXTURES: &str =
        include_str!("../../ember-construct/conformance/aws/factory-fixtures.toml");

    #[test]
    fn disposition_strings_are_stable() {
        #[derive(Debug, Serialize, Deserialize)]
        struct Wrapper {
            disposition: FactoryDisposition,
        }

        for (value, raw) in [
            (FactoryDisposition::Mediated, "mediated"),
            (FactoryDisposition::Credentialless, "credentialless"),
            (FactoryDisposition::ResolverRequired, "resolver_required"),
            (
                FactoryDisposition::PayloadAnalysisRequired,
                "payload_analysis_required",
            ),
            (
                FactoryDisposition::UnsupportedFailClosed,
                "unsupported_fail_closed",
            ),
        ] {
            assert_eq!(value.as_str(), raw);
            assert_eq!(raw.parse::<FactoryDisposition>().unwrap(), value);
            let encoded = toml::to_string(&Wrapper { disposition: value }).unwrap();
            assert_eq!(encoded.trim(), format!("disposition = \"{raw}\""));
            let decoded: Wrapper = toml::from_str(&encoded).unwrap();
            assert_eq!(decoded.disposition, value);
        }
    }

    #[test]
    fn parses_action_manifest_v2_carrier() {
        let carrier = ActionManifestV2Carrier::parse(AWS_MANIFEST).expect("valid aws manifest");
        assert!(carrier.is_v2());
        assert_eq!(
            carrier
                .action_ref_for_key("aws.s3.cp")
                .expect("action ref")
                .to_string(),
            "registry.ember.systems/ember-systems/ember-aws/aws.s3.cp@v1"
        );
    }

    #[test]
    fn parses_and_validates_aws_fixture_corpus_shape() {
        let corpus = parse_factory_fixture_corpus(AWS_FIXTURES).expect("fixture TOML parses");
        let errors = validate_factory_fixture_corpus(&corpus);
        assert!(errors.is_empty(), "{errors:#?}");
    }

    #[test]
    fn parses_factory_fixture_need_ir_archetype_shape() {
        let corpus = parse_factory_fixture_corpus(
            r#"
[[fixtures]]
name = "oauth-mediated"
argv = ["oauth", "write", "repo"]
expected_action_ref = "registry.ember.systems/example/oauth.write@v1"
expected_disposition = "mediated"
expected_target = { provider = "github", repo = "emberdotlink/emberlink-dev" }
expected_need = { provider_ir = "github_need", actions = ["github:contents:write"] }
expected_need_ir = { archetype = "OAuth-scope", provider = "github", scopes = ["contents:write"] }
expected_credential_injection = true

[[fixtures]]
name = "unknown-fails-closed"
argv = ["unknown"]
expected_disposition = "unsupported_fail_closed"
expected_credential_injection = false
reason = "unknown shape"
"#,
        )
        .expect("fixture TOML parses");
        let errors = validate_factory_fixture_corpus(&corpus);
        assert!(errors.is_empty(), "{errors:#?}");
        assert!(matches!(
            corpus.fixtures[0].expected_need_ir.as_ref(),
            Some(NeedIrArchetypeData::OauthScope(_))
        ));
    }

    #[test]
    fn fixture_validator_rejects_non_monotone_need_ir() {
        let corpus = parse_factory_fixture_corpus(
            r#"
[[fixtures]]
name = "oauth-mediated"
argv = ["oauth", "write", "repo"]
expected_action_ref = "registry.ember.systems/example/oauth.write@v1"
expected_disposition = "mediated"
expected_target = { provider = "github", repo = "emberdotlink/emberlink-dev" }
expected_need = { provider_ir = "github_need", actions = ["github:contents:read"] }
expected_need_ir = { archetype = "OAuth-scope", provider = "github", scopes = ["contents:write"] }
expected_credential_injection = true

[[fixtures]]
name = "unknown-fails-closed"
argv = ["unknown"]
expected_disposition = "unsupported_fail_closed"
expected_credential_injection = false
reason = "unknown shape"
"#,
        )
        .expect("fixture TOML parses");
        let errors = validate_factory_fixture_corpus(&corpus);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("expected_need_ir is non-monotone")),
            "{errors:#?}"
        );
    }

    #[test]
    fn fixture_validator_rejects_bad_shapes() {
        let corpus = parse_factory_fixture_corpus(
            r#"
[[fixtures]]
name = "bad"
argv = ["surprise"]
expected_disposition = "unsupported_fail_closed"
expected_credential_injection = true
"#,
        )
        .expect("fixture TOML parses");
        let errors = validate_factory_fixture_corpus(&corpus);
        assert!(
            errors.iter().any(|error| error
                .contains("unsupported_fail_closed fixtures must not inject credentials")),
            "{errors:#?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("unsupported_fail_closed fixtures need a reason")),
            "{errors:#?}"
        );
    }
}
