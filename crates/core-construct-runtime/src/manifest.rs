//! CLASSIFICATION: PUBLIC
//! `construct.toml` manifest reader — per ADR 124 §2.
//!
//! Minimal in-crate parser scoped to the action surface that
//! [`crate::preflight`] needs: the `[meta] name`, manifest/action
//! `authority_refs`, manifest-level `headless_requirements`, and the union of
//! `[[actions]] key` strings. The
//! canonical schema validator with all eight invariants lives in
//! `core-events::construct_toml`; this reader is the smallest
//! dependency-free surface internal-automation needs to consume the legacy
//! `[[actions]]` array-of-tables shape that the bundled cohort-A
//! manifests in `crates/ember-construct/construct/*.toml` ship today.
//!
//! Phase 2 slice B (HEADLESS-PREFLIGHT-LAYER1-PHASE2-B-PARSER): used by
//! the Layer 1 pre-flight resolver to cross-reference task `constructs`
//! declarations against the manifest action surface. The fuller
//! `schema_version = "1"` shape validated by `core-events` is intended for
//! the broker / daemon load path; pre-flight only needs the action key
//! list.

use core_event_types::ActionRef;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

/// Errors returned by [`parse_construct_manifest`].
#[derive(Debug, Error)]
pub enum ManifestError {
    /// File read failed (missing, permission denied, non-UTF-8).
    #[error("read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// TOML parser rejected the bytes.
    #[error("parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
}

/// Parsed view of a `construct.toml` manifest, narrowed to the fields the
/// pre-flight resolver consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstructManifest {
    /// The construct binary's name, from `[meta] name`. Matches the
    /// `<construct>` prefix in a task brief's
    /// `constructs = ["<construct>.<action>"]` entries (e.g. `"ember-gh"`,
    /// `"ember-kubectl"`).
    pub name: String,
    /// ADR 184 package-scoped plugin identity. When absent, callers may still
    /// match legacy action keys, but cannot surface a canonical `ActionRef`.
    pub plugin_address: Option<String>,
    /// Publishing package version from `[meta].plugin_version` when present,
    /// otherwise `[meta].version`. Exposed so callers can surface the current
    /// carrier's action-manifest identity fields without reparsing TOML.
    pub plugin_version: Option<String>,
    /// Optional operator-readable manifest description from `[meta]`.
    pub description: Option<String>,
    /// Manifest-wide default authority families this Construct consumes when
    /// an action does not override them explicitly. Values use
    /// `core_broker::BrokerProvider::as_str` naming (e.g. `"github"`,
    /// `"aws_sts"`). Empty means the manifest intentionally makes no claim
    /// yet; callers must treat that as unresolved rather than guessing.
    pub authority_refs: Vec<String>,
    /// Extra unattended/headless runtime requirements this Construct carries
    /// beyond direct broker-authority shaping. Empty means no extra
    /// requirement is declared. Current values are intentionally stringly and
    /// minimal; for example `"runtime_kms"` means the queue is only
    /// canonically unattended when a runtime KMS-backed secrets-provider lane
    /// is live, not when a legacy passphrase env passthrough path is in play.
    pub headless_requirements: Vec<String>,
    /// Manifest-wide default non-broker material declarations carried into a
    /// headless enrollment when an action does not override them explicitly.
    pub delegated_material: ConstructMaterialDeclarations,
    /// Action keys declared in `[[actions]] key = "..."` blocks, in the
    /// verbatim order they appear in the file. Cohort-A manifests use
    /// either bare keys (`pr_merge`) or tool-prefixed keys
    /// (`kubectl.apply`); the resolver matches whichever shape the task
    /// brief used.
    pub action_keys: Vec<String>,
    /// Action metadata in source order. Kept alongside `action_keys` so
    /// callers that need richer per-action data (for example headless
    /// authority shaping) can consume the same parsed seam without opening
    /// the TOML a second time.
    pub actions: Vec<ConstructAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstructAction {
    pub key: String,
    /// ADR 184 action contract version from the current carrier.
    pub action_version: Option<String>,
    /// Current carrier's default authority disposition for this action.
    pub default_policy: Option<String>,
    /// Current carrier's coarse risk label for operator/catalog projection.
    pub risk_tier: Option<String>,
    /// Optional convention labels surfaced from `[[actions]].semantic_labels`.
    pub semantic_labels: Vec<String>,
    /// Manifest-declared abstract authority need. Empty means unresolved, not
    /// "no authority needed"; use-time materialization must still fail closed
    /// when an action requires brokered material and no need is declared.
    pub need: Vec<String>,
    /// Action-scoped authority families. When empty, callers should fall back
    /// to the manifest-wide [`ConstructManifest::authority_refs`] list.
    pub authority_refs: Vec<String>,
    /// Action-scoped non-broker material declarations. Empty fields fall back
    /// to the manifest-wide defaults on the same field.
    pub delegated_material: ConstructMaterialDeclarations,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConstructMaterialDeclarations {
    pub vault_paths: Vec<String>,
    pub env_passthrough: Vec<String>,
    pub file_env: Vec<String>,
}

impl ConstructMaterialDeclarations {
    pub fn is_empty(&self) -> bool {
        self.vault_paths.is_empty() && self.env_passthrough.is_empty() && self.file_env.is_empty()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConstructActionIdentityError {
    #[error("meta.plugin_address is required for structured action refs")]
    MissingPluginAddress,
    #[error("action {0:?} is not declared in construct.toml [[actions]]")]
    UnknownAction(String),
    #[error("action {0:?} is missing action_version")]
    MissingActionVersion(String),
    #[error("invalid structured action ref: {0}")]
    InvalidActionRef(String),
}

#[derive(Debug, Deserialize)]
struct RawManifest {
    meta: RawMeta,
    #[serde(default)]
    defaults: RawDefaults,
    #[serde(default)]
    authority_refs: Vec<String>,
    #[serde(default)]
    vault_paths: Vec<String>,
    #[serde(default)]
    env_passthrough: Vec<String>,
    #[serde(default)]
    file_env: Vec<String>,
    #[serde(default)]
    actions: Vec<RawAction>,
}

#[derive(Debug, Deserialize)]
struct RawMeta {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    plugin_address: Option<String>,
    #[serde(default)]
    plugin_version: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    authority_refs: Vec<String>,
    #[serde(default)]
    headless_requirements: Vec<String>,
    #[serde(default)]
    vault_paths: Vec<String>,
    #[serde(default)]
    env_passthrough: Vec<String>,
    #[serde(default)]
    file_env: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawDefaults {
    #[serde(default)]
    authority_refs: Vec<String>,
    #[serde(default)]
    material_classes: Vec<RawMaterialClass>,
    #[serde(default)]
    vault_paths: Vec<String>,
    #[serde(default)]
    env_passthrough: Vec<String>,
    #[serde(default)]
    file_env: Vec<String>,
    #[serde(default)]
    headless_requirements: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RawMaterialClass {
    Broker { authority_ref: String },
    Env { name: String },
    FileEnv { name: String },
    VaultPath { path: String },
}

#[derive(Debug, Deserialize)]
struct RawAction {
    key: String,
    #[serde(default)]
    action_version: Option<String>,
    #[serde(default, rename = "default")]
    default_policy: Option<String>,
    #[serde(default)]
    risk_tier: Option<String>,
    #[serde(default)]
    semantic_labels: Vec<String>,
    #[serde(default)]
    need: Vec<String>,
    #[serde(default)]
    authority_refs: Vec<String>,
    #[serde(default)]
    material_classes: Vec<RawMaterialClass>,
    #[serde(default)]
    vault_paths: Vec<String>,
    #[serde(default)]
    env_passthrough: Vec<String>,
    #[serde(default)]
    file_env: Vec<String>,
}

/// Parse a `construct.toml` manifest from disk.
///
/// **Pre:** `path` resolves to a UTF-8 TOML file in the legacy `[[actions]]`
/// array-of-tables shape (the format used by all 14 cohort-A bundled
/// manifests at `crates/ember-construct/construct/*.toml` and
/// `crates/ember-vault/construct.toml` as of ADR 124 §2).
///
/// **Post:** on `Ok`, the returned [`ConstructManifest`] carries the
/// `[meta] name`, any manifest / action `authority_refs`, and every
/// `[[actions]] key` from the file in source order; on `Err`, the read or
/// parse failure is named with the file path.
pub fn parse_construct_manifest(path: &Path) -> Result<ConstructManifest, ManifestError> {
    let text = std::fs::read_to_string(path).map_err(|e| ManifestError::Read {
        path: path.display().to_string(),
        source: e,
    })?;
    parse_construct_manifest_str(&text).map_err(|source| ManifestError::Parse {
        path: path.display().to_string(),
        source,
    })
}

/// Parse a `construct.toml` manifest from an in-memory string.
///
/// Test seam for [`parse_construct_manifest`] — accepts manifest bytes
/// directly without touching the filesystem. Same post-condition on the
/// returned [`ConstructManifest`].
pub fn parse_construct_manifest_str(text: &str) -> Result<ConstructManifest, toml::de::Error> {
    let raw: RawManifest = toml::from_str(text)?;
    let RawManifest {
        meta,
        defaults,
        authority_refs,
        vault_paths,
        env_passthrough,
        file_env,
        actions,
    } = raw;
    let actions: Vec<ConstructAction> = actions
        .into_iter()
        .map(|a| ConstructAction {
            key: a.key,
            action_version: a.action_version,
            default_policy: a.default_policy,
            risk_tier: a.risk_tier,
            semantic_labels: a.semantic_labels,
            need: a.need,
            authority_refs: first_non_empty(
                a.authority_refs,
                broker_authority_refs(&a.material_classes),
            ),
            delegated_material: material_declarations(
                a.vault_paths,
                a.env_passthrough,
                a.file_env,
                &a.material_classes,
            ),
        })
        .collect();
    let RawMeta {
        name,
        version,
        plugin_address,
        plugin_version,
        description,
        authority_refs: meta_authority_refs,
        headless_requirements,
        vault_paths: meta_vault_paths,
        env_passthrough: meta_env_passthrough,
        file_env: meta_file_env,
    } = meta;
    let default_authority_refs = first_non_empty(
        defaults.authority_refs,
        broker_authority_refs(&defaults.material_classes),
    );
    let default_material = material_declarations(
        defaults.vault_paths,
        defaults.env_passthrough,
        defaults.file_env,
        &defaults.material_classes,
    );
    Ok(ConstructManifest {
        name,
        plugin_address,
        plugin_version: plugin_version.or(version),
        description,
        authority_refs: first_non_empty(
            authority_refs,
            first_non_empty(meta_authority_refs, default_authority_refs),
        ),
        headless_requirements: first_non_empty(
            headless_requirements,
            defaults.headless_requirements,
        ),
        delegated_material: first_non_empty_material(
            ConstructMaterialDeclarations {
                vault_paths,
                env_passthrough,
                file_env,
            },
            first_non_empty_material(
                ConstructMaterialDeclarations {
                    vault_paths: meta_vault_paths,
                    env_passthrough: meta_env_passthrough,
                    file_env: meta_file_env,
                },
                default_material,
            ),
        ),
        action_keys: actions.iter().map(|a| a.key.clone()).collect(),
        actions,
    })
}

fn first_non_empty<T>(primary: Vec<T>, fallback: Vec<T>) -> Vec<T> {
    if primary.is_empty() {
        fallback
    } else {
        primary
    }
}

fn first_non_empty_material(
    primary: ConstructMaterialDeclarations,
    fallback: ConstructMaterialDeclarations,
) -> ConstructMaterialDeclarations {
    if primary.is_empty() {
        fallback
    } else {
        primary
    }
}

fn broker_authority_refs(material_classes: &[RawMaterialClass]) -> Vec<String> {
    material_classes
        .iter()
        .filter_map(|material| match material {
            RawMaterialClass::Broker { authority_ref } => Some(authority_ref.clone()),
            RawMaterialClass::Env { .. }
            | RawMaterialClass::FileEnv { .. }
            | RawMaterialClass::VaultPath { .. } => None,
        })
        .collect()
}

fn material_declarations(
    mut vault_paths: Vec<String>,
    mut env_passthrough: Vec<String>,
    mut file_env: Vec<String>,
    material_classes: &[RawMaterialClass],
) -> ConstructMaterialDeclarations {
    for material in material_classes {
        match material {
            RawMaterialClass::Broker { .. } => {}
            RawMaterialClass::Env { name } => env_passthrough.push(name.clone()),
            RawMaterialClass::FileEnv { name } => file_env.push(name.clone()),
            RawMaterialClass::VaultPath { path } => vault_paths.push(path.clone()),
        }
    }
    ConstructMaterialDeclarations {
        vault_paths,
        env_passthrough,
        file_env,
    }
}

/// Look up a manifest by construct name from a manifest registry. Returns
/// `None` when no manifest is registered for `name`.
///
/// Thin wrapper around `HashMap::get` to keep call-sites in the resolver
/// readable; trivial today, but kept as a function so a future migration
/// to a richer registry shape (e.g. versioned, signed) does not ripple
/// through the resolver's call sites.
pub fn lookup<'a>(
    registry: &'a HashMap<String, ConstructManifest>,
    name: &str,
) -> Option<&'a ConstructManifest> {
    registry.get(name)
}

impl ConstructManifest {
    /// Resolve a canonical structured action ref from the already-parsed live
    /// carrier fields. This keeps preflight / registry callers on the same
    /// identity doctrine as broker_exec without re-opening the TOML bytes.
    pub fn action_ref(&self, action_key: &str) -> Result<ActionRef, ConstructActionIdentityError> {
        let plugin_address = self
            .plugin_address
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(ConstructActionIdentityError::MissingPluginAddress)?;
        let action = self
            .actions
            .iter()
            .find(|action| action.key == action_key)
            .ok_or_else(|| ConstructActionIdentityError::UnknownAction(action_key.to_string()))?;
        let action_version = action
            .action_version
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ConstructActionIdentityError::MissingActionVersion(action_key.to_string())
            })?;
        let action_ref = ActionRef::new(plugin_address, action_key, action_version);
        action_ref
            .validate()
            .map_err(|e| ConstructActionIdentityError::InvalidActionRef(e.to_string()))?;
        Ok(action_ref)
    }

    pub fn action_plugin_version(&self) -> Option<&str> {
        self.plugin_version
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    pub fn action(&self, action_key: &str) -> Option<&ConstructAction> {
        self.actions.iter().find(|action| action.key == action_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GH_MANIFEST: &str = r#"
[meta]
name = "ember-gh"
version = "0.1.0"
publisher = "did:emberlink"
description = "GitHub CLI Construct."

authority_refs = ["github"]
env_passthrough = ["GH_TOKEN"]

default = "deny"

[[actions]]
key = "pr_create"
default = "permit"

[[actions]]
key = "pr_merge"
default = "prompt"

[[actions]]
key = "pr_list"
default = "permit"
"#;

    const KUBECTL_MANIFEST: &str = r#"
[meta]
name = "ember-kubectl"
version = "0.1.0"
publisher = "did:emberlink"
description = "kubectl CLI Construct."
file_env = ["KUBECONFIG"]

default = "deny"

[[actions]]
key = "kubectl.apply"
default = "permit"
biometric = "required"

[[actions]]
key = "kubectl.delete"
default = "permit"
biometric = "required"
"#;

    #[test]
    fn parses_meta_name_and_action_keys() {
        let m = parse_construct_manifest_str(GH_MANIFEST).expect("parses");
        assert_eq!(m.name, "ember-gh");
        assert!(m.plugin_address.is_none());
        assert_eq!(m.plugin_version.as_deref(), Some("0.1.0"));
        assert_eq!(m.description.as_deref(), Some("GitHub CLI Construct."));
        assert_eq!(m.authority_refs, vec!["github"]);
        assert!(m.headless_requirements.is_empty());
        assert_eq!(
            m.delegated_material.env_passthrough,
            vec!["GH_TOKEN".to_string()]
        );
        assert_eq!(m.action_keys, vec!["pr_create", "pr_merge", "pr_list"]);
    }

    #[test]
    fn preserves_source_order() {
        let m = parse_construct_manifest_str(KUBECTL_MANIFEST).expect("parses");
        assert_eq!(m.name, "ember-kubectl");
        assert!(m.authority_refs.is_empty());
        assert!(m.headless_requirements.is_empty());
        assert_eq!(
            m.delegated_material.file_env,
            vec!["KUBECONFIG".to_string()]
        );
        assert_eq!(m.action_keys, vec!["kubectl.apply", "kubectl.delete"]);
    }

    #[test]
    fn parses_real_bundled_gh_manifest() {
        // Smoke test: the verbatim cohort-A gh.toml shipped in
        // crates/ember-construct/construct/ must parse cleanly.
        let bytes = include_str!("../../ember-construct/construct/gh.toml");
        let m = parse_construct_manifest_str(bytes).expect("real gh.toml parses");
        assert_eq!(m.name, "ember-gh");
        assert_eq!(
            m.plugin_address.as_deref(),
            Some("registry.ember.systems/ember-systems/ember-gh")
        );
        assert_eq!(m.plugin_version.as_deref(), Some("0.1.0"));
        assert!(m.action_keys.contains(&"pr_merge".to_string()));
        assert!(m.action_keys.contains(&"pr_create".to_string()));
        assert_eq!(
            m.action_ref("pr_create").expect("pr_create action ref"),
            ActionRef::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_create",
                "v1"
            )
        );
        let pr_create = m
            .actions
            .iter()
            .find(|action| action.key == "pr_create")
            .expect("pr_create action");
        assert_eq!(
            pr_create.semantic_labels,
            vec![
                "github.pull_request.write".to_string(),
                "scm.pull_request.write".to_string()
            ]
        );
        assert_eq!(pr_create.default_policy.as_deref(), Some("permit"));
        assert_eq!(pr_create.risk_tier.as_deref(), Some("medium"));
        assert_eq!(
            pr_create.need,
            vec![
                "github:metadata:read".to_string(),
                "github:contents:write".to_string(),
                "github:pull_request:create".to_string()
            ]
        );
    }

    #[test]
    fn parses_real_bundled_kubectl_manifest() {
        let bytes = include_str!("../../ember-construct/construct/kubectl.toml");
        let m = parse_construct_manifest_str(bytes).expect("real kubectl.toml parses");
        assert_eq!(m.name, "ember-kubectl");
        assert!(m.action_keys.contains(&"kubectl.apply".to_string()));
        assert_eq!(
            m.delegated_material.file_env,
            vec!["KUBECONFIG".to_string()]
        );
    }

    #[test]
    fn empty_actions_is_ok() {
        let s = r#"
[meta]
name = "ember-empty"
"#;
        let m = parse_construct_manifest_str(s).expect("parses");
        assert_eq!(m.name, "ember-empty");
        assert!(m.authority_refs.is_empty());
        assert!(m.headless_requirements.is_empty());
        assert!(m.delegated_material.is_empty());
        assert!(m.action_keys.is_empty());
    }

    #[test]
    fn parses_action_specific_authority_refs() {
        let s = r#"
[meta]
name = "ember-toy"

[[actions]]
key = "toy.deploy"
authority_refs = ["github", "vercel"]
file_env = ["KUBECONFIG"]
"#;
        let m = parse_construct_manifest_str(s).expect("parses");
        assert!(m.authority_refs.is_empty());
        assert_eq!(m.actions.len(), 1);
        assert_eq!(m.actions[0].key, "toy.deploy");
        assert_eq!(m.actions[0].authority_refs, vec!["github", "vercel"]);
        assert_eq!(
            m.actions[0].delegated_material.file_env,
            vec!["KUBECONFIG".to_string()]
        );
    }

    #[test]
    fn parses_headless_requirements() {
        let s = r#"
[meta]
name = "ember-pulumi"
headless_requirements = ["runtime_kms"]

[[actions]]
key = "pulumi.up"
"#;
        let m = parse_construct_manifest_str(s).expect("parses");
        assert_eq!(m.name, "ember-pulumi");
        assert!(m.authority_refs.is_empty());
        assert_eq!(m.headless_requirements, vec!["runtime_kms"]);
    }

    #[test]
    fn parses_manifest_level_material_declarations() {
        let s = r#"
[meta]
name = "ember-material"

vault_paths = ["pulumi/org/project/stack"]
env_passthrough = ["PULUMI_CONFIG_PASSPHRASE"]
file_env = ["KUBECONFIG"]

[[actions]]
key = "material.deploy"
"#;
        let m = parse_construct_manifest_str(s).expect("parses");
        assert_eq!(
            m.delegated_material,
            ConstructMaterialDeclarations {
                vault_paths: vec!["pulumi/org/project/stack".to_string()],
                env_passthrough: vec!["PULUMI_CONFIG_PASSPHRASE".to_string()],
                file_env: vec!["KUBECONFIG".to_string()],
            }
        );
    }

    #[test]
    fn parses_v2_defaults_material_declarations() {
        let s = r#"
schema_version = "2"

[meta]
name = "ember-gh"
plugin_address = "registry.ember.systems/ember-systems/ember-gh"
plugin_version = "0.1.0"
description = "GitHub CLI Construct."

[defaults]
material_classes = [
  { kind = "broker", authority_ref = "github" },
  { kind = "env", name = "GH_HOST" },
  { kind = "file_env", name = "KUBECONFIG" },
  { kind = "vault_path", path = "secret/data/github/*" },
]
headless_requirements = ["runtime_kms"]

[[actions]]
key = "pr_create"
action_version = "v1"
"#;
        let m = parse_construct_manifest_str(s).expect("v2 defaults parse");
        assert_eq!(m.authority_refs, vec!["github"]);
        assert_eq!(m.headless_requirements, vec!["runtime_kms"]);
        assert_eq!(
            m.delegated_material,
            ConstructMaterialDeclarations {
                vault_paths: vec!["secret/data/github/*".to_string()],
                env_passthrough: vec!["GH_HOST".to_string()],
                file_env: vec!["KUBECONFIG".to_string()],
            }
        );
    }

    #[test]
    fn missing_meta_name_errors() {
        let s = r#"
[[actions]]
key = "x"
"#;
        assert!(parse_construct_manifest_str(s).is_err());
    }

    #[test]
    fn parse_from_disk_round_trips() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("construct.toml");
        std::fs::write(&path, GH_MANIFEST).expect("write");
        let m = parse_construct_manifest(&path).expect("parses from disk");
        assert_eq!(m.name, "ember-gh");
        assert_eq!(m.action_keys.len(), 3);
    }

    #[test]
    fn parse_from_disk_missing_file_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("does-not-exist.toml");
        let err = parse_construct_manifest(&path).expect_err("missing file errors");
        assert!(matches!(err, ManifestError::Read { .. }));
    }

    #[test]
    fn parse_from_disk_invalid_toml_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("construct.toml");
        std::fs::write(&path, "not [[[ valid").expect("write");
        let err = parse_construct_manifest(&path).expect_err("invalid toml errors");
        assert!(matches!(err, ManifestError::Parse { .. }));
    }

    #[test]
    fn lookup_finds_registered_manifest() {
        let mut registry = HashMap::new();
        let m = parse_construct_manifest_str(GH_MANIFEST).expect("parses");
        registry.insert(m.name.clone(), m);
        let found = lookup(&registry, "ember-gh").expect("registered manifest");
        assert_eq!(found.action_keys.len(), 3);
        assert!(lookup(&registry, "ember-unknown").is_none());
    }
}
