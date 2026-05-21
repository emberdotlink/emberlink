//! `construct.toml` manifest reader — per design §2.
//!
//! Minimal in-crate parser scoped to the action surface that
//! [`crate::preflight`] needs: the `[meta] name`, manifest/action
//! `authority_refs`, manifest-level `headless_requirements`, and the union of
//! `[[actions]] key` strings. The
//! canonical schema validator with all eight invariants lives in
//! `core-events::construct_toml`; this reader is the smallest
//! dependency-free surface runtime-layer needs to consume the legacy
//! `[[actions]]` array-of-tables shape that the bundled cohort-A
//! manifests in `crates/ember-construct/construct/*.toml` ship today.
//!
//! Phase 2 slice B (implementation-note-18): used by
//! the Layer 1 pre-flight resolver to cross-reference task `constructs`
//! declarations against the manifest action surface. The fuller
//! `schema_version = "1"` shape validated by `core-events` is intended for
//! the broker / daemon load path; pre-flight only needs the action key
//! list.

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
    /// Manifest-wide default authority families this Construct consumes when
    /// an action does not override them explicitly. Values use
    /// [`core_broker::BrokerProvider::as_str`] naming (e.g. `"github"`,
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
    /// Action-scoped authority families. When empty, callers should fall back
    /// to the manifest-wide [`ConstructManifest::authority_refs`] list.
    pub authority_refs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawManifest {
    meta: RawMeta,
    #[serde(default)]
    authority_refs: Vec<String>,
    #[serde(default)]
    actions: Vec<RawAction>,
}

#[derive(Debug, Deserialize)]
struct RawMeta {
    name: String,
    #[serde(default)]
    authority_refs: Vec<String>,
    #[serde(default)]
    headless_requirements: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawAction {
    key: String,
    #[serde(default)]
    authority_refs: Vec<String>,
}

/// Parse a `construct.toml` manifest from disk.
///
/// **Pre:** `path` resolves to a UTF-8 TOML file in the legacy `[[actions]]`
/// array-of-tables shape (the format used by all 14 cohort-A bundled
/// manifests at `crates/ember-construct/construct/*.toml` and
/// `crates/ember-vault/construct.toml` as of design §2).
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
        authority_refs,
        actions,
    } = raw;
    let actions: Vec<ConstructAction> = actions
        .into_iter()
        .map(|a| ConstructAction {
            key: a.key,
            authority_refs: a.authority_refs,
        })
        .collect();
    let RawMeta {
        name,
        authority_refs: meta_authority_refs,
        headless_requirements,
    } = meta;
    Ok(ConstructManifest {
        name,
        authority_refs: if authority_refs.is_empty() {
            meta_authority_refs
        } else {
            authority_refs
        },
        headless_requirements,
        action_keys: actions.iter().map(|a| a.key.clone()).collect(),
        actions,
    })
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
        assert_eq!(m.authority_refs, vec!["github"]);
        assert!(m.headless_requirements.is_empty());
        assert_eq!(m.action_keys, vec!["pr_create", "pr_merge", "pr_list"]);
    }

    #[test]
    fn preserves_source_order() {
        let m = parse_construct_manifest_str(KUBECTL_MANIFEST).expect("parses");
        assert_eq!(m.name, "ember-kubectl");
        assert!(m.authority_refs.is_empty());
        assert!(m.headless_requirements.is_empty());
        assert_eq!(m.action_keys, vec!["kubectl.apply", "kubectl.delete"]);
    }

    #[test]
    fn parses_real_bundled_gh_manifest() {
        // Smoke test: the verbatim cohort-A gh.toml shipped in
        // crates/ember-construct/construct/ must parse cleanly.
        let bytes = include_str!("../../ember-construct/construct/gh.toml");
        let m = parse_construct_manifest_str(bytes).expect("real gh.toml parses");
        assert_eq!(m.name, "ember-gh");
        assert!(m.action_keys.contains(&"pr_merge".to_string()));
        assert!(m.action_keys.contains(&"pr_create".to_string()));
    }

    #[test]
    fn parses_real_bundled_kubectl_manifest() {
        let bytes = include_str!("../../ember-construct/construct/kubectl.toml");
        let m = parse_construct_manifest_str(bytes).expect("real kubectl.toml parses");
        assert_eq!(m.name, "ember-kubectl");
        assert!(m.action_keys.contains(&"kubectl.apply".to_string()));
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
"#;
        let m = parse_construct_manifest_str(s).expect("parses");
        assert!(m.authority_refs.is_empty());
        assert_eq!(m.actions.len(), 1);
        assert_eq!(m.actions[0].key, "toy.deploy");
        assert_eq!(m.actions[0].authority_refs, vec!["github", "vercel"]);
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
