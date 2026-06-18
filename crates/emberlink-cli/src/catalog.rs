//! CLASSIFICATION: PUBLIC
//! Authority Catalog read surface per ADR 187 Phase 1.
//!
//! Composes existing primitives — no new storage, no new federation wire:
//!   * each bundled `construct.toml` under `crates/ember-construct/construct/`
//!     supplies one **service** (installed publisher plugin, ADR 187 §2)
//!   * each manifest's `[[actions]]` array supplies the **actions** that
//!     service exposes (ADR 187 §3)
//!   * `core_state::list_active_grants` supplies the **grant** layer
//!
//! ADR 187 explicitly forbids inventing a `Catalog` table. This module is
//! the projection only.
//!
//! ## Grant ↔ service association
//!
//! Until ADR 187 §10's full data-layer work lands, grants do not always carry
//! a first-class service foreign key. This module therefore uses a hybrid
//! matcher:
//!
//! * prefer structured `action_ref.plugin_address` when a statement action is
//!   already encoded as `plugin_address/action_key@action_version`
//! * fall back to the legacy verb-prefix matcher against `authority_refs` for
//!   older named actions such as `"github:pull_request:create"`
//!
//! The composition is still transitional and is flagged as such in the catalog
//! surface. Once ADR 187 §10's structured grant / claim substrate lands, this
//! matcher can collapse to the canonical join without changing the CLI.

use core_event_types::ActionRef;
use serde::Deserialize;

/// One installed service in the Authority Catalog. ADR 187 §2: buyer-facing
/// alias for an installed `Construct`.
#[derive(Debug, Clone)]
pub struct BundledService {
    /// `meta.name` from the manifest — e.g. `"ember-gh"`.
    pub name: String,
    /// `meta.version` — semver string from the construct's own version line.
    pub version: String,
    /// `meta.plugin_address` per ADR 184/186 — e.g.
    /// `"registry.ember.systems/ember-systems/ember-gh"`. `None` only when the
    /// manifest predates the structured-action-ref cutover; bundled cohort-A
    /// manifests all carry it.
    pub plugin_address: Option<String>,
    /// `meta.plugin_version` per ADR 184. Defaults to `meta.version` when
    /// the manifest omits a separate plugin version.
    pub plugin_version: Option<String>,
    /// `meta.publisher` — DID of the publisher key that signs the construct.
    pub publisher: String,
    /// Human-readable description from `meta.description`. `None` when absent.
    pub description: Option<String>,
    /// Service-level broker-provider names this service consumes (`"github"`,
    /// `"aws_sts"`, etc.). For schema v2 manifests this is projected from
    /// `[defaults].material_classes[*].authority_ref`; legacy manifests may
    /// still carry direct `authority_refs`.
    pub authority_refs: Vec<String>,
    /// `meta.wraps_binary` — the binary this construct mediates (e.g. `"gh"`).
    pub wraps_binary: Option<String>,
    /// Actions the service exposes, in source order.
    pub actions: Vec<BundledAction>,
}

/// One action a service exposes (ADR 187 §3 layer 2; read-only).
#[derive(Debug, Clone)]
pub struct BundledAction {
    /// Action key as declared in the manifest — e.g. `"pr_create"`.
    pub key: String,
    /// `action_version` per ADR 186 — e.g. `"v1"`. `None` when the manifest
    /// predates the structured cutover.
    pub action_version: Option<String>,
    /// Default policy from `default = "..."` on the action — `"permit"`,
    /// `"deny"`, or `"prompt"`. `None` when the manifest omits it.
    pub default_policy: Option<String>,
    /// Per-action authority refs override. Empty when the action inherits
    /// the manifest-wide refs.
    pub authority_refs: Vec<String>,
}

impl BundledService {
    /// Stable identity for catalog lookups. Returns `plugin_address` when set,
    /// otherwise the manifest `name`. Both `ember service show <addr>` and
    /// `ember service show <name>` match.
    pub fn identity(&self) -> &str {
        self.plugin_address.as_deref().unwrap_or(&self.name)
    }

    /// Union of manifest-wide and per-action authority refs. Used to project
    /// the verb prefixes a grant statement can target on this service.
    pub fn all_authority_refs(&self) -> Vec<&str> {
        let mut refs: Vec<&str> = self.authority_refs.iter().map(String::as_str).collect();
        for action in &self.actions {
            for r in &action.authority_refs {
                if !refs.contains(&r.as_str()) {
                    refs.push(r.as_str());
                }
            }
        }
        refs
    }

    /// Canonical structured action identity for one bundled action when the
    /// manifest carries the required ADR 186 fields.
    pub fn action_ref_for(&self, action: &BundledAction) -> Option<ActionRef> {
        Some(ActionRef::new(
            self.plugin_address.clone()?,
            action.key.clone(),
            action.action_version.clone()?,
        ))
    }
}

// Internal raw deserialization shape. Captures only fields catalog rendering
// needs; avoids duplicating the full `core_events::construct_toml` validator
// (which is for the daemon load path).
#[derive(Debug, Deserialize)]
struct RawManifest {
    meta: RawMeta,
    #[serde(default)]
    defaults: RawDefaults,
    #[serde(default)]
    authority_refs: Vec<String>,
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
    publisher: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    wraps_binary: Option<String>,
    #[serde(default)]
    authority_refs: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawDefaults {
    #[serde(default)]
    material_classes: Vec<RawMaterialClass>,
    #[serde(default)]
    authority_refs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawMaterialClass {
    kind: String,
    #[serde(default)]
    authority_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawAction {
    key: String,
    #[serde(default)]
    action_version: Option<String>,
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    material_classes: Vec<RawMaterialClass>,
    #[serde(default)]
    authority_refs: Vec<String>,
}

/// Bundled cohort-A construct manifests. Mirrors the set the daemon loads via
/// `bundled_construct_registry()` (`crates/ember-daemon/src/infra/handler.rs`).
/// Both call sites bind to the same `include_str!` source files; if a new
/// construct is added there it must be added here too (compile-time check
/// via the path resolution).
const BUNDLED_MANIFESTS: &[(&str, &str)] = &[
    (
        "aws",
        include_str!("../../ember-construct/construct/aws.toml"),
    ),
    (
        "az",
        include_str!("../../ember-construct/construct/az.toml"),
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
        "gcloud",
        include_str!("../../ember-construct/construct/gcloud.toml"),
    ),
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
        "okta",
        include_str!("../../ember-construct/construct/okta.toml"),
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
        "vercel",
        include_str!("../../ember-construct/construct/vercel.toml"),
    ),
    (
        "wrangler",
        include_str!("../../ember-construct/construct/wrangler.toml"),
    ),
];

/// Load every bundled service manifest. Sorted by service `name` for stable
/// rendering. Manifests that fail to parse are skipped silently — the daemon
/// load path is authoritative for parse errors and surfaces them at startup
/// time.
pub fn bundled_services() -> Vec<BundledService> {
    let mut services: Vec<BundledService> = BUNDLED_MANIFESTS
        .iter()
        .filter_map(|(_, text)| parse_bundled(text).ok())
        .collect();
    services.sort_by(|a, b| a.name.cmp(&b.name));
    services
}

/// Look up a service by `plugin_address` exact match, then by `name`. Returns
/// `None` when no match. Buyer-facing `ember service show <q>` and
/// `ember catalog show <q>` both call this so either spelling works.
pub fn find_service(query: &str) -> Option<BundledService> {
    let services = bundled_services();
    services
        .iter()
        .find(|s| {
            s.plugin_address
                .as_deref()
                .map(|addr| addr == query)
                .unwrap_or(false)
        })
        .or_else(|| services.iter().find(|s| s.name == query))
        .cloned()
}

fn parse_bundled(text: &str) -> Result<BundledService, toml::de::Error> {
    let raw: RawManifest = toml::from_str(text)?;
    let RawManifest {
        meta,
        defaults,
        authority_refs: manifest_refs,
        actions,
    } = raw;
    let RawMeta {
        name,
        version,
        plugin_address,
        plugin_version,
        publisher,
        description,
        wraps_binary,
        authority_refs: meta_refs,
    } = meta;
    let mut authority_refs = if manifest_refs.is_empty() {
        meta_refs
    } else {
        manifest_refs
    };
    append_missing_refs(&mut authority_refs, defaults.authority_refs);
    append_broker_material_authority_refs(&mut authority_refs, defaults.material_classes);
    Ok(BundledService {
        name,
        version: version.unwrap_or_default(),
        plugin_address,
        plugin_version,
        publisher: publisher.unwrap_or_default(),
        description,
        authority_refs,
        wraps_binary,
        actions: actions
            .into_iter()
            .map(|a| {
                let RawAction {
                    key,
                    action_version,
                    default,
                    material_classes,
                    authority_refs,
                } = a;
                let mut authority_refs = authority_refs;
                append_broker_material_authority_refs(&mut authority_refs, material_classes);
                BundledAction {
                    key,
                    action_version,
                    default_policy: default,
                    authority_refs,
                }
            })
            .collect(),
    })
}

fn append_broker_material_authority_refs(refs: &mut Vec<String>, materials: Vec<RawMaterialClass>) {
    for material in materials {
        if material.kind == "broker"
            && let Some(authority_ref) = material.authority_ref
        {
            append_missing_ref(refs, authority_ref);
        }
    }
}

fn append_missing_refs(refs: &mut Vec<String>, new_refs: Vec<String>) {
    for authority_ref in new_refs {
        append_missing_ref(refs, authority_ref);
    }
}

fn append_missing_ref(refs: &mut Vec<String>, authority_ref: String) {
    if !refs.iter().any(|r| r == &authority_ref) {
        refs.push(authority_ref);
    }
}

/// Transitional match for Session 3: prefer canonical `action_ref` service
/// identity when present, otherwise fall back to the legacy named-verb prefix
/// matcher against `authority_refs`.
pub fn statement_targets_service(statement_actions: &[String], service: &BundledService) -> bool {
    statement_actions.iter().any(|action| {
        statement_action_targets_service_via_action_ref(action, service)
            || statement_action_targets_service_via_authority_ref(action, service)
    })
}

fn statement_action_targets_service_via_action_ref(
    statement_action: &str,
    service: &BundledService,
) -> bool {
    let Some(plugin_address) = service.plugin_address.as_deref() else {
        return false;
    };
    let Ok(action_ref) = ActionRef::parse(statement_action) else {
        return false;
    };
    action_ref.plugin_address == plugin_address
}

fn statement_action_targets_service_via_authority_ref(
    statement_action: &str,
    service: &BundledService,
) -> bool {
    let refs = service.all_authority_refs();
    if refs.is_empty() {
        return false;
    }
    let prefix = statement_action
        .split_once(':')
        .map(|(p, _)| p)
        .or_else(|| statement_action.split_once('.').map(|(p, _)| p))
        .unwrap_or(statement_action);
    refs.contains(&prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_services_loads_cohort_a() {
        let services = bundled_services();
        assert!(
            services.iter().any(|s| s.name == "ember-gh"),
            "expected ember-gh in bundled services"
        );
        assert!(
            services.iter().any(|s| s.name == "ember-git"),
            "expected ember-git in bundled services"
        );
        assert!(
            services.iter().any(|s| s.name == "ember-kubectl"),
            "expected ember-kubectl in bundled services"
        );
        assert!(
            services.len() >= 10,
            "expected at least 10 bundled services, got {}",
            services.len()
        );
    }

    #[test]
    fn bundled_gh_has_plugin_address_and_actions() {
        let services = bundled_services();
        let gh = services
            .iter()
            .find(|s| s.name == "ember-gh")
            .expect("ember-gh present");
        assert_eq!(
            gh.plugin_address.as_deref(),
            Some("registry.ember.systems/ember-systems/ember-gh"),
            "plugin_address from gh.toml"
        );
        assert!(gh.authority_refs.iter().any(|r| r == "github"));
        assert!(gh.actions.iter().any(|a| a.key == "pr_create"));
        assert!(gh.actions.iter().any(|a| a.key == "pr_merge"));
    }

    #[test]
    fn services_are_sorted_by_name() {
        let services = bundled_services();
        let mut prev: Option<&str> = None;
        for s in &services {
            if let Some(p) = prev {
                assert!(
                    p <= s.name.as_str(),
                    "services not sorted: {p} > {}",
                    s.name
                );
            }
            prev = Some(s.name.as_str());
        }
    }

    #[test]
    fn find_service_matches_plugin_address() {
        let s = find_service("registry.ember.systems/ember-systems/ember-gh");
        assert!(s.is_some());
        assert_eq!(s.unwrap().name, "ember-gh");
    }

    #[test]
    fn find_service_matches_name() {
        let s = find_service("ember-gh");
        assert!(s.is_some());
        assert_eq!(s.unwrap().name, "ember-gh");
    }

    #[test]
    fn find_service_returns_none_on_miss() {
        assert!(find_service("does-not-exist").is_none());
        assert!(find_service("ember-nope").is_none());
    }

    #[test]
    fn statement_targets_service_matches_colon_prefix() {
        let service = BundledService {
            name: "ember-gh".to_string(),
            version: "0.1.0".to_string(),
            plugin_address: None,
            plugin_version: None,
            publisher: "did:emberlink".to_string(),
            description: None,
            authority_refs: vec!["github".to_string()],
            wraps_binary: Some("gh".to_string()),
            actions: Vec::new(),
        };
        assert!(statement_targets_service(
            &["github:pull_request:create".to_string()],
            &service
        ));
        assert!(statement_targets_service(
            &["github.pr_create".to_string()],
            &service
        ));
        assert!(!statement_targets_service(
            &["aws_sts:assume_role".to_string()],
            &service
        ));
    }

    #[test]
    fn statement_targets_service_matches_structured_action_ref_plugin_address() {
        let service = BundledService {
            name: "ember-gh".to_string(),
            version: "0.1.0".to_string(),
            plugin_address: Some("registry.ember.systems/ember-systems/ember-gh".to_string()),
            plugin_version: Some("0.1.0".to_string()),
            publisher: "did:emberlink".to_string(),
            description: None,
            authority_refs: Vec::new(),
            wraps_binary: Some("gh".to_string()),
            actions: Vec::new(),
        };
        assert!(statement_targets_service(
            &["registry.ember.systems/ember-systems/ember-gh/pr_merge@v1".to_string()],
            &service
        ));
        assert!(!statement_targets_service(
            &["registry.ember.systems/ember-systems/ember-git/status@v1".to_string()],
            &service
        ));
    }

    #[test]
    fn statement_targets_service_handles_empty_refs() {
        let service = BundledService {
            name: "ember-empty".to_string(),
            version: "0.1.0".to_string(),
            plugin_address: None,
            plugin_version: None,
            publisher: "did:emberlink".to_string(),
            description: None,
            authority_refs: Vec::new(),
            wraps_binary: None,
            actions: Vec::new(),
        };
        assert!(!statement_targets_service(
            &["github:pr".to_string()],
            &service
        ));
    }

    #[test]
    fn statement_targets_service_uses_per_action_refs() {
        let service = BundledService {
            name: "ember-toy".to_string(),
            version: "0.1.0".to_string(),
            plugin_address: None,
            plugin_version: None,
            publisher: "did:emberlink".to_string(),
            description: None,
            authority_refs: Vec::new(),
            wraps_binary: None,
            actions: vec![BundledAction {
                key: "deploy".to_string(),
                action_version: None,
                default_policy: None,
                authority_refs: vec!["vercel".to_string()],
            }],
        };
        assert!(statement_targets_service(
            &["vercel:deploy".to_string()],
            &service
        ));
    }

    #[test]
    fn statement_targets_service_keeps_legacy_authority_ref_fallback() {
        let service = BundledService {
            name: "ember-gh".to_string(),
            version: "0.1.0".to_string(),
            plugin_address: Some("registry.ember.systems/ember-systems/ember-gh".to_string()),
            plugin_version: Some("0.1.0".to_string()),
            publisher: "did:emberlink".to_string(),
            description: None,
            authority_refs: vec!["github".to_string()],
            wraps_binary: Some("gh".to_string()),
            actions: Vec::new(),
        };
        assert!(statement_targets_service(
            &["github:pull_request:create".to_string()],
            &service
        ));
    }
}
