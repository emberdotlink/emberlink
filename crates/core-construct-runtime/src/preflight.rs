//! Pre-flight scope check at headless enrollment — Layer 1 (manifest-declared).
//!
//! Per ADR 139 §"Pre-flight scope check at enrollment" Layer 1: for each
//! queued task that declares which Constructs (per ADR 124) it invokes,
//! resolve the union of action permissions those Constructs require,
//! cross-reference against the enrolled persona template, and report any
//! gaps. Surface BEFORE autopilot runs the task, not after — predictive
//! layer atop the historical Layer 2 reader (already shipped at
//! `crate::permission_gaps::recent_gaps_for_persona`).
//!
//! ## Phase 2 slice B (this slice) — manifest-backed resolver
//!
//! [`resolve_queued_task_permissions`] now consumes each task's
//! `constructs` field (HEADLESS-PREFLIGHT-LAYER1-PHASE2-A-SCHEMA) and a
//! registry of parsed `construct.toml` manifests
//! ([`crate::manifest::ConstructManifest`]). For every
//! `"<construct>.<action>"` declaration the task carries, the resolver
//! looks up the construct in the registry, verifies the action key is
//! declared in the manifest, and emits a [`Permission`]. Unknown
//! constructs and unknown actions are skipped silently — pre-flight is a
//! best-effort predictive layer; a task that declares an unknown
//! Construct is still allowed to run (Layer 2 catches the gap from
//! runtime).
//!
//! Convention compatibility: task brief `constructs` entries are written
//! `<construct>.<action>` where `<construct>` is the manifest's
//! `[meta] name` (e.g. `ember-gh`, `ember-kubectl`). The resolver tries
//! the action suffix both verbatim (`pr_merge` matches `gh.toml`'s
//! `key = "pr_merge"`) and with the tool short-name re-prepended (`apply`
//! matches `kubectl.toml`'s `key = "kubectl.apply"` when the construct
//! is `ember-kubectl`).
//!
//! PREFLIGHT-LAYER1-MANIFEST — checkpoint for stale_check; do not remove.
//!
//! CLASSIFICATION: PUBLIC

use std::collections::HashMap;

use crate::manifest::{ConstructAction, ConstructManifest, ConstructMaterialDeclarations, lookup};

/// A permission a Construct requires to perform an action.
///
/// String-based for cohort A; the construct.toml parser (Phase 2) will
/// promote this to a structured enum once the manifest format is locked.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Permission {
    /// Identifier matching the Construct's manifest action surface
    /// (e.g. `"ember-gh.pr.merge"`, `"ember-kubectl.apply"`).
    pub identifier: String,
    /// Optional scope qualifier (e.g. `"forks/*"`, `"staging/*"`) — None
    /// when the permission applies broadly.
    pub scope: Option<String>,
}

/// A gap between a queued task's required permissions and the enrolled
/// persona template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionGap {
    pub task_id: String,
    pub permission: Permission,
}

/// A persona template's allow-list of permissions.
///
/// Phase 1 stub: a flat list. Phase 2 (and the broker layer) wire this to
/// the real persona template store.
#[derive(Debug, Clone, Default)]
pub struct Template {
    pub allowed: Vec<Permission>,
}

/// Identifier alias for the Ranker's `Pick.id` / `Task.id`. Matches the
/// schema's mixed-case task-id grammar (`^[A-Z][A-Za-z0-9_.-]+$`).
pub type TaskId = String;

/// Authority-ref resolution for a queued task set.
///
/// `refs_by_task` is the union of manifest-declared authority families for
/// each task. `fully_declared = false` means at least one declaration was
/// malformed, unknown, or lacked an authority declaration, so callers must
/// not treat the returned refs as a complete minimal authority set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRefResolution {
    pub refs_by_task: HashMap<TaskId, Vec<String>>,
    pub fully_declared: bool,
}

/// Extra unattended/headless runtime requirements declared by a queued task
/// set's Constructs.
///
/// `requirements_by_task` is the union of manifest-declared runtime
/// requirements for each task. `fully_declared = false` means at least one
/// declaration was malformed, unknown, or referred to an unknown action, so
/// callers must not treat the returned requirements as complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadlessRequirementResolution {
    pub requirements_by_task: HashMap<TaskId, Vec<String>>,
    pub fully_declared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterialDeclarationResolution {
    pub materials_by_task: HashMap<TaskId, ConstructMaterialDeclarations>,
    pub fully_declared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionIdentityResolution {
    pub identities_by_task: HashMap<TaskId, Vec<ResolvedActionIdentity>>,
    pub fully_declared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedActionIdentity {
    pub plugin_address: String,
    pub plugin_version: String,
    pub action_key: String,
    pub action_version: String,
}

/// Resolve, for each task, the union of permissions implied by the
/// Constructs that task declares it invokes.
///
/// **Pre:** every entry in `tasks` is a `(task_id, task.constructs)` pair
/// where each construct declaration is the
/// HEADLESS-PREFLIGHT-LAYER1-PHASE2-A-SCHEMA shape
/// `"<construct>.<action>"` (e.g. `"ember-gh.pr_merge"`,
/// `"ember-kubectl.apply"`). `registry` maps a manifest's `[meta] name`
/// (e.g. `"ember-gh"`) to its parsed [`ConstructManifest`].
///
/// **Post:** the returned map has one entry per task in `tasks` (even
/// when the task declares no constructs — value is an empty `Vec`).
/// For each declaration the resolver finds in the registry, the returned
/// `Vec<Permission>` carries one [`Permission`] with `identifier` set to
/// the verbatim declaration. Declarations whose construct is not in the
/// registry, or whose action key is not declared in the manifest, are
/// skipped without error — pre-flight is a best-effort predictive layer.
///
/// Action-key matching tries two shapes for backwards compatibility with
/// the two action-key conventions in the cohort-A bundled manifests:
///   1. The suffix verbatim (`pr_merge` matches `gh.toml`'s
///      `key = "pr_merge"`).
///   2. The construct's short-name prepended (`apply` matches
///      `kubectl.toml`'s `key = "kubectl.apply"` when the construct is
///      `ember-kubectl`).
pub fn resolve_queued_task_permissions(
    tasks: &[(TaskId, Vec<String>)],
    registry: &HashMap<String, ConstructManifest>,
) -> HashMap<TaskId, Vec<Permission>> {
    let mut out = HashMap::with_capacity(tasks.len());
    for (task_id, declarations) in tasks {
        let mut perms = Vec::new();
        for decl in declarations {
            let Some((construct_name, action_suffix)) = decl.split_once('.') else {
                // Malformed declaration (no `.` separator) — skip silently.
                continue;
            };
            let Some(manifest) = lookup(registry, construct_name) else {
                // Unknown construct — Layer 2 will surface the gap at runtime.
                continue;
            };
            if action_key_present(manifest, action_suffix) {
                perms.push(Permission {
                    identifier: decl.clone(),
                    scope: None,
                });
            }
        }
        out.insert(task_id.clone(), perms);
    }
    out
}

/// Resolve, for each task, the manifest-declared authority families its
/// declared Constructs consume.
///
/// Unlike [`resolve_queued_task_permissions`], this resolver is strict about
/// declaration completeness: malformed entries, unknown Constructs, unknown
/// actions, or matched actions with no declared authority refs all flip
/// `fully_declared` to `false`. The returned refs remain useful as a partial
/// narrowing hint, but callers must preserve a broader fail-safe posture when
/// completeness is false.
pub fn resolve_queued_task_authority_refs(
    tasks: &[(TaskId, Vec<String>)],
    registry: &HashMap<String, ConstructManifest>,
) -> AuthorityRefResolution {
    let mut out = HashMap::with_capacity(tasks.len());
    let mut fully_declared = true;
    for (task_id, declarations) in tasks {
        let mut refs = std::collections::BTreeSet::new();
        for decl in declarations {
            let Some((construct_name, action_suffix)) = decl.split_once('.') else {
                fully_declared = false;
                continue;
            };
            let Some(manifest) = lookup(registry, construct_name) else {
                fully_declared = false;
                continue;
            };
            let Some(action_refs) = action_authority_refs(manifest, action_suffix) else {
                fully_declared = false;
                continue;
            };
            refs.extend(action_refs);
        }
        out.insert(task_id.clone(), refs.into_iter().collect());
    }
    AuthorityRefResolution {
        refs_by_task: out,
        fully_declared,
    }
}

/// Resolve, for each task, the manifest-declared unattended/headless runtime
/// requirements its declared Constructs carry.
///
/// This is intentionally manifest-scoped for the first slice because current
/// bundled uses are construct-wide posture claims such as "this queue is only
/// canonically unattended when a runtime KMS-backed secrets-provider lane is
/// live."
pub fn resolve_queued_task_headless_requirements(
    tasks: &[(TaskId, Vec<String>)],
    registry: &HashMap<String, ConstructManifest>,
) -> HeadlessRequirementResolution {
    let mut out = HashMap::with_capacity(tasks.len());
    let mut fully_declared = true;
    for (task_id, declarations) in tasks {
        let mut requirements = std::collections::BTreeSet::new();
        for decl in declarations {
            let Some((construct_name, action_suffix)) = decl.split_once('.') else {
                fully_declared = false;
                continue;
            };
            let Some(manifest) = lookup(registry, construct_name) else {
                fully_declared = false;
                continue;
            };
            if !action_key_present(manifest, action_suffix) {
                fully_declared = false;
                continue;
            }
            requirements.extend(manifest.headless_requirements.iter().cloned());
        }
        out.insert(task_id.clone(), requirements.into_iter().collect());
    }
    HeadlessRequirementResolution {
        requirements_by_task: out,
        fully_declared,
    }
}

pub fn resolve_queued_task_material_declarations(
    tasks: &[(TaskId, Vec<String>)],
    registry: &HashMap<String, ConstructManifest>,
) -> MaterialDeclarationResolution {
    let mut out = HashMap::with_capacity(tasks.len());
    let mut fully_declared = true;
    for (task_id, declarations) in tasks {
        let mut materials = ConstructMaterialDeclarations::default();
        for decl in declarations {
            let Some((construct_name, action_suffix)) = decl.split_once('.') else {
                fully_declared = false;
                continue;
            };
            let Some(manifest) = lookup(registry, construct_name) else {
                fully_declared = false;
                continue;
            };
            let Some(action) = action_entry(manifest, action_suffix) else {
                fully_declared = false;
                continue;
            };
            let resolved = resolved_material(manifest, action);
            if manifest
                .headless_requirements
                .iter()
                .any(|requirement| requirement == "env_passthrough_authority")
                && resolved.is_empty()
            {
                fully_declared = false;
                continue;
            }
            extend_unique(&mut materials.vault_paths, resolved.vault_paths);
            extend_unique(&mut materials.env_passthrough, resolved.env_passthrough);
            extend_unique(&mut materials.file_env, resolved.file_env);
        }
        out.insert(task_id.clone(), materials);
    }
    MaterialDeclarationResolution {
        materials_by_task: out,
        fully_declared,
    }
}

pub fn resolve_queued_task_action_identities(
    tasks: &[(TaskId, Vec<String>)],
    registry: &HashMap<String, ConstructManifest>,
) -> ActionIdentityResolution {
    let mut out = HashMap::with_capacity(tasks.len());
    let mut fully_declared = true;
    for (task_id, declarations) in tasks {
        let mut identities = Vec::new();
        for decl in declarations {
            let Some((construct_name, action_suffix)) = decl.split_once('.') else {
                fully_declared = false;
                continue;
            };
            let Some(manifest) = lookup(registry, construct_name) else {
                fully_declared = false;
                continue;
            };
            let Some(action) = action_entry(manifest, action_suffix) else {
                fully_declared = false;
                continue;
            };
            let Some(plugin_address) = manifest
                .plugin_address
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                fully_declared = false;
                continue;
            };
            let Some(plugin_version) = manifest.action_plugin_version() else {
                fully_declared = false;
                continue;
            };
            let Some(action_version) = action
                .action_version
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                fully_declared = false;
                continue;
            };
            identities.push(ResolvedActionIdentity {
                plugin_address: plugin_address.to_string(),
                plugin_version: plugin_version.to_string(),
                action_key: action.key.clone(),
                action_version: action_version.to_string(),
            });
        }
        out.insert(task_id.clone(), identities);
    }
    ActionIdentityResolution {
        identities_by_task: out,
        fully_declared,
    }
}

/// True when `action_suffix` resolves to a declared action key in
/// `manifest`, trying the suffix verbatim and the short-name-prepended
/// variant. See [`resolve_queued_task_permissions`] for the convention
/// rationale.
fn action_key_present(manifest: &ConstructManifest, action_suffix: &str) -> bool {
    action_entry(manifest, action_suffix).is_some()
}

fn action_entry<'a>(
    manifest: &'a ConstructManifest,
    action_suffix: &str,
) -> Option<&'a ConstructAction> {
    if let Some(action) = manifest.actions.iter().find(|a| a.key == action_suffix) {
        return Some(action);
    }
    let short = manifest
        .name
        .strip_prefix("ember-")
        .unwrap_or(&manifest.name);
    let prefixed = format!("{short}.{action_suffix}");
    manifest.actions.iter().find(|a| a.key == prefixed)
}

fn action_authority_refs(manifest: &ConstructManifest, action_suffix: &str) -> Option<Vec<String>> {
    let action = action_entry(manifest, action_suffix)?;
    if !action.authority_refs.is_empty() {
        return Some(action.authority_refs.clone());
    }
    Some(manifest.authority_refs.clone())
}

fn resolved_material(
    manifest: &ConstructManifest,
    action: &ConstructAction,
) -> ConstructMaterialDeclarations {
    ConstructMaterialDeclarations {
        vault_paths: if action.delegated_material.vault_paths.is_empty() {
            manifest.delegated_material.vault_paths.clone()
        } else {
            action.delegated_material.vault_paths.clone()
        },
        env_passthrough: if action.delegated_material.env_passthrough.is_empty() {
            manifest.delegated_material.env_passthrough.clone()
        } else {
            action.delegated_material.env_passthrough.clone()
        },
        file_env: if action.delegated_material.file_env.is_empty() {
            manifest.delegated_material.file_env.clone()
        } else {
            action.delegated_material.file_env.clone()
        },
    }
}

fn extend_unique(target: &mut Vec<String>, additions: Vec<String>) {
    for value in additions {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

/// Diff a set of needed permissions against an enrolled persona template,
/// returning the gaps (permissions needed but not in the template's
/// allow-list).
///
/// Implementation is unchanged from Phase 1 — the resolver's output
/// shape is the same; only its content gained substance in Phase 2.
pub fn cross_reference(
    needed: &HashMap<TaskId, Vec<Permission>>,
    template: &Template,
) -> Vec<PermissionGap> {
    let mut gaps = Vec::new();
    for (task_id, perms) in needed {
        for perm in perms {
            if !template.allowed.contains(perm) {
                gaps.push(PermissionGap {
                    task_id: task_id.clone(),
                    permission: perm.clone(),
                });
            }
        }
    }
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::parse_construct_manifest_str;

    const GH_MANIFEST: &str = r#"
[meta]
name = "ember-gh"

authority_refs = ["github"]
env_passthrough = ["GH_TOKEN"]

default = "deny"

[[actions]]
key = "pr_create"

[[actions]]
key = "pr_merge"
"#;

    const KUBECTL_MANIFEST: &str = r#"
[meta]
name = "ember-kubectl"
file_env = ["KUBECONFIG"]

default = "deny"

[[actions]]
key = "kubectl.apply"

[[actions]]
key = "kubectl.delete"
"#;

    const PULUMI_MANIFEST: &str = r#"
[meta]
name = "ember-pulumi"

headless_requirements = ["runtime_kms"]

default = "deny"

[[actions]]
key = "pulumi.up"
"#;

    fn registry_with(manifests: &[&str]) -> HashMap<String, ConstructManifest> {
        let mut r = HashMap::new();
        for s in manifests {
            let m = parse_construct_manifest_str(s).expect("manifest parses");
            r.insert(m.name.clone(), m);
        }
        r
    }

    #[test]
    fn empty_tasks_yields_empty_map() {
        let registry = registry_with(&[GH_MANIFEST]);
        let result = resolve_queued_task_permissions(&[], &registry);
        assert!(result.is_empty());
    }

    #[test]
    fn task_without_constructs_yields_empty_perms() {
        let registry = registry_with(&[GH_MANIFEST]);
        let tasks = vec![("AP-FOO".into(), vec![])];
        let result = resolve_queued_task_permissions(&tasks, &registry);
        assert_eq!(result.len(), 1);
        assert!(result.get("AP-FOO").unwrap().is_empty());
    }

    /// Resolver round-trip — the load-bearing test for Phase 2 slice B.
    ///
    /// Parse a real `construct.toml` shape, register it, declare a task
    /// that references it, and assert the resolver emits a `Permission`
    /// keyed by the declaration verbatim.
    #[test]
    fn resolver_round_trip_bare_action_key() {
        let registry = registry_with(&[GH_MANIFEST]);
        let tasks = vec![("TASK-A".to_string(), vec!["ember-gh.pr_merge".to_string()])];
        let result = resolve_queued_task_permissions(&tasks, &registry);
        let perms = result.get("TASK-A").expect("task entry present");
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0].identifier, "ember-gh.pr_merge");
        assert!(perms[0].scope.is_none());
    }

    /// Round-trip for the kubectl-style tool-prefixed action keys.
    ///
    /// Task brief writes `ember-kubectl.apply`; manifest declares
    /// `kubectl.apply`. The resolver matches via the short-name-prepended
    /// fallback shape.
    #[test]
    fn resolver_round_trip_tool_prefixed_action_key() {
        let registry = registry_with(&[KUBECTL_MANIFEST]);
        let tasks = vec![(
            "TASK-B".to_string(),
            vec!["ember-kubectl.apply".to_string()],
        )];
        let result = resolve_queued_task_permissions(&tasks, &registry);
        let perms = result.get("TASK-B").expect("task entry present");
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0].identifier, "ember-kubectl.apply");
    }

    #[test]
    fn authority_refs_round_trip_manifest_default() {
        let registry = registry_with(&[GH_MANIFEST]);
        let tasks = vec![("TASK-H".to_string(), vec!["ember-gh.pr_merge".to_string()])];
        let resolved = resolve_queued_task_authority_refs(&tasks, &registry);
        assert!(resolved.fully_declared);
        assert_eq!(
            resolved
                .refs_by_task
                .get("TASK-H")
                .cloned()
                .unwrap_or_default(),
            vec!["github".to_string()]
        );
    }

    #[test]
    fn empty_authority_ref_can_still_be_fully_declared() {
        let registry = registry_with(&[KUBECTL_MANIFEST]);
        let tasks = vec![(
            "TASK-I".to_string(),
            vec!["ember-kubectl.apply".to_string()],
        )];
        let resolved = resolve_queued_task_authority_refs(&tasks, &registry);
        assert!(resolved.fully_declared);
        assert!(resolved.refs_by_task.get("TASK-I").unwrap().is_empty());
    }

    #[test]
    fn unknown_construct_marks_authority_resolution_incomplete() {
        let registry = registry_with(&[GH_MANIFEST]);
        let tasks = vec![(
            "TASK-J".to_string(),
            vec!["ember-unknown.do_thing".to_string()],
        )];
        let resolved = resolve_queued_task_authority_refs(&tasks, &registry);
        assert!(!resolved.fully_declared);
        assert!(resolved.refs_by_task.get("TASK-J").unwrap().is_empty());
    }

    #[test]
    fn headless_requirements_round_trip_manifest_default() {
        let registry = registry_with(&[PULUMI_MANIFEST]);
        let tasks = vec![("TASK-K".to_string(), vec!["ember-pulumi.up".to_string()])];
        let resolved = resolve_queued_task_headless_requirements(&tasks, &registry);
        assert!(resolved.fully_declared);
        assert_eq!(
            resolved.requirements_by_task.get("TASK-K"),
            Some(&vec!["runtime_kms".to_string()])
        );
    }

    #[test]
    fn material_declarations_round_trip_manifest_default() {
        let registry = registry_with(&[KUBECTL_MANIFEST]);
        let tasks = vec![(
            "TASK-M".to_string(),
            vec!["ember-kubectl.apply".to_string()],
        )];
        let resolved = resolve_queued_task_material_declarations(&tasks, &registry);
        assert!(resolved.fully_declared);
        assert_eq!(
            resolved.materials_by_task.get("TASK-M"),
            Some(&ConstructMaterialDeclarations {
                vault_paths: Vec::new(),
                env_passthrough: Vec::new(),
                file_env: vec!["KUBECONFIG".to_string()],
            })
        );
    }

    #[test]
    fn action_identity_resolution_returns_structured_identity() {
        let registry = registry_with(&[include_str!(
            "../../../crates/ember-construct/construct/gh.toml"
        )]);
        let tasks = vec![("TASK-N".to_string(), vec!["ember-gh.pr_merge".to_string()])];
        let resolved = resolve_queued_task_action_identities(&tasks, &registry);
        assert!(resolved.fully_declared);
        assert_eq!(
            resolved.identities_by_task.get("TASK-N"),
            Some(&vec![ResolvedActionIdentity {
                plugin_address: "registry.ember.systems/ember-systems/ember-gh".to_string(),
                plugin_version: "0.1.0".to_string(),
                action_key: "pr_merge".to_string(),
                action_version: "v1".to_string(),
            }])
        );
    }

    #[test]
    fn unknown_construct_marks_headless_requirement_resolution_incomplete() {
        let registry = registry_with(&[PULUMI_MANIFEST]);
        let tasks = vec![(
            "TASK-L".to_string(),
            vec!["ember-unknown.do_thing".to_string()],
        )];
        let resolved = resolve_queued_task_headless_requirements(&tasks, &registry);
        assert!(!resolved.fully_declared);
        assert!(
            resolved
                .requirements_by_task
                .get("TASK-L")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn unknown_construct_is_skipped() {
        let registry = registry_with(&[GH_MANIFEST]);
        let tasks = vec![(
            "TASK-C".to_string(),
            vec!["ember-unknown.do_thing".to_string()],
        )];
        let result = resolve_queued_task_permissions(&tasks, &registry);
        assert!(result.get("TASK-C").unwrap().is_empty());
    }

    #[test]
    fn unknown_action_is_skipped() {
        let registry = registry_with(&[GH_MANIFEST]);
        let tasks = vec![(
            "TASK-D".to_string(),
            vec!["ember-gh.unknown_action".to_string()],
        )];
        let result = resolve_queued_task_permissions(&tasks, &registry);
        assert!(result.get("TASK-D").unwrap().is_empty());
    }

    #[test]
    fn malformed_declaration_without_dot_is_skipped() {
        let registry = registry_with(&[GH_MANIFEST]);
        let tasks = vec![("TASK-E".to_string(), vec!["nodothere".to_string()])];
        let result = resolve_queued_task_permissions(&tasks, &registry);
        assert!(result.get("TASK-E").unwrap().is_empty());
    }

    #[test]
    fn multiple_tasks_multiple_constructs() {
        let registry = registry_with(&[GH_MANIFEST, KUBECTL_MANIFEST]);
        let tasks = vec![
            (
                "TASK-F".to_string(),
                vec![
                    "ember-gh.pr_create".to_string(),
                    "ember-kubectl.apply".to_string(),
                ],
            ),
            ("TASK-G".to_string(), vec!["ember-gh.pr_merge".to_string()]),
        ];
        let result = resolve_queued_task_permissions(&tasks, &registry);
        assert_eq!(result.len(), 2);
        assert_eq!(result.get("TASK-F").unwrap().len(), 2);
        assert_eq!(result.get("TASK-G").unwrap().len(), 1);
    }

    #[test]
    fn cross_reference_empty_input_yields_no_gaps() {
        let template = Template::default();
        let gaps = cross_reference(&HashMap::new(), &template);
        assert!(gaps.is_empty());
    }

    #[test]
    fn cross_reference_detects_missing_permission() {
        let template = Template {
            allowed: vec![Permission {
                identifier: "ember-gh.pr_create".into(),
                scope: None,
            }],
        };
        let needed = HashMap::from([(
            "TASK-X".into(),
            vec![Permission {
                identifier: "ember-gh.pr_merge".into(),
                scope: None,
            }],
        )]);
        let gaps = cross_reference(&needed, &template);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].task_id, "TASK-X");
        assert_eq!(gaps[0].permission.identifier, "ember-gh.pr_merge");
    }

    #[test]
    fn cross_reference_finds_present_permission_no_gap() {
        let permission = Permission {
            identifier: "ember-kubectl.apply".into(),
            scope: Some("staging/*".into()),
        };
        let template = Template {
            allowed: vec![permission.clone()],
        };
        let needed = HashMap::from([("TASK-Y".into(), vec![permission])]);
        let gaps = cross_reference(&needed, &template);
        assert!(gaps.is_empty(), "exact match → no gap");
    }

    #[test]
    fn permission_equality_includes_scope() {
        let a = Permission {
            identifier: "x".into(),
            scope: Some("a/*".into()),
        };
        let b = Permission {
            identifier: "x".into(),
            scope: Some("b/*".into()),
        };
        assert_ne!(a, b, "different scope → different permission");
    }

    /// End-to-end: parse manifest → register → resolve → cross-reference
    /// against an empty template → gap reported.
    #[test]
    fn resolver_to_cross_reference_pipeline() {
        let registry = registry_with(&[GH_MANIFEST]);
        let tasks = vec![(
            "TASK-PIPELINE".to_string(),
            vec!["ember-gh.pr_merge".to_string()],
        )];
        let needed = resolve_queued_task_permissions(&tasks, &registry);
        let template = Template::default();
        let gaps = cross_reference(&needed, &template);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].task_id, "TASK-PIPELINE");
        assert_eq!(gaps[0].permission.identifier, "ember-gh.pr_merge");
    }
}
