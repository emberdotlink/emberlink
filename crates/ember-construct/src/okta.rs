//! Argv classifier: maps `okta <resource> <verb> ...` to a `construct.toml`
//! action_key. Per ADR 124 §3 — this lives shim-side BUT the daemon
//! re-classifies the argv server-side (untrusts the shim).
//!
//! Okta admin CLI argv shape:
//!
//! ```text
//! okta [global-flags...] <resource> <verb> [verb-args...]
//! ```
//!
//! Global flags (`--profile`, `--config`, `--output`, `--verbose`,
//! `--quiet`, `--token`) may appear before, between, or after the
//! resource/verb tokens. We strip them — including their values for the
//! flags that take one — before pattern-matching, so classification is
//! stable under flag reordering.
//!
//! Coverage (mutating verbs are gated; read-only verbs passthrough as `None`):
//!
//! | argv prefix                                              | action_key                     |
//! |----------------------------------------------------------|--------------------------------|
//! | `users {create,delete,deactivate,suspend,update,reset-password}` | `okta.users.<verb>`     |
//! | `groups {create,delete,add-user,remove-user,update}`     | `okta.groups.<verb>`           |
//! | `apps {create,delete,deactivate,update,assign-user,unassign-user,assign-group,unassign-group}` | `okta.apps.<verb>` |
//! | `policies {create,delete,update,deactivate}`             | `okta.policies.<verb>`         |
//! | `factors {enroll,reset,deactivate}`                      | `okta.factors.<verb>`          |
//! | `idps {create,delete,deactivate,update}`                 | `okta.idps.<verb>`             |
//! | `zones {create,delete,update}`                           | `okta.zones.<verb>`            |
//! | `session end`                                            | `okta.session.end`             |
//! | `system-log export`                                      | `okta.system-log.export`       |
//! | `<any> {list,get,describe}`                              | `None` (passthrough)           |

use core_construct_runtime::ActionKey;
use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};

/// Okta CLI global flags that take a value as the *next* argv token.
/// When stripping, both the flag and its value are removed.
const VALUE_BEARING_GLOBAL_FLAGS: &[&str] = &["--profile", "--config", "--output", "--token"];

/// Okta CLI global flags that are valueless (boolean toggles).
const BOOLEAN_GLOBAL_FLAGS: &[&str] = &["--verbose", "--quiet"];

/// Strip global flags (and their values, where applicable) from `argv`.
///
/// Recognizes both `--flag value` and `--flag=value` forms for the
/// value-bearing flags, plus the boolean toggles in
/// [`BOOLEAN_GLOBAL_FLAGS`]. Non-flag tokens and unknown flags pass
/// through unchanged (the daemon re-classifies anyway).
pub(crate) fn strip_global_flags(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];

        // `--flag=value` form — drop in one step regardless of whether
        // it's a value-bearing or boolean global flag (boolean flags
        // shouldn't have `=value` but accept it tolerantly).
        if let Some(eq) = tok.find('=') {
            let name = &tok[..eq];
            if VALUE_BEARING_GLOBAL_FLAGS.contains(&name) || BOOLEAN_GLOBAL_FLAGS.contains(&name) {
                i += 1;
                continue;
            }
        }

        // `--flag value` form for value-bearing globals.
        if VALUE_BEARING_GLOBAL_FLAGS.contains(&tok.as_str()) {
            // Skip the flag and (if present) its value.
            i += 1;
            if i < argv.len() {
                i += 1;
            }
            continue;
        }

        // Boolean global flags — skip just the flag itself.
        if BOOLEAN_GLOBAL_FLAGS.contains(&tok.as_str()) {
            i += 1;
            continue;
        }

        out.push(tok.clone());
        i += 1;
    }
    out
}

/// Returns `true` if `verb` looks like a read-only Okta CLI verb.
///
/// Read-only verbs include `list`, `get`, `describe`, plus the help
/// shape.
fn is_read_only_verb(verb: &str) -> bool {
    matches!(verb, "list" | "get" | "describe" | "help")
}

/// Classify `okta <resource> <verb> ...` argv into an action_key.
///
/// Returns `None` for read-only / unrecognized shapes — the runtime
/// treats `None` as passthrough (no broker mediation).
pub fn classify_okta_argv(argv: &[String]) -> Option<ActionKey> {
    let stripped = strip_global_flags(argv);

    let resource = stripped.first()?.as_str();
    let verb = stripped.get(1).map(|s| s.as_str())?;

    // Read-only verbs always passthrough, regardless of resource.
    if is_read_only_verb(verb) {
        return None;
    }

    match resource {
        // users <verb>
        "users" => match verb {
            "create" | "delete" | "deactivate" | "suspend" | "update" | "reset-password" => {
                Some(ActionKey(format!("okta.users.{verb}")))
            }
            _ => None,
        },

        // groups <verb>
        "groups" => match verb {
            "create" | "delete" | "add-user" | "remove-user" | "update" => {
                Some(ActionKey(format!("okta.groups.{verb}")))
            }
            _ => None,
        },

        // apps <verb>
        "apps" => match verb {
            "create" | "delete" | "deactivate" | "update" | "assign-user" | "unassign-user"
            | "assign-group" | "unassign-group" => Some(ActionKey(format!("okta.apps.{verb}"))),
            _ => None,
        },

        // policies <verb>
        "policies" => match verb {
            "create" | "delete" | "update" | "deactivate" => {
                Some(ActionKey(format!("okta.policies.{verb}")))
            }
            _ => None,
        },

        // factors <verb>
        "factors" => match verb {
            "enroll" | "reset" | "deactivate" => Some(ActionKey(format!("okta.factors.{verb}"))),
            _ => None,
        },

        // idps <verb>
        "idps" => match verb {
            "create" | "delete" | "deactivate" | "update" => {
                Some(ActionKey(format!("okta.idps.{verb}")))
            }
            _ => None,
        },

        // zones <verb>
        "zones" => match verb {
            "create" | "delete" | "update" => Some(ActionKey(format!("okta.zones.{verb}"))),
            _ => None,
        },

        // session <verb> — only `end` is classified.
        "session" => match verb {
            "end" => Some(ActionKey("okta.session.end".to_string())),
            _ => None,
        },

        // system-log <verb> — only `export` is classified (auditable read).
        "system-log" => match verb {
            "export" => Some(ActionKey("okta.system-log.export".to_string())),
            _ => None,
        },

        // Unknown resource → passthrough; daemon re-classifies.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// OktaFactory — P24 construct-factory contract for the okta construct
// ---------------------------------------------------------------------------

/// Parsed okta.toml action manifest, initialised once at first access.
static OKTA_MANIFEST: std::sync::LazyLock<core_events::construct_toml::ParsedActionManifest> =
    std::sync::LazyLock::new(|| {
        core_events::construct_toml::parse_action_manifest(include_str!("../construct/okta.toml"))
            .expect("bundled okta.toml must be valid")
    });

/// Look up the `need` atoms for an action key from the bundled manifest.
/// Returns `None` if the action is absent from the manifest or has an empty
/// `need` list.
fn manifest_need_for_action(action_key: &str) -> Option<Vec<String>> {
    OKTA_MANIFEST
        .manifest
        .actions
        .iter()
        .find(|a| a.key == action_key)
        .and_then(|a| {
            let need = &a.need;
            if need.is_empty() {
                None
            } else {
                Some(need.clone())
            }
        })
}

/// Returns `true` when `action_key` has an entry in the bundled manifest
/// (regardless of whether it carries a `need`).
fn action_in_manifest(action_key: &str) -> bool {
    OKTA_MANIFEST
        .manifest
        .actions
        .iter()
        .any(|a| a.key == action_key)
}

/// P24 factory implementation for the `okta` construct.
#[derive(Debug, Default, Clone)]
pub struct OktaFactory;

/// Provider-specific target extracted from an `okta` argv invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OktaFactoryTarget {
    pub provider: &'static str,
    pub org_url: Option<String>,
    pub resource_id: Option<String>,
}

/// Need atoms derived from the bundled manifest for one `okta` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OktaFactoryNeed(pub Vec<String>);

/// Extract `--org-url <value>` or `--org-url=<value>` from raw argv.
fn extract_org_url(argv: &[String]) -> Option<String> {
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];
        if let Some(value) = tok.strip_prefix("--org-url=")
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
        if tok == "--org-url"
            && let Some(value) = argv.get(i + 1)
            && !value.starts_with('-')
        {
            return Some(value.clone());
        }
        i += 1;
    }
    None
}

/// Returns `true` if raw argv contains `--profile`, `-p`, `--token`, or `-t`.
///
/// These flags select credential source or material directly, which is outside
/// the factory mediation contract.
fn has_credential_source_flag(argv: &[String]) -> bool {
    for tok in argv {
        // Exact matches for the flag tokens.
        if tok == "--profile" || tok == "-p" || tok == "--token" || tok == "-t" {
            return true;
        }
        // `--flag=value` form.
        if tok.starts_with("--profile=") || tok.starts_with("--token=") {
            return true;
        }
    }
    false
}

/// Returns `true` if the raw argv contains the `login` resource (before flag
/// stripping), indicating an interactive credential-source mutation.
fn has_login_verb(argv: &[String]) -> bool {
    let stripped = strip_global_flags(argv);
    stripped.first().map(|s| s.as_str()) == Some("login")
}

/// Returns `true` if the argv contains a `--file` flag in combination with a
/// `policies` verb, indicating authority-bearing policy payload.
fn has_policy_file_arg(argv: &[String]) -> bool {
    let stripped = strip_global_flags(argv);
    let is_policies = stripped.first().map(|s| s.as_str()) == Some("policies");
    if !is_policies {
        return false;
    }
    argv.iter()
        .any(|tok| tok == "--file" || tok.starts_with("--file="))
}

impl InvocationGrammar for OktaFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_okta_argv(argv)
    }
}

impl TargetExtractor for OktaFactory {
    type Target = OktaFactoryTarget;

    fn target_for_argv(&self, _action_key: &ActionKey, argv: &[String]) -> Option<Self::Target> {
        let org_url = extract_org_url(argv);

        // Extract the first non-flag positional after the resource+verb as a
        // resource identifier (user email, group id, etc.).
        let stripped = strip_global_flags(argv);
        let resource_id = stripped
            .get(2..)
            .unwrap_or_default()
            .iter()
            .find(|tok| !tok.starts_with('-'))
            .cloned();

        Some(OktaFactoryTarget {
            provider: "okta",
            org_url,
            resource_id,
        })
    }
}

impl NeedTemplate for OktaFactory {
    type Need = OktaFactoryNeed;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        _target: &Self::Target,
        _argv: &[String],
    ) -> Option<Self::Need> {
        manifest_need_for_action(&action_key.0).map(OktaFactoryNeed)
    }
}

impl ConstructFactory for OktaFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> FactoryDisposition {
        // Credential-source flags bypass the factory entirely — fail closed.
        // Checked before action_key gate because these flags are dangerous
        // regardless of whether the verb itself classified.
        if has_credential_source_flag(argv) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // `okta login` is a credential-source mutation — fail closed.
        // The classifier does not produce an action key for `login`, so
        // this must be checked before the None-key branch.
        if has_login_verb(argv) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // No action key → reads, version, --version, help — no credentials.
        let Some(key) = action_key else {
            return FactoryDisposition::Credentialless;
        };

        // Policy file args carry authority-bearing payloads.
        if has_policy_file_arg(argv) {
            return FactoryDisposition::PayloadAnalysisRequired;
        }

        // Action not in manifest → not declared, fail closed.
        if !action_in_manifest(&key.0) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // Action is in the manifest. Org/profile must still be resolved from
        // the local okta config, so we need a resolver.
        FactoryDisposition::ResolverRequired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // --- users ---

    #[test]
    fn users_create_classified() {
        let r = classify_okta_argv(&args(&["users", "create", "--email", "u@x"])).unwrap();
        assert_eq!(r.0, "okta.users.create");
    }

    #[test]
    fn users_delete_classified() {
        let r = classify_okta_argv(&args(&["users", "delete", "uid"])).unwrap();
        assert_eq!(r.0, "okta.users.delete");
    }

    #[test]
    fn users_deactivate_classified() {
        let r = classify_okta_argv(&args(&["users", "deactivate", "uid"])).unwrap();
        assert_eq!(r.0, "okta.users.deactivate");
    }

    #[test]
    fn users_suspend_classified() {
        let r = classify_okta_argv(&args(&["users", "suspend", "uid"])).unwrap();
        assert_eq!(r.0, "okta.users.suspend");
    }

    #[test]
    fn users_update_classified() {
        let r = classify_okta_argv(&args(&["users", "update", "uid"])).unwrap();
        assert_eq!(r.0, "okta.users.update");
    }

    #[test]
    fn users_reset_password_classified() {
        let r = classify_okta_argv(&args(&["users", "reset-password", "uid"])).unwrap();
        assert_eq!(r.0, "okta.users.reset-password");
    }

    #[test]
    fn users_get_passthrough() {
        assert!(classify_okta_argv(&args(&["users", "get", "uid"])).is_none());
    }

    // --- groups ---

    #[test]
    fn groups_create_classified() {
        let r = classify_okta_argv(&args(&["groups", "create", "g"])).unwrap();
        assert_eq!(r.0, "okta.groups.create");
    }

    #[test]
    fn groups_delete_classified() {
        let r = classify_okta_argv(&args(&["groups", "delete", "gid"])).unwrap();
        assert_eq!(r.0, "okta.groups.delete");
    }

    #[test]
    fn groups_add_user_classified() {
        let r = classify_okta_argv(&args(&["groups", "add-user", "gid", "uid"])).unwrap();
        assert_eq!(r.0, "okta.groups.add-user");
    }

    #[test]
    fn groups_remove_user_classified() {
        let r = classify_okta_argv(&args(&["groups", "remove-user", "gid", "uid"])).unwrap();
        assert_eq!(r.0, "okta.groups.remove-user");
    }

    #[test]
    fn groups_update_classified() {
        let r = classify_okta_argv(&args(&["groups", "update", "gid"])).unwrap();
        assert_eq!(r.0, "okta.groups.update");
    }

    #[test]
    fn groups_list_passthrough() {
        assert!(classify_okta_argv(&args(&["groups", "list"])).is_none());
    }

    // --- apps ---

    #[test]
    fn apps_create_classified() {
        let r = classify_okta_argv(&args(&["apps", "create"])).unwrap();
        assert_eq!(r.0, "okta.apps.create");
    }

    #[test]
    fn apps_delete_classified() {
        let r = classify_okta_argv(&args(&["apps", "delete", "aid"])).unwrap();
        assert_eq!(r.0, "okta.apps.delete");
    }

    #[test]
    fn apps_deactivate_classified() {
        let r = classify_okta_argv(&args(&["apps", "deactivate", "aid"])).unwrap();
        assert_eq!(r.0, "okta.apps.deactivate");
    }

    #[test]
    fn apps_update_classified() {
        let r = classify_okta_argv(&args(&["apps", "update", "aid"])).unwrap();
        assert_eq!(r.0, "okta.apps.update");
    }

    #[test]
    fn apps_assign_user_classified() {
        let r = classify_okta_argv(&args(&["apps", "assign-user", "aid", "uid"])).unwrap();
        assert_eq!(r.0, "okta.apps.assign-user");
    }

    #[test]
    fn apps_unassign_user_classified() {
        let r = classify_okta_argv(&args(&["apps", "unassign-user", "aid", "uid"])).unwrap();
        assert_eq!(r.0, "okta.apps.unassign-user");
    }

    #[test]
    fn apps_assign_group_classified() {
        let r = classify_okta_argv(&args(&["apps", "assign-group", "aid", "gid"])).unwrap();
        assert_eq!(r.0, "okta.apps.assign-group");
    }

    #[test]
    fn apps_unassign_group_classified() {
        let r = classify_okta_argv(&args(&["apps", "unassign-group", "aid", "gid"])).unwrap();
        assert_eq!(r.0, "okta.apps.unassign-group");
    }

    #[test]
    fn apps_list_passthrough() {
        assert!(classify_okta_argv(&args(&["apps", "list"])).is_none());
    }

    // --- policies ---

    #[test]
    fn policies_create_classified() {
        let r = classify_okta_argv(&args(&["policies", "create"])).unwrap();
        assert_eq!(r.0, "okta.policies.create");
    }

    #[test]
    fn policies_delete_classified() {
        let r = classify_okta_argv(&args(&["policies", "delete", "pid"])).unwrap();
        assert_eq!(r.0, "okta.policies.delete");
    }

    #[test]
    fn policies_update_classified() {
        let r = classify_okta_argv(&args(&["policies", "update", "pid"])).unwrap();
        assert_eq!(r.0, "okta.policies.update");
    }

    #[test]
    fn policies_deactivate_classified() {
        let r = classify_okta_argv(&args(&["policies", "deactivate", "pid"])).unwrap();
        assert_eq!(r.0, "okta.policies.deactivate");
    }

    #[test]
    fn policies_list_passthrough() {
        assert!(classify_okta_argv(&args(&["policies", "list"])).is_none());
    }

    // --- factors ---

    #[test]
    fn factors_enroll_classified() {
        let r = classify_okta_argv(&args(&["factors", "enroll", "uid"])).unwrap();
        assert_eq!(r.0, "okta.factors.enroll");
    }

    #[test]
    fn factors_reset_classified() {
        let r = classify_okta_argv(&args(&["factors", "reset", "uid"])).unwrap();
        assert_eq!(r.0, "okta.factors.reset");
    }

    #[test]
    fn factors_deactivate_classified() {
        let r = classify_okta_argv(&args(&["factors", "deactivate", "uid", "fid"])).unwrap();
        assert_eq!(r.0, "okta.factors.deactivate");
    }

    #[test]
    fn factors_list_passthrough() {
        assert!(classify_okta_argv(&args(&["factors", "list"])).is_none());
    }

    // --- idps ---

    #[test]
    fn idps_create_classified() {
        let r = classify_okta_argv(&args(&["idps", "create"])).unwrap();
        assert_eq!(r.0, "okta.idps.create");
    }

    #[test]
    fn idps_delete_classified() {
        let r = classify_okta_argv(&args(&["idps", "delete", "iid"])).unwrap();
        assert_eq!(r.0, "okta.idps.delete");
    }

    #[test]
    fn idps_deactivate_classified() {
        let r = classify_okta_argv(&args(&["idps", "deactivate", "iid"])).unwrap();
        assert_eq!(r.0, "okta.idps.deactivate");
    }

    #[test]
    fn idps_update_classified() {
        let r = classify_okta_argv(&args(&["idps", "update", "iid"])).unwrap();
        assert_eq!(r.0, "okta.idps.update");
    }

    // --- zones ---

    #[test]
    fn zones_create_classified() {
        let r = classify_okta_argv(&args(&["zones", "create"])).unwrap();
        assert_eq!(r.0, "okta.zones.create");
    }

    #[test]
    fn zones_delete_classified() {
        let r = classify_okta_argv(&args(&["zones", "delete", "zid"])).unwrap();
        assert_eq!(r.0, "okta.zones.delete");
    }

    #[test]
    fn zones_update_classified() {
        let r = classify_okta_argv(&args(&["zones", "update", "zid"])).unwrap();
        assert_eq!(r.0, "okta.zones.update");
    }

    // --- session ---

    #[test]
    fn session_end_classified() {
        let r = classify_okta_argv(&args(&["session", "end", "sid"])).unwrap();
        assert_eq!(r.0, "okta.session.end");
    }

    #[test]
    fn session_other_passthrough() {
        assert!(classify_okta_argv(&args(&["session", "create"])).is_none());
    }

    // --- system-log ---

    #[test]
    fn system_log_export_classified() {
        let r = classify_okta_argv(&args(&["system-log", "export"])).unwrap();
        assert_eq!(r.0, "okta.system-log.export");
    }

    #[test]
    fn system_log_list_passthrough() {
        assert!(classify_okta_argv(&args(&["system-log", "list"])).is_none());
    }

    // --- read-only verbs across resources ---

    #[test]
    fn apps_get_passthrough() {
        assert!(classify_okta_argv(&args(&["apps", "get", "aid"])).is_none());
    }

    #[test]
    fn groups_get_passthrough() {
        assert!(classify_okta_argv(&args(&["groups", "get", "gid"])).is_none());
    }

    #[test]
    fn policies_describe_passthrough() {
        assert!(classify_okta_argv(&args(&["policies", "describe", "pid"])).is_none());
    }

    #[test]
    fn factors_list_at_resource_passthrough() {
        assert!(classify_okta_argv(&args(&["factors", "list"])).is_none());
    }

    // --- global flag stripping ---

    #[test]
    fn profile_flag_before_resource_stripped() {
        let r =
            classify_okta_argv(&args(&["--profile", "prod", "users", "delete", "uid"])).unwrap();
        assert_eq!(r.0, "okta.users.delete");
    }

    #[test]
    fn config_flag_between_resource_and_verb_stripped() {
        let r = classify_okta_argv(&args(&[
            "users",
            "--config",
            "/etc/okta.toml",
            "delete",
            "uid",
        ]))
        .unwrap();
        assert_eq!(r.0, "okta.users.delete");
    }

    #[test]
    fn token_flag_after_verb_stripped() {
        let r =
            classify_okta_argv(&args(&["apps", "delete", "--token", "00aBcDeF", "aid"])).unwrap();
        assert_eq!(r.0, "okta.apps.delete");
    }

    #[test]
    fn output_flag_stripped() {
        let r =
            classify_okta_argv(&args(&["--output", "json", "groups", "delete", "gid"])).unwrap();
        assert_eq!(r.0, "okta.groups.delete");
    }

    #[test]
    fn verbose_boolean_flag_stripped() {
        let r = classify_okta_argv(&args(&["--verbose", "users", "suspend", "uid"])).unwrap();
        assert_eq!(r.0, "okta.users.suspend");
    }

    #[test]
    fn quiet_boolean_flag_stripped() {
        let r = classify_okta_argv(&args(&["--quiet", "policies", "delete", "pid"])).unwrap();
        assert_eq!(r.0, "okta.policies.delete");
    }

    #[test]
    fn equals_form_profile_flag_stripped() {
        let r = classify_okta_argv(&args(&["--profile=prod", "users", "delete", "uid"])).unwrap();
        assert_eq!(r.0, "okta.users.delete");
    }

    #[test]
    fn equals_form_token_flag_stripped() {
        let r = classify_okta_argv(&args(&["--token=00secret", "session", "end", "sid"])).unwrap();
        assert_eq!(r.0, "okta.session.end");
    }

    #[test]
    fn equals_form_config_flag_stripped() {
        let r =
            classify_okta_argv(&args(&["factors", "--config=/x.toml", "reset", "uid"])).unwrap();
        assert_eq!(r.0, "okta.factors.reset");
    }

    #[test]
    fn multiple_global_flags_stripped() {
        let r = classify_okta_argv(&args(&[
            "--profile",
            "prod",
            "--token",
            "00secret",
            "--verbose",
            "--output",
            "json",
            "idps",
            "delete",
            "iid",
        ]))
        .unwrap();
        assert_eq!(r.0, "okta.idps.delete");
    }

    #[test]
    fn flags_reordered_classification_stable() {
        let a =
            classify_okta_argv(&args(&["users", "delete", "uid", "--profile", "prod"])).unwrap();
        let b =
            classify_okta_argv(&args(&["--profile", "prod", "users", "delete", "uid"])).unwrap();
        let c =
            classify_okta_argv(&args(&["users", "--profile", "prod", "delete", "uid"])).unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(b.0, c.0);
    }

    // --- unknown / empty / corner cases ---

    #[test]
    fn empty_argv_passthrough() {
        assert!(classify_okta_argv(&[]).is_none());
    }

    #[test]
    fn only_global_flags_passthrough() {
        assert!(classify_okta_argv(&args(&["--profile", "prod", "--verbose"])).is_none());
    }

    #[test]
    fn unknown_resource_passthrough() {
        assert!(classify_okta_argv(&args(&["roles", "create"])).is_none());
    }

    #[test]
    fn resource_without_verb_passthrough() {
        assert!(classify_okta_argv(&args(&["users"])).is_none());
    }

    #[test]
    fn users_unknown_verb_passthrough() {
        assert!(classify_okta_argv(&args(&["users", "fizz"])).is_none());
    }

    #[test]
    fn apps_unknown_verb_passthrough() {
        assert!(classify_okta_argv(&args(&["apps", "rename"])).is_none());
    }

    // --- proptest: argv fuzzer; no panics; flag-insertion preserves classification ---

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 256,
            ..proptest::test_runner::Config::default()
        })]

        /// Fuzz arbitrary argv shapes — must never panic.
        #[test]
        fn fuzz_classify_no_panic(
            argv in proptest::collection::vec("[a-zA-Z0-9_:.-]{0,16}", 0..8usize)
        ) {
            // We only care that no panic escapes.
            let _ = classify_okta_argv(&argv);
        }

        /// Inserting a recognized value-bearing global flag (with value)
        /// into a known-classified argv must not change the classification.
        #[test]
        fn fuzz_profile_flag_insertion_stable(
            insert_at in 0usize..6,
            profile in "[a-z][a-z0-9-]{0,15}"
        ) {
            let base = vec![
                "users".to_string(),
                "delete".to_string(),
                "uid".to_string(),
            ];
            let base_class = classify_okta_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, profile.clone());
            with_flag.insert(pos, "--profile".to_string());

            let class2 = classify_okta_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }

        /// Inserting a boolean global flag at any position into a known
        /// classified argv must not change the classification.
        #[test]
        fn fuzz_boolean_flag_insertion_stable(insert_at in 0usize..6) {
            let base = vec![
                "policies".to_string(),
                "delete".to_string(),
                "pid".to_string(),
            ];
            let base_class = classify_okta_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, "--verbose".to_string());

            let class2 = classify_okta_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }
    }

    // --- T2: integration with MockBroker for BrokerProvider::Okta ---
    //
    // The full broker_exec lifecycle lives in the daemon; here we cover the
    // contract slice this Construct depends on: the broker registry can
    // hold a `MockBroker::new(BrokerProvider::Okta)`, and a request that
    // declares `provider = Okta` round-trips through issue → revoke
    // without panicking. Real Okta broker impl is BROKER-OKTA-IMPL
    // (separate task).

    use core_broker::{Broker, BrokerError, BrokerProvider, BrokerRequest, MockBroker};
    use std::time::Duration;

    fn okta_request(ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::Okta,
            scope: serde_json::json!({
                "org": "ember-systems",
                "scopes": ["okta.users.manage", "okta.groups.manage"],
            }),
            ttl: Duration::from_secs(ttl_secs),
            contract_id: None,
            action_ref: None,
            workspace_ref: None,
            subject_ref: None,
            coordination_ref: None,
            caller_ref: None,
            authority_ref: None,
            reason: "ember-okta integration test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    #[tokio::test]
    async fn mock_broker_okta_issue_revoke_roundtrip() {
        let broker = MockBroker::new(BrokerProvider::Okta);
        assert_eq!(broker.provider(), BrokerProvider::Okta);

        let creds = broker
            .issue(okta_request(900))
            .await
            .expect("issue should succeed for matching provider");
        assert_eq!(creds.materialization_id, "mock-1");

        broker
            .revoke(&creds.materialization_id)
            .await
            .expect("revoke of issued materialization should succeed");

        assert_eq!(broker.active_count(), 0);
        assert_eq!(broker.revoke_calls(), vec![creds.materialization_id]);
    }

    #[tokio::test]
    async fn mock_broker_okta_rejects_wrong_provider() {
        let broker = MockBroker::new(BrokerProvider::Okta);
        let mut req = okta_request(900);
        req.provider = BrokerProvider::Cloudflare;

        let err = broker.issue(req).await.expect_err("provider mismatch");
        match err {
            BrokerError::InvalidScope(_) => {}
            other => panic!("expected InvalidScope, got {other:?}"),
        }
    }

    #[test]
    fn okta_provider_as_str() {
        assert_eq!(BrokerProvider::Okta.as_str(), "okta");
    }

    // --- OktaFactory tests ---

    #[test]
    fn okta_factory_version_is_credentialless() {
        let f = OktaFactory;
        let a = args(&["--version"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn okta_factory_users_list_is_credentialless() {
        let f = OktaFactory;
        let a = args(&["users", "list"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn okta_factory_users_delete_is_resolver_required() {
        let f = OktaFactory;
        let a = args(&["users", "delete", "alice@example.com"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn okta_factory_profile_flag_is_unsupported() {
        let f = OktaFactory;
        let a = args(&["--profile", "prod", "users", "delete", "alice@example.com"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn okta_factory_short_profile_flag_is_unsupported() {
        let f = OktaFactory;
        let a = args(&["-p", "prod", "users", "delete", "uid"]);
        // -p is not in the long-form global-flag strip list, so the
        // classifier sees "-p" as resource and returns None.  The factory
        // detects the short flag in raw argv and fails closed regardless.
        let key = f.action_key_for_argv(&a);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn okta_factory_token_flag_is_unsupported() {
        let f = OktaFactory;
        let a = args(&["--token", "00secret", "users", "create", "--email", "u@x"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn okta_factory_short_token_flag_is_unsupported() {
        let f = OktaFactory;
        let a = args(&["-t", "00secret", "users", "create", "--email", "u@x"]);
        // -t is not in the long-form global-flag strip list, so the
        // classifier sees "-t" as resource and returns None.  The factory
        // detects the short flag in raw argv and fails closed regardless.
        let key = f.action_key_for_argv(&a);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn okta_factory_login_is_unsupported() {
        let f = OktaFactory;
        let a = args(&["login"]);
        let key = f.action_key_for_argv(&a);
        // login is not classified by the argv classifier, but the factory
        // detects it as a credential-source mutation and fails closed.
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn okta_factory_policy_update_with_file_is_payload_analysis() {
        let f = OktaFactory;
        let a = args(&["policies", "update", "policy-123", "--file", "policy.json"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn okta_factory_policy_create_with_file_equals_is_payload_analysis() {
        let f = OktaFactory;
        let a = args(&["policies", "create", "--file=rules.json"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn okta_factory_groups_create_is_resolver_required() {
        let f = OktaFactory;
        let a = args(&["groups", "create", "admins"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn okta_factory_target_extraction() {
        let f = OktaFactory;
        let a = args(&[
            "users",
            "delete",
            "alice@example.com",
            "--org-url",
            "https://dev-ember.okta.com",
        ]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.provider, "okta");
        assert_eq!(
            target.org_url,
            Some("https://dev-ember.okta.com".to_string())
        );
        assert_eq!(target.resource_id, Some("alice@example.com".to_string()));
    }

    #[test]
    fn okta_factory_target_extraction_org_url_equals() {
        let f = OktaFactory;
        let a = args(&[
            "users",
            "create",
            "--org-url=https://ember.okta.com",
            "--email",
            "u@x",
        ]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.org_url, Some("https://ember.okta.com".to_string()));
    }

    #[test]
    fn okta_factory_target_extraction_no_org_url() {
        let f = OktaFactory;
        let a = args(&["groups", "delete", "gid"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.provider, "okta");
        assert!(target.org_url.is_none());
        assert_eq!(target.resource_id, Some("gid".to_string()));
    }

    #[test]
    fn okta_factory_contract_runs_conformance_corpus() {
        let corpus = core_construct_runtime::factory::parse_factory_fixture_corpus(include_str!(
            "../conformance/okta/factory-fixtures.toml"
        ))
        .expect("fixture TOML parses");
        let errors = core_construct_runtime::factory::validate_factory_fixture_corpus(&corpus);
        assert!(errors.is_empty(), "{errors:#?}");
        let carrier = core_construct_runtime::factory::ActionManifestV2Carrier::parse(
            include_str!("../construct/okta.toml"),
        )
        .expect("valid okta manifest");
        let report = core_construct_runtime::factory::run_factory_fixtures(
            &OktaFactory,
            Some(&carrier),
            &corpus,
        );
        assert!(report.is_clean(), "{:#?}", report.failures);
    }
}
