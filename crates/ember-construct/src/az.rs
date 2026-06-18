//! Argv classifier: maps `az <group> [<subgroup> ...] <verb> [args]` to
//! a `construct.toml` action_key. Per ADR 124 §3 — this lives shim-side BUT
//! the daemon re-classifies the argv server-side (untrusts the shim).
//!
//! Azure CLI argv shape:
//!
//! ```text
//! az [global-flags...] <group> [<subgroup> ...] <verb> [verb-args...]
//! ```
//!
//! Global flags (e.g. `--subscription`, `--resource-group`, `--location`,
//! `--output`, `--query`, `--verbose`, `--debug`) may appear before, between,
//! or after the group/verb tokens. We strip them — including their values
//! for the flags that take one — before pattern-matching, so classification
//! is stable under flag reordering.
//!
//! Coverage (mutating verbs are gated; read-only verbs passthrough as `None`):
//!
//! | argv prefix                                         | action_key                                       |
//! |-----------------------------------------------------|--------------------------------------------------|
//! | `vm {create,delete,deallocate,start,stop,restart}`  | `az.vm.<verb>`                                   |
//! | `vmss {create,delete,scale,update}`                 | `az.vmss.<verb>`                                 |
//! | `storage account {create,delete}`                   | `az.storage.account.<verb>`                      |
//! | `storage blob {delete,upload}`                      | `az.storage.blob.<verb>`                         |
//! | `storage container delete`                          | `az.storage.container.delete`                    |
//! | `keyvault {create,delete}`                          | `az.keyvault.<verb>`                             |
//! | `keyvault key {delete,create,encrypt,decrypt}`      | `az.keyvault.key.<verb>`                         |
//! | `keyvault secret {set,delete,show}`                 | `az.keyvault.secret.<verb>`                      |
//! | `role assignment {create,delete}`                   | `az.role.assignment.<verb>`                      |
//! | `role definition {create,delete}`                   | `az.role.definition.<verb>`                      |
//! | `aks {create,delete,scale,update,get-credentials}`  | `az.aks.<verb>`                                  |
//! | `sql server {create,delete}`                        | `az.sql.server.<verb>`                           |
//! | `sql db {create,delete}`                            | `az.sql.db.<verb>`                               |
//! | `functionapp {create,delete,deploy}`                | `az.functionapp.<verb>`                          |
//! | `webapp {create,delete,deploy}`                     | `az.webapp.<verb>`                               |
//! | `network vnet delete`                               | `az.network.vnet.delete`                         |
//! | `network nsg rule {create,delete}`                  | `az.network.nsg.rule.<verb>`                     |
//! | `group {create,delete}`                             | `az.group.<verb>`                                |
//! | `show \| list \| get-* \| account list \| account show` | `None` (passthrough)                          |

use core_construct_runtime::ActionKey;
use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};

/// Azure CLI global flags that take a value as the *next* argv token.
/// When stripping, both the flag and its value are removed.
const VALUE_BEARING_GLOBAL_FLAGS: &[&str] = &[
    "--subscription",
    "--resource-group",
    "-g",
    "--location",
    "-l",
    "--output",
    "-o",
    "--query",
];

/// Azure CLI global flags that are valueless (boolean toggles).
const BOOLEAN_GLOBAL_FLAGS: &[&str] = &["--verbose", "--debug", "--help", "-h"];

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

/// Returns `true` if `verb` looks like a read-only Azure CLI verb.
///
/// Read-only verbs include `show`, `list`, plus any `get-*` verb shape.
fn is_read_only_verb(verb: &str) -> bool {
    if verb == "show" || verb == "list" || verb == "help" {
        return true;
    }
    if let Some(rest) = verb.strip_prefix("get") {
        // `get` exact match or `get-<something>` (hyphen-separated).
        return rest.is_empty() || rest.starts_with('-');
    }
    false
}

/// Classify `az <group> [<subgroup> ...] <verb> ...` argv into an
/// action_key.
///
/// Returns `None` for read-only / unrecognized shapes — the runtime
/// treats `None` as passthrough (no broker mediation).
pub fn classify_az_argv(argv: &[String]) -> Option<ActionKey> {
    let stripped = strip_global_flags(argv);

    // After stripping global flags, we expect:
    //   <group> [<subgroup> ...] <verb> [args]
    // Length 2 minimum (group + verb).
    if stripped.len() < 2 {
        return None;
    }

    let g0 = stripped.first()?.as_str();
    let g1 = stripped.get(1).map(|s| s.as_str())?;
    let g2 = stripped.get(2).map(|s| s.as_str());
    let g3 = stripped.get(3).map(|s| s.as_str());

    match g0 {
        // vm <verb>
        "vm" => match g1 {
            "create" | "delete" | "deallocate" | "start" | "stop" | "restart" => {
                Some(ActionKey(format!("az.vm.{}", g1)))
            }
            v if is_read_only_verb(v) => None,
            _ => None,
        },

        // vmss <verb>
        "vmss" => match g1 {
            "create" | "delete" | "scale" | "update" => Some(ActionKey(format!("az.vmss.{}", g1))),
            v if is_read_only_verb(v) => None,
            _ => None,
        },

        // storage account <verb> | storage blob <verb> | storage container <verb>
        "storage" => match (g1, g2) {
            ("account", Some(verb)) => match verb {
                "create" | "delete" => Some(ActionKey(format!("az.storage.account.{verb}"))),
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            ("blob", Some(verb)) => match verb {
                "delete" | "upload" => Some(ActionKey(format!("az.storage.blob.{verb}"))),
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            ("container", Some(verb)) => match verb {
                "delete" => Some(ActionKey("az.storage.container.delete".to_string())),
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            _ => None,
        },

        // keyvault <verb> | keyvault key <verb> | keyvault secret <verb>
        "keyvault" => match (g1, g2) {
            ("key", Some(verb)) => match verb {
                "create" | "delete" | "encrypt" | "decrypt" => {
                    Some(ActionKey(format!("az.keyvault.key.{verb}")))
                }
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            ("secret", Some(verb)) => match verb {
                "set" | "delete" | "show" => Some(ActionKey(format!("az.keyvault.secret.{verb}"))),
                v if is_read_only_verb(v) && verb != "show" => None,
                _ => None,
            },
            // keyvault <verb> — top-level vault create/delete.
            (verb, _) => match verb {
                "create" | "delete" => Some(ActionKey(format!("az.keyvault.{verb}"))),
                v if is_read_only_verb(v) => None,
                _ => None,
            },
        },

        // role assignment <verb> | role definition <verb>
        "role" => match (g1, g2) {
            ("assignment", Some(verb)) => match verb {
                "create" | "delete" => Some(ActionKey(format!("az.role.assignment.{verb}"))),
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            ("definition", Some(verb)) => match verb {
                "create" | "delete" => Some(ActionKey(format!("az.role.definition.{verb}"))),
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            _ => None,
        },

        // aks <verb>
        "aks" => match g1 {
            "create" | "delete" | "scale" | "update" | "get-credentials" => {
                Some(ActionKey(format!("az.aks.{}", g1)))
            }
            v if is_read_only_verb(v) => None,
            _ => None,
        },

        // sql server <verb> | sql db <verb>
        "sql" => match (g1, g2) {
            ("server", Some(verb)) => match verb {
                "create" | "delete" => Some(ActionKey(format!("az.sql.server.{verb}"))),
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            ("db", Some(verb)) => match verb {
                "create" | "delete" => Some(ActionKey(format!("az.sql.db.{verb}"))),
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            _ => None,
        },

        // functionapp <verb>
        "functionapp" => match g1 {
            "create" | "delete" | "deploy" => Some(ActionKey(format!("az.functionapp.{}", g1))),
            v if is_read_only_verb(v) => None,
            _ => None,
        },

        // webapp <verb>
        "webapp" => match g1 {
            "create" | "delete" | "deploy" => Some(ActionKey(format!("az.webapp.{}", g1))),
            v if is_read_only_verb(v) => None,
            _ => None,
        },

        // network vnet delete | network nsg rule {create,delete}
        "network" => match (g1, g2, g3) {
            ("vnet", Some("delete"), _) => Some(ActionKey("az.network.vnet.delete".to_string())),
            ("nsg", Some("rule"), Some(verb)) => match verb {
                "create" | "delete" => Some(ActionKey(format!("az.network.nsg.rule.{verb}"))),
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            _ => None,
        },

        // group <verb> — resource group create/delete.
        "group" => match g1 {
            "create" | "delete" => Some(ActionKey(format!("az.group.{}", g1))),
            v if is_read_only_verb(v) => None,
            _ => None,
        },

        // account list | account show — passthrough; classification is None.
        "account" => None,

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// AzFactory — P24 construct-factory contract for the az construct
// ---------------------------------------------------------------------------

/// Parsed az.toml action manifest, initialised once at first access.
static AZ_MANIFEST: std::sync::LazyLock<core_events::construct_toml::ParsedActionManifest> =
    std::sync::LazyLock::new(|| {
        core_events::construct_toml::parse_action_manifest(include_str!("../construct/az.toml"))
            .expect("bundled az.toml must be valid")
    });

/// Look up the `need` atoms for an action key from the bundled manifest.
/// Returns `None` if the action is absent from the manifest or has an empty
/// `need` list.
fn manifest_need_for_action(action_key: &str) -> Option<Vec<String>> {
    let suffix = action_key.strip_prefix("az.")?;
    AZ_MANIFEST
        .manifest
        .actions
        .iter()
        .find(|a| a.key == action_key || a.key.strip_prefix("az.").is_some_and(|k| k == suffix))
        .and_then(|a| {
            let need = &a.need;
            if need.is_empty() {
                None
            } else {
                Some(need.clone())
            }
        })
}

/// Returns `true` when `action_key` (full form, e.g. `"az.vm.create"`) has an
/// entry in the bundled manifest (regardless of whether it carries a `need`).
fn action_in_manifest(action_key: &str) -> bool {
    AZ_MANIFEST.manifest.actions.iter().any(|a| {
        a.key == action_key
            || action_key
                .strip_prefix("az.")
                .and_then(|suffix| {
                    let base = suffix.split('.').next()?;
                    Some(a.key == format!("az.{base}") || a.key == action_key)
                })
                .unwrap_or(false)
    })
}

/// P24 factory implementation for the `az` construct.
#[derive(Debug, Default, Clone)]
pub struct AzFactory;

/// Provider-specific target extracted from an `az` argv invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzFactoryTarget {
    pub provider: &'static str,
    /// Subscription ID or name, when supplied via `--subscription` / `--subscription=`.
    pub subscription: Option<String>,
    /// Resource group, when supplied via `--resource-group` / `-g`.
    pub resource_group: Option<String>,
    /// Resource name, when extractable from `--name` / `-n` or positional argv.
    pub resource_name: Option<String>,
}

/// Need atoms derived from the bundled manifest for one `az` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzFactoryNeed(pub Vec<String>);

/// Extract the value of a named flag from argv, supporting both
/// `--flag value` and `--flag=value` forms.  `names` is the set of flag
/// names that alias (e.g. `["--resource-group", "-g"]`).
fn extract_flag_value(argv: &[String], names: &[&str]) -> Option<String> {
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];
        // --flag=value form
        for &name in names {
            if let Some(val) = tok.strip_prefix(&format!("{name}="))
                && !val.is_empty()
            {
                return Some(val.to_string());
            }
        }
        // --flag value form
        if names.contains(&tok.as_str())
            && let Some(val) = argv.get(i + 1)
            && !val.starts_with('-')
        {
            return Some(val.clone());
        }
        i += 1;
    }
    None
}

/// Returns `true` when any of the given flag names appear in `argv`,
/// regardless of whether a value follows.
fn has_flag(argv: &[String], names: &[&str]) -> bool {
    argv.iter().any(|tok| {
        names.contains(&tok.as_str())
            || names
                .iter()
                .any(|name| tok.starts_with(&format!("{name}=")))
    })
}

impl InvocationGrammar for AzFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_az_argv(argv)
    }
}

impl TargetExtractor for AzFactory {
    type Target = AzFactoryTarget;

    fn target_for_argv(&self, _action_key: &ActionKey, argv: &[String]) -> Option<Self::Target> {
        let subscription = extract_flag_value(argv, &["--subscription"]);
        let resource_group = extract_flag_value(argv, &["--resource-group", "-g"]);
        let resource_name = extract_flag_value(argv, &["--name", "-n"]);

        // Return a target if we found at least one piece of evidence.
        if subscription.is_some() || resource_group.is_some() || resource_name.is_some() {
            Some(AzFactoryTarget {
                provider: "azure",
                subscription,
                resource_group,
                resource_name,
            })
        } else {
            None
        }
    }
}

impl NeedTemplate for AzFactory {
    type Need = AzFactoryNeed;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        _target: &Self::Target,
        _argv: &[String],
    ) -> Option<Self::Need> {
        manifest_need_for_action(&action_key.0).map(AzFactoryNeed)
    }
}

impl ConstructFactory for AzFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> FactoryDisposition {
        // 0. Login verbs are credential-bypass vectors — always fail closed.
        //    Checked against raw argv because `az login` is a single-token
        //    verb that the classifier (which requires group + verb) does not
        //    classify.
        let stripped = strip_global_flags(argv);
        if stripped.first().map(|s| s.as_str()) == Some("login") {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // 1. --subscription appearing as a global flag means the caller is
        //    selecting the authority scope externally → fail closed.
        //    Checked before action_key because this applies regardless of
        //    classification.
        if has_flag(argv, &["--subscription"]) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // 2. ARM/Bicep template file references require payload analysis,
        //    regardless of whether the verb is classified (e.g.
        //    `az deployment group create --template-file` is unclassified
        //    but authority-bearing).
        if has_flag(argv, &["--template-file", "--template-uri"]) {
            return FactoryDisposition::PayloadAnalysisRequired;
        }

        // 3. No action key (reads/version) → credentialless passthrough.
        let Some(key) = action_key else {
            return FactoryDisposition::Credentialless;
        };

        // 4. Also catch any classified login-shaped keys.
        if key.0 == "az.login" || key.0.starts_with("az.login.") {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // 5. Action not in the manifest → fail closed.
        if !action_in_manifest(&key.0) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // 6. Action is in the manifest.  Azure actions currently carry no
        //    `need` atoms (credential model is different from GitHub), so we
        //    proceed to resolver_required — subscription must still be resolved
        //    from configuration.
        FactoryDisposition::ResolverRequired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // --- vm ---

    #[test]
    fn vm_create_classified() {
        let r = classify_az_argv(&args(&["vm", "create", "--name", "vm1"])).unwrap();
        assert_eq!(r.0, "az.vm.create");
    }

    #[test]
    fn vm_delete_classified() {
        let r = classify_az_argv(&args(&["vm", "delete", "--name", "vm1"])).unwrap();
        assert_eq!(r.0, "az.vm.delete");
    }

    #[test]
    fn vm_deallocate_classified() {
        let r = classify_az_argv(&args(&["vm", "deallocate", "--name", "vm1"])).unwrap();
        assert_eq!(r.0, "az.vm.deallocate");
    }

    #[test]
    fn vm_restart_classified() {
        let r = classify_az_argv(&args(&["vm", "restart"])).unwrap();
        assert_eq!(r.0, "az.vm.restart");
    }

    #[test]
    fn vm_list_passthrough() {
        assert!(classify_az_argv(&args(&["vm", "list"])).is_none());
    }

    // --- vmss ---

    #[test]
    fn vmss_create_classified() {
        let r = classify_az_argv(&args(&["vmss", "create", "--name", "ss"])).unwrap();
        assert_eq!(r.0, "az.vmss.create");
    }

    #[test]
    fn vmss_delete_classified() {
        let r = classify_az_argv(&args(&["vmss", "delete", "--name", "ss"])).unwrap();
        assert_eq!(r.0, "az.vmss.delete");
    }

    #[test]
    fn vmss_scale_classified() {
        let r = classify_az_argv(&args(&["vmss", "scale", "--new-capacity", "5"])).unwrap();
        assert_eq!(r.0, "az.vmss.scale");
    }

    #[test]
    fn vmss_update_classified() {
        let r = classify_az_argv(&args(&["vmss", "update"])).unwrap();
        assert_eq!(r.0, "az.vmss.update");
    }

    #[test]
    fn vmss_list_passthrough() {
        assert!(classify_az_argv(&args(&["vmss", "list"])).is_none());
    }

    // --- storage ---

    #[test]
    fn storage_account_create_classified() {
        let r = classify_az_argv(&args(&["storage", "account", "create", "--name", "s"])).unwrap();
        assert_eq!(r.0, "az.storage.account.create");
    }

    #[test]
    fn storage_account_delete_classified() {
        let r = classify_az_argv(&args(&["storage", "account", "delete", "--name", "s"])).unwrap();
        assert_eq!(r.0, "az.storage.account.delete");
    }

    #[test]
    fn storage_account_show_passthrough() {
        assert!(classify_az_argv(&args(&["storage", "account", "show"])).is_none());
    }

    #[test]
    fn storage_account_list_passthrough() {
        assert!(classify_az_argv(&args(&["storage", "account", "list"])).is_none());
    }

    #[test]
    fn storage_blob_delete_classified() {
        let r = classify_az_argv(&args(&["storage", "blob", "delete", "--name", "b"])).unwrap();
        assert_eq!(r.0, "az.storage.blob.delete");
    }

    #[test]
    fn storage_blob_upload_classified() {
        let r = classify_az_argv(&args(&["storage", "blob", "upload", "--file", "f"])).unwrap();
        assert_eq!(r.0, "az.storage.blob.upload");
    }

    #[test]
    fn storage_container_delete_classified() {
        let r =
            classify_az_argv(&args(&["storage", "container", "delete", "--name", "c"])).unwrap();
        assert_eq!(r.0, "az.storage.container.delete");
    }

    #[test]
    fn storage_blob_list_passthrough() {
        assert!(classify_az_argv(&args(&["storage", "blob", "list"])).is_none());
    }

    // --- keyvault ---

    #[test]
    fn keyvault_create_classified() {
        let r = classify_az_argv(&args(&["keyvault", "create", "--name", "kv"])).unwrap();
        assert_eq!(r.0, "az.keyvault.create");
    }

    #[test]
    fn keyvault_delete_classified() {
        let r = classify_az_argv(&args(&["keyvault", "delete", "--name", "kv"])).unwrap();
        assert_eq!(r.0, "az.keyvault.delete");
    }

    #[test]
    fn keyvault_show_passthrough() {
        assert!(classify_az_argv(&args(&["keyvault", "show", "--name", "kv"])).is_none());
    }

    #[test]
    fn keyvault_list_passthrough() {
        assert!(classify_az_argv(&args(&["keyvault", "list"])).is_none());
    }

    #[test]
    fn keyvault_key_create_classified() {
        let r = classify_az_argv(&args(&["keyvault", "key", "create"])).unwrap();
        assert_eq!(r.0, "az.keyvault.key.create");
    }

    #[test]
    fn keyvault_key_delete_classified() {
        let r = classify_az_argv(&args(&["keyvault", "key", "delete"])).unwrap();
        assert_eq!(r.0, "az.keyvault.key.delete");
    }

    #[test]
    fn keyvault_key_encrypt_classified() {
        let r = classify_az_argv(&args(&["keyvault", "key", "encrypt"])).unwrap();
        assert_eq!(r.0, "az.keyvault.key.encrypt");
    }

    #[test]
    fn keyvault_key_decrypt_classified() {
        let r = classify_az_argv(&args(&["keyvault", "key", "decrypt"])).unwrap();
        assert_eq!(r.0, "az.keyvault.key.decrypt");
    }

    #[test]
    fn keyvault_key_list_passthrough() {
        assert!(classify_az_argv(&args(&["keyvault", "key", "list"])).is_none());
    }

    #[test]
    fn keyvault_secret_set_classified() {
        let r = classify_az_argv(&args(&["keyvault", "secret", "set"])).unwrap();
        assert_eq!(r.0, "az.keyvault.secret.set");
    }

    #[test]
    fn keyvault_secret_delete_classified() {
        let r = classify_az_argv(&args(&["keyvault", "secret", "delete"])).unwrap();
        assert_eq!(r.0, "az.keyvault.secret.delete");
    }

    #[test]
    fn keyvault_secret_show_classified() {
        // `show` is treated as a destructive secret-reveal here, NOT as
        // read-only passthrough.
        let r = classify_az_argv(&args(&["keyvault", "secret", "show"])).unwrap();
        assert_eq!(r.0, "az.keyvault.secret.show");
    }

    #[test]
    fn keyvault_secret_list_passthrough() {
        assert!(classify_az_argv(&args(&["keyvault", "secret", "list"])).is_none());
    }

    // --- role ---

    #[test]
    fn role_assignment_create_classified() {
        let r = classify_az_argv(&args(&["role", "assignment", "create"])).unwrap();
        assert_eq!(r.0, "az.role.assignment.create");
    }

    #[test]
    fn role_assignment_delete_classified() {
        let r = classify_az_argv(&args(&["role", "assignment", "delete"])).unwrap();
        assert_eq!(r.0, "az.role.assignment.delete");
    }

    #[test]
    fn role_assignment_list_passthrough() {
        assert!(classify_az_argv(&args(&["role", "assignment", "list"])).is_none());
    }

    #[test]
    fn role_definition_create_classified() {
        let r = classify_az_argv(&args(&["role", "definition", "create"])).unwrap();
        assert_eq!(r.0, "az.role.definition.create");
    }

    #[test]
    fn role_definition_delete_classified() {
        let r = classify_az_argv(&args(&["role", "definition", "delete"])).unwrap();
        assert_eq!(r.0, "az.role.definition.delete");
    }

    #[test]
    fn role_definition_list_passthrough() {
        assert!(classify_az_argv(&args(&["role", "definition", "list"])).is_none());
    }

    // --- aks ---

    #[test]
    fn aks_create_classified() {
        let r = classify_az_argv(&args(&["aks", "create", "--name", "k"])).unwrap();
        assert_eq!(r.0, "az.aks.create");
    }

    #[test]
    fn aks_delete_classified() {
        let r = classify_az_argv(&args(&["aks", "delete", "--name", "k"])).unwrap();
        assert_eq!(r.0, "az.aks.delete");
    }

    #[test]
    fn aks_scale_classified() {
        let r = classify_az_argv(&args(&["aks", "scale", "--node-count", "3"])).unwrap();
        assert_eq!(r.0, "az.aks.scale");
    }

    #[test]
    fn aks_update_classified() {
        let r = classify_az_argv(&args(&["aks", "update"])).unwrap();
        assert_eq!(r.0, "az.aks.update");
    }

    #[test]
    fn aks_get_credentials_classified() {
        let r = classify_az_argv(&args(&["aks", "get-credentials", "--name", "k"])).unwrap();
        assert_eq!(r.0, "az.aks.get-credentials");
    }

    #[test]
    fn aks_show_passthrough() {
        assert!(classify_az_argv(&args(&["aks", "show", "--name", "k"])).is_none());
    }

    #[test]
    fn aks_list_passthrough() {
        assert!(classify_az_argv(&args(&["aks", "list"])).is_none());
    }

    // --- sql ---

    #[test]
    fn sql_server_create_classified() {
        let r = classify_az_argv(&args(&["sql", "server", "create"])).unwrap();
        assert_eq!(r.0, "az.sql.server.create");
    }

    #[test]
    fn sql_server_delete_classified() {
        let r = classify_az_argv(&args(&["sql", "server", "delete"])).unwrap();
        assert_eq!(r.0, "az.sql.server.delete");
    }

    #[test]
    fn sql_db_create_classified() {
        let r = classify_az_argv(&args(&["sql", "db", "create"])).unwrap();
        assert_eq!(r.0, "az.sql.db.create");
    }

    #[test]
    fn sql_db_delete_classified() {
        let r = classify_az_argv(&args(&["sql", "db", "delete"])).unwrap();
        assert_eq!(r.0, "az.sql.db.delete");
    }

    #[test]
    fn sql_db_list_passthrough() {
        assert!(classify_az_argv(&args(&["sql", "db", "list"])).is_none());
    }

    // --- functionapp ---

    #[test]
    fn functionapp_create_classified() {
        let r = classify_az_argv(&args(&["functionapp", "create", "--name", "f"])).unwrap();
        assert_eq!(r.0, "az.functionapp.create");
    }

    #[test]
    fn functionapp_delete_classified() {
        let r = classify_az_argv(&args(&["functionapp", "delete", "--name", "f"])).unwrap();
        assert_eq!(r.0, "az.functionapp.delete");
    }

    #[test]
    fn functionapp_deploy_classified() {
        let r = classify_az_argv(&args(&["functionapp", "deploy"])).unwrap();
        assert_eq!(r.0, "az.functionapp.deploy");
    }

    #[test]
    fn functionapp_list_passthrough() {
        assert!(classify_az_argv(&args(&["functionapp", "list"])).is_none());
    }

    // --- webapp ---

    #[test]
    fn webapp_create_classified() {
        let r = classify_az_argv(&args(&["webapp", "create", "--name", "w"])).unwrap();
        assert_eq!(r.0, "az.webapp.create");
    }

    #[test]
    fn webapp_delete_classified() {
        let r = classify_az_argv(&args(&["webapp", "delete", "--name", "w"])).unwrap();
        assert_eq!(r.0, "az.webapp.delete");
    }

    #[test]
    fn webapp_deploy_classified() {
        let r = classify_az_argv(&args(&["webapp", "deploy"])).unwrap();
        assert_eq!(r.0, "az.webapp.deploy");
    }

    #[test]
    fn webapp_list_passthrough() {
        assert!(classify_az_argv(&args(&["webapp", "list"])).is_none());
    }

    // --- network ---

    #[test]
    fn network_vnet_delete_classified() {
        let r = classify_az_argv(&args(&["network", "vnet", "delete", "--name", "v"])).unwrap();
        assert_eq!(r.0, "az.network.vnet.delete");
    }

    #[test]
    fn network_nsg_rule_create_classified() {
        let r =
            classify_az_argv(&args(&["network", "nsg", "rule", "create", "--name", "r"])).unwrap();
        assert_eq!(r.0, "az.network.nsg.rule.create");
    }

    #[test]
    fn network_nsg_rule_delete_classified() {
        let r =
            classify_az_argv(&args(&["network", "nsg", "rule", "delete", "--name", "r"])).unwrap();
        assert_eq!(r.0, "az.network.nsg.rule.delete");
    }

    #[test]
    fn network_nsg_rule_list_passthrough() {
        assert!(classify_az_argv(&args(&["network", "nsg", "rule", "list"])).is_none());
    }

    #[test]
    fn network_vnet_show_passthrough() {
        assert!(classify_az_argv(&args(&["network", "vnet", "show"])).is_none());
    }

    // --- group (resource group) ---

    #[test]
    fn group_create_classified() {
        let r = classify_az_argv(&args(&["group", "create", "--name", "rg"])).unwrap();
        assert_eq!(r.0, "az.group.create");
    }

    #[test]
    fn group_delete_classified() {
        let r = classify_az_argv(&args(&["group", "delete", "--name", "rg"])).unwrap();
        assert_eq!(r.0, "az.group.delete");
    }

    #[test]
    fn group_show_passthrough() {
        assert!(classify_az_argv(&args(&["group", "show", "--name", "rg"])).is_none());
    }

    #[test]
    fn group_list_passthrough() {
        assert!(classify_az_argv(&args(&["group", "list"])).is_none());
    }

    // --- account (always passthrough) ---

    #[test]
    fn account_show_passthrough() {
        assert!(classify_az_argv(&args(&["account", "show"])).is_none());
    }

    #[test]
    fn account_list_passthrough() {
        assert!(classify_az_argv(&args(&["account", "list"])).is_none());
    }

    // --- global flag stripping ---

    #[test]
    fn subscription_flag_value_form_stripped() {
        let r = classify_az_argv(&args(&[
            "--subscription",
            "my-sub",
            "vm",
            "delete",
            "--name",
            "vm1",
        ]))
        .unwrap();
        assert_eq!(r.0, "az.vm.delete");
    }

    #[test]
    fn subscription_flag_eq_form_stripped() {
        let r = classify_az_argv(&args(&[
            "--subscription=my-sub",
            "vm",
            "delete",
            "--name",
            "vm1",
        ]))
        .unwrap();
        assert_eq!(r.0, "az.vm.delete");
    }

    #[test]
    fn resource_group_flag_value_form_stripped() {
        let r = classify_az_argv(&args(&[
            "--resource-group",
            "my-rg",
            "vm",
            "delete",
            "--name",
            "vm1",
        ]))
        .unwrap();
        assert_eq!(r.0, "az.vm.delete");
    }

    #[test]
    fn resource_group_flag_eq_form_stripped() {
        let r = classify_az_argv(&args(&[
            "--resource-group=my-rg",
            "vm",
            "delete",
            "--name",
            "vm1",
        ]))
        .unwrap();
        assert_eq!(r.0, "az.vm.delete");
    }

    #[test]
    fn resource_group_short_flag_stripped() {
        let r = classify_az_argv(&args(&["-g", "my-rg", "vm", "delete", "--name", "vm1"])).unwrap();
        assert_eq!(r.0, "az.vm.delete");
    }

    #[test]
    fn location_flag_value_form_stripped() {
        let r = classify_az_argv(&args(&[
            "--location",
            "eastus",
            "group",
            "delete",
            "--name",
            "rg",
        ]))
        .unwrap();
        assert_eq!(r.0, "az.group.delete");
    }

    #[test]
    fn output_flag_value_form_stripped() {
        let r = classify_az_argv(&args(&[
            "--output", "json", "vm", "delete", "--name", "vm1",
        ]))
        .unwrap();
        assert_eq!(r.0, "az.vm.delete");
    }

    #[test]
    fn query_flag_value_form_stripped() {
        let r = classify_az_argv(&args(&[
            "--query", "[].name", "vm", "delete", "--name", "vm1",
        ]))
        .unwrap();
        assert_eq!(r.0, "az.vm.delete");
    }

    #[test]
    fn verbose_boolean_flag_stripped() {
        let r = classify_az_argv(&args(&["--verbose", "vm", "delete", "--name", "vm1"])).unwrap();
        assert_eq!(r.0, "az.vm.delete");
    }

    #[test]
    fn debug_boolean_flag_stripped() {
        let r = classify_az_argv(&args(&["--debug", "vm", "delete", "--name", "vm1"])).unwrap();
        assert_eq!(r.0, "az.vm.delete");
    }

    #[test]
    fn flags_reordered_classification_stable() {
        let a = classify_az_argv(&args(&["vm", "delete", "--name", "vm1"])).unwrap();
        let b = classify_az_argv(&args(&[
            "--subscription",
            "s",
            "vm",
            "delete",
            "--name",
            "vm1",
        ]))
        .unwrap();
        let c = classify_az_argv(&args(&[
            "vm",
            "--subscription",
            "s",
            "delete",
            "--name",
            "vm1",
        ]))
        .unwrap();
        let d = classify_az_argv(&args(&[
            "vm",
            "delete",
            "--subscription",
            "s",
            "--name",
            "vm1",
        ]))
        .unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(b.0, c.0);
        assert_eq!(c.0, d.0);
    }

    // --- empty / corner cases ---

    #[test]
    fn empty_argv_passthrough() {
        assert!(classify_az_argv(&[]).is_none());
    }

    #[test]
    fn only_global_flags_passthrough() {
        assert!(classify_az_argv(&args(&["--subscription", "s", "--verbose"])).is_none());
    }

    #[test]
    fn unknown_group_passthrough() {
        assert!(classify_az_argv(&args(&["cosmosdb", "create"])).is_none());
    }

    #[test]
    fn group_without_verb_passthrough() {
        assert!(classify_az_argv(&args(&["vm"])).is_none());
    }

    // --- proptest: argv fuzzer; no panics; passthrough is a fixed point ---

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
            let _ = classify_az_argv(&argv);
        }

        /// Inserting a recognized global flag (with value) into a known
        /// classified argv must not change the classification.
        #[test]
        fn fuzz_subscription_flag_insertion_stable(
            insert_at in 0usize..6,
            sub in "[a-z][a-z0-9-]{2,16}"
        ) {
            let base = vec![
                "vm".to_string(),
                "delete".to_string(),
                "--name".to_string(),
                "vm1".to_string(),
            ];
            let base_class = classify_az_argv(&base).unwrap();

            let mut with_flag = base.clone();
            // Only insert before the verb-args (cap at index 2) so we
            // don't split the `--name vm1` pair the verb cares about.
            let pos = insert_at.min(2);
            with_flag.insert(pos, sub.clone());
            with_flag.insert(pos, "--subscription".to_string());

            let class2 = classify_az_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }

        /// Inserting a boolean global flag at any position into a known
        /// classified argv must not change the classification.
        #[test]
        fn fuzz_boolean_flag_insertion_stable(insert_at in 0usize..6) {
            let base = vec![
                "role".to_string(),
                "assignment".to_string(),
                "delete".to_string(),
            ];
            let base_class = classify_az_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, "--verbose".to_string());

            let class2 = classify_az_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }
    }

    // --- T2: integration with MockBroker for BrokerProvider::AzureCli ---
    //
    // The full broker_exec lifecycle lives in the daemon; here we cover the
    // contract slice this Construct depends on: the broker registry can
    // hold a `MockBroker::new(BrokerProvider::AzureCli)`, and a request that
    // declares `provider = AzureCli` round-trips through issue → revoke
    // without panicking. Real Azure CLI impl is BROKER-AZURE-CLI-IMPL
    // (separate task).

    use core_broker::{Broker, BrokerError, BrokerProvider, BrokerRequest, MockBroker};
    use std::time::Duration;

    fn azure_request(ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::AzureCli,
            scope: serde_json::json!({
                "service_principal": "ember-agent@my-tenant",
                "tenant_id": "00000000-0000-0000-0000-000000000000",
                "actions": ["Microsoft.Storage/storageAccounts/read"],
            }),
            ttl: Duration::from_secs(ttl_secs),
            contract_id: None,
            action_ref: None,
            workspace_ref: None,
            subject_ref: None,
            coordination_ref: None,
            caller_ref: None,
            authority_ref: None,
            reason: "ember-az integration test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    #[tokio::test]
    async fn mock_broker_azure_cli_issue_revoke_roundtrip() {
        let broker = MockBroker::new(BrokerProvider::AzureCli);
        assert_eq!(broker.provider(), BrokerProvider::AzureCli);

        let creds = broker
            .issue(azure_request(900))
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
    async fn mock_broker_azure_cli_rejects_wrong_provider() {
        let broker = MockBroker::new(BrokerProvider::AzureCli);
        let mut req = azure_request(900);
        req.provider = BrokerProvider::Cloudflare;

        let err = broker.issue(req).await.expect_err("provider mismatch");
        match err {
            BrokerError::InvalidScope(_) => {}
            other => panic!("expected InvalidScope, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // AzFactory tests
    // -----------------------------------------------------------------------

    #[test]
    fn az_factory_version_is_credentialless() {
        let f = AzFactory;
        let a = args(&["version"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn az_factory_vm_list_is_credentialless() {
        let f = AzFactory;
        let a = args(&["vm", "list"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn az_factory_vm_delete_with_rg_is_resolver_required() {
        let f = AzFactory;
        let a = args(&[
            "vm",
            "delete",
            "--name",
            "web-01",
            "--resource-group",
            "prod",
        ]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn az_factory_vm_create_no_rg_is_resolver_required() {
        let f = AzFactory;
        let a = args(&["vm", "create", "--name", "web-02"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn az_factory_subscription_flag_fails_closed() {
        let f = AzFactory;
        let a = args(&[
            "--subscription",
            "prod-sub",
            "vm",
            "delete",
            "--name",
            "web-01",
            "--resource-group",
            "prod",
        ]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn az_factory_subscription_eq_flag_fails_closed() {
        let f = AzFactory;
        let a = args(&[
            "--subscription=prod-sub",
            "vm",
            "delete",
            "--name",
            "web-01",
        ]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn az_factory_template_file_needs_payload_analysis() {
        let f = AzFactory;
        // deployment group create is not in the classifier (no action key),
        // but the template flag triggers payload analysis regardless.
        let a = args(&[
            "deployment",
            "group",
            "create",
            "--resource-group",
            "prod",
            "--template-file",
            "main.bicep",
        ]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn az_factory_template_uri_needs_payload_analysis() {
        let f = AzFactory;
        let a = args(&[
            "deployment",
            "group",
            "create",
            "--resource-group",
            "prod",
            "--template-uri",
            "https://example.com/main.json",
        ]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn az_factory_template_file_on_classified_verb_also_payload_analysis() {
        let f = AzFactory;
        let a = args(&[
            "webapp",
            "deploy",
            "--resource-group",
            "prod",
            "--template-file",
            "main.bicep",
        ]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn az_factory_unknown_group_is_credentialless() {
        let f = AzFactory;
        let a = args(&["cosmosdb", "create", "--name", "db1"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn az_factory_target_extraction_with_rg_and_name() {
        let f = AzFactory;
        let a = args(&[
            "vm",
            "delete",
            "--name",
            "web-01",
            "--resource-group",
            "prod",
        ]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.provider, "azure");
        assert_eq!(target.subscription, None);
        assert_eq!(target.resource_group, Some("prod".to_string()));
        assert_eq!(target.resource_name, Some("web-01".to_string()));
    }

    #[test]
    fn az_factory_target_extraction_with_subscription() {
        let f = AzFactory;
        let a = args(&[
            "--subscription",
            "my-sub",
            "vm",
            "delete",
            "--name",
            "web-01",
        ]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.subscription, Some("my-sub".to_string()));
        assert_eq!(target.resource_name, Some("web-01".to_string()));
    }

    #[test]
    fn az_factory_target_extraction_short_rg_flag() {
        let f = AzFactory;
        let a = args(&["vm", "delete", "-g", "prod", "--name", "web-01"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.resource_group, Some("prod".to_string()));
    }

    #[test]
    fn az_factory_target_extraction_no_evidence_returns_none() {
        let f = AzFactory;
        let a = args(&["vm", "create"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert!(f.target_for_argv(&key, &a).is_none());
    }

    #[test]
    fn az_factory_contract_runs_conformance_corpus() {
        let corpus = core_construct_runtime::factory::parse_factory_fixture_corpus(include_str!(
            "../conformance/az/factory-fixtures.toml"
        ))
        .expect("fixture TOML parses");
        let validation_errors =
            core_construct_runtime::factory::validate_factory_fixture_corpus(&corpus);
        assert!(validation_errors.is_empty(), "{validation_errors:#?}");

        let carrier = core_construct_runtime::factory::ActionManifestV2Carrier::parse(
            include_str!("../construct/az.toml"),
        )
        .expect("valid az manifest");
        let report = core_construct_runtime::factory::run_factory_fixtures(
            &AzFactory,
            Some(&carrier),
            &corpus,
        );
        assert!(report.is_clean(), "{:#?}", report.failures);
    }
}
