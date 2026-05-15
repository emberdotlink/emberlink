//! Argv classifier: maps `gcloud <group> [<subgroup> ...] <verb> [args]` to
//! a `construct.toml` action_key. Per design §3 — this lives shim-side BUT
//! the daemon re-classifies the argv server-side (untrusts the shim).
//!
//! gcloud CLI argv shape:
//!
//! ```text
//! gcloud [global-flags...] <group> [<subgroup> ...] <verb> [verb-args...]
//! ```
//!
//! Global flags (e.g. `--project`, `--region`, `--zone`, `--account`,
//! `--quiet`, `--format`, `--verbosity`, `--billing-project`, `--user-output-enabled`,
//! `--log-http`, `--trace-token`, `--configuration`, `--impersonate-service-account`,
//! `--access-token-file`, `--http-timeout`) may appear before, between, or after the
//! group/verb tokens. We strip them — including their values for the
//! flags that take one — before pattern-matching, so classification is
//! stable under flag reordering.
//!
//! Coverage (mutating verbs are gated; read-only verbs passthrough as `None`):
//!
//! | argv prefix                                      | action_key                                       |
//! |--------------------------------------------------|--------------------------------------------------|
//! | `compute instances {create,delete,start,stop,reset}` | `gcloud.compute.instances.<verb>`           |
//! | `iam service-accounts {create,delete}`           | `gcloud.iam.service-accounts.<verb>`             |
//! | `iam roles {create,delete}`                      | `gcloud.iam.roles.<verb>`                        |
//! | `iam policies {add-iam-policy-binding,remove-iam-policy-binding}` | `gcloud.iam.policies.<verb>` |
//! | `storage {rm,cp,mv}`                             | `gcloud.storage.<verb>`                          |
//! | `kms keys {destroy,encrypt,decrypt}`             | `gcloud.kms.keys.<verb>`                         |
//! | `kms keyrings create`                            | `gcloud.kms.keyrings.create`                     |
//! | `secrets {create,delete}`                        | `gcloud.secrets.<verb>`                          |
//! | `secrets versions {add,access}`                  | `gcloud.secrets.versions.<verb>`                 |
//! | `functions {deploy,delete}`                      | `gcloud.functions.<verb>`                        |
//! | `run deploy`                                     | `gcloud.run.deploy`                              |
//! | `run services delete`                            | `gcloud.run.services.delete`                     |
//! | `container clusters {create,delete,update}`      | `gcloud.container.clusters.<verb>`               |
//! | `projects {create,delete}`                       | `gcloud.projects.<verb>`                         |
//! | `describe \| list \| get-iam-policy \| auth list \| config list` | `None` (passthrough)         |

use core_construct_runtime::ActionKey;

/// gcloud CLI global flags that take a value as the *next* argv token.
/// When stripping, both the flag and its value are removed.
const VALUE_BEARING_GLOBAL_FLAGS: &[&str] = &[
    "--project",
    "--region",
    "--zone",
    "--account",
    "--format",
    "--verbosity",
    "--billing-project",
    "--configuration",
    "--impersonate-service-account",
    "--access-token-file",
    "--trace-token",
    "--http-timeout",
    "--flags-file",
    "--flatten",
    "--filter",
    "--limit",
    "--page-size",
    "--sort-by",
    "--request-reason",
];

/// gcloud CLI global flags that are valueless (boolean toggles).
const BOOLEAN_GLOBAL_FLAGS: &[&str] = &[
    "--quiet",
    "-q",
    "--user-output-enabled",
    "--no-user-output-enabled",
    "--log-http",
    "--no-log-http",
    "--help",
    "-h",
    "--version",
];

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
            if VALUE_BEARING_GLOBAL_FLAGS.contains(&name)
                || BOOLEAN_GLOBAL_FLAGS.contains(&name)
            {
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

/// Returns `true` if `verb` looks like a read-only gcloud verb.
///
/// Read-only verbs include `describe`, `list`, `get-iam-policy`, plus
/// the `auth list` / `config list` shapes (handled by checking the trailing
/// token in known passthrough subcommands).
fn is_read_only_verb(verb: &str) -> bool {
    matches!(
        verb,
        "describe" | "list" | "get-iam-policy" | "help" | "get" | "get-value"
    )
}

/// Classify `gcloud <group> [<subgroup> ...] <verb> ...` argv into an
/// action_key.
///
/// Returns `None` for read-only / unrecognized shapes — the runtime
/// treats `None` as passthrough (no broker mediation).
pub fn classify_gcloud_argv(argv: &[String]) -> Option<ActionKey> {
    let stripped = strip_global_flags(argv);

    // After stripping global flags, we expect:
    //   <group> [<subgroup> ...] <verb> [args]
    // Length 2 minimum (group + verb) for the simple cases.
    if stripped.len() < 2 {
        return None;
    }

    let g0 = stripped.first()?.as_str();
    let g1 = stripped.get(1).map(|s| s.as_str())?;
    let g2 = stripped.get(2).map(|s| s.as_str());
    let g3 = stripped.get(3).map(|s| s.as_str());

    // Read-only passthrough — `gcloud auth list`, `gcloud config list`,
    // `gcloud config get-value`, `gcloud config configurations list`, etc.
    // These never reach a mutating verb in the trees we classify.
    if matches!(g0, "auth" | "config") {
        // Walk all tokens and bail out as read-only the moment we see a
        // recognized read-only verb. Otherwise it's still passthrough
        // (we don't classify any auth/config writes here).
        return None;
    }

    match g0 {
        // compute instances <verb>
        "compute" => match (g1, g2) {
            ("instances", Some(verb)) => match verb {
                "create" | "delete" | "start" | "stop" | "reset" => {
                    Some(ActionKey(format!("gcloud.compute.instances.{verb}")))
                }
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            _ => None,
        },

        // iam service-accounts | roles | policies <verb>
        "iam" => match (g1, g2) {
            ("service-accounts", Some(verb)) => match verb {
                "create" | "delete" => {
                    Some(ActionKey(format!("gcloud.iam.service-accounts.{verb}")))
                }
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            ("roles", Some(verb)) => match verb {
                "create" | "delete" => Some(ActionKey(format!("gcloud.iam.roles.{verb}"))),
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            ("policies", Some(verb)) => match verb {
                "add-iam-policy-binding" | "remove-iam-policy-binding" => {
                    Some(ActionKey(format!("gcloud.iam.policies.{verb}")))
                }
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            _ => None,
        },

        // storage <verb>
        "storage" => match g1 {
            "rm" | "cp" | "mv" => Some(ActionKey(format!("gcloud.storage.{}", g1))),
            v if is_read_only_verb(v) => None,
            _ => None,
        },

        // kms keys <verb> | kms keyrings create
        "kms" => match (g1, g2) {
            ("keys", Some(verb)) => match verb {
                "destroy" | "encrypt" | "decrypt" => {
                    Some(ActionKey(format!("gcloud.kms.keys.{verb}")))
                }
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            ("keyrings", Some("create")) => {
                Some(ActionKey("gcloud.kms.keyrings.create".to_string()))
            }
            _ => None,
        },

        // secrets {create,delete} | secrets versions {add,access}
        "secrets" => match (g1, g2) {
            // secrets versions <verb>
            ("versions", Some(verb)) => match verb {
                "add" | "access" => {
                    Some(ActionKey(format!("gcloud.secrets.versions.{verb}")))
                }
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            // secrets <verb>
            (verb, _) => match verb {
                "create" | "delete" => Some(ActionKey(format!("gcloud.secrets.{verb}"))),
                v if is_read_only_verb(v) => None,
                _ => None,
            },
        },

        // functions <verb>
        "functions" => match g1 {
            "deploy" | "delete" => Some(ActionKey(format!("gcloud.functions.{}", g1))),
            v if is_read_only_verb(v) => None,
            _ => None,
        },

        // run deploy | run services delete
        "run" => match (g1, g2) {
            ("deploy", _) => Some(ActionKey("gcloud.run.deploy".to_string())),
            ("services", Some("delete")) => {
                Some(ActionKey("gcloud.run.services.delete".to_string()))
            }
            _ => None,
        },

        // container clusters <verb>
        "container" => match (g1, g2) {
            ("clusters", Some(verb)) => match verb {
                "create" | "delete" | "update" => {
                    Some(ActionKey(format!("gcloud.container.clusters.{verb}")))
                }
                v if is_read_only_verb(v) => None,
                _ => None,
            },
            _ => None,
        },

        // projects <verb>
        "projects" => match g1 {
            "create" | "delete" => Some(ActionKey(format!("gcloud.projects.{}", g1))),
            v if is_read_only_verb(v) => None,
            _ => None,
        },

        _ => {
            // Catch any leftover read-only shape at the leaf positions.
            let _ = (g3,); // silence unused — reserved for future deeper trees
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // --- compute instances ---

    #[test]
    fn compute_instances_create_classified() {
        let r = classify_gcloud_argv(&args(&[
            "compute",
            "instances",
            "create",
            "my-vm",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.compute.instances.create");
    }

    #[test]
    fn compute_instances_delete_classified() {
        let r = classify_gcloud_argv(&args(&[
            "compute",
            "instances",
            "delete",
            "my-vm",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.compute.instances.delete");
    }

    #[test]
    fn compute_instances_start_classified() {
        let r = classify_gcloud_argv(&args(&[
            "compute",
            "instances",
            "start",
            "my-vm",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.compute.instances.start");
    }

    #[test]
    fn compute_instances_stop_classified() {
        let r = classify_gcloud_argv(&args(&[
            "compute",
            "instances",
            "stop",
            "my-vm",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.compute.instances.stop");
    }

    #[test]
    fn compute_instances_reset_classified() {
        let r = classify_gcloud_argv(&args(&[
            "compute",
            "instances",
            "reset",
            "my-vm",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.compute.instances.reset");
    }

    #[test]
    fn compute_instances_describe_passthrough() {
        assert!(classify_gcloud_argv(&args(&[
            "compute",
            "instances",
            "describe",
            "my-vm"
        ]))
        .is_none());
    }

    #[test]
    fn compute_instances_list_passthrough() {
        assert!(classify_gcloud_argv(&args(&["compute", "instances", "list"])).is_none());
    }

    // --- iam ---

    #[test]
    fn iam_service_accounts_create_classified() {
        let r = classify_gcloud_argv(&args(&[
            "iam",
            "service-accounts",
            "create",
            "sa-name",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.iam.service-accounts.create");
    }

    #[test]
    fn iam_service_accounts_delete_classified() {
        let r = classify_gcloud_argv(&args(&[
            "iam",
            "service-accounts",
            "delete",
            "sa@p.iam.gserviceaccount.com",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.iam.service-accounts.delete");
    }

    #[test]
    fn iam_roles_create_classified() {
        let r = classify_gcloud_argv(&args(&["iam", "roles", "create", "myRole"])).unwrap();
        assert_eq!(r.0, "gcloud.iam.roles.create");
    }

    #[test]
    fn iam_roles_delete_classified() {
        let r = classify_gcloud_argv(&args(&["iam", "roles", "delete", "myRole"])).unwrap();
        assert_eq!(r.0, "gcloud.iam.roles.delete");
    }

    #[test]
    fn iam_policies_add_binding_classified() {
        let r = classify_gcloud_argv(&args(&[
            "iam",
            "policies",
            "add-iam-policy-binding",
            "p",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.iam.policies.add-iam-policy-binding");
    }

    #[test]
    fn iam_policies_remove_binding_classified() {
        let r = classify_gcloud_argv(&args(&[
            "iam",
            "policies",
            "remove-iam-policy-binding",
            "p",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.iam.policies.remove-iam-policy-binding");
    }

    #[test]
    fn iam_get_iam_policy_passthrough() {
        // This one is on `projects` — hitting the read-only verb match.
        assert!(
            classify_gcloud_argv(&args(&["projects", "get-iam-policy", "my-proj"])).is_none()
        );
    }

    // --- storage ---

    #[test]
    fn storage_rm_classified() {
        let r = classify_gcloud_argv(&args(&["storage", "rm", "gs://b/k"])).unwrap();
        assert_eq!(r.0, "gcloud.storage.rm");
    }

    #[test]
    fn storage_cp_classified() {
        let r = classify_gcloud_argv(&args(&["storage", "cp", "src", "gs://b/k"])).unwrap();
        assert_eq!(r.0, "gcloud.storage.cp");
    }

    #[test]
    fn storage_mv_classified() {
        let r = classify_gcloud_argv(&args(&["storage", "mv", "gs://a/k", "gs://b/k"]))
            .unwrap();
        assert_eq!(r.0, "gcloud.storage.mv");
    }

    #[test]
    fn storage_ls_passthrough() {
        // `gcloud storage ls` is not a recognized destructive verb here.
        assert!(classify_gcloud_argv(&args(&["storage", "ls", "gs://b/"])).is_none());
    }

    // --- kms ---

    #[test]
    fn kms_keys_destroy_classified() {
        let r = classify_gcloud_argv(&args(&["kms", "keys", "destroy", "k"])).unwrap();
        assert_eq!(r.0, "gcloud.kms.keys.destroy");
    }

    #[test]
    fn kms_keys_encrypt_classified() {
        let r = classify_gcloud_argv(&args(&["kms", "keys", "encrypt"])).unwrap();
        assert_eq!(r.0, "gcloud.kms.keys.encrypt");
    }

    #[test]
    fn kms_keys_decrypt_classified() {
        let r = classify_gcloud_argv(&args(&["kms", "keys", "decrypt"])).unwrap();
        assert_eq!(r.0, "gcloud.kms.keys.decrypt");
    }

    #[test]
    fn kms_keyrings_create_classified() {
        let r = classify_gcloud_argv(&args(&["kms", "keyrings", "create", "ring"])).unwrap();
        assert_eq!(r.0, "gcloud.kms.keyrings.create");
    }

    #[test]
    fn kms_keys_describe_passthrough() {
        assert!(classify_gcloud_argv(&args(&["kms", "keys", "describe", "k"])).is_none());
    }

    // --- secrets ---

    #[test]
    fn secrets_create_classified() {
        let r = classify_gcloud_argv(&args(&["secrets", "create", "my-secret"])).unwrap();
        assert_eq!(r.0, "gcloud.secrets.create");
    }

    #[test]
    fn secrets_delete_classified() {
        let r = classify_gcloud_argv(&args(&["secrets", "delete", "my-secret"])).unwrap();
        assert_eq!(r.0, "gcloud.secrets.delete");
    }

    #[test]
    fn secrets_versions_add_classified() {
        let r = classify_gcloud_argv(&args(&["secrets", "versions", "add", "my-secret"]))
            .unwrap();
        assert_eq!(r.0, "gcloud.secrets.versions.add");
    }

    #[test]
    fn secrets_versions_access_classified() {
        let r =
            classify_gcloud_argv(&args(&["secrets", "versions", "access", "latest"])).unwrap();
        assert_eq!(r.0, "gcloud.secrets.versions.access");
    }

    #[test]
    fn secrets_describe_passthrough() {
        assert!(classify_gcloud_argv(&args(&["secrets", "describe", "s"])).is_none());
    }

    // --- functions ---

    #[test]
    fn functions_deploy_classified() {
        let r = classify_gcloud_argv(&args(&["functions", "deploy", "fn"])).unwrap();
        assert_eq!(r.0, "gcloud.functions.deploy");
    }

    #[test]
    fn functions_delete_classified() {
        let r = classify_gcloud_argv(&args(&["functions", "delete", "fn"])).unwrap();
        assert_eq!(r.0, "gcloud.functions.delete");
    }

    // --- run ---

    #[test]
    fn run_deploy_classified() {
        let r = classify_gcloud_argv(&args(&["run", "deploy", "svc"])).unwrap();
        assert_eq!(r.0, "gcloud.run.deploy");
    }

    #[test]
    fn run_services_delete_classified() {
        let r = classify_gcloud_argv(&args(&["run", "services", "delete", "svc"])).unwrap();
        assert_eq!(r.0, "gcloud.run.services.delete");
    }

    #[test]
    fn run_services_list_passthrough() {
        assert!(classify_gcloud_argv(&args(&["run", "services", "list"])).is_none());
    }

    // --- container ---

    #[test]
    fn container_clusters_create_classified() {
        let r = classify_gcloud_argv(&args(&["container", "clusters", "create", "c"]))
            .unwrap();
        assert_eq!(r.0, "gcloud.container.clusters.create");
    }

    #[test]
    fn container_clusters_delete_classified() {
        let r = classify_gcloud_argv(&args(&["container", "clusters", "delete", "c"]))
            .unwrap();
        assert_eq!(r.0, "gcloud.container.clusters.delete");
    }

    #[test]
    fn container_clusters_update_classified() {
        let r = classify_gcloud_argv(&args(&["container", "clusters", "update", "c"]))
            .unwrap();
        assert_eq!(r.0, "gcloud.container.clusters.update");
    }

    // --- projects ---

    #[test]
    fn projects_create_classified() {
        let r = classify_gcloud_argv(&args(&["projects", "create", "p"])).unwrap();
        assert_eq!(r.0, "gcloud.projects.create");
    }

    #[test]
    fn projects_delete_classified() {
        let r = classify_gcloud_argv(&args(&["projects", "delete", "p"])).unwrap();
        assert_eq!(r.0, "gcloud.projects.delete");
    }

    // --- read-only / passthrough ---

    #[test]
    fn auth_list_passthrough() {
        assert!(classify_gcloud_argv(&args(&["auth", "list"])).is_none());
    }

    #[test]
    fn config_list_passthrough() {
        assert!(classify_gcloud_argv(&args(&["config", "list"])).is_none());
    }

    #[test]
    fn config_get_value_passthrough() {
        assert!(
            classify_gcloud_argv(&args(&["config", "get-value", "project"])).is_none()
        );
    }

    // --- global flag stripping ---

    #[test]
    fn project_flag_value_form_stripped() {
        let r = classify_gcloud_argv(&args(&[
            "--project",
            "my-proj",
            "compute",
            "instances",
            "delete",
            "vm",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.compute.instances.delete");
    }

    #[test]
    fn project_flag_eq_form_stripped() {
        let r = classify_gcloud_argv(&args(&[
            "--project=my-proj",
            "compute",
            "instances",
            "delete",
            "vm",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.compute.instances.delete");
    }

    #[test]
    fn region_flag_value_form_stripped() {
        let r = classify_gcloud_argv(&args(&[
            "--region",
            "us-central1",
            "run",
            "services",
            "delete",
            "svc",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.run.services.delete");
    }

    #[test]
    fn region_flag_eq_form_stripped() {
        let r = classify_gcloud_argv(&args(&[
            "--region=us-central1",
            "run",
            "services",
            "delete",
            "svc",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.run.services.delete");
    }

    #[test]
    fn zone_flag_value_form_stripped() {
        let r = classify_gcloud_argv(&args(&[
            "--zone",
            "us-central1-a",
            "compute",
            "instances",
            "stop",
            "vm",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.compute.instances.stop");
    }

    #[test]
    fn zone_flag_eq_form_stripped() {
        let r = classify_gcloud_argv(&args(&[
            "--zone=us-central1-a",
            "compute",
            "instances",
            "stop",
            "vm",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.compute.instances.stop");
    }

    #[test]
    fn quiet_boolean_flag_stripped() {
        let r = classify_gcloud_argv(&args(&[
            "--quiet",
            "compute",
            "instances",
            "delete",
            "vm",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.compute.instances.delete");
    }

    #[test]
    fn account_flag_stripped() {
        let r = classify_gcloud_argv(&args(&[
            "--account",
            "me@example.com",
            "iam",
            "roles",
            "delete",
            "r",
        ]))
        .unwrap();
        assert_eq!(r.0, "gcloud.iam.roles.delete");
    }

    #[test]
    fn flag_position_stable() {
        let a =
            classify_gcloud_argv(&args(&["compute", "instances", "delete", "vm"])).unwrap();
        let b = classify_gcloud_argv(&args(&[
            "--project",
            "p",
            "compute",
            "instances",
            "delete",
            "vm",
        ]))
        .unwrap();
        let c = classify_gcloud_argv(&args(&[
            "compute",
            "--project",
            "p",
            "instances",
            "delete",
            "vm",
        ]))
        .unwrap();
        let d = classify_gcloud_argv(&args(&[
            "compute",
            "instances",
            "delete",
            "--project",
            "p",
            "vm",
        ]))
        .unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(b.0, c.0);
        assert_eq!(c.0, d.0);
    }

    // --- empty / corner cases ---

    #[test]
    fn empty_argv_passthrough() {
        assert!(classify_gcloud_argv(&[]).is_none());
    }

    #[test]
    fn only_global_flags_passthrough() {
        assert!(
            classify_gcloud_argv(&args(&["--project", "p", "--quiet"])).is_none()
        );
    }

    #[test]
    fn unknown_group_passthrough() {
        assert!(classify_gcloud_argv(&args(&["dataflow", "jobs", "run"])).is_none());
    }

    #[test]
    fn group_without_verb_passthrough() {
        assert!(classify_gcloud_argv(&args(&["compute"])).is_none());
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
            let _ = classify_gcloud_argv(&argv);
        }

        /// Inserting a recognized global flag (with value) into a known
        /// classified argv must not change the classification.
        #[test]
        fn fuzz_project_flag_insertion_stable(
            insert_at in 0usize..6,
            project in "[a-z][a-z0-9-]{2,16}"
        ) {
            let base = vec![
                "compute".to_string(),
                "instances".to_string(),
                "delete".to_string(),
                "vm".to_string(),
            ];
            let base_class = classify_gcloud_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, project.clone());
            with_flag.insert(pos, "--project".to_string());

            let class2 = classify_gcloud_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }

        /// Inserting a boolean global flag at any position into a known
        /// classified argv must not change the classification.
        #[test]
        fn fuzz_boolean_flag_insertion_stable(insert_at in 0usize..6) {
            let base = vec![
                "iam".to_string(),
                "roles".to_string(),
                "delete".to_string(),
                "r".to_string(),
            ];
            let base_class = classify_gcloud_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, "--quiet".to_string());

            let class2 = classify_gcloud_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }
    }

    // --- T2: integration with MockBroker for BrokerProvider::Gcp ---
    //
    // The full broker_exec lifecycle lives in the daemon; here we cover the
    // contract slice this Construct depends on: the broker registry can
    // hold a `MockBroker::new(BrokerProvider::Gcp)`, and a request that
    // declares `provider = Gcp` round-trips through issue → revoke
    // without panicking. Real GCP impl is implementation-note-69 (separate task).

    use core_broker::{Broker, BrokerError, BrokerProvider, BrokerRequest, MockBroker};
    use std::time::Duration;

    fn gcp_request(ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::Gcp,
            scope: serde_json::json!({
                "service_account": "ember-agent@my-proj.iam.gserviceaccount.com",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "actions": ["storage.objects.get", "storage.objects.create"],
            }),
            ttl: Duration::from_secs(ttl_secs),
            reason: "ember-gcloud integration test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    #[tokio::test]
    async fn mock_broker_gcp_issue_revoke_roundtrip() {
        let broker = MockBroker::new(BrokerProvider::Gcp);
        assert_eq!(broker.provider(), BrokerProvider::Gcp);

        let creds = broker
            .issue(gcp_request(900))
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
    async fn mock_broker_gcp_rejects_wrong_provider() {
        let broker = MockBroker::new(BrokerProvider::Gcp);
        let mut req = gcp_request(900);
        req.provider = BrokerProvider::Cloudflare;

        let err = broker.issue(req).await.expect_err("provider mismatch");
        match err {
            BrokerError::InvalidScope(_) => {}
            other => panic!("expected InvalidScope, got {other:?}"),
        }
    }
}
