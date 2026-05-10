//! Argv classifier: maps `okta <resource> <verb> ...` to a `construct.toml`
//! action_key. Per design §3 — this lives shim-side BUT the daemon
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

/// Okta CLI global flags that take a value as the *next* argv token.
/// When stripping, both the flag and its value are removed.
const VALUE_BEARING_GLOBAL_FLAGS: &[&str] = &[
    "--profile",
    "--config",
    "--output",
    "--token",
];

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
            "create"
            | "delete"
            | "deactivate"
            | "update"
            | "assign-user"
            | "unassign-user"
            | "assign-group"
            | "unassign-group" => Some(ActionKey(format!("okta.apps.{verb}"))),
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
            "enroll" | "reset" | "deactivate" => {
                Some(ActionKey(format!("okta.factors.{verb}")))
            }
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
            "create" | "delete" | "update" => {
                Some(ActionKey(format!("okta.zones.{verb}")))
            }
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
    fn users_list_passthrough() {
        assert!(classify_okta_argv(&args(&["users", "list"])).is_none());
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
        let r = classify_okta_argv(&args(&[
            "--profile",
            "prod",
            "users",
            "delete",
            "uid",
        ]))
        .unwrap();
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
        let r = classify_okta_argv(&args(&[
            "apps",
            "delete",
            "--token",
            "00aBcDeF",
            "aid",
        ]))
        .unwrap();
        assert_eq!(r.0, "okta.apps.delete");
    }

    #[test]
    fn output_flag_stripped() {
        let r = classify_okta_argv(&args(&[
            "--output",
            "json",
            "groups",
            "delete",
            "gid",
        ]))
        .unwrap();
        assert_eq!(r.0, "okta.groups.delete");
    }

    #[test]
    fn verbose_boolean_flag_stripped() {
        let r =
            classify_okta_argv(&args(&["--verbose", "users", "suspend", "uid"])).unwrap();
        assert_eq!(r.0, "okta.users.suspend");
    }

    #[test]
    fn quiet_boolean_flag_stripped() {
        let r =
            classify_okta_argv(&args(&["--quiet", "policies", "delete", "pid"])).unwrap();
        assert_eq!(r.0, "okta.policies.delete");
    }

    #[test]
    fn equals_form_profile_flag_stripped() {
        let r = classify_okta_argv(&args(&[
            "--profile=prod",
            "users",
            "delete",
            "uid",
        ]))
        .unwrap();
        assert_eq!(r.0, "okta.users.delete");
    }

    #[test]
    fn equals_form_token_flag_stripped() {
        let r = classify_okta_argv(&args(&[
            "--token=00secret",
            "session",
            "end",
            "sid",
        ]))
        .unwrap();
        assert_eq!(r.0, "okta.session.end");
    }

    #[test]
    fn equals_form_config_flag_stripped() {
        let r = classify_okta_argv(&args(&[
            "factors",
            "--config=/x.toml",
            "reset",
            "uid",
        ]))
        .unwrap();
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
        let a = classify_okta_argv(&args(&[
            "users", "delete", "uid", "--profile", "prod",
        ]))
        .unwrap();
        let b = classify_okta_argv(&args(&[
            "--profile", "prod", "users", "delete", "uid",
        ]))
        .unwrap();
        let c = classify_okta_argv(&args(&[
            "users", "--profile", "prod", "delete", "uid",
        ]))
        .unwrap();
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
        assert!(
            classify_okta_argv(&args(&["--profile", "prod", "--verbose"])).is_none()
        );
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
    // without panicking. Real Okta broker impl is implementation-note-35
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
}
