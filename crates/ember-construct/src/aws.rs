//! Argv classifier: maps `aws <service> <verb> ...` to a `construct.toml`
//! action_key. Per design §3 — this lives shim-side BUT the daemon
//! re-classifies the argv server-side (untrusts the shim).
//!
//! AWS CLI argv shape:
//!
//! ```text
//! aws [global-flags...] <service> <verb> [verb-args...]
//! ```
//!
//! Global flags (e.g. `--region`, `--profile`, `--output`, `--no-cli-pager`,
//! `--debug`, `--endpoint-url`) may appear before, between, or after the
//! service/verb tokens. We strip them — including their values for the
//! flags that take one — before pattern-matching, so classification is
//! stable under flag reordering.
//!
//! Coverage (mutating verbs are gated; read-only verbs passthrough as `None`):
//!
//! | argv prefix                                  | action_key                                       |
//! |----------------------------------------------|--------------------------------------------------|
//! | `s3 cp\|sync\|rm\|mv`                          | `aws.s3.{cp,sync,rm,mv}`                         |
//! | `s3api put-object\|delete-object\|put-bucket-policy` | `aws.s3api.{put-object,delete-object,put-bucket-policy}` |
//! | `iam create-*\|delete-*\|attach-*\|detach-*\|put-*` | `aws.iam.<verb>` (full verb preserved)           |
//! | `sts assume-role`                            | `aws.sts.assume-role`                            |
//! | `secretsmanager create-secret\|update-secret\|delete-secret\|put-secret-value` | `aws.secretsmanager.<verb>`                      |
//! | `kms create-key\|schedule-key-deletion\|encrypt\|decrypt` | `aws.kms.<verb>`                                 |
//! | `ec2 terminate-instances\|delete-volume\|delete-snapshot\|modify-instance-attribute` | `aws.ec2.<verb>`                                 |
//! | `lambda update-function-code\|delete-function\|invoke` | `aws.lambda.<verb>`                              |
//! | `cloudformation deploy\|delete-stack\|update-stack` | `aws.cloudformation.<verb>`                      |
//! | `describe-*\|list-*\|get-*\|ls\|head-object\|...` | `None` (passthrough)                             |
//!
//! Notes:
//!   - `sts assume-role` is classified for audit even though the broker
//!     injects STS-scoped creds upstream; the verb still passes through.
//!   - `s3 rm` / `s3api delete-object` are gated; biometric is required
//!     when the bucket is in the grant's `production_buckets` (handled
//!     daemon-side; the classifier is bucket-agnostic).

use core_construct_runtime::ActionKey;

/// AWS CLI global flags that take a value as the *next* argv token.
/// When stripping, both the flag and its value are removed.
const VALUE_BEARING_GLOBAL_FLAGS: &[&str] = &[
    "--region",
    "--profile",
    "--output",
    "--endpoint-url",
    "--ca-bundle",
    "--cli-read-timeout",
    "--cli-connect-timeout",
    "--cli-binary-format",
    "--cli-auto-prompt",
    "--color",
    "--query",
];

/// AWS CLI global flags that are valueless (boolean toggles).
const BOOLEAN_GLOBAL_FLAGS: &[&str] = &[
    "--no-cli-pager",
    "--no-cli-auto-prompt",
    "--no-paginate",
    "--no-sign-request",
    "--no-verify-ssl",
    "--debug",
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

/// Returns `true` if `verb` starts with any of `prefixes` followed by `-`
/// (or equals one of them outright).
fn matches_prefix(verb: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| {
        if verb == *p {
            true
        } else if let Some(rest) = verb.strip_prefix(p) {
            rest.starts_with('-')
        } else {
            false
        }
    })
}

/// Returns `true` if `verb` looks like a read-only AWS CLI verb.
///
/// Read-only verbs match `describe-*`, `list-*`, `get-*`, plus the
/// service-specific aliases `ls` (s3) and `head-object` (s3api).
fn is_read_only_verb(verb: &str) -> bool {
    if matches_prefix(verb, &["describe", "list", "get"]) {
        return true;
    }
    matches!(verb, "ls" | "head-object" | "head-bucket" | "help")
}

/// Classify `aws <service> <verb> ...` argv into an action_key.
///
/// Returns `None` for read-only / unrecognized shapes — the runtime
/// treats `None` as passthrough (no broker mediation).
pub fn classify_aws_argv(argv: &[String]) -> Option<ActionKey> {
    let stripped = strip_global_flags(argv);

    let service = stripped.first()?.as_str();
    let verb = stripped.get(1).map(|s| s.as_str())?;

    // Read-only verbs always passthrough, regardless of service.
    if is_read_only_verb(verb) {
        return None;
    }

    match service {
        // s3 — high-level mutating verbs.
        "s3" => match verb {
            "cp" => Some(ActionKey("aws.s3.cp".to_string())),
            "sync" => Some(ActionKey("aws.s3.sync".to_string())),
            "rm" => Some(ActionKey("aws.s3.rm".to_string())),
            "mv" => Some(ActionKey("aws.s3.mv".to_string())),
            // s3 ls / mb / rb / website / presign — passthrough or
            // out-of-scope; daemon re-classifies.
            _ => None,
        },

        // s3api — low-level API verbs.
        "s3api" => match verb {
            "put-object" => Some(ActionKey("aws.s3api.put-object".to_string())),
            "delete-object" => Some(ActionKey("aws.s3api.delete-object".to_string())),
            "put-bucket-policy" => Some(ActionKey("aws.s3api.put-bucket-policy".to_string())),
            _ => None,
        },

        // iam — privilege management. Any verb starting with create-,
        // delete-, attach-, detach-, or put- gets classified.
        "iam" => {
            if matches_prefix(verb, &["create", "delete", "attach", "detach", "put"]) {
                Some(ActionKey(format!("aws.iam.{verb}")))
            } else {
                None
            }
        }

        // sts — only assume-role is classified (for audit).
        "sts" => match verb {
            "assume-role" => Some(ActionKey("aws.sts.assume-role".to_string())),
            _ => None,
        },

        // secretsmanager — secret mutations.
        "secretsmanager" => match verb {
            "create-secret" | "update-secret" | "delete-secret" | "put-secret-value" => {
                Some(ActionKey(format!("aws.secretsmanager.{verb}")))
            }
            _ => None,
        },

        // kms — key lifecycle and crypto ops.
        "kms" => match verb {
            "create-key" | "schedule-key-deletion" | "encrypt" | "decrypt" => {
                Some(ActionKey(format!("aws.kms.{verb}")))
            }
            _ => None,
        },

        // ec2 — destructive instance/volume/snapshot ops.
        "ec2" => match verb {
            "terminate-instances"
            | "delete-volume"
            | "delete-snapshot"
            | "modify-instance-attribute" => Some(ActionKey(format!("aws.ec2.{verb}"))),
            _ => None,
        },

        // lambda — function lifecycle + invoke.
        "lambda" => match verb {
            "update-function-code" | "delete-function" | "invoke" => {
                Some(ActionKey(format!("aws.lambda.{verb}")))
            }
            _ => None,
        },

        // cloudformation — stack lifecycle.
        "cloudformation" => match verb {
            "deploy" | "delete-stack" | "update-stack" => {
                Some(ActionKey(format!("aws.cloudformation.{verb}")))
            }
            _ => None,
        },

        // Unknown service → passthrough; daemon re-classifies.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // --- s3 high-level ---

    #[test]
    fn s3_cp_classified() {
        let r = classify_aws_argv(&args(&["s3", "cp", "src", "s3://b/k"])).unwrap();
        assert_eq!(r.0, "aws.s3.cp");
    }

    #[test]
    fn s3_sync_classified() {
        let r = classify_aws_argv(&args(&["s3", "sync", "src/", "s3://b/"])).unwrap();
        assert_eq!(r.0, "aws.s3.sync");
    }

    #[test]
    fn s3_rm_classified() {
        let r = classify_aws_argv(&args(&["s3", "rm", "s3://b/k"])).unwrap();
        assert_eq!(r.0, "aws.s3.rm");
    }

    #[test]
    fn s3_mv_classified() {
        let r = classify_aws_argv(&args(&["s3", "mv", "s3://a/k", "s3://b/k"])).unwrap();
        assert_eq!(r.0, "aws.s3.mv");
    }

    #[test]
    fn s3_ls_passthrough() {
        assert!(classify_aws_argv(&args(&["s3", "ls", "s3://b"])).is_none());
    }

    // --- s3api low-level ---

    #[test]
    fn s3api_put_object_classified() {
        let r = classify_aws_argv(&args(&[
            "s3api",
            "put-object",
            "--bucket",
            "b",
            "--key",
            "k",
        ]))
        .unwrap();
        assert_eq!(r.0, "aws.s3api.put-object");
    }

    #[test]
    fn s3api_delete_object_classified() {
        let r = classify_aws_argv(&args(&["s3api", "delete-object"])).unwrap();
        assert_eq!(r.0, "aws.s3api.delete-object");
    }

    #[test]
    fn s3api_put_bucket_policy_classified() {
        let r = classify_aws_argv(&args(&["s3api", "put-bucket-policy"])).unwrap();
        assert_eq!(r.0, "aws.s3api.put-bucket-policy");
    }

    #[test]
    fn s3api_get_object_passthrough() {
        assert!(classify_aws_argv(&args(&["s3api", "get-object"])).is_none());
    }

    #[test]
    fn s3api_head_object_passthrough() {
        assert!(classify_aws_argv(&args(&["s3api", "head-object"])).is_none());
    }

    #[test]
    fn s3api_list_objects_passthrough() {
        assert!(classify_aws_argv(&args(&["s3api", "list-objects-v2"])).is_none());
    }

    // --- iam (prefix-based) ---

    #[test]
    fn iam_create_user_classified() {
        let r = classify_aws_argv(&args(&["iam", "create-user", "--user-name", "u"])).unwrap();
        assert_eq!(r.0, "aws.iam.create-user");
    }

    #[test]
    fn iam_delete_role_classified() {
        let r = classify_aws_argv(&args(&["iam", "delete-role", "--role-name", "r"])).unwrap();
        assert_eq!(r.0, "aws.iam.delete-role");
    }

    #[test]
    fn iam_attach_role_policy_classified() {
        let r = classify_aws_argv(&args(&["iam", "attach-role-policy"])).unwrap();
        assert_eq!(r.0, "aws.iam.attach-role-policy");
    }

    #[test]
    fn iam_detach_user_policy_classified() {
        let r = classify_aws_argv(&args(&["iam", "detach-user-policy"])).unwrap();
        assert_eq!(r.0, "aws.iam.detach-user-policy");
    }

    #[test]
    fn iam_put_user_policy_classified() {
        let r = classify_aws_argv(&args(&["iam", "put-user-policy"])).unwrap();
        assert_eq!(r.0, "aws.iam.put-user-policy");
    }

    #[test]
    fn iam_list_users_passthrough() {
        assert!(classify_aws_argv(&args(&["iam", "list-users"])).is_none());
    }

    #[test]
    fn iam_get_user_passthrough() {
        assert!(classify_aws_argv(&args(&["iam", "get-user"])).is_none());
    }

    // --- sts ---

    #[test]
    fn sts_assume_role_classified() {
        let r = classify_aws_argv(&args(&[
            "sts",
            "assume-role",
            "--role-arn",
            "arn:aws:iam::123:role/r",
            "--role-session-name",
            "s",
        ]))
        .unwrap();
        assert_eq!(r.0, "aws.sts.assume-role");
    }

    #[test]
    fn sts_get_caller_identity_passthrough() {
        assert!(classify_aws_argv(&args(&["sts", "get-caller-identity"])).is_none());
    }

    // --- secretsmanager ---

    #[test]
    fn secretsmanager_create_secret_classified() {
        let r = classify_aws_argv(&args(&["secretsmanager", "create-secret"])).unwrap();
        assert_eq!(r.0, "aws.secretsmanager.create-secret");
    }

    #[test]
    fn secretsmanager_update_secret_classified() {
        let r = classify_aws_argv(&args(&["secretsmanager", "update-secret"])).unwrap();
        assert_eq!(r.0, "aws.secretsmanager.update-secret");
    }

    #[test]
    fn secretsmanager_delete_secret_classified() {
        let r = classify_aws_argv(&args(&["secretsmanager", "delete-secret"])).unwrap();
        assert_eq!(r.0, "aws.secretsmanager.delete-secret");
    }

    #[test]
    fn secretsmanager_put_secret_value_classified() {
        let r = classify_aws_argv(&args(&["secretsmanager", "put-secret-value"])).unwrap();
        assert_eq!(r.0, "aws.secretsmanager.put-secret-value");
    }

    #[test]
    fn secretsmanager_get_secret_value_passthrough() {
        assert!(classify_aws_argv(&args(&["secretsmanager", "get-secret-value"])).is_none());
    }

    // --- kms ---

    #[test]
    fn kms_create_key_classified() {
        let r = classify_aws_argv(&args(&["kms", "create-key"])).unwrap();
        assert_eq!(r.0, "aws.kms.create-key");
    }

    #[test]
    fn kms_schedule_key_deletion_classified() {
        let r = classify_aws_argv(&args(&["kms", "schedule-key-deletion"])).unwrap();
        assert_eq!(r.0, "aws.kms.schedule-key-deletion");
    }

    #[test]
    fn kms_encrypt_classified() {
        let r = classify_aws_argv(&args(&["kms", "encrypt"])).unwrap();
        assert_eq!(r.0, "aws.kms.encrypt");
    }

    #[test]
    fn kms_decrypt_classified() {
        let r = classify_aws_argv(&args(&["kms", "decrypt"])).unwrap();
        assert_eq!(r.0, "aws.kms.decrypt");
    }

    #[test]
    fn kms_list_keys_passthrough() {
        assert!(classify_aws_argv(&args(&["kms", "list-keys"])).is_none());
    }

    // --- ec2 ---

    #[test]
    fn ec2_terminate_instances_classified() {
        let r = classify_aws_argv(&args(&["ec2", "terminate-instances"])).unwrap();
        assert_eq!(r.0, "aws.ec2.terminate-instances");
    }

    #[test]
    fn ec2_delete_volume_classified() {
        let r = classify_aws_argv(&args(&["ec2", "delete-volume"])).unwrap();
        assert_eq!(r.0, "aws.ec2.delete-volume");
    }

    #[test]
    fn ec2_delete_snapshot_classified() {
        let r = classify_aws_argv(&args(&["ec2", "delete-snapshot"])).unwrap();
        assert_eq!(r.0, "aws.ec2.delete-snapshot");
    }

    #[test]
    fn ec2_modify_instance_attribute_classified() {
        let r = classify_aws_argv(&args(&["ec2", "modify-instance-attribute"])).unwrap();
        assert_eq!(r.0, "aws.ec2.modify-instance-attribute");
    }

    #[test]
    fn ec2_describe_instances_passthrough() {
        assert!(classify_aws_argv(&args(&["ec2", "describe-instances"])).is_none());
    }

    // --- lambda ---

    #[test]
    fn lambda_update_function_code_classified() {
        let r = classify_aws_argv(&args(&["lambda", "update-function-code"])).unwrap();
        assert_eq!(r.0, "aws.lambda.update-function-code");
    }

    #[test]
    fn lambda_delete_function_classified() {
        let r = classify_aws_argv(&args(&["lambda", "delete-function"])).unwrap();
        assert_eq!(r.0, "aws.lambda.delete-function");
    }

    #[test]
    fn lambda_invoke_classified() {
        let r = classify_aws_argv(&args(&["lambda", "invoke", "--function-name", "f"])).unwrap();
        assert_eq!(r.0, "aws.lambda.invoke");
    }

    #[test]
    fn lambda_list_functions_passthrough() {
        assert!(classify_aws_argv(&args(&["lambda", "list-functions"])).is_none());
    }

    // --- cloudformation ---

    #[test]
    fn cloudformation_deploy_classified() {
        let r = classify_aws_argv(&args(&["cloudformation", "deploy"])).unwrap();
        assert_eq!(r.0, "aws.cloudformation.deploy");
    }

    #[test]
    fn cloudformation_delete_stack_classified() {
        let r = classify_aws_argv(&args(&["cloudformation", "delete-stack"])).unwrap();
        assert_eq!(r.0, "aws.cloudformation.delete-stack");
    }

    #[test]
    fn cloudformation_update_stack_classified() {
        let r = classify_aws_argv(&args(&["cloudformation", "update-stack"])).unwrap();
        assert_eq!(r.0, "aws.cloudformation.update-stack");
    }

    #[test]
    fn cloudformation_describe_stacks_passthrough() {
        assert!(classify_aws_argv(&args(&["cloudformation", "describe-stacks"])).is_none());
    }

    // --- global flag stripping ---

    #[test]
    fn region_flag_before_service_stripped() {
        let r =
            classify_aws_argv(&args(&["--region", "us-east-1", "s3", "rm", "s3://b/k"])).unwrap();
        assert_eq!(r.0, "aws.s3.rm");
    }

    #[test]
    fn profile_flag_between_service_and_verb_stripped() {
        let r = classify_aws_argv(&args(&["s3", "--profile", "prod", "rm", "s3://b/k"])).unwrap();
        assert_eq!(r.0, "aws.s3.rm");
    }

    #[test]
    fn output_flag_after_verb_stripped() {
        let r = classify_aws_argv(&args(&["iam", "delete-role", "--output", "json"])).unwrap();
        assert_eq!(r.0, "aws.iam.delete-role");
    }

    #[test]
    fn no_cli_pager_boolean_flag_stripped() {
        let r = classify_aws_argv(&args(&["--no-cli-pager", "kms", "decrypt"])).unwrap();
        assert_eq!(r.0, "aws.kms.decrypt");
    }

    #[test]
    fn equals_form_region_flag_stripped() {
        let r = classify_aws_argv(&args(&["--region=us-west-2", "ec2", "terminate-instances"]))
            .unwrap();
        assert_eq!(r.0, "aws.ec2.terminate-instances");
    }

    #[test]
    fn equals_form_profile_flag_stripped() {
        let r = classify_aws_argv(&args(&["s3api", "--profile=p", "delete-object"])).unwrap();
        assert_eq!(r.0, "aws.s3api.delete-object");
    }

    #[test]
    fn debug_boolean_flag_stripped() {
        let r = classify_aws_argv(&args(&["--debug", "lambda", "delete-function"])).unwrap();
        assert_eq!(r.0, "aws.lambda.delete-function");
    }

    #[test]
    fn multiple_global_flags_stripped() {
        let r = classify_aws_argv(&args(&[
            "--region",
            "eu-west-1",
            "--profile",
            "prod",
            "--no-cli-pager",
            "iam",
            "create-policy",
        ]))
        .unwrap();
        assert_eq!(r.0, "aws.iam.create-policy");
    }

    #[test]
    fn flags_reordered_classification_stable() {
        let a =
            classify_aws_argv(&args(&["s3", "rm", "s3://b/k", "--region", "us-east-1"])).unwrap();
        let b =
            classify_aws_argv(&args(&["--region", "us-east-1", "s3", "rm", "s3://b/k"])).unwrap();
        let c =
            classify_aws_argv(&args(&["s3", "--region", "us-east-1", "rm", "s3://b/k"])).unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(b.0, c.0);
    }

    // --- unknown / empty / corner cases ---

    #[test]
    fn empty_argv_passthrough() {
        assert!(classify_aws_argv(&[]).is_none());
    }

    #[test]
    fn only_global_flags_passthrough() {
        assert!(classify_aws_argv(&args(&["--region", "us-east-1", "--debug"])).is_none());
    }

    #[test]
    fn unknown_service_passthrough() {
        assert!(classify_aws_argv(&args(&["dynamodb", "put-item"])).is_none());
    }

    #[test]
    fn service_without_verb_passthrough() {
        assert!(classify_aws_argv(&args(&["s3"])).is_none());
    }

    #[test]
    fn iam_unknown_verb_passthrough() {
        // `simulate-principal-policy` doesn't start with our prefixes;
        // passthrough.
        assert!(classify_aws_argv(&args(&["iam", "simulate-principal-policy"])).is_none());
    }

    #[test]
    fn iam_create_word_only_classifies() {
        // exact-match `create` (no hyphen) is not a real AWS verb but
        // should still classify as `aws.iam.create` by the prefix rule.
        let r = classify_aws_argv(&args(&["iam", "create"])).unwrap();
        assert_eq!(r.0, "aws.iam.create");
    }

    #[test]
    fn iam_creator_does_not_classify() {
        // `creator` starts with `create` but doesn't have the `-`
        // separator; must NOT classify.
        assert!(classify_aws_argv(&args(&["iam", "creator-check"])).is_none());
    }

    #[test]
    fn read_only_iam_get_passthrough() {
        // `get-user` is read-only even though iam is the service.
        assert!(classify_aws_argv(&args(&["iam", "get-role"])).is_none());
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
            let _ = classify_aws_argv(&argv);
        }

        /// Inserting a recognized global flag (with value) into a known
        /// classified argv must not change the classification.
        #[test]
        fn fuzz_region_flag_insertion_stable(
            insert_at in 0usize..6,
            region in "[a-z]{2}-[a-z]+-[0-9]"
        ) {
            let base = vec![
                "s3".to_string(),
                "rm".to_string(),
                "s3://b/k".to_string(),
            ];
            let base_class = classify_aws_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, region.clone());
            with_flag.insert(pos, "--region".to_string());

            let class2 = classify_aws_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }

        /// Inserting a boolean global flag at any position into a known
        /// classified argv must not change the classification.
        #[test]
        fn fuzz_boolean_flag_insertion_stable(insert_at in 0usize..6) {
            let base = vec![
                "iam".to_string(),
                "delete-role".to_string(),
            ];
            let base_class = classify_aws_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, "--debug".to_string());

            let class2 = classify_aws_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }
    }

    // --- T2: integration with MockBroker for BrokerProvider::AwsSts ---
    //
    // The full broker_exec lifecycle lives in the daemon; here we cover the
    // contract slice this Construct depends on: the broker registry can
    // hold a `MockBroker::new(BrokerProvider::AwsSts)`, and a request that
    // declares `provider = AwsSts` round-trips through issue → revoke
    // without panicking. Real STS impl is implementation-note-81 (separate task).

    use core_broker::{Broker, BrokerError, BrokerProvider, BrokerRequest, MockBroker};
    use std::time::Duration;

    fn aws_sts_request(ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::AwsSts,
            scope: serde_json::json!({
                "role_arn": "arn:aws:iam::123456789012:role/EmberAgentRole",
                "session_name": "ember-agent-session",
                "actions": ["s3:GetObject", "s3:PutObject"],
            }),
            ttl: Duration::from_secs(ttl_secs),
            reason: "ember-aws integration test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    #[tokio::test]
    async fn mock_broker_aws_sts_issue_revoke_roundtrip() {
        let broker = MockBroker::new(BrokerProvider::AwsSts);
        assert_eq!(broker.provider(), BrokerProvider::AwsSts);

        let creds = broker
            .issue(aws_sts_request(900))
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
    async fn mock_broker_aws_sts_rejects_wrong_provider() {
        let broker = MockBroker::new(BrokerProvider::AwsSts);
        let mut req = aws_sts_request(900);
        req.provider = BrokerProvider::Cloudflare;

        let err = broker.issue(req).await.expect_err("provider mismatch");
        match err {
            BrokerError::InvalidScope(_) => {}
            other => panic!("expected InvalidScope, got {other:?}"),
        }
    }
}
