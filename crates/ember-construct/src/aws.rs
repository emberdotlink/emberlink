//! Argv classifier: maps `aws <service> <verb> ...` to a `construct.toml`
//! action_key. Per ADR 124 §3 — this lives shim-side BUT the daemon
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
//! Coverage (mutating verbs are gated; read-only verbs currently passthrough
//! as `None` for compatibility):
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
//! | `describe-*\|list-*\|get-*\|ls\|head-object\|...` | `None` (current compatibility path; P24 disposition is `credentialless`) |
//!
//! Notes:
//!   - `sts assume-role` is classified for audit even though the broker
//!     injects STS-scoped creds upstream; the verb still passes through.
//!   - `s3 rm` / `s3api delete-object` are gated; biometric is required
//!     when the bucket is in the grant's `production_buckets` (handled
//!     daemon-side; the classifier is bucket-agnostic).

use core_broker::project::{
    AwsAction, AwsCondition, AwsConditionKey, AwsConditionOperator, AwsPermissionEffect,
    AwsPermissionSpec,
};
use core_construct_runtime::ActionKey;
use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};
use core_grant_types::ResourceSelector;

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

/// Global flags that affect credential source, provider endpoint, or signing
/// posture and therefore are not harmless under the P24 factory contract.
const UNSAFE_FACTORY_GLOBAL_FLAGS: &[&str] = &["--profile", "--endpoint-url", "--no-sign-request"];

/// AWS implementation of the provider-generic construct-factory contract.
#[derive(Debug, Clone, Copy, Default)]
pub struct AwsFactory;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsFactoryTarget {
    pub provider: &'static str,
    pub resources: Vec<ResourceSelector>,
}

impl AwsFactoryTarget {
    fn from_permission_specs(specs: &[AwsPermissionSpec]) -> Option<Self> {
        let resources: Vec<ResourceSelector> = specs
            .iter()
            .flat_map(|spec| spec.resources.iter().cloned())
            .collect();
        if resources.is_empty() {
            None
        } else {
            Some(Self {
                provider: "aws",
                resources,
            })
        }
    }
}

impl InvocationGrammar for AwsFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_aws_argv(argv)
    }
}

impl TargetExtractor for AwsFactory {
    type Target = AwsFactoryTarget;

    fn target_for_argv(&self, action_key: &ActionKey, argv: &[String]) -> Option<Self::Target> {
        AwsFactoryTarget::from_permission_specs(&aws_permission_specs_for_argv(
            &action_key.0,
            argv,
        )?)
    }
}

impl NeedTemplate for AwsFactory {
    type Need = Vec<AwsPermissionSpec>;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        _target: &Self::Target,
        argv: &[String],
    ) -> Option<Self::Need> {
        let specs = aws_permission_specs_for_argv(&action_key.0, argv)?;
        if specs.is_empty() { None } else { Some(specs) }
    }
}

impl ConstructFactory for AwsFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> FactoryDisposition {
        aws_factory_disposition_for_argv(action_key.map(|key| key.0.as_str()), argv)
    }
}

/// Classify an AWS argv shape into the P24 factory disposition vocabulary.
///
/// This is the conformance-corpus view of the existing parser. It deliberately
/// does not change [`classify_aws_argv`]'s compatibility behavior yet; S3 uses
/// it to inventory current coverage and make fail-closed gaps explicit before
/// a future runtime cutover.
pub fn aws_factory_disposition_for_argv(
    action_key: Option<&str>,
    argv: &[String],
) -> FactoryDisposition {
    if has_unsafe_factory_global_flag(argv) {
        return FactoryDisposition::UnsupportedFailClosed;
    }

    if has_payload_analysis_required_shape(argv) {
        return FactoryDisposition::PayloadAnalysisRequired;
    }

    let stripped = strip_global_flags(argv);
    if let Some(action_key) = action_key {
        if aws_permission_specs_for_argv(action_key, argv).is_some() {
            return FactoryDisposition::Mediated;
        }
        if resolver_required_shape(action_key, &stripped) {
            return FactoryDisposition::ResolverRequired;
        }
        if payload_analysis_required_action(action_key) {
            return FactoryDisposition::PayloadAnalysisRequired;
        }
        return FactoryDisposition::UnsupportedFailClosed;
    }

    match stripped.get(1).map(String::as_str) {
        Some(verb) if is_read_only_verb(verb) => FactoryDisposition::Credentialless,
        _ => FactoryDisposition::UnsupportedFailClosed,
    }
}

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

fn has_unsafe_factory_global_flag(argv: &[String]) -> bool {
    argv.iter().any(|token| {
        UNSAFE_FACTORY_GLOBAL_FLAGS
            .iter()
            .any(|flag| token == flag || token.starts_with(&format!("{flag}=")))
    })
}

fn has_payload_analysis_required_shape(argv: &[String]) -> bool {
    argv.iter().any(|token| {
        matches!(
            token.as_str(),
            "--cli-input-json"
                | "--cli-input-yaml"
                | "--policy"
                | "--policy-document"
                | "--assume-role-policy-document"
                | "--template-body"
                | "--template-file"
        ) || token.starts_with("--cli-input-json=")
            || token.starts_with("--cli-input-yaml=")
            || token.starts_with("--policy=")
            || token.starts_with("--policy-document=")
            || token.starts_with("--assume-role-policy-document=")
            || token.starts_with("--template-body=")
            || token.starts_with("--template-file=")
            || token.starts_with("file://")
            || token.starts_with("fileb://")
    })
}

fn payload_analysis_required_action(action_key: &str) -> bool {
    matches!(
        action_key,
        "aws.cloudformation.deploy"
            | "aws.iam.create-policy"
            | "aws.iam.create-role"
            | "aws.iam.put-user-policy"
            | "aws.iam.put-role-policy"
            | "aws.iam.put-group-policy"
            | "aws.s3api.put-bucket-policy"
    )
}

fn resolver_required_shape(action_key: &str, argv: &[String]) -> bool {
    match action_key {
        "aws.lambda.invoke" | "aws.lambda.update-function-code" | "aws.lambda.delete-function" => {
            option_value(argv.get(2..).unwrap_or_default(), "--function-name")
                .map(|value| lambda_function_resource(&value).is_none())
                .unwrap_or(true)
        }
        "aws.kms.encrypt" | "aws.kms.decrypt" | "aws.kms.schedule-key-deletion" => {
            option_value(argv.get(2..).unwrap_or_default(), "--key-id")
                .map(|value| kms_key_resource(&value).is_none())
                .unwrap_or(true)
        }
        "aws.cloudformation.delete-stack" | "aws.cloudformation.update-stack" => {
            option_value(argv.get(2..).unwrap_or_default(), "--stack-name")
                .map(|value| cloudformation_stack_resource(&value).is_none())
                .unwrap_or(true)
        }
        "aws.secretsmanager.update-secret"
        | "aws.secretsmanager.delete-secret"
        | "aws.secretsmanager.put-secret-value" => {
            option_value(argv.get(2..).unwrap_or_default(), "--secret-id")
                .map(|value| secretsmanager_secret_resource(&value).is_none())
                .unwrap_or(true)
        }
        _ => false,
    }
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

/// Parse daemon-classified AWS argv into the typed, need-side PermissionSpec
/// that the daemon can compare against grants before projecting native STS
/// scope.
///
/// This is deliberately narrower than [`classify_aws_argv`]. Classification
/// answers "is this a mutating AWS action for audit/gating?" PermissionSpec
/// parsing answers "can the daemon identify exact resources for a bounded
/// credential mint?" Unhandled shapes return `None` so the daemon mints
/// nothing rather than falling back to ambient or full-role AWS credentials.
pub fn aws_permission_specs_for_argv(
    action_key: &str,
    argv: &[String],
) -> Option<Vec<AwsPermissionSpec>> {
    let stripped = strip_global_flags(argv);
    let spec = match action_key {
        "aws.s3.cp" => s3_cp_permission_spec(&stripped)?,
        "aws.s3.sync" => return s3_sync_permission_specs(&stripped),
        "aws.s3.mv" => return s3_mv_permission_specs(&stripped),
        "aws.s3.rm" => s3_rm_permission_spec(&stripped)?,
        "aws.s3api.put-object" => {
            s3api_object_permission_spec(&stripped, "put-object", AwsAction::S3PutObject)?
        }
        "aws.s3api.delete-object" => {
            s3api_object_permission_spec(&stripped, "delete-object", AwsAction::S3DeleteObject)?
        }
        "aws.s3api.put-bucket-policy" => s3api_bucket_permission_spec(
            &stripped,
            "put-bucket-policy",
            AwsAction::S3PutBucketPolicy,
        )?,
        "aws.lambda.invoke" => {
            lambda_function_permission_spec(&stripped, "invoke", AwsAction::LambdaInvokeFunction)?
        }
        "aws.lambda.update-function-code" => lambda_function_permission_spec(
            &stripped,
            "update-function-code",
            AwsAction::LambdaUpdateFunctionCode,
        )?,
        "aws.lambda.delete-function" => lambda_function_permission_spec(
            &stripped,
            "delete-function",
            AwsAction::LambdaDeleteFunction,
        )?,
        "aws.kms.encrypt" => kms_key_permission_spec(&stripped, "encrypt", AwsAction::KmsEncrypt)?,
        "aws.kms.decrypt" => kms_key_permission_spec(&stripped, "decrypt", AwsAction::KmsDecrypt)?,
        "aws.kms.schedule-key-deletion" => kms_key_permission_spec(
            &stripped,
            "schedule-key-deletion",
            AwsAction::KmsScheduleKeyDeletion,
        )?,
        "aws.cloudformation.delete-stack" => cloudformation_stack_permission_spec(
            &stripped,
            "delete-stack",
            AwsAction::CloudFormationDeleteStack,
        )?,
        "aws.cloudformation.update-stack" => cloudformation_stack_permission_spec(
            &stripped,
            "update-stack",
            AwsAction::CloudFormationUpdateStack,
        )?,
        "aws.secretsmanager.update-secret" => secretsmanager_secret_permission_spec(
            &stripped,
            "update-secret",
            AwsAction::SecretsManagerUpdateSecret,
        )?,
        "aws.secretsmanager.delete-secret" => secretsmanager_secret_permission_spec(
            &stripped,
            "delete-secret",
            AwsAction::SecretsManagerDeleteSecret,
        )?,
        "aws.secretsmanager.put-secret-value" => secretsmanager_secret_permission_spec(
            &stripped,
            "put-secret-value",
            AwsAction::SecretsManagerPutSecretValue,
        )?,
        _ => return None,
    };
    Some(vec![spec])
}

fn s3_cp_permission_spec(argv: &[String]) -> Option<AwsPermissionSpec> {
    if argv.len() != 4 || argv.first()? != "s3" || argv.get(1)? != "cp" {
        return None;
    }
    let src = argv.get(2)?;
    let dst = argv.get(3)?;
    if src.starts_with("s3://") {
        return None;
    }
    let (bucket, key) = parse_s3_exact_object_uri(dst)?;
    Some(allow_spec(
        AwsAction::S3PutObject,
        s3_object_resource(&bucket, &key)?,
    ))
}

fn s3_rm_permission_spec(argv: &[String]) -> Option<AwsPermissionSpec> {
    if argv.len() != 3 || argv.first()? != "s3" || argv.get(1)? != "rm" {
        return None;
    }
    let (bucket, key) = parse_s3_exact_object_uri(argv.get(2)?)?;
    Some(allow_spec(
        AwsAction::S3DeleteObject,
        s3_object_resource(&bucket, &key)?,
    ))
}

fn s3_mv_permission_specs(argv: &[String]) -> Option<Vec<AwsPermissionSpec>> {
    let (src, dst, recursive) = parse_s3_mv_args(argv)?;
    if recursive {
        return s3_recursive_mv_permission_specs(src, dst);
    }

    let src_is_s3 = src.starts_with("s3://");
    let dst_is_s3 = dst.starts_with("s3://");
    if !src_is_s3 && !dst_is_s3 {
        return None;
    }

    let src_resource = if src_is_s3 {
        let (bucket, key) = parse_s3_exact_object_uri(src)?;
        Some(s3_object_resource(&bucket, &key)?)
    } else {
        None
    };
    let dst_resource = if dst_is_s3 {
        let (bucket, key) = parse_s3_exact_object_uri(dst)?;
        Some(s3_object_resource(&bucket, &key)?)
    } else {
        None
    };

    let mut specs = Vec::new();
    if let Some(resource) = &src_resource {
        specs.push(allow_spec(AwsAction::S3GetObject, resource.clone()));
    }
    if let Some(resource) = dst_resource {
        specs.push(allow_spec(AwsAction::S3PutObject, resource));
    }
    if let Some(resource) = src_resource {
        specs.push(allow_spec(AwsAction::S3DeleteObject, resource));
    }
    Some(specs)
}

fn s3_recursive_mv_permission_specs(src: &str, dst: &str) -> Option<Vec<AwsPermissionSpec>> {
    let src_is_s3 = src.starts_with("s3://");
    let dst_is_s3 = dst.starts_with("s3://");
    if !src_is_s3 && !dst_is_s3 {
        return None;
    }

    match (src_is_s3, dst_is_s3) {
        (false, true) => {
            let (bucket, prefix) = parse_s3_prefix_uri(dst)?;
            Some(vec![allow_spec(
                AwsAction::S3PutObject,
                s3_prefix_resource(&bucket, &prefix)?,
            )])
        }
        (true, false) => {
            let (bucket, prefix) = parse_s3_prefix_uri(src)?;
            Some(vec![
                s3_list_prefix_permission_spec(&bucket, &prefix)?,
                allow_spec(
                    AwsAction::S3GetObject,
                    s3_prefix_resource(&bucket, &prefix)?,
                ),
                allow_spec(
                    AwsAction::S3DeleteObject,
                    s3_prefix_resource(&bucket, &prefix)?,
                ),
            ])
        }
        (true, true) => {
            let (source_bucket, source_prefix) = parse_s3_prefix_uri(src)?;
            let (dest_bucket, dest_prefix) = parse_s3_prefix_uri(dst)?;
            validate_non_overlapping_s3_prefixes(
                &source_bucket,
                &source_prefix,
                &dest_bucket,
                &dest_prefix,
            )?;
            Some(vec![
                s3_list_prefix_permission_spec(&source_bucket, &source_prefix)?,
                allow_spec(
                    AwsAction::S3GetObject,
                    s3_prefix_resource(&source_bucket, &source_prefix)?,
                ),
                allow_spec(
                    AwsAction::S3PutObject,
                    s3_prefix_resource(&dest_bucket, &dest_prefix)?,
                ),
                allow_spec(
                    AwsAction::S3DeleteObject,
                    s3_prefix_resource(&source_bucket, &source_prefix)?,
                ),
            ])
        }
        _ => None,
    }
}

fn parse_s3_mv_args(argv: &[String]) -> Option<(&str, &str, bool)> {
    if argv.first()? != "s3" || argv.get(1)? != "mv" {
        return None;
    }
    let mut operands = Vec::with_capacity(2);
    let mut recursive = false;
    for token in &argv[2..] {
        match token.as_str() {
            "--recursive" => {
                if recursive {
                    return None;
                }
                recursive = true;
            }
            other if other.starts_with('-') => return None,
            other => operands.push(other),
        }
    }
    match operands.as_slice() {
        [src, dst] => Some((*src, *dst, recursive)),
        _ => None,
    }
}

fn s3_sync_permission_specs(argv: &[String]) -> Option<Vec<AwsPermissionSpec>> {
    let (src, dst, delete) = parse_s3_sync_args(argv)?;
    let src_is_s3 = src.starts_with("s3://");
    let dst_is_s3 = dst.starts_with("s3://");

    match (src_is_s3, dst_is_s3) {
        (false, true) => {
            let (bucket, prefix) = parse_s3_prefix_uri(dst)?;
            let mut specs = vec![
                s3_list_prefix_permission_spec(&bucket, &prefix)?,
                allow_spec(
                    AwsAction::S3PutObject,
                    s3_prefix_resource(&bucket, &prefix)?,
                ),
            ];
            if delete {
                specs.push(allow_spec(
                    AwsAction::S3DeleteObject,
                    s3_prefix_resource(&bucket, &prefix)?,
                ));
            }
            Some(specs)
        }
        (true, false) => {
            let (bucket, prefix) = parse_s3_prefix_uri(src)?;
            Some(vec![
                s3_list_prefix_permission_spec(&bucket, &prefix)?,
                allow_spec(
                    AwsAction::S3GetObject,
                    s3_prefix_resource(&bucket, &prefix)?,
                ),
            ])
        }
        (true, true) => {
            let (source_bucket, source_prefix) = parse_s3_prefix_uri(src)?;
            let (dest_bucket, dest_prefix) = parse_s3_prefix_uri(dst)?;
            validate_non_overlapping_s3_prefixes(
                &source_bucket,
                &source_prefix,
                &dest_bucket,
                &dest_prefix,
            )?;
            let mut specs = vec![
                s3_list_prefix_permission_spec(&source_bucket, &source_prefix)?,
                allow_spec(
                    AwsAction::S3GetObject,
                    s3_prefix_resource(&source_bucket, &source_prefix)?,
                ),
                s3_list_prefix_permission_spec(&dest_bucket, &dest_prefix)?,
                allow_spec(
                    AwsAction::S3PutObject,
                    s3_prefix_resource(&dest_bucket, &dest_prefix)?,
                ),
            ];
            if delete {
                specs.push(allow_spec(
                    AwsAction::S3DeleteObject,
                    s3_prefix_resource(&dest_bucket, &dest_prefix)?,
                ));
            }
            Some(specs)
        }
        _ => None,
    }
}

fn parse_s3_sync_args(argv: &[String]) -> Option<(&str, &str, bool)> {
    if argv.first()? != "s3" || argv.get(1)? != "sync" {
        return None;
    }
    let mut operands = Vec::with_capacity(2);
    let mut delete = false;
    for token in &argv[2..] {
        match token.as_str() {
            "--delete" => {
                if delete {
                    return None;
                }
                delete = true;
            }
            other if other.starts_with('-') => return None,
            other => operands.push(other),
        }
    }
    match operands.as_slice() {
        [src, dst] => Some((*src, *dst, delete)),
        _ => None,
    }
}

fn s3api_object_permission_spec(
    argv: &[String],
    verb: &str,
    action: AwsAction,
) -> Option<AwsPermissionSpec> {
    if argv.first()? != "s3api" || argv.get(1)? != verb {
        return None;
    }
    let args = &argv[2..];
    let bucket = option_value(args, "--bucket")?;
    let key = option_value(args, "--key")?;
    Some(allow_spec(action, s3_object_resource(&bucket, &key)?))
}

fn s3api_bucket_permission_spec(
    argv: &[String],
    verb: &str,
    action: AwsAction,
) -> Option<AwsPermissionSpec> {
    if argv.first()? != "s3api" || argv.get(1)? != verb {
        return None;
    }
    let bucket = option_value(&argv[2..], "--bucket")?;
    Some(allow_spec(action, s3_bucket_resource(&bucket)?))
}

fn lambda_function_permission_spec(
    argv: &[String],
    verb: &str,
    action: AwsAction,
) -> Option<AwsPermissionSpec> {
    if argv.first()? != "lambda" || argv.get(1)? != verb {
        return None;
    }
    let function_arn = option_value(&argv[2..], "--function-name")?;
    Some(allow_spec(action, lambda_function_resource(&function_arn)?))
}

fn kms_key_permission_spec(
    argv: &[String],
    verb: &str,
    action: AwsAction,
) -> Option<AwsPermissionSpec> {
    if argv.first()? != "kms" || argv.get(1)? != verb {
        return None;
    }
    let key_arn = option_value(&argv[2..], "--key-id")?;
    Some(allow_spec(action, kms_key_resource(&key_arn)?))
}

fn cloudformation_stack_permission_spec(
    argv: &[String],
    verb: &str,
    action: AwsAction,
) -> Option<AwsPermissionSpec> {
    if argv.first()? != "cloudformation" || argv.get(1)? != verb {
        return None;
    }
    let stack_arn = option_value(&argv[2..], "--stack-name")?;
    Some(allow_spec(
        action,
        cloudformation_stack_resource(&stack_arn)?,
    ))
}

fn secretsmanager_secret_permission_spec(
    argv: &[String],
    verb: &str,
    action: AwsAction,
) -> Option<AwsPermissionSpec> {
    if argv.first()? != "secretsmanager" || argv.get(1)? != verb {
        return None;
    }
    let secret_arn = option_value(&argv[2..], "--secret-id")?;
    Some(allow_spec(
        action,
        secretsmanager_secret_resource(&secret_arn)?,
    ))
}

fn allow_spec(action: AwsAction, resource: ResourceSelector) -> AwsPermissionSpec {
    allow_spec_with_conditions(action, resource, Vec::new())
}

fn allow_spec_with_conditions(
    action: AwsAction,
    resource: ResourceSelector,
    conditions: Vec<AwsCondition>,
) -> AwsPermissionSpec {
    AwsPermissionSpec {
        effect: AwsPermissionEffect::Allow,
        actions: vec![action],
        resources: vec![resource],
        conditions,
    }
}

fn parse_s3_object_uri(uri: &str) -> Option<(String, String)> {
    let rest = uri.strip_prefix("s3://")?;
    let (bucket, key) = rest.split_once('/')?;
    validate_s3_bucket(bucket)?;
    validate_s3_key(key)?;
    Some((bucket.to_string(), key.to_string()))
}

fn parse_s3_exact_object_uri(uri: &str) -> Option<(String, String)> {
    let (bucket, key) = parse_s3_object_uri(uri)?;
    if key.ends_with('/') {
        return None;
    }
    Some((bucket, key))
}

fn parse_s3_prefix_uri(uri: &str) -> Option<(String, String)> {
    let rest = uri.strip_prefix("s3://")?;
    let (bucket, prefix) = rest.split_once('/')?;
    validate_s3_bucket(bucket)?;
    validate_s3_prefix(prefix)?;
    Some((bucket.to_string(), prefix.to_string()))
}

fn s3_object_resource(bucket: &str, key: &str) -> Option<ResourceSelector> {
    validate_s3_bucket(bucket)?;
    validate_s3_key(key)?;
    Some(ResourceSelector::Exact {
        value: format!("arn:aws:s3:::{bucket}/{key}"),
    })
}

fn s3_bucket_resource(bucket: &str) -> Option<ResourceSelector> {
    validate_s3_bucket(bucket)?;
    Some(ResourceSelector::Exact {
        value: format!("arn:aws:s3:::{bucket}"),
    })
}

fn s3_prefix_resource(bucket: &str, prefix: &str) -> Option<ResourceSelector> {
    validate_s3_bucket(bucket)?;
    validate_s3_prefix(prefix)?;
    Some(ResourceSelector::Glob {
        pattern: format!("arn:aws:s3:::{bucket}/{prefix}*"),
    })
}

fn s3_list_prefix_permission_spec(bucket: &str, prefix: &str) -> Option<AwsPermissionSpec> {
    validate_s3_bucket(bucket)?;
    validate_s3_prefix(prefix)?;
    Some(allow_spec_with_conditions(
        AwsAction::S3ListBucket,
        s3_bucket_resource(bucket)?,
        vec![AwsCondition {
            operator: AwsConditionOperator::StringLike,
            key: AwsConditionKey::S3Prefix,
            values: vec![format!("{prefix}*")],
        }],
    ))
}

fn lambda_function_resource(function_arn: &str) -> Option<ResourceSelector> {
    validate_lambda_function_arn(function_arn)?;
    Some(ResourceSelector::Exact {
        value: function_arn.to_string(),
    })
}

fn kms_key_resource(key_arn: &str) -> Option<ResourceSelector> {
    validate_kms_key_arn(key_arn)?;
    Some(ResourceSelector::Exact {
        value: key_arn.to_string(),
    })
}

fn cloudformation_stack_resource(stack_arn: &str) -> Option<ResourceSelector> {
    validate_cloudformation_stack_arn(stack_arn)?;
    Some(ResourceSelector::Exact {
        value: stack_arn.to_string(),
    })
}

fn secretsmanager_secret_resource(secret_arn: &str) -> Option<ResourceSelector> {
    validate_secretsmanager_secret_arn(secret_arn)?;
    Some(ResourceSelector::Exact {
        value: secret_arn.to_string(),
    })
}

fn validate_s3_bucket(bucket: &str) -> Option<()> {
    if bucket.trim() != bucket
        || bucket.is_empty()
        || bucket.contains('/')
        || bucket.contains('*')
        || bucket.chars().any(char::is_control)
    {
        return None;
    }
    Some(())
}

fn validate_s3_key(key: &str) -> Option<()> {
    if key.trim() != key || key.is_empty() || key.contains('*') || key.chars().any(char::is_control)
    {
        return None;
    }
    Some(())
}

fn validate_s3_prefix(prefix: &str) -> Option<()> {
    if prefix.trim() != prefix
        || !(prefix.is_empty() || prefix.ends_with('/'))
        || prefix.contains('*')
        || prefix.chars().any(char::is_control)
    {
        return None;
    }
    Some(())
}

fn validate_non_overlapping_s3_prefixes(
    source_bucket: &str,
    source_prefix: &str,
    dest_bucket: &str,
    dest_prefix: &str,
) -> Option<()> {
    if source_bucket == dest_bucket
        && (source_prefix.starts_with(dest_prefix) || dest_prefix.starts_with(source_prefix))
    {
        return None;
    }
    Some(())
}

fn validate_lambda_function_arn(function_arn: &str) -> Option<()> {
    if function_arn.trim() != function_arn
        || function_arn.is_empty()
        || function_arn.contains('*')
        || function_arn.chars().any(char::is_control)
        || !function_arn.starts_with("arn:")
        || !function_arn.contains(":lambda:")
        || !function_arn.contains(":function:")
    {
        return None;
    }
    Some(())
}

fn validate_kms_key_arn(key_arn: &str) -> Option<()> {
    if key_arn.trim() != key_arn
        || key_arn.is_empty()
        || key_arn.contains('*')
        || key_arn.chars().any(char::is_control)
        || !key_arn.starts_with("arn:")
        || !key_arn.contains(":kms:")
        || !key_arn.contains(":key/")
    {
        return None;
    }
    Some(())
}

fn validate_cloudformation_stack_arn(stack_arn: &str) -> Option<()> {
    if stack_arn.trim() != stack_arn
        || stack_arn.is_empty()
        || stack_arn.contains('*')
        || stack_arn.bytes().any(|b| b.is_ascii_whitespace())
        || stack_arn.chars().any(char::is_control)
    {
        return None;
    }

    let mut parts = stack_arn.splitn(6, ':');
    let arn = parts.next()?;
    let partition = parts.next()?;
    let service = parts.next()?;
    let region = parts.next()?;
    let account = parts.next()?;
    let resource = parts.next()?;
    if arn != "arn"
        || partition.is_empty()
        || !partition
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || service != "cloudformation"
        || region.is_empty()
        || !region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || account.len() != 12
        || !account.bytes().all(|b| b.is_ascii_digit())
        || resource.contains(':')
    {
        return None;
    }

    let stack = resource.strip_prefix("stack/")?;
    let (name, id) = stack.split_once('/')?;
    let name_is_valid = name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && name
            .bytes()
            .next()
            .map(|b| b.is_ascii_alphabetic())
            .unwrap_or(false);
    let id_is_valid = id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if name.is_empty() || id.is_empty() || id.contains('/') || !name_is_valid || !id_is_valid {
        return None;
    }
    Some(())
}

fn validate_secretsmanager_secret_arn(secret_arn: &str) -> Option<()> {
    if secret_arn.trim() != secret_arn
        || secret_arn.is_empty()
        || secret_arn.contains('*')
        || secret_arn.chars().any(char::is_control)
        || !secret_arn.starts_with("arn:")
        || !secret_arn.contains(":secretsmanager:")
        || !secret_arn.contains(":secret:")
    {
        return None;
    }
    Some(())
}

fn option_value(args: &[String], name: &str) -> Option<String> {
    let equals_prefix = format!("{name}=");
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let token = &args[i];
        if let Some(value) = token.strip_prefix(&equals_prefix) {
            set_single_option(&mut out, value)?;
        } else if token == name {
            let value = args.get(i + 1)?;
            if value.starts_with("--") {
                return None;
            }
            set_single_option(&mut out, value)?;
            i += 1;
        }
        i += 1;
    }
    out
}

fn set_single_option(out: &mut Option<String>, value: &str) -> Option<()> {
    if out.is_some() || value.trim() != value || value.is_empty() {
        return None;
    }
    *out = Some(value.to_string());
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn aws_factory_contract_runs_existing_conformance_corpus() {
        let corpus = core_construct_runtime::factory::parse_factory_fixture_corpus(include_str!(
            "../conformance/aws/factory-fixtures.toml"
        ))
        .expect("fixture corpus parses");
        let validation_errors =
            core_construct_runtime::factory::validate_factory_fixture_corpus(&corpus);
        assert!(validation_errors.is_empty(), "{validation_errors:#?}");

        let carrier = core_construct_runtime::factory::ActionManifestV2Carrier::parse(
            include_str!("../construct/aws.toml"),
        )
        .expect("aws manifest carrier parses");
        let report = core_construct_runtime::factory::run_factory_fixtures(
            &AwsFactory,
            Some(&carrier),
            &corpus,
        );
        assert!(report.is_clean(), "{:#?}", report.failures);
    }

    #[test]
    fn factory_disposition_marks_current_exact_targets_mediated() {
        for (action_key, argv) in [
            (
                "aws.s3.cp",
                args(&[
                    "s3",
                    "cp",
                    "dist/app.tar.gz",
                    "s3://assets/releases/app.tar.gz",
                ]),
            ),
            (
                "aws.s3.sync",
                args(&["s3", "sync", "dist/", "s3://assets/releases/"]),
            ),
            (
                "aws.s3api.delete-object",
                args(&[
                    "s3api",
                    "delete-object",
                    "--bucket",
                    "assets",
                    "--key",
                    "old/app.tar.gz",
                ]),
            ),
            (
                "aws.lambda.delete-function",
                args(&[
                    "lambda",
                    "delete-function",
                    "--function-name",
                    "arn:aws:lambda:us-east-1:123456789012:function:publish-site",
                ]),
            ),
            (
                "aws.kms.schedule-key-deletion",
                args(&[
                    "kms",
                    "schedule-key-deletion",
                    "--key-id",
                    "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
                ]),
            ),
            (
                "aws.cloudformation.delete-stack",
                args(&[
                    "cloudformation",
                    "delete-stack",
                    "--stack-name",
                    "arn:aws:cloudformation:us-east-1:123456789012:stack/publish-site/abcd-1234",
                ]),
            ),
            (
                "aws.secretsmanager.update-secret",
                args(&[
                    "secretsmanager",
                    "update-secret",
                    "--secret-id",
                    "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db-AbCdEf",
                ]),
            ),
        ] {
            assert_eq!(
                aws_factory_disposition_for_argv(Some(action_key), &argv),
                FactoryDisposition::Mediated,
                "{action_key} should be mediated for {argv:?}"
            );
        }
    }

    #[test]
    fn factory_disposition_marks_read_only_as_credentialless() {
        assert_eq!(
            aws_factory_disposition_for_argv(None, &args(&["s3", "ls", "s3://assets"])),
            FactoryDisposition::Credentialless
        );
        assert_eq!(
            aws_factory_disposition_for_argv(None, &args(&["lambda", "list-functions"])),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn factory_disposition_marks_resolver_required_names() {
        for (action_key, argv) in [
            (
                "aws.lambda.invoke",
                args(&["lambda", "invoke", "--function-name", "publish-site"]),
            ),
            (
                "aws.kms.decrypt",
                args(&["kms", "decrypt", "--key-id", "alias/publish"]),
            ),
            (
                "aws.cloudformation.update-stack",
                args(&[
                    "cloudformation",
                    "update-stack",
                    "--stack-name",
                    "publish-site",
                ]),
            ),
            (
                "aws.secretsmanager.delete-secret",
                args(&["secretsmanager", "delete-secret", "--secret-id", "prod-db"]),
            ),
        ] {
            assert_eq!(
                aws_factory_disposition_for_argv(Some(action_key), &argv),
                FactoryDisposition::ResolverRequired,
                "{action_key} should need a resolver for {argv:?}"
            );
        }
    }

    #[test]
    fn factory_disposition_marks_payload_and_unsafe_global_refusals() {
        assert_eq!(
            aws_factory_disposition_for_argv(
                Some("aws.cloudformation.deploy"),
                &args(&[
                    "cloudformation",
                    "deploy",
                    "--stack-name",
                    "publish-site",
                    "--template-file",
                    "template.yaml",
                ]),
            ),
            FactoryDisposition::PayloadAnalysisRequired
        );
        assert_eq!(
            aws_factory_disposition_for_argv(
                Some("aws.s3api.put-bucket-policy"),
                &args(&[
                    "s3api",
                    "put-bucket-policy",
                    "--bucket",
                    "assets",
                    "--policy",
                    "file://policy.json",
                ]),
            ),
            FactoryDisposition::PayloadAnalysisRequired
        );
        assert_eq!(
            aws_factory_disposition_for_argv(
                Some("aws.s3.rm"),
                &args(&["--profile", "prod", "s3", "rm", "s3://assets/old.tar.gz"]),
            ),
            FactoryDisposition::UnsupportedFailClosed
        );
        assert_eq!(
            aws_factory_disposition_for_argv(
                Some("aws.s3.rm"),
                &args(&["--no-sign-request", "s3", "rm", "s3://assets/old.tar.gz"]),
            ),
            FactoryDisposition::UnsupportedFailClosed
        );
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

    #[test]
    fn s3_cp_to_exact_object_permission_spec() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.cp",
            &args(&[
                "--region",
                "us-east-1",
                "s3",
                "cp",
                "local.txt",
                "s3://bucket/path/file.txt",
            ]),
        )
        .expect("permission spec");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::bucket/path/file.txt".to_string()
            }]
        );
    }

    #[test]
    fn s3_cp_refuses_unbounded_or_ambiguous_shapes() {
        for argv in [
            args(&["s3", "cp", "s3://bucket/path/file.txt", "local.txt"]),
            args(&["s3", "cp", "local.txt", "s3://bucket"]),
            args(&["s3", "cp", "local.txt", "s3://bucket/path/"]),
            args(&["s3", "cp", "--recursive", "local", "s3://bucket/prefix/"]),
            args(&["s3", "cp", "local.txt", "s3://bucket/path/*"]),
        ] {
            assert!(aws_permission_specs_for_argv("aws.s3.cp", &argv).is_none());
        }
    }

    #[test]
    fn s3_rm_to_exact_delete_permission_spec() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.rm",
            &args(&["s3", "rm", "s3://bucket/path/file.txt"]),
        )
        .expect("permission spec");
        assert_eq!(specs[0].actions, vec![AwsAction::S3DeleteObject]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::bucket/path/file.txt".to_string()
            }]
        );
        assert!(
            aws_permission_specs_for_argv(
                "aws.s3.rm",
                &args(&["s3", "rm", "--recursive", "s3://bucket/path/"])
            )
            .is_none()
        );
        assert!(
            aws_permission_specs_for_argv("aws.s3.rm", &args(&["s3", "rm", "s3://bucket/path/"]))
                .is_none()
        );
    }

    #[test]
    fn s3_mv_local_to_exact_object_permission_spec() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.mv",
            &args(&["s3", "mv", "local.txt", "s3://bucket/path/file.txt"]),
        )
        .expect("permission spec");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::bucket/path/file.txt".to_string()
            }]
        );
    }

    #[test]
    fn s3_mv_exact_object_to_local_permission_specs() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.mv",
            &args(&["s3", "mv", "s3://bucket/path/file.txt", "local.txt"]),
        )
        .expect("permission specs");
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].actions, vec![AwsAction::S3GetObject]);
        assert_eq!(specs[1].actions, vec![AwsAction::S3DeleteObject]);
        for spec in &specs {
            assert_eq!(
                spec.resources,
                vec![ResourceSelector::Exact {
                    value: "arn:aws:s3:::bucket/path/file.txt".to_string()
                }]
            );
        }
    }

    #[test]
    fn s3_mv_exact_object_to_exact_object_permission_specs() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.mv",
            &args(&[
                "s3",
                "mv",
                "s3://source-bucket/src/file.txt",
                "s3://dest-bucket/dst/file.txt",
            ]),
        )
        .expect("permission specs");
        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0].actions, vec![AwsAction::S3GetObject]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::source-bucket/src/file.txt".to_string()
            }]
        );
        assert_eq!(specs[1].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(
            specs[1].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::dest-bucket/dst/file.txt".to_string()
            }]
        );
        assert_eq!(specs[2].actions, vec![AwsAction::S3DeleteObject]);
        assert_eq!(
            specs[2].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::source-bucket/src/file.txt".to_string()
            }]
        );
    }

    #[test]
    fn s3_mv_recursive_local_to_s3_prefix_permission_spec() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.mv",
            &args(&["s3", "mv", "--recursive", "dist/", "s3://assets/releases/"]),
        )
        .expect("recursive local to s3 mv permission specs");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::assets/releases/*".to_string()
            }]
        );
    }

    #[test]
    fn s3_mv_recursive_s3_prefix_to_local_permission_specs() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.mv",
            &args(&["s3", "mv", "s3://assets/releases/", "dist/", "--recursive"]),
        )
        .expect("recursive s3 to local mv permission specs");
        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::assets".to_string()
            }]
        );
        assert_eq!(
            specs[0].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["releases/*".to_string()],
            }]
        );
        assert_eq!(specs[1].actions, vec![AwsAction::S3GetObject]);
        assert_eq!(specs[2].actions, vec![AwsAction::S3DeleteObject]);
        for spec in &specs[1..] {
            assert_eq!(
                spec.resources,
                vec![ResourceSelector::Glob {
                    pattern: "arn:aws:s3:::assets/releases/*".to_string()
                }]
            );
        }
    }

    #[test]
    fn s3_mv_recursive_s3_prefix_to_s3_prefix_permission_specs() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.mv",
            &args(&[
                "s3",
                "mv",
                "--recursive",
                "s3://source-assets/releases/",
                "s3://dest-assets/releases/",
            ]),
        )
        .expect("recursive s3 to s3 mv permission specs");
        assert_eq!(specs.len(), 4);
        assert_eq!(specs[0].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::source-assets".to_string()
            }]
        );
        assert_eq!(
            specs[0].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["releases/*".to_string()],
            }]
        );
        assert_eq!(specs[1].actions, vec![AwsAction::S3GetObject]);
        assert_eq!(
            specs[1].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::source-assets/releases/*".to_string()
            }]
        );
        assert_eq!(specs[2].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(
            specs[2].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::dest-assets/releases/*".to_string()
            }]
        );
        assert_eq!(specs[3].actions, vec![AwsAction::S3DeleteObject]);
        assert_eq!(
            specs[3].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::source-assets/releases/*".to_string()
            }]
        );
    }

    #[test]
    fn s3_mv_recursive_local_to_s3_bucket_root_permission_spec() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.mv",
            &args(&["s3", "mv", "--recursive", "dist/", "s3://bucket/"]),
        )
        .expect("recursive local to s3 bucket-root mv permission specs");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::bucket/*".to_string()
            }]
        );
    }

    #[test]
    fn s3_mv_recursive_s3_bucket_root_to_local_permission_specs() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.mv",
            &args(&["s3", "mv", "--recursive", "s3://bucket/", "dist/"]),
        )
        .expect("recursive s3 bucket-root to local mv permission specs");
        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::bucket".to_string()
            }]
        );
        assert_eq!(
            specs[0].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["*".to_string()],
            }]
        );
        assert_eq!(specs[1].actions, vec![AwsAction::S3GetObject]);
        assert_eq!(specs[2].actions, vec![AwsAction::S3DeleteObject]);
        for spec in &specs[1..] {
            assert_eq!(
                spec.resources,
                vec![ResourceSelector::Glob {
                    pattern: "arn:aws:s3:::bucket/*".to_string()
                }]
            );
        }
    }

    #[test]
    fn s3_mv_refuses_unbounded_or_ambiguous_shapes() {
        for argv in [
            args(&["s3", "mv", "local-a.txt", "local-b.txt"]),
            args(&["s3", "mv", "local.txt", "s3://bucket"]),
            args(&["s3", "mv", "s3://bucket", "local.txt"]),
            args(&["s3", "mv", "local.txt", "s3://bucket/path/"]),
            args(&["s3", "mv", "s3://bucket/path/", "local.txt"]),
            args(&["s3", "mv", "s3://bucket/source.txt", "s3://other/path/"]),
            args(&["s3", "mv", "local.txt", "s3://bucket/path/*"]),
            args(&["s3", "mv", "s3://bucket/path/*", "local.txt"]),
            args(&["s3", "mv", "--recursive", "dist/", "build/"]),
            args(&["s3", "mv", "--recursive", "dist/", "s3://bucket/prefix"]),
            args(&["s3", "mv", "--recursive", "dist/", "s3://bucket/prefix/*"]),
            args(&[
                "s3",
                "mv",
                "--recursive",
                "s3://bucket/",
                "s3://bucket/prefix/",
            ]),
            args(&[
                "s3",
                "mv",
                "--recursive",
                "s3://bucket/prefix/",
                "s3://bucket/",
            ]),
            args(&[
                "s3",
                "mv",
                "--recursive",
                "s3://bucket/prefix/",
                "s3://bucket/prefix/sub/",
            ]),
            args(&[
                "s3",
                "mv",
                "--recursive",
                "s3://bucket/prefix/sub/",
                "s3://bucket/prefix/",
            ]),
            args(&[
                "s3",
                "mv",
                "--recursive",
                "--recursive",
                "dist/",
                "s3://bucket/prefix/",
            ]),
            args(&[
                "s3",
                "mv",
                "--recursive",
                "dist/",
                "s3://bucket/prefix/",
                "--exclude",
                "*",
            ]),
        ] {
            assert!(aws_permission_specs_for_argv("aws.s3.mv", &argv).is_none());
        }
    }

    #[test]
    fn s3_sync_local_to_s3_prefix_permission_spec() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.sync",
            &args(&["s3", "sync", "dist/", "s3://assets/releases/"]),
        )
        .expect("local to s3 sync permission spec");
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::assets".to_string()
            }]
        );
        assert_eq!(
            specs[0].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["releases/*".to_string()],
            }]
        );
        assert_eq!(specs[1].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(
            specs[1].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::assets/releases/*".to_string()
            }]
        );
        assert!(specs[1].conditions.is_empty());
    }

    #[test]
    fn s3_sync_local_to_s3_bucket_root_permission_spec() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.sync",
            &args(&["s3", "sync", "dist/", "s3://assets/"]),
        )
        .expect("local to s3 bucket-root sync permission specs");
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::assets".to_string()
            }]
        );
        assert_eq!(
            specs[0].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["*".to_string()],
            }]
        );
        assert_eq!(specs[1].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(
            specs[1].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::assets/*".to_string()
            }]
        );
        assert!(specs[1].conditions.is_empty());
    }

    #[test]
    fn s3_sync_local_to_s3_prefix_delete_permission_specs() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.sync",
            &args(&["s3", "sync", "--delete", "dist/", "s3://assets/releases/"]),
        )
        .expect("local to s3 delete sync permission specs");
        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(specs[1].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(specs[2].actions, vec![AwsAction::S3DeleteObject]);
        assert_eq!(
            specs[2].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::assets/releases/*".to_string()
            }]
        );
    }

    #[test]
    fn s3_sync_s3_prefix_to_local_permission_specs() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.sync",
            &args(&["s3", "sync", "s3://assets/releases/", "dist/"]),
        )
        .expect("s3 to local sync permission specs");
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::assets".to_string()
            }]
        );
        assert_eq!(
            specs[0].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["releases/*".to_string()],
            }]
        );
        assert_eq!(specs[1].actions, vec![AwsAction::S3GetObject]);
        assert_eq!(
            specs[1].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::assets/releases/*".to_string()
            }]
        );
    }

    #[test]
    fn s3_sync_s3_bucket_root_to_local_permission_specs() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.sync",
            &args(&["s3", "sync", "s3://assets/", "dist/"]),
        )
        .expect("s3 bucket-root to local sync permission specs");
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::assets".to_string()
            }]
        );
        assert_eq!(
            specs[0].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["*".to_string()],
            }]
        );
        assert_eq!(specs[1].actions, vec![AwsAction::S3GetObject]);
        assert_eq!(
            specs[1].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::assets/*".to_string()
            }]
        );
    }

    #[test]
    fn s3_sync_s3_prefix_to_s3_prefix_permission_specs() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.sync",
            &args(&[
                "s3",
                "sync",
                "s3://source-assets/releases/",
                "s3://dest-assets/releases/",
            ]),
        )
        .expect("s3 to s3 sync permission specs");
        assert_eq!(specs.len(), 4);
        assert_eq!(specs[0].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::source-assets".to_string()
            }]
        );
        assert_eq!(
            specs[0].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["releases/*".to_string()],
            }]
        );
        assert_eq!(specs[1].actions, vec![AwsAction::S3GetObject]);
        assert_eq!(
            specs[1].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::source-assets/releases/*".to_string()
            }]
        );
        assert_eq!(specs[2].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[2].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::dest-assets".to_string()
            }]
        );
        assert_eq!(
            specs[2].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["releases/*".to_string()],
            }]
        );
        assert_eq!(specs[3].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(
            specs[3].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::dest-assets/releases/*".to_string()
            }]
        );
    }

    #[test]
    fn s3_sync_s3_bucket_root_to_s3_prefix_permission_specs() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.sync",
            &args(&[
                "s3",
                "sync",
                "s3://source-assets/",
                "s3://dest-assets/releases/",
            ]),
        )
        .expect("s3 bucket-root to s3 prefix sync permission specs");
        assert_eq!(specs.len(), 4);
        assert_eq!(specs[0].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::source-assets".to_string()
            }]
        );
        assert_eq!(
            specs[0].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["*".to_string()],
            }]
        );
        assert_eq!(specs[1].actions, vec![AwsAction::S3GetObject]);
        assert_eq!(
            specs[1].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::source-assets/*".to_string()
            }]
        );
        assert_eq!(specs[2].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[2].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["releases/*".to_string()],
            }]
        );
        assert_eq!(specs[3].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(
            specs[3].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::dest-assets/releases/*".to_string()
            }]
        );
    }

    #[test]
    fn s3_sync_s3_prefix_to_s3_bucket_root_permission_specs() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.sync",
            &args(&[
                "s3",
                "sync",
                "s3://source-assets/releases/",
                "s3://dest-assets/",
            ]),
        )
        .expect("s3 prefix to s3 bucket-root sync permission specs");
        assert_eq!(specs.len(), 4);
        assert_eq!(specs[0].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[0].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["releases/*".to_string()],
            }]
        );
        assert_eq!(specs[1].actions, vec![AwsAction::S3GetObject]);
        assert_eq!(
            specs[1].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::source-assets/releases/*".to_string()
            }]
        );
        assert_eq!(specs[2].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(
            specs[2].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::dest-assets".to_string()
            }]
        );
        assert_eq!(
            specs[2].conditions,
            vec![AwsCondition {
                operator: AwsConditionOperator::StringLike,
                key: AwsConditionKey::S3Prefix,
                values: vec!["*".to_string()],
            }]
        );
        assert_eq!(specs[3].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(
            specs[3].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::dest-assets/*".to_string()
            }]
        );
    }

    #[test]
    fn s3_sync_s3_prefix_to_s3_prefix_delete_permission_specs() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3.sync",
            &args(&[
                "s3",
                "sync",
                "s3://source-assets/releases/",
                "s3://dest-assets/releases/",
                "--delete",
            ]),
        )
        .expect("s3 to s3 delete sync permission specs");
        assert_eq!(specs.len(), 5);
        assert_eq!(specs[0].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(specs[1].actions, vec![AwsAction::S3GetObject]);
        assert_eq!(specs[2].actions, vec![AwsAction::S3ListBucket]);
        assert_eq!(specs[3].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(specs[4].actions, vec![AwsAction::S3DeleteObject]);
        assert_eq!(
            specs[4].resources,
            vec![ResourceSelector::Glob {
                pattern: "arn:aws:s3:::dest-assets/releases/*".to_string()
            }]
        );
    }

    #[test]
    fn s3_sync_refuses_unbounded_or_ambiguous_shapes() {
        for argv in [
            args(&["s3", "sync", "dist/", "build/"]),
            args(&["s3", "sync", "dist/", "s3://assets"]),
            args(&["s3", "sync", "s3://assets", "dist/"]),
            args(&["s3", "sync", "s3://assets", "s3://other/releases/"]),
            args(&["s3", "sync", "s3://assets/", "s3://assets/releases/"]),
            args(&["s3", "sync", "s3://assets/releases/", "s3://assets/"]),
            args(&[
                "s3",
                "sync",
                "s3://assets/releases/",
                "s3://assets/releases/daily/",
            ]),
            args(&["s3", "sync", "dist/", "s3://assets/releases"]),
            args(&["s3", "sync", "dist/", "s3://assets/releases/*"]),
            args(&[
                "s3",
                "sync",
                "dist/",
                "s3://assets/releases/",
                "--delete",
                "--delete",
            ]),
            args(&[
                "s3",
                "sync",
                "dist/",
                "s3://assets/releases/",
                "--exclude",
                "*",
            ]),
        ] {
            assert!(
                aws_permission_specs_for_argv("aws.s3.sync", &argv).is_none(),
                "aws.s3.sync must not mint for {argv:?}"
            );
        }
    }

    #[test]
    fn s3api_object_verbs_parse_bucket_and_key_flags() {
        let put = aws_permission_specs_for_argv(
            "aws.s3api.put-object",
            &args(&[
                "s3api",
                "put-object",
                "--bucket=assets",
                "--key",
                "releases/app.tar.gz",
                "--body",
                "app.tar.gz",
            ]),
        )
        .expect("put object permission spec");
        assert_eq!(put[0].actions, vec![AwsAction::S3PutObject]);
        assert_eq!(
            put[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::assets/releases/app.tar.gz".to_string()
            }]
        );

        let delete = aws_permission_specs_for_argv(
            "aws.s3api.delete-object",
            &args(&[
                "s3api",
                "delete-object",
                "--bucket",
                "assets",
                "--key=old/app.tar.gz",
            ]),
        )
        .expect("delete object permission spec");
        assert_eq!(delete[0].actions, vec![AwsAction::S3DeleteObject]);
        assert_eq!(
            delete[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::assets/old/app.tar.gz".to_string()
            }]
        );

        let slash_key = aws_permission_specs_for_argv(
            "aws.s3api.put-object",
            &args(&["s3api", "put-object", "--bucket", "assets", "--key=dir/"]),
        )
        .expect("s3api slash key remains exact");
        assert_eq!(
            slash_key[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::assets/dir/".to_string()
            }]
        );
    }

    #[test]
    fn s3api_put_bucket_policy_targets_exact_bucket() {
        let specs = aws_permission_specs_for_argv(
            "aws.s3api.put-bucket-policy",
            &args(&[
                "s3api",
                "put-bucket-policy",
                "--bucket",
                "assets",
                "--policy",
                "policy.json",
            ]),
        )
        .expect("bucket policy permission spec");
        assert_eq!(specs[0].actions, vec![AwsAction::S3PutBucketPolicy]);
        assert_eq!(
            specs[0].resources,
            vec![ResourceSelector::Exact {
                value: "arn:aws:s3:::assets".to_string()
            }]
        );
    }

    #[test]
    fn lambda_verbs_parse_exact_function_arn() {
        let function_arn = "arn:aws:lambda:us-east-1:123456789012:function:publish-site";
        for (action_key, verb, action) in [
            (
                "aws.lambda.invoke",
                "invoke",
                AwsAction::LambdaInvokeFunction,
            ),
            (
                "aws.lambda.update-function-code",
                "update-function-code",
                AwsAction::LambdaUpdateFunctionCode,
            ),
            (
                "aws.lambda.delete-function",
                "delete-function",
                AwsAction::LambdaDeleteFunction,
            ),
        ] {
            let specs = aws_permission_specs_for_argv(
                action_key,
                &args(&[
                    "lambda",
                    verb,
                    "--function-name",
                    function_arn,
                    "--payload",
                    "{}",
                    "out.json",
                ]),
            )
            .unwrap_or_else(|| panic!("{action_key} permission spec"));
            assert_eq!(specs.len(), 1);
            assert_eq!(specs[0].actions, vec![action]);
            assert_eq!(
                specs[0].resources,
                vec![ResourceSelector::Exact {
                    value: function_arn.to_string()
                }],
                "{action_key}"
            );
        }
    }

    #[test]
    fn lambda_verbs_refuse_unbounded_or_ambiguous_function_targets() {
        for (action_key, verb) in [
            ("aws.lambda.invoke", "invoke"),
            ("aws.lambda.update-function-code", "update-function-code"),
            ("aws.lambda.delete-function", "delete-function"),
        ] {
            for argv in [
                args(&["lambda", verb, "--function-name", "publish-site"]),
                args(&[
                    "lambda",
                    verb,
                    "--function-name",
                    "arn:aws:lambda:us-east-1:123456789012:function:*",
                ]),
                args(&[
                    "lambda",
                    verb,
                    "--function-name",
                    "arn:aws:iam::123456789012:role/not-a-function",
                ]),
                args(&["lambda", verb]),
                args(&[
                    "lambda",
                    verb,
                    "--function-name",
                    "arn:aws:lambda:us-east-1:123456789012:function:a",
                    "--function-name",
                    "arn:aws:lambda:us-east-1:123456789012:function:b",
                ]),
            ] {
                assert!(
                    aws_permission_specs_for_argv(action_key, &argv).is_none(),
                    "{action_key} must not mint for {argv:?}"
                );
            }
        }
    }

    #[test]
    fn kms_key_verbs_parse_exact_key_arn() {
        let key_arn = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234";
        for (action_key, verb, action) in [
            ("aws.kms.encrypt", "encrypt", AwsAction::KmsEncrypt),
            ("aws.kms.decrypt", "decrypt", AwsAction::KmsDecrypt),
            (
                "aws.kms.schedule-key-deletion",
                "schedule-key-deletion",
                AwsAction::KmsScheduleKeyDeletion,
            ),
        ] {
            let specs = aws_permission_specs_for_argv(
                action_key,
                &args(&[
                    "kms",
                    verb,
                    "--key-id",
                    key_arn,
                    "--plaintext",
                    "fileb://in",
                ]),
            )
            .unwrap_or_else(|| panic!("{action_key} permission spec"));
            assert_eq!(specs.len(), 1);
            assert_eq!(specs[0].actions, vec![action]);
            assert_eq!(
                specs[0].resources,
                vec![ResourceSelector::Exact {
                    value: key_arn.to_string()
                }],
                "{action_key}"
            );
        }
    }

    #[test]
    fn kms_key_verbs_refuse_unbounded_or_ambiguous_key_targets() {
        for (action_key, verb) in [
            ("aws.kms.encrypt", "encrypt"),
            ("aws.kms.decrypt", "decrypt"),
            ("aws.kms.schedule-key-deletion", "schedule-key-deletion"),
        ] {
            for argv in [
                args(&["kms", verb, "--key-id", "alias/publish"]),
                args(&[
                    "kms",
                    verb,
                    "--key-id",
                    "arn:aws:kms:us-east-1:123456789012:key/*",
                ]),
                args(&[
                    "kms",
                    verb,
                    "--key-id",
                    "arn:aws:iam::123456789012:role/not-a-key",
                ]),
                args(&["kms", verb]),
                args(&[
                    "kms",
                    verb,
                    "--key-id",
                    "arn:aws:kms:us-east-1:123456789012:key/a",
                    "--key-id",
                    "arn:aws:kms:us-east-1:123456789012:key/b",
                ]),
            ] {
                assert!(
                    aws_permission_specs_for_argv(action_key, &argv).is_none(),
                    "{action_key} must not mint for {argv:?}"
                );
            }
        }
    }

    #[test]
    fn cloudformation_delete_update_parse_exact_stack_arn() {
        let stack_arn =
            "arn:aws:cloudformation:us-east-1:123456789012:stack/publish-site/abcd-1234";
        for (action_key, verb, action) in [
            (
                "aws.cloudformation.delete-stack",
                "delete-stack",
                AwsAction::CloudFormationDeleteStack,
            ),
            (
                "aws.cloudformation.update-stack",
                "update-stack",
                AwsAction::CloudFormationUpdateStack,
            ),
        ] {
            let specs = aws_permission_specs_for_argv(
                action_key,
                &args(&[
                    "cloudformation",
                    verb,
                    "--stack-name",
                    stack_arn,
                    "--template-body",
                    "file://template.yaml",
                ]),
            )
            .unwrap_or_else(|| panic!("{action_key} permission spec"));
            assert_eq!(specs.len(), 1);
            assert_eq!(specs[0].actions, vec![action]);
            assert_eq!(
                specs[0].resources,
                vec![ResourceSelector::Exact {
                    value: stack_arn.to_string()
                }],
                "{action_key}"
            );
        }
    }

    #[test]
    fn cloudformation_delete_update_refuse_unbounded_or_ambiguous_stack_targets() {
        for (action_key, verb) in [
            ("aws.cloudformation.delete-stack", "delete-stack"),
            ("aws.cloudformation.update-stack", "update-stack"),
        ] {
            for argv in [
                args(&["cloudformation", verb, "--stack-name", "publish-site"]),
                args(&[
                    "cloudformation",
                    verb,
                    "--stack-name",
                    "arn:aws:cloudformation:us-east-1:123456789012:stack/*",
                ]),
                args(&[
                    "cloudformation",
                    verb,
                    "--stack-name",
                    "arn:aws:cloudformation:us-east-1:123456789012:stack/publish-site",
                ]),
                args(&[
                    "cloudformation",
                    verb,
                    "--stack-name",
                    "arn:aws:cloudformation:us-east-1:123456789012:stack/publish-site/",
                ]),
                args(&[
                    "cloudformation",
                    verb,
                    "--stack-name",
                    "arn:aws:cloudformation:us-east-1:123456789012:stack/publish site/abcd",
                ]),
                args(&[
                    "cloudformation",
                    verb,
                    "--stack-name",
                    "arn:aws:cloudformation:us-east-1:123456789012:stack/*/abcd",
                ]),
                args(&[
                    "cloudformation",
                    verb,
                    "--stack-name",
                    "arn:aws:cloudformation:us-east-1:12345678901:stack/publish-site/abcd",
                ]),
                args(&[
                    "cloudformation",
                    verb,
                    "--stack-name",
                    "arn:aws:iam::123456789012:role/not-a-stack",
                ]),
                args(&["cloudformation", verb]),
                args(&[
                    "cloudformation",
                    verb,
                    "--stack-name",
                    "arn:aws:cloudformation:us-east-1:123456789012:stack/a/1",
                    "--stack-name",
                    "arn:aws:cloudformation:us-east-1:123456789012:stack/b/2",
                ]),
            ] {
                assert!(
                    aws_permission_specs_for_argv(action_key, &argv).is_none(),
                    "{action_key} must not mint for {argv:?}"
                );
            }
        }
    }

    #[test]
    fn permission_spec_parser_leaves_unhandled_aws_actions_fail_closed() {
        for (action, argv) in [
            (
                "aws.iam.create-role",
                args(&["iam", "create-role", "--role-name", "r"]),
            ),
            (
                "aws.sts.assume-role",
                args(&["sts", "assume-role", "--role-arn", "arn"]),
            ),
            (
                "aws.kms.create-key",
                args(&["kms", "create-key", "--description", "new-key"]),
            ),
            (
                "aws.secretsmanager.create-secret",
                args(&["secretsmanager", "create-secret", "--name", "new-secret"]),
            ),
            (
                "aws.cloudformation.deploy",
                args(&[
                    "cloudformation",
                    "deploy",
                    "--stack-name",
                    "arn:aws:cloudformation:us-east-1:123456789012:stack/a/1",
                ]),
            ),
        ] {
            assert!(
                aws_permission_specs_for_argv(action, &argv).is_none(),
                "{action} must not mint until a bounded PermissionSpec parser exists"
            );
        }
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

    #[test]
    fn secretsmanager_mutations_parse_exact_secret_arn() {
        let secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db-AbCdEf";
        for (action_key, verb, action) in [
            (
                "aws.secretsmanager.update-secret",
                "update-secret",
                AwsAction::SecretsManagerUpdateSecret,
            ),
            (
                "aws.secretsmanager.delete-secret",
                "delete-secret",
                AwsAction::SecretsManagerDeleteSecret,
            ),
            (
                "aws.secretsmanager.put-secret-value",
                "put-secret-value",
                AwsAction::SecretsManagerPutSecretValue,
            ),
        ] {
            let specs = aws_permission_specs_for_argv(
                action_key,
                &args(&[
                    "secretsmanager",
                    verb,
                    "--secret-id",
                    secret_arn,
                    "--description",
                    "rotated",
                ]),
            )
            .unwrap_or_else(|| panic!("{action_key} permission spec"));
            assert_eq!(specs.len(), 1);
            assert_eq!(specs[0].actions, vec![action]);
            assert_eq!(
                specs[0].resources,
                vec![ResourceSelector::Exact {
                    value: secret_arn.to_string()
                }],
                "{action_key}"
            );
        }
    }

    #[test]
    fn secretsmanager_mutations_refuse_unbounded_or_ambiguous_secret_targets() {
        for (action_key, verb) in [
            ("aws.secretsmanager.update-secret", "update-secret"),
            ("aws.secretsmanager.delete-secret", "delete-secret"),
            ("aws.secretsmanager.put-secret-value", "put-secret-value"),
        ] {
            for argv in [
                args(&["secretsmanager", verb, "--secret-id", "prod-db"]),
                args(&[
                    "secretsmanager",
                    verb,
                    "--secret-id",
                    "arn:aws:secretsmanager:us-east-1:123456789012:secret:*",
                ]),
                args(&[
                    "secretsmanager",
                    verb,
                    "--secret-id",
                    "arn:aws:iam::123456789012:role/not-a-secret",
                ]),
                args(&["secretsmanager", verb]),
                args(&[
                    "secretsmanager",
                    verb,
                    "--secret-id",
                    "arn:aws:secretsmanager:us-east-1:123456789012:secret:a",
                    "--secret-id",
                    "arn:aws:secretsmanager:us-east-1:123456789012:secret:b",
                ]),
            ] {
                assert!(
                    aws_permission_specs_for_argv(action_key, &argv).is_none(),
                    "{action_key} must not mint for {argv:?}"
                );
            }
        }
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
    // without panicking. Real STS impl is BROKER-AWS-STS-IMPL (separate task).

    use core_broker::{Broker, BrokerError, BrokerProvider, BrokerRequest, MockBroker};
    use std::time::Duration;

    fn aws_sts_request(ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::AwsSts,
            scope: serde_json::json!({
                "mode": "assume_role",
                "role_arn": "arn:aws:iam::123456789012:role/EmberAgentRole",
                "session_name": "ember-agent-session",
                "ttl_seconds": ttl_secs,
            }),
            ttl: Duration::from_secs(ttl_secs),
            contract_id: None,
            action_ref: None,
            workspace_ref: None,
            subject_ref: None,
            coordination_ref: None,
            caller_ref: None,
            authority_ref: None,
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
