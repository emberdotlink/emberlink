//! Argv classifier: maps `wrangler <verb> ...` to a `construct.toml` action_key.
//! Per ADR 124 §3 — this lives shim-side BUT the daemon re-classifies the argv
//! server-side (untrusts the shim).
//!
//! Wrangler separator gotchas:
//!   - `secret put`      → space-separated multi-word verb
//!   - `r2 object put`   → space-separated, two levels deep
//!   - `kv:key put`      → COLON separator between namespace and sub-verb
//!   - `pages deploy`    → space-separated
//!   - `d1 execute`      → space-separated
//!
//! Coverage:
//!   - deploy              → wrangler.deploy           (biometric=required)
//!   - delete              → wrangler.delete           (biometric=required, budget 1/session)
//!   - secret put          → wrangler.secret.put       (biometric=required; space multi-word)
//!   - secret delete       → wrangler.secret.delete    (biometric=required; space multi-word)
//!   - secret bulk         → wrangler.secret.bulk      (biometric=required; bulk JSON import)
//!   - r2 object put       → wrangler.r2.put           (biometric=required; two-level space)
//!   - r2 object delete    → wrangler.r2.delete        (biometric=required; budget 5/session)
//!   - r2 bucket create    → wrangler.r2.bucket.create (biometric=required; persistent resource)
//!   - kv:key put          → wrangler.kv.put           (biometric=required; colon separator)
//!   - kv:key delete       → wrangler.kv.delete        (biometric=required; colon separator)
//!   - d1 execute          → wrangler.d1.execute       (biometric=required)
//!   - d1 create           → wrangler.d1.create        (biometric=required; persistent resource)
//!   - pages deploy        → wrangler.pages.deploy     (biometric=required)
//!   - dev / tail / whoami / version / login / logout
//!   - kv:key list / kv:key get / r2 object list / r2 object get
//!   - d1 list / d1 info / secret list                  → None (passthrough)

use core_construct_runtime::ActionKey;
use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};

/// Classify `wrangler <verb> ...` argv into an action_key.
///
/// Returns `None` for read-only / unrecognized shapes — the runtime treats
/// `None` as passthrough (no broker mediation).
pub fn classify_wrangler_argv(argv: &[String]) -> Option<ActionKey> {
    let verb = argv.first()?.as_str();

    match verb {
        // Read-only / informational → passthrough.
        "dev" | "tail" | "whoami" | "version" | "logout" => None,

        // login is classified so the factory can fail it closed (credential-
        // bypass vector), matching the gh.auth_login pattern.
        "login" => Some(ActionKey("wrangler.login".to_string())),

        // deploy → biometric, wrangler.deploy
        "deploy" => Some(ActionKey("wrangler.deploy".to_string())),

        // delete → biometric, budget 1/session, wrangler.delete
        "delete" => Some(ActionKey("wrangler.delete".to_string())),

        // secret subcommand — multi-word verbs (space-separated).
        "secret" => {
            let sub = argv.get(1).map(|s| s.as_str());
            match sub {
                Some("put") => Some(ActionKey("wrangler.secret.put".to_string())),
                Some("delete") => Some(ActionKey("wrangler.secret.delete".to_string())),
                // secret bulk → biometric-gated; bulk JSON import, same threat as secret.put.
                Some("bulk") => Some(ActionKey("wrangler.secret.bulk".to_string())),
                // secret list → passthrough (read-only).
                Some("list") | None => None,
                // Any other secret sub → passthrough; daemon re-classifies.
                _ => None,
            }
        }

        // r2 subcommand — two-level space-separated: `r2 object put/delete`.
        "r2" => {
            let sub1 = argv.get(1).map(|s| s.as_str());
            match sub1 {
                Some("object") => {
                    let sub2 = argv.get(2).map(|s| s.as_str());
                    match sub2 {
                        Some("put") => Some(ActionKey("wrangler.r2.put".to_string())),
                        Some("delete") => Some(ActionKey("wrangler.r2.delete".to_string())),
                        // r2 object list / r2 object get → passthrough.
                        Some("list") | Some("get") | None => None,
                        _ => None,
                    }
                }
                Some("bucket") => {
                    let sub2 = argv.get(2).map(|s| s.as_str());
                    match sub2 {
                        // r2 bucket create → biometric-gated; persistent resource creation.
                        Some("create") => Some(ActionKey("wrangler.r2.bucket.create".to_string())),
                        // r2 bucket list / r2 bucket delete / other → passthrough; daemon re-classifies.
                        _ => None,
                    }
                }
                // other r2 sub → passthrough; daemon re-classifies.
                _ => None,
            }
        }

        // kv:key subcommand — COLON separator: `kv:key put/delete/list/get`.
        // Wrangler uses `kv:key` as a single token (colon is part of the verb).
        "kv:key" => {
            let sub = argv.get(1).map(|s| s.as_str());
            match sub {
                Some("put") => Some(ActionKey("wrangler.kv.put".to_string())),
                Some("delete") => Some(ActionKey("wrangler.kv.delete".to_string())),
                // kv:key list / kv:key get → passthrough (read-only).
                Some("list") | Some("get") | None => None,
                _ => None,
            }
        }

        // kv:namespace / kv:bulk — not in scope for mutation gating in cohort-A.
        "kv:namespace" | "kv:bulk" => None,

        // d1 subcommand.
        "d1" => {
            let sub = argv.get(1).map(|s| s.as_str());
            match sub {
                Some("execute") => Some(ActionKey("wrangler.d1.execute".to_string())),
                // d1 create → biometric-gated; persistent resource creation.
                Some("create") => Some(ActionKey("wrangler.d1.create".to_string())),
                // d1 list / d1 info → passthrough (read-only).
                Some("list") | Some("info") | None => None,
                _ => None,
            }
        }

        // pages subcommand.
        "pages" => {
            let sub = argv.get(1).map(|s| s.as_str());
            match sub {
                Some("deploy") => Some(ActionKey("wrangler.pages.deploy".to_string())),
                _ => None,
            }
        }

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// WranglerFactory — P24 construct-factory contract for the wrangler construct
// ---------------------------------------------------------------------------

/// Parsed wrangler.toml action manifest, initialised once at first access.
static WRANGLER_MANIFEST: std::sync::LazyLock<core_events::construct_toml::ParsedActionManifest> =
    std::sync::LazyLock::new(|| {
        core_events::construct_toml::parse_action_manifest(include_str!(
            "../construct/wrangler.toml"
        ))
        .expect("bundled wrangler.toml must be valid")
    });

/// Look up the `need` atoms for an action key from the bundled manifest.
/// Returns `None` if the action is absent from the manifest or has an empty
/// `need` list.
fn manifest_need_for_action(action_key: &str) -> Option<Vec<String>> {
    WRANGLER_MANIFEST
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
    WRANGLER_MANIFEST
        .manifest
        .actions
        .iter()
        .any(|a| a.key == action_key)
}

/// P24 factory implementation for the `wrangler` construct.
#[derive(Debug, Default, Clone)]
pub struct WranglerFactory;

/// Provider-specific target extracted from a `wrangler` argv invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WranglerFactoryTarget {
    pub provider: &'static str,
    /// Cloudflare account ID, when supplied via argv.
    pub account_id: Option<String>,
    /// Worker name, when supplied via `--name`.
    pub worker_name: Option<String>,
}

/// Need atoms derived from the bundled manifest for one `wrangler` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WranglerFactoryNeed(pub Vec<String>);

/// Extract `--name <value>` or `--name=<value>` from argv.
fn extract_name_flag(argv: &[String]) -> Option<String> {
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];
        if let Some(value) = tok.strip_prefix("--name=")
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
        if tok == "--name"
            && let Some(value) = argv.get(i + 1)
            && !value.starts_with('-')
        {
            return Some(value.clone());
        }
        i += 1;
    }
    None
}

impl InvocationGrammar for WranglerFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_wrangler_argv(argv)
    }
}

impl TargetExtractor for WranglerFactory {
    type Target = WranglerFactoryTarget;

    fn target_for_argv(&self, _action_key: &ActionKey, argv: &[String]) -> Option<Self::Target> {
        Some(WranglerFactoryTarget {
            provider: "cloudflare",
            account_id: None,
            worker_name: extract_name_flag(argv),
        })
    }
}

impl NeedTemplate for WranglerFactory {
    type Need = WranglerFactoryNeed;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        _target: &Self::Target,
        _argv: &[String],
    ) -> Option<Self::Need> {
        manifest_need_for_action(&action_key.0).map(WranglerFactoryNeed)
    }
}

impl ConstructFactory for WranglerFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> FactoryDisposition {
        // --api-token in argv selects credential material — always fail closed,
        // regardless of whether the verb classified. This is a global flag that
        // may appear before the verb (e.g. `--api-token <tok> deploy`).
        if argv
            .iter()
            .any(|a| a == "--api-token" || a.starts_with("--api-token="))
        {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        let Some(key) = action_key else {
            // Unclassified argv — no known action, treat as credentialless
            // passthrough (reads, version, whoami, etc.).
            return FactoryDisposition::Credentialless;
        };

        // wrangler login is a credential-bypass vector — always fail closed.
        if key.0 == "wrangler.login" {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // deploy with --config carries bindings/routes/secrets/D1/R2 — needs
        // payload analysis before materialization.
        if key.0 == "wrangler.deploy"
            && argv.iter().any(|a| {
                a == "--config" || a == "-c" || a.starts_with("--config=") || a.starts_with("-c=")
            })
        {
            return FactoryDisposition::PayloadAnalysisRequired;
        }

        // secret.put injects secret material — always fail closed.
        if key.0 == "wrangler.secret.put" {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // Action not in manifest — no bounded authority declared, fail closed.
        if !action_in_manifest(&key.0) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // Action is in the manifest — account/token must be resolved from
        // wrangler config before materialization can proceed.
        FactoryDisposition::ResolverRequired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // --- deploy ---

    #[test]
    fn deploy_classified() {
        let r = classify_wrangler_argv(&args(&["deploy"])).unwrap();
        assert_eq!(r.0, "wrangler.deploy");
    }

    #[test]
    fn deploy_with_flags_classified() {
        let r = classify_wrangler_argv(&args(&["deploy", "--env", "production"])).unwrap();
        assert_eq!(r.0, "wrangler.deploy");
    }

    // --- delete ---

    #[test]
    fn delete_classified() {
        let r = classify_wrangler_argv(&args(&["delete"])).unwrap();
        assert_eq!(r.0, "wrangler.delete");
    }

    #[test]
    fn delete_with_name_classified() {
        let r = classify_wrangler_argv(&args(&["delete", "my-worker"])).unwrap();
        assert_eq!(r.0, "wrangler.delete");
    }

    // --- secret put / delete (space-separated multi-word) ---

    #[test]
    fn secret_put_classified() {
        let r = classify_wrangler_argv(&args(&["secret", "put", "MY_SECRET"])).unwrap();
        assert_eq!(r.0, "wrangler.secret.put");
    }

    #[test]
    fn secret_delete_classified() {
        let r = classify_wrangler_argv(&args(&["secret", "delete", "MY_SECRET"])).unwrap();
        assert_eq!(r.0, "wrangler.secret.delete");
    }

    #[test]
    fn secret_list_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["secret", "list"])).is_none(),
            "secret list should passthrough"
        );
    }

    #[test]
    fn secret_bare_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["secret"])).is_none(),
            "bare secret should passthrough"
        );
    }

    #[test]
    fn secret_bulk_classified() {
        let r = classify_wrangler_argv(&args(&["secret", "bulk", "secrets.json"])).unwrap();
        assert_eq!(r.0, "wrangler.secret.bulk");
    }

    #[test]
    fn secret_bulk_with_flags_classified() {
        let r =
            classify_wrangler_argv(&args(&["secret", "bulk", "--input", "secrets.json"])).unwrap();
        assert_eq!(r.0, "wrangler.secret.bulk");
    }

    // --- r2 object put / delete (two-level space-separated) ---

    #[test]
    fn r2_object_put_classified() {
        let r = classify_wrangler_argv(&args(&["r2", "object", "put", "my-bucket/key"])).unwrap();
        assert_eq!(r.0, "wrangler.r2.put");
    }

    #[test]
    fn r2_object_put_with_flags_classified() {
        let r = classify_wrangler_argv(&args(&[
            "r2",
            "object",
            "put",
            "my-bucket/key",
            "--file",
            "data.bin",
        ]))
        .unwrap();
        assert_eq!(r.0, "wrangler.r2.put");
    }

    #[test]
    fn r2_object_delete_classified() {
        let r =
            classify_wrangler_argv(&args(&["r2", "object", "delete", "my-bucket/key"])).unwrap();
        assert_eq!(r.0, "wrangler.r2.delete");
    }

    #[test]
    fn r2_object_list_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["r2", "object", "list", "my-bucket"])).is_none(),
            "r2 object list should passthrough"
        );
    }

    #[test]
    fn r2_object_get_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["r2", "object", "get", "my-bucket/key"])).is_none(),
            "r2 object get should passthrough"
        );
    }

    #[test]
    fn r2_bare_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["r2"])).is_none(),
            "bare r2 should passthrough"
        );
    }

    #[test]
    fn r2_bucket_create_classified() {
        let r = classify_wrangler_argv(&args(&["r2", "bucket", "create", "my-bucket"])).unwrap();
        assert_eq!(r.0, "wrangler.r2.bucket.create");
    }

    #[test]
    fn r2_bucket_create_with_flags_classified() {
        let r = classify_wrangler_argv(&args(&[
            "r2",
            "bucket",
            "create",
            "my-bucket",
            "--location",
            "WNAM",
        ]))
        .unwrap();
        assert_eq!(r.0, "wrangler.r2.bucket.create");
    }

    #[test]
    fn r2_bucket_list_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["r2", "bucket", "list"])).is_none(),
            "r2 bucket list should passthrough"
        );
    }

    // --- kv:key put / delete (colon-separator multi-word) ---

    #[test]
    fn kv_key_put_classified() {
        let r = classify_wrangler_argv(&args(&["kv:key", "put", "MY_KEY", "value"])).unwrap();
        assert_eq!(r.0, "wrangler.kv.put");
    }

    #[test]
    fn kv_key_put_with_flags_classified() {
        let r = classify_wrangler_argv(&args(&[
            "kv:key",
            "put",
            "MY_KEY",
            "value",
            "--binding",
            "MY_KV",
        ]))
        .unwrap();
        assert_eq!(r.0, "wrangler.kv.put");
    }

    #[test]
    fn kv_key_delete_classified() {
        let r = classify_wrangler_argv(&args(&["kv:key", "delete", "MY_KEY"])).unwrap();
        assert_eq!(r.0, "wrangler.kv.delete");
    }

    #[test]
    fn kv_key_list_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["kv:key", "list"])).is_none(),
            "kv:key list should passthrough"
        );
    }

    #[test]
    fn kv_key_get_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["kv:key", "get", "MY_KEY"])).is_none(),
            "kv:key get should passthrough"
        );
    }

    #[test]
    fn kv_key_bare_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["kv:key"])).is_none(),
            "bare kv:key should passthrough"
        );
    }

    // --- d1 execute ---

    #[test]
    fn d1_execute_classified() {
        let r = classify_wrangler_argv(&args(&["d1", "execute", "MY_DB", "--command", "SELECT 1"]))
            .unwrap();
        assert_eq!(r.0, "wrangler.d1.execute");
    }

    #[test]
    fn d1_list_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["d1", "list"])).is_none(),
            "d1 list should passthrough"
        );
    }

    #[test]
    fn d1_info_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["d1", "info", "MY_DB"])).is_none(),
            "d1 info should passthrough"
        );
    }

    #[test]
    fn d1_create_classified() {
        let r = classify_wrangler_argv(&args(&["d1", "create", "MY_DB"])).unwrap();
        assert_eq!(r.0, "wrangler.d1.create");
    }

    #[test]
    fn d1_create_with_flags_classified() {
        let r = classify_wrangler_argv(&args(&["d1", "create", "MY_DB", "--location", "wnam"]))
            .unwrap();
        assert_eq!(r.0, "wrangler.d1.create");
    }

    // --- pages deploy ---

    #[test]
    fn pages_deploy_classified() {
        let r = classify_wrangler_argv(&args(&["pages", "deploy", "dist/"])).unwrap();
        assert_eq!(r.0, "wrangler.pages.deploy");
    }

    #[test]
    fn pages_other_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["pages", "list"])).is_none(),
            "pages list should passthrough"
        );
    }

    // --- passthrough verbs ---

    #[test]
    fn dev_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["dev"])).is_none(),
            "dev should passthrough"
        );
    }

    #[test]
    fn tail_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["tail"])).is_none(),
            "tail should passthrough"
        );
    }

    #[test]
    fn whoami_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["whoami"])).is_none(),
            "whoami should passthrough"
        );
    }

    #[test]
    fn version_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["version"])).is_none(),
            "version should passthrough"
        );
    }

    #[test]
    fn login_classified() {
        let r = classify_wrangler_argv(&args(&["login"])).unwrap();
        assert_eq!(r.0, "wrangler.login");
    }

    #[test]
    fn logout_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["logout"])).is_none(),
            "logout should passthrough"
        );
    }

    #[test]
    fn empty_argv_is_passthrough() {
        assert!(classify_wrangler_argv(&[]).is_none());
    }

    #[test]
    fn unknown_verb_passthrough() {
        assert!(
            classify_wrangler_argv(&args(&["generate"])).is_none(),
            "unknown verb should passthrough"
        );
    }

    // --- WranglerFactory tests ---

    #[test]
    fn wrangler_factory_version_is_credentialless() {
        let f = WranglerFactory;
        let a = args(&["--version"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn wrangler_factory_whoami_is_credentialless() {
        let f = WranglerFactory;
        let a = args(&["whoami"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn wrangler_factory_api_token_flag_is_unsupported() {
        let f = WranglerFactory;
        let a = args(&["--api-token", "cf-token", "secret", "put", "API_KEY"]);
        // classify sees the stripped argv; factory sees the raw argv.
        let key = f.action_key_for_argv(&a);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn wrangler_factory_login_is_unsupported() {
        let f = WranglerFactory;
        let a = args(&["login"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn wrangler_factory_deploy_with_config_is_payload_analysis() {
        let f = WranglerFactory;
        let a = args(&["deploy", "--config", "wrangler.toml"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn wrangler_factory_deploy_without_config_is_resolver_required() {
        let f = WranglerFactory;
        let a = args(&["deploy"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn wrangler_factory_secret_put_is_unsupported() {
        let f = WranglerFactory;
        let a = args(&["secret", "put", "MY_SECRET"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn wrangler_factory_r2_delete_is_resolver_required() {
        let f = WranglerFactory;
        let a = args(&["r2", "object", "delete", "bucket/key.txt"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn wrangler_factory_target_extraction() {
        let f = WranglerFactory;
        let a = args(&["deploy", "--name", "my-worker"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.provider, "cloudflare");
        assert_eq!(target.worker_name, Some("my-worker".to_string()));
        assert_eq!(target.account_id, None);
    }

    #[test]
    fn wrangler_factory_target_extraction_no_name() {
        let f = WranglerFactory;
        let a = args(&["deploy"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.provider, "cloudflare");
        assert_eq!(target.worker_name, None);
    }

    #[test]
    fn wrangler_factory_contract_runs_conformance_corpus() {
        let corpus = core_construct_runtime::factory::parse_factory_fixture_corpus(include_str!(
            "../conformance/wrangler/factory-fixtures.toml"
        ))
        .expect("fixture TOML parses");
        let errors = core_construct_runtime::factory::validate_factory_fixture_corpus(&corpus);
        assert!(errors.is_empty(), "{errors:#?}");
        let carrier = core_construct_runtime::factory::ActionManifestV2Carrier::parse(
            include_str!("../construct/wrangler.toml"),
        )
        .expect("valid wrangler manifest");
        let report = core_construct_runtime::factory::run_factory_fixtures(
            &WranglerFactory,
            Some(&carrier),
            &corpus,
        );
        assert!(report.is_clean(), "{:#?}", report.failures);
    }
}
