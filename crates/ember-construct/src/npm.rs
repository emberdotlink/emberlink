//! Argv classifier: maps `npm <verb> ...` to a `construct.toml` action_key.
//! Per ADR 124 §3 — this lives shim-side BUT the daemon re-classifies the argv
//! server-side (untrusts the shim).
//!
//! Coverage (cohort-A scope catalog):
//!   - `publish [tarball|dir]`      → `npm.publish.<registry-host>`
//!   - `version <newversion>`       → `npm.version`
//!   - `install / i / add`          → `npm.install.<registry-host>`
//!   - `ci`                         → `npm.ci.<registry-host>`
//!   - `run-script / run / start /
//!     test / restart / stop`       → `npm.run-script`
//!   - `audit fix`                  → `npm.audit-fix`
//!   - `deprecate <pkg> <msg>`      → `npm.deprecate.<registry-host>`
//!   - `dist-tag <add|rm|set> ...`  → `npm.dist-tag.<registry-host>`
//!   - reads (ls / list / view / info / show / outdated / audit /
//!     config get / search / ping / whoami) → None (passthrough)
//!   - anything else              → None (passthrough)
//!
//! Registry-host extraction order:
//!   1. `--registry <url>` / `--registry=<url>` argv flag
//!   2. `npm_config_registry` / `NPM_CONFIG_REGISTRY` env var
//!   3. fallback → `npmjs.org`
//!
//! NOTE — `publishConfig.registry` from the package's `package.json` would
//! also override (npm's documented precedence). The shim does NOT read the
//! filesystem here; the daemon re-classifies server-side and is the
//! authoritative resolver. This keeps the shim deterministic on argv+env.

use core_construct_runtime::ActionKey;
use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};
use std::env;

const DEFAULT_REGISTRY: &str = "npmjs.org";

/// Classify `npm <verb> ...` argv into an action_key.
///
/// Returns `None` for read-only / unrecognized shapes — the runtime treats
/// `None` as passthrough (no broker mediation).
pub fn classify_npm_argv(argv: &[String]) -> Option<ActionKey> {
    let verb = argv.first()?.as_str();

    match verb {
        // Reads → passthrough. Daemon re-classifies; runtime spawns npm
        // directly without minting credentials.
        "ls" | "list" | "view" | "info" | "show" | "outdated" | "search" | "ping" | "whoami" => {
            None
        }

        // `npm audit` alone is a read; `npm audit fix` is a write.
        "audit" => {
            if argv.iter().skip(1).any(|a| a == "fix") {
                Some(ActionKey("npm.audit-fix".to_string()))
            } else {
                None
            }
        }

        // `npm config get <key>` is a read; `npm config set <key>` is a write
        // but we don't currently mediate it (broker would not mint creds).
        "config" => None,

        "publish" => {
            let host = registry_host(argv);
            Some(ActionKey(format!("npm.publish.{host}")))
        }

        "version" => Some(ActionKey("npm.version".to_string())),

        "install" | "i" | "add" | "isntall" | "in" | "ins" | "inst" | "insta" | "instal"
        | "isnta" | "isnstall" => {
            let host = registry_host(argv);
            Some(ActionKey(format!("npm.install.{host}")))
        }

        "ci" => {
            let host = registry_host(argv);
            Some(ActionKey(format!("npm.ci.{host}")))
        }

        "run" | "run-script" | "start" | "test" | "restart" | "stop" => {
            Some(ActionKey("npm.run-script".to_string()))
        }

        "deprecate" => {
            let host = registry_host(argv);
            Some(ActionKey(format!("npm.deprecate.{host}")))
        }

        "dist-tag" => {
            let host = registry_host(argv);
            Some(ActionKey(format!("npm.dist-tag.{host}")))
        }

        // Explicit deny key — broker will reject at resolve time. Classified
        // here so the daemon sees npm.unpublish rather than unknown (None).
        // See construct.toml §explicit deny list and construct-coverage-audit.
        "unpublish" => Some(ActionKey("npm.unpublish".to_string())),

        // Local tarball creation — non-destructive pre-publish step.
        // See construct.toml §pre-publish local ops and construct-coverage-audit.
        "pack" => Some(ActionKey("npm.pack".to_string())),

        _ => None,
    }
}

/// Extract the registry host from argv `--registry <url>` / `--registry=<url>`
/// or from the `npm_config_registry` / `NPM_CONFIG_REGISTRY` env var. Falls
/// back to `npmjs.org`.
fn registry_host(argv: &[String]) -> String {
    if let Some(url) = registry_from_argv(argv) {
        return host_from_url(&url);
    }
    if let Ok(url) = env::var("npm_config_registry")
        && !url.is_empty()
    {
        return host_from_url(&url);
    }
    if let Ok(url) = env::var("NPM_CONFIG_REGISTRY")
        && !url.is_empty()
    {
        return host_from_url(&url);
    }
    DEFAULT_REGISTRY.to_string()
}

/// Scan argv for `--registry <url>` (split form) or `--registry=<url>`
/// (joined form).
fn registry_from_argv(argv: &[String]) -> Option<String> {
    let mut iter = argv.iter();
    while let Some(a) = iter.next() {
        if let Some(url) = a.strip_prefix("--registry=") {
            return Some(url.to_string());
        }
        if a == "--registry"
            && let Some(url) = iter.next()
        {
            return Some(url.clone());
        }
    }
    None
}

/// Parse the host portion of a registry URL.
///
/// Accepts `https://registry.npmjs.org/`, `http://10.0.0.5:4873/`, bare
/// `registry.example.com`, etc. Strips scheme, path, userinfo. Preserves the
/// `:port` suffix for non-default ports so action keys are precise.
fn host_from_url(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);

    let after_userinfo = after_scheme
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(after_scheme);

    let host_with_port = after_userinfo
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_userinfo);

    if host_with_port.is_empty() {
        return DEFAULT_REGISTRY.to_string();
    }

    host_with_port.to_string()
}

// ---------------------------------------------------------------------------
// NpmFactory — P24 construct-factory contract for the npm construct
// ---------------------------------------------------------------------------

static NPM_MANIFEST: std::sync::LazyLock<core_events::construct_toml::ParsedActionManifest> =
    std::sync::LazyLock::new(|| {
        core_events::construct_toml::parse_action_manifest(include_str!("../construct/npm.toml"))
            .expect("bundled npm.toml must be valid")
    });

fn manifest_need_for_action(action_key: &str) -> Option<Vec<String>> {
    NPM_MANIFEST
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

// Manifest-membership helper retained for parity with manifest_need_for_action; not yet wired.
#[allow(dead_code)]
fn action_in_manifest(action_key: &str) -> bool {
    NPM_MANIFEST
        .manifest
        .actions
        .iter()
        .any(|a| a.key == action_key)
}

#[derive(Debug, Default, Clone)]
pub struct NpmFactory;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmFactoryTarget {
    pub provider: &'static str,
    pub registry_host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmFactoryNeed(pub Vec<String>);

impl InvocationGrammar for NpmFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_npm_argv(argv)
    }
}

impl TargetExtractor for NpmFactory {
    type Target = NpmFactoryTarget;

    fn target_for_argv(&self, action_key: &ActionKey, argv: &[String]) -> Option<Self::Target> {
        let key = &action_key.0;
        if key.starts_with("npm.publish.")
            || key.starts_with("npm.install.")
            || key.starts_with("npm.ci.")
            || key.starts_with("npm.deprecate.")
            || key.starts_with("npm.dist-tag.")
        {
            let host = registry_host(argv);
            Some(NpmFactoryTarget {
                provider: "npm",
                registry_host: host,
            })
        } else {
            None
        }
    }
}

impl NeedTemplate for NpmFactory {
    type Need = NpmFactoryNeed;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        _target: &Self::Target,
        _argv: &[String],
    ) -> Option<Self::Need> {
        manifest_need_for_action(&action_key.0).map(NpmFactoryNeed)
    }
}

fn has_inline_auth_token(argv: &[String]) -> bool {
    argv.iter()
        .any(|a| a.starts_with("--//") && a.contains(":_authToken="))
}

fn has_package_flag(argv: &[String]) -> bool {
    argv.iter()
        .any(|a| a == "--package" || a.starts_with("--package="))
        || argv.windows(2).any(|w| w[0] == "--pack-destination")
}

impl ConstructFactory for NpmFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> FactoryDisposition {
        let Some(key) = action_key else {
            return FactoryDisposition::Credentialless;
        };

        if key.0 == "npm.unpublish" {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        if key.0.starts_with("npm.publish") {
            if has_inline_auth_token(argv) {
                return FactoryDisposition::UnsupportedFailClosed;
            }
            if has_package_flag(argv) {
                return FactoryDisposition::PayloadAnalysisRequired;
            }
            return FactoryDisposition::ResolverRequired;
        }

        if key.0.starts_with("npm.deprecate") || key.0.starts_with("npm.dist-tag") {
            return FactoryDisposition::ResolverRequired;
        }

        FactoryDisposition::Credentialless
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    /// Guard helper — clear registry env vars before tests that depend on
    /// fallback behavior, so a developer's local `npm_config_registry` does
    /// not leak in.
    fn clear_registry_env() {
        // SAFETY: tests run sequentially within a single process by default in
        // Rust's test harness when not marked with `#[test]` parallelism opt-in.
        // We mutate process env only to neutralize developer-machine leakage.
        unsafe {
            env::remove_var("npm_config_registry");
            env::remove_var("NPM_CONFIG_REGISTRY");
        }
    }

    #[test]
    fn publish_default_registry() {
        clear_registry_env();
        let r = classify_npm_argv(&args(&["publish"])).unwrap();
        assert_eq!(r.0, "npm.publish.npmjs.org");
    }

    #[test]
    fn publish_with_registry_flag_split() {
        clear_registry_env();
        let r = classify_npm_argv(&args(&[
            "publish",
            "--registry",
            "https://registry.example.com/",
        ]))
        .unwrap();
        assert_eq!(r.0, "npm.publish.registry.example.com");
    }

    #[test]
    fn publish_with_registry_flag_joined() {
        clear_registry_env();
        let r = classify_npm_argv(&args(&["publish", "--registry=https://npm.pkg.github.com"]))
            .unwrap();
        assert_eq!(r.0, "npm.publish.npm.pkg.github.com");
    }

    #[test]
    fn publish_with_port_preserves_port() {
        clear_registry_env();
        let r = classify_npm_argv(&args(&["publish", "--registry=http://10.0.0.5:4873/"])).unwrap();
        assert_eq!(r.0, "npm.publish.10.0.0.5:4873");
    }

    #[test]
    fn version_classified() {
        let r = classify_npm_argv(&args(&["version", "patch"])).unwrap();
        assert_eq!(r.0, "npm.version");
    }

    #[test]
    fn install_default_registry() {
        clear_registry_env();
        let r = classify_npm_argv(&args(&["install", "lodash"])).unwrap();
        assert_eq!(r.0, "npm.install.npmjs.org");
    }

    #[test]
    fn install_alias_i() {
        clear_registry_env();
        let r = classify_npm_argv(&args(&["i", "lodash"])).unwrap();
        assert_eq!(r.0, "npm.install.npmjs.org");
    }

    #[test]
    fn install_alias_add() {
        clear_registry_env();
        let r = classify_npm_argv(&args(&["add", "lodash"])).unwrap();
        assert_eq!(r.0, "npm.install.npmjs.org");
    }

    #[test]
    fn install_with_registry_flag() {
        clear_registry_env();
        let r = classify_npm_argv(&args(&[
            "install",
            "--registry",
            "https://npm.example.com/",
            "@org/pkg",
        ]))
        .unwrap();
        assert_eq!(r.0, "npm.install.npm.example.com");
    }

    #[test]
    fn ci_classified() {
        clear_registry_env();
        let r = classify_npm_argv(&args(&["ci"])).unwrap();
        assert_eq!(r.0, "npm.ci.npmjs.org");
    }

    #[test]
    fn ci_with_registry_flag() {
        clear_registry_env();
        let r =
            classify_npm_argv(&args(&["ci", "--registry=https://registry.npmjs.org/"])).unwrap();
        assert_eq!(r.0, "npm.ci.registry.npmjs.org");
    }

    #[test]
    fn run_script_classified() {
        let r = classify_npm_argv(&args(&["run", "build"])).unwrap();
        assert_eq!(r.0, "npm.run-script");

        let r = classify_npm_argv(&args(&["run-script", "build"])).unwrap();
        assert_eq!(r.0, "npm.run-script");
    }

    #[test]
    fn lifecycle_aliases_classified() {
        for verb in &["start", "test", "restart", "stop"] {
            let r = classify_npm_argv(&args(&[verb])).unwrap();
            assert_eq!(r.0, "npm.run-script", "{verb} should map to npm.run-script");
        }
    }

    #[test]
    fn audit_passthrough() {
        // Bare `npm audit` is a read.
        assert!(classify_npm_argv(&args(&["audit"])).is_none());
    }

    #[test]
    fn audit_fix_classified() {
        let r = classify_npm_argv(&args(&["audit", "fix"])).unwrap();
        assert_eq!(r.0, "npm.audit-fix");
    }

    #[test]
    fn deprecate_classified() {
        clear_registry_env();
        let r = classify_npm_argv(&args(&["deprecate", "mypkg@1.0.0", "use mypkg@2"])).unwrap();
        assert_eq!(r.0, "npm.deprecate.npmjs.org");
    }

    #[test]
    fn dist_tag_classified() {
        clear_registry_env();
        let r = classify_npm_argv(&args(&["dist-tag", "add", "mypkg@1.2.3", "latest"])).unwrap();
        assert_eq!(r.0, "npm.dist-tag.npmjs.org");
    }

    #[test]
    fn reads_passthrough() {
        for verb in &[
            "ls", "list", "view", "info", "show", "outdated", "search", "ping", "whoami",
        ] {
            assert!(
                classify_npm_argv(&args(&[verb])).is_none(),
                "{verb} should passthrough"
            );
        }
    }

    #[test]
    fn config_passthrough() {
        // `npm config get <key>` and `npm config set <key>` are passthrough at
        // this layer — broker does not mint creds for config ops.
        assert!(classify_npm_argv(&args(&["config", "get", "registry"])).is_none());
        assert!(classify_npm_argv(&args(&["config", "set", "registry", "x"])).is_none());
    }

    #[test]
    fn empty_argv_is_passthrough() {
        assert!(classify_npm_argv(&[]).is_none());
    }

    #[test]
    fn unknown_verb_passthrough() {
        assert!(classify_npm_argv(&args(&["bogus-verb"])).is_none());
    }

    // T1: npm.unpublish — must classify so the broker can apply the explicit deny.
    #[test]
    fn unpublish_classified() {
        let r = classify_npm_argv(&args(&["unpublish", "mypkg@1.0.0"])).unwrap();
        assert_eq!(r.0, "npm.unpublish");
    }

    // T1: npm.pack — non-destructive local op, must classify to permit path.
    #[test]
    fn pack_classified() {
        let r = classify_npm_argv(&args(&["pack"])).unwrap();
        assert_eq!(r.0, "npm.pack");
    }

    #[test]
    fn host_url_with_userinfo_strips_user() {
        let url = format!("https://{}@npm.example.com/", "user:pass");
        assert_eq!(host_from_url(&url), "npm.example.com");
    }

    #[test]
    fn host_url_bare_host() {
        assert_eq!(host_from_url("registry.npmjs.org"), "registry.npmjs.org");
    }

    #[test]
    fn host_url_path_stripped() {
        assert_eq!(
            host_from_url("https://npm.pkg.github.com/some/path"),
            "npm.pkg.github.com"
        );
    }

    #[test]
    fn host_url_query_stripped() {
        assert_eq!(
            host_from_url("https://registry.example.com/?foo=bar"),
            "registry.example.com"
        );
    }

    // --- NpmFactory tests ---

    #[test]
    fn npm_factory_version_flag_is_credentialless() {
        let f = NpmFactory;
        let a = args(&["--version"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn npm_factory_publish_is_resolver_required() {
        clear_registry_env();
        let f = NpmFactory;
        let a = args(&["publish", "--registry", "https://registry.npmjs.org/"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn npm_factory_publish_package_is_payload_analysis() {
        clear_registry_env();
        let f = NpmFactory;
        let a = args(&["publish", "--package", "pkg.tgz"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn npm_factory_publish_inline_auth_is_unsupported() {
        clear_registry_env();
        let f = NpmFactory;
        let a = args(&["publish", "--//registry.npmjs.org/:_authToken=npm-token"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn npm_factory_unpublish_is_unsupported() {
        let f = NpmFactory;
        let a = args(&["unpublish", "mypkg@1.0.0"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn npm_factory_install_is_credentialless() {
        clear_registry_env();
        let f = NpmFactory;
        let a = args(&["install", "lodash"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn npm_factory_run_script_is_credentialless() {
        let f = NpmFactory;
        let a = args(&["run", "build"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn npm_factory_deprecate_is_resolver_required() {
        clear_registry_env();
        let f = NpmFactory;
        let a = args(&["deprecate", "mypkg@1.0.0", "use mypkg@2"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn npm_factory_pack_is_credentialless() {
        let f = NpmFactory;
        let a = args(&["pack"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn npm_factory_target_extraction_publish() {
        clear_registry_env();
        let f = NpmFactory;
        let a = args(&["publish", "--registry", "https://npm.pkg.github.com/"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.provider, "npm");
        assert_eq!(target.registry_host, "npm.pkg.github.com");
    }

    #[test]
    fn npm_factory_target_extraction_run_script_returns_none() {
        let f = NpmFactory;
        let a = args(&["run", "build"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert!(f.target_for_argv(&key, &a).is_none());
    }

    #[test]
    fn npm_factory_contract_runs_conformance_corpus() {
        clear_registry_env();
        let corpus = core_construct_runtime::factory::parse_factory_fixture_corpus(include_str!(
            "../conformance/npm/factory-fixtures.toml"
        ))
        .expect("fixture corpus parses");
        let validation_errors =
            core_construct_runtime::factory::validate_factory_fixture_corpus(&corpus);
        assert!(validation_errors.is_empty(), "{validation_errors:#?}");

        let carrier = core_construct_runtime::factory::ActionManifestV2Carrier::parse(
            include_str!("../construct/npm.toml"),
        )
        .expect("npm manifest carrier parses");
        let report = core_construct_runtime::factory::run_factory_fixtures(
            &NpmFactory,
            Some(&carrier),
            &corpus,
        );
        assert!(report.is_clean(), "{:#?}", report.failures);
    }
}
