//! ember-construct — consolidated crate for all 15 bundled L2 Construct binaries.
//!
//! Per ADR 125: one crate produces 15 `[[bin]]` targets (one per wrapped tool).
//! Each binary embeds its own vendor identifier and `construct.toml` bytes so
//! binaries hash to 15 distinct `content_hash` values, preserving per-vendor
//! WoT trust delegation scoping per ADR 123 §2 + ADR 124 §1.

pub mod aws;
pub mod az;
pub mod delegation_template_schema;
pub mod docker;
pub mod env_derive;
pub mod flyctl;
pub mod gcloud;
pub mod gh;
pub mod git;
pub mod kubectl;
pub mod npm;
pub mod okta;
pub mod policy;
pub mod pulumi;
pub mod scion;
pub mod terraform;
pub mod tofu;
pub mod vercel;
pub mod wrangler;

pub use delegation_template_schema::{Capability, DelegationTemplate, DelegationTemplateError};
pub use gh::GhClassifier;
pub use git::GitClassifier;
pub use kubectl::KubectlClassifier;
pub use policy::{
    CredentialInjection, CredentialPolicy, credential_policy, github_action_catalog,
    manifest_action_need, template_github_needs,
};

use std::process::ExitCode;

use core_construct_runtime::factory::{ConstructFactory, FactoryDisposition};
use core_construct_runtime::{ActionKey, ClassifyArgv, ConstructConfig};

// ---------------------------------------------------------------------------
// VendorManifest — per-vendor compile-time data row
// ---------------------------------------------------------------------------

/// Compile-time descriptor for one bundled L2 Construct vendor.
pub struct VendorManifest {
    pub name: &'static str,
    pub binary_name: &'static str,
    pub binary_env_var: &'static str,
    pub classifier: fn(&[String]) -> Option<ActionKey>,
    /// Emberlink-shaped argv → wrapped-tool-native argv. Defaults to identity
    /// via `identity_argv_translator` for vendors with no emberlink-specific
    /// flags. Scion overrides to `scion::translate_scion_argv` per ADR 140 §4.
    /// See `ConstructConfig::translate_argv` for the contract.
    pub argv_translator: fn(&[String]) -> Vec<String>,
    pub env_passthrough: &'static [&'static str],
    pub construct_toml: &'static [u8],
}

/// Default `argv_translator` — copy argv through unchanged. Used for every
/// vendor whose emberlink-shaped argv is already the wrapped tool's native
/// argv (gh, git, kubectl, aws, etc.).
pub fn identity_argv_translator(argv: &[String]) -> Vec<String> {
    argv.to_vec()
}

// ---------------------------------------------------------------------------
// VENDORS — the 15-row compile-time registry
// ---------------------------------------------------------------------------

pub static VENDORS: &[VendorManifest] = &[
    VendorManifest {
        name: "aws",
        binary_name: "aws",
        binary_env_var: "EMBER_AWS_BINARY",
        classifier: aws::classify_aws_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &["AWS_DEFAULT_REGION"],
        construct_toml: include_bytes!("../construct/aws.toml"),
    },
    VendorManifest {
        name: "az",
        binary_name: "az",
        binary_env_var: "EMBER_AZ_BINARY",
        classifier: az::classify_az_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &["AZURE_ACCESS_TOKEN", "AZURE_AUTH_LOCATION"],
        construct_toml: include_bytes!("../construct/az.toml"),
    },
    VendorManifest {
        name: "gcloud",
        binary_name: "gcloud",
        binary_env_var: "EMBER_GCLOUD_BINARY",
        classifier: gcloud::classify_gcloud_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &[
            "CLOUDSDK_AUTH_ACCESS_TOKEN",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ],
        construct_toml: include_bytes!("../construct/gcloud.toml"),
    },
    VendorManifest {
        name: "vercel",
        binary_name: "vercel",
        binary_env_var: "EMBER_VERCEL_BINARY",
        classifier: vercel::classify_vercel_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &["VERCEL_TOKEN"],
        construct_toml: include_bytes!("../construct/vercel.toml"),
    },
    VendorManifest {
        name: "wrangler",
        binary_name: "wrangler",
        binary_env_var: "EMBER_WRANGLER_BINARY",
        classifier: wrangler::classify_wrangler_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &["CLOUDFLARE_API_TOKEN"],
        construct_toml: include_bytes!("../construct/wrangler.toml"),
    },
    VendorManifest {
        name: "gh",
        binary_name: "gh",
        binary_env_var: "EMBER_GH_BINARY",
        classifier: gh::classify_gh_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &["GH_TOKEN", "GITHUB_TOKEN", "GH_HOST"],
        construct_toml: include_bytes!("../construct/gh.toml"),
    },
    VendorManifest {
        name: "git",
        binary_name: "git",
        binary_env_var: "EMBER_GIT_BINARY",
        classifier: git::classify_git_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &[
            "GITHUB_TOKEN",
            "GITHUB_PERSONAL_ACCESS_TOKEN",
            "GIT_SSH_COMMAND",
            "GIT_SSH",
            "GIT_ASKPASS",
            "GIT_TERMINAL_PROMPT",
            "GIT_AUTHOR_NAME",
            "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME",
            "GIT_COMMITTER_EMAIL",
        ],
        construct_toml: include_bytes!("../construct/git.toml"),
    },
    VendorManifest {
        name: "docker",
        binary_name: "docker",
        binary_env_var: "EMBER_DOCKER_BINARY",
        classifier: docker::classify_docker_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &[
            "DOCKER_CONFIG",
            "DOCKER_HOST",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        ],
        construct_toml: include_bytes!("../construct/docker.toml"),
    },
    VendorManifest {
        name: "kubectl",
        binary_name: "kubectl",
        binary_env_var: "EMBER_KUBECTL_BINARY",
        classifier: kubectl::classify_kubectl_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &[
            "KUBECONFIG",
            "AWS_PROFILE",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "AZURE_TENANT_ID",
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
        ],
        construct_toml: include_bytes!("../construct/kubectl.toml"),
    },
    VendorManifest {
        name: "pulumi",
        binary_name: "pulumi",
        binary_env_var: "EMBER_PULUMI_BINARY",
        classifier: pulumi::classify_pulumi_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &[
            "PULUMI_CONFIG_PASSPHRASE",
            "PULUMI_ACCESS_TOKEN",
            "PULUMI_BACKEND_URL",
        ],
        construct_toml: include_bytes!("../construct/pulumi.toml"),
    },
    VendorManifest {
        name: "terraform",
        binary_name: "terraform",
        binary_env_var: "EMBER_TERRAFORM_BINARY",
        classifier: terraform::classify_terraform_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &[],
        construct_toml: include_bytes!("../construct/terraform.toml"),
    },
    VendorManifest {
        name: "tofu",
        binary_name: "tofu",
        binary_env_var: "EMBER_TOFU_BINARY",
        classifier: tofu::classify_tofu_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &[],
        construct_toml: include_bytes!("../construct/tofu.toml"),
    },
    VendorManifest {
        name: "flyctl",
        binary_name: "flyctl",
        binary_env_var: "EMBER_FLYCTL_BINARY",
        classifier: flyctl::classify_flyctl_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &["FLY_API_TOKEN"],
        construct_toml: include_bytes!("../construct/flyctl.toml"),
    },
    VendorManifest {
        name: "npm",
        binary_name: "npm",
        binary_env_var: "EMBER_NPM_BINARY",
        classifier: npm::classify_npm_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &["NPM_TOKEN", "NPM_CONFIG_REGISTRY", "npm_config_registry"],
        construct_toml: include_bytes!("../construct/npm.toml"),
    },
    VendorManifest {
        name: "okta",
        binary_name: "okta",
        binary_env_var: "EMBER_OKTA_BINARY",
        classifier: okta::classify_okta_argv,
        argv_translator: identity_argv_translator,
        env_passthrough: &["OKTA_API_TOKEN"],
        construct_toml: include_bytes!("../construct/okta.toml"),
    },
    VendorManifest {
        name: "scion",
        // Upstream binary name is "scion" (not "ember-scion"). When
        // EMBER_SESSION_ID is absent the shim passthrough-execs the real
        // scion binary via pick_binary_from_path, which skips self (the
        // ember-scion shim binary) and finds the upstream "scion" downstream
        // on PATH. Using "ember-scion" here would cause pick_binary_from_path
        // to fall through (only one ember-scion on PATH — the shim itself)
        // and the fallback would re-exec the shim → infinite loop.
        binary_name: "scion",
        binary_env_var: "EMBER_SCION_BINARY",
        classifier: scion::classify_scion_argv_key,
        // Scion overrides the default identity translator per ADR 140 §4
        // (META-AP-EMBER-SCION-SHIM-ARGV-A): emberlink-shaped argv
        // (`--persona X --max-depth N --template emberlink-worker --brief ...`)
        // becomes scion-native (`--type emberlink-worker --non-interactive`).
        argv_translator: scion::translate_scion_argv,
        env_passthrough: &[],
        construct_toml: include_bytes!("../construct/scion.toml"),
    },
];

// ---------------------------------------------------------------------------
// pick_binary_from_path — PATH scan that skips our own shim binary
// ---------------------------------------------------------------------------

/// Pick the first `<dir>/<binary_name>` on `path` that is a file AND is not
/// the same canonical path as `self_path`.
///
/// Construct shims live in a shadow dir prepended to `PATH`
/// (e.g. `.ember/shadow/git`). A naive first-match-on-PATH walk would pick
/// the shim itself, `exec()` back into `run()`, and burn 100% CPU in an
/// infinite re-exec loop. Comparing each candidate's canonical path against
/// `current_exe()` and skipping self-matches lets us find the wrapped real
/// binary downstream of the shadow dir.
fn pick_binary_from_path(
    path: &str,
    binary_name: &str,
    self_path: Option<&std::path::Path>,
) -> Option<String> {
    path.split(':')
        .map(|dir| format!("{dir}/{binary_name}"))
        .find(|p| {
            if !std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false) {
                return false;
            }
            match (std::fs::canonicalize(p).ok(), self_path) {
                (Some(c), Some(s)) => c != *s,
                _ => true,
            }
        })
}

// ---------------------------------------------------------------------------
// ManifestConfig — ConstructConfig adapter backed by a VendorManifest row
// ---------------------------------------------------------------------------

struct ManifestConfig<'a>(&'a VendorManifest);

impl ClassifyArgv for ManifestConfig<'_> {
    fn classify(&self, argv: &[String]) -> Option<ActionKey> {
        (self.0.classifier)(argv)
    }
}

impl ConstructConfig for ManifestConfig<'_> {
    fn vendor(&self) -> &'static str {
        self.0.name
    }

    fn session_id_env(&self) -> &'static str {
        "EMBER_SESSION_ID"
    }

    fn construct_toml_bytes(&self) -> &'static [u8] {
        self.0.construct_toml
    }

    fn resolve_binary(&self) -> String {
        let env_var = self.0.binary_env_var;
        let binary_name = self.0.binary_name;
        std::env::var(env_var).unwrap_or_else(|_| {
            let self_path = std::env::current_exe().and_then(std::fs::canonicalize).ok();
            let path = std::env::var("PATH").unwrap_or_default();
            pick_binary_from_path(&path, binary_name, self_path.as_deref())
                .unwrap_or_else(|| binary_name.to_string())
        })
    }

    fn env_passthrough(&self) -> &'static [&'static str] {
        self.0.env_passthrough
    }

    fn factory_disposition(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> Option<FactoryDisposition> {
        match self.0.name {
            "aws" => Some(aws::AwsFactory.disposition_for_argv(action_key, argv)),
            "gh" => Some(gh::GhFactory.disposition_for_argv(action_key, argv)),
            "git" => Some(git::GitFactory.disposition_for_argv(action_key, argv)),
            "docker" => Some(docker::DockerFactory.disposition_for_argv(action_key, argv)),
            "npm" => Some(npm::NpmFactory.disposition_for_argv(action_key, argv)),
            "az" => Some(az::AzFactory.disposition_for_argv(action_key, argv)),
            "gcloud" => Some(gcloud::GcloudFactory.disposition_for_argv(action_key, argv)),
            "flyctl" => Some(flyctl::FlyctlFactory.disposition_for_argv(action_key, argv)),
            "vercel" => Some(vercel::VercelFactory.disposition_for_argv(action_key, argv)),
            "okta" => Some(okta::OktaFactory.disposition_for_argv(action_key, argv)),
            "wrangler" => Some(wrangler::WranglerFactory.disposition_for_argv(action_key, argv)),
            "scion" => Some(scion::ScionFactory.disposition_for_argv(action_key, argv)),
            "kubectl" => Some(kubectl::KubectlFactory.disposition_for_argv(action_key, argv)),
            "terraform" => Some(terraform::TerraformFactory.disposition_for_argv(action_key, argv)),
            "tofu" => Some(tofu::TofuFactory.disposition_for_argv(action_key, argv)),
            "pulumi" => Some(pulumi::PulumiFactory.disposition_for_argv(action_key, argv)),
            _ => None,
        }
    }

    /// Per-construct trusted-resolver dispatch. Only constructs with a
    /// sensible cwd-derive (`gh` + `git` for v0.3.0) override the default
    /// `None`; the rest fall through to the existing ResolverRequired
    /// refusal at the runtime (Phase 2b/2c is a follow-up).
    fn resolve_target_from_environment(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
        cwd: &std::path::Path,
    ) -> Option<Vec<String>> {
        match self.0.name {
            "gh" => gh::GhFactory.resolve_target_from_environment(action_key, argv, cwd),
            "git" => git::GitFactory.resolve_target_from_environment(action_key, argv, cwd),
            _ => None,
        }
    }

    fn credentialless_env_scrub(&self) -> &'static [&'static str] {
        match self.0.name {
            "aws" => &[
                "AWS_ACCESS_KEY_ID",
                "AWS_ACCESS_KEY",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SECRET_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_SECURITY_TOKEN",
                "AWS_PROFILE",
                "AWS_DEFAULT_PROFILE",
                "AWS_SHARED_CREDENTIALS_FILE",
                "AWS_CONFIG_FILE",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                "AWS_ROLE_ARN",
                "AWS_ROLE_SESSION_NAME",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                "AWS_CONTAINER_AUTHORIZATION_TOKEN",
                "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
                "AWS_SDK_LOAD_CONFIG",
            ],
            "gh" => &[
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "GH_ENTERPRISE_TOKEN",
                "GITHUB_ENTERPRISE_TOKEN",
            ],
            "git" => &[
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "GITHUB_PERSONAL_ACCESS_TOKEN",
                "GIT_ASKPASS",
            ],
            "docker" => &["DOCKER_CONFIG", "DOCKER_AUTH_CONFIG", "REGISTRY_AUTH_FILE"],
            "npm" => &[
                "NPM_TOKEN",
                "NPM_CONFIG__AUTHTOKEN",
                "npm_config__authToken",
                "NODE_AUTH_TOKEN",
            ],
            "az" => &[
                "AZURE_CLIENT_ID",
                "AZURE_CLIENT_SECRET",
                "AZURE_TENANT_ID",
                "AZURE_SUBSCRIPTION_ID",
                "AZURE_DEFAULTS_GROUP",
                "AZURE_DEFAULTS_LOCATION",
            ],
            "gcloud" => &[
                "GOOGLE_APPLICATION_CREDENTIALS",
                "GOOGLE_CLOUD_PROJECT",
                "GCLOUD_PROJECT",
                "CLOUDSDK_CORE_PROJECT",
                "CLOUDSDK_CORE_ACCOUNT",
                "CLOUDSDK_AUTH_ACCESS_TOKEN",
            ],
            "flyctl" => &["FLY_API_TOKEN", "FLY_ACCESS_TOKEN"],
            "vercel" => &["VERCEL_TOKEN", "VERCEL_ORG_ID", "VERCEL_PROJECT_ID"],
            "okta" => &["OKTA_API_TOKEN", "OKTA_CLIENT_ID", "OKTA_CLIENT_SECRET"],
            "wrangler" => &[
                "CLOUDFLARE_API_TOKEN",
                "CLOUDFLARE_API_KEY",
                "CLOUDFLARE_EMAIL",
                "CLOUDFLARE_ACCOUNT_ID",
                "CF_API_TOKEN",
                "CF_API_KEY",
                "CF_EMAIL",
            ],
            "kubectl" => &[
                "KUBECONFIG",
                "AWS_PROFILE",
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "GOOGLE_APPLICATION_CREDENTIALS",
                "AZURE_TENANT_ID",
                "AZURE_CLIENT_ID",
                "AZURE_CLIENT_SECRET",
            ],
            "terraform" => &[
                "TF_TOKEN_app_terraform_io",
                "TF_VAR_access_key",
                "TF_VAR_secret_key",
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "GOOGLE_APPLICATION_CREDENTIALS",
                "GOOGLE_CREDENTIALS",
                "ARM_CLIENT_ID",
                "ARM_CLIENT_SECRET",
                "ARM_TENANT_ID",
                "ARM_SUBSCRIPTION_ID",
            ],
            "tofu" => &[
                "TF_TOKEN_app_terraform_io",
                "TF_VAR_access_key",
                "TF_VAR_secret_key",
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "GOOGLE_APPLICATION_CREDENTIALS",
                "GOOGLE_CREDENTIALS",
                "ARM_CLIENT_ID",
                "ARM_CLIENT_SECRET",
                "ARM_TENANT_ID",
                "ARM_SUBSCRIPTION_ID",
            ],
            "pulumi" => &[
                "PULUMI_ACCESS_TOKEN",
                "PULUMI_CONFIG_PASSPHRASE",
                "PULUMI_BACKEND_URL",
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "GOOGLE_APPLICATION_CREDENTIALS",
                "GOOGLE_CREDENTIALS",
                "ARM_CLIENT_ID",
                "ARM_CLIENT_SECRET",
                "ARM_TENANT_ID",
                "ARM_SUBSCRIPTION_ID",
            ],
            _ => &[],
        }
    }

    fn credentialless_env_set(&self) -> &'static [(&'static str, &'static str)] {
        match self.0.name {
            "aws" => &[
                ("AWS_SHARED_CREDENTIALS_FILE", "/dev/null"),
                ("AWS_CONFIG_FILE", "/dev/null"),
                ("AWS_EC2_METADATA_DISABLED", "true"),
            ],
            "git" => &[("GIT_TERMINAL_PROMPT", "0")],
            "terraform" => &[("TF_INPUT", "false")],
            "tofu" => &[("TF_INPUT", "false")],
            _ => &[],
        }
    }

    fn translate_argv(&self, argv: &[String]) -> Vec<String> {
        (self.0.argv_translator)(argv)
    }
}

// ---------------------------------------------------------------------------
// run — the [[bin]] entry point
// ---------------------------------------------------------------------------

/// Dispatch entry point called by each `[[bin]]` target's `main.rs`.
///
/// Panics on unknown `vendor` — build-time invariant since `[[bin]]` main.rs
/// files are checked-in code that passes a literal vendor name.
pub fn run(vendor: &str) -> ExitCode {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let manifest = VENDORS
        .iter()
        .find(|v| v.name == vendor)
        .unwrap_or_else(|| {
            panic!("ember-construct: unknown vendor '{vendor}' — check VENDORS table in lib.rs")
        });

    let argv: Vec<String> = std::env::args().skip(1).collect();
    core_construct_runtime::run_construct_full(&argv, &ManifestConfig(manifest))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod resolve_binary_tests {
    use super::pick_binary_from_path;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    /// Regression: a Construct shim that is also the first `git` on PATH
    /// must NOT pick itself, or every passthrough verb (`git --version`,
    /// `git status`, `git log`, ...) infinite-re-execs.
    #[test]
    fn skips_self_and_picks_downstream_real_binary() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let shadow = tmp.path().join("shadow");
        let real = tmp.path().join("real");
        fs::create_dir(&shadow).unwrap();
        fs::create_dir(&real).unwrap();

        let shim = shadow.join("git");
        let downstream = real.join("git");
        fs::write(&shim, "#!/bin/sh\nexit 0\n").unwrap();
        fs::write(&downstream, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&downstream, fs::Permissions::from_mode(0o755)).unwrap();

        let path = format!("{}:{}", shadow.display(), real.display());
        let self_canon = fs::canonicalize(&shim).unwrap();

        let picked = pick_binary_from_path(&path, "git", Some(&self_canon))
            .expect("should find real downstream git");
        let picked_canon = fs::canonicalize(&picked).unwrap();
        assert_eq!(
            picked_canon,
            fs::canonicalize(&downstream).unwrap(),
            "must skip shim ({}) and pick downstream real binary",
            shim.display()
        );
    }

    #[test]
    fn returns_none_when_no_matches() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().display().to_string();
        assert!(pick_binary_from_path(&path, "nonexistent-binary-xyz", None).is_none());
    }

    #[test]
    fn picks_first_match_when_no_self_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bin = tmp.path().join("git");
        fs::write(&bin, "").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let path = tmp.path().display().to_string();
        let picked = pick_binary_from_path(&path, "git", None).expect("should find");
        assert_eq!(picked, bin.display().to_string());
    }
}

// ---------------------------------------------------------------------------
// translate_argv hook tests (META-AP-EMBER-SCION-SHIM-ARGV-B)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod translate_argv_tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn manifest(name: &str) -> &'static VendorManifest {
        VENDORS
            .iter()
            .find(|v| v.name == name)
            .expect("vendor exists")
    }

    #[test]
    fn identity_translator_round_trips_argv() {
        let input = argv(&["status", "--short"]);
        assert_eq!(identity_argv_translator(&input), input);
    }

    #[test]
    fn gh_vendor_uses_identity_translator() {
        let cfg = ManifestConfig(manifest("gh"));
        let input = argv(&["ember-gh", "pr", "create", "--title", "x"]);
        // gh has no emberlink-specific flags — argv passes through.
        assert_eq!(cfg.translate_argv(&input), input);
    }

    #[test]
    fn git_vendor_uses_identity_translator() {
        let cfg = ManifestConfig(manifest("git"));
        let input = argv(&["ember-git", "push", "-u", "origin", "main"]);
        assert_eq!(cfg.translate_argv(&input), input);
    }

    #[test]
    fn scion_vendor_translates_emberlink_argv() {
        // Scion override: strips emberlink-specific flags, renames --template,
        // injects --non-interactive on start. The detailed behaviour is unit-
        // tested in scion::tests; this test only confirms that the
        // ManifestConfig wiring routes scion's argv through translate_scion_argv
        // (not identity).
        let cfg = ManifestConfig(manifest("scion"));
        let input = argv(&[
            "ember-scion",
            "start",
            "ctr1",
            "--persona",
            "alice",
            "--template",
            "emberlink-worker",
        ]);
        let out = cfg.translate_argv(&input);
        let out_str: Vec<&str> = out.iter().map(String::as_str).collect();
        assert!(
            !out_str.contains(&"--persona"),
            "scion translator must strip --persona; got {out:?}"
        );
        assert!(
            out_str.contains(&"--type"),
            "scion translator must rename --template→--type; got {out:?}"
        );
        assert!(
            out_str.contains(&"--non-interactive"),
            "scion translator must inject --non-interactive on start; got {out:?}"
        );
    }

    #[test]
    fn aws_vendor_wires_factory_credentialless_hook() {
        let cfg = ManifestConfig(manifest("aws"));
        let input = argv(&["s3", "ls", "s3://assets"]);
        assert_eq!(
            cfg.factory_disposition(None, &input),
            Some(FactoryDisposition::Credentialless)
        );
        assert!(
            cfg.credentialless_env_scrub()
                .contains(&"AWS_ACCESS_KEY_ID"),
            "AWS credentialless path must scrub provider credential env"
        );
        assert!(
            cfg.credentialless_env_set()
                .contains(&("AWS_EC2_METADATA_DISABLED", "true")),
            "AWS credentialless path must disable metadata credentials"
        );
    }

    #[test]
    fn docker_factory_is_wired() {
        let cfg = ManifestConfig(manifest("docker"));
        let input = argv(&["stop", "my_container"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::Credentialless)
        );
        assert!(!cfg.credentialless_env_scrub().is_empty());
    }

    #[test]
    fn docker_factory_run_is_payload_analysis_required() {
        let cfg = ManifestConfig(manifest("docker"));
        let input = argv(&["run", "--rm", "alpine"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::PayloadAnalysisRequired)
        );
    }

    #[test]
    fn docker_factory_logout_is_blocked() {
        let cfg = ManifestConfig(manifest("docker"));
        let input = argv(&["logout"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn npm_factory_is_wired() {
        let cfg = ManifestConfig(manifest("npm"));
        let input = argv(&["run", "build"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::Credentialless)
        );
        assert!(!cfg.credentialless_env_scrub().is_empty());
    }

    #[test]
    fn gh_factory_is_wired() {
        let cfg = ManifestConfig(manifest("gh"));
        let input = argv(&["pr", "view", "1", "--repo", "emberdotlink/emberlink-dev"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::Mediated)
        );
    }

    #[test]
    fn git_factory_is_wired() {
        let cfg = ManifestConfig(manifest("git"));
        let input = argv(&["push", "https://github.com/acme/widgets.git", "main"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::Mediated)
        );
    }

    // Phase B cutover: factory is sole authority — ResolverRequired,
    // PayloadAnalysisRequired, and UnsupportedFailClosed are forwarded to
    // the runtime (fail-closed) instead of falling back to legacy.

    #[test]
    fn gh_factory_resolver_required_no_repo() {
        let cfg = ManifestConfig(manifest("gh"));
        let input = argv(&["pr", "create"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::ResolverRequired)
        );
    }

    #[test]
    fn gh_factory_auth_login_blocked() {
        let cfg = ManifestConfig(manifest("gh"));
        let input = argv(&["auth", "login"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn git_factory_named_remote_is_resolver_required() {
        let cfg = ManifestConfig(manifest("git"));
        let input = argv(&["push", "origin", "main"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::ResolverRequired)
        );
    }

    #[test]
    fn git_factory_mirror_is_blocked() {
        let cfg = ManifestConfig(manifest("git"));
        let input = argv(&["push", "--mirror"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn npm_factory_publish_is_resolver_required() {
        let cfg = ManifestConfig(manifest("npm"));
        let input = argv(&["publish"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::ResolverRequired)
        );
    }

    #[test]
    fn npm_factory_unpublish_is_blocked() {
        let cfg = ManifestConfig(manifest("npm"));
        let input = argv(&["unpublish", "foo@1.0.0"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn az_factory_login_is_blocked() {
        let cfg = ManifestConfig(manifest("az"));
        let input = argv(&["login"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn gcloud_factory_auth_is_blocked() {
        let cfg = ManifestConfig(manifest("gcloud"));
        let input = argv(&["auth", "login"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn flyctl_factory_auth_login_is_blocked() {
        let cfg = ManifestConfig(manifest("flyctl"));
        let input = argv(&["auth", "login"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn vercel_factory_login_is_blocked() {
        let cfg = ManifestConfig(manifest("vercel"));
        let input = argv(&["login"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn okta_factory_login_is_blocked() {
        let cfg = ManifestConfig(manifest("okta"));
        let input = argv(&["login"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn wrangler_factory_login_is_blocked() {
        let cfg = ManifestConfig(manifest("wrangler"));
        let input = argv(&["login"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn docker_factory_push_is_resolver_required() {
        let cfg = ManifestConfig(manifest("docker"));
        let input = argv(&["push", "myregistry.io/myimage:latest"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::ResolverRequired)
        );
    }

    #[test]
    fn scion_factory_list_is_credentialless() {
        let cfg = ManifestConfig(manifest("scion"));
        let input = argv(&["ember-scion", "list"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::Credentialless)
        );
    }

    #[test]
    fn scion_factory_start_is_resolver_required() {
        let cfg = ManifestConfig(manifest("scion"));
        let input = argv(&["ember-scion", "start", "worker-a", "--persona", "alice"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::ResolverRequired)
        );
    }

    #[test]
    fn scion_factory_max_depth_is_blocked() {
        let cfg = ManifestConfig(manifest("scion"));
        let input = argv(&["ember-scion", "start", "worker-a", "--max-depth", "3"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn kubectl_factory_is_wired() {
        let cfg = ManifestConfig(manifest("kubectl"));
        let input = argv(&["version", "--client"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::Credentialless)
        );
        assert!(!cfg.credentialless_env_scrub().is_empty());
    }

    #[test]
    fn kubectl_factory_kubeconfig_fails_closed() {
        let cfg = ManifestConfig(manifest("kubectl"));
        let input = argv(&["--kubeconfig", "prod.yaml", "get", "pods"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn terraform_factory_is_wired() {
        let cfg = ManifestConfig(manifest("terraform"));
        let input = argv(&["version"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::Credentialless)
        );
        assert!(!cfg.credentialless_env_scrub().is_empty());
        assert!(
            cfg.credentialless_env_set()
                .contains(&("TF_INPUT", "false")),
            "terraform credentialless path must set TF_INPUT=false"
        );
    }

    #[test]
    fn terraform_factory_state_push_fails_closed() {
        let cfg = ManifestConfig(manifest("terraform"));
        let input = argv(&["state", "push", "terraform.tfstate"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn tofu_factory_is_wired() {
        let cfg = ManifestConfig(manifest("tofu"));
        let input = argv(&["version"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::Credentialless)
        );
        assert!(!cfg.credentialless_env_scrub().is_empty());
        assert!(
            cfg.credentialless_env_set()
                .contains(&("TF_INPUT", "false")),
            "tofu credentialless path must set TF_INPUT=false"
        );
    }

    #[test]
    fn pulumi_factory_is_wired() {
        let cfg = ManifestConfig(manifest("pulumi"));
        let input = argv(&["version"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::Credentialless)
        );
        assert!(!cfg.credentialless_env_scrub().is_empty());
    }

    #[test]
    fn pulumi_factory_login_fails_closed_via_runtime_path() {
        let cfg = ManifestConfig(manifest("pulumi"));
        let input = argv(&["login", "s3://state-bucket"]);
        assert_eq!(
            cfg.factory_disposition(cfg.classify(&input).as_ref(), &input),
            Some(FactoryDisposition::UnsupportedFailClosed)
        );
    }

    #[test]
    fn every_vendor_has_argv_translator_field_set() {
        // Regression guard: if a new VendorManifest entry is added without
        // an argv_translator value, the compile fails. This test makes the
        // 15-vendor enumeration explicit so the "set on every entry"
        // invariant is testable from a single site.
        assert!(VENDORS.iter().all(|v| (v.argv_translator as usize) != 0));
        assert!(
            VENDORS.len() >= 15,
            "expected at least 15 vendor manifests; got {}",
            VENDORS.len()
        );
    }

    #[test]
    fn every_bundled_carrier_is_a_valid_v2_action_manifest() {
        // The carrier-load seam (resolve_action_ref /
        // resolve_action_manifest_identity) is fail-closed on the full ADR-196
        // v2 schema. Every bundled carrier must therefore parse + validate as a
        // complete v2 action manifest, not merely an identity-only stub. This
        // is P11's Definition of Success enforced as a regression guard.
        for vendor in VENDORS {
            let text = std::str::from_utf8(vendor.construct_toml)
                .unwrap_or_else(|e| panic!("{} carrier is not UTF-8: {e}", vendor.name));
            core_events::construct_toml::parse_action_manifest(text).unwrap_or_else(|e| {
                panic!(
                    "{} construct.toml failed v2 action-manifest validation: {e}",
                    vendor.name
                )
            });
        }
    }
    #[test]
    fn scion_factory_conformance_fixtures_pass() {
        use core_construct_runtime::factory::{
            ActionManifestV2Carrier, parse_factory_fixture_corpus, run_factory_fixtures,
        };
        let corpus_text = include_str!("../conformance/scion/factory-fixtures.toml");
        let corpus = parse_factory_fixture_corpus(corpus_text).expect("fixture TOML must parse");
        let carrier_text = std::str::from_utf8(manifest("scion").construct_toml).expect("UTF-8");
        let carrier = ActionManifestV2Carrier::parse(carrier_text).expect("carrier must parse");
        let report = run_factory_fixtures(&scion::ScionFactory, Some(&carrier), &corpus);
        assert!(
            report.is_clean(),
            "scion factory conformance failures: {:?}",
            report.failures
        );
    }
}

// construct_config_translate_argv_hook_landed
