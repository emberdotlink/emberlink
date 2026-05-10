//! ember-construct — consolidated crate for all 15 bundled L2 Construct binaries.
//!
//!
//! Per design: one crate produces 15 `[[bin]]` targets (one per wrapped tool).
//! Each binary embeds its own vendor identifier and `construct.toml` bytes so
//! binaries hash to 15 distinct `content_hash` values, preserving per-vendor
//! WoT trust delegation scoping per design §2 + design §1.

pub mod aws;
pub mod az;
pub mod docker;
pub mod flyctl;
pub mod gcloud;
pub mod gh;
pub mod git;
pub mod kubectl;
pub mod npm;
pub mod okta;
pub mod policy;
pub mod pulumi;
pub mod terraform;
pub mod tofu;
pub mod vercel;
pub mod wrangler;

pub use gh::GhClassifier;
pub use git::GitClassifier;
pub use kubectl::KubectlClassifier;
pub use policy::{credential_policy, CredentialInjection, CredentialPolicy};

use std::process::ExitCode;

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
    pub env_passthrough: &'static [&'static str],
    pub construct_toml: &'static [u8],
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
        env_passthrough: &[
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_DEFAULT_REGION",
        ],
        construct_toml: include_bytes!("../construct/aws.toml"),
    },
    VendorManifest {
        name: "az",
        binary_name: "az",
        binary_env_var: "EMBER_AZ_BINARY",
        classifier: az::classify_az_argv,
        env_passthrough: &["AZURE_ACCESS_TOKEN", "AZURE_AUTH_LOCATION"],
        construct_toml: include_bytes!("../construct/az.toml"),
    },
    VendorManifest {
        name: "gcloud",
        binary_name: "gcloud",
        binary_env_var: "EMBER_GCLOUD_BINARY",
        classifier: gcloud::classify_gcloud_argv,
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
        env_passthrough: &["VERCEL_TOKEN"],
        construct_toml: include_bytes!("../construct/vercel.toml"),
    },
    VendorManifest {
        name: "wrangler",
        binary_name: "wrangler",
        binary_env_var: "EMBER_WRANGLER_BINARY",
        classifier: wrangler::classify_wrangler_argv,
        env_passthrough: &["CLOUDFLARE_API_TOKEN"],
        construct_toml: include_bytes!("../construct/wrangler.toml"),
    },
    VendorManifest {
        name: "gh",
        binary_name: "gh",
        binary_env_var: "EMBER_GH_BINARY",
        classifier: gh::classify_gh_argv,
        env_passthrough: &["GH_TOKEN", "GITHUB_TOKEN", "GH_HOST"],
        construct_toml: include_bytes!("../construct/gh.toml"),
    },
    VendorManifest {
        name: "git",
        binary_name: "git",
        binary_env_var: "EMBER_GIT_BINARY",
        classifier: git::classify_git_argv,
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
        env_passthrough: &[],
        construct_toml: include_bytes!("../construct/terraform.toml"),
    },
    VendorManifest {
        name: "tofu",
        binary_name: "tofu",
        binary_env_var: "EMBER_TOFU_BINARY",
        classifier: tofu::classify_tofu_argv,
        env_passthrough: &[],
        construct_toml: include_bytes!("../construct/tofu.toml"),
    },
    VendorManifest {
        name: "flyctl",
        binary_name: "flyctl",
        binary_env_var: "EMBER_FLYCTL_BINARY",
        classifier: flyctl::classify_flyctl_argv,
        env_passthrough: &["FLY_API_TOKEN"],
        construct_toml: include_bytes!("../construct/flyctl.toml"),
    },
    VendorManifest {
        name: "npm",
        binary_name: "npm",
        binary_env_var: "EMBER_NPM_BINARY",
        classifier: npm::classify_npm_argv,
        env_passthrough: &["NPM_TOKEN", "NPM_CONFIG_REGISTRY", "npm_config_registry"],
        construct_toml: include_bytes!("../construct/npm.toml"),
    },
    VendorManifest {
        name: "okta",
        binary_name: "okta",
        binary_env_var: "EMBER_OKTA_BINARY",
        classifier: okta::classify_okta_argv,
        env_passthrough: &["OKTA_API_TOKEN"],
        construct_toml: include_bytes!("../construct/okta.toml"),
    },
];

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
            std::env::var("PATH")
                .unwrap_or_default()
                .split(':')
                .map(|dir| format!("{dir}/{binary_name}"))
                .find(|p| std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false))
                .unwrap_or_else(|| binary_name.to_string())
        })
    }

    fn env_passthrough(&self) -> &'static [&'static str] {
        self.0.env_passthrough
    }
}

// ---------------------------------------------------------------------------
// run — the [[bin]] entry point
// ---------------------------------------------------------------------------

/// Dispatch entry point called by each `[[bin]]` target's `main.rs`.
///
/// Panics on unknown `vendor` — build-time invariant since [[bin]] main.rs
/// files are checked-in code that passes a literal vendor name.
pub fn run(vendor: &str) -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter("info")
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
