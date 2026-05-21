//! ember-construct — consolidated crate for all 15 bundled L2 Construct binaries.
//!
//! Per design: one crate produces 15 `[[bin]]` targets (one per wrapped tool).
//! Each binary embeds its own vendor identifier and `construct.toml` bytes so
//! binaries hash to 15 distinct `content_hash` values, preserving per-vendor
//! WoT trust delegation scoping per design §2 + design §1.

pub mod aws;
pub mod az;
// implementation-note-91 — Compose V2 manifest
// types + translator substrate. The public checkpoint
// `fn compose_manifest_to_docker_spec` lives in `docker.rs`; this
// module owns `ComposeManifest`, `ComposeService`,
// `DockerContainerSpec`, and `ComposeTranslationError`.
pub mod compose;
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
pub mod scion;
pub mod terraform;
pub mod tofu;
pub mod vercel;
pub mod workflow_template_schema;
pub mod wrangler;

pub use gh::GhClassifier;
pub use git::GitClassifier;
pub use kubectl::KubectlClassifier;
pub use policy::{CredentialInjection, CredentialPolicy, credential_policy};
pub use workflow_template_schema::{Capability, WorkflowTemplate, WorkflowTemplateError};

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
    /// Emberlink-shaped argv → wrapped-tool-native argv. Defaults to identity
    /// via `identity_argv_translator` for vendors with no emberlink-specific
    /// flags. Scion overrides to `scion::translate_scion_argv` per design §4.
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
        // Scion overrides the default identity translator per design §4
        // (implementation-note-100): emberlink-shaped argv
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

    fn translate_argv(&self, argv: &[String]) -> Vec<String> {
        (self.0.argv_translator)(argv)
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
// translate_argv hook tests (implementation-note-29)
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
}

// construct_config_translate_argv_hook_landed
