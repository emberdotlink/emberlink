//! Argv classifier for `gh`. Action keys mirror the cohort-A construct.toml
//! (pr_create, pr_merge, repo_delete, auth_login, workflow_run, ...). Daemon
//! server-side re-classifies on broker.exec; this impl is shim-side only.

use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};
use core_construct_runtime::{ActionKey, ClassifyArgv};

#[derive(Debug, Default, Clone)]
pub struct GhClassifier;

impl ClassifyArgv for GhClassifier {
    fn classify(&self, argv: &[String]) -> Option<ActionKey> {
        classify_gh_argv(argv)
    }
}

/// Free-function entry point for the `VendorManifest` classifier field.
pub fn classify_gh_argv(argv: &[String]) -> Option<ActionKey> {
    if argv.is_empty() {
        return None;
    }
    let verb = argv[0].as_str();
    let subverb = argv.get(1).map(String::as_str);
    let key = match (verb, subverb) {
        ("pr", Some("create")) => "pr_create",
        ("pr", Some("merge")) => "pr_merge",
        ("pr", Some("close")) => "pr_close",
        ("pr", Some("comment")) => "pr_comment",
        ("pr", Some("list")) => "pr_list",
        ("pr", Some("view")) => "pr_view",
        ("pr", Some("edit")) => "pr_edit",
        ("repo", Some("create")) => "repo_create",
        ("repo", Some("delete")) => "repo_delete",
        ("repo", Some("clone")) => "repo_clone",
        ("repo", Some("view")) => "repo_view",
        ("auth", Some("login")) => "auth_login",
        ("auth", Some("status")) => "auth_status",
        ("workflow", Some("run")) => "workflow_run",
        // NB: `gh workflow list` is the GitHub-Actions `workflow` subcommand, NOT
        // the Emberlink authority-context "delegation" concept. The ADR 192/194
        // workflow→delegation rename must not touch wrapped-tool argv classifiers;
        // mis-renaming this to `delegation_list` produced a non-existent action
        // key that matched no construct.toml entry. (Sweep 3 finding S-GHRENAME.)
        ("workflow", Some("list")) => "workflow_list",
        ("issue", Some("create")) => "issue_create",
        ("issue", Some("close")) => "issue_close",
        ("issue", Some("list")) => "issue_list",
        ("release", Some("create")) => "release_create",
        _ => return None,
    };
    Some(ActionKey(format!("gh.{key}")))
}

// ---------------------------------------------------------------------------
// GhFactory — P24 construct-factory contract for the gh construct
// ---------------------------------------------------------------------------

/// Parsed gh.toml action manifest, initialised once at first access.
static GH_MANIFEST: std::sync::LazyLock<core_events::construct_toml::ParsedActionManifest> =
    std::sync::LazyLock::new(|| {
        core_events::construct_toml::parse_action_manifest(include_str!("../construct/gh.toml"))
            .expect("bundled gh.toml must be valid")
    });

/// Look up the `need` atoms for an action suffix (without the `gh.` prefix)
/// from the bundled manifest.  Returns `None` if the action is absent from
/// the manifest or has an empty `need` list.
fn manifest_need_for_action(action_key: &str) -> Option<Vec<String>> {
    let suffix = action_key.strip_prefix("gh.")?;
    GH_MANIFEST
        .manifest
        .actions
        .iter()
        .find(|a| a.key == suffix)
        .and_then(|a| {
            let need = &a.need;
            if need.is_empty() {
                None
            } else {
                Some(need.clone())
            }
        })
}

/// Returns `true` when `action_key` (full form, e.g. `"gh.pr_create"`) has an
/// entry in the bundled manifest (regardless of whether it carries a `need`).
fn action_in_manifest(action_key: &str) -> bool {
    let Some(suffix) = action_key.strip_prefix("gh.") else {
        return false;
    };
    GH_MANIFEST.manifest.actions.iter().any(|a| a.key == suffix)
}

/// Extract the `--repo <owner/repo>` or `-R <owner/repo>` flag value from argv.
///
/// Handles both the space-separated form (`--repo owner/repo`) and the
/// `=`-joined form (`--repo=owner/repo`).  Returns `None` when neither flag
/// is present or the value is missing.
pub fn extract_gh_repo_flag(argv: &[String]) -> Option<String> {
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];
        // --repo=value / -R=value
        for prefix in &["--repo=", "-R="] {
            if let Some(value) = tok.strip_prefix(prefix)
                && !value.is_empty()
            {
                return Some(value.to_string());
            }
        }
        // --repo value / -R value
        if (tok == "--repo" || tok == "-R")
            && let Some(value) = argv.get(i + 1)
            && !value.starts_with('-')
        {
            return Some(value.clone());
        }
        i += 1;
    }
    None
}

/// Extract the positional resource ID that follows a subverb.
///
/// For `gh pr view 123 …` the resource ID is `"123"`.  The function skips
/// tokens that look like flags (`-…` / `--…`) to be tolerant of flag
/// reordering.  Returns `None` when no non-flag token follows the subverb.
fn extract_positional_resource_id(argv: &[String]) -> Option<String> {
    // argv is already stripped of the verb + subverb by the classifier, but we
    // receive the full argv here.  The resource ID lives at index 2 or later.
    argv.get(2..)
        .unwrap_or_default()
        .iter()
        .find(|tok| !tok.starts_with('-'))
        .cloned()
}

/// P24 factory implementation for the `gh` construct.
#[derive(Debug, Default, Clone)]
pub struct GhFactory;

/// Provider-specific target extracted from a `gh` argv invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhFactoryTarget {
    pub provider: &'static str,
    /// GitHub hostname (default `"github.com"`).
    pub host: String,
    /// `owner/repo` as supplied via `--repo` / `-R`.
    pub repo: String,
    /// Positional resource ID, when present (PR number, issue number, …).
    pub resource_id: Option<String>,
}

/// Need atoms derived from the bundled manifest for one `gh` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhFactoryNeed(pub Vec<String>);

impl InvocationGrammar for GhFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_gh_argv(argv)
    }
}

impl TargetExtractor for GhFactory {
    type Target = GhFactoryTarget;

    fn target_for_argv(&self, _action_key: &ActionKey, argv: &[String]) -> Option<Self::Target> {
        let repo = extract_gh_repo_flag(argv)?;

        // Extract optional `--hostname` flag; default to "github.com".
        let host = argv
            .windows(2)
            .find_map(|w| {
                if w[0] == "--hostname" && !w[1].starts_with('-') {
                    Some(w[1].clone())
                } else {
                    None
                }
            })
            .or_else(|| {
                argv.iter().find_map(|tok| {
                    tok.strip_prefix("--hostname=")
                        .filter(|v| !v.is_empty())
                        .map(str::to_string)
                })
            })
            .unwrap_or_else(|| "github.com".to_string());

        let resource_id = extract_positional_resource_id(argv);

        Some(GhFactoryTarget {
            provider: "github",
            host,
            repo,
            resource_id,
        })
    }
}

impl NeedTemplate for GhFactory {
    type Need = GhFactoryNeed;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        _target: &Self::Target,
        _argv: &[String],
    ) -> Option<Self::Need> {
        manifest_need_for_action(&action_key.0).map(GhFactoryNeed)
    }
}

impl ConstructFactory for GhFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> FactoryDisposition {
        let Some(key) = action_key else {
            // Unclassified argv — no known action, treat as credentialless
            // passthrough (e.g. `gh secret set` is not in the classifier).
            return FactoryDisposition::Credentialless;
        };

        // auth login is a credential-bypass vector — always fail closed.
        if key.0 == "gh.auth_login" {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // auth_status and other read-only, non-credential operations where no
        // action manifest entry exists (or where the entry carries no `need`)
        // and the action does not require ambient credentials to be brokered.
        //
        // If the action is not in the manifest at all (e.g. `auth_status`,
        // `workflow_list`, `issue_list`, `repo_clone`, `repo_view`, `pr_comment`,
        // `issue_close`, `pr_comment`) — no bounded authority is declared, so
        // we cannot broker.  Treat that class as UnsupportedFailClosed.
        if !action_in_manifest(&key.0) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // Action is in the manifest.  If it has no `need`, authority is
        // unbounded — fail closed (e.g. `repo_delete`, `repo_create`,
        // `release_create`, `issue_create`, `pr_edit`).
        if manifest_need_for_action(&key.0).is_none() {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // Action is in the manifest and carries a `need`.  Whether we can
        // fully materialize depends on whether the target is locally resolvable.
        if extract_gh_repo_flag(argv).is_some() {
            FactoryDisposition::Mediated
        } else {
            FactoryDisposition::ResolverRequired
        }
    }

    /// Trusted resolver: derive `owner/repo` from the cwd's git origin URL
    /// and synthesize `--repo owner/repo` into argv. The runtime re-runs
    /// disposition on the synthesized argv (which flips ResolverRequired →
    /// Mediated) and the daemon's existing `target ⊆ grant.resource` clamp
    /// gates the derived target.
    ///
    /// Per operator 2026-06-11 lock: applies uniformly to reads AND writes
    /// (`feedback_grant_clamp_is_security_argv_is_ux`). The grant clamp is
    /// the security gate; requiring `--repo` on writes was rejected as
    /// performative ceremony.
    fn resolve_target_from_environment(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
        cwd: &std::path::Path,
    ) -> Option<Vec<String>> {
        // Only attempt for classified gh actions. The runtime only calls
        // us when disposition is ResolverRequired (which already filters
        // to in-manifest actions with `need`), but re-check defensively.
        let _key = action_key?;
        if extract_gh_repo_flag(argv).is_some() {
            return None;
        }
        let url = crate::env_derive::cwd_git_remote_origin_url(cwd)?;
        let owner_repo = crate::git::owner_repo_from_remote_url(&url)?;
        let mut synthesized = argv.to_vec();
        synthesized.push("--repo".to_string());
        synthesized.push(owner_repo);
        Some(synthesized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::credential_policy;
    use core_construct_runtime::ClassifyArgv;
    use core_events::construct_toml::resolve_action_manifest_identity;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classifies_known_verb() {
        let c = GhClassifier;
        assert_eq!(
            c.classify(&argv(&["pr", "create"])),
            Some(ActionKey("gh.pr_create".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["pr", "merge", "--squash"])),
            Some(ActionKey("gh.pr_merge".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["repo", "delete", "myrepo"])),
            Some(ActionKey("gh.repo_delete".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["auth", "login"])),
            Some(ActionKey("gh.auth_login".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["workflow", "run", "ci.yml"])),
            Some(ActionKey("gh.workflow_run".to_string()))
        );
        // Regression: `gh workflow list` must classify to the GitHub-Actions
        // `gh.workflow_list` key, NOT the mis-renamed `gh.delegation_list`.
        assert_eq!(
            c.classify(&argv(&["workflow", "list"])),
            Some(ActionKey("gh.workflow_list".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["issue", "list"])),
            Some(ActionKey("gh.issue_list".to_string()))
        );
    }

    #[test]
    fn classifies_pr_edit() {
        let c = GhClassifier;
        assert_eq!(
            c.classify(&argv(&["pr", "edit", "42", "--title", "New title"])),
            Some(ActionKey("gh.pr_edit".to_string()))
        );
    }

    #[test]
    fn classifies_release_create() {
        let c = GhClassifier;
        assert_eq!(
            c.classify(&argv(&["release", "create", "v1.2.3", "--title", "v1.2.3"])),
            Some(ActionKey("gh.release_create".to_string()))
        );
    }

    #[test]
    fn unknown_verb_returns_none() {
        let c = GhClassifier;
        assert_eq!(c.classify(&argv(&["secret", "set"])), None);
        assert_eq!(c.classify(&argv(&["pr", "unknown"])), None);
        assert_eq!(c.classify(&argv(&["unknown"])), None);
    }

    #[test]
    fn empty_argv_returns_none() {
        let c = GhClassifier;
        assert_eq!(c.classify(&[]), None);
    }

    #[test]
    fn bundled_manifest_identity_fields_align_with_classification_and_policy() {
        let action_key = classify_gh_argv(&argv(&["pr", "create"])).expect("classified action");
        let action_suffix = action_key
            .0
            .strip_prefix("gh.")
            .expect("gh classifier prefixes action keys with gh.");
        let identity =
            resolve_action_manifest_identity(include_str!("../construct/gh.toml"), action_suffix)
                .expect("bundled gh manifest identity");

        assert_eq!(
            identity.plugin_address,
            "registry.ember.systems/ember-systems/ember-gh"
        );
        assert_eq!(identity.action_key, "pr_create");
        assert_eq!(identity.action_version, "v1");
        assert_eq!(
            identity.semantic_labels,
            vec![
                "github.pull_request.write".to_string(),
                "scm.pull_request.write".to_string()
            ]
        );
        assert!(
            credential_policy(&action_key.0).is_some(),
            "credential policy must still resolve for classified action {}",
            action_key.0
        );
    }

    // -----------------------------------------------------------------------
    // GhFactory tests
    // -----------------------------------------------------------------------

    #[test]
    fn gh_factory_pr_view_with_repo_is_mediated() {
        let f = GhFactory;
        let a = argv(&["pr", "view", "123", "--repo", "acme/backend"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::Mediated
        );
    }

    #[test]
    fn gh_factory_pr_create_no_repo_is_resolver_required() {
        let f = GhFactory;
        let a = argv(&["pr", "create", "--title", "my PR"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn gh_factory_auth_login_is_unsupported() {
        let f = GhFactory;
        let a = argv(&["auth", "login"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn gh_factory_auth_status_is_unsupported_fail_closed() {
        // auth_status is classified but has no manifest entry — no bounded
        // authority → fail closed.
        let f = GhFactory;
        let a = argv(&["auth", "status"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn gh_factory_unknown_verb_is_credentialless() {
        // Unclassified argv → None action_key → Credentialless.
        let f = GhFactory;
        let a = argv(&["secret", "set", "MY_SECRET"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn gh_factory_repo_delete_no_need_is_unsupported() {
        // repo_delete is in the manifest but has no `need` field → fail closed.
        let f = GhFactory;
        let a = argv(&["repo", "delete", "acme/old-repo"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn gh_factory_target_extraction_with_repo_flag() {
        let f = GhFactory;
        let a = argv(&["pr", "view", "42", "--repo", "acme/backend"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.provider, "github");
        assert_eq!(target.host, "github.com");
        assert_eq!(target.repo, "acme/backend");
        assert_eq!(target.resource_id, Some("42".to_string()));
    }

    #[test]
    fn gh_factory_target_extraction_with_r_flag() {
        let f = GhFactory;
        let a = argv(&["pr", "close", "7", "-R", "acme/frontend"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.repo, "acme/frontend");
        assert_eq!(target.resource_id, Some("7".to_string()));
    }

    #[test]
    fn gh_factory_need_resolution() {
        let f = GhFactory;
        let a = argv(&["pr", "view", "1", "--repo", "acme/backend"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target");
        let need = f.need_for_target(&key, &target, &a).expect("need resolved");
        assert_eq!(
            need.0,
            vec!["github:metadata:read", "github:pull_request:read"]
        );
    }

    #[test]
    fn gh_factory_need_resolution_pr_create() {
        let f = GhFactory;
        let a = argv(&["pr", "create", "--repo", "acme/backend", "--title", "x"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target");
        let need = f.need_for_target(&key, &target, &a).expect("need resolved");
        assert_eq!(
            need.0,
            vec![
                "github:metadata:read",
                "github:contents:write",
                "github:pull_request:create"
            ]
        );
    }

    #[test]
    fn gh_factory_target_extraction_no_repo_returns_none() {
        let f = GhFactory;
        let a = argv(&["pr", "list"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert!(f.target_for_argv(&key, &a).is_none());
    }

    #[test]
    fn gh_factory_target_extraction_custom_hostname() {
        let f = GhFactory;
        let a = argv(&[
            "pr",
            "view",
            "5",
            "--repo",
            "acme/internal",
            "--hostname",
            "github.acme.com",
        ]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target");
        assert_eq!(target.host, "github.acme.com");
    }

    #[test]
    fn gh_factory_contract_runs_conformance_corpus() {
        let corpus = core_construct_runtime::factory::parse_factory_fixture_corpus(include_str!(
            "../conformance/gh/factory-fixtures.toml"
        ))
        .expect("fixture corpus parses");
        let validation_errors =
            core_construct_runtime::factory::validate_factory_fixture_corpus(&corpus);
        assert!(validation_errors.is_empty(), "{validation_errors:#?}");

        let carrier = core_construct_runtime::factory::ActionManifestV2Carrier::parse(
            include_str!("../construct/gh.toml"),
        )
        .expect("gh manifest carrier parses");
        let report = core_construct_runtime::factory::run_factory_fixtures(
            &GhFactory,
            Some(&carrier),
            &corpus,
        );
        assert!(report.is_clean(), "{:#?}", report.failures);
    }

    // -----------------------------------------------------------------------
    // V030-FACTORY-RESOLVER-COHORT-A: GhFactory::resolve_target_from_environment
    //
    // AC-1 happy path: real git repo with github origin → synthesizes
    //                  `--repo owner/repo` into argv.
    // AC-2 refusal:    cwd is not a git repo → None.
    // AC-3 adversarial: cwd's origin claims `elevated/repo` → resolver
    //                  returns synthesized argv with `elevated/repo`
    //                  *verbatim*; daemon clamp is the security gate.
    // AC-4 uniform:    same resolver path for read verbs (pr_list) and
    //                  write verbs (pr_create) — no read/write asymmetry
    //                  per operator lock 2026-06-11.
    // AC-5 / AC-6:     covered at env_derive::tests level (hash mismatch,
    //                  subprocess timeout).
    // -----------------------------------------------------------------------

    use std::process::Command;
    use std::sync::Mutex;

    /// Serialise tests that change the cwd or rely on system git setup.
    static GH_RESOLVER_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn make_git_repo_with_origin(remote_url: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cwd = tmp.path();
        let init = Command::new(crate::env_derive::SYSTEM_GIT_BINARY)
            .args(["init", "--quiet"])
            .current_dir(cwd)
            .output()
            .expect("git init");
        assert!(init.status.success(), "git init failed: {init:?}");
        let remote = Command::new(crate::env_derive::SYSTEM_GIT_BINARY)
            .args(["remote", "add", "origin", remote_url])
            .current_dir(cwd)
            .output()
            .expect("git remote add");
        assert!(remote.status.success(), "git remote add failed: {remote:?}");
        tmp
    }

    fn skip_if_no_system_git() -> bool {
        if !std::path::Path::new(crate::env_derive::SYSTEM_GIT_BINARY).exists() {
            eprintln!(
                "skipping: {} not present on this host",
                crate::env_derive::SYSTEM_GIT_BINARY
            );
            return true;
        }
        false
    }

    /// AC-1: from inside a git repo with a github origin, the resolver
    /// returns a synthesized argv carrying `--repo owner/repo`.
    #[test]
    fn gh_factory_resolver_synthesizes_repo_flag_from_cwd_git_origin() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GH_RESOLVER_TEST_LOCK.lock().unwrap();
        let repo = make_git_repo_with_origin("https://github.com/acme/widgets.git");

        let f = GhFactory;
        let argv = argv(&["pr", "list", "--state", "open"]);
        let key = f.action_key_for_argv(&argv).expect("classified");
        let synthesized = f
            .resolve_target_from_environment(Some(&key), &argv, repo.path())
            .expect("resolver derived target");

        assert_eq!(
            synthesized,
            vec![
                "pr".to_string(),
                "list".to_string(),
                "--state".to_string(),
                "open".to_string(),
                "--repo".to_string(),
                "acme/widgets".to_string()
            ]
        );

        // And the re-disposition on the synthesized argv flips to Mediated
        // (which is the proof that the runtime would unblock the call).
        assert_eq!(
            f.disposition_for_argv(Some(&key), &synthesized),
            FactoryDisposition::Mediated
        );
    }

    /// AC-2: cwd is not a git repo → resolver returns None and the
    /// existing ResolverRequired refusal stands.
    #[test]
    fn gh_factory_resolver_outside_git_repo_returns_none() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GH_RESOLVER_TEST_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().expect("tempdir");

        let f = GhFactory;
        let argv = argv(&["pr", "list"]);
        let key = f.action_key_for_argv(&argv).expect("classified");
        let synthesized = f.resolve_target_from_environment(Some(&key), &argv, tmp.path());
        assert_eq!(
            synthesized, None,
            "resolver MUST return None outside any git repo"
        );
    }

    /// AC-3 (resolver side): the resolver returns whatever the cwd's
    /// origin says, verbatim — no internal trust. The daemon's
    /// `target ⊆ grant.resource` clamp is the security gate that would
    /// refuse a non-grant target downstream. This test pins the contract
    /// "resolver supplies a target candidate, daemon decides authority."
    #[test]
    fn gh_factory_resolver_passes_origin_through_verbatim_for_daemon_clamp() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GH_RESOLVER_TEST_LOCK.lock().unwrap();
        let repo = make_git_repo_with_origin("https://github.com/ember-systems/grant-elevated.git");

        let f = GhFactory;
        let argv = argv(&["pr", "list"]);
        let key = f.action_key_for_argv(&argv).expect("classified");
        let synthesized = f
            .resolve_target_from_environment(Some(&key), &argv, repo.path())
            .expect("resolver derived target");

        // The resolver MUST pass the malicious-looking value through
        // unaltered; clamping is the daemon's job.
        assert_eq!(
            synthesized,
            vec![
                "pr".to_string(),
                "list".to_string(),
                "--repo".to_string(),
                "ember-systems/grant-elevated".to_string()
            ],
            "resolver MUST NOT pre-filter; daemon clamp is the security gate"
        );
    }

    /// AC-4: uniform reads + writes. The resolver synthesizes `--repo`
    /// regardless of read/write classification — per operator lock
    /// `feedback_grant_clamp_is_security_argv_is_ux` (2026-06-11).
    #[test]
    fn gh_factory_resolver_synthesizes_uniformly_for_reads_and_writes() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GH_RESOLVER_TEST_LOCK.lock().unwrap();
        let repo = make_git_repo_with_origin("https://github.com/acme/widgets.git");

        let f = GhFactory;

        // Read verb.
        let read_argv = argv(&["pr", "list"]);
        let read_key = f.action_key_for_argv(&read_argv).expect("classified");
        let read_synth = f
            .resolve_target_from_environment(Some(&read_key), &read_argv, repo.path())
            .expect("read resolver derived target");
        assert!(read_synth.contains(&"--repo".to_string()));
        assert!(read_synth.contains(&"acme/widgets".to_string()));

        // Write verb. `gh.pr_create` has a `need` in the manifest, so
        // disposition is ResolverRequired without `--repo` (matches read
        // path) — the resolver must apply identically.
        let write_argv = argv(&["pr", "create", "--title", "Test"]);
        let write_key = f.action_key_for_argv(&write_argv).expect("classified");
        let write_synth = f
            .resolve_target_from_environment(Some(&write_key), &write_argv, repo.path())
            .expect("write resolver derived target");
        assert!(
            write_synth.contains(&"--repo".to_string()),
            "write verb MUST get the same --repo synthesis as the read verb (no asymmetry)"
        );
        assert!(write_synth.contains(&"acme/widgets".to_string()));
    }

    /// Defensive: resolver returns None when argv already carries `--repo`.
    #[test]
    fn gh_factory_resolver_no_op_when_repo_flag_already_present() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GH_RESOLVER_TEST_LOCK.lock().unwrap();
        let repo = make_git_repo_with_origin("https://github.com/acme/widgets.git");

        let f = GhFactory;
        let argv = argv(&["pr", "list", "--repo", "explicit/target"]);
        let key = f.action_key_for_argv(&argv).expect("classified");
        let synthesized = f.resolve_target_from_environment(Some(&key), &argv, repo.path());
        assert_eq!(
            synthesized, None,
            "resolver MUST be a no-op when --repo is already in argv"
        );
    }

    /// Non-github origin (e.g. GitLab) → resolver returns None.
    /// The GitHub installation-token projector cannot mint for a
    /// non-github target, so synthesising a GitLab URL would create
    /// confusing daemon-side failures.
    #[test]
    fn gh_factory_resolver_returns_none_for_non_github_origin() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GH_RESOLVER_TEST_LOCK.lock().unwrap();
        let repo = make_git_repo_with_origin("https://gitlab.com/acme/widgets.git");

        let f = GhFactory;
        let argv = argv(&["pr", "list"]);
        let key = f.action_key_for_argv(&argv).expect("classified");
        let synthesized = f.resolve_target_from_environment(Some(&key), &argv, repo.path());
        assert_eq!(
            synthesized, None,
            "non-github origin must NOT synthesize a --repo flag"
        );
    }
}
