//! Per-action credential policy for cohort-A Constructs.
//!
//! Single source of truth for which action keys (e.g. `gh.pr_create`,
//! `git.push`) require the daemon's broker to mint a scoped credential
//! at exec time, and how the credential is presented to the child
//! process (env-var binding, git URL rewrite).
//!
//! This module is consumed by `ember-daemon::broker::handler::handle_broker_exec`
//! (T-CONSTRUCT-EXEC-CRED-INJECT) — the daemon classifies argv via
//! per-tool `classify_argv` modules and then queries
//! [`credential_policy`] to decide whether (and how) to mint + inject.
//!
//! The policy lives here, not in each `construct.toml`, because the
//! daemon is the trust boundary — the construct.toml shipped with a
//! shim binary describes the SHIM's view of the action; the policy
//! that determines credential issuance must be daemon-defined so a
//! tampered shim cannot escalate its own credential needs. The shim's
//! pinned binary (verified by the daemon's binary-pin check at exec
//! time) carries argv classification only.
//!
//! Adding a new action: extend the `match` in [`credential_policy`].
//! Cohort A is closed by ADR 124 §3 so the list is small and stable.

use core_broker::BrokerProvider;
use core_event_types::{ActionRef, ActionRefPattern};

/// How the daemon presents a minted credential to the spawned child
/// process. Variants reflect how upstream tools consume credentials:
/// `gh` reads `GH_TOKEN` directly, `git` over HTTPS uses a per-host URL
/// rewrite to inject the token into the remote URL, and AWS tooling
/// reads the standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
/// `AWS_SESSION_TOKEN` triple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialInjection {
    /// Bind plaintext to a single environment variable. Used by `gh`,
    /// which honours `GH_TOKEN` for all API operations.
    ///
    /// Example: `Env("GH_TOKEN")` for `gh.pr_create`.
    Env(&'static str),

    /// Set `GIT_CONFIG_COUNT=N` plus `GIT_CONFIG_KEY_<i>` /
    /// `GIT_CONFIG_VALUE_<i>` triples that rewrite each `https://<host>/`
    /// remote URL to `https://x-access-token:<token>@<host>/` for the
    /// subprocess lifetime only — same shape today's
    /// `crates/internal-automation/src/ship.rs::bot_env` builds (lines 629-647).
    /// No `.git/config` mutation; the override is per-invocation.
    ///
    /// `hosts` lists git hosts the rewrite applies to. Example:
    /// `GitHttpRewrite { hosts: ["github.com"] }` for `git.push`.
    GitHttpRewrite { hosts: &'static [&'static str] },

    /// Split a JSON-encoded AWS credential bundle (issued by the AWS
    /// STS broker as `{access_key_id, secret_access_key, session_token,
    /// expiration}`) into the standard AWS env-var triple:
    /// `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
    /// `AWS_SESSION_TOKEN`. Consumed by `aws-cli`, `aws-sdk-*`,
    /// `terraform`, etc.
    ///
    /// The plaintext passed to `apply_credential_to_env` is the JSON
    /// blob the broker wrote into `BrokeredCredential::token`; the
    /// daemon parses it once at exec time and emits the three env
    /// vars. No env var is named here because all three are AWS-
    /// standard.
    AwsCredentials,

    /// Bind a GCP impersonated OAuth access token (issued by
    /// `GcpBroker` via service-account impersonation through the IAM
    /// Credentials API) to `CLOUDSDK_AUTH_ACCESS_TOKEN` — the env var
    /// honoured by `gcloud`, the Google Cloud SDK libraries, and
    /// `terraform`'s `google` provider for short-lived bearer-token
    /// auth. Single env var rather than a JSON bundle: GCP impersonation
    /// returns one OAuth token (not a key triple like AWS STS), and
    /// downstream tooling uniformly accepts that token via this var.
    GcpAccessToken,

    /// Bind an Azure AD OAuth bearer token (issued by `AzureCliBroker`
    /// via the service-principal client-credentials grant) to
    /// `AZURE_ACCESS_TOKEN`. Single env var rather than a JSON bundle:
    /// Azure AD client-credentials returns one OAuth bearer token, and
    /// `az` CLI / Azure SDK consumers honour `AZURE_ACCESS_TOKEN`
    /// directly for short-lived bearer auth.
    AzureAccessToken,

    /// Bind a Fly.io scoped API token (issued by `FlyBroker` via the
    /// GraphQL `createApiToken` mutation) to `FLY_API_TOKEN` — the env
    /// var honoured by the `fly` CLI, `flyctl`, and Fly's Machines API
    /// clients for bearer auth. Single env var rather than a JSON
    /// bundle: Fly's `createApiToken` returns one scoped token.
    FlyApiToken,

    /// Split a JSON-encoded HashiCorp Vault credential bundle (issued
    /// by `HashiVaultBroker` via `auth/token/create` as
    /// `{token, address}`) into the two env vars Vault clients need:
    /// `VAULT_TOKEN` (the minted child token) and `VAULT_ADDR` (the
    /// Vault server URL). The child token alone is useless without the
    /// address, so the broker bundles them and the daemon-side handler
    /// emits both env vars from one materialization.
    VaultToken,

    /// Bind an Okta OAuth bearer token (issued by `OktaBroker` via the
    /// service-app `private_key_jwt` client-credentials grant) to
    /// `OKTA_API_TOKEN` — the env var honoured by the official Okta
    /// SDKs (`@okta/okta-sdk-nodejs`, `okta-sdk-python`, terraform's
    /// `okta` provider) and `okta-aws-cli`. Single env var rather than
    /// a JSON bundle: Okta's `client_credentials` grant returns one
    /// short-lived bearer token (cap 3600s).
    OktaApiToken,

    /// Bind a Vercel scoped API token (issued by `VercelBroker` via
    /// the `POST /v3/user/tokens` endpoint) to `VERCEL_TOKEN` — the
    /// env var honoured by the `vercel` CLI for non-interactive auth.
    /// Single env var rather than a JSON bundle: Vercel's
    /// create-token endpoint returns one scoped token.
    VercelToken,
}

/// Daemon-side credential **delivery** policy for a classified action.
///
/// `provider` selects which broker mints the credential; `injection` describes
/// how the minted plaintext lands in the child env. Both are delivery facts, not
/// authority — a tampered shim cannot choose its own broker or delivery channel.
///
/// The action's least-privilege **need** is NOT here: it is declared in the
/// bundled manifest (`need` field, resolved by [`manifest_action_need`]) and the
/// audited projector derives native scope from it (ADR 204 Amendment 6 /
/// I6 — only the projector speaks native). This struct formerly carried a
/// hardcoded `capabilities` (the native need); that table was re-homed to the
/// manifest + projector (checkpoint `action_need_is_manifest_sourced_not_hardcoded`).
/// AWS's need is a dynamic per-argv `AwsPermissionSpec` parsed at mint, not a
/// static string, so it too lives off this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPolicy {
    pub provider: BrokerProvider,
    pub injection: CredentialInjection,
}

/// Look up the credential policy for a daemon-classified action key.
///
/// Returns `None` for actions that don't require a minted credential
/// (read-only verbs, kubectl actions, etc.). Returns `Some(policy)`
/// for verbs that authenticate against an upstream provider.
///
/// The cohort-A list is closed by ADR 124 §3; new entries land
/// alongside their cohort-A construct.toml addition in the same PR.
pub fn credential_policy(action_key: &str) -> Option<CredentialPolicy> {
    match action_key {
        // ───── gh — GitHub App installation token, delivered via GH_TOKEN ─────
        // The per-verb least-privilege need now lives in the bundled gh manifest
        // (`manifest_action_need`); this arm carries only the broker + delivery
        // channel. The read/write split that used to live here (load-bearing for
        // BKR-4c: a read-only template must not lower to `contents:write`) is now
        // the manifest's `need` field (pr_view/pr_list → metadata:read +
        // pull_request:read).
        "gh.pr_view" | "gh.pr_list" | "gh.pr_create" | "gh.pr_close" | "gh.workflow_run"
        | "gh.pr_merge" => Some(CredentialPolicy {
            provider: BrokerProvider::Github,
            injection: CredentialInjection::Env("GH_TOKEN"),
        }),

        // ───── git — GitHub App installation token, delivered via URL rewrite ─────
        // push mutates remote refs (manifest need contents:write); fetch/clone/
        // pull read the remote (contents:read) — the need lives in the git
        // manifest, the delivery channel here.
        "git.push" | "git.fetch" | "git.clone" | "git.pull" => Some(CredentialPolicy {
            provider: BrokerProvider::Github,
            injection: CredentialInjection::GitHttpRewrite {
                hosts: &["github.com"],
            },
        }),

        // ───── aws — STS AssumeRole credentials, delivered via AWS env vars ─────
        //
        // The concrete PermissionSpec is parsed from argv in `aws.rs` at mint
        // time, then checked `need <= grant` before the AWS STS projector
        // synthesizes native inline policy JSON. AWS's need is a dynamic per-argv
        // `AwsPermissionSpec`, never a static manifest string (ADR 204 amend 1),
        // so its manifest `need` is empty.
        "aws.s3.cp"
        | "aws.s3.sync"
        | "aws.s3.mv"
        | "aws.s3.rm"
        | "aws.s3api.put-object"
        | "aws.s3api.delete-object"
        | "aws.s3api.put-bucket-policy"
        | "aws.lambda.invoke"
        | "aws.lambda.update-function-code"
        | "aws.lambda.delete-function"
        | "aws.kms.encrypt"
        | "aws.kms.decrypt"
        | "aws.kms.schedule-key-deletion"
        | "aws.cloudformation.delete-stack"
        | "aws.cloudformation.update-stack"
        | "aws.secretsmanager.update-secret"
        | "aws.secretsmanager.delete-secret"
        | "aws.secretsmanager.put-secret-value" => Some(CredentialPolicy {
            provider: BrokerProvider::AwsSts,
            injection: CredentialInjection::AwsCredentials,
        }),

        // Everything else: no credential mint. Includes:
        //   - gh.repo_delete (deny-default in construct.toml; never auto-mint)
        //   - gh.auth_login (explicitly excluded — credential mint goes
        //     through the broker, not gh's local keychain)
        //   - git.commit, git.status, git.log, git.diff (local-only)
        //   - kubectl.* (separate provider; not in T1+T2 scope)
        _ => None,
    }
}

/// The bundled cohort-A construct manifest text for a tool slug, or `None` when
/// the tool carries no static credential need. These manifests are
/// `include_str!`-compiled into the daemon — the **same trust base** as the
/// former hardcoded `github_action_need` map (ADR 204 Amendment 6) — so
/// resolving need from them adds no attestation surface.
///
/// Only `gh` and `git` declare a static `provider:object:verb` need: they are
/// the cohort-A providers whose least-privilege need is a static per-action
/// string. AWS computes a dynamic per-argv `AwsPermissionSpec` at mint (ADR 204
/// amendment 1), not a static manifest need; the remaining tools mint no github
/// credential. A future static-need provider is registered here alongside its
/// bundled manifest.
fn bundled_manifest_toml(tool: &str) -> Option<&'static str> {
    Some(match tool {
        "gh" => include_str!("../construct/gh.toml"),
        "git" => include_str!("../construct/git.toml"),
        _ => return None,
    })
}

/// Resolve a daemon-classified action's least-privilege authority **need** from
/// the bundled cohort-A manifest (ADR 204 Amendment 6; checkpoint
/// `action_need_is_manifest_sourced_not_hardcoded`). The manifest-sourced
/// replacement for the former hardcoded `github_action_need` map.
///
/// `action_key` is the classifiers' dotted `<tool>.<verb>` key (`gh.pr_create`,
/// `git.push`). The need is read from the **bundled** manifest keyed by the
/// daemon-classified tool+action — never from shim-supplied carrier bytes, which
/// stay untrusted (ADR 205 §9). Returns `[]` for actions that mint no provider
/// credential (local/read verbs, kubectl, AWS — whose need is a dynamic
/// `AwsPermissionSpec` —, unknown actions, or a manifest parse failure), so an
/// empty need is the fail-safe (an under-grant, never an over-grant).
pub fn manifest_action_need(action_key: &str) -> Vec<String> {
    let Some(tool) = action_key.split('.').next().filter(|t| !t.is_empty()) else {
        return Vec::new();
    };
    let Some(text) = bundled_manifest_toml(tool) else {
        return Vec::new();
    };
    core_events::construct_toml::resolve_action_need(text, action_key).unwrap_or_default()
}

/// Canonical cohort-A construct-tool registry prefix. The bundled wrapper tools
/// publish under `registry.ember.systems/ember-systems/ember-<tool>` — the same
/// address the bundled delegation templates (`delegation_template_schema`),
/// `classify_argv_daemon_side`, and the `trust/standing_grant.rs` callers use.
/// The dotted action keys ([`manifest_action_need`]: `gh.pr_create`,
/// `git.push`) are `<tool>.<verb>`; lowering a template's action-ref scope
/// patterns back into those keys requires reconstructing the full plugin
/// address from the tool slug.
const CONSTRUCT_REGISTRY_PREFIX: &str = "registry.ember.systems/ember-systems";

/// The closed catalog of cohort-A action keys that carry a github capability
/// **need** — i.e. the exact set for which [`manifest_action_need`] returns a
/// non-empty `Vec`. BKR-4c lowers a delegation template's action-ref scope
/// patterns into the union of these actions' needs by enumerating this catalog
/// and testing each entry against the template's scopes/excludes.
///
/// Drift guard (`github_action_catalog_matches_need` +
/// `catalog_covers_every_credentialed_bundled_action` tests): every entry here
/// MUST resolve to a non-empty manifest need, and every credentialed bundled
/// gh/git manifest action MUST appear here. A need-bearing manifest action
/// missing from the catalog would silently drop it from template lowering (an
/// under-grant — fail-safe, but still wrong), so the tests fail closed on
/// either-direction drift.
pub fn github_action_catalog() -> &'static [&'static str] {
    &[
        "gh.pr_create",
        "gh.pr_close",
        "gh.pr_view",
        "gh.pr_list",
        "gh.workflow_run",
        "gh.pr_merge",
        "git.push",
        "git.fetch",
        "git.clone",
        "git.pull",
    ]
}

/// Reconstruct the canonical [`ActionRef`] for a dotted catalog key
/// (`gh.pr_create` → `registry.ember.systems/ember-systems/ember-gh` /
/// `pr_create` / `v1`). The catalog is closed and well-formed; a key without a
/// `.` would be a programmer error, so it falls back to an empty tool slug,
/// which simply never matches a real template pattern (fail-closed).
fn catalog_action_ref(dotted_key: &str) -> ActionRef {
    let (tool, verb) = dotted_key.split_once('.').unwrap_or(("", dotted_key));
    ActionRef::new(
        format!("{CONSTRUCT_REGISTRY_PREFIX}/ember-{tool}"),
        verb,
        "v1",
    )
}

/// Lower a delegation template's action-ref scope patterns into the union of
/// canonical github capability needs (`github:<object>:<verb>`) that its
/// in-scope, non-excluded actions require — the BKR-4c session-open standing-
/// grant lowering (ADR 205 §6).
///
/// The returned set becomes the runtime grant's enumerated github authority
/// Statements, replacing the broad `github:*` ceiling the runtime lane mirrors
/// today (memory `create_persona_seals_under_kek_s` / the dev0 github ceiling).
/// An out-of-scope github action's manifest need is then NOT a subset of
/// the standing grant, so use-time resolution falls through to JIT instead of
/// silently pre-approving it. `excludes` override `scopes` (an excluded action
/// contributes no need), exactly matching `DelegationTemplate::allows`.
///
/// Enumeration semantics: each catalog action is built at version `v1` (the
/// version every bundled template scopes at); a template that scopes a verb at
/// a different explicit version would not lower it. `*` in a pattern's version
/// position still matches via [`ActionRefPattern::matches`].
///
/// Determinism: the union is collected through a `BTreeSet`, so the Statement
/// order is stable across runs — load-bearing for the signed grant chain's
/// reproducibility.
pub fn template_github_needs(
    scopes: &[ActionRefPattern],
    excludes: &[ActionRefPattern],
) -> Vec<String> {
    let mut needs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for dotted in github_action_catalog() {
        let action_ref = catalog_action_ref(dotted);
        let in_scope = scopes.iter().any(|p| p.matches(&action_ref));
        let excluded = excludes.iter().any(|p| p.matches(&action_ref));
        if in_scope && !excluded {
            needs.extend(manifest_action_need(dotted));
        }
    }
    needs.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gh_pr_create_returns_github_policy_with_gh_token_env() {
        // credential_policy carries only broker + delivery now; the per-verb
        // least-privilege need lives in the manifest (asserted in
        // manifest_action_need_resolves_bundled_gh_and_git).
        let policy = credential_policy("gh.pr_create").expect("policy must be Some");
        assert_eq!(policy.provider, BrokerProvider::Github);
        assert_eq!(policy.injection, CredentialInjection::Env("GH_TOKEN"));
    }

    #[test]
    fn gh_pr_merge_has_distinct_policy_entry() {
        // pr_merge mints the same broker + delivery channel as pr_create; their
        // distinct needs are declared in the manifest, not here.
        let pr_merge = credential_policy("gh.pr_merge").expect("pr_merge must have policy");
        let pr_create = credential_policy("gh.pr_create").expect("pr_create must have policy");
        assert_eq!(pr_merge.provider, pr_create.provider);
        assert_eq!(pr_merge.injection, pr_create.injection);
    }

    #[test]
    fn git_push_returns_github_policy_with_url_rewrite() {
        let policy = credential_policy("git.push").expect("policy must be Some");
        assert_eq!(policy.provider, BrokerProvider::Github);
        match policy.injection {
            CredentialInjection::GitHttpRewrite { hosts } => {
                assert_eq!(hosts, &["github.com"]);
            }
            other => panic!("expected GitHttpRewrite, got {other:?}"),
        }
    }

    #[test]
    fn git_read_verbs_deliver_via_url_rewrite() {
        // Delivery is the URL rewrite for all git remote verbs; least-privilege
        // (push=contents:write vs fetch/clone/pull=contents:read) is the
        // manifest's `need`, not this delivery map.
        for verb in ["git.fetch", "git.clone", "git.pull"] {
            let policy =
                credential_policy(verb).unwrap_or_else(|| panic!("{verb} must have policy"));
            assert_eq!(policy.provider, BrokerProvider::Github, "{verb}");
            match &policy.injection {
                CredentialInjection::GitHttpRewrite { hosts } => {
                    assert_eq!(*hosts, &["github.com"], "{verb} hosts");
                }
                other => panic!("{verb} expected GitHttpRewrite, got {other:?}"),
            }
        }
    }

    #[test]
    fn aws_mutations_use_aws_sts_policy() {
        for verb in [
            "aws.s3.cp",
            "aws.s3.sync",
            "aws.s3.mv",
            "aws.s3.rm",
            "aws.s3api.put-object",
            "aws.s3api.delete-object",
            "aws.s3api.put-bucket-policy",
            "aws.lambda.invoke",
            "aws.lambda.update-function-code",
            "aws.lambda.delete-function",
            "aws.kms.encrypt",
            "aws.kms.decrypt",
            "aws.kms.schedule-key-deletion",
            "aws.cloudformation.delete-stack",
            "aws.cloudformation.update-stack",
            "aws.secretsmanager.update-secret",
            "aws.secretsmanager.delete-secret",
            "aws.secretsmanager.put-secret-value",
        ] {
            let policy =
                credential_policy(verb).unwrap_or_else(|| panic!("{verb} must have policy"));
            assert_eq!(policy.provider, BrokerProvider::AwsSts, "{verb}");
            assert_eq!(
                policy.injection,
                CredentialInjection::AwsCredentials,
                "{verb}"
            );
            // AWS need is a dynamic per-argv AwsPermissionSpec, never a static
            // manifest string (ADR 204 amendment 1).
            assert!(
                manifest_action_need(verb).is_empty(),
                "{verb} must carry no static manifest need"
            );
        }
    }

    #[test]
    fn read_only_actions_have_no_policy() {
        for verb in [
            "git.status",
            "git.log",
            "git.diff",
            "git.commit",
            "kubectl.get",
        ] {
            assert!(
                credential_policy(verb).is_none(),
                "{verb} must have no credential policy"
            );
        }
    }

    #[test]
    fn dangerous_actions_have_no_auto_policy() {
        // repo_delete + auth_login are deny-default in construct.toml;
        // they MUST NOT auto-mint a credential here either.
        assert!(
            credential_policy("gh.repo_delete").is_none(),
            "repo_delete must never auto-mint credentials"
        );
        assert!(
            credential_policy("gh.auth_login").is_none(),
            "auth_login must never auto-mint credentials"
        );
    }

    #[test]
    fn unknown_action_returns_none() {
        assert!(credential_policy("totally.unknown").is_none());
        assert!(credential_policy("").is_none());
    }

    // ---- manifest-sourced need resolver (ADR 204 Amendment 6) -----------

    #[test]
    fn manifest_action_need_resolves_bundled_gh_and_git() {
        // gh: the classifier's dotted key resolves to the bare manifest key
        // via the legacy alias (`gh.pr_create` → `pr_create`).
        assert_eq!(
            manifest_action_need("gh.pr_create"),
            vec![
                "github:metadata:read".to_string(),
                "github:contents:write".to_string(),
                "github:pull_request:create".to_string(),
            ]
        );
        assert_eq!(
            manifest_action_need("gh.pr_list"),
            vec![
                "github:metadata:read".to_string(),
                "github:pull_request:read".to_string(),
            ]
        );
        // git: the classifier's dotted key IS the manifest key (exact match).
        assert_eq!(
            manifest_action_need("git.push"),
            vec![
                "github:metadata:read".to_string(),
                "github:contents:write".to_string(),
            ]
        );
        assert_eq!(
            manifest_action_need("git.fetch"),
            vec![
                "github:metadata:read".to_string(),
                "github:contents:read".to_string(),
            ]
        );
        // The per-verb corrections live at the manifest source.
        assert_eq!(
            manifest_action_need("gh.pr_close"),
            vec![
                "github:metadata:read".to_string(),
                "github:pull_request:create".to_string(),
            ]
        );
        assert_eq!(
            manifest_action_need("gh.workflow_run"),
            vec![
                "github:metadata:read".to_string(),
                "github:actions:write".to_string(),
            ]
        );
        // No static credential need (local/read verbs, other providers,
        // unknown actions, empty) ⇒ empty, the fail-safe.
        for verb in [
            "git.status",
            "git.commit",
            "git.push.force",
            "kubectl.get",
            "aws.s3.cp",
            "totally.unknown",
            "",
        ] {
            assert!(
                manifest_action_need(verb).is_empty(),
                "{verb} must resolve to no manifest need"
            );
        }
    }

    #[test]
    fn need_and_credential_policy_cover_the_same_actions() {
        // The delivery map and the manifest need must never drift: every github
        // action with a credential_policy has a non-empty manifest need, and
        // vice versa. Non-GitHub providers carry their own need IR (AWS = dynamic
        // PermissionSpec), so their manifest need is empty.
        for action in [
            "gh.pr_create",
            "gh.pr_close",
            "gh.pr_view",
            "gh.pr_list",
            "gh.workflow_run",
            "gh.pr_merge",
            "git.push",
            "git.fetch",
            "git.clone",
            "git.pull",
        ] {
            let policy =
                credential_policy(action).unwrap_or_else(|| panic!("{action} should have policy"));
            assert_eq!(policy.provider, BrokerProvider::Github, "{action}");
            assert!(
                !manifest_action_need(action).is_empty(),
                "{action} has a github credential_policy but no manifest need"
            );
        }

        for action in [
            "aws.s3.cp",
            "aws.s3.sync",
            "aws.s3.mv",
            "aws.s3.rm",
            "aws.s3api.put-object",
            "aws.s3api.delete-object",
            "aws.s3api.put-bucket-policy",
            "aws.lambda.invoke",
            "aws.lambda.update-function-code",
            "aws.lambda.delete-function",
            "aws.kms.encrypt",
            "aws.kms.decrypt",
            "aws.kms.schedule-key-deletion",
            "aws.cloudformation.delete-stack",
            "aws.cloudformation.update-stack",
            "aws.secretsmanager.update-secret",
            "aws.secretsmanager.delete-secret",
            "aws.secretsmanager.put-secret-value",
        ] {
            let policy =
                credential_policy(action).unwrap_or_else(|| panic!("{action} should have policy"));
            assert_eq!(policy.provider, BrokerProvider::AwsSts, "{action}");
            assert!(
                manifest_action_need(action).is_empty(),
                "{action} must not declare a static manifest need (uses PermissionSpec)"
            );
        }

        // And actions with no credential_policy have no need.
        for action in ["git.status", "git.commit", "kubectl.get", "gh.repo_delete"] {
            assert!(
                credential_policy(action).is_none(),
                "{action} should have no credential_policy"
            );
            assert!(
                manifest_action_need(action).is_empty(),
                "{action} has no credential_policy but a non-empty manifest need"
            );
        }
    }

    // ---- BKR-4c template → standing-grant lowering ----------------------

    fn gh_pat(action_key: &str) -> ActionRefPattern {
        ActionRefPattern::new(
            "registry.ember.systems/ember-systems/ember-gh",
            action_key,
            "v1",
        )
    }

    fn git_pat(action_key: &str) -> ActionRefPattern {
        ActionRefPattern::new(
            "registry.ember.systems/ember-systems/ember-git",
            action_key,
            "v1",
        )
    }

    /// Drift guard: the catalog and the manifest need must agree in BOTH
    /// directions. Every catalog entry resolves to a non-empty manifest need,
    /// and every known github-need-bearing verb is in the catalog. Catches a
    /// catalog entry whose manifest need was emptied (under-grant — silent scope
    /// drop) or a need-bearing action missing from the catalog.
    #[test]
    fn github_action_catalog_matches_need() {
        // Direction 1: catalog ⊆ need-bearing (manifest-sourced).
        for key in github_action_catalog() {
            assert!(
                !manifest_action_need(key).is_empty(),
                "catalog entry {key} has an empty manifest need"
            );
        }
        // Direction 2: need-bearing ⊆ catalog. The closed need-bearing set;
        // assert each is present so a new need-bearing action without a catalog
        // entry trips here.
        let need_bearing = [
            "gh.pr_create",
            "gh.pr_close",
            "gh.pr_view",
            "gh.pr_list",
            "gh.workflow_run",
            "gh.pr_merge",
            "git.push",
            "git.fetch",
            "git.clone",
            "git.pull",
        ];
        for key in need_bearing {
            assert!(
                github_action_catalog().contains(&key),
                "need-bearing action {key} is missing from github_action_catalog()"
            );
        }
        assert_eq!(
            github_action_catalog().len(),
            need_bearing.len(),
            "catalog has entries beyond the known need-bearing set (or vice versa)"
        );
    }

    /// The manifest is the source of truth for needs: every credentialed action
    /// declared in the bundled gh/git manifests must appear in the catalog, so
    /// template lowering never silently drops a need-bearing action (under-grant).
    #[test]
    fn catalog_covers_every_credentialed_bundled_action() {
        use core_events::construct_toml::parse_action_manifest;
        let catalog: std::collections::BTreeSet<&str> =
            github_action_catalog().iter().copied().collect();
        for (tool, text) in [
            ("gh", include_str!("../construct/gh.toml")),
            ("git", include_str!("../construct/git.toml")),
        ] {
            let parsed = parse_action_manifest(text).expect("bundled manifest parses");
            for action in &parsed.manifest.actions {
                if action.need.is_empty() {
                    continue;
                }
                // Reconstruct the dotted catalog key the classifiers use: gh keys
                // are bare (`pr_create` → `gh.pr_create`); git keys are already
                // dotted (`git.push`).
                let prefix = format!("{tool}.");
                let dotted = if action.key.starts_with(&prefix) {
                    action.key.clone()
                } else {
                    format!("{prefix}{}", action.key)
                };
                assert!(
                    catalog.contains(dotted.as_str()),
                    "{tool} manifest action {} declares a need but is absent from \
                     github_action_catalog()",
                    action.key
                );
            }
        }
    }

    #[test]
    fn template_github_needs_unions_emberd_development_scopes() {
        // emberd-development: `gh.*` + `git.*`, minus `gh.repo_delete`.
        let scopes = vec![git_pat("*"), gh_pat("*")];
        let excludes = vec![gh_pat("repo_delete")];
        let needs = template_github_needs(&scopes, &excludes);
        // Union over all in-scope gh + git verbs (BTreeSet → sorted). After the
        // ADR 204 Amendment 6 per-verb corrections: workflow_run contributes
        // actions:WRITE (dispatch), and pr_create/pr_close no longer pull in
        // actions:read — so the action verb present is actions:write.
        assert_eq!(
            needs,
            vec![
                "github:actions:write".to_string(),
                "github:contents:read".to_string(),
                "github:contents:write".to_string(),
                "github:metadata:read".to_string(),
                "github:pull_request:create".to_string(),
                "github:pull_request:read".to_string(),
            ]
        );
    }

    #[test]
    fn template_github_needs_read_only_template_stays_read_only() {
        // Regression (operator 2026-06-07): a read-only delegation template
        // (git reads + `gh pr list`) must lower to READ needs only — never
        // contents:write — else `need ⊆ grant` at use-time would silently admit
        // a `git.push`. The need is the manifest's: pr_list/pr_view are reads,
        // not the write bundle.
        let scopes = vec![
            git_pat("fetch"),
            git_pat("log"),
            git_pat("status"),
            git_pat("diff"),
            gh_pat("pr_list"),
        ];
        let needs = template_github_needs(&scopes, &[]);
        assert!(
            !needs.contains(&"github:contents:write".to_string()),
            "read-only template must NOT grant contents:write, got {needs:?}"
        );
        assert_eq!(
            needs,
            vec![
                "github:contents:read".to_string(),     // git.fetch
                "github:metadata:read".to_string(),     // GitHub App token baseline
                "github:pull_request:read".to_string(), // gh.pr_list
            ]
        );
    }

    #[test]
    fn template_github_needs_exclude_drops_a_need() {
        // `git.*` minus `git.push` ⇒ only read-side verbs remain, so
        // `github:contents:write` must NOT appear (the exclude is load-bearing).
        let scopes = vec![git_pat("*")];
        let excludes = vec![git_pat("push")];
        let needs = template_github_needs(&scopes, &excludes);
        assert_eq!(
            needs,
            vec![
                "github:contents:read".to_string(),
                "github:metadata:read".to_string(),
            ]
        );
        assert!(
            !needs.contains(&"github:contents:write".to_string()),
            "excluding git.push must drop contents:write"
        );
    }

    #[test]
    fn template_github_needs_empty_for_non_github_template() {
        // A template that scopes only non-github tools lowers to no github
        // authority at all (the standing grant carries no github statements).
        let scopes = vec![
            ActionRefPattern::new(
                "registry.ember.systems/ember-systems/ember-kubectl",
                "*",
                "v1",
            ),
            ActionRefPattern::new(
                "registry.ember.systems/ember-systems/ember-trust",
                "*",
                "v1",
            ),
        ];
        assert!(template_github_needs(&scopes, &[]).is_empty());
    }

    #[test]
    fn template_github_needs_single_verb_scope() {
        // infra-iteration scopes `gh.pr_create` exactly (not `gh.*`): the union
        // is precisely that verb's need, repo binding applied at use-time.
        let scopes = vec![gh_pat("pr_create"), git_pat("*")];
        let needs = template_github_needs(&scopes, &[]);
        // pr_create ⇒ {metadata:read, contents:write, pr:create}
        // (Amendment 6: no actions:read); git.* adds contents:read
        // (fetch/clone/pull) + contents:write (push, already in). No
        // workflow_run in scope ⇒ no actions verb at all.
        assert_eq!(
            needs,
            vec![
                "github:contents:read".to_string(),
                "github:contents:write".to_string(),
                "github:metadata:read".to_string(),
                "github:pull_request:create".to_string(),
            ]
        );
    }

    #[test]
    fn template_github_needs_respects_version_pin() {
        // A scope pinned to a non-`v1` version does not lower the v1 catalog
        // action (the catalog enumerates at v1); `*` version still matches.
        let v2_scope = vec![ActionRefPattern::new(
            "registry.ember.systems/ember-systems/ember-git",
            "push",
            "v2",
        )];
        assert!(template_github_needs(&v2_scope, &[]).is_empty());

        let star_version = vec![ActionRefPattern::new(
            "registry.ember.systems/ember-systems/ember-git",
            "push",
            "*",
        )];
        assert_eq!(
            template_github_needs(&star_version, &[]),
            vec![
                "github:contents:write".to_string(),
                "github:metadata:read".to_string(),
            ]
        );
    }
}
