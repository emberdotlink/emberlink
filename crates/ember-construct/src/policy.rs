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
//! Cohort A is closed by design §3 so the list is small and stable.

use core_broker::BrokerProvider;
use serde_json::Value;

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
    /// `crates/headless-runtime/src/ship.rs::bot_env` builds (lines 629-647).
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

/// Daemon-evaluated credential policy for a classified action.
///
/// `provider` selects which broker mints the credential; `scope` is
/// the provider-specific scope payload (deserialized inside the
/// provider's `Broker::issue` impl); `injection` describes how the
/// minted plaintext lands in the child env.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialPolicy {
    pub provider: BrokerProvider,
    pub scope: Value,
    pub injection: CredentialInjection,
}

/// Look up the credential policy for a daemon-classified action key.
///
/// Returns `None` for actions that don't require a minted credential
/// (read-only verbs, kubectl actions, etc.). Returns `Some(policy)`
/// for verbs that authenticate against an upstream provider.
///
/// The cohort-A list is closed by design §3; new entries land
/// alongside their cohort-A construct.toml addition in the same PR.
pub fn credential_policy(action_key: &str) -> Option<CredentialPolicy> {
    match action_key {
        // ───── gh — GitHub App installation token, delivered via GH_TOKEN ─────
        "gh.pr_create" | "gh.pr_close" | "gh.pr_view" | "gh.pr_list" | "gh.workflow_run" => {
            Some(CredentialPolicy {
                provider: BrokerProvider::Github,
                scope: serde_json::json!({
                    "permissions": [
                        ["pull_requests", "write"],
                        ["contents", "write"],
                        ["actions", "read"],
                    ],
                }),
                injection: CredentialInjection::Env("GH_TOKEN"),
            })
        }

        "gh.pr_merge" => Some(CredentialPolicy {
            // pr_merge requires the wider "write" scope on contents and PRs
            // because the merge call may push a merge commit. Identical to
            // pr_create today; called out separately so a future tightening
            // of pr_merge scope (e.g. workflow approval) lands here cleanly.
            provider: BrokerProvider::Github,
            scope: serde_json::json!({
                "permissions": [
                    ["pull_requests", "write"],
                    ["contents", "write"],
                ],
            }),
            injection: CredentialInjection::Env("GH_TOKEN"),
        }),

        // ───── git — GitHub App installation token, delivered via URL rewrite ─────
        // git.push mutates remote refs; needs contents:write.
        "git.push" => Some(CredentialPolicy {
            provider: BrokerProvider::Github,
            scope: serde_json::json!({
                "permissions": [["contents", "write"]],
            }),
            injection: CredentialInjection::GitHttpRewrite {
                hosts: &["github.com"],
            },
        }),

        // git.fetch / git.clone / git.pull are read-only against the remote;
        // they need an installation token for private-repo auth but
        // principle-of-least-privilege wants contents:read, not write.
        // Anchor: fetch_pull_clone_use_read_scope
        "git.fetch" | "git.clone" | "git.pull" => Some(CredentialPolicy {
            provider: BrokerProvider::Github,
            scope: serde_json::json!({
                "permissions": [["contents", "read"]],
            }),
            injection: CredentialInjection::GitHttpRewrite {
                hosts: &["github.com"],
            },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gh_pr_create_returns_github_policy_with_gh_token_env() {
        let policy = credential_policy("gh.pr_create").expect("policy must be Some");
        assert_eq!(policy.provider, BrokerProvider::Github);
        assert_eq!(policy.injection, CredentialInjection::Env("GH_TOKEN"));
        assert!(policy.scope.is_object());
    }

    #[test]
    fn gh_pr_merge_has_distinct_policy_entry() {
        // Same shape as pr_create today, but a separate match arm so we
        // can tighten pr_merge independently in the future.
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
    fn git_push_has_write_scope() {
        let policy = credential_policy("git.push").expect("git.push must have policy");
        let perms = policy
            .scope
            .get("permissions")
            .expect("permissions present");
        let perms = perms.as_array().expect("permissions is array");
        let first = perms.first().expect("at least one permission");
        let pair = first.as_array().expect("permission entry is array");
        assert_eq!(pair[0].as_str(), Some("contents"));
        assert_eq!(
            pair[1].as_str(),
            Some("write"),
            "git.push must request contents:write"
        );
    }

    #[test]
    fn git_fetch_clone_pull_have_read_scope() {
        // fetch_pull_clone_use_read_scope: read-only verbs must NOT mint
        // contents:write — principle of least privilege.
        for verb in ["git.fetch", "git.clone", "git.pull"] {
            let policy =
                credential_policy(verb).unwrap_or_else(|| panic!("{verb} must have policy"));
            match &policy.injection {
                CredentialInjection::GitHttpRewrite { hosts } => {
                    assert_eq!(*hosts, &["github.com"], "{verb} hosts");
                }
                other => panic!("{verb} expected GitHttpRewrite, got {other:?}"),
            }
            let perms = policy
                .scope
                .get("permissions")
                .expect("permissions present");
            let perms = perms.as_array().expect("permissions is array");
            let first = perms.first().expect("at least one permission");
            let pair = first.as_array().expect("permission entry is array");
            assert_eq!(pair[0].as_str(), Some("contents"), "{verb}");
            assert_eq!(
                pair[1].as_str(),
                Some("read"),
                "{verb} must request contents:read, not write"
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
}
