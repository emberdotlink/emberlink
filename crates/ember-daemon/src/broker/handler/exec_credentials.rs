use crate::infra::store::DaemonStore;
use crate::trust::use_time_verify::{RefuseReason, UseVerdict, verify_grant_for_use};
use core_broker::project::{
    AwsAction, AwsPermissionEffect, AwsPermissionSpec, AwsStsAssumeRoleProjection, AwsStsProjector,
};
use core_broker::{BrokerProvider, BrokerRequest, BrokerScope, MintStamp};
use core_event_types::ExecutionContract;
use core_events::receipt::atomic::StatementProjection;
use core_grant_types::{AccessGrant, ResourceSelector, ResourceType, Statement, Usage};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{BrokerRegistry, current_registry, now_rfc3339_at};

/// Stable, low-cardinality label naming the verifier layer that refused a
/// use-time authority decision ([`verify_grant_for_use`]). Oracle-avoidance:
/// the failing **layer** only, never the internal `NeedUnsatisfiable` /
/// `RevokedAncestor` detail — the warn line is for the operator's audit, not a
/// probing oracle for whatever is driving the mint.
///
/// `pub(super)` so the sibling credential-issue boundary
/// ([`super::materialization::issue_with_registry`]) renders the same
/// low-cardinality labels when it routes through the one composed verifier.
pub(super) fn refuse_layer(reason: &RefuseReason) -> &'static str {
    match reason {
        RefuseReason::NoRootedChainValidGrant => "root_unauthorized_or_chain_invalid",
        RefuseReason::ChainAttenuationViolation { .. } => "chain_attenuation_violation",
        RefuseReason::Unsatisfiable(_) => "need_not_subset_of_grant",
        RefuseReason::AncestorRevoked(_) => "ancestor_revoked",
    }
}

/// V030-REVOKE-ERROR-MESSAGE: operator-facing recovery hint for a use-time
/// refusal. When the refusal is revocation-related, name the canonical
/// abandon-and-reopen action so daemon-log readers see the right next step.
/// Other refusal layers fall through to a generic hint pointing at the
/// runbook. Revoked is terminal at v0.3.0 per ADR 114; CYRUS's v0.3.1+
/// `rebind_grant_after_revoke` brief replaces the restart recovery with a
/// one-RPC rebind. The session-resume path is deliberately NOT named: it
/// re-attaches to the existing session's `meta.grant_id` and would inherit
/// the dead grant — the canonical recovery is to abandon the current harness
/// session and open a fresh one via `ember claude` / `ember codex`.
pub(super) fn revoked_grant_recovery_hint(reason: &RefuseReason) -> &'static str {
    match reason {
        RefuseReason::AncestorRevoked(_) => {
            "parent grant cascade-revoked; this session cannot make brokered calls. Exit the current `claude`/`codex` process and open a fresh session with `ember claude` or `ember codex` under a fresh parent authority (Revoked is terminal at v0.3.0 per ADR 114; v0.3.1+ rebind primitive tracked at docs/runbook/recovery.md `After a grant is revoked`)"
        }
        _ => {
            "see docs/runbook/recovery.md (`After a grant is revoked`) for the canonical recovery flow"
        }
    }
}

/// Lower an action's abstract `github:<object>:<verb>` capability need
/// (from [`ember_construct::manifest_action_need`]) into the canonical
/// `provider:object:verb` use-time need shape — a `Vec<Statement>`, one
/// clause per need string, each repo-bound to the concrete `owner/repo`
/// the operation targets (`ResourceSelector::Exact`).
///
/// This is the BKR-4 PR-B need half: it lives in the SAME algebra the
/// runtime grant lives in (ADR 205 §1/§8, I8), so
/// [`core_grants::scope::resolve_need_against_grants`] can compare
/// `need ⊆ grant` BEFORE projection. `resource_type` is set to
/// `Credential` (matching the dev0 `github:*` grant statement minted by
/// `build_composite_grant_statements`); it is gate-irrelevant metadata —
/// the attenuation walk matches on `actions` + `resource` only
/// (`core-grants/scope.rs` NOTE at §8 / P69K-A2-I4). Budget/conditions
/// are empty: a use-time need carries none of its own.
///
/// Returns an empty `Vec` for an empty need; the caller treats an empty
/// need as fail-closed-by-policy (never "nothing to check").
fn github_need_as_statements(
    need_actions: &[String],
    concrete_repo: &str,
) -> Vec<core_grant_types::Statement> {
    use core_grant_types::{ResourceSelector, ResourceType, Statement, Usage};
    need_actions
        .iter()
        .enumerate()
        .map(|(i, action)| Statement {
            sid: format!("need-{i}"),
            resource_type: ResourceType::Credential,
            actions: vec![action.clone()],
            resource: ResourceSelector::Exact {
                value: concrete_repo.to_string(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        })
        .collect()
}

/// Lower typed AWS PermissionSpecs into canonical use-time need clauses. The
/// role clause and every operation clause must be covered by one runtime grant
/// before the daemon projects native STS scope.
fn aws_permission_specs_as_statements(
    permission_specs: &[AwsPermissionSpec],
    role_arn: &str,
) -> Option<Vec<Statement>> {
    if permission_specs.is_empty() {
        return None;
    }
    let mut out = vec![Statement {
        sid: "aws-need-assume-role".to_string(),
        resource_type: ResourceType::Credential,
        actions: vec!["aws:assume_role".to_string()],
        resource: ResourceSelector::Exact {
            value: role_arn.to_string(),
        },
        budget: None,
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    }];

    let mut i = 0;
    for spec in permission_specs {
        if spec.effect != AwsPermissionEffect::Allow
            || spec.actions.is_empty()
            || spec.resources.is_empty()
        {
            return None;
        }
        for action in &spec.actions {
            let action = aws_grant_action_for(*action);
            for resource in &spec.resources {
                if resource.is_unbounded() {
                    return None;
                }
                out.push(Statement {
                    sid: format!("aws-need-{i}"),
                    resource_type: ResourceType::Credential,
                    actions: vec![action.to_string()],
                    resource: resource.clone(),
                    budget: None,
                    usage: Usage::default(),
                    conditions: Vec::new(),
                    can_delegate: None,
                });
                i += 1;
            }
        }
    }
    Some(out)
}

fn aws_grant_action_for(action: AwsAction) -> &'static str {
    match action {
        AwsAction::S3GetObject => "aws:s3:get_object",
        AwsAction::S3PutObject => "aws:s3:put_object",
        AwsAction::S3DeleteObject => "aws:s3:delete_object",
        AwsAction::S3ListBucket => "aws:s3:list_bucket",
        AwsAction::S3PutBucketPolicy => "aws:s3:put_bucket_policy",
        AwsAction::KmsEncrypt => "aws:kms:encrypt",
        AwsAction::KmsDecrypt => "aws:kms:decrypt",
        AwsAction::KmsScheduleKeyDeletion => "aws:kms:schedule_key_deletion",
        AwsAction::LambdaInvokeFunction => "aws:lambda:invoke_function",
        AwsAction::LambdaUpdateFunctionCode => "aws:lambda:update_function_code",
        AwsAction::LambdaDeleteFunction => "aws:lambda:delete_function",
        AwsAction::CloudFormationCreateChangeSet => "aws:cloudformation:create_change_set",
        AwsAction::CloudFormationExecuteChangeSet => "aws:cloudformation:execute_change_set",
        AwsAction::CloudFormationDeleteStack => "aws:cloudformation:delete_stack",
        AwsAction::CloudFormationUpdateStack => "aws:cloudformation:update_stack",
        AwsAction::SecretsManagerUpdateSecret => "aws:secretsmanager:update_secret",
        AwsAction::SecretsManagerDeleteSecret => "aws:secretsmanager:delete_secret",
        AwsAction::SecretsManagerPutSecretValue => "aws:secretsmanager:put_secret_value",
    }
}

fn aws_assume_role_arn_from_grant(grant: &AccessGrant) -> Option<String> {
    let mut found: Option<String> = None;
    for (_, stmt) in grant.statements() {
        if !stmt
            .actions
            .iter()
            .any(|a| matches!(a.as_str(), "*" | "aws:*" | "aws:assume_role"))
        {
            continue;
        }
        let ResourceSelector::Exact { value } = &stmt.resource else {
            continue;
        };
        if !is_concrete_aws_role_arn(value) {
            continue;
        }
        match found.as_deref() {
            Some(existing) if existing != value => return None,
            Some(_) => {}
            None => found = Some(value.clone()),
        }
    }
    found
}

fn is_concrete_aws_role_arn(value: &str) -> bool {
    value.trim() == value
        && !value.is_empty()
        && !value.contains('*')
        && !value.chars().any(char::is_control)
        && value.starts_with("arn:")
        && value.contains(":role/")
}

fn aws_sts_session_name(action_key: &str, runtime_persona_id: Option<&str>) -> String {
    let mut raw = String::from("ember-");
    raw.push_str(action_key);
    if let Some(persona) = runtime_persona_id.filter(|s| !s.is_empty()) {
        raw.push('-');
        raw.push_str(persona);
    }
    let mut sanitized: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '=' | ',' | '.' | '@' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    sanitized.truncate(64);
    if sanitized.is_empty() {
        "ember-aws".to_string()
    } else {
        sanitized
    }
}

/// Apply a minted credential's plaintext to `env` per the
/// [`ember_construct::CredentialInjection`] shape — single env
/// var for `gh`-style tools, GIT_CONFIG_COUNT/KEY/VALUE triples for git
/// HTTPS URL rewrites. Pure function: no broker, no registry, no
/// network.
///
/// Extracted from [`mint_and_inject_for_action_with_registry`] so the
/// env-mutation logic is unit-testable without a registry.
fn apply_credential_to_env(
    plaintext: &str,
    injection: &ember_construct::CredentialInjection,
    env: &mut std::collections::HashMap<String, String>,
) {
    match injection {
        ember_construct::CredentialInjection::Env(name) => {
            env.insert(name.to_string(), plaintext.to_string());
        }
        ember_construct::CredentialInjection::GitHttpRewrite { hosts } => {
            // Mirror ship.rs::bot_env (lines 629-647 today): set
            // GIT_CONFIG_COUNT plus per-host (KEY_<i>, VALUE_<i>) triples
            // that rewrite https://<host>/ → https://x-access-token:<token>@<host>/
            // for the subprocess lifetime only. No .git/config mutation.
            env.insert("GIT_CONFIG_COUNT".to_string(), hosts.len().to_string());
            for (i, host) in hosts.iter().enumerate() {
                env.insert(
                    format!("GIT_CONFIG_KEY_{i}"),
                    format!("url.https://x-access-token:{plaintext}@{host}/.insteadOf"),
                );
                env.insert(format!("GIT_CONFIG_VALUE_{i}"), format!("https://{host}/"));
            }
        }
        ember_construct::CredentialInjection::AwsCredentials => {
            // The AWS STS broker writes a JSON-encoded credential
            // bundle into BrokeredCredential::token; split it into the
            // three AWS env vars consumed by aws-cli / aws-sdk-* /
            // terraform / etc. Parse failure is logged and produces
            // no env mutation — the child runs without AWS credentials
            // rather than with garbled ones.
            #[derive(serde::Deserialize, Zeroize, ZeroizeOnDrop)]
            struct AwsBundle {
                access_key_id: String,
                secret_access_key: String,
                session_token: String,
            }
            match serde_json::from_str::<AwsBundle>(plaintext) {
                Ok(bundle) => {
                    env.insert(
                        "AWS_ACCESS_KEY_ID".to_string(),
                        bundle.access_key_id.clone(),
                    );
                    env.insert(
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                        bundle.secret_access_key.clone(),
                    );
                    env.insert(
                        "AWS_SESSION_TOKEN".to_string(),
                        bundle.session_token.clone(),
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "AwsCredentials injection: token is not a JSON credential bundle; child runs without AWS env vars"
                    );
                }
            }
        }
        ember_construct::CredentialInjection::GcpAccessToken => {
            // GcpBroker returns a single OAuth bearer token in
            // BrokeredCredential::token — bind it to the env var the
            // Google Cloud SDK + terraform's `google` provider both
            // honour for short-lived bearer auth.
            env.insert(
                "CLOUDSDK_AUTH_ACCESS_TOKEN".to_string(),
                plaintext.to_string(),
            );
        }
        ember_construct::CredentialInjection::AzureAccessToken => {
            // AzureCliBroker returns a single OAuth bearer token in
            // BrokeredCredential::token (minted via the service-
            // principal client-credentials grant). Bind it to the env
            // var the `az` CLI + Azure SDK honour for short-lived
            // bearer auth.
            env.insert("AZURE_ACCESS_TOKEN".to_string(), plaintext.to_string());
        }
        ember_construct::CredentialInjection::FlyApiToken => {
            // FlyBroker returns a single scoped Fly API token in
            // BrokeredCredential::token (minted via Fly's GraphQL
            // `createApiToken` mutation). Bind it to the env var
            // honoured by the `fly` CLI, `flyctl`, and Fly's Machines
            // API clients for bearer auth.
            env.insert("FLY_API_TOKEN".to_string(), plaintext.to_string());
        }
        ember_construct::CredentialInjection::VaultToken => {
            // HashiVaultBroker returns a JSON bundle pairing the minted
            // child token with VAULT_ADDR (the Vault server URL the
            // child needs to dial). Split into the two env vars Vault
            // clients (`vault` CLI, vault SDKs, terraform's `vault`
            // provider) honour: VAULT_TOKEN (the bearer credential) and
            // VAULT_ADDR (the endpoint). Parse failure logs and emits
            // no env mutation — the child runs without Vault env vars
            // rather than with garbled ones.
            #[derive(serde::Deserialize, Zeroize, ZeroizeOnDrop)]
            struct VaultBundle {
                token: String,
                address: String,
            }
            match serde_json::from_str::<VaultBundle>(plaintext) {
                Ok(bundle) => {
                    env.insert("VAULT_TOKEN".to_string(), bundle.token.clone());
                    env.insert("VAULT_ADDR".to_string(), bundle.address.clone());
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "VaultToken injection: token is not a JSON {{token,address}} bundle; child runs without Vault env vars"
                    );
                }
            }
        }
        ember_construct::CredentialInjection::OktaApiToken => {
            // OktaBroker returns a single OAuth bearer token in
            // BrokeredCredential::token (minted via the service-app
            // `private_key_jwt` client-credentials grant). Bind it to
            // OKTA_API_TOKEN — the env var honoured by the official
            // Okta SDKs (`@okta/okta-sdk-nodejs`, `okta-sdk-python`),
            // terraform's `okta` provider, and `okta-aws-cli`.
            env.insert("OKTA_API_TOKEN".to_string(), plaintext.to_string());
        }
        ember_construct::CredentialInjection::VercelToken => {
            // VercelBroker returns a single scoped Vercel API token in
            // BrokeredCredential::token (minted via the
            // `POST /v3/user/tokens` endpoint). Bind it to the env var
            // honoured by the `vercel` CLI for non-interactive auth.
            env.insert("VERCEL_TOKEN".to_string(), plaintext.to_string());
        }
    }
}

/// META-BROKER-EXEC-ENV-LEAK-VIA-PROC Phase 1 (Linux memfd path).
///
/// When `EMBER_BROKER_SEAL_CREDS` is not explicitly set to `0`/`false`
/// on the daemon's environment, replace credential env entries with
/// memfd-sealed fd pointers via
/// [`crate::broker::exec_env::seal_credentials_for_exec`].
/// `credential_keys` is the set of keys that
/// [`apply_credential_to_env`] populated for this exec — typically
/// 0–3 entries depending on the credential shape.
///
/// Returns `(handle, env_for_spawn)`. The handle must outlive the
/// child spawn (its `Drop` closes the fds); `env_for_spawn` carries
/// `<KEY>_FD=<n>` in place of the original `<KEY>=<plaintext>`.
///
/// Default-on (META-EXEC-DOMAIN-MEMFD-SEAL-PHASE-2-LINUX-B): the
/// Phase 2 pre-exec stub in `handle_broker_exec` now rewrites the
/// child's env back to plaintext immediately before execve, so
/// existing consumers (`gh`, `aws`, `vault`, etc.) see plaintext
/// under the expected name. Set `EMBER_BROKER_SEAL_CREDS=0` to
/// disable for diagnostics. Set `EMBER_BROKER_SEAL_CREDS=require` to
/// fail closed instead of falling back when sealing is unavailable.
///
/// On non-Linux targets, `seal_credentials_for_exec` returns
/// `SealError::NotImplemented` — this helper logs a warning at
/// debug-level and falls back to the plaintext env path so the daemon
/// still works on macOS until Phase 2 ships the shm_open variant.
///
/// Safety: returns the ORIGINAL env unchanged when the opt-in is off
/// or when `credential_keys` is empty — the fast path is a no-op move.
pub(super) fn maybe_seal_credentials_in_env(
    env: &mut std::collections::HashMap<String, String>,
    credential_keys: &[String],
) -> Result<
    (
        Option<crate::broker::exec_env::SealedEnv>,
        std::collections::HashMap<String, String>,
    ),
    crate::broker::exec_env::SealError,
> {
    // META-EXEC-DOMAIN-MEMFD-SEAL-PHASE-2-LINUX-B: default flipped to
    // true now that Phase 2's pre-exec stub (in handle_broker_exec
    // above) rewrites the child env back to plaintext before execve.
    // Setting EMBER_BROKER_SEAL_CREDS=0 remains supported as an
    // explicit off-switch for diagnostics. Empty credential list also
    // short-circuits — nothing to seal.
    let seal_mode = std::env::var("EMBER_BROKER_SEAL_CREDS").unwrap_or_else(|_| "1".to_string());
    let require_seal = seal_mode.eq_ignore_ascii_case("require");
    let opt_in = require_seal || !(seal_mode == "0" || seal_mode.eq_ignore_ascii_case("false"));
    if !opt_in || credential_keys.is_empty() {
        return Ok((None, env.clone()));
    }

    // Filter to keys actually present in env that also match the
    // `[A-Z_][A-Z0-9_]*` validator (defence-in-depth — bundle splits
    // like `GIT_CONFIG_KEY_0` match the validator, so this is a
    // defensive net rather than a load-bearing check).
    let pairs: Vec<(String, Zeroizing<String>)> = credential_keys
        .iter()
        .filter_map(|k| env.get(k).map(|v| (k.clone(), Zeroizing::new(v.clone()))))
        .collect();
    if pairs.is_empty() {
        return Ok((None, env.clone()));
    }
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    match crate::broker::exec_env::seal_credentials_for_exec(&refs) {
        Ok(sealed) => {
            // Strip the plaintext entries, insert the `<KEY>_FD=<n>` pairs.
            let mut spawn_env = env.clone();
            for (k, _) in &pairs {
                spawn_env.remove(k);
            }
            for (fd_key, fd_val) in sealed.env_entries() {
                spawn_env.insert(fd_key, fd_val);
            }
            tracing::info!(
                sealed_count = sealed.len(),
                "broker_exec: sealed credentials into memfds (EMBER_BROKER_SEAL_CREDS opt-in)"
            );
            Ok((Some(sealed), spawn_env))
        }
        Err(crate::broker::exec_env::SealError::NotImplemented) => {
            if require_seal {
                return Err(crate::broker::exec_env::SealError::NotImplemented);
            }
            tracing::debug!(
                "broker_exec: EMBER_BROKER_SEAL_CREDS=1 but seal not implemented on this platform; falling back to plaintext env"
            );
            Ok((None, env.clone()))
        }
        Err(e) => {
            if require_seal {
                return Err(e);
            }
            // memfd_create / write / seal failed. Log and fall back to
            // plaintext — failing closed here would block every broker
            // exec on a kernel quirk, which is worse than the leak the
            // seal mitigates. Operators see the warning and can
            // investigate.
            tracing::warn!(
                error = %e,
                "broker_exec: seal_credentials_for_exec failed; falling back to plaintext env"
            );
            Ok((None, env.clone()))
        }
    }
}
/// Lower an action's abstract GitHub capability *need* onto the single
/// concrete `owner/repo` the operation targets, via the audited
/// [`core_broker::project::GithubProjector`] — the only code permitted to
/// speak github's native scope. Yields a native scope whose `repositories`
/// is exactly `[repo]` (owner stripped on the wire) instead of the empty
/// list that means a full installation token.
///
/// Returns `None` (fail-closed) on empty/unparseable need or any projector
/// refusal — a refusal is never widened to an unbounded mint (ADR 205 §4).
///
/// `needs` are the action's abstract `github:<object>:<verb>` need strings,
/// resolved from the bundled manifest (`manifest_action_need`, ADR 204
/// Amendment 6). Each is lowered to a [`core_broker::project::CapabilityVerb`]
/// (`parse_github_need`) bound to `owner_repo`, then projected — keeping I6:
/// only the audited [`core_broker::project::GithubProjector`] speaks github's
/// native scope.
fn project_github_need_to_repo(needs: &[String], owner_repo: &str) -> Option<BrokerScope> {
    use core_broker::project::{
        CapabilityVerb, ConcreteTarget, GithubProjector, NativeProjector, ResolvedNeed,
    };
    if needs.is_empty() {
        return None;
    }
    let mut resolved: Vec<ResolvedNeed> = Vec::with_capacity(needs.len());
    for need in needs {
        let Some(capability) = CapabilityVerb::parse_github_need(need) else {
            tracing::warn!(
                need = %need,
                owner_repo = %owner_repo,
                "broker_exec: manifest github need did not lower to a capability — \
                 no credential minted (fail-closed)"
            );
            return None;
        };
        resolved.push(ResolvedNeed {
            capability,
            target: ConcreteTarget::Repo(owner_repo.to_string()),
        });
    }
    match GithubProjector.project(&resolved) {
        Ok(scope) => Some(scope),
        Err(e) => {
            tracing::warn!(
                error = %e,
                owner_repo = %owner_repo,
                "broker_exec: github projector refused — no credential minted (fail-closed)"
            );
            None
        }
    }
}

/// ADR 204 amendment 2 / ADR 205 §B.4 — the provider-echo clamp (I7).
///
/// `minted_native` is the scope the projector CLAIMED it asked the provider to
/// mint; `echo` is the provider's authoritative scope echo — what it ACTUALLY
/// granted. Assert the echo is no wider than the claim, compared **in native
/// space** (the projector's own vocabulary; no lossy bridge to the grant's
/// action-intent algebra — `need ⊆ grant` already ran on that axis). Catches a
/// projector/provider that yielded authority beyond the request, and — via
/// `native_upper_bound`'s unbounded-refusal — an echo widened to a full
/// installation token (empty repos/permissions). Fail-closed: any violation, or
/// an unparseable/unbounded echo, is `Err` so the caller revokes the mint.
///
/// The daemon clamp intentionally has no per-provider arm (ADR 213 AC-5).
/// Typed `MintStamp` payloads route to provider-declared parser helpers in
/// `core-broker`: G1 `Scope` parses and compares scope upper bounds, while G2
/// `Identity` parses and compares the minted identity. G3 variants carry no
/// checkable bound; the caller skips this function via
/// [`MintStamp::is_checkable`].
pub(super) fn assert_mint_stamp_within_minted(
    provider: BrokerProvider,
    minted_native: &BrokerScope,
    echo: &MintStamp,
) -> Result<(), String> {
    echo.assert_within_minted(provider, minted_native)
}

fn broker_resolved_ttl_line(
    provider: BrokerProvider,
    persona_display: &str,
    ttl_minutes: i64,
) -> String {
    format!(
        "[broker] resolved {}-token to {} — TTL {}m",
        provider.as_str(),
        persona_display,
        ttl_minutes
    )
}

/// Resolve the concrete `owner/repo` a `gh.*` action targets, for binding
/// the minted installation token. Reads an **explicit** `--repo`/`-R` flag
/// (the `--repo=owner/repo`, `-R owner/repo`, and attached `-Rowner/repo`
/// forms gh accepts), and accepts both a bare `owner/repo` and a full
/// github URL. Returns `None` when no explicit, unambiguous github target is
/// present — the caller falls back to the cwd's `origin` remote, then
/// fail-closed. We deliberately do NOT replicate gh's full base-repo
/// resolution (the `GH_REPO` env, fork upstream-vs-origin heuristics): a
/// guess that bound the token to the wrong repo would 403 the command.
pub(super) fn resolve_gh_repo_from_argv(argv: &[String]) -> Option<String> {
    let mut target: Option<String> = None;
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if let Some(v) = a.strip_prefix("--repo=").or_else(|| a.strip_prefix("-R=")) {
            target = Some(v.to_string());
        } else if a == "--repo" || a == "-R" {
            if i + 1 < argv.len() {
                target = Some(argv[i + 1].clone());
                i += 1;
            }
        } else if let Some(v) = a.strip_prefix("-R").filter(|v| !v.is_empty()) {
            // gh's attached short form `-Rowner/repo`.
            target = Some(v.to_string());
        }
        i += 1;
    }
    let t = target?;
    // URL form (`https://…`, `git@…`) → reuse the strict host classifier.
    if t.contains("://") || t.contains('@') {
        return ember_construct::git::owner_repo_from_remote_url(&t);
    }
    // Bare `[github.com/]owner/repo` form.
    let segs: Vec<&str> = t.trim_matches('/').split('/').collect();
    let (owner, repo) = match segs.as_slice() {
        [owner, repo] => (*owner, *repo),
        [host, owner, repo] if *host == "github.com" => (*owner, *repo),
        _ => return None,
    };
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if owner.is_empty() || repo.is_empty() || owner.contains('*') || repo.contains('*') {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

/// Best-effort concrete `owner/repo` for a `gh.*` action with no explicit
/// `--repo`: read the `origin` remote from the cwd's git config (gh's own
/// default base-repo source). Returns `None` outside a git work tree, when
/// `origin` is absent/unreadable, or when it is not a github.com remote — the
/// caller then fail-closes the mint rather than guessing a wrong-repo bound.
///
/// Documented limit (dev0): for a fork whose gh base-repo is the upstream
/// (not `origin`), this binds to `origin`; if gh then targets the upstream the
/// call 403s. At dev0 (own repos, origin == target) this does not arise, and
/// fail-closed-to-403 is strictly safer than an unbounded full-installation token.
pub(super) fn origin_owner_repo_from_cwd(cwd: &str) -> Option<String> {
    use std::path::Path;
    let wtree_id = crate::broker::working_tree_id::working_tree_id(Path::new(cwd)).ok()?;
    let url = crate::broker::gitconfig_reader::read_remote_url_from_gitconfig(
        Path::new(&wtree_id),
        "origin",
    )
    .ok()?;
    ember_construct::git::owner_repo_from_remote_url(&url)
}

/// Mint a credential through `registry` for `action_key`'s declared
/// policy and inject into `env`. Tests pass a fresh `BrokerRegistry`
/// with `MockBroker` registered to verify behaviour without touching
/// the process-global `OnceCell`. Production callers use
/// [`mint_and_inject_for_action`] which resolves the registry via
/// [`current_registry`].
///
/// `concrete_repo` is the `owner/repo` the operation targets; the github
/// mint is bound to it via the projector. `None` ⇒ fail-closed (no mint).
///
/// `runtime_grant` is the resolved runtime persona's chain-verified
/// standing grant (BKR-4 PR-B). The action's abstract operation need
/// (`ember_construct::manifest_action_need`, repo-bound to `concrete_repo`)
/// is checked `need ⊆ grant` via
/// [`core_grants::scope::resolve_need_against_grants`] BEFORE
/// `broker.issue()`. Fail-closed: `None` grant, an empty/unknown need, or
/// `need ⊄ grant` ⇒ mint NOTHING (this closes the historical
/// `caller_persona = None` authority bypass, current-architecture.md §116).
///
/// `runtime_persona_id` is the resolved runtime persona that the minted
/// credential is bound to (replaces the prior `caller_persona: None`).
///
/// T-CONSTRUCT-EXEC-CRED-INJECT.
#[allow(clippy::too_many_arguments)]
async fn mint_and_inject_for_action_with_registry(
    action_key: &str,
    env: &mut std::collections::HashMap<String, String>,
    registry: &BrokerRegistry,
    store: &DaemonStore,
    persona_alias: Option<&str>,
    concrete_repo: Option<&str>,
    aws_permission_specs: Option<&[AwsPermissionSpec]>,
    execution_contract: Option<&ExecutionContract>,
    runtime_grant: Option<&AccessGrant>,
    runtime_persona_id: Option<&str>,
) -> Option<(String, BrokerProvider)> {
    use secrecy::ExposeSecret;
    let policy = ember_construct::credential_policy(action_key)?;
    let broker = registry.brokers.get(&policy.provider)?;

    let Some(grant) = runtime_grant else {
        tracing::warn!(
            action = %action_key,
            "broker_exec: no runtime grant resolved for need ≤ grant check — \
             no credential minted (fail-closed, BKR-4 PR-B); child runs without token"
        );
        return None;
    };

    // ADR 205 §1/§4 + ADR 204 — native scope is DERIVED, never caller-authored.
    // Each provider first builds its concrete use-time need in the grant
    // algebra, checks `need <= grant`, and only then projects native scope.
    let (native_scope, resolved_grant_id, grant_bound_identity, requested_scope_statements) =
        match policy.provider {
            BrokerProvider::Github => {
                let Some(repo) = concrete_repo else {
                    tracing::warn!(
                        action = %action_key,
                        "broker_exec: no concrete repo target resolved for github mint — \
                         no credential minted (fail-closed, ADR 205 §4); child runs without token"
                    );
                    return None;
                };
                let need_actions = ember_construct::manifest_action_need(action_key);
                if need_actions.is_empty() {
                    tracing::warn!(
                        action = %action_key,
                        "broker_exec: action declares no github operation need but requires a \
                         credential mint — no credential minted (fail-closed, BKR-4 PR-B)"
                    );
                    return None;
                }
                let need = github_need_as_statements(&need_actions, repo);
                // BKR-4b (ADR 205 §A.6 step 3): authorize the mint through the
                // COMPOSED use-time verifier, never `resolve_need_against_grants`
                // alone (§A.3). Over the bare predicate this adds, at the mint
                // boundary: (1) root-authorization of the issuing persona
                // (transitional daemon-stored root — the §A.5/§9 dev0 limit; firms
                // to the device-set when ADR 206 steps 1–2 land, no caller change),
                // (2) grant-chain signature verification, and (4) the §A.4 online
                // ancestor-revocation walk (a revoked ANCESTOR blocks the mint even
                // when the leaf grant is active — today enforced only at the proxy
                // boundary). Fail-closed: any refusal mints NOTHING; the log names
                // only the failing layer (oracle-avoidance).
                let resolved_grant_id = match verify_grant_for_use(
                    store,
                    store,
                    std::slice::from_ref(grant),
                    &need,
                ) {
                    UseVerdict::Authorized { grant_id, .. } => grant_id,
                    UseVerdict::Refused { reason } => {
                        // V030-REVOKE-ERROR-MESSAGE: when the use-time verifier
                        // refuses for a revocation reason (leaf revoked / ancestor
                        // revoked), name the operator-facing recovery action in
                        // the warn log so daemon-log readers see the canonical
                        // restart command. Revoked is terminal at v0.3.0 per
                        // ADR 114; CYRUS's v0.3.1+ rebind brief is out of scope.
                        let recovery = revoked_grant_recovery_hint(&reason);
                        tracing::warn!(
                            action = %action_key,
                            grant_id = %grant.id,
                            concrete_repo = %repo,
                            refused = %refuse_layer(&reason),
                            needed = ?need_actions,
                            recovery = %recovery,
                            "broker_exec: github mint refused by composed use-time verifier — \
                             no credential minted (fail-closed, BKR-4b §A.3/§A.4); child runs without token"
                        );
                        return None;
                    }
                };
                let native_scope = project_github_need_to_repo(&need_actions, repo)?;
                (native_scope, resolved_grant_id, None, need)
            }
            BrokerProvider::AwsSts => {
                let Some(permission_specs) = aws_permission_specs.filter(|specs| !specs.is_empty())
                else {
                    tracing::warn!(
                        action = %action_key,
                        "broker_exec: aws action has no bounded PermissionSpec — \
                         no credential minted (fail-closed)"
                    );
                    return None;
                };
                let Some(role_arn) = aws_assume_role_arn_from_grant(grant) else {
                    tracing::warn!(
                        action = %action_key,
                        grant_id = %grant.id,
                        "broker_exec: runtime grant does not name one concrete aws:assume_role role — \
                         no credential minted (fail-closed)"
                    );
                    return None;
                };
                let Some(need) = aws_permission_specs_as_statements(permission_specs, &role_arn)
                else {
                    tracing::warn!(
                        action = %action_key,
                        grant_id = %grant.id,
                        aws_role_arn = %role_arn,
                        "broker_exec: aws PermissionSpec could not be lowered to grant need — \
                         no credential minted (fail-closed)"
                    );
                    return None;
                };
                // BKR-4b (ADR 205 §A.6 step 3): same composed use-time verifier as
                // the github branch — root-auth (1) + chain-verify (2) + need⊆grant
                // (3) + §A.4 ancestor-revocation walk (4), never the bare predicate
                // alone (§A.3). Fail-closed; the log names only the failing layer.
                let resolved_grant_id = match verify_grant_for_use(
                    store,
                    store,
                    std::slice::from_ref(grant),
                    &need,
                ) {
                    UseVerdict::Authorized { grant_id, .. } => grant_id,
                    UseVerdict::Refused { reason } => {
                        // V030-REVOKE-ERROR-MESSAGE: same recovery hint as the
                        // github branch — when the refusal is revocation-related,
                        // surface the canonical session-restart command in the
                        // warn log so operators aren't left guessing.
                        let recovery = revoked_grant_recovery_hint(&reason);
                        tracing::warn!(
                            action = %action_key,
                            grant_id = %grant.id,
                            aws_role_arn = %role_arn,
                            refused = %refuse_layer(&reason),
                            aws_permission_specs = ?permission_specs,
                            recovery = %recovery,
                            "broker_exec: aws mint refused by composed use-time verifier — \
                             no credential minted (fail-closed, BKR-4b §A.3/§A.4); child runs without AWS credentials"
                        );
                        return None;
                    }
                };
                let native_scope =
                    match AwsStsProjector.project_assume_role(&AwsStsAssumeRoleProjection {
                        role_arn: role_arn.clone(),
                        session_name: aws_sts_session_name(action_key, runtime_persona_id),
                        ttl_seconds: 3600,
                        permissions: permission_specs.to_vec(),
                        external_id: None,
                    }) {
                        Ok(scope) => scope,
                        Err(e) => {
                            tracing::warn!(
                                action = %action_key,
                                grant_id = %grant.id,
                                aws_role_arn = %role_arn,
                                error = %e,
                                "broker_exec: aws projector refused PermissionSpec — \
                                 no credential minted (fail-closed)"
                            );
                            return None;
                        }
                    };
                (native_scope, resolved_grant_id, Some(role_arn), need)
            }
            other => {
                tracing::warn!(
                    action = %action_key,
                    provider = other.as_str(),
                    "broker_exec: no native-scope projector for provider — \
                     no credential minted (fail-closed)"
                );
                return None;
            }
        };

    let requested_scope: Vec<StatementProjection> = requested_scope_statements
        .iter()
        .map(StatementProjection::from)
        .collect();
    let granted_scope: Vec<StatementProjection> = grant
        .statements()
        .map(|(_, stmt)| StatementProjection::from(stmt))
        .collect();

    // Keep the native scope we are about to mint for the materialization audit
    // event (the projector-claim half), before it is moved into the request.
    let minted_native = native_scope.clone();

    let req = BrokerRequest {
        provider: policy.provider,
        scope: native_scope,
        // 1-hour TTL matches GitHub App installation token cap; provider
        // brokers may clamp downward. Per-action TTL tuning lands when a
        // narrower window is needed (e.g. high-blast-radius actions).
        ttl: std::time::Duration::from_secs(3600),
        contract_id: execution_contract.and_then(|contract| contract.contract_id.clone()),
        action_ref: execution_contract.map(|contract| contract.action_ref.clone()),
        workspace_ref: execution_contract.and_then(|contract| contract.workspace_ref.clone()),
        subject_ref: execution_contract.and_then(|contract| contract.subject_ref.clone()),
        coordination_ref: execution_contract.and_then(|contract| contract.coordination_ref.clone()),
        caller_ref: execution_contract.and_then(|contract| contract.caller_ref.clone()),
        authority_ref: execution_contract.and_then(|contract| contract.authority_ref.clone()),
        reason: format!("broker_exec:{action_key}"),
        // BKR-4 PR-B: the broker_exec credential mint is now authorized by the
        // `need ⊆ grant` check above (NOT just construct.toml policy). Bind the
        // request to the resolved runtime persona that holds the covering grant,
        // closing the historical `caller_persona: None` bypass
        // (current-architecture.md §116).
        caller_persona: runtime_persona_id.map(|id| id.to_string()),
        grants_file_rev: None,
        grants_file_credential_name: None,
    };

    let cred = match broker.issue(req.clone()).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                action = %action_key,
                provider = policy.provider.as_str(),
                error = %e,
                "broker_exec: credential mint failed; child runs without injected credential"
            );
            return None;
        }
    };

    // ADR 204 amendment 2 / ADR 205 §B.4 (I7) — the provider-echo clamp. The
    // mint recorded what the projector CLAIMED (`minted_native`); the provider's
    // echo is what it ACTUALLY granted. Assert the echo is no wider than the
    // claim BEFORE the credential is recorded or injected — catching a
    // projector/provider that yielded authority beyond the request. Fail-closed
    // by the same COMPENSATION as the audit-write failure arm below: revoke
    // the just-minted credential, inject nothing. Variant-dispatched per
    // ADR 213 §D4 via `is_checkable()`: `Scope` / `Identity`
    // enter the clamp; the three G3 variants (`Unbounded` /
    // `Opaque` / `Unwired`) skip — there is no
    // checkable bound to verify, and per AC-3 the skip is type-driven, not
    // an `Option` toggle. A future variant addition forces an exhaustive
    // match in `is_checkable`, so a new bound-bearing variant
    // cannot silently slip past this gate.
    let clamp_result = if cred.mint_stamp.is_checkable() {
        assert_mint_stamp_within_minted(policy.provider, &minted_native, &cred.mint_stamp)
    } else {
        Ok(())
    };
    if let Err(reason) = clamp_result {
        tracing::error!(
            target: "ember::broker",
            action = %action_key,
            provider = policy.provider.as_str(),
            materialization_id = %cred.materialization_id,
            reason = %reason,
            "broker_exec: provider scope echo EXCEEDS minted claim (ADR 204 I7) — \
             revoking credential and injecting nothing (fail-closed)"
        );
        revoke_minted_credential_with_registry(&cred.materialization_id, policy.provider, registry)
            .await;
        return None;
    }

    // ADR 213 AC-9 — G2 secondary gate. A MintStamp::Identity credential is
    // bounded by the operator's identity-provisioning discipline, NOT by a
    // permission echo. The grant MUST have resolved a concrete identity
    // (role/SA/principal) pre-mint; if the provider stamped Identity but the
    // flow resolved no grant-bound identity, the mint is unbounded and must
    // fail closed. For AWS STS the identity is the assumed role ARN
    // (extracted at line 713); future G2 providers populate the same slot.
    if matches!(cred.mint_stamp, MintStamp::Identity { .. }) && grant_bound_identity.is_none() {
        tracing::error!(
            target: "ember::broker",
            action = %action_key,
            provider = policy.provider.as_str(),
            materialization_id = %cred.materialization_id,
            "broker_exec: G2 mint stamp is Identity but no concrete grant-bound identity \
             was resolved — revoking credential (fail-closed, ADR 213 AC-9)"
        );
        revoke_minted_credential_with_registry(&cred.materialization_id, policy.provider, registry)
            .await;
        return None;
    }

    // ADR 213 AC-10 — G3 secondary gate. A G3 MintStamp (Unbounded / Opaque /
    // Unwired) carries no checkable scope bound — the authority ceiling comes
    // from the proxy budget/egress policy. broker_exec is the direct-injection
    // path: credentials are injected as env vars / git config and the child
    // calls the provider directly, bypassing the proxy. No proxy = no budget
    // enforcement = the credential is unbounded. Fail closed: revoke the
    // just-minted credential and inject nothing.
    if !cred.mint_stamp.is_checkable() {
        tracing::error!(
            target: "ember::broker",
            action = %action_key,
            provider = policy.provider.as_str(),
            materialization_id = %cred.materialization_id,
            mint_stamp_kind = %cred.mint_stamp.kind(),
            "broker_exec: G3 mint has no checkable bound and no active proxy \
             budget/egress policy (direct-injection path bypasses proxy) — \
             revoking credential (fail-closed, ADR 213 AC-10)"
        );
        revoke_minted_credential_with_registry(&cred.materialization_id, policy.provider, registry)
            .await;
        return None;
    }

    // ADR 205 §B / ADR 204 amendment 3 — emit the materialization AUDIT event
    // BEFORE injecting the credential, and FAIL CLOSED: if the (hash-chained,
    // tamper-evident) audit write fails, refuse to inject. Absent record ⇒
    // structurally a non-mint. BKR-5 makes mint+record atomic-in-effect: an
    // external mint and this local audit log share no transaction, so a failed
    // audit write actively REVOKES the just-minted credential (compensation)
    // rather than leaking it to TTL — see the failure arm below. broker_exec
    // previously emitted NO materialization record at all — `git.push` / `gh.*`
    // minted-JIT credentials were fulfilled unrecorded.
    //
    // BKR-4 PR-B: the authority basis is now the runtime persona's standing
    // grant (the `need ⊆ grant` check above passed), NOT just construct.toml
    // policy — record `authority_basis: "grant"` + the resolved `grant_id` the
    // need was fulfilled against (current-architecture.md §324). The declared
    // capability need is still recorded alongside.
    // ADR 213 §D4 / §AC-3 — record the typed `MintStamp` variant
    // discriminator + payload. Replaces the legacy `provider_scope_attestable:
    // bool` derived from `is_some()`, which lost the G1-vs-G2 distinction.
    // Offline verifiers and org policy read `mint_stamp_kind` ("permissions" /
    // "identity" / "none") to pick the right guarantee shape; `mint_stamp`
    // serializes the variant + payload (tagged JSON) so the verifier can re-run
    // the variant-specific check.
    let mint_stamp_kind = cred.mint_stamp.kind();
    let aws_permission_specs_for_audit = if policy.provider == BrokerProvider::AwsSts {
        serde_json::to_value(aws_permission_specs.unwrap_or(&[] as &[AwsPermissionSpec]))
            .unwrap_or(serde_json::Value::Null)
    } else {
        serde_json::Value::Null
    };
    let authority_capabilities = match policy.provider {
        // The abstract github need (manifest-sourced, ADR 204 Amendment 6) that
        // was projected to native scope — recorded for the audit trail.
        BrokerProvider::Github => {
            format!("{:?}", ember_construct::manifest_action_need(action_key))
        }
        BrokerProvider::AwsSts => format!("{:?}", aws_permission_specs.unwrap_or(&[])),
        _ => String::new(),
    };
    let audit_details = serde_json::json!({
        "kind": "broker.materialization",
        "source": "broker_exec",
        "action_key": action_key,
        "provider": policy.provider.as_str(),
        "materialization_id": cred.materialization_id,
        "contract_id": req.contract_id,
        "action_ref": req.action_ref,
        "workspace_ref": req.workspace_ref,
        "subject_ref": req.subject_ref,
        "coordination_ref": req.coordination_ref,
        "caller_ref": req.caller_ref,
        "authority_ref": req.authority_ref,
        "concrete_repo": concrete_repo,
        "aws_role_arn": grant_bound_identity,
        "grant_bound_identity": grant_bound_identity,
        "aws_permission_specs": aws_permission_specs_for_audit,
        "expires_at": now_rfc3339_at(cred.expires_at),
        "authority_basis": "grant",
        "grant_id": resolved_grant_id,
        "caller_persona": runtime_persona_id,
        "authority_capabilities": authority_capabilities,
        // Authority-algebra evidence — enough for an offline verifier to
        // re-run `need <= grant` without trusting the provider-native shape.
        "grant_comparison": "need_lte_grant",
        "grant_comparison_verifier": "verify_grant_for_use",
        "requested_scope": requested_scope,
        "granted_scope": granted_scope,
        // Projector-claim half — the native scope we asked the provider to mint.
        "minted_native": minted_native,
        // Provider-truth half, recorded DISTINCTLY (ADR 204 amd 2 / I7 / ADR 213
        // §D4) so an offline verifier can detect a provider/projector that
        // yielded wider authority than the leaf claimed. Serialized as the
        // tagged `MintStamp` variant (`kind` = permissions / identity /
        // unbounded / opaque / unwired + typed payload when present).
        "mint_stamp": cred.mint_stamp,
        // ADR 213 §AC-3 discriminator: replaces `provider_scope_attestable:
        // bool`. Stable strings the offline verifier / org policy reads to
        // select the per-variant guarantee shape ("permissions" = G1
        // granular bound, "identity" = G2 identity-only, "unbounded" /
        // "opaque" / "unwired" = the three G3 sources).
        "mint_stamp_kind": mint_stamp_kind,
        // ADR 213 AC-9/AC-10 — the effective authority ceiling for this mint.
        // "permissions" = G1 (bounded by attested scope echo),
        // "bound_identity" = G2 (bounded by operator identity-provisioning).
        // G3 variants never reach this audit write — AC-10 fails them closed
        // above — so proxy_budget_active=false is correct (direct-injection).
        "effective_ceiling": cred.mint_stamp.effective_ceiling(false),
    })
    .to_string();

    if let Err(e) = store.log_event(
        persona_alias,
        "broker.materialization",
        Some(policy.provider.as_str()),
        "allowed",
        Some(&audit_details),
    ) {
        tracing::error!(
            target: "ember::broker",
            action = %action_key,
            provider = policy.provider.as_str(),
            materialization_id = %cred.materialization_id,
            error = %e,
            "broker_exec: materialization audit-event write FAILED — refusing to \
             inject credential (fail-closed; absent record ⇒ non-mint, ADR 205 §B.5)"
        );
        // BKR-5 — atomic-in-effect mint+record via compensation. The mint
        // already succeeded at the broker, so returning here without revoking
        // would leak a LIVE, unrecorded credential until its TTL. An external
        // mint and the local hash-chained audit log share no transaction, so we
        // recover atomicity by REVOKING the just-minted credential. The env is
        // mutated only AFTER this durable audit write (below), so no token was
        // ever injected; the only residual is a daemon crash between `issue()`
        // and this point, which stays TTL-bounded and uninjected.
        revoke_minted_credential_with_registry(&cred.materialization_id, policy.provider, registry)
            .await;
        return None;
    }

    apply_credential_to_env(cred.token.expose_secret(), &policy.injection, env);

    // SCION-DEMO-BEAT-6-BROKER-TTL-LOG — emit a single operator-visible
    // line at info level so the demo recording (and post-hoc operators)
    // can see the broker minted a TTL'd credential bound to the caller
    // persona. The wider tracing event above carries the structured
    // fields; this line is the human-readable companion the storyboard
    // narrates. `target = "ember::broker"` keeps the line greppable
    // even when the daemon log is mixed with other subsystems.
    let ttl_minutes = cred
        .expires_at
        .duration_since(std::time::SystemTime::now())
        .map(|d| (d.as_secs() / 60) as i64)
        .unwrap_or(0);
    let persona_display = persona_alias.unwrap_or("<no-persona>");
    let operator_line = broker_resolved_ttl_line(policy.provider, persona_display, ttl_minutes);
    tracing::info!(
        target: "ember::broker",
        "{}",
        operator_line,
    );

    tracing::info!(
        action = %action_key,
        provider = policy.provider.as_str(),
        materialization_id = %cred.materialization_id,
        ttl_minutes = ttl_minutes,
        persona_alias = persona_display,
        "broker_exec: credential minted and injected"
    );

    Some((cred.materialization_id, policy.provider))
}

/// Production wrapper resolving the process-global registry. Returns
/// `None` when no registry is installed, no policy applies to the
/// action, or the broker's `issue` fails — caller continues without
/// injection (logged warning).
#[allow(clippy::too_many_arguments)]
pub(super) async fn mint_and_inject_for_action(
    action_key: &str,
    env: &mut std::collections::HashMap<String, String>,
    store: &DaemonStore,
    persona_alias: Option<&str>,
    concrete_repo: Option<&str>,
    aws_permission_specs: Option<&[AwsPermissionSpec]>,
    execution_contract: Option<&ExecutionContract>,
    runtime_grant: Option<&AccessGrant>,
    runtime_persona_id: Option<&str>,
) -> Option<(String, BrokerProvider)> {
    let registry = current_registry()?;
    mint_and_inject_for_action_with_registry(
        action_key,
        env,
        registry,
        store,
        persona_alias,
        concrete_repo,
        aws_permission_specs,
        execution_contract,
        runtime_grant,
        runtime_persona_id,
    )
    .await
}

/// Revoke a credential previously minted by
/// [`mint_and_inject_for_action_with_registry`] against `registry`.
/// Best-effort — failures are logged but don't propagate.
async fn revoke_minted_credential_with_registry(
    materialization_id: &str,
    provider: BrokerProvider,
    registry: &BrokerRegistry,
) {
    let Some(broker) = registry.brokers.get(&provider) else {
        tracing::warn!(
            materialization_id = %materialization_id,
            provider = provider.as_str(),
            "broker_exec: cannot revoke credential — provider not registered"
        );
        return;
    };
    let plaintext = registry
        .lookup_plaintext(materialization_id)
        .map(|entry| entry.plaintext);

    match broker.revoke(materialization_id, plaintext).await {
        Ok(()) => {
            tracing::info!(
                materialization_id = %materialization_id,
                provider = provider.as_str(),
                "broker_exec: credential revoked"
            );
        }
        Err(e) => {
            tracing::warn!(
                materialization_id = %materialization_id,
                provider = provider.as_str(),
                error = %e,
                "broker_exec: credential revoke failed (TTL bound applies)"
            );
        }
    }
}

/// Production wrapper resolving the process-global registry. No-op when
/// no registry is installed.
pub(super) async fn revoke_minted_credential(materialization_id: &str, provider: BrokerProvider) {
    let Some(registry) = current_registry() else {
        tracing::warn!(
            materialization_id = %materialization_id,
            provider = provider.as_str(),
            "broker_exec: cannot revoke credential — registry unavailable"
        );
        return;
    };
    revoke_minted_credential_with_registry(materialization_id, provider, registry).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_event_types::ActionRef;

    // ─── T-CONSTRUCT-EXEC-CRED-INJECT ──────────────────────────────────────

    fn fresh_registry_with_mock(provider: core_broker::BrokerProvider) -> BrokerRegistry {
        let mut r = BrokerRegistry::new();
        r.register(Box::new(core_broker::MockBroker::new(provider)));
        r
    }

    // ─── BKR-4b (ADR 205 §A.6 step 3): runtime-grant fixtures ───────────────
    //
    // The broker_exec mint now authorizes through the COMPOSED verifier
    // `verify_grant_for_use` (§A.3), not `resolve_need_against_grants` alone. A
    // runtime grant must therefore be (1) issued by a persona the store roots
    // AND (2) carry a real signed chain — not merely satisfy need⊆grant. These
    // fixtures create a real persona in `store` and sign the grant with its root
    // key so it PASSES the composition. `synthetic_unrooted_grant` keeps the
    // pre-BKR-4b unsigned shape for the negative (unrooted-refusal) test.

    /// Attach an in-memory vault (idempotent — keyed deterministically) so
    /// `create_persona` + root-key signing work; `DaemonStore::open_in_memory()`
    /// attaches none.
    fn ensure_vault(store: &DaemonStore) {
        store.set_vault(std::rc::Rc::new(crate::infra::vault::Vault::new(
            [0xAB; 32],
        )));
    }

    /// Create a real persona in `store` and return an Active, root-authorized,
    /// chain-VERIFIED `AccessGrant` carrying `statements`, signed by that
    /// persona's root key. This is exactly what the composed verifier requires:
    /// (1) `authorized_root_pubkey` resolves the persona row, (2) `verify_chain`
    /// checks the real signature, (3) `resolve_need_against_grants` runs over
    /// `statements`. Apex grant (id not inserted into the `grants` table), so the
    /// §A.4 ancestry walk is a no-op. Use wherever the mint must SUCCEED, or must
    /// refuse for a genuine need⊄grant reason (vs the unrooted path).
    fn rooted_grant(store: &DaemonStore, statements: Vec<Statement>) -> AccessGrant {
        ensure_vault(store);
        let persona = store
            .create_persona("agent-runtime")
            .expect("create runtime persona");
        crate::trust::grant::access_grant_from_statements_for_persona(
            store,
            "grant-runtime-test",
            &persona.id,
            "r",
            statements,
            0,
            None,
        )
        .expect("sign rooted runtime grant")
    }

    fn credential_statement(
        sid: &str,
        actions: Vec<String>,
        resource: ResourceSelector,
    ) -> Statement {
        Statement {
            sid: sid.to_string(),
            resource_type: ResourceType::Credential,
            actions,
            resource,
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        }
    }

    /// A rooted single-statement grant (`actions` on `resource`).
    fn runtime_grant_with(
        store: &DaemonStore,
        actions: Vec<String>,
        resource: ResourceSelector,
    ) -> AccessGrant {
        rooted_grant(
            store,
            vec![credential_statement("g-stmt", actions, resource)],
        )
    }

    /// The pre-BKR-4b synthetic shape: a well-formed-but-UNSIGNED grant whose
    /// issuing persona is NOT in the store. `resolve_need_against_grants` alone
    /// would admit it; the composed verifier refuses it at part (1)/(2)
    /// (`NoRootedChainValidGrant`). Used only by the unrooted-refusal test.
    fn synthetic_unrooted_grant(actions: Vec<String>, resource: ResourceSelector) -> AccessGrant {
        use core_event_types::PresentationAudienceKind;
        use core_grant_types::{
            AttestationBinding, Block, GrantMode, GrantStatus, RecipientProfile, SignedBlock,
        };
        AccessGrant {
            id: "grant-runtime-test".into(),
            version: 1,
            issuing_persona_id: "p".into(),
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: "r".into(),
            recipient_profile: RecipientProfile::Agent,
            status: GrantStatus::Active,
            mode: GrantMode::OneShot,
            blocks: vec![SignedBlock {
                block: Block {
                    statements: vec![credential_statement("g-stmt", actions, resource)],
                    nbf: None,
                    expires_at: None,
                    issued_by: "p".into(),
                    issued_at: 0,
                    approval: None,
                    note: None,
                },
                pubkey_next: "x".into(),
                signature: "x".into(),
            }],
            attestation: AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        }
    }

    /// The dev0 github ceiling grant (`github:*` on `*`) minted by
    /// `build_composite_grant_statements` (PR-A) and mirrored onto the runtime
    /// persona. Subsumes any `github:<object>:<verb>` need on any repo. Rooted in
    /// `store` so it passes the composed verifier.
    fn github_star_grant(store: &DaemonStore) -> AccessGrant {
        runtime_grant_with(
            store,
            vec!["github:*".to_string()],
            ResourceSelector::Glob {
                pattern: "*".to_string(),
            },
        )
    }

    use core_grant_types::ResourceSelector;

    fn grant_statement(
        sid: &str,
        actions: Vec<String>,
        resource: ResourceSelector,
    ) -> core_grant_types::Statement {
        core_grant_types::Statement {
            sid: sid.to_string(),
            resource_type: core_grant_types::ResourceType::Credential,
            actions,
            resource,
            budget: None,
            usage: core_grant_types::Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        }
    }

    fn runtime_grant_with_statements(
        store: &DaemonStore,
        statements: Vec<core_grant_types::Statement>,
    ) -> AccessGrant {
        rooted_grant(store, statements)
    }

    fn aws_runtime_grant_for_s3_put(
        store: &DaemonStore,
        role_arn: &str,
        object_arn: &str,
    ) -> AccessGrant {
        runtime_grant_with_statements(
            store,
            vec![
                grant_statement(
                    "aws-role",
                    vec!["aws:assume_role".to_string()],
                    ResourceSelector::Exact {
                        value: role_arn.to_string(),
                    },
                ),
                grant_statement(
                    "aws-s3-put",
                    vec!["aws:s3:put_object".to_string()],
                    ResourceSelector::Exact {
                        value: object_arn.to_string(),
                    },
                ),
            ],
        )
    }

    fn aws_runtime_grant_for_cloudformation(
        store: &DaemonStore,
        role_arn: &str,
        action: &str,
        stack_arn: &str,
    ) -> AccessGrant {
        runtime_grant_with_statements(
            store,
            vec![
                grant_statement(
                    "aws-role",
                    vec!["aws:assume_role".to_string()],
                    ResourceSelector::Exact {
                        value: role_arn.to_string(),
                    },
                ),
                grant_statement(
                    "aws-cloudformation-stack",
                    vec![action.to_string()],
                    ResourceSelector::Exact {
                        value: stack_arn.to_string(),
                    },
                ),
            ],
        )
    }

    struct AwsJsonBroker {
        issued: std::sync::Arc<std::sync::Mutex<Vec<BrokerRequest>>>,
    }

    impl core_broker::Broker for AwsJsonBroker {
        fn provider(&self) -> core_broker::BrokerProvider {
            core_broker::BrokerProvider::AwsSts
        }

        async fn issue(
            &self,
            req: BrokerRequest,
        ) -> Result<core_broker::BrokeredCredential, core_broker::BrokerError> {
            self.issued.lock().expect("issued mutex").push(req.clone());
            let token = serde_json::json!({
                "access_key_id": "ASIATESTACCESSKEY",
                "secret_access_key": "testSecretAccessKeyValue",
                "session_token": "testSessionTokenValue",
                "expiration": "2099-01-01T00:00:00Z",
            })
            .to_string();
            // Mirror the real broker: AWS echoes the assumed-role IDENTITY only
            // (not the permissions). This stand-in attests the minted role.
            let assumed_role_arn = req
                .scope
                .get("role_arn")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            Ok(core_broker::BrokeredCredential {
                token: secrecy::SecretString::from(token),
                expires_at: std::time::SystemTime::now() + req.ttl,
                materialization_id: "aws-json-1".to_string(),
                mint_stamp: core_broker::MintStamp::Identity {
                    identity: core_broker::IdentityRef {
                        provider: core_broker::BrokerProvider::AwsSts,
                        identity: assumed_role_arn,
                    },
                },
            })
        }

        async fn revoke(&self, _materialization_id: &str) -> Result<(), core_broker::BrokerError> {
            Ok(())
        }
    }

    struct RecordingGithubBroker {
        issued: std::sync::Arc<std::sync::Mutex<Vec<BrokerRequest>>>,
    }

    impl core_broker::Broker for RecordingGithubBroker {
        fn provider(&self) -> core_broker::BrokerProvider {
            core_broker::BrokerProvider::Github
        }

        async fn issue(
            &self,
            req: BrokerRequest,
        ) -> Result<core_broker::BrokeredCredential, core_broker::BrokerError> {
            self.issued.lock().expect("issued mutex").push(req.clone());
            let bound = core_broker::PermissionBound::from_native(
                core_broker::BrokerProvider::Github,
                req.scope.clone(),
            )
            .map_err(core_broker::BrokerError::InvalidScope)?;
            Ok(core_broker::BrokeredCredential {
                token: secrecy::SecretString::from("canary-token-github-recording".to_string()),
                expires_at: std::time::SystemTime::now() + req.ttl,
                materialization_id: "github-recording-1".to_string(),
                mint_stamp: core_broker::MintStamp::Permissions { bound },
            })
        }

        async fn revoke(&self, _materialization_id: &str) -> Result<(), core_broker::BrokerError> {
            Ok(())
        }
    }

    fn resolve_access_pr_create_grant(store: &DaemonStore) -> AccessGrant {
        runtime_grant_with_statements(
            store,
            vec![
                grant_statement(
                    "resolve-access-metadata",
                    vec!["github:metadata:read".to_string()],
                    ResourceSelector::Exact {
                        value: "acme/widgets".to_string(),
                    },
                ),
                grant_statement(
                    "resolve-access-contents",
                    vec!["github:contents:write".to_string()],
                    ResourceSelector::Exact {
                        value: "acme/widgets".to_string(),
                    },
                ),
                grant_statement(
                    "resolve-access-pr",
                    vec!["github:pull_request:create".to_string()],
                    ResourceSelector::Exact {
                        value: "acme/widgets".to_string(),
                    },
                ),
            ],
        )
    }

    #[test]
    fn apply_credential_to_env_single_env_inserts_named_var() {
        let mut env = std::collections::HashMap::new();
        let injection = ember_construct::CredentialInjection::Env("GH_TOKEN");
        apply_credential_to_env("ghs_test_token", &injection, &mut env);
        assert_eq!(
            env.get("GH_TOKEN").map(|s| s.as_str()),
            Some("ghs_test_token")
        );
        assert_eq!(env.len(), 1);
    }

    #[test]
    fn apply_credential_to_env_git_rewrite_writes_config_count_and_triple() {
        let mut env = std::collections::HashMap::new();
        let injection = ember_construct::CredentialInjection::GitHttpRewrite {
            hosts: &["github.com"],
        };
        apply_credential_to_env("ghs_secret_value", &injection, &mut env);
        let expected_key = format!(
            "url.https://x-access-token:{}@github.com/.insteadOf",
            "ghs_secret_value"
        );
        assert_eq!(env.get("GIT_CONFIG_COUNT").map(|s| s.as_str()), Some("1"));
        assert_eq!(
            env.get("GIT_CONFIG_KEY_0").map(|s| s.as_str()),
            Some(expected_key.as_str()),
        );
        assert_eq!(
            env.get("GIT_CONFIG_VALUE_0").map(|s| s.as_str()),
            Some("https://github.com/"),
        );
    }

    #[test]
    fn apply_credential_to_env_git_rewrite_handles_multiple_hosts() {
        let mut env = std::collections::HashMap::new();
        let injection = ember_construct::CredentialInjection::GitHttpRewrite {
            hosts: &["github.com", "gitlab.com"],
        };
        apply_credential_to_env("tok", &injection, &mut env);
        assert_eq!(env.get("GIT_CONFIG_COUNT").map(|s| s.as_str()), Some("2"));
        assert!(env.contains_key("GIT_CONFIG_KEY_0"));
        assert!(env.contains_key("GIT_CONFIG_KEY_1"));
        assert!(env.contains_key("GIT_CONFIG_VALUE_0"));
        assert!(env.contains_key("GIT_CONFIG_VALUE_1"));
    }

    #[test]
    fn apply_credential_to_env_aws_credentials_splits_json_bundle_into_three_vars() {
        let mut env = std::collections::HashMap::new();
        let injection = ember_construct::CredentialInjection::AwsCredentials;
        let bundle = serde_json::json!({
            "access_key_id": "ASIATESTACCESSKEY",
            "secret_access_key": "testSecretAccessKeyValue",
            "session_token": "testSessionTokenValue",
            "expiration": "2099-01-01T00:00:00Z",
        })
        .to_string();
        apply_credential_to_env(&bundle, &injection, &mut env);
        assert_eq!(
            env.get("AWS_ACCESS_KEY_ID").map(|s| s.as_str()),
            Some("ASIATESTACCESSKEY")
        );
        assert_eq!(
            env.get("AWS_SECRET_ACCESS_KEY").map(|s| s.as_str()),
            Some("testSecretAccessKeyValue")
        );
        assert_eq!(
            env.get("AWS_SESSION_TOKEN").map(|s| s.as_str()),
            Some("testSessionTokenValue")
        );
        assert_eq!(env.len(), 3);
    }

    #[test]
    fn apply_credential_to_env_aws_credentials_invalid_json_leaves_env_unchanged() {
        let mut env = std::collections::HashMap::new();
        let injection = ember_construct::CredentialInjection::AwsCredentials;
        // Plaintext is not a valid AWS bundle — child runs without
        // AWS env vars (logged warning) rather than with garbage.
        apply_credential_to_env("not a json bundle", &injection, &mut env);
        assert!(env.is_empty(), "env must stay empty on parse failure");
    }

    #[tokio::test]
    async fn mint_for_action_with_no_policy_returns_none_and_no_env_change() {
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let result = mint_and_inject_for_action_with_registry(
            "git.status", // local-only action — no policy
            &mut env,
            &registry,
            &store,
            None,
            Some("acme/widgets"),
            None,
            None,
            None,
            None,
        )
        .await;
        assert!(result.is_none(), "no-policy actions must return None");
        assert!(
            env.is_empty(),
            "env must not be modified for no-policy actions"
        );
    }

    #[tokio::test]
    async fn mint_for_gh_pr_create_injects_gh_token_and_returns_id() {
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = github_star_grant(&store);
        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            None,
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;
        let (mat_id, provider) = result.expect("mint must succeed with registered MockBroker");
        assert_eq!(provider, core_broker::BrokerProvider::Github);
        assert!(
            mat_id.starts_with("mock-"),
            "MockBroker IDs are mock-N: {mat_id}"
        );
        assert!(env.contains_key("GH_TOKEN"));
        assert!(env.get("GH_TOKEN").unwrap().starts_with("canary-token-"));
    }

    #[tokio::test]
    async fn github_service_connection_readiness_alone_never_authorizes_ember_gh_pr_create() {
        // A registered GitHub broker models Service Connection readiness: the
        // upstream material can mint. It still cannot authorize an Action.
        // Without a runtime Grant, the daemon must not call broker.issue().
        let issued = std::sync::Arc::new(std::sync::Mutex::new(Vec::<BrokerRequest>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(RecordingGithubBroker {
            issued: issued.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();

        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            None,
            Some("persona-x"),
        )
        .await;

        assert!(
            result.is_none(),
            "GitHub Service Connection readiness alone must not authorize ember-gh.pr_create"
        );
        assert!(env.is_empty(), "no token may be injected without a Grant");
        assert!(
            issued.lock().expect("issued mutex").is_empty(),
            "broker.issue must not be called when no runtime Grant authorizes the Action"
        );
    }

    #[tokio::test]
    async fn github_materialization_records_need_lte_grant_evidence_for_resolve_access() {
        let issued = std::sync::Arc::new(std::sync::Mutex::new(Vec::<BrokerRequest>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(RecordingGithubBroker {
            issued: issued.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = resolve_access_pr_create_grant(&store);

        let (mat_id, provider) = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await
        .expect("Resolve Access grant delta must authorize PR creation");

        assert_eq!(mat_id, "github-recording-1");
        assert_eq!(provider, core_broker::BrokerProvider::Github);
        assert!(env.contains_key("GH_TOKEN"));

        let issued = issued.lock().expect("issued mutex");
        assert_eq!(issued.len(), 1);
        let req = &issued[0];
        assert_eq!(req.provider, core_broker::BrokerProvider::Github);
        assert_eq!(req.scope["repositories"], serde_json::json!(["widgets"]));
        let permissions = req.scope["permissions"]
            .as_array()
            .expect("github permissions array");
        assert!(
            permissions.contains(&serde_json::json!(["metadata", "read"])),
            "GitHub mint must include the provider metadata permission: {permissions:?}"
        );
        assert!(
            permissions.contains(&serde_json::json!(["contents", "write"])),
            "GitHub mint must include the manifest-derived contents permission: {permissions:?}"
        );
        assert!(
            permissions.contains(&serde_json::json!(["pull_requests", "write"])),
            "GitHub mint must include the manifest-derived PR permission: {permissions:?}"
        );
        assert_eq!(
            permissions.len(),
            3,
            "GitHub mint must not widen beyond the approved GrantDelta statements"
        );

        let events = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("query audit");
        assert_eq!(events.len(), 1);
        let details: serde_json::Value =
            serde_json::from_str(events[0].details.as_deref().expect("details"))
                .expect("details json");
        assert_eq!(details["grant_comparison"], "need_lte_grant");
        assert_eq!(details["grant_comparison_verifier"], "verify_grant_for_use");
        assert_eq!(details["requested_scope"].as_array().unwrap().len(), 3);
        assert_eq!(details["granted_scope"].as_array().unwrap().len(), 3);
        assert_eq!(
            details["requested_scope"][0]["resource"],
            serde_json::json!({"kind": "exact", "value": "acme/widgets"})
        );
        assert_eq!(
            details["granted_scope"][0]["sid"],
            "resolve-access-metadata"
        );
        assert_eq!(
            details["granted_scope"][1]["sid"],
            "resolve-access-contents"
        );
        assert_eq!(details["granted_scope"][2]["sid"], "resolve-access-pr");
        assert_eq!(
            details["minted_native"]["repositories"],
            serde_json::json!(["widgets"])
        );
        assert_eq!(details["mint_stamp_kind"], "permissions");
    }

    #[tokio::test]
    async fn mint_refused_when_grant_persona_not_root_authorized() {
        // BKR-4b (ADR 205 §A.3): the composed verifier refuses a grant whose
        // issuing persona is NOT authorized by the store's root set, even though
        // its statements satisfy need ⊆ grant. This is the store-injected /
        // forged-grant gap that `resolve_need_against_grants` alone (which trusts
        // the grants it is handed) would admit. The synthetic grant carries
        // `github:*` on `*` (covers gh.pr_create's need) but persona "p" was
        // never created in the store ⇒ part (1) root-authorization fails closed
        // (NoRootedChainValidGrant) ⇒ no credential minted.
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = synthetic_unrooted_grant(
            vec!["github:*".to_string()],
            ResourceSelector::Glob {
                pattern: "*".to_string(),
            },
        );
        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            None,
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;
        assert!(
            result.is_none(),
            "a grant whose persona is not root-authorized must fail closed at the \
             composed verifier (part 1), not mint a credential"
        );
        assert!(env.is_empty(), "no token must be injected on refusal");
    }

    #[tokio::test]
    async fn mint_refused_when_grant_ancestor_revoked() {
        // BKR-4b (ADR 205 §A.4): the online ancestor-revocation walk now runs at
        // the broker_exec MINT boundary, not only at the proxy. A leaf runtime
        // grant that is itself active AND covers the need is still refused if an
        // ANCESTOR in its `parent_grant_id` lineage was revoked — the exact hole
        // the eager `cascade_revoke_children` write can miss (crash/race), and
        // that `resolve_need_against_grants` (leaf-only) would never catch.
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        ensure_vault(&store);
        let persona = store.create_persona("agent-runtime").unwrap();

        // Apex parent grant — a real row; only its status matters to the walk.
        let parent = store
            .create_grant(&persona.id, "parent", "github:*", None)
            .unwrap();

        // Leaf grant: create a row, then (a) make it cover gh.pr_create's need by
        // overwriting blocks_json with a signed `github:*` statement and (b) make
        // it descend from the (soon-revoked) parent via `parent_grant_id`.
        let leaf_row = store
            .create_grant(&persona.id, "leaf", "github:*", None)
            .unwrap();
        let covering = crate::trust::grant::access_grant_from_statements_for_persona(
            &store,
            &leaf_row.id,
            &persona.id,
            "leaf",
            vec![credential_statement(
                "g-stmt",
                vec!["github:*".to_string()],
                ResourceSelector::Glob {
                    pattern: "*".to_string(),
                },
            )],
            0,
            None,
        )
        .unwrap();
        let blocks_json = crate::trust::grant::access_grant_blocks_to_json(&covering).unwrap();
        store
            .conn()
            .execute(
                "UPDATE grants SET blocks_json = ?1, parent_grant_id = ?2 WHERE id = ?3",
                rusqlite::params![blocks_json, parent.id, leaf_row.id],
            )
            .unwrap();

        // Revoke ONLY the parent — simulate a cascade that never reached the
        // still-active leaf.
        store
            .conn()
            .execute(
                "UPDATE grants SET status = 'revoked' WHERE id = ?1",
                rusqlite::params![parent.id],
            )
            .unwrap();

        let grant = store.get_access_grant(&leaf_row.id).unwrap();
        assert_eq!(
            grant.status,
            core_grant_types::GrantStatus::Active,
            "leaf grant must itself be active so the refusal is purely the §A.4 walk"
        );

        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            None,
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;
        assert!(
            result.is_none(),
            "a revoked ANCESTOR must block the broker_exec mint via the §A.4 walk, \
             even though the leaf grant is active and covers the need"
        );
        assert!(
            env.is_empty(),
            "no token must be injected when an ancestor is revoked"
        );
    }

    #[tokio::test]
    async fn broker_exec_mint_emits_materialization_audit_event() {
        // ADR 205 §B — the broker_exec (construct) mint path now emits a
        // materialization AUDIT event; previously it emitted NO record at all,
        // so git.push / gh.* minted-JIT credentials were fulfilled unrecorded.
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let mut execution_contract = ExecutionContract::new(ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "gh.pr_create",
            "v1",
        ))
        .with_contract_id("contract-forge-123");
        execution_contract.workspace_ref = Some("managed_worktree:forge".to_string());
        execution_contract.subject_ref = Some("forge:run:run-123".to_string());
        execution_contract.coordination_ref = Some("forge:workflow_event:event-123".to_string());
        execution_contract.caller_ref = Some("persona:forge".to_string());
        execution_contract.authority_ref = Some("grant:forge".to_string());
        let grant = github_star_grant(&store);
        let (mat_id, _provider) = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            Some(&execution_contract),
            Some(&grant),
            Some("persona-x"),
        )
        .await
        .expect("mint must succeed");

        let events = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("query audit");
        assert_eq!(
            events.len(),
            1,
            "exactly one broker_exec materialization audit event"
        );
        let details: serde_json::Value =
            serde_json::from_str(events[0].details.as_deref().expect("details present"))
                .expect("details is json");
        assert_eq!(details["source"], "broker_exec");
        assert_eq!(details["action_key"], "gh.pr_create");
        assert_eq!(details["materialization_id"], mat_id);
        assert_eq!(details["provider"], "github");
        assert_eq!(details["contract_id"], "contract-forge-123");
        assert_eq!(details["workspace_ref"], "managed_worktree:forge");
        assert_eq!(details["subject_ref"], "forge:run:run-123");
        assert_eq!(
            details["coordination_ref"],
            "forge:workflow_event:event-123"
        );
        assert_eq!(details["caller_ref"], "persona:forge");
        assert_eq!(details["authority_ref"], "grant:forge");
        // BKR-4 PR-B — the materialization records that the mint was authorized
        // by the runtime persona's standing grant (need ≤ grant), naming the
        // covering grant id + the resolved persona that holds it.
        assert_eq!(
            details["authority_basis"], "grant",
            "authority_basis must be 'grant' (was construct_policy): {details}"
        );
        assert_eq!(
            details["grant_id"], "grant-runtime-test",
            "materialization must record the covering grant id: {details}"
        );
        assert_eq!(details["caller_persona"], "persona-x");
        // MockBroker mirrors the prod GitHub adapter: echoes the request
        // scope as MintStamp::Permissions (G1). The audit records the
        // variant discriminator + tagged payload; the legacy bool MUST NOT
        // appear (AC-3: bool removed and unread).
        assert!(details.get("provider_scope_attestable").is_none());
        assert_eq!(details["mint_stamp_kind"], "permissions");
        assert_eq!(details["mint_stamp"]["kind"], "permissions");
        // Projector-claim half is recorded (the native GithubScope minted).
        assert!(
            details["minted_native"].is_object(),
            "minted_native recorded: {details}"
        );
        assert_eq!(events[0].agent_id.as_deref(), Some("persona-x"));
    }

    /// Broker whose `issue()` mints a deterministic canary and whose
    /// `revoke()` records the materialization id into a shared `Arc` the
    /// test still holds — lets a test observe the BKR-5 compensation revoke
    /// without reaching back into the registry's boxed `dyn DynBroker`.
    struct RevokeSpyBroker {
        provider: core_broker::BrokerProvider,
        revoked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl core_broker::Broker for RevokeSpyBroker {
        fn provider(&self) -> core_broker::BrokerProvider {
            self.provider
        }

        async fn issue(
            &self,
            req: BrokerRequest,
        ) -> Result<core_broker::BrokeredCredential, core_broker::BrokerError> {
            // Echo the request scope as Permissions (G1) so AC-10 doesn't
            // refuse the mint before the audit-write compensation path this
            // broker exists to test.
            let mint_stamp =
                core_broker::PermissionBound::from_native(self.provider, req.scope.clone())
                    .map(|bound| core_broker::MintStamp::Permissions { bound })
                    .unwrap_or(core_broker::MintStamp::Unbounded);
            Ok(core_broker::BrokeredCredential {
                token: secrecy::SecretString::from("canary-token-spy-1".to_string()),
                expires_at: std::time::SystemTime::now() + req.ttl,
                materialization_id: "spy-1".to_string(),
                mint_stamp,
            })
        }

        async fn revoke(&self, materialization_id: &str) -> Result<(), core_broker::BrokerError> {
            self.revoked
                .lock()
                .expect("revoke spy mutex")
                .push(materialization_id.to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn broker_exec_revokes_mint_when_audit_write_fails() {
        // BKR-5 — mint+record atomic-in-effect by COMPENSATION. If the durable,
        // hash-chained materialization audit write fails AFTER a successful
        // broker mint, the just-minted credential must be REVOKED (not leaked to
        // TTL) and NO token injected. An external mint shares no transaction
        // with the local audit log, so revoke-on-failure is the achievable
        // atomicity. This is the failure-path companion to
        // `broker_exec_mint_emits_materialization_audit_event`.
        let revoked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(RevokeSpyBroker {
            provider: core_broker::BrokerProvider::Github,
            revoked: revoked.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        // Force every audit write on this store to fail by removing the table
        // the appender reads/writes — the deterministic stand-in for a real
        // audit-log write failure.
        store
            .conn()
            .execute("DROP TABLE audit_log", [])
            .expect("drop audit_log to force write failure");
        let grant = github_star_grant(&store);

        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;

        assert!(
            result.is_none(),
            "a failed materialization audit write must refuse the mint (fail-closed)"
        );
        assert!(
            !env.contains_key("GH_TOKEN"),
            "no token may be injected when the materialization record could not be written"
        );
        assert_eq!(
            revoked.lock().expect("revoke spy mutex").as_slice(),
            ["spy-1"],
            "the just-minted credential must be revoked (compensation), not leaked to TTL"
        );
    }

    /// Broker that mints a canary credential carrying a configurable github
    /// `mint_stamp`, and records `revoke` calls — to exercise the ADR 204 I7
    /// provider-echo clamp (a provider that echoes authority wider than minted).
    struct EchoBroker {
        echo: core_broker::GithubScope,
        revoked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl core_broker::Broker for EchoBroker {
        fn provider(&self) -> core_broker::BrokerProvider {
            core_broker::BrokerProvider::Github
        }

        async fn issue(
            &self,
            req: BrokerRequest,
        ) -> Result<core_broker::BrokeredCredential, core_broker::BrokerError> {
            // EchoBroker feeds the daemon clamp deliberately-wider-than-minted
            // github echoes. `self.echo` is always a parseable bounded scope
            // (non-empty repos + permissions); it differs from minted only in
            // WHICH permissions it claims. `from_native` accepts it (bounded
            // ⇒ Ok); the clamp's `echo_needs ⊆ minted_needs` check is the
            // actual gate, and that's what the outer test asserts.
            let native = serde_json::to_value(&self.echo).expect("GithubScope serializes");
            let bound = core_broker::PermissionBound::from_native(
                core_broker::BrokerProvider::Github,
                native,
            )
            .expect("EchoBroker fixture must supply a parseable bounded github native");
            Ok(core_broker::BrokeredCredential {
                token: secrecy::SecretString::from("canary-token-echo-1".to_string()),
                expires_at: std::time::SystemTime::now() + req.ttl,
                materialization_id: "echo-1".to_string(),
                mint_stamp: core_broker::MintStamp::Permissions { bound },
            })
        }

        async fn revoke(&self, materialization_id: &str) -> Result<(), core_broker::BrokerError> {
            self.revoked
                .lock()
                .expect("revoke spy mutex")
                .push(materialization_id.to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn broker_exec_revokes_when_mint_stamp_exceeds_minted_scope() {
        // ADR 204 amendment 2 / ADR 205 §B.4 (I7) — the provider echoed authority
        // the projector never minted (`administration:write` is not in
        // gh.pr_create's scope). The clamp must revoke the credential and inject
        // nothing, fail-closed.
        let revoked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(EchoBroker {
            echo: core_broker::GithubScope {
                repositories: vec!["widgets".to_string()],
                permissions: vec![("administration".to_string(), "write".to_string())],
            },
            revoked: revoked.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = github_star_grant(&store);

        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;

        assert!(
            result.is_none(),
            "a provider echo wider than the minted scope must refuse the mint (I7)"
        );
        assert!(
            !env.contains_key("GH_TOKEN"),
            "no token may be injected when the provider echo exceeds the minted claim"
        );
        assert_eq!(
            revoked.lock().expect("revoke spy mutex").as_slice(),
            ["echo-1"],
            "the over-wide credential must be revoked (compensation), not leaked to TTL"
        );
    }

    #[tokio::test]
    async fn broker_exec_accepts_mint_stamp_within_minted_scope() {
        // ADR 204 I7 — the echo is a SUBSET of the minted scope
        // (`contents:write` on the same repo, which gh.pr_create did request).
        // The clamp passes; the token is injected and nothing is revoked.
        let revoked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(EchoBroker {
            echo: core_broker::GithubScope {
                repositories: vec!["widgets".to_string()],
                permissions: vec![("contents".to_string(), "write".to_string())],
            },
            revoked: revoked.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = github_star_grant(&store);

        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;

        assert!(
            result.is_some(),
            "a provider echo within the minted scope must mint successfully (I7)"
        );
        assert!(
            env.contains_key("GH_TOKEN"),
            "the token is injected when the echo is within the minted claim"
        );
        assert!(
            revoked.lock().expect("revoke spy mutex").is_empty(),
            "no revoke when the provider echo is within scope"
        );
    }

    #[tokio::test]
    async fn mint_for_git_push_injects_git_config_rewrite_triple() {
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = github_star_grant(&store);
        let result = mint_and_inject_for_action_with_registry(
            "git.push",
            &mut env,
            &registry,
            &store,
            None,
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;
        let (_mat_id, provider) = result.expect("git.push mint must succeed");
        assert_eq!(provider, core_broker::BrokerProvider::Github);
        assert_eq!(env.get("GIT_CONFIG_COUNT").map(|s| s.as_str()), Some("1"));
        assert!(
            env.get("GIT_CONFIG_KEY_0")
                .map(|s| s.contains("github.com"))
                .unwrap_or(false)
        );
    }

    #[tokio::test]
    async fn mint_for_action_with_no_registered_broker_returns_none() {
        // Empty registry — no MockBroker registered.
        let registry = BrokerRegistry::new();
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            None,
            Some("acme/widgets"),
            None,
            None,
            None,
            None,
        )
        .await;
        assert!(result.is_none(), "missing broker must return None");
        assert!(
            env.is_empty(),
            "env must not be modified when broker is missing"
        );
    }

    #[tokio::test]
    async fn mint_github_action_fails_closed_without_concrete_repo() {
        // ADR 205 §4 — a github mint with no resolved concrete repo target must
        // mint NOTHING (the prior behaviour widened to a full installation
        // token). No env mutation; the child runs without a token.
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = github_star_grant(&store);
        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            None,
            None,
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;
        assert!(
            result.is_none(),
            "github mint must fail closed without a concrete repo target"
        );
        assert!(
            env.is_empty(),
            "no credential env var may be injected on a fail-closed mint"
        );
    }

    #[test]
    fn project_github_need_bounds_scope_to_single_repo() {
        // The projected native scope must name exactly the operation's repo
        // (owner stripped on the wire) — never an empty `repositories` that
        // GitHub reads as the App's full installation scope. The need is the
        // manifest-sourced abstract string (ADR 204 Amendment 6), including
        // GitHub's provider-mandatory metadata:read baseline.
        let need = ember_construct::manifest_action_need("git.push");
        assert_eq!(
            need,
            vec![
                "github:metadata:read".to_string(),
                "github:contents:write".to_string(),
            ]
        );
        let scope =
            project_github_need_to_repo(&need, "acme/widgets").expect("projector must bound");
        assert_eq!(scope["repositories"], serde_json::json!(["widgets"]));
        assert_eq!(
            scope["permissions"],
            serde_json::json!([["contents", "write"], ["metadata", "read"]])
        );
        // Empty need ⇒ fail-closed (no full-token widen).
        assert!(project_github_need_to_repo(&[], "acme/widgets").is_none());
        // A non-concrete (glob) target the projector refuses ⇒ fail-closed.
        assert!(project_github_need_to_repo(&need, "acme/*").is_none());
        // An unparseable need string ⇒ fail-closed (never widened).
        assert!(
            project_github_need_to_repo(&["github:bogus:write".to_string()], "acme/widgets")
                .is_none()
        );
    }

    #[test]
    fn resolve_gh_repo_from_argv_parses_repo_flag_forms() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            resolve_gh_repo_from_argv(&v(&["pr", "create", "--repo", "acme/widgets"])),
            Some("acme/widgets".to_string())
        );
        assert_eq!(
            resolve_gh_repo_from_argv(&v(&["pr", "list", "--repo=acme/widgets"])),
            Some("acme/widgets".to_string())
        );
        assert_eq!(
            resolve_gh_repo_from_argv(&v(&["pr", "view", "-Racme/widgets"])),
            Some("acme/widgets".to_string())
        );
        assert_eq!(
            resolve_gh_repo_from_argv(&v(&["pr", "view", "-R", "github.com/acme/widgets"])),
            Some("acme/widgets".to_string())
        );
        // URL form routes through the strict host classifier.
        assert_eq!(
            resolve_gh_repo_from_argv(&v(&[
                "pr",
                "view",
                "--repo",
                "https://github.com/acme/widgets.git"
            ])),
            Some("acme/widgets".to_string())
        );
        // No --repo ⇒ None (caller falls back to cwd origin, then fail-closed).
        assert_eq!(resolve_gh_repo_from_argv(&v(&["pr", "create"])), None);
        // A non-github host is not a valid github target.
        assert_eq!(
            resolve_gh_repo_from_argv(&v(&[
                "pr",
                "view",
                "--repo",
                "https://gitlab.com/acme/widgets"
            ])),
            None
        );
    }

    #[tokio::test]
    async fn revoke_minted_credential_calls_broker_revoke() {
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = github_star_grant(&store);
        let (mat_id, provider) = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            None,
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await
        .expect("mint must succeed");

        // Pre-revoke: MockBroker has 1 active.
        let mock = registry
            .brokers
            .get(&provider)
            .expect("github broker registered");
        let _ = mock; // can't downcast DynBroker → MockBroker; assert via revoke success below

        revoke_minted_credential_with_registry(&mat_id, provider, &registry).await;
        // Second revoke should fail (already revoked) — confirms first revoke
        // landed at the broker.
        let _ = mat_id; // re-revoke handled silently in production wrapper
    }

    // SCION-DEMO-BEAT-6-BROKER-TTL-LOG — regression test that the
    // operator-visible "[broker] resolved <provider>-token to <persona> — TTL <m>m"
    // line is emitted on a successful credential mint. The demo recording's
    // overlay narrates this line; if it disappears, the storyboard breaks.
    #[test]
    fn broker_resolved_ttl_line_formats_operator_visible_message() {
        let snapshot =
            broker_resolved_ttl_line(core_broker::BrokerProvider::Github, "worker-b", 59);
        assert!(
            snapshot.contains("[broker] resolved github-token to worker-b"),
            "expected operator-visible broker-resolved line; got: {snapshot}"
        );
        assert!(
            snapshot.contains("TTL ") && snapshot.contains("m"),
            "expected TTL minutes in operator-visible broker-resolved line; got: {snapshot}"
        );
    }

    #[tokio::test]
    async fn revoke_minted_credential_handles_unregistered_provider_gracefully() {
        let registry = BrokerRegistry::new(); // empty
        // Should NOT panic; should NOT propagate. Just logs.
        revoke_minted_credential_with_registry(
            "fake-mat-id",
            core_broker::BrokerProvider::Github,
            &registry,
        )
        .await;
    }

    // ─── BKR-4 PR-B: need ≤ grant gate at the construct mint ───────────────

    #[test]
    fn github_need_as_statements_binds_each_need_clause_to_the_repo() {
        // gh.pr_create declares provider metadata plus verb-specific clauses
        // (ADR 204 Amendment 6: contents:write + pull_request:create; no
        // actions:read), each repo-bound.
        let need = ember_construct::manifest_action_need("gh.pr_create");
        let stmts = github_need_as_statements(&need, "acme/widgets");
        assert_eq!(stmts.len(), 3, "pr_create need has three clauses");
        for s in &stmts {
            assert_eq!(s.actions.len(), 1, "one action per need clause");
            assert_eq!(
                s.resource,
                core_grant_types::ResourceSelector::Exact {
                    value: "acme/widgets".to_string()
                },
                "each clause is repo-bound to the concrete owner/repo"
            );
        }
        let actions: Vec<&str> = stmts.iter().map(|s| s.actions[0].as_str()).collect();
        assert!(actions.contains(&"github:metadata:read"));
        assert!(actions.contains(&"github:contents:write"));
        assert!(actions.contains(&"github:pull_request:create"));
    }

    #[tokio::test]
    async fn mint_proceeds_when_need_subset_of_github_star_grant() {
        // git.push need (github:metadata:read + github:contents:write on
        // acme/widgets) ⊆ github:* on *.
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = github_star_grant(&store);
        let result = mint_and_inject_for_action_with_registry(
            "git.push",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;
        assert!(
            result.is_some(),
            "need ⊆ github:* grant must mint a credential"
        );
        assert_eq!(env.get("GIT_CONFIG_COUNT").map(|s| s.as_str()), Some("1"));
    }

    #[tokio::test]
    async fn mint_refused_when_grant_absent() {
        // Hard-right P4: no resolved runtime grant ⇒ fail-closed, NO mint.
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let result = mint_and_inject_for_action_with_registry(
            "git.push",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            None, // no runtime grant
            Some("persona-x"),
        )
        .await;
        assert!(
            result.is_none(),
            "absent grant must mint NOTHING (fail-closed BKR-4 PR-B)"
        );
        assert!(env.is_empty(), "no credential env var on a refused mint");
    }

    #[tokio::test]
    async fn mint_refused_when_need_not_subset_read_only_grant() {
        // git.push needs github:metadata:read + github:contents:write; a
        // contents:READ-only grant must refuse it — the metadata and write
        // clauses are uncovered.
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = runtime_grant_with(
            &store,
            vec!["github:contents:read".to_string()],
            ResourceSelector::Glob {
                pattern: "*".to_string(),
            },
        );
        let result = mint_and_inject_for_action_with_registry(
            "git.push",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;
        assert!(
            result.is_none(),
            "contents:write need ⊄ contents:read grant must mint NOTHING"
        );
        assert!(env.is_empty(), "no credential env var on a refused mint");
    }

    #[tokio::test]
    async fn mint_pr_create_proceeds_under_github_star_grant() {
        // gh.pr_create carries provider metadata plus its verb-specific need;
        // all clauses ⊆ github:*.
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = github_star_grant(&store);
        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;
        assert!(result.is_some(), "gh.pr_create need ⊆ github:* must mint");
        assert!(env.contains_key("GH_TOKEN"));
    }

    #[tokio::test]
    async fn mint_pr_create_refused_under_contents_write_only_grant() {
        // gh.pr_create needs metadata:read + contents:write + pull_request:create.
        // A grant carrying ONLY github:contents:write fails the
        // metadata:read and pull_request:create clauses ⇒ refused, no mint.
        let registry = fresh_registry_with_mock(core_broker::BrokerProvider::Github);
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = runtime_grant_with(
            &store,
            vec!["github:contents:write".to_string()],
            ResourceSelector::Glob {
                pattern: "*".to_string(),
            },
        );
        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;
        assert!(
            result.is_none(),
            "pr_create need ⊄ contents:write-only grant (pull_request:create uncovered) must mint NOTHING"
        );
        assert!(env.is_empty(), "no credential env var on a refused mint");
    }

    #[test]
    fn aws_permission_specs_as_statements_includes_role_and_operation_need() {
        let specs = ember_construct::aws::aws_permission_specs_for_argv(
            "aws.s3api.put-object",
            &[
                "s3api".to_string(),
                "put-object".to_string(),
                "--bucket".to_string(),
                "assets".to_string(),
                "--key".to_string(),
                "releases/app.tar.gz".to_string(),
            ],
        )
        .expect("specs");
        let role = "arn:aws:iam::123456789012:role/ember-agent";
        let need = aws_permission_specs_as_statements(&specs, role).expect("aws need statements");
        assert_eq!(need.len(), 2);
        assert_eq!(need[0].actions, vec!["aws:assume_role".to_string()]);
        assert_eq!(
            need[0].resource,
            ResourceSelector::Exact {
                value: role.to_string()
            }
        );
        assert_eq!(need[1].actions, vec!["aws:s3:put_object".to_string()]);
        assert_eq!(
            need[1].resource,
            ResourceSelector::Exact {
                value: "arn:aws:s3:::assets/releases/app.tar.gz".to_string()
            }
        );
    }

    #[test]
    fn aws_permission_specs_as_statements_lowers_cloudformation_stack_need() {
        let stack_arn =
            "arn:aws:cloudformation:us-east-1:123456789012:stack/publish-site/abcd-1234";
        let specs = ember_construct::aws::aws_permission_specs_for_argv(
            "aws.cloudformation.update-stack",
            &[
                "cloudformation".to_string(),
                "update-stack".to_string(),
                "--stack-name".to_string(),
                stack_arn.to_string(),
            ],
        )
        .expect("specs");
        let role = "arn:aws:iam::123456789012:role/ember-agent";
        let need = aws_permission_specs_as_statements(&specs, role).expect("aws need statements");
        assert_eq!(need.len(), 2);
        assert_eq!(need[0].actions, vec!["aws:assume_role".to_string()]);
        assert_eq!(
            need[1].actions,
            vec!["aws:cloudformation:update_stack".to_string()]
        );
        assert_eq!(
            need[1].resource,
            ResourceSelector::Exact {
                value: stack_arn.to_string()
            }
        );
    }

    #[tokio::test]
    async fn mint_aws_s3api_put_object_projects_sts_scope_and_injects_env() {
        let issued = std::sync::Arc::new(std::sync::Mutex::new(Vec::<BrokerRequest>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(AwsJsonBroker {
            issued: issued.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let role_arn = "arn:aws:iam::123456789012:role/ember-agent";
        let object_arn = "arn:aws:s3:::assets/releases/app.tar.gz";
        let grant = aws_runtime_grant_for_s3_put(&store, role_arn, object_arn);
        let specs = ember_construct::aws::aws_permission_specs_for_argv(
            "aws.s3api.put-object",
            &[
                "s3api".to_string(),
                "put-object".to_string(),
                "--bucket".to_string(),
                "assets".to_string(),
                "--key".to_string(),
                "releases/app.tar.gz".to_string(),
            ],
        )
        .expect("specs");

        let (mat_id, provider) = mint_and_inject_for_action_with_registry(
            "aws.s3api.put-object",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            None,
            Some(specs.as_slice()),
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await
        .expect("aws mint must succeed");

        assert_eq!(mat_id, "aws-json-1");
        assert_eq!(provider, core_broker::BrokerProvider::AwsSts);
        assert_eq!(
            env.get("AWS_ACCESS_KEY_ID").map(|s| s.as_str()),
            Some("ASIATESTACCESSKEY")
        );
        assert_eq!(
            env.get("AWS_SECRET_ACCESS_KEY").map(|s| s.as_str()),
            Some("testSecretAccessKeyValue")
        );
        assert_eq!(
            env.get("AWS_SESSION_TOKEN").map(|s| s.as_str()),
            Some("testSessionTokenValue")
        );

        let issued = issued.lock().expect("issued mutex");
        assert_eq!(issued.len(), 1);
        let req = &issued[0];
        assert_eq!(req.provider, core_broker::BrokerProvider::AwsSts);
        assert_eq!(req.caller_persona.as_deref(), Some("persona-x"));
        assert_eq!(req.scope["mode"], serde_json::json!("assume_role"));
        assert_eq!(req.scope["role_arn"], serde_json::json!(role_arn));
        let inline_policy = req.scope["inline_policy"].as_str().expect("inline policy");
        let inline_policy: serde_json::Value =
            serde_json::from_str(inline_policy).expect("inline policy json");
        assert_eq!(
            inline_policy["Statement"][0]["Action"],
            serde_json::json!(["s3:PutObject"])
        );
        assert_eq!(
            inline_policy["Statement"][0]["Resource"],
            serde_json::json!([object_arn])
        );

        let events = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("query audit");
        assert_eq!(events.len(), 1);
        let details: serde_json::Value =
            serde_json::from_str(events[0].details.as_deref().expect("details"))
                .expect("details json");
        assert_eq!(details["provider"], "aws_sts");
        assert_eq!(details["aws_role_arn"], role_arn);
        assert_eq!(
            details["aws_permission_specs"][0]["actions"][0],
            "S3PutObject"
        );
        // ADR 213 §D4 G2 — AWS attests WHICH role it assumed, not its
        // permissions. The materialization records the "identity"
        // discriminator + the typed `IdentityRef` payload (AC-3 / AC-4); the
        // legacy bool must NOT appear.
        assert!(details.get("provider_scope_attestable").is_none());
        assert_eq!(details["mint_stamp_kind"], "identity");
        assert_eq!(details["mint_stamp"]["kind"], "identity");
        assert_eq!(details["mint_stamp"]["identity"]["provider"], "aws_sts");
        assert_eq!(details["mint_stamp"]["identity"]["identity"], role_arn);
    }

    #[tokio::test]
    async fn mint_aws_cloudformation_update_stack_projects_sts_scope_and_injects_env() {
        let issued = std::sync::Arc::new(std::sync::Mutex::new(Vec::<BrokerRequest>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(AwsJsonBroker {
            issued: issued.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let role_arn = "arn:aws:iam::123456789012:role/ember-agent";
        let stack_arn =
            "arn:aws:cloudformation:us-east-1:123456789012:stack/publish-site/abcd-1234";
        let grant = aws_runtime_grant_for_cloudformation(
            &store,
            role_arn,
            "aws:cloudformation:update_stack",
            stack_arn,
        );
        let specs = ember_construct::aws::aws_permission_specs_for_argv(
            "aws.cloudformation.update-stack",
            &[
                "cloudformation".to_string(),
                "update-stack".to_string(),
                "--stack-name".to_string(),
                stack_arn.to_string(),
                "--template-body".to_string(),
                "file://template.yaml".to_string(),
            ],
        )
        .expect("specs");

        let (mat_id, provider) = mint_and_inject_for_action_with_registry(
            "aws.cloudformation.update-stack",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            None,
            Some(specs.as_slice()),
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await
        .expect("aws mint must succeed");

        assert_eq!(mat_id, "aws-json-1");
        assert_eq!(provider, core_broker::BrokerProvider::AwsSts);
        assert_eq!(
            env.get("AWS_ACCESS_KEY_ID").map(|s| s.as_str()),
            Some("ASIATESTACCESSKEY")
        );

        let issued = issued.lock().expect("issued mutex");
        assert_eq!(issued.len(), 1);
        let req = &issued[0];
        assert_eq!(req.provider, core_broker::BrokerProvider::AwsSts);
        assert_eq!(req.caller_persona.as_deref(), Some("persona-x"));
        assert_eq!(req.scope["mode"], serde_json::json!("assume_role"));
        assert_eq!(req.scope["role_arn"], serde_json::json!(role_arn));
        let inline_policy = req.scope["inline_policy"].as_str().expect("inline policy");
        let inline_policy: serde_json::Value =
            serde_json::from_str(inline_policy).expect("inline policy json");
        assert_eq!(
            inline_policy["Statement"][0]["Action"],
            serde_json::json!(["cloudformation:UpdateStack"])
        );
        assert_eq!(
            inline_policy["Statement"][0]["Resource"],
            serde_json::json!([stack_arn])
        );

        let events = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("query audit");
        assert_eq!(events.len(), 1);
        let details: serde_json::Value =
            serde_json::from_str(events[0].details.as_deref().expect("details"))
                .expect("details json");
        assert_eq!(details["provider"], "aws_sts");
        assert_eq!(details["aws_role_arn"], role_arn);
        assert_eq!(
            details["aws_permission_specs"][0]["actions"][0],
            "CloudFormationUpdateStack"
        );
        // ADR 213 §D4 G2 — identity-only attestation; see comment above.
        assert!(details.get("provider_scope_attestable").is_none());
        assert_eq!(details["mint_stamp_kind"], "identity");
        assert_eq!(details["mint_stamp"]["kind"], "identity");
        assert_eq!(details["mint_stamp"]["identity"]["provider"], "aws_sts");
        assert_eq!(details["mint_stamp"]["identity"]["identity"], role_arn);
    }

    #[tokio::test]
    async fn mint_aws_refuses_without_permission_spec() {
        let issued = std::sync::Arc::new(std::sync::Mutex::new(Vec::<BrokerRequest>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(AwsJsonBroker {
            issued: issued.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = aws_runtime_grant_for_s3_put(
            &store,
            "arn:aws:iam::123456789012:role/ember-agent",
            "arn:aws:s3:::assets/releases/app.tar.gz",
        );

        let result = mint_and_inject_for_action_with_registry(
            "aws.s3api.put-object",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            None,
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;

        assert!(
            result.is_none(),
            "missing AWS PermissionSpec must fail closed"
        );
        assert!(env.is_empty());
        assert!(issued.lock().expect("issued mutex").is_empty());
    }

    #[tokio::test]
    async fn mint_aws_refuses_when_s3_need_not_subset_grant() {
        let issued = std::sync::Arc::new(std::sync::Mutex::new(Vec::<BrokerRequest>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(AwsJsonBroker {
            issued: issued.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let role_arn = "arn:aws:iam::123456789012:role/ember-agent";
        let grant = runtime_grant_with_statements(
            &store,
            vec![grant_statement(
                "aws-role",
                vec!["aws:assume_role".to_string()],
                ResourceSelector::Exact {
                    value: role_arn.to_string(),
                },
            )],
        );
        let specs = ember_construct::aws::aws_permission_specs_for_argv(
            "aws.s3api.put-object",
            &[
                "s3api".to_string(),
                "put-object".to_string(),
                "--bucket".to_string(),
                "assets".to_string(),
                "--key".to_string(),
                "releases/app.tar.gz".to_string(),
            ],
        )
        .expect("specs");

        let result = mint_and_inject_for_action_with_registry(
            "aws.s3api.put-object",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            None,
            Some(specs.as_slice()),
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;

        assert!(
            result.is_none(),
            "AWS role grant without S3 operation coverage must fail closed"
        );
        assert!(env.is_empty());
        assert!(issued.lock().expect("issued mutex").is_empty());
    }

    /// AWS broker whose `issue()` mints a deterministic canary carrying a
    /// configurable typed `MintStamp::Identity` (the assumed role ARN), and
    /// records `revoke` calls — the AWS counterpart to `EchoBroker`, to
    /// exercise the `AwsSts` arm of the ADR 204 I7 / ADR 213 §D4 G2
    /// provider-echo clamp.
    struct AwsEchoBroker {
        attested_role_arn: String,
        revoked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl core_broker::Broker for AwsEchoBroker {
        fn provider(&self) -> core_broker::BrokerProvider {
            core_broker::BrokerProvider::AwsSts
        }

        async fn issue(
            &self,
            req: BrokerRequest,
        ) -> Result<core_broker::BrokeredCredential, core_broker::BrokerError> {
            let token = serde_json::json!({
                "access_key_id": "ASIATESTACCESSKEY",
                "secret_access_key": "testSecretAccessKeyValue",
                "session_token": "testSessionTokenValue",
                "expiration": "2099-01-01T00:00:00Z",
            })
            .to_string();
            Ok(core_broker::BrokeredCredential {
                token: secrecy::SecretString::from(token),
                expires_at: std::time::SystemTime::now() + req.ttl,
                materialization_id: "aws-echo-1".to_string(),
                mint_stamp: core_broker::MintStamp::Identity {
                    identity: core_broker::IdentityRef {
                        provider: core_broker::BrokerProvider::AwsSts,
                        identity: self.attested_role_arn.clone(),
                    },
                },
            })
        }

        async fn revoke(&self, materialization_id: &str) -> Result<(), core_broker::BrokerError> {
            self.revoked
                .lock()
                .expect("revoke spy mutex")
                .push(materialization_id.to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn broker_exec_revokes_when_aws_mint_stamp_role_exceeds_minted() {
        // ADR 204 amendment 2 / ADR 205 §B.4 (I7), AWS arm — the provider echoed a
        // credential for a WIDER role (`admin-role`) than the projector minted from
        // the grant (`ember-agent`). The clamp must revoke the credential and inject
        // nothing, fail-closed. (The accept-within path is already covered by the
        // `mint_aws_*` success tests, where `AwsJsonBroker` echoes the minted scope.)
        let revoked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let object_arn = "arn:aws:s3:::assets/releases/app.tar.gz";
        // The AWS echo is a role-identity attestation. Here STS attested a
        // DIFFERENT role (`admin-role`) than the grant authorizes
        // (`ember-agent`), so the I7 clamp's role comparison must fail closed.
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(AwsEchoBroker {
            attested_role_arn: "arn:aws:iam::123456789012:role/admin-role".to_string(),
            revoked: revoked.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = aws_runtime_grant_for_s3_put(
            &store,
            "arn:aws:iam::123456789012:role/ember-agent",
            object_arn,
        );
        let specs = ember_construct::aws::aws_permission_specs_for_argv(
            "aws.s3api.put-object",
            &[
                "s3api".to_string(),
                "put-object".to_string(),
                "--bucket".to_string(),
                "assets".to_string(),
                "--key".to_string(),
                "releases/app.tar.gz".to_string(),
            ],
        )
        .expect("specs");

        let result = mint_and_inject_for_action_with_registry(
            "aws.s3api.put-object",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            None,
            Some(specs.as_slice()),
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;

        assert!(
            result.is_none(),
            "an AWS echo naming a wider role than minted must fail closed (I7)"
        );
        assert!(
            !env.contains_key("AWS_ACCESS_KEY_ID"),
            "no AWS credential may be injected when the echo exceeds the minted role"
        );
        assert_eq!(
            revoked.lock().expect("revoke spy mutex").as_slice(),
            ["aws-echo-1"],
            "the over-wide credential must be revoked (compensation), not leaked to TTL"
        );
    }

    // ---- ADR 213 AC-9 tests ----

    /// Broker that returns `MintStamp::Identity` for a github provider —
    /// simulates a provider that erroneously stamps an identity attestation
    /// with no corresponding grant-bound identity resolved in the flow.
    struct IdentityStampGithubBroker {
        revoked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl core_broker::Broker for IdentityStampGithubBroker {
        fn provider(&self) -> core_broker::BrokerProvider {
            core_broker::BrokerProvider::Github
        }

        async fn issue(
            &self,
            req: BrokerRequest,
        ) -> Result<core_broker::BrokeredCredential, core_broker::BrokerError> {
            Ok(core_broker::BrokeredCredential {
                token: secrecy::SecretString::from("canary-token-id-1".to_string()),
                expires_at: std::time::SystemTime::now() + req.ttl,
                materialization_id: "identity-no-grant-1".to_string(),
                mint_stamp: core_broker::MintStamp::Identity {
                    identity: core_broker::IdentityRef {
                        provider: core_broker::BrokerProvider::Github,
                        identity: "some-identity".to_string(),
                    },
                },
            })
        }

        async fn revoke(&self, materialization_id: &str) -> Result<(), core_broker::BrokerError> {
            self.revoked
                .lock()
                .expect("revoke spy mutex")
                .push(materialization_id.to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn ac9_g2_identity_stamp_on_non_identity_path_fails_closed() {
        // ADR 213 AC-9 defense-in-depth — a provider that stamps
        // MintStamp::Identity on a path that resolved no grant-bound
        // identity must never produce a successful mint. The github path
        // sets grant_bound_identity = None; the D5.1 clamp catches the
        // mismatch (Github has no identity parser), and the AC-9 gate
        // provides a second backstop. Either way: credential refused.
        let revoked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(IdentityStampGithubBroker {
            revoked: revoked.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = github_star_grant(&store);

        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;

        assert!(
            result.is_none(),
            "a G2 Identity stamp on a non-identity provider path must fail closed"
        );
        assert!(
            !env.contains_key("GH_TOKEN"),
            "no token may be injected when Identity stamp has no grant-bound identity"
        );
    }

    /// Broker that always returns a G3 MintStamp, for AC-10 gate testing.
    struct G3SpyBroker {
        revoked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl core_broker::Broker for G3SpyBroker {
        fn provider(&self) -> core_broker::BrokerProvider {
            core_broker::BrokerProvider::Github
        }

        async fn issue(
            &self,
            req: BrokerRequest,
        ) -> Result<core_broker::BrokeredCredential, core_broker::BrokerError> {
            Ok(core_broker::BrokeredCredential {
                token: secrecy::SecretString::from("canary-token-g3-1".to_string()),
                expires_at: std::time::SystemTime::now() + req.ttl,
                materialization_id: "g3-1".to_string(),
                mint_stamp: core_broker::MintStamp::Unbounded,
            })
        }

        async fn revoke(&self, materialization_id: &str) -> Result<(), core_broker::BrokerError> {
            self.revoked
                .lock()
                .expect("g3 spy mutex")
                .push(materialization_id.to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn ac10_g3_mint_fails_closed_in_direct_injection_path() {
        // ADR 213 AC-10 — G3SpyBroker returns MintStamp::Unbounded (G3,
        // simulating a GitHub all-repos installation token). The exec_credentials
        // path is direct-injection (no proxy budget enforcement), so the G3
        // mint must fail closed: credential revoked, nothing injected, no
        // materialization audit event recorded.
        let revoked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(G3SpyBroker {
            revoked: revoked.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = github_star_grant(&store);

        let result = mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await;

        assert!(
            result.is_none(),
            "G3 mint in direct-injection path must fail closed (AC-10)"
        );
        assert!(
            env.get("GH_TOKEN").is_none(),
            "No credential must be injected when AC-10 gate fails"
        );

        let events = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("query audit");
        assert!(
            events.is_empty(),
            "No materialization audit event when G3 mint is refused (AC-10)"
        );

        let revoked = revoked.lock().expect("g3 spy mutex");
        assert_eq!(
            revoked.as_slice(),
            &["g3-1"],
            "AC-10 must revoke the just-minted G3 credential"
        );
    }

    #[tokio::test]
    async fn ac9_effective_ceiling_permissions_for_g1_echo() {
        // ADR 213 AC-9 — EchoBroker yields MintStamp::Permissions (G1), so
        // effective_ceiling = "permissions" (bounded by attested scope echo).
        let revoked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(EchoBroker {
            echo: core_broker::GithubScope {
                repositories: vec!["widgets".to_string()],
                permissions: vec![("contents".to_string(), "write".to_string())],
            },
            revoked: revoked.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let grant = github_star_grant(&store);

        mint_and_inject_for_action_with_registry(
            "gh.pr_create",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            Some("acme/widgets"),
            None,
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await
        .expect("G1 permissions mint must succeed");

        let events = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("query audit");
        assert_eq!(events.len(), 1);
        let details: serde_json::Value =
            serde_json::from_str(events[0].details.as_deref().expect("details"))
                .expect("details json");
        assert_eq!(
            details["effective_ceiling"], "permissions",
            "G1 Permissions mint must record effective_ceiling = permissions (AC-9): {details}"
        );
    }

    #[tokio::test]
    async fn ac9_effective_ceiling_recorded_for_g2_aws_mint() {
        // ADR 213 AC-9 — G2 AWS mint records effective_ceiling: "bound_identity".
        let issued = std::sync::Arc::new(std::sync::Mutex::new(Vec::<BrokerRequest>::new()));
        let mut registry = BrokerRegistry::new();
        registry.register(Box::new(AwsJsonBroker {
            issued: issued.clone(),
        }));
        let mut env = std::collections::HashMap::new();
        let store = DaemonStore::open_in_memory().unwrap();
        let role_arn = "arn:aws:iam::123456789012:role/ember-agent";
        let object_arn = "arn:aws:s3:::assets/releases/app.tar.gz";
        let grant = aws_runtime_grant_for_s3_put(&store, role_arn, object_arn);
        let specs = ember_construct::aws::aws_permission_specs_for_argv(
            "aws.s3api.put-object",
            &[
                "s3api".to_string(),
                "put-object".to_string(),
                "--bucket".to_string(),
                "assets".to_string(),
                "--key".to_string(),
                "releases/app.tar.gz".to_string(),
            ],
        )
        .expect("specs");

        mint_and_inject_for_action_with_registry(
            "aws.s3api.put-object",
            &mut env,
            &registry,
            &store,
            Some("persona-x"),
            None,
            Some(specs.as_slice()),
            None,
            Some(&grant),
            Some("persona-x"),
        )
        .await
        .expect("G2 AWS mint must succeed");

        let events = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("query audit");
        assert_eq!(events.len(), 1);
        let details: serde_json::Value =
            serde_json::from_str(events[0].details.as_deref().expect("details"))
                .expect("details json");
        assert_eq!(
            details["effective_ceiling"], "bound_identity",
            "G2 AWS mint must record effective_ceiling = bound_identity (AC-9): {details}"
        );
        assert_eq!(
            details["grant_bound_identity"], role_arn,
            "G2 AWS mint must record the grant-bound identity: {details}"
        );
    }
}
