//! Broker execution-contract dispatch and host-direct runner routing.
//!
//! This Module keeps the broker_exec execution contract Interface small at the
//! parent handler while concentrating the authority-space validation and
//! execution-space dispatch implementation in one loadable file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(test)]
use std::sync::Arc;

use chrono::Utc;
use core_broker::BrokerProvider;
use core_event_types::ActionRef;
use core_events::construct_toml::TerminalMode;
use serde_json::Value;

use crate::broker::runners::{RunnerBinarySource, RunnerCwdSource, runner_class_as_str};
use crate::infra::receipt::current_identity;
use crate::infra::rpc_error::RpcError;
use crate::infra::store::DaemonStore;
use crate::session::lifecycle::DaemonPersonaSigner;

use super::exec_admission::admit_broker_exec_contract;
use super::exec_credentials::{
    maybe_seal_credentials_in_env, mint_and_inject_for_action, origin_owner_repo_from_cwd,
    resolve_gh_repo_from_argv, revoke_minted_credential,
};
#[cfg(test)]
use super::exec_policy::append_ephemeral_git_config_entry;
use super::exec_policy::{
    APPROVAL_BINDING_PENDING_TTL_SECS, ConstructExecPolicy, NestedExecutionContractRequirement,
    approval_binding_scope, approval_required_response, capture_text_tail,
    daemon_classification_tool_name, execution_contract_digest, extract_remote_name_daemon_side,
    inject_ephemeral_git_safe_directory, invocation_plan_digest, lookup_binary_in_manifest,
    parse_construct_exec_policy, reject_legacy_broker_exec_fields,
    runner_action_matches_authority_action, sha256_hex_text,
    validate_nested_execution_contract_wire_shape, warn_ignored_execution_contract_mirror_fields,
};
#[cfg(unix)]
use super::pty::forkpty_exec_and_bridge;
use super::pty::{ShimEofOutcome, ShimEofPolicy};
use super::{
    BrokerExecRequest, BrokerExecResponse, DelegationEvalOutcome, PendingSpawnHandle,
    check_grants_schema_version_for_persona, check_peer_binary_pinned,
    check_principal_against_persona, check_principal_enrollment_strict, check_principal_is_alive,
    check_principal_namespace_inodes, classify_argv_daemon_side, current_registry,
    eval_workflow_for_action, log_legacy_socket_resolution, resolve_workflow_strict_mode,
};

/// Best-effort caller for the `exec.completion` Receipt v2 emission path.
///
/// This helper stays with broker_exec because it belongs to execution dispatch,
/// not to the broker issue/revoke materialization lifecycle.
fn emit_scion_exec_completion_receipt(
    store: &DaemonStore,
    params: &Value,
    binary_path: PathBuf,
    binary_blake3: String,
    target_uid: u32,
    exit_code: i32,
) {
    use uuid::Uuid;

    let persona_str = params
        .get("caller_persona")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let persona_id = Uuid::parse_str(persona_str).unwrap_or_else(|_| Uuid::nil());

    let grant_id: Uuid = if persona_id == Uuid::nil() {
        Uuid::nil()
    } else {
        match store.list_active_grants() {
            Ok(grants) => grants
                .into_iter()
                .find(|g| g.persona_id == persona_str && g.status == "active")
                .and_then(|g| Uuid::parse_str(&g.id).ok())
                .unwrap_or_else(Uuid::nil),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "exec.completion: list_active_grants failed; emitting receipt with nil grant_id"
                );
                Uuid::nil()
            }
        }
    };

    let identity = match current_identity() {
        Some(i) => i,
        None => {
            tracing::warn!(
                "exec.completion: daemon identity not initialised - skipping receipt emission"
            );
            return;
        }
    };
    let signer = DaemonPersonaSigner::new(identity);
    let materialized_at = chrono::Utc::now();

    let envelope = match crate::spawn::scion::emit_exec_completion_receipt(
        persona_id,
        grant_id,
        binary_path.clone(),
        binary_blake3,
        target_uid,
        exit_code,
        materialized_at,
        &signer,
    ) {
        Ok(env) => env,
        Err(e) => {
            tracing::warn!(
                error = %e,
                binary_path = %binary_path.display(),
                target_uid,
                exit_code,
                "exec.completion: sign_receipt_v2 failed; receipt not persisted"
            );
            return;
        }
    };

    let envelope_json = match serde_json::to_string(&envelope) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "exec.completion: envelope serialize failed; receipt not persisted"
            );
            return;
        }
    };
    if let Err(e) = store.log_event(
        Some(persona_str),
        "exec.completion",
        None,
        if exit_code == 0 { "success" } else { "errored" },
        Some(&envelope_json),
    ) {
        tracing::warn!(
            error = %e,
            receipt_id = %envelope.receipt_id,
            "exec.completion: failed to persist receipt audit-log row"
        );
    }
}

/// Refuse commits/pushes/PR-opens that mutate `.classification` files
/// under bot identity. Returns `Some(file_list)` listing the offending
/// `.classification` paths when the action would author such a change;
/// `None` for read-only verbs or actions whose diff doesn't touch
/// `.classification`. The daemon's `handle_broker_exec` aborts the
/// invocation when this returns `Some`.
///
/// action keys:
///
/// - `git.commit`: `git diff --staged --name-only` → match `.classification$`
/// - `git.push` / `gh.pr_create`: `git log --name-only --pretty=format: origin/main..HEAD`
///
/// Other actions return `None` immediately so read-only verbs (status,
/// log, diff) don't pay the check cost.
pub(super) fn check_classification_refusal(action_key: &str, cwd: &str) -> Option<Vec<String>> {
    let (cmd_args, kind): (&[&str], &str) = match action_key {
        "git.commit" => (&["diff", "--staged", "--name-only"], "staged"),
        "git.push" | "gh.pr_create" => (
            &[
                "log",
                "--name-only",
                "--pretty=format:",
                "origin/main..HEAD",
            ],
            "ahead",
        ),
        _ => return None,
    };

    let output = std::process::Command::new("git")
        .args(cmd_args)
        .current_dir(cwd)
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        Ok(_) | Err(_) => {
            // Couldn't run git here — could be a fresh repo without
            // origin/main, a non-git cwd, or a transient error. Don't
            // refuse on inability to verify; surface a debug-level
            // tracing event so the operator can investigate if needed.
            tracing::debug!(
                action = %action_key,
                cwd = %cwd,
                kind = kind,
                "broker_exec: classification refusal check skipped — git query did not succeed"
            );
            return None;
        }
    };

    let touched: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| {
            // Match either `.classification` at root or `<dir>/.classification`.
            *l == ".classification" || l.ends_with("/.classification")
        })
        .map(|l| l.to_string())
        .collect();

    if touched.is_empty() {
        None
    } else {
        Some(touched)
    }
}

pub(super) fn allocate_broker_exec_home() -> std::io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("emberd-exec-home-");

    #[cfg(target_os = "macos")]
    {
        // The installed launchd sandbox only allows writes under
        // `/tmp/emberd-*` and `/private/tmp/emberd-*`. Using the ambient
        // `std::env::temp_dir()` resolves to `/var/folders/.../T` under
        // launchd, which causes broker_exec to fail before the child runs.
        builder.tempdir_in("/tmp")
    }

    #[cfg(not(target_os = "macos"))]
    {
        builder.tempdir()
    }
}

//
// All host-direct broker_exec spawn paths drop to a per-spawn uid
// from the configured pool before execve. See `broker/uid_alloc.rs`
// for the pool primitives; see ADR 167 (amendment to ADR 131) for
// the allocation-strategy rationale.
//
// Refusal codes — chosen distinct from the existing -32010
// (ERR_GRANT_SCHEMA_VERSION_MISMATCH, line ~1769) and -32011
// (ERR_NO_REGISTRY / classification refusal / BrokerError::Upstream).
//
//   -32020 — retryable pool exhausted, or Finding 14 target_uid == daemon_uid
//            refused before spawn
//   -32021 — pool not configured / empty (install required)
//   -32030 — construct hash mismatch (clone3-spawn pre-execve verify)
//   -32031 — PTY + subuid combo refused (ADR 155 Path A does not yet
//            route PTY constructs through the user-namespace primitive
//            because forkpty's `setresuid` runs on the host side which
//            requires CAP_SETUID; tracked under
//            a follow-up scope)
//   -32033 — broker_exec ssh_agent=true refused until the ADR 214 brokered SSH
//            host-client / forwarder delivery exists. The old raw-agent fallback
//            bypassed the SshAgentBridge lease gate + per-sign audit. It cannot
//            be pointed at the existing bridge: a host-direct broker_exec child
//            runs as a per-spawn pool uid (Finding-14 / -32020 refuses the
//            daemon's own uid, anti `/proc/<pid>/environ` cred-leak), so it
//            cannot open the daemon-uid `0600` bridge socket. Re-home (per #5762
//            + ADR 215's per-issuee gate framework) = a brokered host-client
//            forwarder SIDECAR: the child connects to a per-spawn child-owned
//            local UDS, the sidecar forwards to the daemon-owned bridge, and
//            teardown ties to the uid lease / session close (the host analog of
//            the F2 container forwarder). Do NOT weaken the bridge's peer-uid
//            check to admit arbitrary children; the target-uid bridge-socket
//            alternative needs explicit operator security signoff. Fail closed
//            loudly until the sidecar exists.
//
// The SCION dispatch path (`scion_exec_socket = Some(_)`) bypasses
// the local pool: the receiver-side ember-exec runtime owns its
// own privilege drop via `ember_exec::spawn::drop_privileges`.

const ERR_BROKER_EXEC_SSH_AGENT_FORWARDER_UNAVAILABLE: i32 = -32033;
const EMPIRICAL_BROKER_EXEC_COHORT: &str = "dev0";

static BROKER_EXEC_INFLIGHT: AtomicU32 = AtomicU32::new(0);

struct BrokerExecInflightSampleGuard;

impl BrokerExecInflightSampleGuard {
    fn enter() -> Self {
        let concurrent = BROKER_EXEC_INFLIGHT
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        crate::telemetry::measurement::record_inflight_sample(
            EMPIRICAL_BROKER_EXEC_COHORT,
            concurrent,
        );
        Self
    }
}

impl Drop for BrokerExecInflightSampleGuard {
    fn drop(&mut self) {
        BROKER_EXEC_INFLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
pub(super) fn reset_broker_exec_inflight_for_test() {
    BROKER_EXEC_INFLIGHT.store(0, Ordering::Release);
}

fn broker_exec_ssh_agent_forwarder_unavailable() -> (i32, String) {
    (
        ERR_BROKER_EXEC_SSH_AGENT_FORWARDER_UNAVAILABLE,
        "broker_exec ssh_agent=true is disabled until the ADR 214 brokered SSH host-client/forwarder is wired; refusing to spawn the legacy raw ssh-agent because it is not lease-gated or per-sign audited"
            .to_string(),
    )
}

/// Resolve a per-spawn uid lease for the host-direct broker_exec
/// path. Returns the lease (Drop returns the uid to the pool when
/// the spawn completes) or the JSON-RPC error tuple the handler
/// should propagate.
///
/// Refusal contracts:
/// - `-32021 (pool not configured)` — the global pool was not
///   installed at startup (no `[spawn_pool]` in config.toml).
///   Operator action: run `sudo ember daemon install` (or rerun with
///   `--upgrade`) to provision the pool, then restart the daemon.
/// - `-32020 (pool exhausted)` — every uid is currently in use.
///   Caller action: honor the structured `retry_after_ms` hint and retry
///   with bounded backoff; operators can also raise `[spawn_pool] uids`.
/// - `-32020 (Finding 14)` — the allocated uid equals the daemon's
///   own uid. Refusal before fork because spawning as the daemon
///   uid would leak credentials via `/proc/<pid>/environ` (Finding
///   14 from the cycle-32 adversarial review).
///
/// Test pools (installed via `uid_alloc::init_uid_pool_for_test`)
/// carry a `test_mode` flag that skips the Finding-14 refusal —
/// production pools never set this flag.
fn resolve_broker_exec_uid_lease(
    spawn_binary: &str,
) -> Result<crate::broker::uid_alloc::UidLease, (i32, String)> {
    use crate::broker::uid_alloc;

    let pool = uid_alloc::global_pool().ok_or((
        -32021,
        "spawn pool not configured — `ember daemon install` must provision the uid pool \
         (META-BROKER-EXEC-PER-SPAWN-UID)"
            .to_string(),
    ))?;

    // Use the binary path + a fresh UUID as the spawn id so concurrent
    // calls (even for the same binary) get unique pool slots. The
    // BrokerExecRequest does not carry a materialization id at the
    // request shape; a UUID is the safest unique key.
    let spawn_id = format!(
        "{}:{}",
        std::path::Path::new(spawn_binary)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<unknown>".to_string()),
        uuid::Uuid::new_v4()
    );

    let lease = pool.checkout(&spawn_id).map_err(|e| match e {
        uid_alloc::UidAllocError::PoolEmpty => (
            -32021,
            format!("spawn pool unavailable: {e} (META-BROKER-EXEC-PER-SPAWN-UID)"),
        ),
        uid_alloc::UidAllocError::PoolExhausted { .. } => RpcError::PoolExhausted {
            retry_after_ms: 100,
        }
        .into(),
        uid_alloc::UidAllocError::AlreadyCheckedOut(_) => {
            (-32603, format!("spawn pool internal error: {e}"))
        }
    })?;

    // Finding 14: refuse to spawn the child as the daemon's own uid.
    // The pool allocator returns a real separate uid in production;
    // a misconfigured pool that contains the daemon's uid would
    // silently re-introduce the env-leak side-channel. Test pools
    // bypass this gate via the `test_mode` flag because the test
    // harness must spawn as the test process's uid (no root, no
    // separate-uid provisioning).
    #[cfg(unix)]
    {
        let daemon_uid = nix::unistd::geteuid().as_raw();
        if lease.uid() == daemon_uid && !pool.is_test_mode() {
            // Lease drops here, returning the uid to the pool.
            return Err((
                -32020,
                format!(
                    "refusing to spawn child as daemon uid (Finding 14): \
                     pool allocated uid {} but daemon runs as uid {} — \
                     fix `[spawn_pool] uids = [...]` in config.toml \
                     (META-BROKER-EXEC-PER-SPAWN-UID)",
                    lease.uid(),
                    daemon_uid
                ),
            ));
        }
    }

    Ok(lease)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostDirectNonPtySpawnRoute {
    SpawnHelper,
    ExecDomainSubuid,
    DirectSetuid,
}

fn select_host_direct_non_pty_spawn_route(
    spawn_lease: Option<&crate::broker::uid_alloc::UidLease>,
) -> HostDirectNonPtySpawnRoute {
    #[cfg(unix)]
    if let Some(lease) = spawn_lease {
        let current_uid = nix::unistd::geteuid().as_raw();
        let current_gid = nix::unistd::getegid().as_raw();
        if lease.uid() == current_uid && lease.gid() == current_gid {
            return HostDirectNonPtySpawnRoute::DirectSetuid;
        }
    }

    if cfg!(target_os = "linux") && spawn_lease.is_some_and(|lease| lease.is_subuid()) {
        HostDirectNonPtySpawnRoute::ExecDomainSubuid
    } else if spawn_lease.is_some() && crate::broker::spawn_helper_client::should_use_spawn_helper()
    {
        HostDirectNonPtySpawnRoute::SpawnHelper
    } else {
        HostDirectNonPtySpawnRoute::DirectSetuid
    }
}

fn build_spawn_helper_directive(
    req: &BrokerExecRequest,
    binary: &str,
    env: &HashMap<String, String>,
    cwd: &str,
    spawn_lease: &crate::broker::uid_alloc::UidLease,
) -> Result<ember_spawn_helper::SpawnDirective, (i32, String)> {
    let binary_path = PathBuf::from(binary);
    let content_hash_blake3 =
        ember_spawn_helper::hash::blake3_hex_of_file(&binary_path).map_err(|e| {
            (
                -32000,
                format!(
                    "spawn-helper hash read failed for {}: {e}",
                    binary_path.display()
                ),
            )
        })?;

    let mut argv = Vec::with_capacity(req.argv.len() + 1);
    argv.push(binary.to_string());
    argv.extend(req.argv.iter().cloned());

    let mut env_pairs: Vec<(String, String)> =
        env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    env_pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    Ok(ember_spawn_helper::SpawnDirective {
        protocol_version: ember_spawn_helper::WIRE_VERSION,
        binary_path,
        argv,
        env: env_pairs,
        cwd: PathBuf::from(cwd),
        target_uid: spawn_lease.uid(),
        target_gid: spawn_lease.gid(),
        content_hash_blake3,
        chroot_dir: None,
        sandbox_profile: None,
        seccomp_filter: None,
        invocation_id: None,
    })
}

fn map_spawn_helper_error(
    err: crate::broker::spawn_helper_client::SpawnHelperError,
) -> (i32, String) {
    use crate::broker::spawn_helper_client::SpawnHelperError;

    match err {
        SpawnHelperError::Connect { .. }
        | SpawnHelperError::NoReply
        | SpawnHelperError::Timeout { .. } => (
            -32021,
            format!(
                "spawn-helper unavailable: {err}; re-run `sudo ember daemon install` and restart the daemon"
            ),
        ),
        SpawnHelperError::HashMismatch { .. } => {
            (-32030, format!("construct_hash_mismatch: {err}"))
        }
        SpawnHelperError::ShimHashMismatch { detail } => (
            -32032,
            detail
                .map(|d| format!("spawn-helper shim hash mismatch: {d}"))
                .unwrap_or_else(|| "spawn-helper shim hash mismatch".to_string()),
        ),
        SpawnHelperError::Refused { reason, detail } => (
            -32000,
            match detail {
                Some(detail) if !detail.is_empty() => {
                    format!("spawn-helper refused {reason}: {detail}")
                }
                _ => format!("spawn-helper refused {reason}"),
            },
        ),
        SpawnHelperError::Frame(_)
        | SpawnHelperError::UnexpectedFrame(_)
        | SpawnHelperError::UnsupportedPlatform => {
            (-32000, format!("spawn-helper protocol error: {err}"))
        }
    }
}

async fn spawn_host_direct_via_spawn_helper(
    req: &BrokerExecRequest,
    binary: &str,
    env: &HashMap<String, String>,
    cwd: &str,
    spawn_lease: &crate::broker::uid_alloc::UidLease,
) -> Result<(i32, String, String), (i32, String)> {
    let directive = build_spawn_helper_directive(req, binary, env, cwd, spawn_lease)?;
    let socket_path = crate::broker::spawn_helper_client::default_socket_path();
    let (exit_code, stdout_tail, stderr_tail) =
        crate::broker::spawn_helper_client::send_spawn_directive(&socket_path, directive, None)
            .await
            .map_err(map_spawn_helper_error)?;
    Ok((exit_code, stdout_tail, stderr_tail))
}

#[cfg(test)]
mod host_direct_non_pty_route_tests {
    use super::*;

    fn sample_broker_exec_request() -> BrokerExecRequest {
        BrokerExecRequest {
            execution_contract: None,
            argv: vec![
                "pr".to_string(),
                "list".to_string(),
                "--limit".to_string(),
                "1".to_string(),
            ],
            env_passthrough: vec![],
            pty_socket_path: None,
            ssh_agent: false,
            on_shim_eof: None,
            claimed_action: None,
            contract_id: None,
            action_ref: None,
            workspace_ref: None,
            cwd: None,
            caller_ref: None,
            authority_ref: None,
            action_env_allowlist: None,
            construct_toml_bytes: None,
            scion_exec_socket: None,
            scion_target_uid: 0,
            scion_target_gid: 0,
            secret_ref: None,
            session_id: None,
        }
    }

    #[test]
    fn build_spawn_helper_directive_preserves_cwd_and_binary_argv0() {
        let binary = std::env::current_exe()
            .expect("current_exe")
            .to_string_lossy()
            .into_owned();
        let req = sample_broker_exec_request();
        let pool = Arc::new(crate::broker::uid_alloc::UidPool::new(vec![10010], 10010));
        let lease = pool
            .checkout("spawn-helper-directive-test")
            .expect("checkout");
        let env = HashMap::from([
            ("HOME".to_string(), "/tmp/emberd-home".to_string()),
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ]);

        let directive =
            build_spawn_helper_directive(&req, &binary, &env, "/tmp/emberlink-worktree", &lease)
                .expect("directive");

        assert_eq!(directive.cwd, PathBuf::from("/tmp/emberlink-worktree"));
        assert_eq!(directive.argv[0], binary);
        assert_eq!(directive.argv[1], "pr");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_system_user_leases_route_via_spawn_helper() {
        let pool = Arc::new(crate::broker::uid_alloc::UidPool::new(vec![10010], 10010));
        let lease = pool.checkout("macos-helper-route").expect("checkout");

        assert_eq!(
            select_host_direct_non_pty_spawn_route(Some(&lease)),
            HostDirectNonPtySpawnRoute::SpawnHelper
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_subuid_leases_route_via_execution_domain() {
        let pool = Arc::new(crate::broker::uid_alloc::UidPool::new_subuid(
            vec![100000],
            100000,
        ));
        let lease = pool.checkout("linux-subuid-route").expect("checkout");

        assert_eq!(
            select_host_direct_non_pty_spawn_route(Some(&lease)),
            HostDirectNonPtySpawnRoute::ExecDomainSubuid
        );
    }

    #[test]
    fn daemon_classification_tool_name_falls_back_to_known_binary_basename() {
        let tool = daemon_classification_tool_name("/opt/homebrew/bin/gh", None);
        assert_eq!(tool.as_deref(), Some("gh"));

        let action = tool.as_deref().and_then(|tool_name| {
            classify_argv_daemon_side(tool_name, &sample_broker_exec_request().argv)
        });
        assert_eq!(action.as_deref(), Some("gh.pr_list"));
    }

    #[test]
    fn daemon_classification_tool_name_prefers_manifest_lookup_when_present() {
        let manifest_lookup = Some(("ember-gh".to_string(), "did:emberlink".to_string()));
        let tool =
            daemon_classification_tool_name("/opt/homebrew/bin/gh", manifest_lookup.as_ref());
        assert_eq!(tool.as_deref(), Some("ember-gh"));
    }

    #[test]
    fn ssh_agent_request_refusal_names_retired_raw_path() {
        let (code, message) = broker_exec_ssh_agent_forwarder_unavailable();

        assert_eq!(code, -32033);
        assert!(message.contains("ADR 214 brokered SSH host-client/forwarder"));
        assert!(message.contains("legacy raw ssh-agent"));
        assert!(message.contains("not lease-gated or per-sign audited"));
    }

    #[test]
    fn current_identity_leases_stay_on_direct_route() {
        let current_uid = nix::unistd::geteuid().as_raw();
        let current_gid = nix::unistd::getegid().as_raw();
        let pool = Arc::new(crate::broker::uid_alloc::UidPool::new(
            vec![current_uid],
            current_gid,
        ));
        let lease = pool.checkout("current-identity-route").expect("checkout");

        assert_eq!(
            select_host_direct_non_pty_spawn_route(Some(&lease)),
            HostDirectNonPtySpawnRoute::DirectSetuid
        );
    }

    #[test]
    fn append_ephemeral_git_config_entry_initializes_count_and_pair() {
        let mut env = HashMap::new();
        append_ephemeral_git_config_entry(&mut env, "safe.directory", "*");
        assert_eq!(env.get("GIT_CONFIG_COUNT").map(|v| v.as_str()), Some("1"));
        assert_eq!(
            env.get("GIT_CONFIG_KEY_0").map(|v| v.as_str()),
            Some("safe.directory")
        );
        assert_eq!(env.get("GIT_CONFIG_VALUE_0").map(|v| v.as_str()), Some("*"));
    }

    #[test]
    fn inject_ephemeral_git_safe_directory_appends_after_git_rewrite_entries() {
        let mut env = HashMap::new();
        env.insert("GIT_CONFIG_COUNT".to_string(), "1".to_string());
        let existing_rewrite_key = format!(
            "url.https://x-access-token:{}@github.com/.insteadOf",
            "ghs_secret_value"
        );
        env.insert("GIT_CONFIG_KEY_0".to_string(), existing_rewrite_key);
        env.insert(
            "GIT_CONFIG_VALUE_0".to_string(),
            "https://github.com/".to_string(),
        );

        inject_ephemeral_git_safe_directory(&mut env, "/opt/homebrew/bin/git");

        assert_eq!(env.get("GIT_CONFIG_COUNT").map(|v| v.as_str()), Some("2"));
        assert_eq!(
            env.get("GIT_CONFIG_KEY_1").map(|v| v.as_str()),
            Some("safe.directory")
        );
        assert_eq!(env.get("GIT_CONFIG_VALUE_1").map(|v| v.as_str()), Some("*"));
    }

    #[test]
    fn inject_ephemeral_git_safe_directory_skips_non_git_binaries() {
        let mut env = HashMap::new();
        inject_ephemeral_git_safe_directory(&mut env, "/usr/local/bin/kubectl");
        assert!(
            env.is_empty(),
            "non git-family tools must not get safe.directory"
        );
    }
}

/// Handle the `broker_exec` socket RPC.
///
/// Spawns the Construct binary as the daemon's child, captures exit code,
/// emits a `session.construct_invocation` Receipt. Per ADR 124 §"daemon-
/// as-process-supervisor".
///
/// When `pty_socket_path` is set in the request the daemon allocates a pty
/// pair via `forkpty(3)`, attaches the slave fd to the child's
/// stdin/stdout/stderr, and calls `pty_bridge_run` with the master fd and
/// the agent's UDS path. The non-PTY (piped stderr) path is preserved for
/// callers that omit `pty_socket_path`.
///
/// Strict env allowlist (PATH, HOME, USER, LANG, TERM + caller-supplied
/// `env_passthrough` filtered through validation). Argv is taken
/// verbatim — daemon-side argv re-classification is a follow-up
/// that can ride atop this scaffold.
///
/// Peercred principal-binding: when `principal` is
/// supplied, the kernel-attested uid is compared against the uid
/// ADR 213 AC-7: Construct publisher-trust signature verification gate.
///
/// Checks for a `.sig` sidecar alongside `resolved_binary`. When
/// present, reads the sidecar + binary + construct_toml, loads active
/// publisher-trust delegations, and runs the full verification
/// pipeline. Fail-closed on any error.
///
/// When no sidecar exists the gate is a no-op (transitional: bundled
/// first-party binaries may not ship sidecars yet).
///
/// BOSCO F6 (deferred): sidecar `name`/`version` are not yet bound to
/// the manifest-resolved construct identity. The blake3 pin over
/// binary+toml prevents cross-construct sidecar reuse when binaries
/// differ; full name binding requires the manifest entry to carry the
/// sidecar-facing construct name (currently only tool_name/publisher).
///
///   -32040 — sidecar present but verification failed
///   -32041 — sidecar present but construct_toml_bytes absent
fn verify_construct_sidecar(
    resolved_binary: &str,
    construct_toml_text: Option<&str>,
    store: &DaemonStore,
) -> Result<(), (i32, String)> {
    let sig_path = format!("{resolved_binary}.sig");
    if !std::path::Path::new(&sig_path).exists() {
        return Ok(());
    }

    let toml_bytes = construct_toml_text.map(|t| t.as_bytes()).ok_or((
        -32041,
        format!(
            "construct_signature_verification: sidecar present at {sig_path} \
                 but construct_toml_bytes absent in request"
        ),
    ))?;

    let sidecar_json = std::fs::read_to_string(&sig_path).map_err(|e| {
        (
            -32040,
            format!("construct_signature_verification: sidecar read failed: {sig_path}: {e}"),
        )
    })?;
    let sidecar: crate::signature_verifier::SidecarEnvelope = serde_json::from_str(&sidecar_json)
        .map_err(|e| {
        (
            -32040,
            format!("construct_signature_verification: sidecar parse failed: {sig_path}: {e}"),
        )
    })?;

    let binary_path = std::path::Path::new(resolved_binary);
    let blake3_hex = {
        let meta = std::fs::metadata(binary_path).map_err(|e| {
            (
                -32040,
                format!(
                    "construct_signature_verification: binary stat failed: {resolved_binary}: {e}"
                ),
            )
        })?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let file_size = meta.len();

        let cache = crate::signature_verifier::verifier_cache();
        if let Some(cached) = cache.get(binary_path, mtime, file_size) {
            cached
        } else {
            let binary_bytes = std::fs::read(binary_path).map_err(|e| {
                (
                    -32040,
                    format!("construct_signature_verification: binary read failed: {resolved_binary}: {e}"),
                )
            })?;
            let hex = crate::signature_verifier::compute_blake3_hex(&binary_bytes, toml_bytes);
            cache.insert(binary_path.to_path_buf(), mtime, file_size, hex.clone());
            hex
        }
    };

    crate::signature_verifier::verify_construct_signature(&sidecar, &blake3_hex, store)
        .map_err(|e| (-32040, format!("construct_signature_verification: {e}")))
}

fn calling_shim_from_action_ref(action_ref: &ActionRef) -> Option<String> {
    action_ref
        .plugin_address
        .rsplit('/')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn wrapped_binary_from_construct_manifest(text: &str) -> Result<String, (i32, String)> {
    let parsed = core_events::construct_toml::parse_action_manifest(text)
        .map_err(|e| (-32009, format!("construct manifest schema invalid: {e}")))?;
    let wrapped = parsed
        .manifest
        .runtime
        .cli
        .as_ref()
        .map(|cli| cli.wrapped_binary.trim())
        .filter(|value| !value.is_empty())
        .ok_or((
            -32009,
            "construct manifest missing [runtime.cli].wrapped_binary".to_string(),
        ))?;
    Ok(wrapped.to_string())
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn resolve_wrapped_binary_path(wrapped_binary: &str) -> Result<String, (i32, String)> {
    let wrapped = wrapped_binary.trim();
    if wrapped.is_empty() {
        return Err((-32009, "wrapped_binary must not be empty".to_string()));
    }

    let path = Path::new(wrapped);
    if path.is_absolute() {
        return if is_executable_file(path) {
            Ok(path.to_string_lossy().into_owned())
        } else {
            Err((
                -32024,
                format!("wrapped_binary {wrapped} is not an executable file"),
            ))
        };
    }
    if wrapped.contains('/') {
        return Err((
            -32009,
            format!("wrapped_binary {wrapped:?} must be absolute or a bare command name"),
        ));
    }

    let mut dirs: Vec<PathBuf> = [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/opt/local/bin",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if let Some(path_var) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path_var).filter(|dir| {
            let path = dir.to_string_lossy();
            !path.contains("/.ember/shadow/bin") && !path.ends_with("/.ember/shadow/bin")
        }));
    }

    for dir in dirs {
        let candidate = dir.join(wrapped);
        if is_executable_file(&candidate) {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }

    Err((
        -32024,
        format!("wrapped_binary {wrapped:?} was not found on daemon search path"),
    ))
}

/// bound to the payload's `caller_persona` field — same gate shape
/// as `handle_broker_issue`. A mismatch is refused with `-32004`
/// before the daemon spawns any child process.
///
/// Per-spawn uid drop: every host-direct spawn path
/// (PTY + non-PTY) drops privileges into a per-spawn uid checked
/// out from the configured pool before execve. See
/// [`resolve_broker_exec_uid_lease`] for the refusal contracts
/// (`-32020` retryable pool exhausted / Finding 14, `-32021` pool not
/// configured / empty).
///
/// // PTY_BRIDGE_INTEGRATED
pub async fn handle_broker_exec(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    handle_broker_exec_with_sessions(principal, store, None, params).await
}

pub async fn handle_broker_exec_with_sessions(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    sessions_dir: Option<&std::path::Path>,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let overlaid_params;
    let resolved_attachment_authority;
    let params = if let Some((attachment_id, endpoint_token)) =
        crate::infra::attachment::attachment_endpoint_from_params(params)
    {
        let sessions_dir = sessions_dir.ok_or((
            -32000,
            "broker_exec: sessions_dir is required for attachment authority resolution".to_string(),
        ))?;
        resolved_attachment_authority = Some(
            crate::infra::attachment::resolve_attachment_authority(
                sessions_dir,
                attachment_id,
                endpoint_token,
            )
            .await?,
        );
        overlaid_params = crate::infra::attachment::overlay_broker_attachment_authority(
            params,
            resolved_attachment_authority
                .as_ref()
                .expect("attachment authority present"),
        )?;
        &overlaid_params
    } else {
        resolved_attachment_authority = None;
        params
    };

    check_grants_schema_version_for_persona(store, params, "caller_persona")?;
    check_principal_is_alive(principal)?;
    check_principal_namespace_inodes(principal, store)?;
    check_peer_binary_pinned(principal)?;
    log_legacy_socket_resolution(principal, store, params, "caller_persona", "broker_exec");
    check_principal_against_persona(principal, store, params, "caller_persona")?;
    check_principal_enrollment_strict(principal, store, params, "caller_persona")?;
    reject_legacy_broker_exec_fields(params)?;
    validate_nested_execution_contract_wire_shape(
        params,
        "broker_exec",
        NestedExecutionContractRequirement::Required,
    )?;
    warn_ignored_execution_contract_mirror_fields(params, "broker_exec");
    // PTY_BRIDGE_INTEGRATED
    let req: BrokerExecRequest = serde_json::from_value(params.clone())
        .map_err(|e| (-32602, format!("invalid broker_exec params: {e}")))?;
    if req.ssh_agent {
        return Err(broker_exec_ssh_agent_forwarder_unavailable());
    }
    // BKR-4 PR-B: capture the resolved live attachment authority (it carries
    // the runtime persona's `grant_id`) so the credential mint below can gate
    // `need ⊆ grant`. Previously this resolution ran only as a liveness/persona
    // check and its result was discarded.
    let mut live_attachment_authority: Option<
        crate::infra::handlers::session::LiveAttachmentAuthority,
    > = None;
    if let (Some(sessions_dir), Some(session_id)) = (sessions_dir, req.session_id.as_deref()) {
        let request_persona = params
            .get("caller_persona")
            .and_then(|value| value.as_str());
        live_attachment_authority = Some(
            crate::infra::handlers::session::resolve_live_attachment_authority(
                sessions_dir,
                session_id,
                request_persona,
            )
            .await
            .map_err(|e| e.into_rpc_error("broker_exec"))?,
        );
    }

    // spawn_handle_ttl gate — close replay window.
    // When the request carries a `secret_ref` (SCION shim resolve path), look
    // up the pending spawn handle and refuse if the 30-second TTL has elapsed.
    // Legacy / non-SCION exec paths omit `secret_ref` and skip this gate.
    let mut pending_spawn_handle: Option<PendingSpawnHandle> = None;
    if let Some(ref mat_id) = req.secret_ref
        && let Some(registry) = current_registry()
    {
        if let Some(handle) = registry.peek_spawn_handle(mat_id) {
            if chrono::Utc::now() > handle.not_after {
                tracing::info!(
                    target: "audit",
                    spawn_handle_id = ?handle.handle_id,
                    not_after = ?handle.not_after,
                    "spawn handle exec refused: SpawnHandleExpired"
                );
                return Err((-32002, "SpawnHandleExpired".to_string()));
            }
            if let Err(err) = handle.validate_bound_pidfd(principal) {
                tracing::warn!(
                    target: "audit",
                    spawn_handle_id = ?handle.handle_id,
                    reason = %err.reason,
                    "spawn handle exec refused: SpawnHandlePidfdInvalidated"
                );
                return Err(err.into_rpc_error());
            }
            pending_spawn_handle = Some(handle.clone());
            tracing::info!(
                target: "audit",
                spawn_handle_id = ?handle.handle_id,
                not_after = ?handle.not_after,
                "spawn handle exec preflight"
            );
        } else {
            // spawn_handle_single_use gate — close replay attack.
            // consume_spawn_handle returned None: the handle is not in pending_spawn_handles.
            // If it appears in consumed_recent (consumed within last 60s), this is a replay
            // attempt — return SpawnHandleAlreadyConsumed to distinguish from an unknown handle.
            if registry.was_recently_consumed(mat_id) {
                tracing::info!(
                    target: "audit",
                    spawn_handle_id = %mat_id,
                    "spawn handle exec refused: SpawnHandleAlreadyConsumed"
                );
                return Err((-32003, "SpawnHandleAlreadyConsumed".to_string()));
            }
            // Handle was never issued via the shim path or has aged out of consumed_recent —
            // no TTL gate applies (legacy credential path).
        }
    }

    let admission = admit_broker_exec_contract(
        &req,
        pending_spawn_handle.as_ref(),
        resolved_attachment_authority.as_ref(),
    )?;
    let execution_contract = Some(admission.execution_contract);
    let contract_id = admission.contract_id;
    let action_ref = admission.action_ref;
    let workspace_ref = admission.workspace_ref;
    let subject_ref = admission.subject_ref;
    let coordination_ref = admission.coordination_ref;
    let caller_ref = admission.caller_ref;
    let mut authority_ref = admission.authority_ref;
    let crate::broker::runners::RunnerDispatchResolution {
        runner_class,
        binary: construct_binary,
        binary_source: construct_binary_source,
        cwd,
        cwd_source,
    } = admission.runner_resolution;
    let calling_shim = calling_shim_from_action_ref(&action_ref);
    let mut resolved_binary = construct_binary.clone();
    let mut binary_source = construct_binary_source;

    // Validate env_passthrough names (defense-in-depth against env injection).
    let env_name_re = regex::Regex::new(r"^[A-Z_][A-Z0-9_]*$").unwrap();
    for name in &req.env_passthrough {
        if !env_name_re.is_match(name) {
            return Err((-32602, format!("invalid env_passthrough name: {name}")));
        }
    }

    // Structured action-ref + rail manifest gate. When the request carries
    // both `construct_toml_bytes` and `action_ref`, the daemon validates the
    // live carrier's rail trust-contract declaration (when present), resolves
    // the manifest-declared structured action ref for
    // `action_ref.action_key`, and requires an exact structured match.
    let mut construct_toml_text: Option<String> = None;
    let mut terminal_mode = TerminalMode::Auto;
    if let Some(b64_bytes) = req.construct_toml_bytes.as_deref() {
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64_bytes)
            .map_err(|e| {
                (
                    -32602,
                    format!("invalid base64 in construct_toml_bytes: {e}"),
                )
            })?;
        let text = std::str::from_utf8(&decoded).map_err(|e| {
            (
                -32602,
                format!("construct_toml_bytes is not valid UTF-8: {e}"),
            )
        })?;
        construct_toml_text = Some(text.to_string());
        let declared =
            core_events::construct_toml::resolve_action_ref(text, &action_ref.action_key)
                .map_err(|e| (-32009, e.to_string()))?;
        terminal_mode =
            core_events::construct_toml::resolve_action_terminal_mode(text, &action_ref.action_key)
                .map_err(|e| (-32009, e.to_string()))?;
        if declared != action_ref {
            return Err((
                -32009,
                format!(
                    "action_ref mismatch: requested {} but manifest declares {}",
                    action_ref, declared
                ),
            ));
        }
        let wrapped_binary = wrapped_binary_from_construct_manifest(text)?;
        resolved_binary = resolve_wrapped_binary_path(&wrapped_binary)?;
        binary_source = RunnerBinarySource::WrappedBinary;
    }
    if terminal_mode == TerminalMode::Piped && req.pty_socket_path.is_some() {
        return Err((
            -32602,
            format!(
                "broker_exec pty_socket_path is forbidden for action_ref {} because construct.toml terminal_mode=piped",
                action_ref
            ),
        ));
    }

    // Per-action env-passthrough allowlist (ADR 124 axis A2). When the request carries an
    // `action_env_allowlist` (sourced from construct.toml's
    // `[actions.<X>].env_passthrough` for the classified action), strip any
    // requested env name not in the allowlist. The strip count is recorded
    // on the Receipt under `env_passthrough_stripped` so forensic chains
    // can see which env names a buggy/hostile shim tried to forward.
    let mut env_passthrough_filtered: Vec<String> = req.env_passthrough.clone();
    let mut env_passthrough_stripped: Vec<String> = Vec::new();
    if let Some(allowlist) = req.action_env_allowlist.as_ref() {
        let allow: std::collections::HashSet<&str> = allowlist.iter().map(|s| s.as_str()).collect();
        let (kept, stripped): (Vec<String>, Vec<String>) = env_passthrough_filtered
            .into_iter()
            .partition(|name| allow.contains(name.as_str()));
        env_passthrough_filtered = kept;
        env_passthrough_stripped = stripped;
        if !env_passthrough_stripped.is_empty() {
            tracing::warn!(
                stripped = ?env_passthrough_stripped,
                action_allowlist = ?allowlist,
                "broker_exec: stripped env_passthrough names not in construct.toml allowlist"
            );
        }
    }

    // Daemon-side argv re-classification (ADR 124 axis E1). Resolve binary → tool_name via the manifest, run the
    // per-tool classifier server-side, and (when the shim claimed an action)
    // refuse on mismatch with a structured Receipt + JSON-RPC error. Grant
    // evaluation downstream uses `daemon_action`, NEVER `req.claimed_action`.
    let manifest_lookup = lookup_binary_in_manifest(&resolved_binary);
    let classification_tool_name =
        daemon_classification_tool_name(&resolved_binary, manifest_lookup.as_ref());
    let daemon_action: Option<String> = classification_tool_name
        .as_deref()
        .and_then(|tool_name| classify_argv_daemon_side(tool_name, &req.argv));
    // DCC-5: extract remote-name positional alongside the action key so DCC-6
    // can use it in the remote-binding allowlist check.
    let _daemon_remote_name: Option<String> = manifest_lookup
        .as_ref()
        .and_then(|(tool_name, _publisher)| extract_remote_name_daemon_side(tool_name, &req.argv));
    let claimed_action = Some(action_ref.action_key.as_str()).or(req.claimed_action.as_deref());
    if let Some(claimed) = claimed_action {
        match daemon_action.as_deref() {
            Some(daemon)
                if runner_action_matches_authority_action(
                    daemon,
                    claimed,
                    classification_tool_name.as_deref(),
                ) =>
            {
                // Match — daemon-classified action confirms the shim's claim.
            }
            other => {
                let daemon_repr = other.unwrap_or("<unclassified>");
                let mismatch_payload = serde_json::json!({
                    "kind": "argv_classification_mismatch",
                    "binary": resolved_binary,
                    "action_ref": action_ref,
                    "claimed_action": claimed,
                    "daemon_action": daemon_repr,
                });
                if let Err(e) = store.log_event(
                    None,
                    "session.argv_classification_mismatch",
                    None,
                    "denied",
                    Some(&mismatch_payload.to_string()),
                ) {
                    tracing::warn!(
                        error = %e,
                        "broker_exec: failed to record argv_classification_mismatch receipt"
                    );
                }
                return Err((
                    -32003,
                    format!(
                        "argv_classification_mismatch: claimed={} daemon={}",
                        claimed, daemon_repr
                    ),
                ));
            }
        }
    }

    verify_construct_sidecar(&construct_binary, construct_toml_text.as_deref(), store)?;

    let request_persona = params
        .get("caller_persona")
        .and_then(|value| value.as_str());
    let mut approval_binding_to_consume: Option<(
        String,
        crate::trust::approval::ApprovalBindingRecord,
    )> = None;
    let workflow_authorized = if resolved_attachment_authority.is_some() {
        match eval_workflow_for_action(
            store,
            sessions_dir,
            req.session_id.as_deref(),
            Some(&action_ref),
            request_persona,
            resolve_workflow_strict_mode(sessions_dir, req.session_id.as_deref()),
            chrono::Utc::now(),
        ) {
            DelegationEvalOutcome::Approve { .. } => true,
            DelegationEvalOutcome::StandingGrantRequired { reason } => {
                return Err((
                    -32005,
                    format!(
                        "authority_delegation_required: session_id={} reason={}",
                        req.session_id.as_deref().unwrap_or(""),
                        reason,
                    ),
                ));
            }
            _ => false,
        }
    } else {
        false
    };
    let construct_exec_policy = construct_toml_text
        .as_deref()
        .map(|text| parse_construct_exec_policy(text, &action_ref.action_key))
        .transpose()?
        .unwrap_or(ConstructExecPolicy::Permit);
    match construct_exec_policy {
        ConstructExecPolicy::Deny => {
            return Err((
                -32009,
                format!(
                    "construct exec policy denies action_ref {}",
                    action_ref.action_key
                ),
            ));
        }
        ConstructExecPolicy::Prompt if !workflow_authorized => {
            let attachment_authority = resolved_attachment_authority.as_ref().ok_or((
                -32006,
                "approval binding requires attachment-scoped runtime authority".to_string(),
            ))?;
            let attachment_endpoint_token = params
                .get("attachment_endpoint_token")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or((
                    -32006,
                    "approval binding requires attachment_endpoint_token".to_string(),
                ))?;
            let request_persona = request_persona.ok_or((
                -32006,
                "approval binding requires caller_persona".to_string(),
            ))?;
            let execution_contract_for_approval = execution_contract
                .as_ref()
                .expect("execution contract present after action_ref gate");
            let binding = crate::trust::approval::ApprovalBindingRecord {
                attachment_id: attachment_authority.attachment_id.clone(),
                caller_binding_id: attachment_authority.caller_binding_id.clone(),
                attachment_endpoint_token_sha256: sha256_hex_text(attachment_endpoint_token),
                execution_contract_digest: execution_contract_digest(
                    execution_contract_for_approval,
                )?,
                invocation_digest: invocation_plan_digest(
                    runner_class,
                    &resolved_binary,
                    cwd.as_deref().expect("exec dispatch must resolve cwd"),
                    &req.argv,
                    &env_passthrough_filtered,
                )?,
            };
            let approval_scope =
                approval_binding_scope(&binding.attachment_id, &binding.invocation_digest);
            let mut approval_authorized = false;
            let mut pending_approval = None;
            if let Some(existing) = store
                .find_matching_approval_binding(request_persona, &action_ref.action_key, &binding)
                .map_err(|e| (-32000, format!("find matching approval binding: {e}")))?
            {
                if existing.status == "approved" {
                    approval_binding_to_consume = Some((existing.id.clone(), binding.clone()));
                    approval_authorized = true;
                } else if existing.status == "pending" {
                    pending_approval = Some(existing.id);
                }
            }
            if !approval_authorized {
                let approval_request_id = if let Some(existing_id) = pending_approval {
                    existing_id
                } else {
                    store
                        .submit_decision_only_approval_binding(
                            request_persona,
                            &action_ref.action_key,
                            &approval_scope,
                            &action_ref.action_key,
                            "high",
                            daemon_action.clone(),
                            None,
                            None,
                            Some("construct".to_string()),
                            &binding,
                        )
                        .map_err(|e| {
                            (
                                -32000,
                                format!("submit decision-only approval binding: {e}"),
                            )
                        })?
                        .id
                };
                if let Some(mat_id) = req.secret_ref.as_deref()
                    && let Some(registry) = current_registry()
                {
                    let _ = registry.extend_spawn_handle_not_after(
                        mat_id,
                        Utc::now() + chrono::Duration::seconds(APPROVAL_BINDING_PENDING_TTL_SECS),
                    );
                }
                return approval_required_response(
                    &contract_id,
                    execution_contract.as_ref(),
                    &action_ref,
                    workspace_ref.as_deref(),
                    subject_ref.as_deref(),
                    coordination_ref.as_deref(),
                    caller_ref.as_deref(),
                    authority_ref.as_deref(),
                    &approval_request_id,
                );
            }
        }
        _ => {}
    }

    // Build env: allowlist baseline + caller-supplied passthrough (post-strip).
    //
    // HOME is deliberately omitted from the inherited allowlist.
    // Inheriting the daemon's HOME leaks the operator's
    // `~/.config/` into the broker-spawned child — a separate-uid daemon
    // running as `ember` then tries to read operator-owned dotfiles
    // (`~/.config/gh/config.yml` mode 600) and fails with permission-denied,
    // OR succeeds and uses operator-owned credentials, defeating the broker's
    // "only daemon-minted credentials reach the child" invariant. Instead
    // the daemon allocates a per-spawn ephemeral HOME (a fresh tempdir owned
    // by the daemon uid). Tools that scan HOME (`gh`, `git`, `aws`) see an
    // empty dir, fall through to their defaults, and consume ONLY the
    // credentials the broker injected via env.
    let allowlist = ["PATH", "USER", "LANG", "TERM"];
    let mut env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for name in allowlist
        .iter()
        .copied()
        .chain(env_passthrough_filtered.iter().map(|s| s.as_str()))
    {
        if let Ok(val) = std::env::var(name) {
            env.insert(name.to_string(), val);
        }
    }

    // Per-spawn ephemeral HOME. Bound to `_exec_home` so the TempDir lives
    // until this function returns (i.e. through the child's full exec); its
    // Drop unlinks the directory and reclaims the inode. Daemon uid owns the
    // dir, so the spawned child (running as the daemon uid in the host-direct
    // path) can read+write inside it without inheriting operator-owned state.
    let exec_home = allocate_broker_exec_home().map_err(|e| {
        (
            -32000,
            format!("failed to allocate broker_exec HOME tempdir: {e}"),
        )
    })?;
    env.insert(
        "HOME".to_string(),
        exec_home.path().to_string_lossy().into_owned(),
    );

    // Runner-owned workspace resolution. Preferred flows resolve cwd from the
    // logical workspace ref; compatibility callers may supply an explicit cwd
    // only when no logical workspace handle exists.
    let cwd = cwd.expect("exec dispatch must resolve cwd");
    let cwd_source = cwd_source.expect("exec dispatch must record cwd source");
    if matches!(cwd_source, RunnerCwdSource::CompatibilityCwd) {
        tracing::warn!(
            cwd = %cwd,
            action_ref = %action_ref,
            "broker_exec: using compatibility cwd fallback because workspace_ref is absent"
        );
    }

    // Classification-file refusal under bot
    // identity. Migrated from `.claude/scripts/as-bot.sh` (deleted in
    // a prior migration) into the daemon's broker_exec —
    // the new trust boundary for bot-authored ops. Refuses any
    // commit/push/pr_create whose payload mutates a `.classification`
    // file. Defends against #4 + #11 from the classification-routing
    // adversarial review (a quiet refactor PR flipping a crate's
    // classification under cover of refactor noise).
    //
    // Operator-authored commits (no broker_exec → no daemon mediation)
    // remain gated by CODEOWNERS' `**/.classification @operator`.
    if let Some(action) = daemon_action.as_deref()
        && let Some(violation) = check_classification_refusal(action, &cwd)
    {
        tracing::warn!(
            action = %action,
            cwd = %cwd,
            "broker_exec: refusing — agent identity cannot author .classification changes"
        );
        let payload = serde_json::json!({
            "kind": "classification_refusal",
            "action": action,
            "cwd": cwd,
            "files": violation,
        });
        if let Err(e) = store.log_event(
            None,
            "session.classification_refusal",
            None,
            "denied",
            Some(&payload.to_string()),
        ) {
            tracing::warn!(
                error = %e,
                "broker_exec: failed to record classification_refusal receipt"
            );
        }
        return Err((
                -32011,
                "agent identity cannot author classification changes; operator must commit these directly".to_string(),
            ));
    }

    // Per-action credential injection.
    //
    // When `daemon_action` matches an entry in `ember_construct::policy`,
    // the daemon mints a scoped credential through the registered broker for
    // the policy's `provider` and writes it into the child env via the
    // policy's `injection` shape (single env var for `gh`, GIT_CONFIG_*
    // triple for `git` HTTPS pushes). The credential is revoked after the
    // child exits — see the post-spawn block at end of this function.
    //
    // Failure to mint (broker unavailable, upstream API error) is logged
    // but NOT fatal: the child runs without the injected credential and
    // surfaces its own auth error if it needs the token. Constructs that
    // critically depend on the mint should declare `default = "deny"` in
    // construct.toml so unauthorized invocations fail at the gate.
    //
    // Env-leak hardening Phase 1: snapshot env keys before
    // and after the mint so the seal-swap site downstream can identify
    // which env entries are credentials without re-parsing the broker
    // policy. `credential_env_keys` is the set of keys that
    // `apply_credential_to_env` populated; the spawn site (when the
    // EMBER_BROKER_SEAL_CREDS opt-in is on) reroutes those entries
    // through `exec_env::seal_credentials_for_exec` so `/proc/<pid>/environ`
    // exposes `<KEY>_FD=<n>` instead of `<KEY>=<plaintext>`.

    // ALLOWLIST_GATE_HTTPS — HTTPS credential allowlist closure
    // (ADR 150).
    //
    // For git credential-bearing actions, the daemon refuses the broker_exec
    // unless a matching binding exists for (caller_persona, working_tree,
    // remote_name) AND the .git/config URL for that remote matches the
    // binding's recorded URL. No binding → call tofu_confirm_binding
    // (DCC-3A stub returns Refused; DCC-3B will replace with biometric).
    // URL drift → refuse with -32008. No caller_persona → refuse with -32007.
    //
    // The credential-bearing surface is identified by EITHER:
    //   1. `daemon_action` resolving to one of git.{push,fetch,pull,clone}
    //      via the manifest-driven classifier (production path), OR
    //   2. The invoked binary's basename being `git` / `ember-git` AND the
    //      first argv positional being one of {push, fetch, pull, clone}
    //      (test-and-defense-in-depth path — fires even when the manifest
    //      classifier returns None because the binary path isn't in the
    //      bundled manifest).
    //
    // Either trigger funnels through the same allowlist gate. The gate
    // runs BEFORE `mint_and_inject_for_action` so an unbound remote can
    // never reach the broker.
    //
    // BKR-2 (ADR 205 §4): the concrete `owner/repo` the github mint is bound
    // to. For git.{push,fetch,pull,clone} it is the TOFU-validated remote URL
    // resolved in the gate below (the authoritative target); set there.
    let mut git_remote_owner_repo: Option<String> = None;
    let is_credential_bearing_git_action = {
        let action_match = matches!(
            daemon_action.as_deref(),
            Some("git.push" | "git.fetch" | "git.pull" | "git.clone")
        );
        let basename_match = {
            let bin_basename = std::path::Path::new(&resolved_binary)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let stripped = bin_basename
                .strip_prefix("ember-")
                .unwrap_or(&bin_basename)
                .to_string();
            let verb_match = req
                .argv
                .first()
                .map(|v| matches!(v.as_str(), "push" | "fetch" | "pull" | "clone"))
                .unwrap_or(false);
            stripped == "git" && verb_match
        };
        action_match || basename_match
    };
    if is_credential_bearing_git_action {
        use std::path::Path;
        use uuid::Uuid;

        let persona_str = params
            .get("caller_persona")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let persona_id = match Uuid::parse_str(persona_str) {
            Ok(uid) if !uid.is_nil() => uid,
            _ => return Err((-32007, "binding requires caller_persona".to_string())),
        };

        let wtree_id = match crate::broker::working_tree_id::working_tree_id(Path::new(&cwd)) {
            Ok(id) => id,
            Err(e) => return Err((-32007, format!("binding requires git working tree: {e}"))),
        };

        // Resolve remote-name: prefer the daemon-side classifier output
        // (when the manifest_lookup resolves the binary to `git`); else
        // fall back to the direct-argv extractor used by the basename
        // trigger above. `ember_construct::git::extract_git_remote_name`
        // takes the git verb + the trailing argv after the verb.
        let remote_name = manifest_lookup
            .as_ref()
            .and_then(|(tool_name, _publisher)| {
                extract_remote_name_daemon_side(tool_name, &req.argv)
            })
            .or_else(|| {
                let verb = req.argv.first()?;
                ember_construct::git::extract_git_remote_name(verb.as_str(), &req.argv[1..])
            })
            .ok_or((
                -32007,
                "binding requires explicit remote name in argv".to_string(),
            ))?;

        let cfg_url = match crate::broker::gitconfig_reader::read_remote_url_from_gitconfig(
            Path::new(&wtree_id),
            &remote_name,
        ) {
            Ok(url) => url,
            Err(e) => {
                return Err((
                    -32007,
                    format!("binding requires readable .git/config: {e}"),
                ));
            }
        };

        let key = crate::broker::bindings::BindingKey {
            principal_id: persona_id.to_string(),
            working_tree_id: wtree_id.clone(),
            remote_name: remote_name.clone(),
        };
        let binding_lookup = crate::broker::bindings::get(store, &key)
            .map_err(|e| (-32603, format!("bindings::get failed: {e}")))?;

        match binding_lookup {
            Some(existing) if existing.remote_url == cfg_url => {
                // proceed to mint
            }
            Some(_drifted) => {
                return Err((
                    -32008,
                    format!(
                        "url_changed_rebind_required: .git/config URL for remote {remote_name} differs from registered binding"
                    ),
                ));
            }
            None => {
                let scope = "contents:write";
                let outcome = crate::broker::tofu::tofu_confirm_binding(
                    store,
                    &persona_id,
                    &wtree_id,
                    &remote_name,
                    &cfg_url,
                    scope,
                )
                .await
                .map_err(|e| (-32603, format!("tofu_confirm_binding failed: {e}")))?;
                match outcome {
                    crate::broker::tofu::TofuOutcome::Confirmed => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        let new_binding = crate::broker::bindings::Binding {
                            principal_id: persona_id.to_string(),
                            working_tree_id: wtree_id.clone(),
                            remote_name: remote_name.clone(),
                            remote_url: cfg_url.clone(),
                            created_at: now,
                        };
                        crate::broker::bindings::insert(store, &new_binding)
                            .map_err(|e| (-32603, format!("bindings::insert failed: {e}")))?;
                    }
                    _ => return Err((-32007, "binding_not_confirmed".to_string())),
                }
            }
        }
        // The remote URL was just validated against the TOFU binding, so it is
        // the authoritative target for the github mint. A non-github.com remote
        // yields None — a github installation token is useless there, and the
        // mint is fail-closed-skipped downstream (ADR 205 §4).
        git_remote_owner_repo = ember_construct::git::owner_repo_from_remote_url(&cfg_url);
    }

    if let Some((approval_id, binding)) = approval_binding_to_consume {
        if store
            .consume_approval_binding(&approval_id, &binding)
            .map_err(|e| (-32000, format!("consume approval binding: {e}")))?
        {
            authority_ref = Some(format!("approval:{approval_id}"));
        } else {
            return Err((
                -32006,
                "approval binding was no longer available; retry to request fresh approval"
                    .to_string(),
            ));
        }
    }

    let env_keys_pre_mint: std::collections::HashSet<String> = env.keys().cloned().collect();
    // Thread the caller_persona JSON
    // field (the persona id string the client sent) through the mint
    // path so the operator log line names the resolver, not just the
    // action key. Falls back to "<no-persona>" inside the mint helper
    // when omitted (legacy / system-internal callers).
    let mint_persona_alias: Option<String> = params
        .get("caller_persona")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    // BKR-2 (ADR 205 §4) — resolve the concrete `owner/repo` to bind the github
    // mint to. git.* takes the TOFU-validated remote (set in the gate above);
    // gh.* takes an explicit `--repo`/`-R`, else the cwd's `origin` remote.
    // Unresolved ⇒ None ⇒ the mint is fail-closed-skipped (no unbounded token).
    let concrete_github_repo: Option<String> = match daemon_action.as_deref() {
        Some("git.push" | "git.fetch" | "git.pull" | "git.clone") => git_remote_owner_repo.clone(),
        Some(action) if action.starts_with("gh.") => {
            resolve_gh_repo_from_argv(&req.argv).or_else(|| origin_owner_repo_from_cwd(&cwd))
        }
        _ => None,
    };
    let aws_permission_specs = match daemon_action.as_deref() {
        Some(action) if action.starts_with("aws.") => {
            ember_construct::aws::aws_permission_specs_for_argv(action, &req.argv)
        }
        _ => None,
    };
    // BKR-4 PR-B: resolve the runtime persona's standing grant (and its
    // persona id) so the credential mint can enforce `need ⊆ grant`
    // fail-closed (closing the `caller_persona = None` bypass). The grant_id
    // comes from whichever attachment-authority resolution fired: the
    // attachment-endpoint path (`resolved_attachment_authority`) or the
    // session path (`live_attachment_authority`). Both resolve to the runtime
    // persona's `meta.grant_id`. No resolved authority ⇒ `None` grant ⇒ the
    // mint is fail-closed-skipped (no token), which is the hard-right P4
    // disposition (ADR 205 / design §P4).
    let (resolved_runtime_grant_id, resolved_runtime_persona_id): (Option<String>, Option<String>) =
        match (
            resolved_attachment_authority.as_ref(),
            live_attachment_authority.as_ref(),
        ) {
            (Some(att), _) => (
                Some(att.grant_id.clone()),
                Some(att.runtime_persona_id.clone()),
            ),
            (None, Some(live)) => (
                Some(live.grant_id.clone()),
                Some(live.runtime_persona_id.clone()),
            ),
            (None, None) => (None, None),
        };
    let resolved_runtime_grant: Option<core_grant_types::AccessGrant> =
        match resolved_runtime_grant_id.as_deref() {
            Some(grant_id) => match store.get_access_grant(grant_id) {
                Ok(grant) => Some(grant),
                Err(e) => {
                    // Fail-closed: a grant_id that does not resolve to a
                    // chain-verified grant must mint NOTHING. Leaving the grant
                    // `None` makes the mint refuse downstream.
                    tracing::warn!(
                        grant_id = %grant_id,
                        error = %e,
                        "broker_exec: runtime grant did not resolve for need ≤ grant check — \
                         credential mint will fail closed (BKR-4 PR-B)"
                    );
                    None
                }
            },
            None => None,
        };
    let exec_credential: Option<(String, BrokerProvider)> = match daemon_action.as_deref() {
        Some(action) => {
            mint_and_inject_for_action(
                action,
                &mut env,
                store,
                mint_persona_alias.as_deref(),
                concrete_github_repo.as_deref(),
                aws_permission_specs.as_deref(),
                execution_contract.as_ref(),
                resolved_runtime_grant.as_ref(),
                resolved_runtime_persona_id.as_deref(),
            )
            .await
        }
        None => None,
    };
    let credential_env_keys: Vec<String> = env
        .keys()
        .filter(|k| !env_keys_pre_mint.contains(*k))
        .cloned()
        .collect();
    inject_ephemeral_git_safe_directory(&mut env, &resolved_binary);

    if let Some(mat_id) = req.secret_ref.as_deref()
        && pending_spawn_handle.is_some()
        && let Some(registry) = current_registry()
    {
        let Some(handle) = registry.consume_spawn_handle(mat_id) else {
            if registry.was_recently_consumed(mat_id) {
                return Err((-32003, "SpawnHandleAlreadyConsumed".to_string()));
            }
            return Err((-32002, "SpawnHandleExpired".to_string()));
        };
        if chrono::Utc::now() > handle.not_after {
            return Err((-32002, "SpawnHandleExpired".to_string()));
        }
        if let Err(err) = handle.validate_bound_pidfd(principal) {
            tracing::warn!(
                target: "audit",
                spawn_handle_id = ?handle.handle_id,
                reason = %err.reason,
                "spawn handle exec refused at consume: SpawnHandlePidfdInvalidated"
            );
            return Err(err.into_rpc_error());
        }
        tracing::info!(
            target: "audit",
            spawn_handle_consumed = ?handle.handle_id,
            not_after = ?handle.not_after,
            "spawn handle exec"
        );
    }

    let started_at = std::time::Instant::now();
    let shim_eof_policy = ShimEofPolicy::from_toml_value(req.on_shim_eof.as_deref());
    let mut shim_outcome = ShimEofOutcome::ChildExitedFirst;

    // Host-direct spawn paths drop
    // privileges to a per-spawn uid checked out from the configured
    // pool. The SCION dispatch path (scion_exec_socket = Some(_))
    // routes through the in-container `ember-exec` receiver which
    // owns its own privilege drop (subtask B/C); we skip the local
    // pool checkout in that case. The lease binding is held in this
    // function's scope across `.await` boundaries so the uid stays
    // checked out until after the child has been waited on.
    //
    // The pool is consulted via `resolve_broker_exec_uid_lease`,
    // which surfaces `-32020` for retryable exhaustion / Finding-14
    // refusal and `-32021` for unconfigured or empty pools. Test pools
    // (installed via `uid_alloc::init_uid_pool_for_test`) carry a
    // `test_mode` flag that bypasses the Finding-14 refusal so
    // in-process unit tests don't need to root-drop into a real
    // separate uid; production pools always have `test_mode = false`.
    let spawn_lease: Option<crate::broker::uid_alloc::UidLease> = if req.scion_exec_socket.is_none()
    {
        Some(resolve_broker_exec_uid_lease(&resolved_binary)?)
    } else {
        None
    };

    // ADR 155 Path A — PTY + subuid combo refusal (-32031).
    //
    // The modern-Linux subuid-pool spawn path (`spawn_in_execution_
    // domain`) routes through `clone3(CLONE_NEWUSER) + newuidmap` so
    // the child's host-visible uid is mapped to a subuid WITHOUT the
    // daemon ever holding host-level CAP_SETUID. The forkpty path
    // (`forkpty_exec_and_bridge`), in contrast, calls `setresuid` on
    // the host side after fork — that syscall fails EPERM under a
    // subuid pool because the daemon has no host CAP_SETUID, and the
    // child exits 127 with a cryptic stderr.
    //
    // Routing PTY constructs through the user-namespace primitive is
    // a follow-up scope — the
    // namespace-spawn primitive doesn't currently expose a slave-fd
    // wire-up the way `forkpty` does. Until that lands we refuse the
    // combo cleanly here rather than letting the broker_exec call
    // crash inside the spawn-blocking task with a cryptic errno.
    //
    // The lease drops on early return — the pool slot is reclaimed.
    if req.pty_socket_path.is_some()
        && spawn_lease.as_ref().is_some_and(|l| l.is_subuid())
        && cfg!(target_os = "linux")
    {
        return Err((
            -32031,
            "PTY constructs not yet routed through user-namespace; \
             subuid pool in use. Run the construct in non-PTY mode, \
             or migrate this construct's broker_exec to omit \
             pty_socket_path. Tracked under \
             META-EXEC-DOMAIN-PTY-SUBUID-ROUTING follow-up."
                .to_string(),
        ));
    }

    let _inflight_sample = BrokerExecInflightSampleGuard::enter();
    let (exit_code, stdout_tail, stderr_tail) = if let Some(ref scion_sock) = req.scion_exec_socket
    {
        // In-container exec path.
        // emberd dispatches the binary via the in-container `ember-exec`
        // listener — UDS connect, write `SpawnDirective`, drive frames
        // until `ExecFrame::Exit { code }`. The host-direct forkpty path
        // (below) stays unchanged: the two paths are mutually exclusive
        // and the receiver-side carries its own hash-verify + privilege
        // drop (subtask B/C).
        #[cfg(unix)]
        {
            use ember_exec::uds::{ExecFrame, SpawnDirective, read_frame};
            let socket_path = std::path::PathBuf::from(scion_sock);

            // Compute the binary's blake3 content hash for the
            // SpawnDirective. The receiver re-checks before any
            // privileged work (CRIT-B mitigation, subtask B).
            let binary_for_hash = resolved_binary.clone();
            let content_hash_expected =
                tokio::task::spawn_blocking(move || -> Result<String, std::io::Error> {
                    let mut f = std::fs::File::open(&binary_for_hash)?;
                    let mut hasher = blake3::Hasher::new();
                    std::io::copy(&mut f, &mut hasher)?;
                    Ok(hasher.finalize().to_hex().to_string())
                })
                .await
                .map_err(|e| (-32000, format!("blake3 task panicked: {e}")))?
                .map_err(|e| (-32000, format!("blake3 read failed: {e}")))?;

            // Materialise the env into the SpawnDirective shape. The
            // child env is split into two carriers: env_allowlist names
            // the var names the receiver may keep from its own ambient
            // environment, and credential_env carries the broker-
            // resolved scoped credentials emberd injects directly. The
            // current path treats every entry in `env` as a directly-
            // injected pair so the receiver doesn't need ambient host
            // env on the in-container side.
            let credential_env: Vec<(String, String)> =
                env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            let env_allowlist: Vec<String> = env.keys().cloned().collect();

            // Clone the verified
            // hash + binary path + target_uid BEFORE we hand the
            // directive to `send_spawn_directive` (which consumes it).
            // The receipt records "what emberd actually approved", so
            // the hash MUST come from this verified value, not a
            // post-execve recomputation.
            let receipt_binary_path = std::path::PathBuf::from(&resolved_binary);
            let receipt_binary_blake3 = content_hash_expected.clone();
            let receipt_target_uid = req.scion_target_uid;

            let directive = SpawnDirective {
                binary_path: resolved_binary.clone(),
                argv: req.argv.clone(),
                env_allowlist,
                credential_env,
                target_uid: req.scion_target_uid,
                target_gid: req.scion_target_gid,
                content_hash_expected,
            };

            let mut stream = crate::spawn::scion::send_spawn_directive(&socket_path, directive)
                .await
                .map_err(|e| (-32000, format!("send_spawn_directive: {e}")))?;

            // Drive frames inbound from the receiver until Exit. Output
            // frames are surfaced as best-effort traces — full
            // bidirectional proxying to a peer pty socket is subtask F+
            // scope (this path establishes the dispatch and exit-code
            // contract).
            let mut exit_code: i32 = -1;
            let mut received_exit_frame = false;
            loop {
                match read_frame(&mut stream).await {
                    Ok(Some(ExecFrame::Exit { code })) => {
                        exit_code = code;
                        received_exit_frame = true;
                        break;
                    }
                    Ok(Some(ExecFrame::HashMismatch { expected, actual })) => {
                        tracing::warn!(
                            binary = %resolved_binary,
                            expected = %expected,
                            actual = %actual,
                            "scion_exec: receiver-side content_hash mismatch"
                        );
                        break;
                    }
                    Ok(Some(_)) => {
                        // OutputBytes / other mid-session frames — drain
                        // toward stderr_tail buffer is follow-up scope;
                        // for now keep the dispatch contract minimal.
                    }
                    Ok(None) => break, // peer closed
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "scion_exec: frame read failed; closing"
                        );
                        break;
                    }
                }
            }

            // Receipt v2 emission
            // on every Exit frame. Best-effort: a missing daemon
            // identity or a sign-side error logs a warning and does
            // NOT fail the RPC (the exec already happened upstream).
            // One receipt per Exit frame — gated on
            // `received_exit_frame` so frame-read errors / hash
            // mismatches / peer-close-without-Exit do NOT emit a
            // spurious zero-exit receipt.
            //
            // Credential hygiene: credential_env is NEVER referenced
            // in this block. The receipt body carries metadata only
            // (binary path / hash / uid / exit / persona / grant /
            // timestamp).
            if received_exit_frame {
                emit_scion_exec_completion_receipt(
                    store,
                    params,
                    receipt_binary_path,
                    receipt_binary_blake3,
                    receipt_target_uid,
                    exit_code,
                );
            }

            (exit_code, String::new(), String::new())
        }
        #[cfg(not(unix))]
        {
            let _ = scion_sock;
            return Err((
                -32000,
                "scion_exec_socket is not supported on this platform".to_string(),
            ));
        }
    } else if let Some(ref socket_path) = req.pty_socket_path {
        // PTY path: forkpty → slave fd attached to child → bridge on master fd.
        #[cfg(unix)]
        {
            let socket_path = std::path::PathBuf::from(socket_path);
            let binary = resolved_binary.clone();
            let argv = req.argv.clone();
            let env_pairs: Vec<(String, String)> = env.into_iter().collect();
            let cwd_clone = cwd.clone();
            let policy = shim_eof_policy;

            // Read uid/gid out of the
            // lease BEFORE moving into the spawn_blocking closure (the
            // lease binding stays in the outer scope so it lives across
            // the .await below). The forkpty child branch calls
            // `setresgid` + `setresuid` between `chdir` and `execvpe`.
            let target_uid = spawn_lease.as_ref().map(|l| l.uid());
            let target_gid = spawn_lease.as_ref().map(|l| l.gid());

            // forkpty + exec are inherently sync/fork-unsafe in async context;
            // run on the blocking thread pool and join before we proceed.
            let (exit_code, bridge_err, outcome) = tokio::task::spawn_blocking(move || {
                forkpty_exec_and_bridge(
                    &binary,
                    &argv,
                    &env_pairs,
                    &cwd_clone,
                    &socket_path,
                    policy,
                    target_uid,
                    target_gid,
                )
            })
            .await
            .map_err(|e| (-32000, format!("pty spawn task panicked: {e}")))?
            .map_err(|e| (-32000, e))?;

            if let Some(e) = bridge_err {
                tracing::warn!(error = %e, "broker_exec pty: bridge returned error (child exit still reported)");
            }
            shim_outcome = outcome;
            (exit_code, String::new(), String::new())
        }
        #[cfg(not(unix))]
        {
            let _ = socket_path;
            return Err((
                -32000,
                "pty_socket_path is not supported on this platform".to_string(),
            ));
        }
    } else if select_host_direct_non_pty_spawn_route(spawn_lease.as_ref())
        == HostDirectNonPtySpawnRoute::SpawnHelper
    {
        let lease = spawn_lease
            .as_ref()
            .expect("spawn-helper route requires a host-direct uid lease");
        let (exit_code, stdout_tail, stderr_tail) =
            spawn_host_direct_via_spawn_helper(&req, &resolved_binary, &env, &cwd, lease).await?;
        (exit_code, stdout_tail, stderr_tail)
    } else if cfg!(target_os = "linux") && spawn_lease.as_ref().is_some_and(|l| l.is_subuid()) {
        // ADR 155 Component 2 — modern-Linux execution-domain path.
        // The lease was minted from a subuid-range pool (the install
        // path provisioned `/etc/subuid:ember:N:M` and the config has
        // `[spawn_pool] subuid_range_start = N / subuid_range_slots = M`).
        // Route through `spawn_in_execution_domain`, which clones a
        // user namespace, invokes `newuidmap`/`newgidmap` to wire the
        // mapping, then `execveat`s the verified binary as namespace
        // inner-root. The daemon never holds host-level CAP_SETUID.
        //
        // The memfd-seal pre_exec stub does NOT compose with this path in v0.3
        // — the namespace-spawn primitive doesn't expose a generic
        // pre_exec hook for sealed-env rewriting, and the same
        // /proc-environ-leak threat model is structurally closed by
        // the namespace's cross-uid ACL. Future composition (sealed
        // env inside namespace) is a follow-up.
        let lease = spawn_lease.as_ref().expect("is_subuid implies Some");
        let target_subuid = lease.uid();
        let target_subgid = lease.gid();
        let env_pairs: Vec<(String, String)> = env.into_iter().collect();
        let env_os: Vec<(std::ffi::OsString, std::ffi::OsString)> = env_pairs
            .iter()
            .map(|(k, v)| (std::ffi::OsString::from(k), std::ffi::OsString::from(v)))
            .collect();
        let argv_os: Vec<std::ffi::OsString> =
            req.argv.iter().map(std::ffi::OsString::from).collect();
        let binary_path = std::path::PathBuf::from(&resolved_binary);
        let cwd_clone = std::path::PathBuf::from(&cwd);

        // Hash the binary for the two-point verify. spawn_in_execution_
        // domain re-checks via the O_PATH fd inside the syscall path.
        let binary_for_hash = binary_path.clone();
        let content_hash_expected =
            tokio::task::spawn_blocking(move || -> Result<String, std::io::Error> {
                let mut f = std::fs::File::open(&binary_for_hash)?;
                let mut hasher = blake3::Hasher::new();
                std::io::copy(&mut f, &mut hasher)?;
                Ok(hasher.finalize().to_hex().to_string())
            })
            .await
            .map_err(|e| (-32000, format!("blake3 task panicked: {e}")))?
            .map_err(|e| (-32000, format!("blake3 read failed: {e}")))?;

        // spawn_in_execution_domain is sync + fork-based; offload to
        // the blocking pool so we don't block the runtime worker.
        let exit_status = tokio::task::spawn_blocking(move || {
            crate::spawn::exec_domain::spawn_in_execution_domain(
                &binary_path,
                &argv_os,
                &env_os,
                &cwd_clone,
                target_subuid,
                target_subgid,
                &content_hash_expected,
            )
        })
        .await
        .map_err(|e| (-32000, format!("exec_domain spawn task panicked: {e}")))?;

        let exit_status = exit_status.map_err(|e| match e {
            crate::spawn::exec_domain::ExecDomainError::UnsupportedPlatform => {
                (-32021, format!("execution_domain_pool_unavailable: {e}"))
            }
            crate::spawn::exec_domain::ExecDomainError::NewuidmapNotInstalled { .. } => {
                (-32021, format!("execution_domain_pool_unavailable: {e}"))
            }
            crate::spawn::exec_domain::ExecDomainError::HashMismatch { .. } => {
                (-32030, format!("construct_hash_mismatch: {e}"))
            }
            crate::spawn::exec_domain::ExecDomainError::NamespaceCreate(_)
            | crate::spawn::exec_domain::ExecDomainError::UidMapWrite(_)
            | crate::spawn::exec_domain::ExecDomainError::NewuidmapFailed { .. }
            | crate::spawn::exec_domain::ExecDomainError::NewuidmapInvocation { .. } => {
                (-32021, format!("execution_domain_pool_unavailable: {e}"))
            }
            _ => (-32000, format!("execution_domain: {e}")),
        })?;

        let exit_code = exit_status
            .exit_code
            .or_else(|| exit_status.signal.map(|s| 128 + s))
            .unwrap_or(-1);
        (exit_code, String::new(), exit_status.stderr_tail)
    } else {
        // Non-PTY path: tokio::process::Command with piped stdout/stderr.
        //
        // Env-leak hardening Phase 1 (Linux only): when
        // `EMBER_BROKER_SEAL_CREDS=1` is set on the daemon, replace any
        // credential env entries (populated by `mint_and_inject_for_action`
        // and tracked in `credential_env_keys`) with memfd-sealed file
        // descriptors via `exec_env::seal_credentials_for_exec`. The
        // child env then carries `<KEY>_FD=<n>` instead of
        // `<KEY>=<plaintext>`, so `/proc/<pid>/environ` no longer
        // exposes the secret string.
        //
        // The opt-in gate is intentional for Phase 1: existing consumers
        // (`gh`, `aws`, `vault`, etc.) still read the plaintext env var,
        // so flipping the swap default-on would break them. Phase 2
        // ships a Construct-side pre-exec stub that re-exports the
        // plaintext from the inherited fd into the child's actual env
        // immediately before execve — at which point this gate flips
        // to default-on and the plaintext env path is removed.
        //
        // The `_sealed_env` binding holds the `OwnedFd`s alive across
        // `output().await`; dropping it before spawn would close the
        // fds and orphan the child's `*_FD` env entries. tokio's
        // `Command::output()` spawns + waits, so the fds inherit
        // correctly during fork+exec.
        let (sealed_env_opt, env_for_spawn) =
            maybe_seal_credentials_in_env(&mut env, &credential_env_keys).map_err(|e| {
                (
                    -32031,
                    format!("broker_exec: credential sealing required but unavailable: {e}"),
                )
            })?;
        let _sealed_env = sealed_env_opt; // RAII: keep fds open across spawn

        // This command builder integrates two
        // post-fork pre-execve hooks:
        //
        //   1. (#[cfg(unix)]) Drop privileges to the leased per-spawn uid
        //      via `as_std_mut().uid/gid`. The lease is guaranteed to be
        //      `Some` on the host-direct path; only `None` for SCION.
        //   2. (#[cfg(target_os = "linux")]) Install a `pre_exec` closure
        //      that reads each Phase 1 sealed fd, rewrites `<KEY>=<plaintext>`
        //      into the child's env, removes `<KEY>_FD=<n>`, and closes the
        //      fd. Anchor: memfd_seal_phase_2_pre_exec_stub_landed.
        //
        // Both hooks run in the forked child between fork and execve. The
        // kernel snapshots envp at execve, so standard tools (gh, git,
        // aws) see plaintext under the expected name once the binary
        // starts.
        #[cfg(target_os = "macos")]
        let output = {
            let binary = resolved_binary.clone();
            let argv = req.argv.clone();
            let cwd_clone = cwd.clone();
            let env_pairs: Vec<(String, String)> = env_for_spawn.into_iter().collect();
            let target_uid = spawn_lease.as_ref().map(|l| l.uid());
            let target_gid = spawn_lease.as_ref().map(|l| l.gid());

            // The installed macOS daemon runs inside the launchd SBPL sandbox
            // with per-spawn uid drop enabled. In that posture, the Tokio
            // async pipe wrapper can return empty stdout/stderr tails even
            // when the child executed and wrote output successfully. Keep the
            // fork/exec privilege-drop contract, but use std's synchronous
            // capture path on a blocking worker so the daemon still surfaces
            // headless construct output on macOS.
            tokio::task::spawn_blocking(move || -> Result<std::process::Output, std::io::Error> {
                use std::os::unix::process::CommandExt;

                let mut command = std::process::Command::new(&binary);
                command
                    .args(&argv)
                    .current_dir(&cwd_clone)
                    .env_clear()
                    .envs(env_pairs)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped());

                if let Some(uid) = target_uid {
                    command.uid(uid);
                }
                if let Some(gid) = target_gid {
                    command.gid(gid);
                }

                command.output()
            })
            .await
            .map_err(|e| (-32000, format!("spawn capture task panicked: {e}")))?
            .map_err(|e| (-32000, format!("spawn failed: {e}")))?
        };

        #[cfg(not(target_os = "macos"))]
        let output = {
            let mut command = tokio::process::Command::new(&resolved_binary);
            command
                .args(&req.argv)
                .current_dir(&cwd)
                .env_clear()
                .envs(&env_for_spawn)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());

            #[cfg(unix)]
            if let Some(ref lease) = spawn_lease {
                use std::os::unix::process::CommandExt;
                // CommandExt::uid/gid are on std::process::Command;
                // tokio's Command::as_std_mut surfaces the underlying
                // builder so we can attach the privilege drop without
                // bypassing tokio's wait/output machinery.
                command.as_std_mut().uid(lease.uid()).gid(lease.gid());
            }

            #[cfg(target_os = "linux")]
            if let Some(sealed) = _sealed_env.as_ref() {
                let key_fd_map = sealed.key_fd_map();
                // SAFETY: pre_exec runs post-fork pre-execve, single-threaded.
                // The closure only performs async-signal-safe operations
                // (libc::read via read_sealed_fd, std::env::set_var/remove_var,
                // libc::close). The plaintext String drops at end of the closure
                // body; the child's address space is fully replaced at execve so
                // a kernel-level scrub isn't required — the kernel snapshot at
                // execve sees the rewritten env (plaintext under <KEY>, no
                // <KEY>_FD remainder).
                unsafe {
                    use std::os::unix::process::CommandExt;
                    command.pre_exec(move || {
                        for (key, fd) in &key_fd_map {
                            let plaintext =
                                crate::broker::exec_env::read_sealed_fd(*fd).map_err(|e| {
                                    std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        format!("read_sealed_fd({key}_FD={fd}) failed: {e}"),
                                    )
                                })?;
                            // Set <KEY>=<plaintext> in the child's env, remove
                            // <KEY>_FD=<n>, close the inherited fd.
                            std::env::set_var(key, &plaintext);
                            std::env::remove_var(format!("{key}_FD"));
                            libc::close(*fd);
                            // plaintext drops here; the Rust allocator may
                            // reuse the buffer post-execve but the child's
                            // address space is fully replaced at execve so
                            // a kernel-level scrub isn't required.
                        }
                        Ok(())
                    });
                }
            }

            command
                .output()
                .await
                .map_err(|e| (-32000, format!("spawn failed: {e}")))?
        };

        let exit_code = output.status.code().unwrap_or(-1);
        // Tail stdout/stderr for the JSON-RPC reply. stdout is preserved so
        // headless brokered commands (Claude/Codex/bash tool lanes) can still
        // surface useful command output when no PTY bridge is active.
        const STDOUT_TAIL_CAP: usize = 64 * 1024;
        const STDERR_TAIL_CAP: usize = 4096;
        let stdout_tail = capture_text_tail(&output.stdout, STDOUT_TAIL_CAP);
        let stderr_tail = capture_text_tail(&output.stderr, STDERR_TAIL_CAP);
        (exit_code, stdout_tail, stderr_tail)
    };

    let elapsed_ms = started_at.elapsed().as_millis() as u64;
    let success = exit_code == 0;

    // Emit receipt. Best-effort — log the event into the daemon's audit log.
    // Schema: session.construct_invocation per docs/receipt-format-v2.md.
    // Shim-EOF evidence (ADR 124 §"Shim-EOF correctness"): when the bridge
    // surfaced shim disappearance, attach `revoked_early` (SIGTERM path)
    // or `shim_disappeared_at` (drain path) for forensic visibility.
    //
    let mut details = serde_json::json!({
        "contract_id": contract_id,
        "binary": resolved_binary,
        "runner_binary_source": binary_source.as_str(),
        "construct_binary": construct_binary,
        "construct_binary_source": construct_binary_source.as_str(),
        "runner_class": runner_class_as_str(runner_class),
        "runner_cwd_source": cwd_source.as_str(),
        "argv_len": req.argv.len(),
        "exit_code": exit_code,
        "elapsed_ms": elapsed_ms,
        "pty": req.pty_socket_path.is_some(),
    });
    if let Some(session_id) = req.session_id.as_deref().filter(|s| !s.is_empty())
        && let Some(map) = details.as_object_mut()
    {
        map.insert(
            "session_id".to_string(),
            Value::String(session_id.to_string()),
        );
    }
    if let Some(map) = details.as_object_mut() {
        if let Some(execution_contract) = execution_contract.as_ref() {
            map.insert(
                "execution_contract".to_string(),
                serde_json::to_value(execution_contract).unwrap_or(Value::Null),
            );
        }
        map.insert(
            "action_ref".to_string(),
            serde_json::to_value(&action_ref).unwrap_or(Value::Null),
        );
        if let Some(calling_shim) = calling_shim.as_ref() {
            map.insert(
                "calling_shim".to_string(),
                Value::String(calling_shim.clone()),
            );
        }
        map.insert(
            "workspace_ref".to_string(),
            serde_json::to_value(workspace_ref.clone()).unwrap_or(Value::Null),
        );
        if let Some(subject_ref) = subject_ref.as_ref() {
            map.insert(
                "subject_ref".to_string(),
                Value::String(subject_ref.clone()),
            );
        }
        if let Some(coordination_ref) = coordination_ref.as_ref() {
            map.insert(
                "coordination_ref".to_string(),
                Value::String(coordination_ref.clone()),
            );
        }
        if let Some(caller_ref) = caller_ref.as_ref() {
            map.insert("caller_ref".to_string(), Value::String(caller_ref.clone()));
        }
        if let Some(authority_ref) = authority_ref.as_ref() {
            map.insert(
                "authority_ref".to_string(),
                Value::String(authority_ref.clone()),
            );
        }
        if let Some(action) = daemon_action.as_ref() {
            map.insert(
                "runner_action_key".to_string(),
                Value::String(action.clone()),
            );
        }
        match shim_outcome {
            ShimEofOutcome::ChildExitedFirst => {}
            ShimEofOutcome::RevokedEarly { at_unix_secs } => {
                map.insert("revoked_early".to_string(), Value::Bool(true));
                map.insert("revoked_early_at".to_string(), Value::from(at_unix_secs));
                map.insert(
                    "shim_eof_policy".to_string(),
                    Value::String("sigterm".to_string()),
                );
            }
            ShimEofOutcome::ShimDisappearedDrain { at_unix_secs } => {
                map.insert("shim_disappeared_at".to_string(), Value::from(at_unix_secs));
                map.insert(
                    "shim_eof_policy".to_string(),
                    Value::String("drain".to_string()),
                );
            }
        }
        // Record the env names
        // stripped by the per-action allowlist so forensic chains can see
        // what a buggy/hostile shim attempted to forward. Empty list is
        // omitted to keep Receipt JSON terse on the happy path.
        if !env_passthrough_stripped.is_empty() {
            map.insert(
                "env_passthrough_stripped".to_string(),
                Value::Array(
                    env_passthrough_stripped
                        .iter()
                        .map(|s| Value::String(s.clone()))
                        .collect(),
                ),
            );
        }
        // Record the materialization_id of
        // any credential the daemon minted for this exec so audit can
        // correlate exec → token life across the broker registry.
        if let Some((mat_id, provider)) = exec_credential.as_ref() {
            map.insert(
                "credential_materialization_id".to_string(),
                Value::String(mat_id.clone()),
            );
            map.insert(
                "credential_provider".to_string(),
                Value::String(provider.as_str().to_string()),
            );
        }
    }
    if let Err(e) = store.log_event(
        None, // persona_id; optional for system-emitted
        "session.construct_invocation",
        None, // credential_name; not directly applicable
        if success { "success" } else { "errored" },
        Some(&details.to_string()),
    ) {
        tracing::warn!(
            error = %e,
            "broker_exec: failed to record session.construct_invocation audit row"
        );
    }

    // Revoke any credential the daemon minted
    // for this exec. Best-effort — revoke failures are logged but don't
    // alter the response (the credential's TTL bound is the safety net).
    if let Some((mat_id, provider)) = exec_credential.as_ref() {
        revoke_minted_credential(mat_id, *provider).await;
    }

    let resp = BrokerExecResponse {
        exit_code,
        success,
        stdout_tail,
        stderr_tail,
        approval_required: false,
        approval_request_id: None,
    };
    let mut resp_value = serde_json::to_value(resp)
        .map_err(|e| (-32000, format!("serialize BrokerExecResponse: {e}")))?;
    if let Some(map) = resp_value.as_object_mut() {
        map.insert("contract_id".to_string(), Value::String(contract_id));
        if let Some(execution_contract) = execution_contract {
            map.insert(
                "execution_contract".to_string(),
                serde_json::to_value(execution_contract).unwrap_or(Value::Null),
            );
        }
        map.insert(
            "action_ref".to_string(),
            serde_json::to_value(action_ref).unwrap_or(Value::Null),
        );
        map.insert(
            "workspace_ref".to_string(),
            serde_json::to_value(workspace_ref).unwrap_or(Value::Null),
        );
        if let Some(subject_ref) = subject_ref {
            map.insert("subject_ref".to_string(), Value::String(subject_ref));
        }
        if let Some(coordination_ref) = coordination_ref {
            map.insert(
                "coordination_ref".to_string(),
                Value::String(coordination_ref),
            );
        }
        if let Some(caller_ref) = caller_ref {
            map.insert("caller_ref".to_string(), Value::String(caller_ref));
        }
        if let Some(authority_ref) = authority_ref {
            map.insert("authority_ref".to_string(), Value::String(authority_ref));
        }
    }
    Ok(resp_value)
}

#[cfg(test)]
mod sidecar_verification_tests {
    use super::*;
    use crate::infra::store::DaemonStore;
    use base64::Engine as _;

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        let mut seed = [0u8; 32];
        seed[0] = 0xa5;
        seed[31] = 0x5a;
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        debug_assert_ne!(
            sk.verifying_key().to_bytes(),
            crate::trust_graph::EMBER_SYSTEMS_PUBKEY_BYTES,
            "sidecar_verification_tests must not use the dev0 placeholder anchor"
        );
        sk
    }

    fn write_valid_sidecar(
        dir: &std::path::Path,
        binary_name: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> (String, String) {
        use ed25519_dalek::Signer as _;

        let binary_bytes = format!("fake-binary-content-{binary_name}").into_bytes();
        let toml_text = "[meta]\npublisher = \"did:test\"\nname = \"test-construct\"\n";
        let toml_bytes = toml_text.as_bytes();

        let binary_path = dir.join(binary_name);
        std::fs::write(&binary_path, &binary_bytes).unwrap();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&binary_bytes);
        hasher.update(toml_bytes);
        let blake3_hex = hex::encode(hasher.finalize().as_bytes());
        let blake3_field = format!("blake3:{blake3_hex}");

        let build_ts = "2026-05-05T13:42:08Z";
        let payload = serde_json::json!({
            "blake3": blake3_field,
            "build_ts": build_ts,
            "name": "test-construct",
            "publisher_did": "did:test",
            "version": "1.0.0",
        });
        let canonical = core_crypto::canonicalize_jcs(&payload).unwrap();
        let signature = signing_key.sign(&canonical);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        let sidecar = serde_json::json!({
            "schema_version": 1,
            "publisher_did": "did:test",
            "name": "test-construct",
            "version": "1.0.0",
            "blake3": blake3_field,
            "build_ts": build_ts,
            "signature": format!("ed25519:{sig_b64}"),
            "signature_alg": "ed25519"
        });
        let sig_path = dir.join(format!("{binary_name}.sig"));
        std::fs::write(&sig_path, serde_json::to_string_pretty(&sidecar).unwrap()).unwrap();

        (
            binary_path.to_string_lossy().into_owned(),
            toml_text.to_string(),
        )
    }

    #[test]
    fn no_sidecar_passes_through() {
        let store = DaemonStore::open_in_memory().unwrap();
        let result = verify_construct_sidecar("/nonexistent/binary", None, &store);
        assert!(result.is_ok(), "no sidecar must pass through: {result:?}");
    }

    #[test]
    fn sidecar_present_but_no_toml_returns_32041() {
        let dir = tempfile::tempdir().unwrap();
        let binary_path = dir.path().join("ember-test");
        std::fs::write(&binary_path, b"fake").unwrap();
        std::fs::write(dir.path().join("ember-test.sig"), "{}").unwrap();

        let store = DaemonStore::open_in_memory().unwrap();
        let result = verify_construct_sidecar(binary_path.to_str().unwrap(), None, &store);
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, -32041, "expected -32041, got {code}: {msg}");
    }

    #[test]
    fn valid_sidecar_with_delegation_passes() {
        let dir = tempfile::tempdir().unwrap();
        let sk = test_signing_key();
        let (binary_path, toml_text) = write_valid_sidecar(dir.path(), "ember-happy", &sk);

        let store = DaemonStore::open_in_memory().unwrap();
        let deleg = crate::trust_graph::PublisherTrustDelegation {
            id: "test-deleg".to_string(),
            publisher_did: "did:test".to_string(),
            pubkey_bytes: sk.verifying_key().to_bytes(),
            valid_from: 0,
            valid_until: None,
            installed_at: 1000,
            revoked_at: None,
        };
        store.install_publisher_trust(&deleg).unwrap();

        let result = verify_construct_sidecar(&binary_path, Some(&toml_text), &store);
        assert!(
            result.is_ok(),
            "valid sidecar + delegation must pass: {result:?}"
        );
    }

    #[test]
    fn valid_sidecar_without_delegation_returns_32040() {
        let dir = tempfile::tempdir().unwrap();
        let sk = test_signing_key();
        let (binary_path, toml_text) = write_valid_sidecar(dir.path(), "ember-no-deleg", &sk);

        let store = DaemonStore::open_in_memory().unwrap();
        let result = verify_construct_sidecar(&binary_path, Some(&toml_text), &store);
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, -32040, "expected -32040, got {code}: {msg}");
        assert!(
            msg.contains("publisher not trusted"),
            "error must name the trust failure: {msg}"
        );
    }

    #[test]
    fn tampered_binary_returns_32040_pin_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let sk = test_signing_key();
        let (binary_path, toml_text) = write_valid_sidecar(dir.path(), "ember-tampered", &sk);

        std::fs::write(&binary_path, b"tampered-content").unwrap();

        let store = DaemonStore::open_in_memory().unwrap();
        let deleg = crate::trust_graph::PublisherTrustDelegation {
            id: "test-deleg".to_string(),
            publisher_did: "did:test".to_string(),
            pubkey_bytes: sk.verifying_key().to_bytes(),
            valid_from: 0,
            valid_until: None,
            installed_at: 1000,
            revoked_at: None,
        };
        store.install_publisher_trust(&deleg).unwrap();

        let result = verify_construct_sidecar(&binary_path, Some(&toml_text), &store);
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, -32040, "expected -32040, got {code}: {msg}");
        assert!(
            msg.contains("binary_pin_mismatch"),
            "error must name the pin mismatch: {msg}"
        );
    }

    #[test]
    fn revoked_delegation_returns_32040() {
        let dir = tempfile::tempdir().unwrap();
        let sk = test_signing_key();
        let (binary_path, toml_text) = write_valid_sidecar(dir.path(), "ember-revoked", &sk);

        let store = DaemonStore::open_in_memory().unwrap();
        let deleg = crate::trust_graph::PublisherTrustDelegation {
            id: "revoked-deleg".to_string(),
            publisher_did: "did:test".to_string(),
            pubkey_bytes: sk.verifying_key().to_bytes(),
            valid_from: 0,
            valid_until: None,
            installed_at: 1000,
            revoked_at: Some(1735000000),
        };
        store.install_publisher_trust(&deleg).unwrap();

        let result = verify_construct_sidecar(&binary_path, Some(&toml_text), &store);
        let (code, _msg) = result.unwrap_err();
        assert_eq!(code, -32040, "revoked delegation must fail with -32040");
    }

    #[test]
    fn revoke_delegation_immediately_fails_without_cache_invalidation() {
        let dir = tempfile::tempdir().unwrap();
        let sk = test_signing_key();
        let (binary_path, toml_text) =
            write_valid_sidecar(dir.path(), "ember-revoke-regression", &sk);

        let store = DaemonStore::open_in_memory().unwrap();
        let deleg = crate::trust_graph::PublisherTrustDelegation {
            id: "regression-deleg".to_string(),
            publisher_did: "did:test".to_string(),
            pubkey_bytes: sk.verifying_key().to_bytes(),
            valid_from: 0,
            valid_until: None,
            installed_at: 1000,
            revoked_at: None,
        };
        store.install_publisher_trust(&deleg).unwrap();

        let result = verify_construct_sidecar(&binary_path, Some(&toml_text), &store);
        assert!(result.is_ok(), "first verify must pass: {result:?}");

        // Revoke the delegation through the store API — NO explicit cache
        // invalidation between here and the next verify call.
        let revoked = store
            .revoke_publisher_trust("regression-deleg", 1735500000)
            .unwrap();
        assert!(revoked, "revocation must succeed");

        // The binary-hash cache still has the file entry (the binary hasn't
        // changed), but the trust-state read is fresh — the revoked delegation
        // must cause an immediate verification failure.
        let result = verify_construct_sidecar(&binary_path, Some(&toml_text), &store);
        let (code, msg) = result.expect_err("revoked delegation must fail on re-verify");
        assert_eq!(code, -32040, "expected -32040, got {code}: {msg}");

        // The binary-hash cache entry is still valid — failure came from
        // fresh trust-state reads, not from cache invalidation.
        let bp = std::path::Path::new(&binary_path);
        let meta = std::fs::metadata(bp).unwrap();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let cached = crate::signature_verifier::verifier_cache().get(bp, mtime, meta.len());
        assert!(
            cached.is_some(),
            "binary-hash cache entry must still be present"
        );
    }
}
