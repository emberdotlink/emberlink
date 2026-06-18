use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use core_event_types::{ActionRef, ExecutionContract};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::binary_manifest::BinaryManifest;
use crate::broker::runners::runner_class_as_str;

use super::current_manifest;

static LEGACY_EXECUTION_CONTRACT_MIRROR_SEEN: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Binary pin verification (ADR 124 §7)
// ---------------------------------------------------------------------------

/// A verified pinned binary — the daemon trusts this path's bytes
/// match the manifest's recorded content_hash AT THE TIME OF VERIFY.
/// `broker_exec` should call `verify_binary_pin` IMMEDIATELY before
/// spawn (TOCTOU window minimization).
#[derive(Debug, Clone)]
pub struct PinnedBinary {
    pub path: PathBuf,
    pub content_hash: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("tool '{0}' not in manifest")]
    NotInManifest(String),
    #[error("binary_pin_mismatch: expected={expected} actual={actual} path={path:?}")]
    HashMismatch {
        expected: String,
        actual: String,
        path: PathBuf,
    },
    #[error("io reading binary: {0}")]
    Io(String),
}

/// Verify that the on-disk binary at `manifest[tool].absolute_path`
/// hashes to `manifest[tool].content_hash` per ADR 124 §7.
///
/// Reads binary bytes (mmap optimization deferred — `std::fs::read` is
/// fine for v1 since binaries are typically <100 MB), recomputes
/// blake3, compares to the manifest's recorded hash. Returns
/// `PinError::HashMismatch` on divergence (caller emits the
/// `binary_pin_mismatch` Receipt).
pub fn verify_binary_pin(manifest: &BinaryManifest, tool: &str) -> Result<PinnedBinary, PinError> {
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.tool_name == tool)
        .ok_or_else(|| PinError::NotInManifest(tool.to_string()))?;

    let bytes = std::fs::read(&entry.absolute_path).map_err(|e| PinError::Io(e.to_string()))?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(&bytes);
    let computed = hex::encode(hasher.finalize().as_bytes());

    let expected = entry
        .content_hash
        .strip_prefix("blake3:")
        .unwrap_or(&entry.content_hash);

    if computed != expected {
        return Err(PinError::HashMismatch {
            expected: expected.to_string(),
            actual: computed,
            path: entry.absolute_path.clone(),
        });
    }

    Ok(PinnedBinary {
        path: entry.absolute_path.clone(),
        content_hash: format!("blake3:{computed}"),
        bytes,
    })
}

/// Look up `(tool_name, publisher)` for a given binary path by scanning
/// the bundled-install manifest. Returns `None` when the manifest is
/// missing, unreadable, or does not contain an entry whose
/// `absolute_path` matches `binary_path`.
///
/// Best-effort surface used by the `session.construct_invocation`
/// Receipt emitter to attach `tool_name` + `publisher` fields per ADR
/// 135 §4 (action-key DID-prefix migration). The caller can then
/// reconstruct the fully-qualified action key downstream once the
/// argv classifier names which `[actions.X]` block was invoked.
///
/// Loads the manifest fresh on every call. The cost is one TOML parse
/// per `broker_exec` Receipt emission; cohort A is ~7 entries so the
/// parse is sub-millisecond. A daemon-global cached manifest is the
/// natural follow-up but not required for correctness.
pub(super) fn lookup_binary_in_manifest(binary_path: &str) -> Option<(String, String)> {
    // Prefer the process-global
    // manifest loaded at startup (runtime.rs PATH-PINNING-STARTUP-VERIFY).
    // That loader honors an explicit startup manifest path, then the system
    // path `/usr/local/lib/ember/binaries/manifest.toml`.
    // Fall through to a fresh disk read of the system path only if the global
    // was never installed (defense-in-depth — same path the legacy
    // implementation used).
    //
    // Path normalization: `ember binary install` stores the canonical path
    // (via `Path::canonicalize`); construct shims resolve binaries via PATH
    // and send the un-canonical path (e.g. `/opt/homebrew/bin/gh` →
    // canonical `/opt/homebrew/Cellar/gh/2.89.0/bin/gh`). Compare both
    // forms so a symlinked PATH entry matches its canonical manifest entry.
    let canon = std::fs::canonicalize(binary_path)
        .map(|p| p.as_os_str().to_owned())
        .ok();
    let matches = |e: &crate::binary_manifest::BinaryManifestEntry| -> bool {
        if e.absolute_path.as_os_str() == binary_path {
            return true;
        }
        if let Some(c) = canon.as_ref()
            && e.absolute_path.as_os_str() == c.as_os_str()
        {
            return true;
        }
        false
    };
    if let Some(manifest) = current_manifest() {
        let entry = manifest.entries.iter().find(|e| matches(e))?;
        return Some((entry.tool_name.clone(), entry.publisher.clone()));
    }
    let manifest_path = crate::binary_manifest::bundled_install_dir().join("manifest.toml");
    let manifest = crate::binary_manifest::load_manifest(&manifest_path).ok()?;
    let entry = manifest.entries.iter().find(|e| matches(e))?;
    Some((entry.tool_name.clone(), entry.publisher.clone()))
}

// ---------------------------------------------------------------------------
// L1 authoring mode — dev-path registry
// (ADRs 124 + 135)
// ---------------------------------------------------------------------------

/// Parsed `~/.ember/authoring-paths.toml`. Mirrors the CLI-side schema in
/// `emberlink-cli::construct::dev::AuthoringPaths` — kept duplicated here
/// rather than introducing a daemon→cli dep so the daemon can be built
/// without pulling the CLI in.
#[derive(Debug, Default, Deserialize)]
pub struct AuthoringPathsRegistry {
    #[serde(default)]
    pub paths: Vec<PathBuf>,
}

/// Default location of the authoring-paths registry. Lives under `$HOME`
/// so the file is owned by the running uid; mode 0600 is set by the
/// CLI's `save_registry` and verified at load time.
pub fn authoring_paths_registry_path() -> Option<PathBuf> {
    dirs_next::home_dir().map(|h| h.join(".ember").join("authoring-paths.toml"))
}

/// Load the on-disk authoring-paths registry. Returns an empty registry
/// when the file does not exist (every end-user install starts with
/// zero registered paths — this is the "refuse unsigned scripts"
/// default the spec requires).
///
/// Best-effort: parse failures are logged + degraded to empty so the
/// daemon never trusts a corrupt registry. Authors who care must inspect
/// the daemon log when they registered a path and the daemon doesn't
/// honor it.
pub fn load_authoring_paths_registry(path: &std::path::Path) -> AuthoringPathsRegistry {
    if !path.exists() {
        return AuthoringPathsRegistry::default();
    }
    let s = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "authoring_paths: read failed; refusing all unsigned scripts"
            );
            return AuthoringPathsRegistry::default();
        }
    };
    match toml::from_str::<AuthoringPathsRegistry>(&s) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "authoring_paths: parse failed; refusing all unsigned scripts"
            );
            AuthoringPathsRegistry::default()
        }
    }
}

/// Returns true when `script_path` resides under any registered authoring
/// path — the daemon's gate for honoring `broker.resolve` from authoring
/// mode. End-user installs (registry empty / file missing) never match,
/// so the daemon refuses unsigned scripts structurally.
pub fn script_is_in_authoring_path(
    registry: &AuthoringPathsRegistry,
    script_path: &std::path::Path,
) -> bool {
    let canonical = match std::fs::canonicalize(script_path) {
        Ok(p) => p,
        Err(_) => script_path.to_path_buf(),
    };
    registry
        .paths
        .iter()
        .any(|registered| canonical.starts_with(registered))
}

// ---------------------------------------------------------------------------
// Daemon-side argv re-classification (ADR 124)
// ---------------------------------------------------------------------------

/// Daemon-side argv re-classification per
/// `docs/adversarial/2026-05-07-daemon-supervisor-vs-shim-supervisor.md` axis
/// E1. The daemon does NOT trust the shim's `claimed_action`; it resolves the
/// binary path to a known cohort-A tool via the manifest's `tool_name` and
/// invokes the matching argv classifier from `ember-construct-classify`.
///
/// Returns `Some(action_key)` like `"gh.pr_create"` when the binary is a
/// known cohort-A tool whose classifier recognizes the verb pair; `None`
/// when the binary isn't in the manifest, the tool isn't a cohort-A tool,
/// or the classifier rejects the argv shape.
///
/// Tool-name dispatch covers cohort A: `ember-gh`, `ember-git`, `ember-kubectl`
/// (the bundled wrapper names — bare `gh`/`git`/`kubectl` would still go
/// through this path when their manifest tool_name matches the bundled
/// publisher's tool stub).
pub fn classify_argv_daemon_side(tool_name: &str, argv: &[String]) -> Option<String> {
    use core_construct_runtime::ClassifyArgv;

    // Strip the `ember-` prefix so the bundled wrapper name maps onto the
    // cohort-A classifier crate's per-tool dispatch. Manifest entries today
    // record `ember-gh`/`ember-git`/`ember-kubectl`; the classifiers key
    // off `gh.<verb>` / `git.<verb>` / `kubectl.<verb>` action keys.
    let normalized = tool_name.strip_prefix("ember-").unwrap_or(tool_name);

    let key = match normalized {
        "gh" => ember_construct::GhClassifier.classify(argv)?,
        "git" => ember_construct::GitClassifier.classify(argv)?,
        "kubectl" => ember_construct::KubectlClassifier.classify(argv)?,
        _ => return None,
    };

    Some(key.0)
}

pub(super) fn known_wrapped_tool_name_from_binary_path(binary_path: &str) -> Option<String> {
    let basename = std::path::Path::new(binary_path)
        .file_name()?
        .to_string_lossy();
    let normalized = basename.strip_prefix("ember-").unwrap_or(&basename);
    match normalized {
        "gh" | "git" | "kubectl" => Some(normalized.to_string()),
        _ => None,
    }
}

pub(super) fn daemon_classification_tool_name(
    binary_path: &str,
    manifest_lookup: Option<&(String, String)>,
) -> Option<String> {
    manifest_lookup
        .map(|(tool_name, _publisher)| tool_name.clone())
        .or_else(|| known_wrapped_tool_name_from_binary_path(binary_path))
}

pub(super) fn runner_action_matches_authority_action(
    runner_action: &str,
    authority_action_key: &str,
    tool_name: Option<&str>,
) -> bool {
    if runner_action == authority_action_key {
        return true;
    }

    let Some(tool_name) = tool_name else {
        return false;
    };
    let normalized = tool_name.strip_prefix("ember-").unwrap_or(tool_name);
    runner_action
        .strip_prefix(normalized)
        .and_then(|suffix| suffix.strip_prefix('.'))
        == Some(authority_action_key)
}

pub(super) fn append_ephemeral_git_config_entry(
    env: &mut std::collections::HashMap<String, String>,
    key: &str,
    value: &str,
) {
    let index = env
        .get("GIT_CONFIG_COUNT")
        .and_then(|count| count.parse::<usize>().ok())
        .unwrap_or(0);
    env.insert("GIT_CONFIG_COUNT".to_string(), (index + 1).to_string());
    env.insert(format!("GIT_CONFIG_KEY_{index}"), key.to_string());
    env.insert(format!("GIT_CONFIG_VALUE_{index}"), value.to_string());
}

pub(super) fn inject_ephemeral_git_safe_directory(
    env: &mut std::collections::HashMap<String, String>,
    binary_path: &str,
) {
    // Host broker_exec runs git-family tools under a pool uid distinct from
    // the operator's uid. Git therefore treats ordinary operator-owned repos
    // as dubious unless we provide an ephemeral safe.directory override. Keep
    // the override process-local to this child; do not mutate host gitconfig.
    if matches!(
        known_wrapped_tool_name_from_binary_path(binary_path).as_deref(),
        Some("gh" | "git")
    ) {
        append_ephemeral_git_config_entry(env, "safe.directory", "*");
    }
}

/// Extract the remote-name positional from a daemon-side tool invocation.
///
/// Sibling to [`classify_argv_daemon_side`]. Calls
/// [`ember_construct::git::extract_git_remote_name`] for `git`-family tools
/// when the action is one that carries a remote-name positional
/// (push, fetch, pull, clone). Returns `None` for all other tools and verbs.
///
/// This is intentionally separate from `classify_argv_daemon_side` so
/// `handle_broker_exec` can call it without changing the classifier's
/// existing return type or cascading through its call sites.
pub fn extract_remote_name_daemon_side(tool_name: &str, argv: &[String]) -> Option<String> {
    let normalized = tool_name.strip_prefix("ember-").unwrap_or(tool_name);
    if normalized != "git" {
        return None;
    }
    // argv[0] is the git subcommand (verb); rest is argv[1..].
    let verb = argv.first()?;
    ember_construct::git::extract_git_remote_name(verb.as_str(), &argv[1..])
}
// ---------------------------------------------------------------------------
// BrokerExecRequest / BrokerExecResponse — `broker_exec` wire shapes
// ---------------------------------------------------------------------------

/// Wire shape for `broker_exec` RPC params.
#[derive(Debug, serde::Deserialize)]
pub struct BrokerExecRequest {
    /// Authority-side execution contract. This is the canonical Phase B seam.
    /// The top-level mirror fields below remain legacy-only compatibility and
    /// will be removed in Phase C once remaining callers are cut over.
    #[serde(default)]
    pub execution_contract: Option<ExecutionContract>,
    /// Authority-minted execution-contract identifier. On the resolve → exec
    /// path this is minted by `broker_resolve`; direct shim callers may leave
    /// it unset and let `broker_exec` mint a best-effort id for receipt truth.
    #[serde(default)]
    pub contract_id: Option<String>,
    /// Canonical authority-side action identity.
    #[serde(default)]
    pub action_ref: Option<ActionRef>,
    /// Logical workspace handle, never a raw cwd path.
    #[serde(default)]
    pub workspace_ref: Option<String>,
    /// Explicit compatibility-only cwd fallback for construct shims running
    /// without a logical workspace handle. This is transitional and should
    /// only appear when the launcher/runtime cannot populate `workspace_ref`.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Requesting caller/session/persona identity in authority space.
    #[serde(default)]
    pub caller_ref: Option<String>,
    /// Grant or authority binding used for approval.
    #[serde(default)]
    pub authority_ref: Option<String>,
    /// CLI argv (does NOT include argv[0]).
    pub argv: Vec<String>,
    /// Subset of host env vars the child should inherit beyond the allowlist
    /// (PATH, HOME, USER, LANG, TERM). Transitional runner-local coordinate;
    /// each entry must match `^[A-Z_][A-Z0-9_]*$` shape.
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    /// When present, the daemon allocates a pty pair via forkpty, attaches
    /// the slave fd to the child's stdin/stdout/stderr, and calls
    /// `pty_bridge_run` with the master fd + this UDS path. The agent must
    /// be listening on this socket before sending the RPC; the daemon
    /// connects immediately after fork. Absence falls through to the
    /// non-PTY (piped) spawn path.
    #[serde(default)]
    pub pty_socket_path: Option<String>,
    /// Legacy SSH-agent request bit. ADR 214 requires SSH signing to flow
    /// through the lease-gated `SshAgentBridge`; `broker_exec` must not satisfy
    /// this by spawning a raw daemon-managed agent in the child environment.
    /// The handler currently refuses this flag until the brokered host-client /
    /// forwarder substrate lands.
    #[serde(default)]
    pub ssh_agent: bool,
    /// Per-action shim-EOF policy, sourced from `construct.toml`'s
    /// `[actions.<name>].on_shim_eof` field (ADR 124 §"Shim-EOF
    /// correctness"). Allowed values:
    ///
    /// - `"sigterm"` (default) — daemon SIGTERMs the spawned child within
    ///   1s if the shim's UDS connection EOFs before the child exits.
    /// - `"drain"` — daemon lets the child run to natural completion
    ///   (e.g. `pulumi up` where mid-run interruption corrupts state);
    ///   the disappearance is recorded as `shim_disappeared_at` on the
    ///   `session.construct_invocation` Receipt for forensic visibility.
    #[serde(default)]
    pub on_shim_eof: Option<String>,
    /// Caller-claimed action key for the invocation, e.g. `gh.pr_create`.
    /// The daemon re-classifies argv server-side via
    /// [`classify_argv_daemon_side`] and
    /// refuses with `argv_classification_mismatch` if the daemon's
    /// classification disagrees. Optional — when omitted, the daemon
    /// records the daemon-classified action without a mismatch check
    /// (the shim-supervisor pre-cohort path).
    #[serde(default)]
    pub claimed_action: Option<String>,
    /// Per-action env-passthrough allowlist sourced from
    /// `construct.toml::[actions.<X>].env_passthrough`. The daemon strips
    /// any name in `env_passthrough` that is NOT in this allowlist before
    /// fork+execve, and records the strip count on the Receipt under
    /// `env_passthrough_stripped`. ADR 124 axis A2. When omitted, the strip path is a no-op
    /// (preserves the pre-A2 behavior for shims that don't yet emit this
    /// field). Empty list (`Some(vec![])`) is the strict "deny all
    /// passthrough" mode and strips every entry.
    #[serde(default)]
    pub action_env_allowlist: Option<Vec<String>>,
    /// Raw bytes of the Construct's `construct.toml` manifest, base64-
    /// encoded for JSON wire safety. The daemon decodes + parses via
    /// [`core_events::construct_toml::parse_and_validate`] and consults
    /// the manifest's `[actions.*]` table to enforce the action-level
    /// policy gate. When
    /// omitted, the manifest gate is skipped (preserves pre-policy
    /// behavior for shims that don't yet emit this field).
    #[serde(default)]
    pub construct_toml_bytes: Option<String>,
    /// When set, the spawn
    /// target lives inside an agent SCION container and emberd dispatches
    /// the binary via the in-container `ember-exec` listener at this UDS
    /// path (host-side absolute path bound into the container at the
    /// canonical `/run/emberd/agent-<uuid>.sock`). The daemon opens
    /// a `UnixStream` to the listener, writes a
    /// `ExecFrame::SpawnDirective`, then drives the bidirectional
    /// pty-frame proxy until the child exits.
    ///
    /// When `None`, the daemon spawns the binary directly on the host
    /// via the existing fork-exec / forkpty path. The two paths are
    /// mutually exclusive: in-container exec carries its own hash-verify
    /// and privilege drop on the receiver side (subtask C), so the
    /// host-side path stays the only `pty_socket_path` consumer.
    #[serde(default)]
    pub scion_exec_socket: Option<String>,
    /// Target uid the in-container
    /// `ember-exec` receiver drops privileges to before `execve` (subtask
    /// B's `drop_privileges`). Ignored when `scion_exec_socket` is `None`.
    /// Defaults to `0`: the receiver-side handler treats uid 0 as "no
    /// privilege drop" so the same code path works in dev / test runs
    /// before the operator wires real per-container uids.
    #[serde(default)]
    pub scion_target_uid: u32,
    /// Target gid companion to
    /// `scion_target_uid`. Same uid=0 / dev-default semantics.
    #[serde(default)]
    pub scion_target_gid: u32,
    /// Opaque spawn-handle reference minted by `broker_resolve` for the
    /// SCION shim resolve path.
    /// The daemon uses this to look up the `PendingSpawnHandle` and enforce
    /// the `SPAWN_HANDLE_TTL_SECS` deadline.
    /// When absent the TTL gate is a no-op (legacy / non-SCION exec paths).
    #[serde(default)]
    pub secret_ref: Option<String>,
    /// Real launcher session id carried by brokered construct shims.
    /// When present, the daemon can correlate broker_exec receipts and
    /// per-session side effects (for example the daemon-managed ssh-agent)
    /// with the launcher-opened session instead of minting an unrelated
    /// synthetic id.
    #[serde(default)]
    pub session_id: Option<String>,
}

pub(super) fn warn_ignored_execution_contract_mirror_fields(params: &Value, rpc_method: &str) {
    let mut saw_legacy_mirror = false;
    for field in [
        "contract_id",
        "action_ref",
        "workspace_ref",
        "subject_ref",
        "coordination_ref",
        "caller_ref",
        "authority_ref",
    ] {
        if params.get(field).is_some() {
            saw_legacy_mirror = true;
            tracing::warn!(
                rpc_method,
                deprecated_field = field,
                "deprecated top-level execution_contract mirror ignored; nested execution_contract is authoritative"
            );
        }
    }
    if saw_legacy_mirror && !LEGACY_EXECUTION_CONTRACT_MIRROR_SEEN.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            rpc_method,
            "deprecated top-level execution_contract mirrors observed for the first time; nested execution_contract is the only authority surface"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NestedExecutionContractRequirement {
    Optional,
    Required,
}

pub(super) fn validate_nested_execution_contract_wire_shape(
    params: &Value,
    rpc_method: &str,
    requirement: NestedExecutionContractRequirement,
) -> Result<(), (i32, String)> {
    let Some(execution_contract) = params.get("execution_contract") else {
        if matches!(requirement, NestedExecutionContractRequirement::Required) {
            return Err((-32602, format!("{rpc_method} missing_execution_contract")));
        }
        return Ok(());
    };
    let Some(contract) = execution_contract.as_object() else {
        return Err((
            -32602,
            format!("{rpc_method} execution_contract must be a JSON object"),
        ));
    };

    for field in [
        "schema_version",
        "action_ref",
        "materialization_policy",
        "runner_policy",
        "topology_policy",
        "interaction_class",
        "lease_policy",
        "audit_policy",
    ] {
        if !contract.contains_key(field) {
            return Err((
                -32602,
                format!("{rpc_method} execution_contract missing required field {field}"),
            ));
        }
    }

    let Some(runner_policy) = contract.get("runner_policy").and_then(Value::as_object) else {
        return Err((
            -32602,
            format!("{rpc_method} execution_contract.runner_policy must be a JSON object"),
        ));
    };
    let Some(allowed) = runner_policy.get("allowed").and_then(Value::as_array) else {
        return Err((
            -32602,
            format!("{rpc_method} execution_contract.runner_policy.allowed must be present"),
        ));
    };
    if allowed.is_empty() {
        return Err((
            -32602,
            format!("{rpc_method} execution_contract.runner_policy.allowed must not be empty"),
        ));
    }
    if runner_policy
        .get("preferred")
        .and_then(Value::as_array)
        .is_none()
    {
        return Err((
            -32602,
            format!("{rpc_method} execution_contract.runner_policy.preferred must be present"),
        ));
    }

    Ok(())
}

pub(super) fn inherit_execution_contract_from_resolve(
    request_contract: ExecutionContract,
    resolved_contract: &ExecutionContract,
) -> Result<ExecutionContract, (i32, String)> {
    if request_contract != *resolved_contract {
        return Err((
            -32602,
            format!(
                "broker_exec execution_contract does not match resolved handle: {:?} != {:?}",
                request_contract, resolved_contract
            ),
        ));
    }
    Ok(request_contract)
}

/// Response shape for `broker_exec`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BrokerExecResponse {
    /// Exit code; -1 if the child was terminated by signal.
    pub exit_code: i32,
    /// True iff exit_code == 0.
    pub success: bool,
    /// Truncated stdout (last 64 KiB) for headless brokered commands.
    /// Empty on PTY and spawn-helper paths where output is streamed or
    /// otherwise unavailable to the RPC reply.
    pub stdout_tail: String,
    /// Truncated stderr (last 4 KiB) for diagnostics. Stdout is NOT
    /// interleaved with stderr — the non-PTY path returns the two streams
    /// separately and the construct runtime replays them to the caller.
    pub stderr_tail: String,
    /// Attachment-local one-shot approval gate. When true, the daemon has not
    /// spawned the child yet; callers should poll `grant_status` for the
    /// attached `approval_request_id` and retry the same broker_exec after the
    /// row becomes `approved`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub approval_required: bool,
    /// Approval row to poll when `approval_required == true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub(super) fn reject_legacy_broker_resolve_fields(params: &Value) -> Result<(), (i32, String)> {
    if params
        .get("lease_request")
        .and_then(|lease| lease.get("binary"))
        .is_some()
    {
        return Err((
            -32602,
            "broker_resolve legacy lease_request.binary is no longer accepted; send lease_request.action_ref and execution_contract.action_ref"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) fn reject_legacy_broker_exec_fields(params: &Value) -> Result<(), (i32, String)> {
    if params.get("binary").is_some() {
        return Err((
            -32602,
            "broker_exec legacy binary is no longer accepted; send execution_contract.action_ref"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) fn capture_text_tail(bytes: &[u8], cap: usize) -> String {
    let full = String::from_utf8_lossy(bytes);
    if full.len() > cap {
        format!(
            "...[{} bytes truncated]...{}",
            full.len() - cap,
            &full[full.len() - cap..]
        )
    } else {
        full.into_owned()
    }
}

pub(super) const APPROVAL_BINDING_PENDING_TTL_SECS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConstructExecPolicy {
    Permit,
    Prompt,
    Deny,
}

#[derive(Debug, Deserialize)]
struct ConstructExecPolicyManifest {
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    actions: Vec<ConstructExecPolicyAction>,
}

#[derive(Debug, Deserialize)]
struct ConstructExecPolicyAction {
    key: String,
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    mode: Option<String>,
}

pub(super) fn parse_construct_exec_policy(
    manifest_text: &str,
    action_key: &str,
) -> Result<ConstructExecPolicy, (i32, String)> {
    let manifest: ConstructExecPolicyManifest = toml::from_str(manifest_text).map_err(|e| {
        (
            -32602,
            format!("construct_toml_bytes policy parse failed: {e}"),
        )
    })?;
    let action = manifest
        .actions
        .iter()
        .find(|action| action.key == action_key);
    let fallback_policy = action
        .and_then(|action| action.default.as_deref())
        .or(manifest.default.as_deref())
        .unwrap_or("permit");
    let raw_policy = match action.and_then(|action| action.mode.as_deref()) {
        // Live bundled construct manifests use `mode = "gate"` as the old
        // broker-mediated carrier flag. It is not the approval decision itself;
        // keep the decision on the adjacent/default policy field.
        Some("gate") | None => fallback_policy,
        Some(mode) => mode,
    };
    match raw_policy {
        "permit" | "auto_approve" | "auto_approve_if_pregranted" => Ok(ConstructExecPolicy::Permit),
        "prompt" | "jit_approval" => Ok(ConstructExecPolicy::Prompt),
        "deny" => Ok(ConstructExecPolicy::Deny),
        other => Err((
            -32602,
            format!("unsupported construct exec policy for {action_key}: {other}"),
        )),
    }
}

fn sha256_hex_value(value: &Value) -> Result<String, (i32, String)> {
    let canonical = serde_json::to_vec(value).map_err(|e| {
        (
            -32000,
            format!("serialize approval binding digest payload: {e}"),
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn sha256_hex_text(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

pub(super) fn execution_contract_digest(
    execution_contract: &ExecutionContract,
) -> Result<String, (i32, String)> {
    let mut canonical = execution_contract.clone();
    canonical.contract_id = None;
    let value = serde_json::to_value(canonical).map_err(|e| {
        (
            -32000,
            format!("serialize execution contract for digest: {e}"),
        )
    })?;
    sha256_hex_value(&value)
}

pub(super) fn invocation_plan_digest(
    runner_class: core_event_types::RunnerClass,
    resolved_binary: &str,
    cwd: &str,
    argv: &[String],
    env_passthrough_filtered: &[String],
) -> Result<String, (i32, String)> {
    let payload = json!({
        "runner_class": runner_class_as_str(runner_class),
        "binary": resolved_binary,
        "cwd": cwd,
        "argv": argv,
        "env_passthrough": env_passthrough_filtered,
    });
    sha256_hex_value(&payload)
}

pub(super) fn approval_binding_scope(attachment_id: &str, invocation_digest: &str) -> String {
    format!("approval_binding:{attachment_id}:{invocation_digest}")
}

// RPC/plumbing signature — structurally many params; refactor would touch call sites in other files.
#[allow(clippy::too_many_arguments)]
pub(super) fn approval_required_response(
    contract_id: &str,
    execution_contract: Option<&ExecutionContract>,
    action_ref: &ActionRef,
    workspace_ref: Option<&str>,
    subject_ref: Option<&str>,
    coordination_ref: Option<&str>,
    caller_ref: Option<&str>,
    authority_ref: Option<&str>,
    approval_request_id: &str,
) -> Result<Value, (i32, String)> {
    let mut resp_value = serde_json::to_value(BrokerExecResponse {
        exit_code: 0,
        success: false,
        stdout_tail: String::new(),
        stderr_tail: String::new(),
        approval_required: true,
        approval_request_id: Some(approval_request_id.to_string()),
    })
    .map_err(|e| {
        (
            -32000,
            format!("serialize approval-required BrokerExecResponse: {e}"),
        )
    })?;
    let Some(map) = resp_value.as_object_mut() else {
        return Err((
            -32000,
            "serialize approval-required BrokerExecResponse returned non-object".to_string(),
        ));
    };
    map.insert(
        "contract_id".to_string(),
        Value::String(contract_id.to_string()),
    );
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
        map.insert(
            "subject_ref".to_string(),
            Value::String(subject_ref.to_string()),
        );
    }
    if let Some(coordination_ref) = coordination_ref {
        map.insert(
            "coordination_ref".to_string(),
            Value::String(coordination_ref.to_string()),
        );
    }
    if let Some(caller_ref) = caller_ref {
        map.insert(
            "caller_ref".to_string(),
            Value::String(caller_ref.to_string()),
        );
    }
    if let Some(authority_ref) = authority_ref {
        map.insert(
            "authority_ref".to_string(),
            Value::String(authority_ref.to_string()),
        );
    }
    Ok(resp_value)
}

#[cfg(test)]
mod tests {
    //! T2: binary-pin unit tests use temporary files as local fixture binaries.

    use super::*;

    #[test]
    fn verify_binary_pin_matches_correct_hash() {
        use crate::binary_manifest::{
            BinaryDistributionChannel, BinaryManifest, BinaryManifestEntry,
        };
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut f = NamedTempFile::new().expect("temp");
        f.write_all(b"hello world test binary").expect("write");
        let path = f.path().to_path_buf();

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hello world test binary");
        let expected = hex::encode(hasher.finalize().as_bytes());

        let manifest = BinaryManifest {
            entries: vec![BinaryManifestEntry {
                tool_name: "test-tool".to_string(),
                version: "1.0.0".to_string(),
                content_hash: format!("blake3:{expected}"),
                absolute_path: path.clone(),
                installed_at: 0,
                publisher: "did:test".to_string(),
                channel: BinaryDistributionChannel::Bundled,
            }],
        };

        let result = verify_binary_pin(&manifest, "test-tool").expect("should match");
        assert_eq!(result.path, path);
    }

    #[test]
    fn verify_binary_pin_detects_mismatch() {
        use crate::binary_manifest::{
            BinaryDistributionChannel, BinaryManifest, BinaryManifestEntry,
        };
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut f = NamedTempFile::new().expect("temp");
        f.write_all(b"actual bytes").expect("write");

        let manifest = BinaryManifest {
            entries: vec![BinaryManifestEntry {
                tool_name: "test-tool".to_string(),
                version: "1.0.0".to_string(),
                content_hash:
                    "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                absolute_path: f.path().to_path_buf(),
                installed_at: 0,
                publisher: "did:test".to_string(),
                channel: BinaryDistributionChannel::Bundled,
            }],
        };

        match verify_binary_pin(&manifest, "test-tool") {
            Err(PinError::HashMismatch {
                expected, actual, ..
            }) => {
                assert_eq!(
                    expected,
                    "0000000000000000000000000000000000000000000000000000000000000000"
                );
                assert_ne!(actual, expected);
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_binary_pin_unknown_tool_returns_not_in_manifest() {
        use crate::binary_manifest::BinaryManifest;

        let manifest = BinaryManifest::default();
        match verify_binary_pin(&manifest, "ghost-tool") {
            Err(PinError::NotInManifest(s)) => assert_eq!(s, "ghost-tool"),
            other => panic!("expected NotInManifest, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------------
    // Daemon-side argv re-classification
    // ---------------------------------------------------------------------

    #[test]
    fn classify_argv_daemon_side_recognizes_gh_pr_create() {
        let action = classify_argv_daemon_side(
            "ember-gh",
            &[
                "pr".to_string(),
                "create".to_string(),
                "--title".to_string(),
            ],
        );
        assert_eq!(action.as_deref(), Some("gh.pr_create"));
    }

    #[test]
    fn classify_argv_daemon_side_recognizes_gh_repo_delete() {
        // Hostile shim sends `argv=["repo","delete","--yes"]` while
        // claiming `pr_create`. The daemon's classifier sees `repo_delete`.
        let action = classify_argv_daemon_side(
            "ember-gh",
            &[
                "repo".to_string(),
                "delete".to_string(),
                "--yes".to_string(),
            ],
        );
        assert_eq!(action.as_deref(), Some("gh.repo_delete"));
    }

    #[test]
    fn classify_argv_daemon_side_recognizes_bare_tool_name() {
        // Manifest entries written by older daemons may use the bare
        // tool name (no `ember-` prefix) - both must work.
        let action = classify_argv_daemon_side(
            "git",
            &["push".to_string(), "origin".to_string(), "main".to_string()],
        );
        assert_eq!(action.as_deref(), Some("git.push"));
    }

    #[test]
    fn classify_argv_daemon_side_unknown_tool_returns_none() {
        let action =
            classify_argv_daemon_side("ember-mystery", &["pr".to_string(), "create".to_string()]);
        assert!(action.is_none());
    }

    #[test]
    fn classify_argv_daemon_side_empty_argv_returns_none() {
        let action = classify_argv_daemon_side("ember-gh", &[]);
        assert!(action.is_none());
    }

    // ---------------------------------------------------------------------
    // L1 authoring gate
    // ---------------------------------------------------------------------

    #[test]
    fn script_is_in_authoring_path_matches_registered_prefix() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let worktree = tmp.path().join("my-construct");
        std::fs::create_dir_all(&worktree).expect("mkdir");
        let script = worktree.join("scripts/run.py");
        std::fs::create_dir_all(script.parent().unwrap()).expect("mkdir script dir");
        std::fs::write(&script, b"# script").expect("write script");

        let registry = AuthoringPathsRegistry {
            paths: vec![std::fs::canonicalize(&worktree).unwrap()],
        };
        assert!(script_is_in_authoring_path(&registry, &script));
    }

    #[test]
    fn empty_registry_refuses_all_scripts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = tmp.path().join("anywhere.py");
        std::fs::write(&script, b"# script").expect("write");
        let registry = AuthoringPathsRegistry::default();
        assert!(
            !script_is_in_authoring_path(&registry, &script),
            "end-user install (registry empty) must refuse every script"
        );
    }

    #[test]
    fn load_authoring_paths_registry_returns_empty_for_missing_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bogus = tmp.path().join("does-not-exist.toml");
        let r = load_authoring_paths_registry(&bogus);
        assert!(r.paths.is_empty(), "missing file -> empty registry");
    }

    #[test]
    fn load_authoring_paths_registry_parses_well_formed_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let registry_file = tmp.path().join("authoring-paths.toml");
        let worktree = tmp.path().join("my-construct");
        std::fs::create_dir_all(&worktree).expect("mkdir");
        let canonical = std::fs::canonicalize(&worktree).unwrap();
        let s = format!("paths = [\"{}\"]\n", canonical.display());
        std::fs::write(&registry_file, s).unwrap();

        let r = load_authoring_paths_registry(&registry_file);
        assert_eq!(r.paths.len(), 1);
        assert_eq!(r.paths[0], canonical);
    }

    #[test]
    fn construct_exec_policy_gate_mode_uses_default_policy() {
        let manifest_toml = r#"
[meta]
name = "ember-aws"
version = "1.0.0"

[[actions]]
key = "aws.s3.rm"
action_version = "v1"
default = "prompt"
mode = "gate"

[[actions]]
key = "aws.s3.cp"
action_version = "v1"
default = "permit"
mode = "gate"
"#;

        assert_eq!(
            parse_construct_exec_policy(manifest_toml, "aws.s3.rm").unwrap(),
            ConstructExecPolicy::Prompt
        );
        assert_eq!(
            parse_construct_exec_policy(manifest_toml, "aws.s3.cp").unwrap(),
            ConstructExecPolicy::Permit
        );
    }
}
