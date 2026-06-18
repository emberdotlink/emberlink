//! Shared launcher core for harness adapters.
//!
//! Keeps the daemon session contract and child-process env injection in one
//! place so harness adapters (`claude`, `codex`, later others) only own
//! binary-specific policy.
//!
//! Anchor: AuthorityDelegation_retired (per ADR 205 §6 / BKR-4c and
//! `docs/current-architecture.md:95`) — the legacy delegation-sidecar
//! vocabulary is retired in favor of `StandingGrant` / `Statement` terms.
//! The launcher posture enum is `StandingGrantMode`; the
//! `EMBER_AUTHORITY_DELEGATION` env var is preserved as a shipped
//! contract on child processes (see `AUTHORITY_DELEGATION_ENV`).

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const AUTHORITY_FALLBACK_ENV: &str = "EMBER_AUTHORITY_FALLBACK";
const AUTHORITY_DELEGATION_ENV: &str = "EMBER_AUTHORITY_DELEGATION";
const OPERATOR_PERSONA_ID_ENV: &str = "EMBER_PERSONA_ID";
const ATTACHMENT_ID_ENV: &str = "EMBER_ATTACHMENT_ID";
const ATTACHMENT_ENDPOINT_TOKEN_ENV: &str = "EMBER_ATTACHMENT_ENDPOINT_TOKEN";

/// Outcome of the daemon `register_session` RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeClientBundle {
    pub port: u16,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub ca_cert_pem: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityFallbackMode {
    Jit,
    Strict,
}

impl AuthorityFallbackMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jit => "jit",
            Self::Strict => "strict",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "jit" => Some(Self::Jit),
            "strict" => Some(Self::Strict),
            _ => None,
        }
    }
}

/// Launcher-side delegation posture for a session. Per ADR 205 §6,
/// the type adopts the `StandingGrant` vocabulary (retiring the legacy
/// delegation-sidecar naming); the variants describe whether the runtime persona
/// inherits the operator's ambient standing grant (`Ambient`) or operates
/// under a template-derived narrowed standing grant (`Delegated`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandingGrantMode {
    Ambient,
    Delegated,
}

impl StandingGrantMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ambient => "ambient",
            Self::Delegated => "delegated",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "ambient" => Some(Self::Ambient),
            "delegated" => Some(Self::Delegated),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityPosture {
    pub fallback: AuthorityFallbackMode,
    pub delegation: StandingGrantMode,
}

impl AuthorityPosture {
    pub fn from_components(authority_strict: bool, delegated_template: Option<&str>) -> Self {
        Self {
            fallback: if authority_strict {
                AuthorityFallbackMode::Strict
            } else {
                AuthorityFallbackMode::Jit
            },
            delegation: if delegated_template.is_some() {
                StandingGrantMode::Delegated
            } else {
                StandingGrantMode::Ambient
            },
        }
    }

    pub fn describe(self) -> String {
        format!("{}+{}", self.fallback.as_str(), self.delegation.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRegistration {
    pub session_id: String,
    pub grant_id: String,
    pub proxy_url: String,
    /// Canonical daemon persona id for this session. Forwarded into child
    /// construct shims so broker RPCs can bind to the enrolled persona instead
    /// of relying on the launcher-facing display name.
    pub persona_id: Option<String>,
    /// Optional Anthropic gateway base URL for launcher-mediated Claude
    /// sessions.
    pub anthropic_base_url: Option<String>,
    /// Newline-separated `Name: Value` headers for Claude's
    /// `ANTHROPIC_CUSTOM_HEADERS` env var.
    pub anthropic_custom_headers: Option<String>,
    /// Git credential-injection proxy URL.
    pub git_proxy_url: Option<String>,
    /// Cursor-compatible generic HTTP(S) egress proxy URL. This is separate
    /// from `proxy_url` (LLM credential gateway) and `git_proxy_url` (GitHub
    /// smart-HTTP projector); the Cursor launcher may set `HTTPS_PROXY` only
    /// when the daemon returns this explicit field.
    pub cursor_egress_proxy_url: Option<String>,
    /// Per-session loopback responses-API-proxy base URL for the codex HOST
    /// lane (P22-S2 / ADR 197 codex). `http://127.0.0.1:<port>/v1`. When set,
    /// the codex launcher writes a relocated `CODEX_HOME/config.toml` pointing
    /// codex's `model_providers.ember.base_url` here and strips ambient OpenAI
    /// credentials from the child env.
    pub codex_responses_proxy_url: Option<String>,
    /// Per-session loopback Code Assist proxy base URL for the gemini HOST lane
    /// (ADR 215 §2). BARE base `http://127.0.0.1:<port>` (NO `/v1` suffix): the
    /// gemini-cli builds `${CODE_ASSIST_ENDPOINT}/v1internal:<method>` itself.
    /// When set, the gemini launcher points `CODE_ASSIST_ENDPOINT` here and
    /// strips ambient Google API credentials from the child env.
    pub gemini_proxy_url: Option<String>,
    /// Path to the daemon-managed ssh-agent socket for this session.
    pub ssh_auth_sock: Option<String>,
    /// Optional delegation grant ULID minted at session-open.
    pub delegation_id: Option<String>,
    /// Optional delegation template name paired with `delegation_id`.
    pub delegation_template: Option<String>,
    /// Explicit authority posture resolved by the daemon for this session-open.
    pub authority_posture: AuthorityPosture,
    /// Optional per-session bridge client bundle for isolated/container launch.
    pub bridge_client_bundle: Option<BridgeClientBundle>,
    /// Attachment-scoped local endpoint coordinates. These are daemon-minted
    /// local capability handles; the daemon still resolves real authority at
    /// use time from attachment -> caller binding -> current grant/delegation.
    pub attachment_id: Option<String>,
    pub attachment_endpoint_token: Option<String>,
    /// P22-S2 (ADR 197 §2): per-session peercred-gated UDS path. When `Some`,
    /// the harness routes Anthropic API traffic over this Unix socket
    /// (`ANTHROPIC_UNIX_SOCKET`) with the checkpoint base URL + bearer-free
    /// headers the daemon supplied. Tool shims still receive the attachment
    /// endpoint token through the child env until ADR 215's unified endpoint
    /// gate gives them a peer-authenticated transport too. `None` means the
    /// transitional TCP `proxy_url` path remains active for older daemons.
    pub anthropic_unix_socket: Option<String>,
    /// P22-S2 Door-1 leaf-pin (ADR 197 §2, adversarial FINDING-1): the
    /// unguessable nonce the daemon returned on the UDS lane. The launcher
    /// echoes it on `report_session_leaf` so the daemon can bind the leaf-pin
    /// report to this launcher (a same-uid attacker who knows the session_id
    /// but not this nonce cannot hijack the gate). `Some` iff
    /// `anthropic_unix_socket` is `Some`.
    pub leaf_report_nonce: Option<String>,
}

/// Generic launch request once a harness has already registered a session.
pub struct LauncherInvocation<'a> {
    pub launcher_name: &'a str,
    pub binary: &'a str,
    pub extra_args: &'a [String],
    pub socket_path: &'a Path,
    pub shadow_bin_dir: &'a Path,
    pub current_dir: Option<&'a Path>,
    /// Environment variables that must be removed from the inherited parent
    /// environment before the child launches.
    pub stripped_env: &'a [&'a str],
}

/// Resolve the shared shadow root directory: `~/.ember/shadow/`, overridable
/// via `$EMBER_SHADOW_DIR` for test harnesses.
pub fn resolve_shadow_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("EMBER_SHADOW_DIR") {
        return PathBuf::from(override_dir);
    }
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".ember")
        .join("shadow")
}

fn legacy_private_worktree_launch_message(
    launcher_name: &str,
    repo_root: &Path,
    cwd: &Path,
) -> Option<String> {
    let legacy_root = crate::launcher::worktree::legacy_worktrees_dir(repo_root);
    if !cwd.starts_with(&legacy_root) {
        return None;
    }

    let suggested = cwd.file_name().map_or_else(
        || crate::launcher::worktree::primary_worktrees_dir(repo_root),
        |leaf| crate::launcher::worktree::primary_worktrees_dir(repo_root).join(leaf),
    );
    Some(format!(
        "ember {launcher_name}: host-mode launch from legacy private worktrees under {} is unsupported because brokered child processes cannot traverse that path.\n  launch from the repo root or migrate this worktree under {}",
        legacy_root.display(),
        suggested.display()
    ))
}

fn legacy_private_worktree_launch_error(launcher_name: &str, cwd: &Path) -> Option<io::Error> {
    let repo_root = crate::launcher::worktree::resolve_repo_root().ok()?;
    legacy_private_worktree_launch_message(launcher_name, &repo_root, cwd).map(io::Error::other)
}

pub fn ensure_broker_safe_launch_cwd(launcher_name: &str) -> io::Result<()> {
    let cwd = std::env::current_dir()?;
    if let Some(err) = legacy_private_worktree_launch_error(launcher_name, &cwd) {
        return Err(err);
    }
    Ok(())
}

fn resolve_safe_launch_cwd() -> PathBuf {
    std::env::current_dir()
        .ok()
        .filter(|path| path.exists())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|path| path.exists())
        })
        .or_else(|| dirs_next::home_dir().filter(|path| path.exists()))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn path_is_executable(path: &Path) -> io::Result<bool> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    if !metadata.is_file() {
        return Ok(false);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        Ok(metadata.permissions().mode() & 0o111 != 0)
    }

    #[cfg(not(unix))]
    {
        Ok(true)
    }
}

fn which_on_path_from_env(binary: &str, path_env: &str) -> Option<PathBuf> {
    for dir in std::env::split_paths(path_env) {
        let candidate = dir.join(binary);
        if path_is_executable(&candidate).ok()? {
            return Some(candidate);
        }
    }
    None
}

fn looks_like_mise_shim(path: &Path) -> bool {
    let path_text = path.to_string_lossy();
    path_text.contains("/mise/shims/") || path.file_name().is_some_and(|name| name == "mise")
}

fn resolve_mise_managed_binary_from_path(binary: &str, path_env: &str) -> Option<PathBuf> {
    let mise_bin = which_on_path_from_env("mise", path_env)?;
    let output = Command::new(mise_bin)
        .arg("which")
        .arg(binary)
        .current_dir(resolve_safe_launch_cwd())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let resolved = String::from_utf8(output.stdout).ok()?;
    let trimmed = resolved.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn preferred_runtime_bin_dirs(parent_path: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let Some(node_path) = which_on_path_from_env("node", parent_path) else {
        return dirs;
    };
    if !looks_like_mise_shim(&node_path) {
        return dirs;
    }
    if let Some(real_node) = resolve_mise_managed_binary_from_path("node", parent_path)
        && let Some(node_bin_dir) = real_node.parent()
    {
        dirs.push(node_bin_dir.to_path_buf());
    }
    dirs
}

fn build_child_path(shadow_bin_dir: &Path, parent_path: &str) -> OsString {
    let mut entries = vec![shadow_bin_dir.to_path_buf()];
    for extra_dir in preferred_runtime_bin_dirs(parent_path) {
        if !entries.iter().any(|entry| entry == &extra_dir) {
            entries.push(extra_dir);
        }
    }
    for entry in std::env::split_paths(parent_path) {
        if !entries.iter().any(|existing| existing == &entry) {
            entries.push(entry);
        }
    }
    std::env::join_paths(entries).unwrap_or_else(|_| OsString::from(parent_path))
}

/// Spawn the upstream harness binary with the common Ember session env layered
/// on top of the inherited parent environment.
pub fn run_with_registration<I>(
    invocation: LauncherInvocation<'_>,
    registration: &SessionRegistration,
    extra_env: I,
) -> io::Result<i32>
where
    I: IntoIterator<Item = (String, String)>,
{
    eprintln!(
        "ember {}: launching {} (session={}, attachment={}, proxy={}, posture={})",
        invocation.launcher_name,
        invocation.binary,
        registration.session_id,
        registration.attachment_id.as_deref().unwrap_or("<legacy>"),
        registration.proxy_url,
        registration.authority_posture.describe(),
    );

    let parent_path = std::env::var("PATH").unwrap_or_default();
    let child_path = build_child_path(invocation.shadow_bin_dir, &parent_path);

    let mut cmd = Command::new(invocation.binary);
    cmd.args(invocation.extra_args)
        .env("EMBER_PROXY_URL", &registration.proxy_url)
        .env("EMBER_SOCKET_PATH", invocation.socket_path.as_os_str())
        .env("EMBER_DAEMON_SOCKET", invocation.socket_path.as_os_str())
        .env("EMBER_SESSION_ID", &registration.session_id)
        .env(
            AUTHORITY_FALLBACK_ENV,
            registration.authority_posture.fallback.as_str(),
        )
        .env(
            AUTHORITY_DELEGATION_ENV,
            registration.authority_posture.delegation.as_str(),
        )
        .env("PATH", &child_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if let Some(delegation_id) = registration.delegation_id.as_deref() {
        cmd.env("EMBER_DELEGATION_ID", delegation_id);
    }
    if let Some(delegation_template) = registration.delegation_template.as_deref() {
        cmd.env("EMBER_DELEGATION_TEMPLATE", delegation_template);
    }
    if let Some(persona_id) = registration.persona_id.as_deref() {
        cmd.env(OPERATOR_PERSONA_ID_ENV, persona_id);
    }
    if let Some(attachment_id) = registration.attachment_id.as_deref() {
        cmd.env(ATTACHMENT_ID_ENV, attachment_id);
    }
    // The Anthropic UDS lane no longer uses the endpoint-token bearer for LLM
    // auth, but child tool shims still need attachment endpoint coordinates for
    // broker_resolve over the daemon socket. Do not drop this until the tool
    // lane moves onto the shared peer-authenticated endpoint gate (ADR 215).
    if let Some(endpoint_token) = registration.attachment_endpoint_token.as_deref() {
        cmd.env(ATTACHMENT_ENDPOINT_TOKEN_ENV, endpoint_token);
    }

    if let Some(current_dir) = invocation.current_dir {
        cmd.current_dir(current_dir);
    }

    for key in invocation.stripped_env {
        cmd.env_remove(key);
    }

    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    // Spawn (not `status()`) so we can capture the harness child pid for the
    // P22-S2 Door-1 leaf-pin before waiting on it. `spawn()?.wait()` is exactly
    // what `status()` does internally, so exit/signal semantics are unchanged.
    let mut child = cmd.spawn().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "ember {}: failed to spawn {}: {e}",
                invocation.launcher_name, invocation.binary
            ),
        )
    })?;

    // P22-S2 Door-1 leaf-pin (ADR 197 §2): on the per-session UDS lane, tell the
    // daemon the exact pid we spawned so its per-session socket gate admits only
    // this process. Reported synchronously here — before the harness boots far
    // enough to make its first API call — so the gate has a leaf to pin against
    // by the time the harness connects. Skipped on the transitional TCP lane
    // (no per-session socket).
    if registration.anthropic_unix_socket.is_some() {
        crate::launcher::session_rpc::report_session_leaf_rpc(
            &registration.session_id,
            child.id(),
            registration.leaf_report_nonce.as_deref().unwrap_or(""),
            invocation.socket_path,
            invocation.launcher_name,
        );
    }

    let status = child.wait().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "ember {}: failed to wait on {}: {e}",
                invocation.launcher_name, invocation.binary
            ),
        )
    })?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn write_executable(path: &Path, body: &str) {
        std::fs::write(path, body).expect("write executable");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod executable");
    }

    fn fixture() -> SessionRegistration {
        SessionRegistration {
            session_id: "sess_fixture".to_string(),
            grant_id: "grt_fixture".to_string(),
            proxy_url: "http://127.0.0.1:9999".to_string(),
            persona_id: None,
            anthropic_base_url: None,
            anthropic_custom_headers: None,
            git_proxy_url: None,
            cursor_egress_proxy_url: None,
            codex_responses_proxy_url: None,
            gemini_proxy_url: None,
            ssh_auth_sock: None,
            delegation_id: None,
            delegation_template: None,
            authority_posture: AuthorityPosture::from_components(false, None),
            bridge_client_bundle: None,
            attachment_id: Some("att_fixture".to_string()),
            attachment_endpoint_token: Some("ep_fixture".to_string()),
            anthropic_unix_socket: None,
            leaf_report_nonce: None,
        }
    }

    fn invocation<'a>(binary: &'a str) -> LauncherInvocation<'a> {
        LauncherInvocation {
            launcher_name: "test",
            binary,
            extra_args: &[],
            socket_path: Path::new("/nonexistent.sock"),
            shadow_bin_dir: Path::new("/tmp"),
            current_dir: None,
            stripped_env: &[],
        }
    }

    #[test]
    fn run_with_registration_propagates_zero_exit() {
        let code = run_with_registration(invocation("/usr/bin/true"), &fixture(), Vec::new())
            .expect("spawn /usr/bin/true");
        assert_eq!(code, 0);
    }

    #[test]
    fn run_with_registration_propagates_nonzero_exit() {
        let code = run_with_registration(invocation("/usr/bin/false"), &fixture(), Vec::new())
            .expect("spawn /usr/bin/false");
        assert_eq!(code, 1);
    }

    #[test]
    fn run_with_registration_does_not_pollute_parent_env() {
        let _ = run_with_registration(invocation("/usr/bin/true"), &fixture(), Vec::new())
            .expect("spawn /usr/bin/true");
        let leaked = std::env::var("EMBER_ATTACHMENT_ENDPOINT_TOKEN")
            .map(|v| v.contains("grt_fixture"))
            .unwrap_or(false);
        assert!(
            !leaked,
            "launcher must not write attachment endpoint token into parent env"
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_with_registration_exports_attachment_endpoint_for_tool_shims_on_uds_lane() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = tmp.path().join("check-attachment-env.sh");
        write_executable(
            &script,
            "#!/bin/sh\n[ \"$EMBER_ATTACHMENT_ID\" = \"att_fixture\" ] || exit 51\n[ \"$EMBER_ATTACHMENT_ENDPOINT_TOKEN\" = \"ep_fixture\" ] || exit 52\nexit 0\n",
        );
        let mut registration = fixture();
        registration.anthropic_unix_socket = Some(
            tmp.path()
                .join("anthropic.sock")
                .to_string_lossy()
                .into_owned(),
        );
        registration.leaf_report_nonce = Some("lrn_fixture".to_string());

        let code = run_with_registration(
            invocation(script.to_str().expect("utf8 script path")),
            &registration,
            Vec::new(),
        )
        .expect("spawn attachment env checker");
        assert_eq!(code, 0);

        let leaked = std::env::var("EMBER_ATTACHMENT_ENDPOINT_TOKEN")
            .map(|v| v.contains("ep_fixture"))
            .unwrap_or(false);
        assert!(
            !leaked,
            "launcher must still keep the endpoint token out of the parent env"
        );
    }

    #[test]
    fn run_with_registration_reports_spawn_failure() {
        let result = run_with_registration(
            invocation("/no/such/binary-that-must-not-exist"),
            &fixture(),
            Vec::new(),
        );
        assert!(
            result.is_err(),
            "missing binary must surface as Err, not silent zero exit"
        );
    }

    #[test]
    fn run_with_registration_exports_explicit_authority_posture_env() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = tmp.path().join("check-posture-env.sh");
        write_executable(
            &script,
            "#!/bin/sh\n[ \"$EMBER_AUTHORITY_FALLBACK\" = \"strict\" ] || exit 41\n[ \"$EMBER_AUTHORITY_DELEGATION\" = \"delegated\" ] || exit 42\nexit 0\n",
        );
        let mut registration = fixture();
        registration.authority_posture = AuthorityPosture::from_components(true, Some("ops"));
        let code = run_with_registration(
            invocation(script.to_str().expect("utf8 script path")),
            &registration,
            Vec::new(),
        )
        .expect("spawn posture checker");
        assert_eq!(code, 0, "child must receive explicit authority posture env");
    }

    #[test]
    fn run_with_registration_exports_workflow_env_when_present() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = tmp.path().join("check-workflow-env.sh");
        write_executable(
            &script,
            "#!/bin/sh\n[ \"$EMBER_DELEGATION_ID\" = \"wfg_fixture\" ] || exit 43\n[ \"$EMBER_DELEGATION_TEMPLATE\" = \"emberd-development\" ] || exit 44\nexit 0\n",
        );
        let mut registration = fixture();
        registration.delegation_id = Some("wfg_fixture".to_string());
        registration.delegation_template = Some("emberd-development".to_string());
        let code = run_with_registration(
            invocation(script.to_str().expect("utf8 script path")),
            &registration,
            Vec::new(),
        )
        .expect("spawn workflow env checker");
        assert_eq!(code, 0, "child must receive delegated workflow env exports");
    }

    #[test]
    fn resolve_shadow_dir_honors_override() {
        unsafe {
            std::env::set_var("EMBER_SHADOW_DIR", "/tmp/ember-shadow-override");
        }
        assert_eq!(
            resolve_shadow_dir(),
            PathBuf::from("/tmp/ember-shadow-override")
        );
        unsafe {
            std::env::remove_var("EMBER_SHADOW_DIR");
        }
    }

    #[test]
    fn legacy_private_worktree_launch_error_flags_legacy_paths() {
        let repo_root = PathBuf::from("/tmp/repo");
        let cwd = repo_root.join(".claude/worktrees/pulumi");
        let msg = legacy_private_worktree_launch_message("claude", &repo_root, &cwd)
            .expect("legacy path must produce guidance");
        assert!(msg.contains("/tmp/repo/.claude/worktrees"));
        assert!(msg.contains("/tmp/repo/.ember/worktrees/pulumi"));
    }

    #[test]
    fn build_child_path_prepends_real_node_bin_when_node_is_mise_shim() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let shadow = tmp.path().join("shadow/bin");
        let tools = tmp.path().join("tools");
        let shim_dir = tmp.path().join("mise/shims");
        let runtime_bin = tmp.path().join("installs/node/24.14.1/bin");
        std::fs::create_dir_all(&shadow).expect("create shadow");
        std::fs::create_dir_all(&tools).expect("create tools");
        std::fs::create_dir_all(&shim_dir).expect("create shim dir");
        std::fs::create_dir_all(&runtime_bin).expect("create runtime bin");

        write_executable(
            &tools.join("mise"),
            &format!(
                "#!/bin/sh\nif [ \"$1\" = \"which\" ] && [ \"$2\" = \"node\" ]; then\n  printf '%s\\n' '{}'\n  exit 0\nfi\nexit 1\n",
                runtime_bin.join("node").display()
            ),
        );
        write_executable(&shim_dir.join("node"), "#!/bin/sh\nexit 0\n");
        write_executable(&runtime_bin.join("node"), "#!/bin/sh\nexit 0\n");

        let parent_path =
            std::env::join_paths([tools.as_path(), shim_dir.as_path(), Path::new("/usr/bin")])
                .expect("join parent path");
        let child_path = build_child_path(&shadow, &parent_path.to_string_lossy());
        let entries: Vec<PathBuf> = std::env::split_paths(&child_path).collect();
        assert_eq!(entries[0], shadow);
        assert_eq!(entries[1], runtime_bin);
        assert!(
            entries.iter().any(|entry| entry == &shim_dir),
            "original node shim path must still be preserved later in PATH"
        );
    }

    #[test]
    fn build_child_path_leaves_parent_order_when_node_is_not_mise_shim() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let shadow = tmp.path().join("shadow/bin");
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&shadow).expect("create shadow");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");
        write_executable(&bin_dir.join("node"), "#!/bin/sh\nexit 0\n");

        let parent_path =
            std::env::join_paths([bin_dir.as_path(), Path::new("/usr/bin")]).expect("join path");
        let child_path = build_child_path(&shadow, &parent_path.to_string_lossy());
        let entries: Vec<PathBuf> = std::env::split_paths(&child_path).collect();
        assert_eq!(entries[0], shadow);
        assert_eq!(entries[1], bin_dir);
        assert_eq!(entries[2], PathBuf::from("/usr/bin"));
    }
}
