//! `ember up` — session-open response parsing.
//!
//! The shipped local launcher path is still direct daemon `register_session`
//! success over the Unix socket. This module preserves the reserved
//! `presence_required` response shape for compatibility, but when that branch is
//! encountered it now returns an explicit `Unsupported` error instead of
//! pretending the browser/session-open bridge is already live.

pub mod fallback;
pub mod idmapped;
pub mod overrides;
pub mod userns;
pub mod volumes;

use std::io;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::launcher::claude_code::SessionRegistration;
use crate::launcher::harness::HarnessKind;
use crate::launcher::path_shadow::shadow_bin_dir;
use crate::launcher::presence;

use ed25519_dalek::VerifyingKey;
use ember_update::auto_update::{UpdateDecision, UpdateDecisionError, decide_update};
use ember_update::channel::ChannelPointer;
use ember_update::revocations::{RevocationAction, RevocationSeverity, RevocationsPoller};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolatedClaudeCodeCapability {
    Ready {
        engine: RuntimeEngine,
        template_path: PathBuf,
    },
    Unavailable {
        reason: String,
    },
}

const CONTAINER_WORKDIR: &str = "/work/repo";
const CONTAINER_HOME: &str = "/home/agent";
const CONTAINER_CODEX_RUNTIME_ROOT: &str = "/usr/local/lib/ember/codex-runtime";
const CONTAINER_DEFAULT_PATH: &str =
    "/usr/local/lib/shadow/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin";
const ISOLATED_HARNESS_WORKER_IMAGE: &str = "ember-claude-code:v1";

/// implementation-note-438 — container runtime engines `ember up`
/// detects on the host. Order tracks design review 2026-05-15 compose-
/// topology D7 (Docker first, then OrbStack on macOS, then Podman, then
/// the SCION ephemeral runtime).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEngine {
    /// Docker Desktop / Docker CE — `docker compose` available on PATH.
    Docker,
    /// OrbStack on macOS — registers itself as `docker` (shim) plus its
    /// own `orbctl` binary. Detected by presence of `orbctl`; the
    /// compose invocation still goes through `docker compose`.
    OrbStack,
    /// Podman with the `podman compose` subcommand.
    Podman,
}

impl RuntimeEngine {
    pub fn from_backend_hint(hint: &str) -> io::Result<Self> {
        match hint {
            "docker" => Ok(RuntimeEngine::Docker),
            "orbstack" => Ok(RuntimeEngine::OrbStack),
            "podman" => Ok(RuntimeEngine::Podman),
            "scion" => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "backend hint `scion` is not wired on current main; use Docker, OrbStack, or Podman for the isolated path",
            )),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unknown backend hint `{other}`. Supported isolated backends on current main: docker | orbstack | podman"
                ),
            )),
        }
    }

    /// Binary the compose-up shell-out invokes. OrbStack ships a
    /// `docker` shim so the compose path is identical.
    pub fn compose_binary(self) -> &'static str {
        match self {
            RuntimeEngine::Docker | RuntimeEngine::OrbStack => "docker",
            RuntimeEngine::Podman => "podman",
        }
    }

    /// Human-readable name for log lines + remediation messages.
    pub fn display_name(self) -> &'static str {
        match self {
            RuntimeEngine::Docker => "Docker",
            RuntimeEngine::OrbStack => "OrbStack",
            RuntimeEngine::Podman => "Podman",
        }
    }

    fn supports_procfs_hardening(self) -> bool {
        cfg!(target_os = "linux") && matches!(self, RuntimeEngine::Docker | RuntimeEngine::Podman)
    }
}

/// Probe for an installed container runtime in the preference order
/// locked by design review 2026-05-15 compose-topology D7. Returns
/// `Ok(Some(engine))` on the first hit, `Ok(None)` when nothing is
/// installed.
///
/// "Installed" means the binary resolves on PATH — the helper does
/// NOT exercise the daemon (we don't want a slow Docker socket probe
/// here; the subsequent `docker compose up` does its own error
/// surfacing). The OrbStack branch checks `orbctl` because OrbStack
/// installs a `docker` shim that would otherwise mask its presence.
pub fn detect_runtime_engine() -> io::Result<Option<RuntimeEngine>> {
    // OrbStack first on macOS — its `docker` shim would match the
    // Docker branch below and hide the OrbStack distinction operators
    // care about for remediation messages.
    if which_on_path("orbctl")?.is_some() {
        return Ok(Some(RuntimeEngine::OrbStack));
    }
    if which_on_path("docker")?.is_some() {
        return Ok(Some(RuntimeEngine::Docker));
    }
    if which_on_path("podman")?.is_some() {
        return Ok(Some(RuntimeEngine::Podman));
    }
    Ok(None)
}

pub fn detect_runtime_engine_with_hint(hint: Option<&str>) -> io::Result<Option<RuntimeEngine>> {
    match hint {
        None => detect_runtime_engine(),
        Some(hint) => {
            let wanted = RuntimeEngine::from_backend_hint(hint)?;
            let present = match wanted {
                RuntimeEngine::Docker => which_on_path("docker")?.is_some(),
                RuntimeEngine::OrbStack => which_on_path("orbctl")?.is_some(),
                RuntimeEngine::Podman => which_on_path("podman")?.is_some(),
            };
            if present { Ok(Some(wanted)) } else { Ok(None) }
        }
    }
}

/// Best-effort `which`-style lookup. Returns the absolute path of the
/// first PATH entry that contains `binary`, `Ok(None)` if no PATH
/// entry resolves.
fn which_on_path(binary: &str) -> io::Result<Option<PathBuf>> {
    let Some(path_env) = std::env::var_os("PATH") else {
        return Ok(None);
    };
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(binary);
        if path_is_executable(&candidate)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
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

fn isolated_session_run_root(home: &Path) -> PathBuf {
    dirs_next::data_local_dir()
        .unwrap_or_else(|| home.join(".local").join("share"))
        .join("emberlink")
        .join("session-open")
}

/// Human-readable remediation hint emitted when
/// [`detect_runtime_engine`] returns `Ok(None)`. Per-platform pointers
/// to install docs.
pub fn missing_runtime_remediation() -> &'static str {
    if cfg!(target_os = "macos") {
        "No container runtime detected. Install one:\n\
         - OrbStack (recommended on macOS): https://orbstack.dev\n\
         - Docker Desktop: https://docs.docker.com/desktop/install/mac-install/\n\
         - Podman Desktop: https://podman-desktop.io"
    } else if cfg!(target_os = "linux") {
        "No container runtime detected. Install one:\n\
         - Docker: https://docs.docker.com/engine/install/\n\
         - Podman: https://podman.io/getting-started/installation"
    } else {
        "No container runtime detected. `ember up` requires Docker, OrbStack, or Podman on PATH."
    }
}

fn resolve_profile(profile: Option<&str>) -> io::Result<String> {
    let profile = profile.unwrap_or("dev").to_string();
    if matches!(profile.as_str(), "dev" | "headless" | "demo") {
        Ok(profile)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown profile: {profile}. Supported: dev | headless | demo"),
        ))
    }
}

fn resolve_compose_template_path(current_dir: &Path) -> PathBuf {
    if let Ok(path) = std::env::var("EMBER_COMPOSE_TEMPLATE") {
        return PathBuf::from(path);
    }
    current_dir.join("crates/headless-runtime/templates/compose.yml.j2")
}

pub fn detect_isolated_claude_code_capability(
    current_dir: &Path,
    backend_hint: Option<&str>,
) -> io::Result<IsolatedClaudeCodeCapability> {
    let Some(engine) = detect_runtime_engine_with_hint(backend_hint)? else {
        return Ok(IsolatedClaudeCodeCapability::Unavailable {
            reason: missing_runtime_remediation().to_string(),
        });
    };

    let template_path = resolve_compose_template_path(current_dir);
    if !template_path.exists() {
        return Ok(IsolatedClaudeCodeCapability::Unavailable {
            reason: format!(
                "compose template not found at {} — isolated launch must run from the emberlink workspace root, or set EMBER_COMPOSE_TEMPLATE",
                template_path.display()
            ),
        });
    }

    Ok(IsolatedClaudeCodeCapability::Ready {
        engine,
        template_path,
    })
}

/// Result of [`run_auto_update_check`] — tells the launcher whether to
/// proceed with container start.
///
/// `Proceed` means the launcher continues; `Abort` means refuse to
/// start (revoked image / stale revocations / signature failure / etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoUpdateOutcome {
    /// Steady state — current digest matches the signed channel pointer.
    NoUpdate,
    /// A new manifest is available; the launcher should pull + verify
    /// it next (manifest in-toto verification is the caller's
    /// follow-up; this scaffold prints an advisory notice).
    UpdateAvailable {
        new_digest: String,
        manifest_uri: String,
    },
    /// Auto-update inputs were not supplied (channel pointer fetcher
    /// not yet wired). The launcher proceeds without checking.
    Skipped,
    /// Current digest is revoked at a severity that does not refuse
    /// the launch (High / Medium / Low). Launcher proceeds with a
    /// warning.
    RevokedAdvisory {
        severity: RevocationSeverity,
        reason: String,
    },
}

/// Auto-update check before container start
/// (`ember_up_auto_update_b_launcher_integration` — subtask B of
/// `implementation-note-526`).
///
/// Pure orchestration over the existing `ember_update::auto_update::decide_update`
/// decision function. Network fetching of the channel pointer + the
/// revocations document is the caller's responsibility — when the
/// launcher does not yet have a fetcher wired (today), pass `None` for
/// the network inputs and the check is skipped.
///
/// Routes per the four [`UpdateDecision`] branches and the two
/// [`UpdateDecisionError`] variants:
///
/// | Decision                       | Outcome                                           | Operator visible |
/// |--------------------------------|---------------------------------------------------|------------------|
/// | `NoUpdate`                     | `Ok(NoUpdate)`                                    | silent           |
/// | `UpdateAvailable`              | `Ok(UpdateAvailable { … })`                       | one-line notice  |
/// | `CurrentRevoked` (Critical)    | `Err(refuse-to-start)`                            | severity + reason|
/// | `CurrentRevoked` (High/Med/Low)| `Ok(RevokedAdvisory { … })`                       | severity + reason|
/// | `BlockedByStaleRevocations`    | `Err(refuse-to-start)`                            | staleness reason |
/// | `PointerInvalid`               | `Err(refuse-to-start)`                            | error string     |
/// | `RevocationsInvalid`           | `Err(refuse-to-start)`                            | error string     |
///
/// Returns `Err(io::Error)` when the launcher must refuse to start.
/// Returns `Ok(_)` when the launcher should proceed.
pub fn run_auto_update_check(
    current_digest: Option<&str>,
    pointer: Option<&ChannelPointer>,
    pointer_signer: Option<&VerifyingKey>,
    revocations_raw: Option<&[u8]>,
    revocations_poller: Option<&RevocationsPoller>,
    now_unix_ms: u64,
) -> io::Result<AutoUpdateOutcome> {
    let (Some(current), Some(p), Some(signer), Some(rev_raw), Some(poller)) = (
        current_digest,
        pointer,
        pointer_signer,
        revocations_raw,
        revocations_poller,
    ) else {
        return Ok(AutoUpdateOutcome::Skipped);
    };

    let decision = decide_update(current, p, signer, rev_raw, poller, now_unix_ms);

    match decision {
        Ok(UpdateDecision::NoUpdate) => Ok(AutoUpdateOutcome::NoUpdate),
        Ok(UpdateDecision::UpdateAvailable {
            new_digest,
            manifest_uri,
        }) => {
            println!("agent runtime upgraded to {new_digest}");
            Ok(AutoUpdateOutcome::UpdateAvailable {
                new_digest,
                manifest_uri,
            })
        }
        Ok(UpdateDecision::CurrentRevoked {
            severity,
            action,
            reason,
        }) => match action {
            RevocationAction::IsolateDrainKill | RevocationAction::FailClosed { .. } => {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing to start: current image digest revoked at severity {severity:?} — {reason}"
                    ),
                ))
            }
            RevocationAction::DrainToTtl | RevocationAction::Log => {
                eprintln!(
                    "warning: current image digest revoked at severity {severity:?} — {reason}; proceeding (operator advisory)"
                );
                Ok(AutoUpdateOutcome::RevokedAdvisory { severity, reason })
            }
        },
        Ok(UpdateDecision::BlockedByStaleRevocations { reason }) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to start: revocations document stale ({reason}) — refusing new container starts until the document refreshes"
            ),
        )),
        Err(UpdateDecisionError::PointerInvalid(e)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("refusing to start: channel pointer failed to verify: {e}"),
        )),
        Err(UpdateDecisionError::RevocationsInvalid(e)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("refusing to start: revocations document failed to parse: {e}"),
        )),
    }
}

pub fn open_claude_code_isolated(
    profile: Option<&str>,
    backend_hint: Option<&str>,
) -> io::Result<()> {
    let prepared = prepare_isolated_stack(
        profile,
        backend_hint,
        &std::env::current_dir()?,
        ComposeRenderContextOverrides::default(),
    )?;
    println!(
        "Runtime: {} ({})",
        prepared.engine.display_name(),
        prepared.engine.compose_binary()
    );
    println!("Compose: {}", prepared.compose_path.display());

    // ember_up_auto_update_b_launcher_integration — auto-update check before
    // container start. Today the network transport for the channel pointer
    // and the revocations document is not wired into the launcher path
    // (subtasks C+D), so this resolves to `Skipped`. Once the fetcher lands
    // the launcher will pass the freshly-fetched pointer + revocations and
    // the per-branch routing below kicks in for real.
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let _outcome = run_auto_update_check(None, None, None, None, None, now_unix_ms)?;

    let (stdout, _stderr) = compose_up(prepared.engine, &prepared.compose_path, &prepared.profile)?;
    if !stdout.trim().is_empty() {
        println!("{}", stdout.trim_end());
    }

    eprintln!(
        "note: bridge cert provisioning + `bridge-cli ping` healthcheck land once implementation-note-527 wires the daemon presence RPC. The compose stack is up; the trust handshake is not yet enforced from this verb."
    );
    println!("\nember up: session ready (profile={})", prepared.profile);
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ComposeRenderContextOverrides {
    pub shadow_bin_source: Option<PathBuf>,
    pub claude_bin_source: Option<PathBuf>,
    pub codex_runtime_source: Option<PathBuf>,
    pub worker_persona_id: Option<String>,
    pub worker_command: Option<Vec<String>>,
    pub worker_seccomp_profile_path: Option<PathBuf>,
    pub worker_image: Option<String>,
    pub worker_home_path: Option<PathBuf>,
    pub worker_codex_config_path: Option<PathBuf>,
    pub worker_worktree_path: Option<PathBuf>,
    pub worker_extra_hosts: Vec<String>,
    pub agent_id: Option<String>,
    pub bridge_enabled: bool,
    pub orchestrator_enabled: bool,
}

impl Default for ComposeRenderContextOverrides {
    fn default() -> Self {
        Self {
            shadow_bin_source: None,
            claude_bin_source: None,
            codex_runtime_source: None,
            worker_persona_id: None,
            worker_command: None,
            worker_seccomp_profile_path: None,
            worker_image: None,
            worker_home_path: None,
            worker_codex_config_path: None,
            worker_worktree_path: None,
            worker_extra_hosts: Vec::new(),
            agent_id: None,
            bridge_enabled: true,
            orchestrator_enabled: true,
        }
    }
}

#[derive(Debug, Clone)]
struct PreparedIsolatedStack {
    engine: RuntimeEngine,
    profile: String,
    compose_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct IsolatedHarnessLaunch {
    pub harness: HarnessKind,
    pub persona: String,
    pub registration: SessionRegistration,
    pub extra_args: Vec<String>,
    pub backend_hint: Option<String>,
    pub preset: Option<String>,
    pub workspace_root: PathBuf,
    pub shadow_root: PathBuf,
    pub codex_runtime_source: Option<PathBuf>,
    pub codex_config_source: Option<PathBuf>,
}

pub fn launch_harness_isolated(request: IsolatedHarnessLaunch) -> io::Result<i32> {
    let home = dirs_next::home_dir()
        .ok_or_else(|| io::Error::other("could not resolve $HOME for isolated launch"))?;
    let run_root = isolated_session_run_root(&home);
    std::fs::create_dir_all(&run_root)?;
    let isolated_home = run_root.join(format!(
        "{}-home-{}",
        request.harness.as_str(),
        &request.registration.session_id
    ));
    std::fs::create_dir_all(&isolated_home)?;

    let overrides = ComposeRenderContextOverrides {
        shadow_bin_source: Some(shadow_bin_dir(&request.shadow_root)),
        codex_runtime_source: request.codex_runtime_source.clone(),
        worker_persona_id: Some(request.persona.clone()),
        worker_command: Some(vec![
            "sh".to_string(),
            "-lc".to_string(),
            "tail -f /dev/null".to_string(),
        ]),
        worker_image: Some(ISOLATED_HARNESS_WORKER_IMAGE.to_string()),
        worker_seccomp_profile_path: None,
        worker_home_path: Some(isolated_home.clone()),
        worker_codex_config_path: request.codex_config_source.clone(),
        worker_worktree_path: Some(request.workspace_root.clone()),
        worker_extra_hosts: Vec::new(),
        agent_id: Some(request.registration.session_id.clone()),
        claude_bin_source: None,
        bridge_enabled: false,
        orchestrator_enabled: false,
    };

    let prepared = prepare_isolated_stack(
        request.preset.as_deref(),
        request.backend_hint.as_deref(),
        &request.workspace_root,
        overrides,
    )?;
    println!(
        "Runtime: {} ({})",
        prepared.engine.display_name(),
        prepared.engine.compose_binary()
    );
    println!("Compose: {}", prepared.compose_path.display());

    let (stdout, _stderr) =
        match compose_up(prepared.engine, &prepared.compose_path, &prepared.profile) {
            Ok(output) => output,
            Err(err) => {
                cleanup_isolated_stack_best_effort(
                    prepared.engine,
                    &prepared.compose_path,
                    &prepared.profile,
                );
                return Err(err);
            }
        };
    if !stdout.trim().is_empty() {
        println!("{}", stdout.trim_end());
    }

    let binary = match request.harness {
        HarnessKind::Claude => "claude".to_string(),
        HarnessKind::Codex => codex_container_binary_path(&request)?,
        HarnessKind::Other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "isolated launcher only supports Claude and Codex",
            ));
        }
    };

    let args = match request.harness {
        HarnessKind::Codex => codex_args_with_workspace(&request.extra_args),
        _ => request.extra_args.clone(),
    };

    let env = isolated_child_env(prepared.engine, &request.persona, &request.registration);
    if request.harness == HarnessKind::Codex && request.codex_config_source.is_some() {
        eprintln!(
            "ember codex: isolated mode reuses the canonical host ~/.codex authority via bind-mount; no per-container auth copy is created"
        );
    }

    let result = compose_exec(
        prepared.engine,
        &prepared.compose_path,
        &prepared.profile,
        "worker",
        Some(CONTAINER_WORKDIR),
        &env,
        &binary,
        &args,
    );
    cleanup_isolated_stack_best_effort(prepared.engine, &prepared.compose_path, &prepared.profile);
    result
}

fn cleanup_isolated_stack_best_effort(engine: RuntimeEngine, compose_path: &Path, profile: &str) {
    if let Err(err) = compose_down(engine, compose_path, true) {
        eprintln!(
            "warning: failed to tear down isolated launcher stack for profile `{profile}` at {}: {err}",
            compose_path.display()
        );
    }
}

fn codex_args_with_workspace(extra_args: &[String]) -> Vec<String> {
    if extra_args.iter().any(|arg| arg == "-C" || arg == "--cd") {
        return extra_args.to_vec();
    }
    let mut args = Vec::with_capacity(extra_args.len() + 2);
    args.push("-C".to_string());
    args.push(CONTAINER_WORKDIR.to_string());
    args.extend(extra_args.iter().cloned());
    args
}

fn codex_container_binary_path(request: &IsolatedHarnessLaunch) -> io::Result<String> {
    if request.codex_runtime_source.is_none() {
        return Err(io::Error::other(
            "isolated `ember codex` requires a container-ready Codex runtime root; resolve the host Codex install first or use the host launcher path",
        ));
    }
    Ok(format!("{CONTAINER_CODEX_RUNTIME_ROOT}/bin/codex"))
}

fn isolated_child_env(
    engine: RuntimeEngine,
    persona: &str,
    registration: &SessionRegistration,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("EMBER_PERSONA".to_string(), persona.to_string()),
        ("EMBER_PERSONA_ID".to_string(), persona.to_string()),
        ("EMBER_GRANT_ID".to_string(), registration.grant_id.clone()),
        (
            "EMBER_PROXY_URL".to_string(),
            rewrite_loopback_url_for_container(&registration.proxy_url, engine),
        ),
        (
            "EMBER_SESSION_ID".to_string(),
            registration.session_id.clone(),
        ),
        (
            "EMBER_SOCKET_PATH".to_string(),
            "/run/ember/daemon.sock".to_string(),
        ),
        (
            "EMBER_DAEMON_SOCKET".to_string(),
            "/run/ember/daemon.sock".to_string(),
        ),
        ("HOME".to_string(), CONTAINER_HOME.to_string()),
        ("PATH".to_string(), CONTAINER_DEFAULT_PATH.to_string()),
    ];
    if let Some(base_url) = registration.anthropic_base_url.as_deref() {
        env.push((
            "ANTHROPIC_BASE_URL".to_string(),
            rewrite_loopback_url_for_container(base_url, engine),
        ));
    }
    if let Some(headers) = registration.anthropic_custom_headers.as_deref() {
        env.push(("ANTHROPIC_CUSTOM_HEADERS".to_string(), headers.to_string()));
    }
    if let Some(git_proxy_url) = registration.git_proxy_url.as_deref() {
        env.push((
            "EMBER_GIT_PROXY_URL".to_string(),
            rewrite_loopback_url_for_container(git_proxy_url, engine),
        ));
    }
    env
}

fn rewrite_loopback_url_for_container(url: &str, engine: RuntimeEngine) -> String {
    let host = container_loopback_host(engine);
    if let Some(rest) = url.strip_prefix("http://127.0.0.1:") {
        return format!("http://{host}:{rest}");
    }
    if let Some(rest) = url.strip_prefix("https://127.0.0.1:") {
        return format!("https://{host}:{rest}");
    }
    if let Some(rest) = url.strip_prefix("http://localhost:") {
        return format!("http://{host}:{rest}");
    }
    if let Some(rest) = url.strip_prefix("https://localhost:") {
        return format!("https://{host}:{rest}");
    }
    url.to_string()
}

fn container_loopback_host(engine: RuntimeEngine) -> &'static str {
    match engine {
        RuntimeEngine::Podman => "host.containers.internal",
        RuntimeEngine::Docker | RuntimeEngine::OrbStack => "host.docker.internal",
    }
}

fn prepare_isolated_stack(
    profile: Option<&str>,
    backend_hint: Option<&str>,
    workspace_root: &Path,
    overrides: ComposeRenderContextOverrides,
) -> io::Result<PreparedIsolatedStack> {
    let ComposeRenderContextOverrides {
        shadow_bin_source,
        claude_bin_source,
        codex_runtime_source,
        worker_persona_id,
        worker_command,
        worker_seccomp_profile_path,
        worker_image,
        worker_home_path,
        worker_codex_config_path,
        worker_worktree_path,
        worker_extra_hosts,
        agent_id,
        bridge_enabled,
        orchestrator_enabled,
    } = overrides;
    let profile = resolve_profile(profile)?;
    let template_search_root = resolve_workspace_repo_root(workspace_root)?;
    let capability = detect_isolated_claude_code_capability(&template_search_root, backend_hint)?;
    let (engine, template_path) = match capability {
        IsolatedClaudeCodeCapability::Ready {
            engine,
            template_path,
        } => (engine, template_path),
        IsolatedClaudeCodeCapability::Unavailable { reason } => {
            return Err(io::Error::new(io::ErrorKind::NotFound, reason));
        }
    };

    let home = dirs_next::home_dir().ok_or_else(|| {
        io::Error::other("could not resolve $HOME for the isolated session-open root")
    })?;
    let run_dir = isolated_session_run_root(&home).join(format!(
        "{}-{}",
        profile,
        uuid::Uuid::new_v4().as_simple()
    ));
    std::fs::create_dir_all(&run_dir)?;
    let bridge_cert_dir = run_dir.join("certs");
    std::fs::create_dir_all(&bridge_cert_dir)?;
    let compose_path = run_dir.join("compose.yml");

    let mut context = ComposeRenderContext::default_for_profile(profile.clone(), bridge_cert_dir);
    if let Some(shadow_bin_source) = shadow_bin_source {
        context.shadow_bin_source = Some(shadow_bin_source);
    }
    context.claude_bin_source = claude_bin_source;
    context.codex_runtime_source = codex_runtime_source;
    context.worker_persona_id = worker_persona_id;
    context.worker_command = worker_command;
    context.worker_seccomp_profile_path = worker_seccomp_profile_path;
    context.worker_image = worker_image;
    context.worker_home_path = worker_home_path;
    context.worker_codex_config_path = worker_codex_config_path;
    context.worker_worktree_path = worker_worktree_path;
    context.worker_extra_hosts = worker_extra_hosts;
    context.bridge_enabled = bridge_enabled;
    context.orchestrator_enabled = orchestrator_enabled;
    context.worker_procfs_hardening_enabled = engine.supports_procfs_hardening();
    if let Some(agent_id) = agent_id {
        context.agent_id = agent_id;
    }
    if matches!(engine, RuntimeEngine::Docker) && cfg!(target_os = "linux") {
        context
            .worker_extra_hosts
            .push("host.docker.internal:host-gateway".to_string());
    }
    if context.worker_seccomp_profile_path.is_none() {
        let seccomp_profile_path = template_search_root.join("infra/seccomp/agent-seccomp.json");
        if seccomp_profile_path.exists() {
            context.worker_seccomp_profile_path = Some(seccomp_profile_path);
        }
    }

    let rendered = render_compose_template(&template_path, &context)?;
    std::fs::write(&compose_path, &rendered)?;
    Ok(PreparedIsolatedStack {
        engine,
        profile,
        compose_path,
    })
}

fn resolve_workspace_repo_root(workspace_root: &Path) -> io::Result<PathBuf> {
    let output = match Command::new("git")
        .arg("-C")
        .arg(workspace_root)
        .args(["rev-parse", "--show-toplevel"])
        .output()
    {
        Ok(output) => output,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(workspace_root.to_path_buf());
        }
        Err(err) => return Err(err),
    };
    if !output.status.success() {
        return Ok(workspace_root.to_path_buf());
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

/// Render the compose template at `template_path` (a Jinja2 file —
/// canonical location `crates/headless-runtime/templates/compose.yml.j2`)
/// with the supplied per-run context variables. Returns the rendered
/// YAML as a UTF-8 string.
///
/// implementation-note-438: uses minijinja's strict-undefined mode so
/// missing required variables surface as render errors at boot time
/// rather than silently leaving the template with `{{ var }}` markers
/// that `docker compose` would refuse to parse later.
pub fn render_compose_template(
    template_path: &Path,
    context: &ComposeRenderContext,
) -> io::Result<String> {
    let template_source = std::fs::read_to_string(template_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "render_compose_template: read {}: {}",
                template_path.display(),
                e
            ),
        )
    })?;
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    env.add_template("compose.yml.j2", &template_source)
        .map_err(|e| io::Error::other(format!("compose template parse error: {e}")))?;
    let tmpl = env
        .get_template("compose.yml.j2")
        .map_err(|e| io::Error::other(format!("compose template lookup error: {e}")))?;
    let rendered = tmpl
        .render(context.to_minijinja_value())
        .map_err(|e| io::Error::other(format!("compose template render error: {e}")))?;
    Ok(rendered)
}

/// Per-run context passed to the compose template renderer.
/// Mirrors the `{{ var }}` slots in
/// `crates/headless-runtime/templates/compose.yml.j2`; defaults inside the
/// template handle most optional fields, so the context only needs the
/// load-bearing identity values.
#[derive(Debug, Clone)]
pub struct ComposeRenderContext {
    /// Host-side directory holding bridge cert PEMs (CA, server cert,
    /// server key). Bind-mounted RO into the bridge container at
    /// `/run/ember`.
    pub bridge_cert_dir: PathBuf,
    /// Compose profile name (`dev` / `headless` / `demo`) — selects
    /// which optional services boot.
    pub profile: String,
    /// Whether the worker sidecar should boot. Defaults to true via
    /// the template's `worker_enabled | default(true)`; toggled off
    /// here for headless profiles that don't need a worker.
    pub worker_enabled: bool,
    /// Whether the bridge sidecar should boot. Full `ember up` stacks use
    /// the bridge; direct harness-isolated launches do not.
    pub bridge_enabled: bool,
    /// Whether the orchestrator sidecar should boot. Full `ember up` stacks
    /// use the orchestrator; direct harness-isolated launches do not.
    pub orchestrator_enabled: bool,
    /// Optional worker image override. Harness-isolated launches target the
    /// locally built Claude base image rather than the unpublished fleet tags.
    pub worker_image: Option<String>,
    /// Worktree path bind-mounted into the worker. `None` skips the
    /// worktree mount block.
    pub worker_worktree_path: Option<PathBuf>,
    /// Writable home directory bind-mounted into the worker at
    /// the configured worker home target (`/home/agent` for the harness
    /// isolated lane).
    pub worker_home_path: Option<PathBuf>,
    /// Canonical host `~/.codex` authority mount for Codex's native auth lane.
    pub worker_codex_config_path: Option<PathBuf>,
    /// In-container destination for `worker_home_path`.
    pub worker_home_target: String,
    /// In-container destination for `worker_codex_config_path`.
    pub worker_codex_config_target: String,
    /// Whether Linux-only `/proc` remount + mask hardening should be rendered.
    pub worker_procfs_hardening_enabled: bool,
    /// Host operator UID for idmapped mount + userns_mode. Defaults to
    /// the running process's effective UID.
    pub host_uid: u32,
    /// Host operator GID for idmapped mount. Defaults to the running
    /// process's effective GID. Distinct from `host_uid`: on macOS the
    /// typical user has uid=501 / gid=20 (staff), so defaulting GID to
    /// UID silently miswrites container ownership.
    /// Per implementation-note-528.
    pub host_gid: u32,
    /// Stable agent identifier used in compose volume names so
    /// build-cache volumes are per-agent. Empty string suppresses the
    /// `agent_id`-guarded block in the template.
    pub agent_id: String,
    /// Absolute host path for the Construct shadow-bin mount.
    pub shadow_bin_source: Option<PathBuf>,
    /// Optional host Claude binary override. When `None`, the container image's
    /// baked Claude binary stays active.
    pub claude_bin_source: Option<PathBuf>,
    /// Optional host Codex runtime root mounted at
    /// `/usr/local/lib/ember/codex-runtime`.
    pub codex_runtime_source: Option<PathBuf>,
    /// Persona identifier injected into isolated worker startup env.
    pub worker_persona_id: Option<String>,
    /// Optional worker command override. Isolated harness launches keep the
    /// worker alive for subsequent `compose exec` handoff.
    pub worker_command: Option<Vec<String>>,
    /// Absolute host path for the worker seccomp profile.
    pub worker_seccomp_profile_path: Option<PathBuf>,
    /// Optional extra host mappings for the worker service.
    pub worker_extra_hosts: Vec<String>,
}

impl ComposeRenderContext {
    /// Resolve a default context for `ember up --profile <name>`.
    /// Reads runtime-derived fields (UID, agent_id placeholder) so the
    /// caller in `cmd_up` does not have to assemble them by hand.
    pub fn default_for_profile(profile: impl Into<String>, bridge_cert_dir: PathBuf) -> Self {
        Self {
            bridge_cert_dir,
            profile: profile.into(),
            worker_enabled: true,
            bridge_enabled: true,
            orchestrator_enabled: true,
            worker_image: None,
            worker_worktree_path: None,
            worker_home_path: None,
            worker_codex_config_path: None,
            worker_home_target: CONTAINER_HOME.to_string(),
            worker_codex_config_target: format!("{CONTAINER_HOME}/.codex"),
            worker_procfs_hardening_enabled: cfg!(target_os = "linux"),
            #[cfg(unix)]
            host_uid: {
                // SAFETY: getuid() is signal-safe and always succeeds.
                unsafe { libc::getuid() }
            },
            #[cfg(not(unix))]
            host_uid: 1000,
            #[cfg(unix)]
            host_gid: {
                // SAFETY: getgid() is signal-safe and always succeeds.
                unsafe { libc::getgid() }
            },
            #[cfg(not(unix))]
            host_gid: 1000,
            agent_id: String::new(),
            shadow_bin_source: dirs_next::home_dir()
                .map(|home| home.join(".ember").join("shadow").join("bin")),
            claude_bin_source: None,
            codex_runtime_source: None,
            worker_persona_id: None,
            worker_command: None,
            worker_seccomp_profile_path: None,
            worker_extra_hosts: Vec::new(),
        }
    }

    /// Build the minijinja value map. Keeps the bridge between the
    /// Rust type and the Jinja template names in one spot.
    fn to_minijinja_value(&self) -> minijinja::value::Value {
        use minijinja::value::Value;
        let mut map: std::collections::BTreeMap<&'static str, Value> =
            std::collections::BTreeMap::new();
        map.insert(
            "bridge_cert_dir",
            Value::from(self.bridge_cert_dir.to_string_lossy().to_string()),
        );
        map.insert("profile", Value::from(self.profile.clone()));
        map.insert("worker_enabled", Value::from(self.worker_enabled));
        map.insert("bridge_enabled", Value::from(self.bridge_enabled));
        map.insert(
            "orchestrator_enabled",
            Value::from(self.orchestrator_enabled),
        );
        if let Some(p) = &self.worker_worktree_path {
            map.insert(
                "worker_worktree_path",
                Value::from(p.to_string_lossy().to_string()),
            );
        }
        if let Some(p) = &self.worker_home_path {
            map.insert(
                "worker_home_path",
                Value::from(p.to_string_lossy().to_string()),
            );
        }
        if let Some(p) = &self.worker_codex_config_path {
            map.insert(
                "worker_codex_config_path",
                Value::from(p.to_string_lossy().to_string()),
            );
        }
        map.insert(
            "worker_home_target",
            Value::from(self.worker_home_target.clone()),
        );
        map.insert(
            "worker_codex_config_target",
            Value::from(self.worker_codex_config_target.clone()),
        );
        map.insert(
            "worker_procfs_hardening_enabled",
            Value::from(self.worker_procfs_hardening_enabled),
        );
        map.insert("host_uid", Value::from(self.host_uid));
        map.insert("host_gid", Value::from(self.host_gid));
        if !self.agent_id.is_empty() {
            map.insert("agent_id", Value::from(self.agent_id.clone()));
        }
        if let Some(p) = &self.shadow_bin_source {
            map.insert(
                "ember_override_shadow",
                Value::from(p.to_string_lossy().to_string()),
            );
        }
        if let Some(p) = &self.claude_bin_source {
            map.insert(
                "ember_override_claude",
                Value::from(p.to_string_lossy().to_string()),
            );
        }
        if let Some(p) = &self.codex_runtime_source {
            map.insert(
                "ember_override_codex",
                Value::from(p.to_string_lossy().to_string()),
            );
        }
        if let Some(persona_id) = &self.worker_persona_id {
            map.insert("worker_persona_id", Value::from(persona_id.clone()));
        }
        if let Some(command) = &self.worker_command {
            map.insert("worker_command", Value::from_serialize(command));
        }
        if let Some(p) = &self.worker_seccomp_profile_path {
            map.insert(
                "worker_seccomp_profile_path",
                Value::from(p.to_string_lossy().to_string()),
            );
        }
        if let Some(image) = &self.worker_image {
            map.insert("worker_image", Value::from(image.clone()));
        }
        if !self.worker_extra_hosts.is_empty() {
            map.insert(
                "worker_extra_hosts",
                Value::from_serialize(&self.worker_extra_hosts),
            );
        }
        Value::from_serialize(&map)
    }
}

/// Spawn the compose stack from a pre-rendered compose file.
/// `compose_path` is the path to the YAML written by the caller after
/// [`render_compose_template`]. The function returns
/// `Ok((stdout, stderr))` on a successful `compose up -d` and
/// surfaces non-zero exits as `io::Error`.
pub fn compose_up(
    engine: RuntimeEngine,
    compose_path: &Path,
    profile: &str,
) -> io::Result<(String, String)> {
    let output = Command::new(engine.compose_binary())
        .arg("compose")
        .arg("-f")
        .arg(compose_path)
        .arg("--profile")
        .arg(profile)
        .arg("up")
        .arg("-d")
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{} compose up exited {}: {}",
            engine.display_name(),
            output.status.code().unwrap_or(-1),
            stderr.trim()
        )));
    }
    Ok((stdout, stderr))
}

/// Tear down a compose stack previously started via [`compose_up`].
/// `compose_path` must point at the same rendered YAML the
/// corresponding `ember up` produced. The `purge` flag forwards to
/// `compose down -v` (removes named volumes) — the caller in
/// `cmd_down` is responsible for the operator-confirmation prompt.
pub fn compose_down(
    engine: RuntimeEngine,
    compose_path: &Path,
    purge: bool,
) -> io::Result<(String, String)> {
    let mut cmd = Command::new(engine.compose_binary());
    cmd.arg("compose").arg("-f").arg(compose_path).arg("down");
    if purge {
        cmd.arg("-v");
    }
    // 10s graceful SIGTERM per design review compose-topology D8.
    cmd.arg("--timeout").arg("10");
    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{} compose down exited {}: {}",
            engine.display_name(),
            output.status.code().unwrap_or(-1),
            stderr.trim()
        )));
    }
    Ok((stdout, stderr))
}

pub fn compose_exec(
    engine: RuntimeEngine,
    compose_path: &Path,
    profile: &str,
    service: &str,
    workdir: Option<&str>,
    env_pairs: &[(String, String)],
    binary: &str,
    args: &[String],
) -> io::Result<i32> {
    let mut cmd = Command::new(engine.compose_binary());
    cmd.arg("compose")
        .arg("-f")
        .arg(compose_path)
        .arg("--profile")
        .arg(profile)
        .arg("exec");
    if !std::io::stdin().is_terminal() {
        cmd.arg("-T");
    }
    if let Some(workdir) = workdir {
        cmd.arg("-w").arg(workdir);
    }
    for (key, value) in env_pairs {
        cmd.arg("-e").arg(format!("{key}={value}"));
    }
    cmd.arg(service).arg(binary).args(args);

    let status = cmd.status()?;
    Ok(status.code().unwrap_or(1))
}

/// The daemon responded to a `register_session` call asking for a
/// presence proof before the session can be opened.
///
/// The `tab_url` field is reserved for a future dashboard/browser flow.
#[derive(Debug, Clone)]
pub struct PresenceRequired {
    /// The dashboard URL to open (`http://localhost:<port>/prompt/<prompt_id>`).
    pub tab_url: String,
    /// Opaque prompt identifier used to correlate the handle when polling.
    pub prompt_id: String,
}

/// Attempt to parse a daemon `register_session` response that may carry a
/// "need presence proof" branch.
///
/// Returns `Ok(Ok(reg))` when the daemon minted a session immediately,
/// `Ok(Err(presence))` when the daemon returned the reserved browser-presence
/// branch, or `Err` for unrecognised / invalid responses.
pub fn parse_session_open_response(
    raw: &serde_json::Value,
) -> io::Result<Result<SessionRegistration, PresenceRequired>> {
    // Fast path: normal registration — daemon returned session_id + grant_id.
    if let (Some(session_id), Some(grant_id)) =
        (raw["session_id"].as_str(), raw["grant_id"].as_str())
    {
        let proxy_url = raw["proxy_url"]
            .as_str()
            .unwrap_or("http://127.0.0.1:8484")
            .to_string();
        let anthropic_base_url = raw["anthropic_base_url"].as_str().map(|s| s.to_string());
        let anthropic_custom_headers = raw["anthropic_custom_headers"]
            .as_str()
            .map(|s| s.to_string());
        let git_proxy_url = raw["git_proxy_url"].as_str().map(|s| s.to_string());
        let ssh_auth_sock = raw["ssh_auth_sock"].as_str().map(|s| s.to_string());
        let workflow_id = raw["workflow_id"].as_str().map(|s| s.to_string());
        let workflow_template = raw["workflow_template"].as_str().map(|s| s.to_string());
        return Ok(Ok(SessionRegistration {
            session_id: session_id.to_string(),
            grant_id: grant_id.to_string(),
            proxy_url,
            presence_token_json: raw
                .get("presence_token")
                .map(serde_json::to_string)
                .transpose()
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid presence_token in register_session response: {e}"),
                    )
                })?,
            anthropic_base_url,
            anthropic_custom_headers,
            git_proxy_url,
            ssh_auth_sock,
            workflow_id,
            workflow_template,
        }));
    }

    // Reserved browser-presence branch.
    if let (Some(tab_url), Some(prompt_id)) = (
        raw["presence_required"]["tab_url"].as_str(),
        raw["presence_required"]["prompt_id"].as_str(),
    ) {
        return Ok(Err(PresenceRequired {
            tab_url: tab_url.to_string(),
            prompt_id: prompt_id.to_string(),
        }));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unrecognised daemon session-open response: {}", raw),
    ))
}

/// Open a session via the daemon response payload.
///
/// Direct `register_session` success remains the shipped path. If the daemon
/// returns the reserved `presence_required` branch, the function refuses
/// cleanly with `io::ErrorKind::Unsupported` rather than opening a browser and
/// then failing later.
pub async fn open_session_with_presence(
    socket_path: &Path,
    raw_response: &serde_json::Value,
) -> io::Result<SessionRegistration> {
    match parse_session_open_response(raw_response)? {
        Ok(registration) => Ok(registration),
        Err(presence_required) => Err(presence::session_open_presence_unavailable(
            socket_path,
            &presence_required.prompt_id,
            &presence_required.tab_url,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvGuard {
        home: Option<std::ffi::OsString>,
        path: Option<std::ffi::OsString>,
        template: Option<std::ffi::OsString>,
        cwd: PathBuf,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                home: std::env::var_os("HOME"),
                path: std::env::var_os("PATH"),
                template: std::env::var_os("EMBER_COMPOSE_TEMPLATE"),
                cwd: std::env::current_dir().expect("capture cwd"),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.cwd);
            // SAFETY: test-only environment restoration under a process-wide lock.
            unsafe {
                match &self.home {
                    Some(value) => std::env::set_var("HOME", value),
                    None => std::env::remove_var("HOME"),
                }
                match &self.path {
                    Some(value) => std::env::set_var("PATH", value),
                    None => std::env::remove_var("PATH"),
                }
                match &self.template {
                    Some(value) => std::env::set_var("EMBER_COMPOSE_TEMPLATE", value),
                    None => std::env::remove_var("EMBER_COMPOSE_TEMPLATE"),
                }
            }
        }
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, contents: &str) {
        use std::os::unix::fs::PermissionsExt as _;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(path, contents).expect("write executable");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("set executable permissions");
    }

    #[cfg(unix)]
    fn install_fake_docker(bin_dir: &Path, exec_exit_code: i32) -> PathBuf {
        let docker = bin_dir.join("docker");
        let log_path = bin_dir.join("docker.log");
        write_executable(
            &docker,
            &format!(
                "#!/bin/sh\n\
set -eu\n\
log='{}'\n\
printf 'CMD' >> \"$log\"\n\
for arg in \"$@\"; do\n\
  printf ' [%s]' \"$arg\" >> \"$log\"\n\
done\n\
printf '\\n' >> \"$log\"\n\
case \" $* \" in\n\
  *\" exec \"*) exit {exec_exit_code} ;;\n\
  *\" up -d \"*) echo 'stack up'; exit 0 ;;\n\
  *) exit 0 ;;\n\
esac\n",
                log_path.display()
            ),
        );
        log_path
    }

    #[test]
    fn parse_normal_registration_response() {
        let raw = json!({
            "session_id": "sess_abc",
            "grant_id": "grt_abc",
            "proxy_url": "http://127.0.0.1:9001",
            "git_proxy_url": "http://127.0.0.1:9002",
            "ssh_auth_sock": "/tmp/ember-ssh-agent.sock",
        });
        let result = parse_session_open_response(&raw).expect("should parse");
        let reg = result.expect("should be Ok(registration), not Err(presence)");
        assert_eq!(reg.session_id, "sess_abc");
        assert_eq!(reg.grant_id, "grt_abc");
        assert_eq!(reg.proxy_url, "http://127.0.0.1:9001");
        assert_eq!(reg.anthropic_base_url, None);
        assert_eq!(reg.anthropic_custom_headers, None);
        assert_eq!(reg.git_proxy_url.as_deref(), Some("http://127.0.0.1:9002"));
        assert_eq!(
            reg.ssh_auth_sock.as_deref(),
            Some("/tmp/ember-ssh-agent.sock")
        );
    }

    #[test]
    fn parse_registration_with_anthropic_gateway_bundle() {
        let raw = json!({
            "session_id": "sess_abc",
            "grant_id": "grt_abc",
            "proxy_url": "http://127.0.0.1:9001",
            "anthropic_base_url": "http://127.0.0.1:9001",
            "anthropic_custom_headers": "X-Ember-Persona: persona-main\nX-Ember-Credential: anthropic-key\nX-Ember-Target: https://api.anthropic.com",
        });
        let result = parse_session_open_response(&raw).expect("should parse");
        let reg = result.expect("should be Ok(registration), not Err(presence)");
        assert_eq!(
            reg.anthropic_base_url.as_deref(),
            Some("http://127.0.0.1:9001")
        );
        assert_eq!(
            reg.anthropic_custom_headers.as_deref(),
            Some(
                "X-Ember-Persona: persona-main\nX-Ember-Credential: anthropic-key\nX-Ember-Target: https://api.anthropic.com"
            )
        );
    }

    #[test]
    fn parse_registration_without_proxy_url_uses_fallback() {
        let raw = json!({
            "session_id": "sess_nourl",
            "grant_id": "grt_nourl",
        });
        let result = parse_session_open_response(&raw).expect("should parse");
        let reg = result.expect("should be Ok(registration)");
        assert_eq!(reg.proxy_url, "http://127.0.0.1:8484");
    }

    #[test]
    fn parse_presence_required_response() {
        let raw = json!({
            "presence_required": {
                "tab_url": "http://localhost:5173/prompt/pmt_xyz",
                "prompt_id": "pmt_xyz",
            }
        });
        let result = parse_session_open_response(&raw).expect("should parse");
        let presence = result.expect_err("should be Err(presence_required)");
        assert_eq!(presence.tab_url, "http://localhost:5173/prompt/pmt_xyz");
        assert_eq!(presence.prompt_id, "pmt_xyz");
    }

    #[test]
    fn parse_unrecognised_response_returns_io_error() {
        let raw = json!({ "unexpected_field": true });
        let result = parse_session_open_response(&raw);
        assert!(result.is_err(), "unrecognised response must surface as Err");
    }

    #[tokio::test]
    async fn open_session_with_presence_returns_direct_registration() {
        let raw = json!({
            "session_id": "sess_abc",
            "grant_id": "grt_abc",
            "proxy_url": "http://127.0.0.1:9001",
        });
        let reg = open_session_with_presence(Path::new("/tmp/daemon.sock"), &raw)
            .await
            .expect("direct registration must still work");
        assert_eq!(reg.session_id, "sess_abc");
        assert_eq!(reg.grant_id, "grt_abc");
    }

    #[tokio::test]
    async fn open_session_with_presence_refuses_reserved_presence_branch() {
        let raw = json!({
            "presence_required": {
                "tab_url": "http://localhost:5173/prompt/pmt_xyz",
                "prompt_id": "pmt_xyz",
            }
        });
        let err = open_session_with_presence(Path::new("/tmp/daemon.sock"), &raw)
            .await
            .expect_err("reserved browser branch must refuse cleanly");
        let msg = err.to_string();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(
            msg.contains("browser/session-open presence flow is not shipped yet"),
            "error must explain current state: {msg}"
        );
        assert!(
            msg.contains("tab_url=http://localhost:5173/prompt/pmt_xyz"),
            "error must keep the returned tab_url for debugging: {msg}"
        );
        assert!(
            msg.contains("prompt_id=pmt_xyz"),
            "error must keep the returned prompt_id for debugging: {msg}"
        );
    }

    #[test]
    fn render_compose_template_substitutes_context() {
        // implementation-note-438 — minimal smoke against a one-line
        // Jinja fragment so the renderer wiring is exercised without
        // depending on the bundled compose.yml.j2's full surface.
        let tmp = tempfile::tempdir().expect("tempdir");
        let template = tmp.path().join("mini.yml.j2");
        std::fs::write(
            &template,
            "bridge_cert_dir: {{ bridge_cert_dir }}\nprofile: {{ profile }}\n",
        )
        .expect("write fixture");
        let ctx = ComposeRenderContext::default_for_profile("dev", PathBuf::from("/tmp/certs"));
        let rendered = render_compose_template(&template, &ctx).expect("render");
        assert!(rendered.contains("bridge_cert_dir: /tmp/certs"));
        assert!(rendered.contains("profile: dev"));
    }

    #[test]
    fn render_compose_template_uses_host_gid_distinct_from_host_uid() {
        // implementation-note-528: prior to this fix the
        // template defaulted host_gid to host_uid, silently miswriting
        // container ownership on macOS (uid=501, gid=20). The fix gives
        // host_gid its own default. Property: rendering with mismatched
        // uid/gid produces a YAML fragment containing both distinct
        // values, not the uid twice.
        let tmp = tempfile::tempdir().expect("tempdir");
        let template = tmp.path().join("idmap.yml.j2");
        std::fs::write(
            &template,
            "uid: {{ host_uid | default(1000) }}\ngid: {{ host_gid | default(1000) }}\n",
        )
        .expect("write fixture");
        let mut ctx = ComposeRenderContext::default_for_profile("dev", PathBuf::from("/tmp/certs"));
        ctx.host_uid = 501;
        ctx.host_gid = 20;
        let rendered = render_compose_template(&template, &ctx).expect("render");
        assert!(
            rendered.contains("uid: 501"),
            "expected uid: 501 in {rendered}"
        );
        assert!(
            rendered.contains("gid: 20"),
            "expected gid: 20 (distinct from uid), got {rendered}"
        );
    }

    #[test]
    fn render_compose_template_strict_undefined_refuses_missing_var() {
        // implementation-note-438 — UndefinedBehavior::Strict means a
        // template referencing an unset variable surfaces as an error
        // at boot time rather than silently rendering "" into the YAML.
        let tmp = tempfile::tempdir().expect("tempdir");
        let template = tmp.path().join("strict.yml.j2");
        std::fs::write(&template, "missing: {{ never_set }}\n").expect("write fixture");
        let ctx = ComposeRenderContext::default_for_profile("dev", PathBuf::from("/tmp/certs"));
        let err = render_compose_template(&template, &ctx)
            .expect_err("strict mode must refuse undefined variable");
        let msg = err.to_string();
        assert!(
            msg.contains("render error"),
            "unexpected error shape: {msg}"
        );
    }

    #[test]
    fn detect_runtime_engine_returns_ok() {
        // Smoke: the detector must not panic on any host. Result content
        // depends on the host PATH; we only assert it's well-formed.
        let _ = detect_runtime_engine().expect("detection must not error");
    }

    #[test]
    fn which_on_path_skips_non_executable_candidates() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = tmp.path().join("first");
        let second = tmp.path().join("second");
        std::fs::create_dir_all(&first).expect("create first path entry");
        std::fs::create_dir_all(&second).expect("create second path entry");

        let blocked = first.join("docker");
        std::fs::write(&blocked, "#!/bin/sh\nexit 0\n").expect("write blocked docker");
        #[cfg(unix)]
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o644))
            .expect("chmod blocked docker");

        let ready = second.join("docker");
        std::fs::write(&ready, "#!/bin/sh\nexit 0\n").expect("write ready docker");
        #[cfg(unix)]
        std::fs::set_permissions(&ready, std::fs::Permissions::from_mode(0o755))
            .expect("chmod ready docker");

        // SAFETY: test-only environment override under a process-wide lock.
        unsafe { std::env::set_var("PATH", format!("{}:{}", first.display(), second.display())) };

        let resolved = which_on_path("docker").expect("resolve docker");
        drop(env);
        assert_eq!(resolved.as_deref(), Some(ready.as_path()));
    }

    #[test]
    fn open_claude_code_isolated_uses_operator_session_root_not_daemon_run_dir() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let daemon_run_dir = home.join(".ember").join("run");
        std::fs::create_dir_all(&daemon_run_dir).expect("create daemon run dir");
        #[cfg(unix)]
        std::fs::set_permissions(&daemon_run_dir, std::fs::Permissions::from_mode(0o000))
            .expect("chmod daemon run dir");

        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");
        let docker = bin_dir.join("docker");
        std::fs::write(&docker, "#!/bin/sh\nexit 0\n").expect("write fake docker");
        #[cfg(unix)]
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake docker");

        let template = tmp.path().join("compose.yml.j2");
        std::fs::write(&template, "services: {}\n").expect("write compose template");

        // SAFETY: test-only environment override under a process-wide lock.
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("PATH", &bin_dir);
            std::env::set_var("EMBER_COMPOSE_TEMPLATE", &template);
        }
        let expected_session_open_root = isolated_session_run_root(&home);
        std::env::set_current_dir(tmp.path()).expect("set cwd");

        let result = open_claude_code_isolated(Some("dev"), Some("docker"));

        #[cfg(unix)]
        std::fs::set_permissions(&daemon_run_dir, std::fs::Permissions::from_mode(0o700))
            .expect("restore daemon run dir perms");
        drop(env);

        result.expect("isolated launch should not require daemon-owned ~/.ember/run");
        assert!(
            expected_session_open_root.exists(),
            "operator-owned session-open root must exist"
        );

        let compose_files: Vec<_> = std::fs::read_dir(&expected_session_open_root)
            .expect("list session-open root")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path().join("compose.yml"))
            .filter(|path| path.exists())
            .collect();
        assert!(
            !compose_files.is_empty(),
            "expected a rendered compose.yml under {}",
            expected_session_open_root.display()
        );
    }

    fn bundled_compose_template_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../headless-runtime/templates/compose.yml.j2")
    }

    fn fixture_registration() -> SessionRegistration {
        SessionRegistration {
            session_id: "sess_fixture".to_string(),
            grant_id: "grant_fixture".to_string(),
            presence_token_json: None,
            proxy_url: "http://127.0.0.1:62735".to_string(),
            anthropic_base_url: Some("http://localhost:62735".to_string()),
            anthropic_custom_headers: Some("X-Test: one".to_string()),
            git_proxy_url: Some("https://127.0.0.1:62727".to_string()),
            ssh_auth_sock: None,
            workflow_id: None,
            workflow_template: None,
        }
    }

    #[test]
    fn rewrite_loopback_url_for_container_uses_engine_specific_host_alias() {
        assert_eq!(
            rewrite_loopback_url_for_container("http://127.0.0.1:4242", RuntimeEngine::Docker),
            "http://host.docker.internal:4242"
        );
        assert_eq!(
            rewrite_loopback_url_for_container("https://localhost:4243", RuntimeEngine::OrbStack),
            "https://host.docker.internal:4243"
        );
        assert_eq!(
            rewrite_loopback_url_for_container("http://127.0.0.1:4244", RuntimeEngine::Podman),
            "http://host.containers.internal:4244"
        );
        assert_eq!(
            rewrite_loopback_url_for_container("https://api.anthropic.com", RuntimeEngine::Docker),
            "https://api.anthropic.com"
        );
    }

    #[test]
    fn isolated_child_env_rewrites_proxy_urls_for_container() {
        let env = isolated_child_env(
            RuntimeEngine::Podman,
            "persona-main",
            &fixture_registration(),
        );
        let env_map: std::collections::BTreeMap<_, _> = env.into_iter().collect();

        assert_eq!(
            env_map.get("EMBER_PERSONA").map(String::as_str),
            Some("persona-main")
        );
        assert_eq!(
            env_map.get("EMBER_PROXY_URL").map(String::as_str),
            Some("http://host.containers.internal:62735")
        );
        assert_eq!(
            env_map.get("ANTHROPIC_BASE_URL").map(String::as_str),
            Some("http://host.containers.internal:62735")
        );
        assert_eq!(
            env_map.get("EMBER_GIT_PROXY_URL").map(String::as_str),
            Some("https://host.containers.internal:62727")
        );
        assert_eq!(
            env_map.get("ANTHROPIC_CUSTOM_HEADERS").map(String::as_str),
            Some("X-Test: one")
        );
        assert_eq!(
            env_map.get("HOME").map(String::as_str),
            Some(CONTAINER_HOME)
        );
        assert_eq!(
            env_map.get("PATH").map(String::as_str),
            Some(CONTAINER_DEFAULT_PATH)
        );
    }

    #[test]
    fn render_real_compose_template_includes_codex_isolated_mounts() {
        let template = bundled_compose_template_path();
        assert!(template.exists(), "expected bundled compose template");

        let mut ctx =
            ComposeRenderContext::default_for_profile("headless", PathBuf::from("/tmp/certs"));
        ctx.shadow_bin_source = Some(PathBuf::from("/home/test/.ember/shadow/bin"));
        ctx.codex_runtime_source = Some(PathBuf::from("/home/test/.local/share/codex-runtime"));
        ctx.worker_home_path = Some(PathBuf::from("/home/test/.ember/session-open/worker-home"));
        ctx.worker_codex_config_path = Some(PathBuf::from("/home/test/.codex"));
        ctx.worker_worktree_path = Some(PathBuf::from("/home/test/src/repo"));
        ctx.worker_extra_hosts = vec!["host.docker.internal:host-gateway".to_string()];
        ctx.agent_id = "sess_fixture".to_string();

        let rendered = render_compose_template(&template, &ctx).expect("render real template");

        assert!(rendered.contains("extra_hosts:"));
        assert!(rendered.contains("\"host.docker.internal:host-gateway\""));
        assert!(rendered.contains("source: \"/home/test/.local/share/codex-runtime\""));
        assert!(rendered.contains("target: /usr/local/lib/ember/codex-runtime"));
        assert!(rendered.contains("source: \"/home/test/.ember/session-open/worker-home\""));
        assert!(rendered.contains("target: \"/home/agent\""));
        assert!(rendered.contains("source: \"/home/test/.codex\""));
        assert!(rendered.contains("target: \"/home/agent/.codex\""));
        assert!(rendered.contains("source: \"/home/test/src/repo\""));
        assert!(rendered.contains("target: /work/repo"));
    }

    #[test]
    fn render_real_compose_template_standalone_worker_omits_bridge_services() {
        let template = bundled_compose_template_path();
        assert!(template.exists(), "expected bundled compose template");

        let mut ctx = ComposeRenderContext::default_for_profile("dev", PathBuf::from("/tmp/certs"));
        ctx.bridge_enabled = false;
        ctx.orchestrator_enabled = false;
        ctx.worker_procfs_hardening_enabled = false;
        ctx.worker_image = Some(ISOLATED_HARNESS_WORKER_IMAGE.to_string());
        ctx.worker_command = Some(vec![
            "sh".to_string(),
            "-lc".to_string(),
            "tail -f /dev/null".to_string(),
        ]);
        ctx.worker_worktree_path = Some(PathBuf::from("/home/test/src/repo"));

        let rendered = render_compose_template(&template, &ctx).expect("render real template");

        assert!(
            !rendered.contains("\n  bridge:\n"),
            "standalone worker render must omit bridge service"
        );
        assert!(
            !rendered.contains("\n  orchestrator:\n"),
            "standalone worker render must omit orchestrator service"
        );
        assert!(rendered.contains("image: \"ember-claude-code:v1\""));
        assert!(rendered.contains("command:"));
        assert!(rendered.contains("- \"tail -f /dev/null\""));
        assert!(
            !rendered.contains("EMBER_BRIDGE_URL"),
            "standalone worker render must not inject bridge env"
        );
        assert!(
            !rendered.contains("proc-masks="),
            "standalone worker render must omit Linux-only proc masks when procfs hardening is disabled"
        );
        assert!(
            !rendered.contains("\"/proc:hidepid=2,gid=0\""),
            "standalone worker render must omit Linux-only /proc remount hardening when procfs hardening is disabled"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_isolated_stack_preserves_default_shadow_mount_when_override_absent() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let bin_dir = tmp.path().join("bin");
        let workspace_root = tmp.path().join("repo");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");
        std::fs::create_dir_all(&workspace_root).expect("create workspace root");
        install_fake_docker(&bin_dir, 0);

        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("PATH", &bin_dir);
            std::env::set_var("EMBER_COMPOSE_TEMPLATE", bundled_compose_template_path());
        }

        let prepared = prepare_isolated_stack(
            Some("dev"),
            Some("docker"),
            &workspace_root,
            ComposeRenderContextOverrides::default(),
        )
        .expect("prepare isolated stack");

        let compose = std::fs::read_to_string(&prepared.compose_path).expect("read compose file");
        assert!(
            compose.contains(&format!(
                "source: \"{}\"",
                home.join(".ember").join("shadow").join("bin").display()
            )),
            "default isolated stack render must preserve the default shadow bind mount: {compose}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn launch_harness_isolated_claude_uses_standalone_worker_handoff() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let bin_dir = tmp.path().join("bin");
        let workspace_root = tmp.path().join("repo");
        let shadow_root = tmp.path().join("shadow");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");
        std::fs::create_dir_all(&workspace_root).expect("create workspace root");
        std::fs::create_dir_all(&shadow_root).expect("create shadow root");
        let docker_log = install_fake_docker(&bin_dir, 23);

        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("PATH", &bin_dir);
            std::env::set_var("EMBER_COMPOSE_TEMPLATE", bundled_compose_template_path());
        }

        let code = launch_harness_isolated(IsolatedHarnessLaunch {
            harness: HarnessKind::Claude,
            persona: "persona-main".to_string(),
            registration: fixture_registration(),
            extra_args: vec!["--help".to_string()],
            backend_hint: Some("docker".to_string()),
            preset: Some("dev".to_string()),
            workspace_root: workspace_root.clone(),
            shadow_root,
            codex_runtime_source: None,
            codex_config_source: None,
        })
        .expect("launch isolated claude");

        assert_eq!(code, 23, "compose exec exit code should bubble up");
        let session_open_root = isolated_session_run_root(&home);
        assert!(
            session_open_root.join("claude-home-sess_fixture").exists(),
            "isolated worker home must live under the operator-owned session-open root"
        );

        let compose_files: Vec<_> = std::fs::read_dir(&session_open_root)
            .expect("list session-open root")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path().join("compose.yml"))
            .filter(|path| path.exists())
            .collect();
        assert_eq!(compose_files.len(), 1, "expected one compose render");
        let compose = std::fs::read_to_string(&compose_files[0]).expect("read compose file");
        assert!(!compose.contains("\n  bridge:\n"));
        assert!(!compose.contains("\n  orchestrator:\n"));
        assert!(compose.contains("- \"tail -f /dev/null\""));

        let docker_log = std::fs::read_to_string(docker_log).expect("read docker log");
        assert!(docker_log.contains("[up] [-d]"));
        assert!(docker_log.contains("[exec] [-T] [-w] [/work/repo]"));
        assert!(docker_log.contains("[down] [-v] [--timeout] [10]"));
        assert!(docker_log.contains("[worker] [claude] [--help]"));
    }

    #[cfg(unix)]
    #[test]
    fn launch_harness_isolated_codex_execs_container_runtime_binary() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let bin_dir = tmp.path().join("bin");
        let workspace_root = tmp.path().join("repo");
        let shadow_root = tmp.path().join("shadow");
        let codex_runtime_root = tmp.path().join("codex-runtime");
        let codex_config_root = home.join(".codex");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");
        std::fs::create_dir_all(&workspace_root).expect("create workspace root");
        std::fs::create_dir_all(&shadow_root).expect("create shadow root");
        std::fs::create_dir_all(&codex_runtime_root).expect("create codex runtime root");
        std::fs::create_dir_all(&codex_config_root).expect("create codex config root");
        let docker_log = install_fake_docker(&bin_dir, 23);

        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("PATH", &bin_dir);
            std::env::set_var("EMBER_COMPOSE_TEMPLATE", bundled_compose_template_path());
        }

        let code = launch_harness_isolated(IsolatedHarnessLaunch {
            harness: HarnessKind::Codex,
            persona: "persona-main".to_string(),
            registration: fixture_registration(),
            extra_args: vec!["--help".to_string()],
            backend_hint: Some("docker".to_string()),
            preset: Some("dev".to_string()),
            workspace_root,
            shadow_root,
            codex_runtime_source: Some(codex_runtime_root.clone()),
            codex_config_source: Some(codex_config_root.clone()),
        })
        .expect("launch isolated codex");

        assert_eq!(code, 23, "compose exec exit code should bubble up");
        let session_open_root = isolated_session_run_root(&home);
        let compose_files: Vec<_> = std::fs::read_dir(&session_open_root)
            .expect("list session-open root")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path().join("compose.yml"))
            .filter(|path| path.exists())
            .collect();
        assert_eq!(compose_files.len(), 1, "expected one compose render");
        let compose = std::fs::read_to_string(&compose_files[0]).expect("read compose file");
        assert!(compose.contains(&format!("source: \"{}\"", codex_runtime_root.display())));
        assert!(compose.contains(&format!("source: \"{}\"", codex_config_root.display())));

        let docker_log = std::fs::read_to_string(docker_log).expect("read docker log");
        assert!(docker_log.contains("[up] [-d]"));
        assert!(docker_log.contains("[exec] [-T] [-w] [/work/repo]"));
        assert!(docker_log.contains("[down] [-v] [--timeout] [10]"));
        assert!(
            docker_log.contains("[worker] [/usr/local/lib/ember/codex-runtime/bin/codex]"),
            "Codex handoff must exec the container runtime binary: {docker_log}"
        );
        assert!(
            docker_log.contains("[-C] [/work/repo] [--help]"),
            "Codex handoff must inject the container worktree via -C: {docker_log}"
        );
    }

    // ember_up_auto_update_b_launcher_integration — branch coverage for the
    // four UpdateDecision branches + the two UpdateDecisionError variants +
    // the "not configured" skip path.
    mod auto_update {
        use super::super::*;
        use ed25519_dalek::SigningKey;
        use ember_update::channel::{Channel, sign_channel_pointer};
        use ember_update::revocations::RevocationsPoller;
        use serde_json::json;

        const FIXED_DIGEST: &str =
            "sha256:0000000000000000000000000000000000000000000000000000000000000001";
        const NEW_DIGEST: &str =
            "sha256:0000000000000000000000000000000000000000000000000000000000000002";

        fn fixture_keys() -> (SigningKey, VerifyingKey) {
            let sk = SigningKey::from_bytes(&[42u8; 32]);
            let vk = sk.verifying_key();
            (sk, vk)
        }

        fn make_pointer(sk: &SigningKey, digest: &str, now_ms: u64) -> ChannelPointer {
            sign_channel_pointer(
                Channel::Release,
                "https://manifest.example/manifest-001.json".to_string(),
                digest.to_string(),
                60 * 60 * 1000,
                now_ms,
                sk,
            )
        }

        fn fresh_revocations_doc(now_unix_secs: u64) -> Vec<u8> {
            serde_json::to_vec(&json!({
                "issued_at_unix_secs": now_unix_secs,
                "revocations": []
            }))
            .expect("serialize revocations doc")
        }

        fn revoked_revocations_doc(now_unix_secs: u64, digest: &str, severity: &str) -> Vec<u8> {
            serde_json::to_vec(&json!({
                "issued_at_unix_secs": now_unix_secs,
                "revocations": [{
                    "digest": digest,
                    "severity": severity,
                    "reason": "test fixture revocation",
                }]
            }))
            .expect("serialize revocations doc")
        }

        #[test]
        fn skipped_when_inputs_absent() {
            let outcome =
                run_auto_update_check(None, None, None, None, None, 0).expect("skip path is Ok");
            assert_eq!(outcome, AutoUpdateOutcome::Skipped);
        }

        #[test]
        fn no_update_when_digests_match() {
            let (sk, vk) = fixture_keys();
            let now_ms = 1_700_000_000_000u64;
            let pointer = make_pointer(&sk, FIXED_DIGEST, now_ms);
            let revocations = fresh_revocations_doc(now_ms / 1000);
            let poller = RevocationsPoller::new();
            let outcome = run_auto_update_check(
                Some(FIXED_DIGEST),
                Some(&pointer),
                Some(&vk),
                Some(&revocations),
                Some(&poller),
                now_ms,
            )
            .expect("ok branch");
            assert_eq!(outcome, AutoUpdateOutcome::NoUpdate);
        }

        #[test]
        fn update_available_when_pointer_advances() {
            let (sk, vk) = fixture_keys();
            let now_ms = 1_700_000_000_000u64;
            let pointer = make_pointer(&sk, NEW_DIGEST, now_ms);
            let revocations = fresh_revocations_doc(now_ms / 1000);
            let poller = RevocationsPoller::new();
            let outcome = run_auto_update_check(
                Some(FIXED_DIGEST),
                Some(&pointer),
                Some(&vk),
                Some(&revocations),
                Some(&poller),
                now_ms,
            )
            .expect("ok branch");
            match outcome {
                AutoUpdateOutcome::UpdateAvailable { new_digest, .. } => {
                    assert_eq!(new_digest, NEW_DIGEST);
                }
                other => panic!("expected UpdateAvailable, got {other:?}"),
            }
        }

        #[test]
        fn current_revoked_critical_refuses() {
            let (sk, vk) = fixture_keys();
            let now_ms = 1_700_000_000_000u64;
            let pointer = make_pointer(&sk, FIXED_DIGEST, now_ms);
            let revocations = revoked_revocations_doc(now_ms / 1000, FIXED_DIGEST, "critical");
            let poller = RevocationsPoller::new();
            let err = run_auto_update_check(
                Some(FIXED_DIGEST),
                Some(&pointer),
                Some(&vk),
                Some(&revocations),
                Some(&poller),
                now_ms,
            )
            .expect_err("critical revocation should refuse to start");
            assert!(err.to_string().contains("refusing to start"));
        }

        #[test]
        fn pointer_invalid_refuses() {
            let (sk, _vk) = fixture_keys();
            let (sk_other, vk_other) = {
                let sk = SigningKey::from_bytes(&[7u8; 32]);
                let vk = sk.verifying_key();
                (sk, vk)
            };
            let _ = sk_other; // unused — we deliberately verify the pointer with a
            // mismatched key to force PointerInvalid.
            let now_ms = 1_700_000_000_000u64;
            let pointer = make_pointer(&sk, FIXED_DIGEST, now_ms);
            let revocations = fresh_revocations_doc(now_ms / 1000);
            let poller = RevocationsPoller::new();
            let err = run_auto_update_check(
                Some(FIXED_DIGEST),
                Some(&pointer),
                Some(&vk_other), // wrong verifying key — signature won't verify
                Some(&revocations),
                Some(&poller),
                now_ms,
            )
            .expect_err("pointer signed by other key should fail verify");
            assert!(err.to_string().contains("refusing to start"));
        }
    }
}
