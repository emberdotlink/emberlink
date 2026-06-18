//! CLASSIFICATION: PUBLIC
//! `ember up` / `ember claude|codex --isolated` — the isolated container launcher.
//!
//! Renders the worker compose stack, prepares the ADR 154 mTLS bridge client
//! bundle, assembles the container child env, and execs the harness inside the
//! worker container. The canonical `register_session` response parser lives in
//! [`crate::launcher::session_rpc::parse_register_session_result`]; the reserved
//! `presence_required` branch is rejected there with an `Unsupported` error.
//! (An earlier duplicate parser in this module, `parse_session_open_response` /
//! `open_session_with_presence`, was dead — zero non-test callers — and was
//! deleted to keep one response parser, per ADR 207 seam 6.)

pub mod fallback;
pub mod idmapped;
pub mod overrides;
pub mod sandvault;
pub mod userns;
pub mod volumes;

use std::ffi::OsString;
use std::io;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::launcher::claude_code::SessionRegistration;
use crate::launcher::harness::HarnessKind;
use crate::launcher::path_shadow::{ConstructSpec, install_path_shadow, shadow_bin_dir};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandvaultRuntimeCapability {
    Available {
        binary: PathBuf,
        version: String,
    },
    Unavailable {
        reason: String,
    },
    Blocked {
        binary: Option<PathBuf>,
        reason: String,
    },
}

const CONTAINER_WORKDIR: &str = "/work/repo";
const CONTAINER_HOME: &str = "/home/agent";
const CONTAINER_CODEX_RUNTIME_ROOT: &str = "/usr/local/lib/ember/codex-runtime";
// ADR 207 seam 8 / §correction-2: the daemon UDS is never mounted into the
// container (no `/run/emberd-host`), nor handed to it as `EMBER_SOCKET_PATH` /
// `EMBER_DAEMON_SOCKET` — the container reaches emberd only over the ADR 154
// mTLS bridge. The former `CONTAINER_DAEMON_MOUNT_ROOT` / `CONTAINER_DAEMON_SOCKET`
// constants were removed with the UDS-in-container path.
const CONTAINER_BRIDGE_CERT: &str = "/run/ember/client.crt";
const CONTAINER_BRIDGE_KEY: &str = "/run/ember/client.key";
const CONTAINER_BRIDGE_CA: &str = "/run/ember/ca.crt";
const ISOLATED_COMPOSE_PROJECT_PREFIX: &str = "dev-";
const ISOLATED_COMPOSE_PROJECT_HEX_LEN: usize = 32;
// ssh-agent-over-bridge S2: the former `CONTAINER_SSH_AUTH_SOCK` (a host
// ssh-agent socket bind-mounted into the worker at `/run/ember/ssh-agent.sock`)
// was retired — that path handed the in-container agent unbridged, unleased,
// unaudited use of every key the host agent held. With it gone, in-container SSH
// fails closed (no agent socket, no host key files). The TARGET path is the
// brokered S1 signer (`ember-broker::ssh_agent_bridge`, lease-gated +
// per-session-key-isolated), reached via a container-LOCAL `$SSH_AUTH_SOCK` UDS
// served by the bridge client (NOT a host mount); that forwarder + its lease land
// with the S3 `register_session` provisioning. Until S3, SSH stays fail-closed.
const CONTAINER_EMBER_BINARIES_ROOT: &str = "/usr/local/lib/ember/binaries";
const CONTAINER_SHADOW_BIN_DIR: &str = "/usr/local/lib/shadow/bin";
const CONTAINER_SHELL_ENV_FILE: &str = "/home/agent/.ember-shell-env";
const CONTAINER_DEFAULT_PATH: &str =
    "/usr/local/lib/shadow/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin";
const ISOLATED_HARNESS_WORKER_IMAGE: &str = "ember-claude-code:v1";
const ISOLATED_CLAUDE_PROXY_AUTH_PLACEHOLDER: &str = "ember-proxy-session";

fn resolve_home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .or_else(dirs_next::home_dir)
}

/// ARCH-CLI-EMBER-UP-VERB-B — container runtime engines `ember up`
/// detects on the host. Order tracks autogrill 2026-05-15 compose-
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
/// locked by autogrill 2026-05-15 compose-topology D7. Returns
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

pub fn detect_sandvault_runtime_capability() -> io::Result<SandvaultRuntimeCapability> {
    if !cfg!(target_os = "macos") {
        return Ok(SandvaultRuntimeCapability::Unavailable {
            reason: "Sandvault is macOS-only".to_string(),
        });
    }

    if let Some(explicit) = std::env::var_os("SANDVAULT_BIN").filter(|value| !value.is_empty()) {
        let binary = PathBuf::from(explicit);
        if !path_is_executable(&binary)? {
            return Ok(SandvaultRuntimeCapability::Blocked {
                binary: Some(binary),
                reason: "SANDVAULT_BIN is set but is not executable".to_string(),
            });
        }
        return detect_sandvault_runtime_capability_from_binary(Some(binary));
    }

    let binary = which_on_path_from_env("sv", std::env::var_os("PATH"))?;
    detect_sandvault_runtime_capability_from_binary(binary)
}

fn detect_sandvault_runtime_capability_from_binary(
    binary: Option<PathBuf>,
) -> io::Result<SandvaultRuntimeCapability> {
    let Some(binary) = binary else {
        return Ok(SandvaultRuntimeCapability::Unavailable {
            reason: "Sandvault CLI `sv` is not on PATH".to_string(),
        });
    };

    let version_output = Command::new(&binary).arg("--version").output()?;
    if !version_output.status.success() {
        return Ok(SandvaultRuntimeCapability::Blocked {
            binary: Some(binary),
            reason: format!(
                "`sv --version` failed: {}",
                command_output_summary(&version_output)
            ),
        });
    }
    let version = String::from_utf8_lossy(&version_output.stdout)
        .trim()
        .to_string();

    let no_build_output = Command::new(&binary)
        .args(["--no-build", "shell", "--", "/usr/bin/true"])
        .output()?;
    if no_build_output.status.success() {
        return Ok(SandvaultRuntimeCapability::Available { binary, version });
    }

    let summary = command_output_summary(&no_build_output);
    if summary.contains("sandvault is not installed") {
        return Ok(SandvaultRuntimeCapability::Unavailable {
            reason: "Sandvault CLI is present, but host provisioning is not installed".to_string(),
        });
    }
    if summary.contains("sandbox_apply: Operation not permitted") {
        return Ok(SandvaultRuntimeCapability::Blocked {
            binary: Some(binary),
            reason: "current harness blocks nested sandbox-exec; rerun detection from an unsandboxed host shell".to_string(),
        });
    }

    Ok(SandvaultRuntimeCapability::Blocked {
        binary: Some(binary),
        reason: format!("`sv --no-build shell -- /usr/bin/true` failed: {summary}"),
    })
}

fn which_on_path_from_env(binary: &str, path_env: Option<OsString>) -> io::Result<Option<PathBuf>> {
    let Some(path_env) = path_env else {
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

fn command_output_summary(output: &std::process::Output) -> String {
    let mut text = String::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    text.push_str(stdout.trim());
    if !stderr.trim().is_empty() {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(stderr.trim());
    }
    if text.is_empty() {
        format!("exit status {}", output.status)
    } else {
        text.replace('\n', " ")
    }
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

fn path_is_shadow_bin_dir(path: &Path) -> bool {
    let mut parts = path.components().rev();
    matches!(parts.next(), Some(std::path::Component::Normal(bin)) if bin == "bin")
        && matches!(parts.next(), Some(std::path::Component::Normal(shadow)) if shadow == "shadow")
}

fn resolve_host_brokered_tool_binary(binary: &str) -> io::Result<Option<PathBuf>> {
    let Some(path_env) = std::env::var_os("PATH") else {
        return Ok(None);
    };
    for dir in std::env::split_paths(&path_env) {
        if path_is_shadow_bin_dir(&dir) {
            continue;
        }
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
    if matches!(profile.as_str(), "dev" | "autopilot" | "demo") {
        Ok(profile)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown profile: {profile}. Supported: dev | autopilot | demo"),
        ))
    }
}

fn resolve_compose_template_path(current_dir: &Path) -> PathBuf {
    if let Ok(path) = std::env::var("EMBER_COMPOSE_TEMPLATE") {
        return PathBuf::from(path);
    }
    current_dir.join("crates/emberlink-cli/templates/compose.yml.j2")
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
/// `ARCH-IMG-EMBER-UP-AUTO-UPDATE`).
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
            format!("refusing to start: revocations document failed trust check: {e}"),
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
        "note: bridge cert provisioning + `bridge-cli ping` healthcheck land once META-AP-DAEMON-PER-METHOD-AUTHORITY-D wires the daemon presence RPC. The compose stack is up; the trust handshake is not yet enforced from this verb."
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
    pub worker_codex_authority_path: Option<PathBuf>,
    pub worker_overlay_mounts: Vec<ComposeBindMount>,
    pub worker_extra_mounts: Vec<ComposeBindMount>,
    pub worker_worktree_path: Option<PathBuf>,
    pub worker_extra_hosts: Vec<String>,
    pub worker_bridge_url: Option<String>,
    pub worker_bridge_cert_dir: Option<PathBuf>,
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
            worker_codex_authority_path: None,
            worker_overlay_mounts: Vec::new(),
            worker_extra_mounts: Vec::new(),
            worker_worktree_path: None,
            worker_extra_hosts: Vec::new(),
            worker_bridge_url: None,
            worker_bridge_cert_dir: None,
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
    pub daemon_socket_path: PathBuf,
    pub extra_args: Vec<String>,
    pub backend_hint: Option<String>,
    pub preset: Option<String>,
    pub workspace_root: PathBuf,
    pub shadow_root: PathBuf,
    pub codex_runtime_source: Option<PathBuf>,
    pub codex_config_source: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ComposeBindMount {
    pub source: PathBuf,
    pub target: String,
    pub read_only: bool,
}

impl ComposeBindMount {
    fn rw(source: PathBuf, target: impl Into<String>) -> Self {
        Self {
            source,
            target: target.into(),
            read_only: false,
        }
    }

    // Symmetric read-only constructor mirrors `rw`; kept for completeness.
    #[allow(dead_code)]
    fn ro(source: PathBuf, target: impl Into<String>) -> Self {
        Self {
            source,
            target: target.into(),
            read_only: true,
        }
    }
}

#[derive(Debug, Clone)]
struct PreparedIsolatedCodexHome {
    authority_root: PathBuf,
    #[cfg(test)]
    overlay_root: PathBuf,
    overlay_mounts: Vec<ComposeBindMount>,
}

#[derive(Debug, Clone)]
struct PreparedIsolatedBridgeClient {
    url: String,
    cert_dir: PathBuf,
}

pub fn launch_harness_isolated(request: IsolatedHarnessLaunch) -> io::Result<i32> {
    let home = resolve_home_dir()
        .ok_or_else(|| io::Error::other("could not resolve $HOME for isolated launch"))?;
    let run_root = isolated_session_run_root(&home);
    std::fs::create_dir_all(&run_root)?;
    let isolated_home = run_root.join(format!(
        "{}-home-{}",
        request.harness.as_str(),
        &request.registration.session_id
    ));
    prepare_isolated_worker_home(&isolated_home)?;
    let projected_shadow_root =
        prepare_isolated_shadow_mount(&run_root, &request.registration.session_id)?;
    let isolated_codex = if request.harness == HarnessKind::Codex {
        request.codex_config_source.as_deref().map(|source| {
            prepare_isolated_codex_home(&run_root, &request.registration.session_id, source)
        })
    } else {
        None
    }
    .transpose()?;
    let worker_extra_mounts = isolated_socket_mounts(request.registration.ssh_auth_sock.as_deref());
    let worker_bridge = prepare_isolated_bridge_client_bundle(
        &run_root,
        request.backend_hint.as_deref(),
        &request.registration,
    )?;

    let overrides = ComposeRenderContextOverrides {
        shadow_bin_source: Some(shadow_bin_dir(&projected_shadow_root)),
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
        worker_codex_config_path: None,
        worker_codex_authority_path: isolated_codex
            .as_ref()
            .map(|prepared| prepared.authority_root.clone()),
        worker_overlay_mounts: isolated_codex
            .as_ref()
            .map(|prepared| prepared.overlay_mounts.clone())
            .unwrap_or_default(),
        worker_extra_mounts,
        worker_worktree_path: Some(request.workspace_root.clone()),
        worker_extra_hosts: Vec::new(),
        worker_bridge_url: Some(worker_bridge.url),
        worker_bridge_cert_dir: Some(worker_bridge.cert_dir),
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
        HarnessKind::Claude => claude_container_binary_path()?,
        HarnessKind::Codex => codex_container_binary_path(&request)?,
        HarnessKind::Cursor | HarnessKind::Gemini | HarnessKind::Other => {
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

    let env = isolated_child_env(
        prepared.engine,
        &request.persona,
        &request.registration,
        &request.workspace_root,
    );
    if request.harness == HarnessKind::Codex && isolated_codex.is_some() {
        eprintln!(
            "ember codex: isolated mode keeps host auth live at the real ~/.codex root while masking write-heavy state and repo-local Codex surfaces with per-session overlays"
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

fn isolated_container_construct_specs() -> Vec<ConstructSpec> {
    vec![
        ConstructSpec {
            tool_name: "gh".to_string(),
            target_binary: PathBuf::from(format!("{CONTAINER_EMBER_BINARIES_ROOT}/ember-gh")),
        },
        ConstructSpec {
            tool_name: "git".to_string(),
            target_binary: PathBuf::from(format!("{CONTAINER_EMBER_BINARIES_ROOT}/ember-git")),
        },
    ]
}

fn prepare_isolated_shadow_mount(run_root: &Path, session_id: &str) -> io::Result<PathBuf> {
    let shadow_root = run_root.join(format!("shadow-{session_id}"));
    std::fs::create_dir_all(&shadow_root)?;
    install_path_shadow(&shadow_root, &isolated_container_construct_specs())?;
    Ok(shadow_root)
}

fn prepare_isolated_worker_home(worker_home: &Path) -> io::Result<()> {
    std::fs::create_dir_all(worker_home)?;
    let shell_env = format!(
        "# Generated by ember isolated launcher.\n\
         # Keep brokered Construct shims first even when a harness spawns a shell.\n\
         case \":$PATH:\" in\n\
         *:{CONTAINER_SHADOW_BIN_DIR}:*) ;;\n\
         *) export PATH=\"{CONTAINER_SHADOW_BIN_DIR}:$PATH\" ;;\n\
         esac\n"
    );
    std::fs::write(worker_home.join(".ember-shell-env"), shell_env.as_bytes())?;
    let profile = format!(
        "# Generated by ember isolated launcher.\n\
         # Source the same brokered shell env used by non-interactive bash.\n\
         if [ -r \"{CONTAINER_SHELL_ENV_FILE}\" ]; then . \"{CONTAINER_SHELL_ENV_FILE}\"; fi\n"
    );
    for file_name in [".profile", ".bash_profile"] {
        std::fs::write(worker_home.join(file_name), profile.as_bytes())?;
    }
    Ok(())
}

/// Bind mounts for the isolated worker container.
///
/// **No host socket is ever bind-mounted into the worker.** Two host sockets
/// were historically candidates; both are now refused here:
///
/// - **The daemon UDS** (ADR 207 seam 8 / §correction-2, "No UDS-in-container,
///   ever"): a bind-mounted `AF_UNIX` socket is remapped to `root:root` by the
///   runtime userns, so the agent uid cannot `connect(2)` to it and peer-cred
///   identity is meaningless across the namespace. The container reaches emberd
///   exclusively over the ADR 154 mTLS bridge (client cert/key/CA mounted
///   separately at `/run/ember` by `prepare_isolated_bridge_client_bundle`).
/// - **The host ssh-agent socket** (ssh-agent-over-bridge S2): bind-mounting the
///   caller's `$SSH_AUTH_SOCK` gave the in-container agent direct, unbridged,
///   unleased, unaudited use of every key the host agent holds ("read-only" is
///   meaningless on a socket — it gates writes to the inode, not agent
///   operations). That mount is **retired**, so in-container SSH fails closed
///   (no agent socket, no host key files) until the brokered path lands. The
///   target path is the lease-gated, per-session-key-isolated S1 signer
///   (`ember-broker::ssh_agent_bridge`), reached via a container-LOCAL
///   `$SSH_AUTH_SOCK` UDS served by the bridge client; that forwarder + its lease
///   land with the S3 `register_session` provisioning.
///
/// `ssh_auth_sock` (a legacy host path the daemon could place on the session
/// registration) is accepted but deliberately **not** mounted — keeping the
/// parameter makes the regression guard explicit: even when a host ssh-agent
/// socket path is threaded in, this function mounts nothing.
fn isolated_socket_mounts(_ssh_auth_sock: Option<&str>) -> Vec<ComposeBindMount> {
    Vec::new()
}

fn cleanup_isolated_stack_best_effort(engine: RuntimeEngine, compose_path: &Path, profile: &str) {
    if let Err(err) = compose_down_with_timeout(
        engine,
        compose_path,
        true,
        ISOLATED_HARNESS_COMPOSE_DOWN_TIMEOUT_SECS,
    ) {
        eprintln!(
            "warning: failed to tear down isolated launcher stack for profile `{profile}` at {}: {err}",
            compose_path.display()
        );
    }
}

const ISOLATED_HARNESS_COMPOSE_DOWN_TIMEOUT_SECS: u64 = 1;
const DEFAULT_COMPOSE_DOWN_TIMEOUT_SECS: u64 = 10;

const ISOLATED_CODEX_SEED_FILES: &[&str] = &[
    "config.toml",
    "hooks.json",
    "AGENTS.md",
    "installation_id",
    "version.json",
    ".personality_migration",
];
const ISOLATED_CODEX_SEED_DIRS: &[&str] = &["skills", "rules", "memories"];
const ISOLATED_CODEX_MUTABLE_FILES: &[&str] = &[
    "history.jsonl",
    "session_index.jsonl",
    ".codex-global-state.json",
    ".codex-global-state.json.bak",
    "models_cache.json",
];
const ISOLATED_CODEX_MUTABLE_DIRS: &[&str] = &[
    "archived_sessions",
    "cache",
    "log",
    "sessions",
    "shell_snapshots",
    "tmp",
    ".tmp",
    "sqlite",
    "node_repl",
    "worktrees",
];
const ISOLATED_CODEX_DEFAULT_SQLITE_BASES: &[&str] = &[
    "state_5.sqlite",
    "goals_1.sqlite",
    "logs_1.sqlite",
    "logs_2.sqlite",
];

fn prepare_isolated_codex_home(
    run_root: &Path,
    session_id: &str,
    host_config_root: &Path,
) -> io::Result<PreparedIsolatedCodexHome> {
    let overlay_root = run_root.join(format!("codex-overlay-{session_id}"));
    if overlay_root.exists() {
        std::fs::remove_dir_all(&overlay_root)?;
    }
    std::fs::create_dir_all(&overlay_root)?;
    let mut overlay_mounts = Vec::new();

    for relative in ISOLATED_CODEX_SEED_FILES {
        let source = host_config_root.join(relative);
        if source.is_file() {
            let dest = overlay_root.join(relative);
            copy_seed_entry(&source, &dest)?;
            overlay_mounts.push(codex_overlay_mount(dest, relative));
        }
    }
    for relative in ISOLATED_CODEX_SEED_DIRS {
        let dest = overlay_root.join(relative);
        std::fs::create_dir_all(&dest)?;
        let source = host_config_root.join(relative);
        if source.exists() {
            copy_seed_entry(&source, &dest)?;
        }
        overlay_mounts.push(codex_overlay_mount(dest, relative));
    }

    for relative in ISOLATED_CODEX_MUTABLE_FILES {
        let dest = overlay_root.join(relative);
        seed_or_initialize_mutable_codex_file(host_config_root, relative, &dest)?;
        overlay_mounts.push(codex_overlay_mount(dest, relative));
    }
    for relative in ISOLATED_CODEX_MUTABLE_DIRS {
        let dest = overlay_root.join(relative);
        std::fs::create_dir_all(&dest)?;
        overlay_mounts.push(codex_overlay_mount(dest, relative));
    }
    for relative in discover_isolated_codex_sqlite_surfaces(host_config_root)? {
        let dest = overlay_root.join(&relative);
        ensure_empty_file(&dest)?;
        overlay_mounts.push(codex_overlay_mount(dest, &relative));
    }

    Ok(PreparedIsolatedCodexHome {
        authority_root: host_config_root.to_path_buf(),
        #[cfg(test)]
        overlay_root,
        overlay_mounts,
    })
}

fn codex_overlay_mount(source: PathBuf, relative: impl AsRef<str>) -> ComposeBindMount {
    ComposeBindMount::rw(
        source,
        format!("{CONTAINER_HOME}/.codex/{}", relative.as_ref()),
    )
}

fn ensure_empty_file(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, [])?;
    Ok(())
}

fn seed_or_initialize_mutable_codex_file(
    host_config_root: &Path,
    relative: &str,
    dest: &Path,
) -> io::Result<()> {
    let source = host_config_root.join(relative);
    if source.is_file() && relative == "models_cache.json" {
        return copy_seed_entry(&source, dest);
    }
    ensure_empty_file(dest)
}

fn discover_isolated_codex_sqlite_surfaces(host_config_root: &Path) -> io::Result<Vec<String>> {
    let mut bases = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(host_config_root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(base) = name.strip_suffix("-wal") {
            if base.ends_with(".sqlite") {
                bases.insert(base.to_string());
            }
            continue;
        }
        if let Some(base) = name.strip_suffix("-shm") {
            if base.ends_with(".sqlite") {
                bases.insert(base.to_string());
            }
            continue;
        }
        if name.ends_with(".sqlite") {
            bases.insert(name.to_string());
        }
    }
    if bases.is_empty() {
        bases.extend(
            ISOLATED_CODEX_DEFAULT_SQLITE_BASES
                .iter()
                .map(|base| (*base).to_string()),
        );
    }

    let mut files = Vec::new();
    for base in bases {
        files.push(base.clone());
        files.push(format!("{base}-wal"));
        files.push(format!("{base}-shm"));
    }
    Ok(files)
}

fn copy_seed_entry(source: &Path, dest: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(source)?;
    if metadata.is_dir() {
        std::fs::create_dir_all(dest)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            copy_seed_entry(&entry.path(), &dest.join(entry.file_name()))?;
        }
        return Ok(());
    }

    if metadata.file_type().is_symlink() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let _ = std::fs::remove_file(dest);
            symlink(std::fs::read_link(source)?, dest)?;
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            let resolved = std::fs::canonicalize(source)?;
            return copy_seed_entry(&resolved, dest);
        }
    }

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(source, dest)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode() & 0o777;
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
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

fn claude_container_binary_path() -> io::Result<String> {
    Ok(isolated_container_binary_override("EMBER_CLAUDE_BIN")?
        .unwrap_or_else(|| "claude".to_string()))
}

fn codex_container_binary_path(request: &IsolatedHarnessLaunch) -> io::Result<String> {
    if let Some(override_path) = isolated_container_binary_override("EMBER_CODEX_BIN")? {
        return Ok(override_path);
    }
    if request.codex_runtime_source.is_none() {
        return Err(io::Error::other(
            "isolated `ember codex` requires a container-ready Codex runtime root; resolve the host Codex install first or use the host launcher path",
        ));
    }
    Ok(format!("{CONTAINER_CODEX_RUNTIME_ROOT}/bin/codex"))
}

pub(crate) fn isolated_container_binary_override(env_name: &str) -> io::Result<Option<String>> {
    let Some(value) = std::env::var_os(env_name) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(value);
    let path_display = path.display().to_string();
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{env_name} for isolated launches must be an absolute container-visible path, got `{path_display}`"
            ),
        ));
    }
    if !isolated_binary_override_is_container_visible(&path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{env_name} for isolated launches must point inside the worker container, got `{path_display}`; use a path such as `/bin/sh` or `{CONTAINER_WORKDIR}/...`"
            ),
        ));
    }
    Ok(Some(path_display))
}

fn isolated_binary_override_is_container_visible(path: &Path) -> bool {
    [
        Path::new("/bin"),
        Path::new("/sbin"),
        Path::new("/usr/bin"),
        Path::new("/usr/sbin"),
        Path::new("/usr/local/bin"),
        Path::new(CONTAINER_WORKDIR),
        Path::new(CONTAINER_HOME),
        Path::new(CONTAINER_EMBER_BINARIES_ROOT),
        Path::new(CONTAINER_CODEX_RUNTIME_ROOT),
    ]
    .iter()
    .any(|root| path.starts_with(root))
}

fn managed_worktree_runtime_id_from_meta(host_workspace_root: &Path) -> Option<String> {
    let body = std::fs::read_to_string(host_workspace_root.join(".agent-session")).ok()?;
    let runtime_id = body
        .lines()
        .find_map(|line| line.strip_prefix("runtime_id: "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)?;
    let declared_worktree = body
        .lines()
        .find_map(|line| line.strip_prefix("worktree_path: "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)?;
    (declared_worktree == host_workspace_root).then_some(runtime_id)
}

fn isolated_child_env(
    engine: RuntimeEngine,
    persona: &str,
    registration: &SessionRegistration,
    host_workspace_root: &Path,
) -> Vec<(String, String)> {
    let persona_id = registration.persona_id.as_deref().unwrap_or(persona);
    let mut env = vec![
        ("EMBER_PERSONA".to_string(), persona.to_string()),
        ("EMBER_PERSONA_ID".to_string(), persona_id.to_string()),
        (
            "EMBER_PROXY_URL".to_string(),
            rewrite_loopback_url_for_container(&registration.proxy_url, engine),
        ),
        (
            "EMBER_SESSION_ID".to_string(),
            registration.session_id.clone(),
        ),
        ("BASH_ENV".to_string(), CONTAINER_SHELL_ENV_FILE.to_string()),
        ("HOME".to_string(), CONTAINER_HOME.to_string()),
        ("PATH".to_string(), CONTAINER_DEFAULT_PATH.to_string()),
    ];
    if let Some(runtime_id) = managed_worktree_runtime_id_from_meta(host_workspace_root) {
        env.push((
            crate::dev_runtime::DEV_RUNTIME_ID_ENV.to_string(),
            runtime_id,
        ));
    }
    tracing::warn!(
        workspace_root = %host_workspace_root.display(),
        "EMBER_BROKER_CWD is deprecated for isolated construct shims; use EMBER_DEV_RUNTIME_ID-derived managed_worktree workspace_ref"
    );
    env.push((
        "EMBER_BROKER_CWD".to_string(),
        host_workspace_root.to_string_lossy().to_string(),
    ));
    if let Some(attachment_id) = registration.attachment_id.as_deref() {
        env.push(("EMBER_ATTACHMENT_ID".to_string(), attachment_id.to_string()));
    }
    if let Some(endpoint_token) = registration.attachment_endpoint_token.as_deref() {
        env.push((
            "EMBER_ATTACHMENT_ENDPOINT_TOKEN".to_string(),
            endpoint_token.to_string(),
        ));
    }
    // ADR 207 seam 8 / §correction-2: the container's emberd control path is
    // the ADR 154 mTLS bridge ONLY — it is never handed a daemon UDS path (the
    // bind-mounted socket is unusable across the userns; see
    // `isolated_socket_mounts`). The bridge bundle is required upstream by
    // `prepare_isolated_bridge_client_bundle`, which fails the launch if it is
    // absent, so there is no UDS fallback to emit here.
    if let Some(bundle) = registration.bridge_client_bundle.as_ref() {
        env.push((
            "EMBER_BRIDGE_URL".to_string(),
            format!(
                "https://{}:{}",
                container_loopback_host(engine),
                bundle.port
            ),
        ));
        env.push((
            "EMBER_CLIENT_CERT".to_string(),
            CONTAINER_BRIDGE_CERT.to_string(),
        ));
        env.push((
            "EMBER_CLIENT_KEY".to_string(),
            CONTAINER_BRIDGE_KEY.to_string(),
        ));
        env.push(("EMBER_CA_CERT".to_string(), CONTAINER_BRIDGE_CA.to_string()));
    }
    if let Some(base_url) = registration.anthropic_base_url.as_deref() {
        env.push((
            "ANTHROPIC_BASE_URL".to_string(),
            rewrite_loopback_url_for_container(base_url, engine),
        ));
    }
    if let Some(headers) = registration.anthropic_custom_headers.as_deref() {
        env.push(("ANTHROPIC_CUSTOM_HEADERS".to_string(), headers.to_string()));
    }
    if registration.anthropic_base_url.is_some() || registration.anthropic_custom_headers.is_some()
    {
        // A pristine isolated HOME lacks the host Keychain / Claude login
        // substrate, and Claude can refuse to start before it ever sends a
        // request. Seed a harmless bearer placeholder so Claude clears local
        // auth preflight, while the daemon proxy still strips client auth and
        // injects the real vault-backed credential upstream.
        env.push((
            "ANTHROPIC_AUTH_TOKEN".to_string(),
            ISOLATED_CLAUDE_PROXY_AUTH_PLACEHOLDER.to_string(),
        ));
    }
    if let Some(git_proxy_url) = registration.git_proxy_url.as_deref() {
        env.push((
            "EMBER_GIT_PROXY_URL".to_string(),
            rewrite_loopback_url_for_container(git_proxy_url, engine),
        ));
    }
    // ssh-agent-over-bridge S2: the container env never points `SSH_AUTH_SOCK`
    // at a bind-mounted host agent (that mount is retired; see
    // `isolated_socket_mounts`). Until the S3 brokered container-local forwarder
    // is provisioned, in-container SSH key auth has no agent and fails closed
    // rather than reaching the host agent's keys. The S3 forwarder will set
    // `SSH_AUTH_SOCK` to a container-LOCAL UDS served by the bridge client.
    for (binary, env_var) in [
        ("gh", "EMBER_GH_BINARY"),
        ("git", "EMBER_GIT_BINARY"),
        ("kubectl", "EMBER_KUBECTL_BINARY"),
        ("docker", "EMBER_DOCKER_BINARY"),
        ("aws", "EMBER_AWS_BINARY"),
        ("az", "EMBER_AZ_BINARY"),
        ("gcloud", "EMBER_GCLOUD_BINARY"),
        ("vercel", "EMBER_VERCEL_BINARY"),
        ("wrangler", "EMBER_WRANGLER_BINARY"),
        ("pulumi", "EMBER_PULUMI_BINARY"),
        ("terraform", "EMBER_TERRAFORM_BINARY"),
        ("tofu", "EMBER_TOFU_BINARY"),
        ("flyctl", "EMBER_FLYCTL_BINARY"),
        ("npm", "EMBER_NPM_BINARY"),
        ("okta", "EMBER_OKTA_BINARY"),
        ("scion", "EMBER_SCION_BINARY"),
    ] {
        if let Ok(Some(path)) = resolve_host_brokered_tool_binary(binary) {
            env.push((env_var.to_string(), path.to_string_lossy().to_string()));
        }
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

fn prepare_isolated_bridge_client_bundle(
    run_root: &Path,
    backend_hint: Option<&str>,
    registration: &SessionRegistration,
) -> io::Result<PreparedIsolatedBridgeClient> {
    let engine = match backend_hint {
        Some(hint) => RuntimeEngine::from_backend_hint(hint)?,
        None => detect_runtime_engine()?
            .ok_or_else(|| io::Error::other("no supported container runtime detected"))?,
    };
    let session_id = &registration.session_id;
    let bundle = registration.bridge_client_bundle.as_ref().ok_or_else(|| {
        io::Error::other(
            "isolated bridge client bundle missing from register_session response; update the daemon and rerun the isolated launch",
        )
    })?;

    let cert_dir = run_root.join(format!("bridge-certs-{session_id}"));
    if cert_dir.exists() {
        std::fs::remove_dir_all(&cert_dir)?;
    }
    std::fs::create_dir_all(&cert_dir)?;
    write_bridge_bundle_file(
        &cert_dir.join("client.crt"),
        bundle.client_cert_pem.as_bytes(),
        0o644,
    )?;
    write_bridge_bundle_file(
        &cert_dir.join("client.key"),
        bundle.client_key_pem.as_bytes(),
        0o600,
    )?;
    write_bridge_bundle_file(
        &cert_dir.join("ca.crt"),
        bundle.ca_cert_pem.as_bytes(),
        0o644,
    )?;

    let bridge_addr = std::env::var("EMBER_BRIDGE_ADDR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("{}:{}", container_loopback_host(engine), bundle.port));
    let url = if bridge_addr.contains("://") {
        bridge_addr
    } else {
        format!("https://{bridge_addr}")
    };

    Ok(PreparedIsolatedBridgeClient { url, cert_dir })
}

fn write_bridge_bundle_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
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
        worker_codex_authority_path,
        worker_overlay_mounts,
        worker_extra_mounts,
        worker_worktree_path,
        worker_extra_hosts,
        worker_bridge_url,
        worker_bridge_cert_dir,
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

    let home = resolve_home_dir().ok_or_else(|| {
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
    context.worker_codex_authority_path = worker_codex_authority_path;
    context.worker_overlay_mounts = worker_overlay_mounts;
    context.worker_extra_mounts = worker_extra_mounts;
    context.worker_worktree_path = worker_worktree_path;
    context.worker_extra_hosts = worker_extra_hosts;
    context.worker_bridge_url = worker_bridge_url;
    context.worker_bridge_cert_dir = worker_bridge_cert_dir;
    context.bridge_enabled = bridge_enabled;
    context.orchestrator_enabled = orchestrator_enabled;
    context.worker_procfs_hardening_enabled = engine.supports_procfs_hardening();
    if context.bridge_enabled {
        if context.worker_bridge_url.is_none() {
            context.worker_bridge_url = Some("https://bridge:4243".to_string());
        }
        if context.worker_bridge_cert_dir.is_none() {
            context.worker_bridge_cert_dir = Some(run_dir.join("certs"));
        }
    }
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
/// canonical location `crates/emberlink-cli/templates/compose.yml.j2`)
/// with the supplied per-run context variables. Returns the rendered
/// YAML as a UTF-8 string.
///
/// ARCH-CLI-EMBER-UP-VERB-B: uses minijinja's strict-undefined mode so
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
/// `crates/emberlink-cli/templates/compose.yml.j2`; defaults inside the
/// template handle most optional fields, so the context only needs the
/// load-bearing identity values.
#[derive(Debug, Clone)]
pub struct ComposeRenderContext {
    /// Host-side directory holding bridge cert PEMs (CA, server cert,
    /// server key). Bind-mounted RO into the bridge container at
    /// `/run/ember`.
    pub bridge_cert_dir: PathBuf,
    /// Compose profile name (`dev` / `autopilot` / `demo`) — selects
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
    /// Per-session Codex home subtree seeded from safe host config surfaces.
    pub worker_codex_config_path: Option<PathBuf>,
    /// Shared host Codex root mounted at the real in-container `~/.codex`
    /// path so auth refreshes keep using Codex's native root layout.
    pub worker_codex_authority_path: Option<PathBuf>,
    /// Fine-grained overlay binds layered on top of the shared Codex root.
    pub worker_overlay_mounts: Vec<ComposeBindMount>,
    /// Additional bind mounts for isolated runtime sockets and other
    /// non-Codex mutable surfaces.
    pub worker_extra_mounts: Vec<ComposeBindMount>,
    /// In-container destination for `worker_home_path`.
    pub worker_home_target: String,
    /// In-container destination for `worker_codex_config_path`.
    pub worker_codex_config_target: String,
    /// In-container destination for the shared Codex root mount.
    pub worker_codex_authority_target: String,
    /// Whether Linux-only `/proc` remount + mask hardening should be rendered.
    pub worker_procfs_hardening_enabled: bool,
    /// Host operator UID for idmapped mount + userns_mode. Defaults to
    /// the running process's effective UID.
    pub host_uid: u32,
    /// Host operator GID for idmapped mount. Defaults to the running
    /// process's effective GID. Distinct from `host_uid`: on macOS the
    /// typical user has uid=501 / gid=20 (staff), so defaulting GID to
    /// UID silently miswrites container ownership.
    /// Per META-AP-COMPOSE-HOST-GID-VARIABLE-FIX.
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
    /// Explicit worker bridge endpoint. Full stacks default to the in-stack
    /// bridge; standalone isolated launches point at the host bridge.
    pub worker_bridge_url: Option<String>,
    /// Host-side client-cert bundle mounted into the worker at `/run/ember`.
    pub worker_bridge_cert_dir: Option<PathBuf>,
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
            worker_codex_authority_path: None,
            worker_overlay_mounts: Vec::new(),
            worker_extra_mounts: Vec::new(),
            worker_home_target: CONTAINER_HOME.to_string(),
            worker_codex_config_target: format!("{CONTAINER_HOME}/.codex"),
            worker_codex_authority_target: format!("{CONTAINER_HOME}/.codex"),
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
            shadow_bin_source: resolve_home_dir()
                .map(|home| home.join(".ember").join("shadow").join("bin")),
            claude_bin_source: None,
            codex_runtime_source: None,
            worker_persona_id: None,
            worker_command: None,
            worker_seccomp_profile_path: None,
            worker_extra_hosts: Vec::new(),
            worker_bridge_url: None,
            worker_bridge_cert_dir: None,
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
        if let Some(p) = &self.worker_codex_authority_path {
            map.insert(
                "worker_codex_authority_path",
                Value::from(p.to_string_lossy().to_string()),
            );
        }
        if !self.worker_overlay_mounts.is_empty() {
            map.insert(
                "worker_overlay_mounts",
                Value::from_serialize(&self.worker_overlay_mounts),
            );
        }
        if !self.worker_extra_mounts.is_empty() {
            map.insert(
                "worker_extra_mounts",
                Value::from_serialize(&self.worker_extra_mounts),
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
            "worker_codex_authority_target",
            Value::from(self.worker_codex_authority_target.clone()),
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
        if let Some(url) = &self.worker_bridge_url {
            map.insert("worker_bridge_url", Value::from(url.clone()));
        }
        if let Some(p) = &self.worker_bridge_cert_dir {
            map.insert(
                "worker_bridge_cert_dir",
                Value::from(p.to_string_lossy().to_string()),
            );
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
    reap_stale_isolated_compose_networks_best_effort(engine);

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

fn reap_stale_isolated_compose_networks_best_effort(engine: RuntimeEngine) {
    if !matches!(engine, RuntimeEngine::Docker | RuntimeEngine::OrbStack) {
        return;
    }

    let output = match Command::new(engine.compose_binary())
        .arg("network")
        .arg("ls")
        .arg("--filter")
        .arg("label=com.docker.compose.project")
        .arg("--format")
        .arg(r#"{{.Name}}	{{.Label "com.docker.compose.project"}}"#)
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            eprintln!(
                "warning: failed to inspect stale isolated compose networks before launch: {err}"
            );
            return;
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!(
            "warning: {} network ls failed while checking stale isolated compose networks: {}",
            engine.display_name(),
            stderr.trim()
        );
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for network in stale_isolated_compose_networks_from_listing(&stdout) {
        let output = match Command::new(engine.compose_binary())
            .arg("network")
            .arg("rm")
            .arg(&network)
            .output()
        {
            Ok(output) => output,
            Err(err) => {
                eprintln!(
                    "warning: failed to remove stale isolated compose network {network}: {err}"
                );
                continue;
            }
        };
        if output.status.success() {
            continue;
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("has active endpoints") || stderr.contains("active endpoints") {
            continue;
        }
        eprintln!(
            "warning: {} network rm {network} failed while checking stale isolated compose networks: {}",
            engine.display_name(),
            stderr.trim()
        );
    }
}

fn stale_isolated_compose_networks_from_listing(listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter_map(|line| {
            let (name, project) = line.split_once('\t')?;
            if is_ember_isolated_compose_network(name.trim(), project.trim()) {
                Some(name.trim().to_string())
            } else {
                None
            }
        })
        .collect()
}

fn is_ember_isolated_compose_network(name: &str, project: &str) -> bool {
    is_ember_isolated_compose_project(project) && name == format!("{project}_default")
}

fn is_ember_isolated_compose_project(project: &str) -> bool {
    let Some(hex) = project.strip_prefix(ISOLATED_COMPOSE_PROJECT_PREFIX) else {
        return false;
    };
    hex.len() == ISOLATED_COMPOSE_PROJECT_HEX_LEN && hex.chars().all(|c| c.is_ascii_hexdigit())
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
    compose_down_with_timeout(
        engine,
        compose_path,
        purge,
        DEFAULT_COMPOSE_DOWN_TIMEOUT_SECS,
    )
}

pub fn compose_down_with_timeout(
    engine: RuntimeEngine,
    compose_path: &Path,
    purge: bool,
    timeout_secs: u64,
) -> io::Result<(String, String)> {
    let mut cmd = Command::new(engine.compose_binary());
    cmd.arg("compose").arg("-f").arg(compose_path).arg("down");
    if purge {
        cmd.arg("-v");
    }
    // Long-lived `ember down` keeps the 10s graceful SIGTERM window per
    // autogrill compose-topology D8. Ephemeral harness launchers pass a shorter
    // timeout because their worker process is only a keepalive shell.
    cmd.arg("--timeout").arg(timeout_secs.to_string());
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

// compose exec plumbing signature — structurally many params (engine/path/profile/service/env/argv).
#[allow(clippy::too_many_arguments)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launcher::core::AuthorityPosture;
    use std::sync::Mutex;

    fn env_lock() -> &'static Mutex<()> {
        &crate::PROCESS_ENV_CWD_TEST_LOCK
    }

    fn capture_cwd() -> PathBuf {
        std::env::current_dir().unwrap_or_else(|_| {
            let fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            std::env::set_current_dir(&fallback).expect("restore test cwd fallback");
            fallback
        })
    }

    struct EnvGuard {
        home: Option<std::ffi::OsString>,
        path: Option<std::ffi::OsString>,
        template: Option<std::ffi::OsString>,
        vault_passphrase: Option<std::ffi::OsString>,
        claude_bin: Option<std::ffi::OsString>,
        codex_bin: Option<std::ffi::OsString>,
        cwd: PathBuf,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                home: std::env::var_os("HOME"),
                path: std::env::var_os("PATH"),
                template: std::env::var_os("EMBER_COMPOSE_TEMPLATE"),
                vault_passphrase: std::env::var_os("EMBER_VAULT_PASSPHRASE"),
                claude_bin: std::env::var_os("EMBER_CLAUDE_BIN"),
                codex_bin: std::env::var_os("EMBER_CODEX_BIN"),
                cwd: capture_cwd(),
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
                match &self.vault_passphrase {
                    Some(value) => std::env::set_var("EMBER_VAULT_PASSPHRASE", value),
                    None => std::env::remove_var("EMBER_VAULT_PASSPHRASE"),
                }
                match &self.claude_bin {
                    Some(value) => std::env::set_var("EMBER_CLAUDE_BIN", value),
                    None => std::env::remove_var("EMBER_CLAUDE_BIN"),
                }
                match &self.codex_bin {
                    Some(value) => std::env::set_var("EMBER_CODEX_BIN", value),
                    None => std::env::remove_var("EMBER_CODEX_BIN"),
                }
            }
        }
    }

    fn write_default_home_config(home_dir: &Path, bridge_bind: Option<&str>) {
        let ember_dir = home_dir.join(".ember");
        let config_path = ember_dir.join("config.toml");
        let data_dir = ember_dir.join("data");
        let socket_dir = ember_dir.join("run");
        let pid_file = socket_dir.join("emberd.pid");
        let policy_file = ember_dir.join("policy.toml");

        std::fs::create_dir_all(&ember_dir).expect("create ~/.ember");
        let mut cfg = format!(
            "[daemon]\ndata_dir = \"{}\"\nsocket_dir = \"{}\"\npid_file = \"{}\"\npolicy_file = \"{}\"\nlog_level = \"info\"\n[keyring]\nservice = \"ember-daemon-test\"\naccount = \"vault\"\n",
            data_dir.display(),
            socket_dir.display(),
            pid_file.display(),
            policy_file.display(),
        );
        if let Some(bridge_bind) = bridge_bind {
            cfg.push_str(&format!("bridge_bind = \"{bridge_bind}\"\n"));
        }
        std::fs::write(&config_path, cfg.as_bytes()).expect("write ~/.ember/config.toml");
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
    #[test]
    fn sandvault_capability_reports_available_when_no_build_smoke_passes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sv = tmp.path().join("sv");
        write_executable(
            &sv,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "sv version 1.20.0"
  exit 0
fi
if [ "$1" = "--no-build" ] && [ "$2" = "shell" ]; then
  exit 0
fi
exit 2
"#,
        );

        let capability =
            detect_sandvault_runtime_capability_from_binary(Some(sv.clone())).expect("detect");
        assert_eq!(
            capability,
            SandvaultRuntimeCapability::Available {
                binary: sv,
                version: "sv version 1.20.0".to_string(),
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandvault_capability_reports_unavailable_when_cli_is_not_installed() {
        let capability =
            detect_sandvault_runtime_capability_from_binary(None).expect("detect missing");
        assert!(matches!(
            capability,
            SandvaultRuntimeCapability::Unavailable { reason }
                if reason.contains("not on PATH")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn sandvault_capability_reports_unavailable_when_host_is_not_provisioned() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sv = tmp.path().join("sv");
        write_executable(
            &sv,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "sv version 1.20.0"
  exit 0
fi
echo "sandvault is not installed (run without --no-build flag)" >&2
exit 1
"#,
        );

        let capability = detect_sandvault_runtime_capability_from_binary(Some(sv)).expect("detect");
        assert!(matches!(
            capability,
            SandvaultRuntimeCapability::Unavailable { reason }
                if reason.contains("host provisioning is not installed")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn sandvault_capability_reports_blocked_when_nested_sandbox_is_denied() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sv = tmp.path().join("sv");
        write_executable(
            &sv,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "sv version 1.20.0"
  exit 0
fi
echo "sandbox-exec: sandbox_apply: Operation not permitted" >&2
exit 1
"#,
        );

        let capability = detect_sandvault_runtime_capability_from_binary(Some(sv)).expect("detect");
        assert!(matches!(
            capability,
            SandvaultRuntimeCapability::Blocked { reason, .. }
                if reason.contains("nested sandbox-exec")
        ));
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
  *\" network ls \"*) exit 0 ;;\n\
  *\" network rm \"*) exit 0 ;;\n\
  *) exit 0 ;;\n\
esac\n",
                log_path.display()
            ),
        );
        log_path
    }

    #[test]
    fn stale_isolated_compose_network_filter_is_ember_only() {
        let listing = "\
dev-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_default\tdev-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
dev-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_other\tdev-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
dev-gggggggggggggggggggggggggggggggg_default\tdev-gggggggggggggggggggggggggggggggg\n\
project_default\tproject\n\
k3d-tz-dev\tk3d-tz-dev\n";

        assert_eq!(
            stale_isolated_compose_networks_from_listing(listing),
            vec!["dev-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_default"]
        );
    }

    #[test]
    fn stale_isolated_compose_project_requires_dev_32hex() {
        assert!(is_ember_isolated_compose_project(
            "dev-0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_ember_isolated_compose_project(
            "dev-0123456789abcdef0123456789abcde"
        ));
        assert!(!is_ember_isolated_compose_project(
            "dev-0123456789abcdef0123456789abcdef0"
        ));
        assert!(!is_ember_isolated_compose_project(
            "prod-0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_ember_isolated_compose_project(
            "dev-0123456789abcdef0123456789abcdeg"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn compose_down_keeps_default_ten_second_timeout() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");
        let log = install_fake_docker(&bin_dir, 0);
        let compose = tmp.path().join("compose.yml");
        std::fs::write(&compose, "services: {}\n").expect("write compose");

        unsafe { std::env::set_var("PATH", &bin_dir) };

        compose_down(RuntimeEngine::Docker, &compose, true).expect("compose down");
        drop(env);

        let logged = std::fs::read_to_string(log).expect("read fake docker log");
        assert!(
            logged.contains("CMD [compose] [-f]"),
            "fake docker should capture compose invocation: {logged}"
        );
        assert!(
            logged.contains("[down] [-v] [--timeout] [10]"),
            "long-lived compose_down must keep the documented 10s grace: {logged}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn compose_down_with_timeout_uses_requested_timeout() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");
        let log = install_fake_docker(&bin_dir, 0);
        let compose = tmp.path().join("compose.yml");
        std::fs::write(&compose, "services: {}\n").expect("write compose");

        unsafe { std::env::set_var("PATH", &bin_dir) };

        compose_down_with_timeout(RuntimeEngine::Docker, &compose, true, 1)
            .expect("compose down with timeout");
        drop(env);

        let logged = std::fs::read_to_string(log).expect("read fake docker log");
        assert!(
            logged.contains("[down] [-v] [--timeout] [1]"),
            "ephemeral isolated harness cleanup must use the requested short timeout: {logged}"
        );
    }

    #[test]
    fn render_compose_template_substitutes_context() {
        // ARCH-CLI-EMBER-UP-VERB-B — minimal smoke against a one-line
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
        // META-AP-COMPOSE-HOST-GID-VARIABLE-FIX: prior to this fix the
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
        // ARCH-CLI-EMBER-UP-VERB-B — UndefinedBehavior::Strict means a
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
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/compose.yml.j2")
    }

    fn fixture_registration() -> SessionRegistration {
        SessionRegistration {
            session_id: "sess_fixture".to_string(),
            grant_id: "grant_fixture".to_string(),
            persona_id: Some("persona_fixture_id".to_string()),
            proxy_url: "http://127.0.0.1:62735".to_string(),
            anthropic_base_url: Some("http://localhost:62735".to_string()),
            anthropic_custom_headers: Some("X-Test: one".to_string()),
            git_proxy_url: Some("https://127.0.0.1:62727".to_string()),
            cursor_egress_proxy_url: None,
            codex_responses_proxy_url: None,
            gemini_proxy_url: None,
            ssh_auth_sock: None,
            delegation_id: None,
            delegation_template: None,
            authority_posture: AuthorityPosture::from_components(false, None),
            bridge_client_bundle: Some(crate::launcher::core::BridgeClientBundle {
                port: 4243,
                client_cert_pem: "mock-client-cert".to_string(),
                client_key_pem: "mock-client-key".to_string(),
                ca_cert_pem: "mock-ca-cert".to_string(),
            }),
            attachment_id: Some("att_fixture".to_string()),
            attachment_endpoint_token: Some("ep_fixture".to_string()),
            anthropic_unix_socket: None,
            leaf_report_nonce: None,
        }
    }

    #[test]
    fn isolated_socket_mounts_never_mounts_any_host_socket() {
        // ssh-agent-over-bridge S2 (ADR 207 §"No UDS-in-container" + §correction-2):
        // the isolated launcher bind-mounts NO host socket into the worker —
        // neither the daemon UDS (an `AF_UNIX` socket is remapped to root:root by
        // the userns, so it is unusable and peer-cred identity is meaningless) NOR
        // the host ssh-agent socket. A bind-mounted host `$SSH_AUTH_SOCK` would
        // hand the in-container agent unbridged, unleased, unaudited use of every
        // key the host agent holds ("read-only" is meaningless on a socket). The
        // host ssh-agent mount was retired here; in-container SSH now routes
        // through the brokered S1 signer (`ember-broker::ssh_agent_bridge`) or
        // fails closed.
        //
        // Regression guard: even when a (legacy daemon-provided) host ssh-agent
        // socket path is threaded in, NOTHING is mounted. This is the exact
        // failure the decomposition threat-model warned about — a future change
        // re-introducing the path must not silently re-mount the host agent.
        let with_ssh = isolated_socket_mounts(Some("/tmp/ember-ssh-agent.sock"));
        assert!(
            with_ssh.is_empty(),
            "no host socket may be mounted into the isolated worker, even when a \
             host ssh-agent socket path is supplied (S2 retired the host mount)"
        );

        let without_ssh = isolated_socket_mounts(None);
        assert!(
            without_ssh.is_empty(),
            "no host socket mounts when no ssh-agent socket path is supplied"
        );
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
        let mut registration = fixture_registration();
        registration.ssh_auth_sock = Some("/tmp/ember-ssh-agent.sock".to_string());
        let env = isolated_child_env(
            RuntimeEngine::Podman,
            "persona-main",
            &registration,
            Path::new("/home/test/repo"),
        );
        let env_map: std::collections::BTreeMap<_, _> = env.into_iter().collect();

        assert_eq!(
            env_map.get("EMBER_PERSONA").map(String::as_str),
            Some("persona-main")
        );
        assert_eq!(
            env_map.get("EMBER_PERSONA_ID").map(String::as_str),
            Some("persona_fixture_id")
        );
        assert_eq!(
            env_map.get("EMBER_BROKER_CWD").map(String::as_str),
            Some("/home/test/repo")
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
            env_map.get("ANTHROPIC_AUTH_TOKEN").map(String::as_str),
            Some(ISOLATED_CLAUDE_PROXY_AUTH_PLACEHOLDER)
        );
        assert_eq!(
            env_map.get("HOME").map(String::as_str),
            Some(CONTAINER_HOME)
        );
        assert_eq!(
            env_map.get("PATH").map(String::as_str),
            Some(CONTAINER_DEFAULT_PATH)
        );
        assert_eq!(
            env_map.get("EMBER_BRIDGE_URL").map(String::as_str),
            Some("https://host.containers.internal:4243")
        );
        assert_eq!(
            env_map.get("EMBER_CLIENT_CERT").map(String::as_str),
            Some(CONTAINER_BRIDGE_CERT)
        );
        assert_eq!(
            env_map.get("EMBER_CLIENT_KEY").map(String::as_str),
            Some(CONTAINER_BRIDGE_KEY)
        );
        assert_eq!(
            env_map.get("EMBER_CA_CERT").map(String::as_str),
            Some(CONTAINER_BRIDGE_CA)
        );
        // ssh-agent-over-bridge S2: the container env never points `SSH_AUTH_SOCK`
        // at a bind-mounted host agent, even when the (legacy) daemon-provided
        // `ssh_auth_sock` is present on the registration. With no host mount and no
        // brokered container-local forwarder yet (S3), in-container SSH key auth
        // fails closed rather than reaching the host agent.
        assert!(
            !env_map.contains_key("SSH_AUTH_SOCK"),
            "isolated container env must not point SSH_AUTH_SOCK at a host-agent \
             mount (S2 retired the host ssh-agent bind-mount)"
        );
        assert!(
            !env_map.contains_key("EMBER_SOCKET_PATH"),
            "bridge-enabled isolated launches must not leak legacy UDS env"
        );
        assert!(
            !env_map.contains_key("EMBER_DAEMON_SOCKET"),
            "bridge-enabled isolated launches must not leak legacy UDS env"
        );
    }

    #[test]
    fn isolated_child_env_exports_runtime_id_from_managed_worktree_metadata() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let workspace = tmp.path().join("worktree");
        std::fs::create_dir_all(&workspace).expect("create worktree");
        std::fs::write(
            workspace.join(".agent-session"),
            format!(
                "session_name: fixture\nruntime_id: rt-fixture123\nworktree_path: {}\n",
                workspace.display()
            ),
        )
        .expect("write managed worktree metadata");

        let registration = fixture_registration();
        let env = isolated_child_env(
            RuntimeEngine::Docker,
            "persona-main",
            &registration,
            &workspace,
        );
        let env_map: std::collections::BTreeMap<_, _> = env.into_iter().collect();

        assert_eq!(
            env_map
                .get(crate::dev_runtime::DEV_RUNTIME_ID_ENV)
                .map(String::as_str),
            Some("rt-fixture123")
        );
        assert_eq!(
            env_map.get("EMBER_BROKER_CWD").map(String::as_str),
            Some(workspace.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn isolated_child_env_resolves_host_tool_binaries_outside_shadow_path() {
        let _lock = env_lock().lock().unwrap();
        let _guard = EnvGuard::capture();

        let root = tempfile::TempDir::new().unwrap();
        let shadow_dir = root.path().join("shadow/bin");
        let real_dir = root.path().join("host/bin");
        std::fs::create_dir_all(&shadow_dir).unwrap();
        std::fs::create_dir_all(&real_dir).unwrap();

        let shadow_gh = shadow_dir.join("gh");
        let real_gh = real_dir.join("gh");
        let real_git = real_dir.join("git");
        std::fs::write(&shadow_gh, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&real_gh, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&real_git, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for path in [&shadow_gh, &real_gh, &real_git] {
                let mut perms = std::fs::metadata(path).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(path, perms).unwrap();
            }
        }

        // SAFETY: test-only PATH mutation under the process-wide env lock.
        unsafe {
            std::env::set_var(
                "PATH",
                format!("{}:{}", shadow_dir.display(), real_dir.display()),
            );
        }

        let env = isolated_child_env(
            RuntimeEngine::Docker,
            "persona-main",
            &fixture_registration(),
            Path::new("/home/test/repo"),
        );
        let env_map: std::collections::BTreeMap<_, _> = env.into_iter().collect();

        assert_eq!(
            env_map.get("EMBER_GH_BINARY").map(String::as_str),
            Some(real_gh.to_string_lossy().as_ref())
        );
        assert_eq!(
            env_map.get("EMBER_GIT_BINARY").map(String::as_str),
            Some(real_git.to_string_lossy().as_ref())
        );
        assert_eq!(
            env_map.get("BASH_ENV").map(String::as_str),
            Some(CONTAINER_SHELL_ENV_FILE),
            "isolated command shells must source the brokered shim env"
        );
    }

    #[test]
    fn prepare_isolated_worker_home_preserves_shadow_path_for_shells() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let worker_home = tmp.path().join("worker-home");

        prepare_isolated_worker_home(&worker_home).expect("prepare isolated worker home");
        prepare_isolated_worker_home(&worker_home).expect("prepare isolated worker home twice");

        let shell_env =
            std::fs::read_to_string(worker_home.join(".ember-shell-env")).expect("read shell env");
        assert!(
            shell_env.contains(CONTAINER_SHADOW_BIN_DIR),
            "shell env must restore the brokered shadow path: {shell_env}"
        );
        assert!(
            shell_env.contains("export PATH=\"/usr/local/lib/shadow/bin:$PATH\""),
            "shell env must prepend, not append, brokered shims: {shell_env}"
        );

        for file_name in [".profile", ".bash_profile"] {
            let profile =
                std::fs::read_to_string(worker_home.join(file_name)).expect("read shell profile");
            assert!(
                profile.contains(CONTAINER_SHELL_ENV_FILE),
                "{file_name} must source the brokered shell env: {profile}"
            );
        }
    }

    #[test]
    fn render_real_compose_template_includes_codex_isolated_mounts() {
        let template = bundled_compose_template_path();
        assert!(template.exists(), "expected bundled compose template");

        let mut ctx =
            ComposeRenderContext::default_for_profile("autopilot", PathBuf::from("/tmp/certs"));
        ctx.shadow_bin_source = Some(PathBuf::from("/home/test/.ember/shadow/bin"));
        ctx.codex_runtime_source = Some(PathBuf::from("/home/test/.local/share/codex-runtime"));
        ctx.worker_home_path = Some(PathBuf::from("/home/test/.ember/session-open/worker-home"));
        ctx.worker_codex_authority_path = Some(PathBuf::from("/home/test/.codex"));
        ctx.worker_overlay_mounts = vec![
            ComposeBindMount::rw(
                PathBuf::from("/home/test/.ember/session-open/codex-overlay/config.toml"),
                "/home/agent/.codex/config.toml",
            ),
            ComposeBindMount::rw(
                PathBuf::from("/home/test/.ember/session-open/codex-overlay/state_5.sqlite"),
                "/home/agent/.codex/state_5.sqlite",
            ),
            ComposeBindMount::rw(
                PathBuf::from("/home/test/.ember/session-open/codex-overlay/log"),
                "/home/agent/.codex/log",
            ),
        ];
        // `worker_extra_mounts` is the generic extra-bind-mount seam (the host
        // ssh-agent socket mount that once used it was retired in S2). Exercise it
        // with a neutral read-only mount so the renderer path stays covered.
        ctx.worker_extra_mounts = vec![ComposeBindMount::ro(
            PathBuf::from("/home/test/.ember/extra/ro-asset"),
            "/opt/ember/ro-asset",
        )];
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
        assert!(rendered.contains("target: \"/home/agent/.codex\""));
        assert!(rendered.contains("source: \"/home/test/.codex\""));
        assert!(
            rendered
                .contains("source: \"/home/test/.ember/session-open/codex-overlay/config.toml\"")
        );
        assert!(rendered.contains("target: \"/home/agent/.codex/config.toml\""));
        assert!(
            rendered.contains(
                "source: \"/home/test/.ember/session-open/codex-overlay/state_5.sqlite\""
            )
        );
        assert!(rendered.contains("target: \"/home/agent/.codex/state_5.sqlite\""));
        assert!(rendered.contains("source: \"/home/test/.ember/session-open/codex-overlay/log\""));
        assert!(rendered.contains("target: \"/home/agent/.codex/log\""));
        // ADR 207 seam 8 — the daemon UDS is no longer mounted into the worker.
        assert!(!rendered.contains("/run/emberd-host"));
        // S2: no host ssh-agent socket is ever mounted into the worker.
        assert!(!rendered.contains("/run/ember/ssh-agent.sock"));
        // The generic extra-mount seam still renders.
        assert!(rendered.contains("source: \"/home/test/.ember/extra/ro-asset\""));
        assert!(rendered.contains("target: \"/opt/ember/ro-asset\""));
        assert!(rendered.contains("read_only: true"));
        assert!(rendered.contains("source: \"/home/test/src/repo\""));
        assert!(rendered.contains("target: /work/repo"));
    }

    #[test]
    fn prepare_isolated_codex_home_copies_safe_files_and_isolates_mutable_state() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let host = tmp.path().join("host-codex");
        std::fs::create_dir_all(host.join("skills/custom")).expect("create skills dir");
        std::fs::create_dir_all(host.join("memories")).expect("create memories dir");
        std::fs::create_dir_all(host.join("log")).expect("create log dir");
        std::fs::write(host.join("auth.json"), b"{\"ok\":true}").expect("write auth");
        std::fs::write(host.join("config.toml"), b"model = 'gpt-5.4'\n").expect("write config");
        std::fs::write(host.join("skills/custom/SKILL.md"), b"# skill\n").expect("write skill");
        std::fs::write(host.join("memories/repo.md"), b"remember\n").expect("write memory");
        std::fs::write(host.join("state_5.sqlite"), b"sqlite-bytes").expect("write sqlite");
        std::fs::write(host.join("logs_9.sqlite-wal"), b"wal")
            .expect("write custom sqlite surface");

        let prepared =
            prepare_isolated_codex_home(tmp.path(), "sess_fixture", &host).expect("stage config");

        assert_eq!(prepared.authority_root, host);
        let staged = prepared.overlay_root;
        assert!(staged.join("config.toml").is_file());
        assert!(staged.join("skills/custom/SKILL.md").is_file());
        assert!(staged.join("memories/repo.md").is_file());
        assert!(
            !staged.join("auth.json").exists(),
            "auth should stay on the shared host root"
        );
        assert!(staged.join("log").is_dir());
        assert!(staged.join("history.jsonl").is_file());
        assert!(staged.join("state_5.sqlite").is_file());
        assert!(staged.join("state_5.sqlite-wal").is_file());
        assert!(staged.join("state_5.sqlite-shm").is_file());
        assert!(staged.join("logs_9.sqlite").is_file());
        assert!(staged.join("logs_9.sqlite-wal").is_file());
        assert!(staged.join("logs_9.sqlite-shm").is_file());
        assert!(
            prepared
                .overlay_mounts
                .iter()
                .any(|mount| mount.target == "/home/agent/.codex/log"),
            "mutable log dir should be overlaid into the shared Codex root"
        );
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
        ctx.worker_bridge_url = Some("https://host.docker.internal:4243".to_string());
        ctx.worker_bridge_cert_dir = Some(PathBuf::from("/tmp/worker-certs"));

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
            rendered.contains("worker-chown-init:"),
            "standalone worker render must include the chown init container on idmapped fallback runtimes"
        );
        assert!(
            rendered.contains("grep -v 'No such file or directory'"),
            "worker-chown-init must tolerate transient ENOENT churn from active host build trees"
        );
        assert!(
            rendered.contains("EMBER_BRIDGE_URL: \"https://host.docker.internal:4243\""),
            "standalone worker render must inject host-bridge env"
        );
        assert!(
            rendered.contains(
                "PATH: \"/usr/local/lib/shadow/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin\""
            ),
            "standalone worker render must put brokered shims on the service PATH"
        );
        assert!(
            rendered.contains("source: \"/tmp/worker-certs\""),
            "standalone worker render must mount the staged bridge client bundle"
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
        write_default_home_config(&home, Some("127.0.0.1:4243"));
        let docker_log = install_fake_docker(&bin_dir, 23);
        let daemon_socket_path = tmp.path().join("daemon.sock");
        std::fs::write(&daemon_socket_path, b"").expect("write fake daemon socket");

        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("PATH", &bin_dir);
            std::env::set_var("EMBER_COMPOSE_TEMPLATE", bundled_compose_template_path());
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-isolated-bridge-passphrase");
        }

        let code = launch_harness_isolated(IsolatedHarnessLaunch {
            harness: HarnessKind::Claude,
            persona: "persona-main".to_string(),
            registration: fixture_registration(),
            daemon_socket_path,
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
        assert!(compose.contains("EMBER_BRIDGE_URL: \"https://host.docker.internal:4243\""));
        assert!(
            compose.contains(
                "PATH: \"/usr/local/lib/shadow/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin\""
            ),
            "isolated compose render must expose brokered shims on the worker service PATH"
        );
        assert!(compose.contains("target: /run/ember"));

        let docker_log = std::fs::read_to_string(docker_log).expect("read docker log");
        assert!(docker_log.contains("[up] [-d]"));
        assert!(docker_log.contains("[exec] [-T] [-w] [/work/repo]"));
        assert!(docker_log.contains("[down] [-v] [--timeout] [1]"));
        assert!(docker_log.contains("[worker] [claude] [--help]"));
    }

    #[cfg(unix)]
    #[test]
    fn launch_harness_isolated_claude_honors_container_binary_override() {
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
        write_default_home_config(&home, Some("127.0.0.1:4243"));
        let docker_log = install_fake_docker(&bin_dir, 23);
        let daemon_socket_path = tmp.path().join("daemon.sock");
        std::fs::write(&daemon_socket_path, b"").expect("write fake daemon socket");

        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("PATH", &bin_dir);
            std::env::set_var("EMBER_COMPOSE_TEMPLATE", bundled_compose_template_path());
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-isolated-bridge-passphrase");
            std::env::set_var("EMBER_CLAUDE_BIN", "/bin/sh");
        }

        let code = launch_harness_isolated(IsolatedHarnessLaunch {
            harness: HarnessKind::Claude,
            persona: "persona-main".to_string(),
            registration: fixture_registration(),
            daemon_socket_path,
            extra_args: vec!["-c".to_string(), "true".to_string()],
            backend_hint: Some("docker".to_string()),
            preset: Some("dev".to_string()),
            workspace_root,
            shadow_root,
            codex_runtime_source: None,
            codex_config_source: None,
        })
        .expect("launch isolated claude with override");

        assert_eq!(code, 23, "compose exec exit code should bubble up");
        let docker_log = std::fs::read_to_string(docker_log).expect("read docker log");
        assert!(docker_log.contains("[worker] [/bin/sh] [-c] [true]"));
        assert!(
            !docker_log.contains("[worker] [claude]"),
            "isolated Claude must not ignore EMBER_CLAUDE_BIN: {docker_log}"
        );
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
        let daemon_socket_path = tmp.path().join("daemon.sock");
        let ssh_auth_sock = tmp.path().join("ssh-agent.sock");
        write_default_home_config(&home, Some("127.0.0.1:4243"));
        std::fs::write(
            codex_config_root.join("config.toml"),
            b"model = 'gpt-5.4'\n",
        )
        .expect("write codex config");
        std::fs::write(&daemon_socket_path, b"").expect("write fake daemon socket");
        std::fs::write(&ssh_auth_sock, b"").expect("write fake ssh auth socket");
        let docker_log = install_fake_docker(&bin_dir, 23);

        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("PATH", &bin_dir);
            std::env::set_var("EMBER_COMPOSE_TEMPLATE", bundled_compose_template_path());
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-isolated-bridge-passphrase");
        }

        let mut registration = fixture_registration();
        registration.ssh_auth_sock = Some(ssh_auth_sock.display().to_string());
        let code = launch_harness_isolated(IsolatedHarnessLaunch {
            harness: HarnessKind::Codex,
            persona: "persona-main".to_string(),
            registration,
            daemon_socket_path: daemon_socket_path.clone(),
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
        let worker_home = session_open_root.join("codex-home-sess_fixture");
        let shell_env = std::fs::read_to_string(worker_home.join(".ember-shell-env"))
            .expect("isolated Codex home must seed non-interactive shell env");
        assert!(
            shell_env.contains(CONTAINER_SHADOW_BIN_DIR),
            "Codex isolated command shells must preserve brokered shim PATH: {shell_env}"
        );
        let bash_profile = std::fs::read_to_string(worker_home.join(".bash_profile"))
            .expect("isolated Codex home must seed bash login profile");
        assert!(
            bash_profile.contains(CONTAINER_SHELL_ENV_FILE),
            "Codex isolated login shells must source brokered shim env: {bash_profile}"
        );
        let compose_files: Vec<_> = std::fs::read_dir(&session_open_root)
            .expect("list session-open root")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path().join("compose.yml"))
            .filter(|path| path.exists())
            .collect();
        assert_eq!(compose_files.len(), 1, "expected one compose render");
        let compose = std::fs::read_to_string(&compose_files[0]).expect("read compose file");
        assert!(compose.contains(&format!("source: \"{}\"", codex_runtime_root.display())));
        assert!(compose.contains("target: \"/home/agent/.codex\""));
        assert!(compose.contains(&format!("source: \"{}\"", codex_config_root.display())));
        let staged_overlay = session_open_root.join("codex-overlay-sess_fixture");
        assert!(compose.contains(&format!(
            "source: \"{}\"",
            staged_overlay.join("config.toml").display()
        )));
        assert!(compose.contains(&format!(
            "source: \"{}\"",
            staged_overlay.join("state_5.sqlite").display()
        )));
        assert!(compose.contains(&format!(
            "source: \"{}\"",
            staged_overlay.join("history.jsonl").display()
        )));
        assert!(compose.contains("target: \"/home/agent/.codex/config.toml\""));
        assert!(compose.contains("target: \"/home/agent/.codex/state_5.sqlite\""));
        assert!(compose.contains("target: \"/home/agent/.codex/history.jsonl\""));
        // ADR 207 seam 8 — the daemon UDS dir is not mounted into the worker;
        // the container reaches emberd only over the mTLS bridge.
        assert!(
            !compose.contains("/run/emberd-host"),
            "daemon UDS must not be mounted into the isolated worker"
        );
        assert!(compose.contains("EMBER_BRIDGE_URL: \"https://host.docker.internal:4243\""));
        assert!(
            compose.contains(
                "PATH: \"/usr/local/lib/shadow/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin\""
            ),
            "isolated Codex compose render must expose brokered shims on the worker service PATH"
        );
        // ssh-agent-over-bridge S2: even though the registration carries a host
        // ssh_auth_sock path, the isolated launcher mounts NO host ssh-agent
        // socket into the worker (the unbridged-host-agent exposure is retired).
        assert!(
            !compose.contains(&format!("source: \"{}\"", ssh_auth_sock.display())),
            "host ssh-agent socket must not be bind-mounted into the worker"
        );
        assert!(
            !compose.contains("target: \"/run/ember/ssh-agent.sock\""),
            "no /run/ember/ssh-agent.sock host mount in the isolated worker"
        );

        let docker_log = std::fs::read_to_string(docker_log).expect("read docker log");
        assert!(docker_log.contains("[up] [-d]"));
        assert!(docker_log.contains("[exec] [-T] [-w] [/work/repo]"));
        assert!(docker_log.contains("[down] [-v] [--timeout] [1]"));
        assert!(docker_log.contains("[-e] [BASH_ENV=/home/agent/.ember-shell-env]"));
        assert!(docker_log.contains("[-e] [EMBER_BRIDGE_URL=https://host.docker.internal:4243]"));
        assert!(docker_log.contains("[-e] [EMBER_CLIENT_CERT=/run/ember/client.crt]"));
        assert!(docker_log.contains("[-e] [EMBER_CLIENT_KEY=/run/ember/client.key]"));
        assert!(docker_log.contains("[-e] [EMBER_CA_CERT=/run/ember/ca.crt]"));
        assert!(
            !docker_log.contains("[-e] [EMBER_SOCKET_PATH=/run/emberd-host/daemon.sock]"),
            "bridge-enabled isolated codex launch must not forward legacy UDS env"
        );
        assert!(
            !docker_log.contains("[-e] [EMBER_DAEMON_SOCKET=/run/emberd-host/daemon.sock]"),
            "bridge-enabled isolated codex launch must not forward legacy UDS env"
        );
        assert!(
            !docker_log.contains("SSH_AUTH_SOCK="),
            "isolated worker env must not point SSH_AUTH_SOCK at a host-agent mount"
        );
        assert!(
            docker_log.contains("[worker] [/usr/local/lib/ember/codex-runtime/bin/codex]"),
            "Codex handoff must exec the container runtime binary: {docker_log}"
        );
        assert!(
            docker_log.contains("[-C] [/work/repo] [--help]"),
            "Codex handoff must inject the container worktree via -C: {docker_log}"
        );
    }

    #[test]
    fn isolated_container_binary_override_requires_container_visible_path() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        unsafe {
            std::env::set_var("EMBER_CODEX_BIN", "/tmp/codex-test");
        }

        let err = codex_container_binary_path(&IsolatedHarnessLaunch {
            harness: HarnessKind::Codex,
            persona: "persona-main".to_string(),
            registration: fixture_registration(),
            daemon_socket_path: PathBuf::from("/tmp/daemon.sock"),
            extra_args: Vec::new(),
            backend_hint: Some("docker".to_string()),
            preset: Some("dev".to_string()),
            workspace_root: PathBuf::from("/tmp/repo"),
            shadow_root: PathBuf::from("/tmp/shadow"),
            codex_runtime_source: None,
            codex_config_source: None,
        })
        .expect_err("host-only override path must be refused for isolated launches");
        let msg = err.to_string();
        assert!(msg.contains("EMBER_CODEX_BIN"), "got: {msg}");
        assert!(msg.contains("/work/repo"), "got: {msg}");
    }

    #[test]
    fn isolated_codex_container_binary_override_accepts_workspace_path() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        unsafe {
            std::env::set_var("EMBER_CODEX_BIN", "/work/repo/.ember/codex-standin");
        }

        let binary = codex_container_binary_path(&IsolatedHarnessLaunch {
            harness: HarnessKind::Codex,
            persona: "persona-main".to_string(),
            registration: fixture_registration(),
            daemon_socket_path: PathBuf::from("/tmp/daemon.sock"),
            extra_args: Vec::new(),
            backend_hint: Some("docker".to_string()),
            preset: Some("dev".to_string()),
            workspace_root: PathBuf::from("/tmp/repo"),
            shadow_root: PathBuf::from("/tmp/shadow"),
            codex_runtime_source: None,
            codex_config_source: None,
        })
        .expect("workspace override is container-visible");

        assert_eq!(binary, "/work/repo/.ember/codex-standin");
    }

    // ember_up_auto_update_b_launcher_integration — branch coverage for the
    // four UpdateDecision branches + the two UpdateDecisionError variants +
    // the "not configured" skip path.
    mod auto_update {
        use super::super::*;
        use ed25519_dalek::SigningKey;
        use ember_update::channel::{Channel, sign_channel_pointer};
        use ember_update::in_toto;
        use ember_update::revocations::{
            RevocationDocument, RevocationEntry, RevocationSeverity, RevocationsPoller,
            revocation_statement,
        };

        const FIXED_DIGEST: &str =
            "sha256:0000000000000000000000000000000000000000000000000000000000000001";
        const NEW_DIGEST: &str =
            "sha256:0000000000000000000000000000000000000000000000000000000000000002";

        fn fixture_keys() -> (SigningKey, VerifyingKey) {
            let sk = SigningKey::from_bytes(&[42u8; 32]);
            let vk = sk.verifying_key();
            (sk, vk)
        }

        fn revocation_fixture_keys() -> (SigningKey, VerifyingKey) {
            let sk = SigningKey::from_bytes(&[77u8; 32]);
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

        fn fresh_revocations_doc(signer: &SigningKey, now_unix_secs: u64) -> Vec<u8> {
            signed_revocations_doc(
                signer,
                RevocationDocument {
                    issued_at_unix_secs: now_unix_secs,
                    revocations: Vec::new(),
                },
            )
        }

        fn revoked_revocations_doc(
            signer: &SigningKey,
            now_unix_secs: u64,
            digest: &str,
            severity: RevocationSeverity,
        ) -> Vec<u8> {
            signed_revocations_doc(
                signer,
                RevocationDocument {
                    issued_at_unix_secs: now_unix_secs,
                    revocations: vec![RevocationEntry {
                        digest: digest.to_string(),
                        severity,
                        reason: "test fixture revocation".to_string(),
                    }],
                },
            )
        }

        fn signed_revocations_doc(signer: &SigningKey, doc: RevocationDocument) -> Vec<u8> {
            let signed =
                in_toto::sign(revocation_statement(doc), signer).expect("sign revocations doc");
            serde_json::to_vec(&signed).expect("serialize signed revocations doc")
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
            let (rev_sk, rev_vk) = revocation_fixture_keys();
            let now_ms = 1_700_000_000_000u64;
            let pointer = make_pointer(&sk, FIXED_DIGEST, now_ms);
            let revocations = fresh_revocations_doc(&rev_sk, now_ms / 1000);
            let poller = RevocationsPoller::with_trusted_signer(rev_vk);
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
            let (rev_sk, rev_vk) = revocation_fixture_keys();
            let now_ms = 1_700_000_000_000u64;
            let pointer = make_pointer(&sk, NEW_DIGEST, now_ms);
            let revocations = fresh_revocations_doc(&rev_sk, now_ms / 1000);
            let poller = RevocationsPoller::with_trusted_signer(rev_vk);
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
            let (rev_sk, rev_vk) = revocation_fixture_keys();
            let now_ms = 1_700_000_000_000u64;
            let pointer = make_pointer(&sk, FIXED_DIGEST, now_ms);
            let revocations = revoked_revocations_doc(
                &rev_sk,
                now_ms / 1000,
                FIXED_DIGEST,
                RevocationSeverity::Critical,
            );
            let poller = RevocationsPoller::with_trusted_signer(rev_vk);
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
            let (rev_sk, rev_vk) = revocation_fixture_keys();
            let now_ms = 1_700_000_000_000u64;
            let pointer = make_pointer(&sk, FIXED_DIGEST, now_ms);
            let revocations = fresh_revocations_doc(&rev_sk, now_ms / 1000);
            let poller = RevocationsPoller::with_trusted_signer(rev_vk);
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
