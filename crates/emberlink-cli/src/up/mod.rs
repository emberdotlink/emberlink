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
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::launcher::claude_code::SessionRegistration;
use crate::launcher::presence;

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

/// implementation-note-428 — container runtime engines `ember up`
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
        if candidate.is_file() {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
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

pub fn open_claude_code_isolated(
    profile: Option<&str>,
    backend_hint: Option<&str>,
) -> io::Result<()> {
    let profile = resolve_profile(profile)?;
    let workspace_root = std::env::current_dir()?;
    let capability = detect_isolated_claude_code_capability(&workspace_root, backend_hint)?;
    let (engine, template_path) = match capability {
        IsolatedClaudeCodeCapability::Ready {
            engine,
            template_path,
        } => (engine, template_path),
        IsolatedClaudeCodeCapability::Unavailable { reason } => {
            return Err(io::Error::new(io::ErrorKind::NotFound, reason));
        }
    };

    println!(
        "Runtime: {} ({})",
        engine.display_name(),
        engine.compose_binary()
    );

    let run_dir = dirs_next::home_dir()
        .ok_or_else(|| io::Error::other("could not resolve $HOME for ~/.ember/run"))?
        .join(".ember/run")
        .join(format!("{}-{}", profile, chrono::Utc::now().timestamp()));
    std::fs::create_dir_all(&run_dir)?;
    let bridge_cert_dir = run_dir.join("certs");
    std::fs::create_dir_all(&bridge_cert_dir)?;
    let compose_path = run_dir.join("compose.yml");

    let context = ComposeRenderContext::default_for_profile(profile.clone(), bridge_cert_dir);
    let rendered = render_compose_template(&template_path, &context)?;
    std::fs::write(&compose_path, &rendered)?;
    println!("Compose: {}", compose_path.display());

    let (stdout, _stderr) = compose_up(engine, &compose_path, &profile)?;
    if !stdout.trim().is_empty() {
        println!("{}", stdout.trim_end());
    }

    eprintln!(
        "note: bridge cert provisioning + `bridge-cli ping` healthcheck land once implementation-note-454 wires the daemon presence RPC. The compose stack is up; the trust handshake is not yet enforced from this verb."
    );
    println!("\nember up: session ready (profile={profile})");
    Ok(())
}

/// Render the compose template at `template_path` (a Jinja2 file —
/// canonical location `crates/headless-runtime/templates/compose.yml.j2`)
/// with the supplied per-run context variables. Returns the rendered
/// YAML as a UTF-8 string.
///
/// implementation-note-428: uses minijinja's strict-undefined mode so
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
    /// Worktree path bind-mounted into the worker. `None` skips the
    /// worktree mount block.
    pub worker_worktree_path: Option<PathBuf>,
    /// Host operator UID for idmapped mount + userns_mode. Defaults to
    /// the running process's effective UID.
    pub host_uid: u32,
    /// Stable agent identifier used in compose volume names so
    /// build-cache volumes are per-agent. Empty string suppresses the
    /// `agent_id`-guarded block in the template.
    pub agent_id: String,
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
            worker_worktree_path: None,
            #[cfg(unix)]
            host_uid: {
                // SAFETY: getuid() is signal-safe and always succeeds.
                unsafe { libc::getuid() }
            },
            #[cfg(not(unix))]
            host_uid: 1000,
            agent_id: String::new(),
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
        if let Some(p) = &self.worker_worktree_path {
            map.insert(
                "worker_worktree_path",
                Value::from(p.to_string_lossy().to_string()),
            );
        }
        map.insert("host_uid", Value::from(self.host_uid));
        if !self.agent_id.is_empty() {
            map.insert("agent_id", Value::from(self.agent_id.clone()));
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
        return Ok(Ok(SessionRegistration {
            session_id: session_id.to_string(),
            grant_id: grant_id.to_string(),
            proxy_url,
            anthropic_base_url,
            anthropic_custom_headers,
            git_proxy_url,
            ssh_auth_sock,
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
        // implementation-note-428 — minimal smoke against a one-line
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
    fn render_compose_template_strict_undefined_refuses_missing_var() {
        // implementation-note-428 — UndefinedBehavior::Strict means a
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
}
