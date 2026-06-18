//! Sandvault runtime adapter helpers.
//!
//! Sandvault runs the harness as a dedicated macOS user. That is not the host
//! launcher contract: parent env is not preserved, arbitrary operator-owned
//! worktrees under `/Users/$USER` are not readable, and the direct child PID is
//! the outer `sv` process. This adapter therefore stages a standalone clone and
//! a launch bundle under Sandvault's shared workspace, then relies on the
//! daemon bridge rather than host UDS access.

use std::io;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::launcher::core::SessionRegistration;
use crate::launcher::harness::HarnessKind;
use crate::launcher::path_shadow::{ConstructSpec, install_path_shadow, shadow_bin_dir};

const SANDVAULT_BASE_REF: &str = "origin/main";
const SANDVAULT_CLAUDE_PROXY_AUTH_PLACEHOLDER: &str = "ember-proxy-session";

#[derive(Debug, Clone)]
pub struct SandvaultPreparedWorktree {
    pub path: PathBuf,
    pub branch: String,
}

#[derive(Debug, Clone)]
pub struct SandvaultHarnessLaunch {
    pub harness: HarnessKind,
    pub registration: SessionRegistration,
    pub workspace_root: PathBuf,
    pub workspace_ref: String,
    pub shadow_root: PathBuf,
    pub construct_specs: Vec<ConstructSpec>,
    pub persona: String,
    pub extra_args: Vec<String>,
}

#[derive(Debug, Clone)]
struct PreparedSandvaultBridgeClient {
    url: String,
    cert_dir: PathBuf,
}

pub fn shared_workspace_for_host_user(host_user: &str) -> PathBuf {
    PathBuf::from("/Users/Shared").join(format!("sv-{host_user}"))
}

pub fn shared_workspace_root() -> io::Result<PathBuf> {
    let host_user = std::env::var("USER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| io::Error::other("cannot resolve host USER for Sandvault workspace"))?;
    Ok(shared_workspace_for_host_user(&host_user)
        .join("user")
        .join("emberlink"))
}

pub fn worktree_path_for_session(session_name: &str) -> io::Result<PathBuf> {
    let slug = crate::launcher::worktree::slugify(session_name);
    if slug.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("session name '{session_name}' slugified to empty"),
        ));
    }
    Ok(shared_workspace_root()?.join("worktrees").join(slug))
}

pub fn ensure_managed_clone_from_base(
    repo_root: &Path,
    worktree_path: &Path,
    branch: &str,
) -> io::Result<SandvaultPreparedWorktree> {
    crate::launcher::worktree::validate_branch(branch)?;
    if !worktree_path.exists() {
        let parent = worktree_path.parent().ok_or_else(|| {
            io::Error::other(format!(
                "Sandvault worktree path has no parent: {}",
                worktree_path.display()
            ))
        })?;
        std::fs::create_dir_all(parent)?;
        run_git(
            None,
            &[
                "clone",
                "--no-local",
                repo_root
                    .to_str()
                    .ok_or_else(|| io::Error::other("repo root is not UTF-8"))?,
                worktree_path
                    .to_str()
                    .ok_or_else(|| io::Error::other("worktree path is not UTF-8"))?,
            ],
        )?;
    }

    if branch_exists(worktree_path, branch)? {
        run_git(Some(worktree_path), &["checkout", branch])?;
    } else {
        let _ = run_git(Some(worktree_path), &["fetch", "origin", "main"]);
        run_git(
            Some(worktree_path),
            &["checkout", "-B", branch, SANDVAULT_BASE_REF],
        )?;
    }

    Ok(SandvaultPreparedWorktree {
        path: worktree_path.to_path_buf(),
        branch: branch.to_string(),
    })
}

fn branch_exists(repo: &Path, branch: &str) -> io::Result<bool> {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", "--quiet"])
        .arg(format!("refs/heads/{branch}"))
        .status()?;
    Ok(status.success())
}

fn run_git(repo: Option<&Path>, args: &[&str]) -> io::Result<()> {
    let mut command = Command::new("git");
    if let Some(repo) = repo {
        command.arg("-C").arg(repo);
    }
    let output = command.args(args).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "git {} failed with exit {}: {}{}",
        args.join(" "),
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

pub fn launch_harness_sandvault(request: SandvaultHarnessLaunch) -> io::Result<i32> {
    let crate::up::SandvaultRuntimeCapability::Available {
        binary: sv_binary, ..
    } = crate::up::detect_sandvault_runtime_capability()?
    else {
        return Err(io::Error::other(
            "Sandvault runtime is unavailable; run `SANDVAULT_BIN=/path/to/sv bash scripts/agent/sandvault-runtime-spike.sh --require-sv` for diagnostics",
        ));
    };

    if request.registration.anthropic_unix_socket.is_some() {
        return Err(io::Error::other(
            "Sandvault launch refused: registration returned a host UDS Anthropic lane; use the bridge/TCP lane for separate-user Sandvault sessions",
        ));
    }

    install_path_shadow(&request.shadow_root, &request.construct_specs)?;
    let shadow_bin = shadow_bin_dir(&request.shadow_root);
    let bridge =
        prepare_sandvault_bridge_client_bundle(&request.workspace_root, &request.registration)?;
    let launch_dir = request
        .workspace_root
        .join(".ember")
        .join("sandvault-launch")
        .join(&request.registration.session_id);
    if launch_dir.exists() {
        std::fs::remove_dir_all(&launch_dir)?;
    }
    std::fs::create_dir_all(&launch_dir)?;
    let script_path = launch_dir.join("launch.sh");
    write_sandvault_file(
        &script_path,
        render_launch_script(&request, &shadow_bin, &bridge)?.as_bytes(),
        0o640,
    )?;

    eprintln!(
        "ember {}: launching Sandvault runtime at {} (session={}, bridge={})",
        harness_label(request.harness),
        request.workspace_root.display(),
        request.registration.session_id,
        bridge.url,
    );

    let mut command = Command::new(sv_binary);
    command
        .arg("--no-build")
        .arg("shell")
        .arg(&request.workspace_root)
        .arg("--")
        .arg("/bin/sh")
        .arg(&script_path)
        .args(&request.extra_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = command.status().map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to spawn Sandvault runtime: {err}"),
        )
    })?;
    Ok(status.code().unwrap_or(1))
}

fn prepare_sandvault_bridge_client_bundle(
    workspace_root: &Path,
    registration: &SessionRegistration,
) -> io::Result<PreparedSandvaultBridgeClient> {
    let bundle = registration.bridge_client_bundle.as_ref().ok_or_else(|| {
        io::Error::other(
            "Sandvault bridge client bundle missing from register_session response; update daemon and retry",
        )
    })?;
    let cert_dir = workspace_root
        .join(".ember")
        .join("sandvault-bridge-certs")
        .join(&registration.session_id);
    if cert_dir.exists() {
        std::fs::remove_dir_all(&cert_dir)?;
    }
    std::fs::create_dir_all(&cert_dir)?;
    write_sandvault_file(
        &cert_dir.join("client.crt"),
        bundle.client_cert_pem.as_bytes(),
        0o644,
    )?;
    write_sandvault_file(
        &cert_dir.join("client.key"),
        bundle.client_key_pem.as_bytes(),
        0o640,
    )?;
    write_sandvault_file(
        &cert_dir.join("ca.crt"),
        bundle.ca_cert_pem.as_bytes(),
        0o644,
    )?;
    Ok(PreparedSandvaultBridgeClient {
        url: format!("https://127.0.0.1:{}", bundle.port),
        cert_dir,
    })
}

fn write_sandvault_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::os::unix::fs::PermissionsExt as _;

        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)?;
        file.write_all(bytes)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::write(path, bytes)?;
    }
    Ok(())
}

fn render_launch_script(
    request: &SandvaultHarnessLaunch,
    shadow_bin: &Path,
    bridge: &PreparedSandvaultBridgeClient,
) -> io::Result<String> {
    let mut out = String::new();
    out.push_str("#!/bin/sh\nset -eu\n");
    push_export(&mut out, "EMBER_PERSONA", &request.persona);
    push_export(
        &mut out,
        "EMBER_PERSONA_ID",
        request
            .registration
            .persona_id
            .as_deref()
            .unwrap_or(&request.persona),
    );
    push_export(&mut out, "EMBER_PROXY_URL", &request.registration.proxy_url);
    push_export(
        &mut out,
        "EMBER_SESSION_ID",
        &request.registration.session_id,
    );
    push_export(&mut out, "EMBER_BRIDGE_URL", &bridge.url);
    push_export(
        &mut out,
        "EMBER_CLIENT_CERT",
        &bridge.cert_dir.join("client.crt").to_string_lossy(),
    );
    push_export(
        &mut out,
        "EMBER_CLIENT_KEY",
        &bridge.cert_dir.join("client.key").to_string_lossy(),
    );
    push_export(
        &mut out,
        "EMBER_CA_CERT",
        &bridge.cert_dir.join("ca.crt").to_string_lossy(),
    );
    push_export(
        &mut out,
        crate::launcher::worktree::WORKSPACE_REF_ENV,
        &request.workspace_ref,
    );
    push_export(
        &mut out,
        "EMBER_BROKER_CWD",
        &request.workspace_root.to_string_lossy(),
    );
    if let Some(attachment_id) = request.registration.attachment_id.as_deref() {
        push_export(&mut out, "EMBER_ATTACHMENT_ID", attachment_id);
    }
    if let Some(endpoint_token) = request.registration.attachment_endpoint_token.as_deref() {
        push_export(&mut out, "EMBER_ATTACHMENT_ENDPOINT_TOKEN", endpoint_token);
    }
    if let Some(delegation_id) = request.registration.delegation_id.as_deref() {
        push_export(&mut out, "EMBER_DELEGATION_ID", delegation_id);
    }
    if let Some(template) = request.registration.delegation_template.as_deref() {
        push_export(&mut out, "EMBER_DELEGATION_TEMPLATE", template);
    }
    if let Some(git_proxy_url) = request.registration.git_proxy_url.as_deref() {
        push_export(&mut out, "EMBER_GIT_PROXY_URL", git_proxy_url);
    }
    out.push_str("export PATH=");
    out.push_str(&shell_single_quote(&shadow_bin.to_string_lossy()));
    out.push_str(":\"$PATH\"\n");

    match request.harness {
        HarnessKind::Claude => {
            out.push_str("unset CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN\n");
            if let Some(base_url) = request.registration.anthropic_base_url.as_deref() {
                push_export(&mut out, "ANTHROPIC_BASE_URL", base_url);
            }
            if let Some(headers) = request.registration.anthropic_custom_headers.as_deref() {
                push_export(&mut out, "ANTHROPIC_CUSTOM_HEADERS", headers);
            }
            if request.registration.anthropic_base_url.is_some()
                || request.registration.anthropic_custom_headers.is_some()
            {
                push_export(
                    &mut out,
                    "ANTHROPIC_AUTH_TOKEN",
                    SANDVAULT_CLAUDE_PROXY_AUTH_PLACEHOLDER,
                );
            }
        }
        HarnessKind::Codex => {
            out.push_str("unset CODEX_API_KEY CODEX_ACCESS_TOKEN OPENAI_API_KEY\n");
            if let Some(codex_url) = request.registration.codex_responses_proxy_url.as_deref() {
                let codex_home = write_sandvault_codex_home(&request.workspace_root, codex_url)?;
                push_export(&mut out, "CODEX_HOME", &codex_home.to_string_lossy());
            }
        }
        HarnessKind::Cursor => {}
        // ADR 215 §2: gemini's Code Assist loopback proxy is HOST-only for now
        // (the daemon returns no `gemini_proxy_url` for container sessions), so
        // `ember gemini` rejects sandvault/isolated placement at the launch layer
        // and this arm is unreachable in practice. Defensive fail-closed unset so
        // no ambient Google credential leaks into a container shell.
        HarnessKind::Gemini => {
            out.push_str("unset GEMINI_API_KEY GOOGLE_API_KEY GOOGLE_GENAI_USE_VERTEXAI GOOGLE_GEMINI_BASE_URL GOOGLE_CLOUD_PROJECT GOOGLE_CLOUD_PROJECT_ID GOOGLE_CLOUD_LOCATION GOOGLE_APPLICATION_CREDENTIALS GOOGLE_CLOUD_ACCESS_TOKEN GEMINI_FORCE_ENCRYPTED_FILE_STORAGE\n");
        }
        HarnessKind::Other => {}
    }

    out.push_str("cd ");
    out.push_str(&shell_single_quote(
        &request.workspace_root.to_string_lossy(),
    ));
    out.push('\n');
    out.push_str("exec ");
    out.push_str(&shell_single_quote(&harness_binary(request.harness)));
    out.push_str(" \"$@\"\n");
    Ok(out)
}

fn write_sandvault_codex_home(
    workspace_root: &Path,
    codex_responses_url: &str,
) -> io::Result<PathBuf> {
    let session_root = workspace_root.join(".ember").join("sandvault-codex-home");
    std::fs::create_dir_all(&session_root)?;
    let config_toml = format!(
        "model_provider = \"ember\"\n\
         \n\
         [model_providers.ember]\n\
         name = \"Ember Broker\"\n\
         base_url = {}\n\
         wire_api = \"responses\"\n\
         requires_openai_auth = false\n",
        toml_basic_string(codex_responses_url)
    );
    std::fs::write(session_root.join("config.toml"), config_toml)?;
    Ok(session_root)
}

fn toml_basic_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                out.push_str(&format!("\\u{:04X}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn harness_binary(harness: HarnessKind) -> String {
    match harness {
        HarnessKind::Claude => {
            std::env::var("EMBER_CLAUDE_BIN").unwrap_or_else(|_| "claude".to_string())
        }
        HarnessKind::Codex => {
            std::env::var("EMBER_CODEX_BIN").unwrap_or_else(|_| "codex".to_string())
        }
        HarnessKind::Cursor => {
            std::env::var("EMBER_CURSOR_BIN").unwrap_or_else(|_| "cursor-agent".to_string())
        }
        HarnessKind::Gemini => {
            std::env::var("EMBER_GEMINI_BIN").unwrap_or_else(|_| "gemini".to_string())
        }
        HarnessKind::Other => "sh".to_string(),
    }
}

fn harness_label(harness: HarnessKind) -> &'static str {
    match harness {
        HarnessKind::Claude => "claude",
        HarnessKind::Codex => "codex",
        HarnessKind::Cursor => "cursor",
        HarnessKind::Gemini => "gemini",
        HarnessKind::Other => "harness",
    }
}

fn push_export(out: &mut String, key: &str, value: &str) {
    out.push_str("export ");
    out.push_str(key);
    out.push('=');
    out.push_str(&shell_single_quote(value));
    out.push('\n');
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_workspace_for_host_user_matches_sandvault_layout() {
        assert_eq!(
            shared_workspace_for_host_user("operator"),
            PathBuf::from("/Users/Shared/sv-operator")
        );
    }

    #[test]
    fn shell_single_quote_handles_embedded_quotes() {
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn toml_basic_string_escapes_special_characters() {
        assert_eq!(
            toml_basic_string("http://127.0.0.1/\"x\"\n"),
            "\"http://127.0.0.1/\\\"x\\\"\\n\""
        );
    }
}
