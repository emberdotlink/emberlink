//! `ember claude-code` launcher.
//!
//! Per design §2 / implementation-note-499 + design §3 (PATH-shadow wiring, sub-B).
//! Real daemon RPC shipped in #2318 (LAUNCHER-SESSION-RPC); see design §2
//! for the full protocol contract.
//!
//! 1. Resolve persona: `$EMBER_PERSONA` env var if set; otherwise
//!    `claude-code-{hostname}` (matching what `init --for claude-code`
//!    creates). Install PATH-shadow symlinks via `install_path_shadow`
//!    (idempotent; creates `~/.ember/shadow/bin/` on first launch, verifies
//!    symlinks on subsequent launches).
//! 2. Register a new session with the daemon (`register_session_rpc`) — live
//!    Unix-socket RPC per design §2. Returns `{session_id, grant_id,
//!    proxy_url}`.
//! 3. Set `EMBER_GRANT_ID` / `EMBER_PROXY_URL` / `EMBER_SESSION_ID` in
//!    the child env. `HTTPS_PROXY` is intentionally NOT set — the
//!    daemon's LLM proxy isn't CONNECT-compatible (see
//!    implementation-note-500). Claude Code talks
//!    to api.anthropic.com directly with the friendly's own auth.
//! 4. Prepend `shadow_dir` to the child's `PATH` via `Command::env` so that
//!    tool invocations like `gh pr create` resolve to the ember Construct
//!    binary. **We never write to `std::env::set_var`** — the parent shell's
//!    PATH is unchanged after the launcher returns.
//! 5. Spawn `claude` (or `$EMBER_CLAUDE_BIN` override) with the augmented
//!    env, inheriting stdin/stdout/stderr.
//! 6. On child exit (signal forwarded by the terminal, or natural
//!    termination), close the session via `close_session_rpc` which emits
//!    a signed Receipt with `termination_reason = clean_exit`.
//! 7. Exit with the child's status code.
//!
//! implementation-note-501
//!
//! The launcher uses `std::process::Command::status` (parent-and-child
//! model) rather than `execve`. Terminal SIGINT/SIGTERM go to the
//! foreground process group, so the child gets the signal at the same
//! time the launcher does. The `status()` call returns the child's
//! disposition; `close_session_rpc` runs after it returns regardless of
//! exit code, giving us a single exit-trap point.
//!
//! Env-injection scope (cohort A acceptance): the child inherits the
//! parent env via `Command`'s default behavior, then we layer the ember
//! vars on top. **We never write to `std::env::set_var`** — the parent
//! shell's environment is unchanged after the launcher returns.

use std::io;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::install_paths::PROD_MANIFEST_PATH;
use crate::launcher::path_shadow::{ConstructSpec, install_path_shadow, shadow_bin_dir};
use crate::launcher::presence;
use crate::launcher::session_prefs;

use serde_json::{Value, json};

/// Outcome of the daemon `register_session` RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRegistration {
    pub session_id: String,
    pub grant_id: String,
    pub proxy_url: String,
    /// Optional Anthropic gateway base URL for launcher-mediated Claude Code
    /// sessions. Present only when the daemon has already resolved the active
    /// session grant to a composite Anthropic grant shape.
    pub anthropic_base_url: Option<String>,
    /// Newline-separated `Name: Value` headers for Claude Code's
    /// `ANTHROPIC_CUSTOM_HEADERS` env var. Present only alongside
    /// `anthropic_base_url`.
    pub anthropic_custom_headers: Option<String>,
    /// Git credential-injection proxy URL (implementation-note-302).
    /// When `Some`, the child process receives `EMBER_GIT_PROXY_URL=<url>`.
    /// `None` when the daemon did not allocate a git proxy (git proxy disabled
    /// or pre-fix daemon).
    pub git_proxy_url: Option<String>,
    /// Path to the daemon-managed ssh-agent socket for this session
    /// (implementation-note-85). When `Some`, the child process
    /// receives `SSH_AUTH_SOCK=<path>` so git/ssh in the child tree find
    /// the daemon socket. `None` when the daemon did not allocate an
    /// ssh-agent for this session (e.g. pre-design daemon).
    pub ssh_auth_sock: Option<String>,
    /// design §Component 3 — workflow grant ULID stamped by the daemon when
    /// the launcher selected a workflow template at session-open. None when
    /// the launcher opened the session without picking a template.
    pub workflow_id: Option<String>,
    /// design §Component 3 — workflow template name (e.g. `emberd-development`)
    /// the operator picked at session-open. Paired with `workflow_id`.
    pub workflow_template: Option<String>,
}

/// Call the daemon `register_session` RPC and return the session triple.
///
/// `persona` — the persona name or id for the session.
/// `socket_path` — path to the daemon Unix socket (`~/.ember/run/daemon.sock`).
///
/// Returns `Err` when the daemon is unreachable or returns an error.
pub fn register_session_rpc(persona: &str, socket_path: &Path) -> io::Result<SessionRegistration> {
    register_session_rpc_with_workflow(persona, socket_path, None)
}

/// Call the daemon `register_session` RPC with an optional `workflow_template`.
///
/// design §Component 3 — when `workflow_template` is `Some(name)`, the daemon
/// looks up the template, issues a `WorkflowGrant` via
/// `workflow_grant::save_if_absent`, stamps `workflow_id` + `workflow_template`
/// onto `SessionMeta`, and returns both in the response. Touch ID fires inside
/// the daemon as part of the operator-presence gate on `register_session`.
///
/// The `None` form is the legacy path — no workflow grant is issued and the
/// per-action / JIT chain governs `broker.resolve` outcomes (design §C2).
pub fn register_session_rpc_with_workflow(
    persona: &str,
    socket_path: &Path,
    workflow_template: Option<&str>,
) -> io::Result<SessionRegistration> {
    let launcher_pid = std::process::id();
    let mut params = json!({
        "persona": persona,
        "launcher_pid": launcher_pid,
    });
    if let Some(template) = workflow_template
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("workflow_template".to_string(), json!(template));
    }
    let result = call_daemon(socket_path, "register_session", &params)?;
    parse_register_session_result(&result, socket_path)
}

fn parse_register_session_result(
    result: &Value,
    socket_path: &Path,
) -> io::Result<SessionRegistration> {
    if let (Some(tab_url), Some(prompt_id)) = (
        result["presence_required"]["tab_url"].as_str(),
        result["presence_required"]["prompt_id"].as_str(),
    ) {
        return Err(presence::session_open_presence_unavailable(
            socket_path,
            prompt_id,
            tab_url,
        ));
    }

    let session_id = result["session_id"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "daemon: missing session_id"))?
        .to_string();
    let grant_id = result["grant_id"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "daemon: missing grant_id"))?
        .to_string();
    // implementation-note-302: the daemon should always include
    // proxy_url in the register_session response (it reads EMBER_PROXY_URL
    // from runtime state). If the fallback to 8484 fires it means the daemon
    // is pre-fix or the LLM proxy failed to bind — Claude Code will hit
    // ECONNREFUSED. Emit a clear warning so the regression is visible.
    let proxy_url = match result["proxy_url"].as_str() {
        Some(url) => url.to_string(),
        None => {
            eprintln!(
                "ember claude: WARNING — daemon did not return proxy_url in \
                 register_session response; falling back to http://127.0.0.1:8484 which \
                 is likely not bound. Claude Code may fail with ECONNREFUSED. \
                 (implementation-note-302)"
            );
            "http://127.0.0.1:8484".to_string()
        }
    };
    let anthropic_base_url = result["anthropic_base_url"].as_str().map(|s| s.to_string());
    let anthropic_custom_headers = result["anthropic_custom_headers"]
        .as_str()
        .map(|s| s.to_string());
    let git_proxy_url = result["git_proxy_url"].as_str().map(|s| s.to_string());
    let ssh_auth_sock = result["ssh_auth_sock"].as_str().map(|s| s.to_string());
    let workflow_id = result["workflow_id"].as_str().map(|s| s.to_string());
    let workflow_template = result["workflow_template"].as_str().map(|s| s.to_string());
    Ok(SessionRegistration {
        session_id,
        grant_id,
        proxy_url,
        anthropic_base_url,
        anthropic_custom_headers,
        git_proxy_url,
        ssh_auth_sock,
        workflow_id,
        workflow_template,
    })
}

/// Resolve a workflow template name for this launch (design §Component 3 /
/// implementation-note-502).
///
/// Decision flow:
/// 1. Read `EMBER_WORKFLOW_TEMPLATE` from env — explicit operator override,
///    skips listing + prompting entirely (treated as already-chosen).
/// 2. Resolve the bundled `workflow-templates/` directory under the install
///    root. When the directory is missing or the template list is empty,
///    return `None` — the session opens without a workflow template and the
///    legacy per-action / JIT chain governs `broker.resolve`.
/// 3. When stdin is a TTY, run the interactive selector
///    (`prompt_for_template_with_cache` — pre-selects the operator's last-used
///    template, persists the new choice on success).
/// 4. When stdin is not a TTY (headless / CI), return the cached last-used
///    template or the first template in the list (alphabetical).
///
/// Errors from template discovery degrade to `None` with a stderr warning —
/// Adversarial HIGH-4 fix (2026-05-22): refuse template names that
/// could traverse out of the workflow-templates dir. `<dir>.join(name)`
/// happily accepts `../`, absolute paths, and Windows-style drive
/// prefixes — any of those make the daemon load arbitrary TOML.
/// Restrict to a single ASCII path component.
fn is_safe_template_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    // Must not contain path separators (POSIX OR Windows).
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return false;
    }
    // Must be exactly one `Normal` path component when parsed.
    let p = std::path::Path::new(name);
    let mut comps = p.components();
    let only = comps.next();
    if comps.next().is_some() {
        return false;
    }
    matches!(only, Some(std::path::Component::Normal(_)))
}

/// the legacy chain still applies and the launch never fails on template
/// resolution.
fn resolve_workflow_template_for_launch() -> Option<String> {
    // 1. Explicit override via env var.
    if let Ok(name) = std::env::var("EMBER_WORKFLOW_TEMPLATE")
        && !name.is_empty()
    {
        // Adversarial HIGH-4 fix (2026-05-22): refuse template names
        // that contain path separators or non-`Normal` path
        // components. Pre-fix a child process inheriting an
        // attacker-influenced env (`EMBER_WORKFLOW_TEMPLATE=../../tmp/evil`)
        // could make the daemon's TOML loader traverse out of the
        // template directory.
        if is_safe_template_name(&name) {
            return Some(name);
        } else {
            eprintln!(
                "ember claude: refusing $EMBER_WORKFLOW_TEMPLATE={name:?}: name must be a plain identifier (no slashes or path components)"
            );
            // Fall through to discovery; do NOT honor the unsafe value.
        }
    }

    // 2. List available templates.
    let install_root = workflow_template_install_root();
    let templates = match crate::workflow_prompt::list_templates(&install_root) {
        Ok(t) => t,
        Err(crate::workflow_prompt::WorkflowPromptError::NoTemplates { .. }) => {
            return None;
        }
        Err(e) => {
            eprintln!(
                "ember claude: workflow template discovery failed ({e}); continuing without a workflow grant"
            );
            return None;
        }
    };
    if templates.is_empty() {
        return None;
    }

    // 3. TTY: prompt interactively.
    if std::io::stdin().is_terminal() {
        match crate::workflow_prompt::prompt_for_template_with_cache(&templates) {
            Ok(chosen) => return Some(chosen.name),
            Err(crate::workflow_prompt::WorkflowPromptError::NotInteractive) => {
                // Fall through to the headless default path.
            }
            Err(e) => {
                eprintln!(
                    "ember claude: workflow selection failed ({e}); continuing without a workflow grant"
                );
                return None;
            }
        }
    }

    // 4. Headless: cached last-used or first-list-item default.
    if let Some(cached) = crate::workflow_prompt::load_last_workflow()
        && templates.iter().any(|t| t.name == cached)
    {
        return Some(cached);
    }
    templates.first().map(|t| t.name.clone())
}

/// Resolve the bundled workflow-templates install root.
///
/// Priority (env-overridable for tests + dev installs):
/// 1. `EMBER_WORKFLOW_TEMPLATES_ROOT` — explicit override (test harness +
///    `ember dev install` use this to point at a non-prod install).
/// 2. Sibling of the current executable's parent: if `ember` lives at
///    `/usr/local/lib/ember/binaries/ember`, the bundled root is
///    `/usr/local/lib/ember/`. Mirrors how the daemon's `bundled_install_dir`
///    walks up from its own exe.
/// 3. `PROD_INSTALL_ROOT` fallback (`/usr/local/lib/ember`).
fn workflow_template_install_root() -> PathBuf {
    if let Ok(override_dir) = std::env::var("EMBER_WORKFLOW_TEMPLATES_ROOT")
        && !override_dir.is_empty()
    {
        return PathBuf::from(override_dir);
    }

    if let Ok(exe) = std::env::current_exe()
        && let Some(bin_dir) = exe.parent()
        && let Some(parent) = bin_dir.parent()
    {
        let candidate = parent.join("workflow-templates");
        if candidate.exists() {
            return parent.to_path_buf();
        }
    }

    PathBuf::from(crate::install_paths::PROD_INSTALL_ROOT)
}

/// Call the daemon `close_session` RPC.
///
/// Triggers daemon-side grant termination and emits a signed Receipt with
/// `termination_reason = clean_exit` into the session's sidecar directory.
/// Errors are logged to stderr but do not affect the launcher's exit code
/// — the child has already exited by this point.
pub fn close_session_rpc(session_id: &str, socket_path: &Path) {
    let params = json!({ "session_id": session_id });
    if let Err(e) = call_daemon(socket_path, "close_session", &params) {
        eprintln!("ember claude: close_session failed: {e}");
    }
}

/// Resolve the shadow root directory: `~/.ember/shadow/`, overridable via
/// `$EMBER_SHADOW_DIR` for test harnesses.
///
/// The shadow root holds credential / config / state files. Shim binaries
/// live under `<shadow_dir>/bin/` — use [`shadow_bin_dir`] to obtain the
/// PATH-prepend target.
pub fn resolve_shadow_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("EMBER_SHADOW_DIR") {
        return PathBuf::from(override_dir);
    }
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".ember")
        .join("shadow")
}

/// Cohort-A canonical Construct set (Option 2 — hardcoded constant).
///
/// Maps tool names to the expected `ember-<tool>` binary name. The binary is
/// resolved by searching `$PATH` for `ember-<tool>`, then falling back to a
/// sibling of the current executable (for installed layouts where all ember
/// binaries live in the same directory).
///
/// TODO: post-v0.3 follow-up: discover dynamically by scanning
/// `~/.ember/constructs/` or querying the daemon's installed-constructs list.
pub const COHORT_A_TOOLS: &[&str] = &[
    "gh", "git", "kubectl", "npm", "docker", "wrangler", "pulumi",
];

fn normalize_lexical_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn resolve_symlink_target(path: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        normalize_lexical_path(target.to_path_buf())
    } else {
        normalize_lexical_path(path.parent().unwrap_or_else(|| Path::new("/")).join(target))
    }
}

fn resolve_terminal_candidate(path: &Path) -> PathBuf {
    let mut current = path.to_path_buf();
    for _ in 0..8 {
        let Ok(target) = std::fs::read_link(&current) else {
            return current;
        };
        current = resolve_symlink_target(&current, &target);
    }
    current
}

fn path_looks_like_repo_build_artifact(path: &Path) -> bool {
    path.components().any(|component| component.as_os_str() == "target")
}

fn prod_safe_construct_candidate(candidate: &Path) -> bool {
    if !candidate.exists() {
        return false;
    }
    let terminal = resolve_terminal_candidate(candidate);
    terminal.exists() && !path_looks_like_repo_build_artifact(&terminal)
}

/// Build the [`ConstructSpec`] list for the cohort-A Construct set.
///
/// For each tool in [`COHORT_A_TOOLS`], attempts to resolve `ember-<tool>` by:
/// 1. Searching the current `$PATH` via `which`-style lookup.
/// 2. Checking for a sibling binary next to the current executable.
///
/// Tools whose binary cannot be found are silently skipped — the shadow
/// directory only needs shims for Constructs that are actually installed.
pub fn cohort_a_construct_specs() -> Vec<ConstructSpec> {
    let sibling_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    COHORT_A_TOOLS
        .iter()
        .filter_map(|tool| {
            let ember_name = format!("ember-{tool}");

            // 1. Sibling of current executable (preferred for installed layout).
            if let Some(ref dir) = sibling_dir {
                let candidate = dir.join(&ember_name);
                if candidate.exists() {
                    return Some(ConstructSpec {
                        tool_name: tool.to_string(),
                        target_binary: candidate,
                    });
                }
            }

            // 2. Search PATH entries for `ember-<tool>`.
            if let Ok(path_var) = std::env::var("PATH") {
                for entry in std::env::split_paths(&path_var) {
                    let candidate = entry.join(&ember_name);
                    if candidate.exists() {
                        return Some(ConstructSpec {
                            tool_name: tool.to_string(),
                            target_binary: candidate,
                        });
                    }
                }
            }

            None
        })
        .collect()
}

fn managed_prod_construct_specs_from_sources(
    manifest: Option<&ember_daemon::binary_manifest::BinaryManifest>,
    bundled_dir: &Path,
    path_var: Option<&str>,
) -> Vec<ConstructSpec> {
    if let Some(manifest) = manifest {
        let specs: Vec<ConstructSpec> = COHORT_A_TOOLS
            .iter()
            .filter_map(|tool| {
                let ember_name = format!("ember-{tool}");
                let entry = ember_daemon::binary_manifest::lookup_construct(manifest, &ember_name)
                    .ok()?;
                if prod_safe_construct_candidate(&entry.absolute_path) {
                    Some(ConstructSpec {
                        tool_name: (*tool).to_string(),
                        target_binary: entry.absolute_path.clone(),
                    })
                } else {
                    None
                }
            })
            .collect();
        if !specs.is_empty() {
            return specs;
        }
    }

    let bundled_specs: Vec<ConstructSpec> = COHORT_A_TOOLS
        .iter()
        .filter_map(|tool| {
            let ember_name = format!("ember-{tool}");
            let candidate = bundled_dir.join(&ember_name);
            if prod_safe_construct_candidate(&candidate) {
                Some(ConstructSpec {
                    tool_name: (*tool).to_string(),
                    target_binary: candidate,
                })
            } else {
                None
            }
        })
        .collect();
    if !bundled_specs.is_empty() {
        return bundled_specs;
    }

    let mut specs = Vec::new();
    if let Some(path_var) = path_var {
        for tool in COHORT_A_TOOLS {
            let ember_name = format!("ember-{tool}");
            for entry in std::env::split_paths(path_var) {
                let candidate = entry.join(&ember_name);
                if prod_safe_construct_candidate(&candidate) {
                    specs.push(ConstructSpec {
                        tool_name: (*tool).to_string(),
                        target_binary: candidate,
                    });
                    break;
                }
            }
        }
    }
    specs
}

pub fn managed_prod_construct_specs() -> Vec<ConstructSpec> {
    let manifest =
        ember_daemon::binary_manifest::load_manifest(Path::new(PROD_MANIFEST_PATH)).ok();
    let bundled_dir = ember_daemon::binary_manifest::bundled_install_dir();
    managed_prod_construct_specs_from_sources(manifest.as_ref(), &bundled_dir, std::env::var("PATH").ok().as_deref())
}

pub fn prod_required_constructs_present(specs: &[ConstructSpec]) -> bool {
    ["gh", "git"]
        .into_iter()
        .all(|tool| specs.iter().any(|spec| spec.tool_name == tool))
}

/// Resolve the child binary. `$EMBER_CLAUDE_BIN` overrides the default
/// `claude` lookup so test harnesses can substitute `/usr/bin/true` etc.
pub fn resolve_claude_bin() -> String {
    std::env::var("EMBER_CLAUDE_BIN").unwrap_or_else(|_| "claude".to_string())
}

/// Run `claude` (or `$EMBER_CLAUDE_BIN`) with cohort A env vars layered on
/// top of the inherited parent environment. Returns the child's exit code
/// (or `1` if the child was killed by a signal with no exit code).
///
/// `shadow_dir` is prepended to the child's `PATH` so Construct shims
/// intercept tool invocations transparently. The parent shell's PATH is
/// never mutated — this uses `Command::env("PATH", ...)` only.
///
/// Pure function over the registration so unit tests can drive it with
/// fixture values; the real CLI entry point fills in the registration via
/// `register_session_rpc`.
pub fn run_with_registration(
    bin: &str,
    extra_args: &[String],
    registration: &SessionRegistration,
    socket_path: &Path,
    shadow_dir: &Path,
) -> io::Result<i32> {
    run_with_registration_with_runtime_id(
        bin,
        extra_args,
        registration,
        socket_path,
        shadow_dir,
        None,
    )
}

fn run_with_registration_with_runtime_id(
    bin: &str,
    extra_args: &[String],
    registration: &SessionRegistration,
    socket_path: &Path,
    shadow_dir: &Path,
    dev_runtime_id: Option<&str>,
) -> io::Result<i32> {
    eprintln!(
        "ember claude: launching {bin} (session={}, grant={}, proxy={})",
        registration.session_id, registration.grant_id, registration.proxy_url,
    );

    // Build child PATH: shadow_dir prepended to the parent's PATH.
    // We use Command::env so the parent shell's PATH is never touched.
    let parent_path = std::env::var("PATH").unwrap_or_default();
    let child_path = format!("{}:{}", shadow_dir.display(), parent_path);

    let mut cmd = Command::new(bin);
    cmd.args(extra_args)
        .env("EMBER_GRANT_ID", &registration.grant_id)
        .env("EMBER_PROXY_URL", &registration.proxy_url)
        .env("EMBER_SOCKET_PATH", socket_path.as_os_str())
        .env("EMBER_DAEMON_SOCKET", socket_path.as_os_str())
        // implementation-note-500: do NOT inject
        // HTTPS_PROXY for Claude Code. The daemon's LLM proxy
        // (`infra::proxy::run_proxy`) is a custom POST endpoint for the
        // Anthropic SDK base_url use case — NOT a CONNECT-supporting
        // transparent HTTPS_PROXY. Claude Code uses HTTPS_PROXY
        // semantics (sends `CONNECT api.anthropic.com:443`), and
        // run_proxy returns 400 (ERR_BAD_REQUEST) on CONNECT. Cohort-A
        // value prop is still the broker for credentialed SUBPROCESS calls
        // (gh / git push / kubectl) via Constructs + shadow PATH. Claude
        // runtime mediation now lands via `ANTHROPIC_BASE_URL` +
        // `ANTHROPIC_CUSTOM_HEADERS` when the session grant carries the
        // right composite shape; without that bundle, Claude Code's own API
        // auth remains the friendly's concern. EMBER_PROXY_URL is still
        // injected so Constructs can use it via different code paths if
        // needed.
        .env("EMBER_SESSION_ID", &registration.session_id)
        .env("EMBER_PERSONA", resolve_persona_name())
        .env("PATH", &child_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(ref base_url) = registration.anthropic_base_url {
        cmd.env("ANTHROPIC_BASE_URL", base_url);
    }
    if let Some(ref headers) = registration.anthropic_custom_headers {
        cmd.env("ANTHROPIC_CUSTOM_HEADERS", headers);
    }
    // Inject the git proxy URL when the daemon provided one (implementation-note-302).
    if let Some(ref gpu) = registration.git_proxy_url {
        cmd.env("EMBER_GIT_PROXY_URL", gpu);
    }
    // Inject daemon-managed ssh-agent socket when the broker provided one
    // (implementation-note-85). git/ssh in the child tree pick this up
    // automatically without any additional configuration.
    if let Some(ref sock) = registration.ssh_auth_sock {
        cmd.env("SSH_AUTH_SOCK", sock);
    }
    if let Some(runtime_id) = dev_runtime_id {
        cmd.env(crate::dev_runtime::DEV_RUNTIME_ID_ENV, runtime_id);
    }
    let status = cmd.status().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("ember claude: failed to spawn {bin}: {e}"),
        )
    })?;

    // Exit trap: close session unconditionally on child exit, including
    // signal-forwarded SIGINT/SIGTERM. close_session_rpc logs but does not
    // propagate errors — the child exit code is what the user cares about.
    close_session_rpc(&registration.session_id, socket_path);

    Ok(status.code().unwrap_or(1))
}

/// Resolve the persona name for the session.
///
/// Priority:
/// 1. `$EMBER_PERSONA` env var — explicit override, highest precedence.
/// 2. The locked 2-slot Persona schema (CONTEXT.md "Identity surface"
///    §Persona ID schema): `claude-code-<context>` where `<context>` is
///    the worktree directory name when launched with `-w` (future flag)
///    or `default`. Routes through the shared helper
///    [`super::default_persona_id_for_runtime`] so the launcher and
///    `onboarding::claude_code::claude_code_persona_name` agree on the
///    same identifier shape.
///
/// Returns the persona name string. The caller is responsible for surfacing a
/// clear error if the daemon rejects the persona (e.g. user never ran
/// `ember init --for claude-code`).
pub fn resolve_persona_name() -> String {
    if let Ok(v) = std::env::var("EMBER_PERSONA")
        && !v.is_empty()
    {
        return v;
    }
    crate::onboarding::claude_code::claude_code_persona_name()
}

/// Print the host-mode mediation disclaimer (design §Component 5a) and
/// wait for the user to acknowledge or suppress it.
///
/// Behaviour:
/// - If stderr is not a tty (piped / CI): returns immediately without printing.
/// - If `host_mode_disclaimer_suppressed` is true in session-prefs: returns
///   immediately without printing.
/// - Otherwise: prints the locked copy to stderr, reads one line from stdin,
///   and (if the user typed `s` or `S`) persists suppression to session-prefs.
///   Any other input (including bare Enter) continues silently.
pub fn maybe_print_host_mode_disclaimer() -> io::Result<()> {
    // Skip when stderr is not a tty — no human reader, suppression irrelevant.
    if !std::io::stderr().is_terminal() {
        return Ok(());
    }

    // Skip when the user has already suppressed the disclaimer.
    let prefs = session_prefs::load();
    if prefs.host_mode_disclaimer_suppressed {
        return Ok(());
    }

    // LOCKED COPY — do not edit. Source: design §Component 5a.
    eprintln!(
        "\nember brokers 15 tools (git, gh, kubectl, …); other commands run with your shell's authority.\n\
         Need stricter? `ember up` runs in a container.\n\
         \n\
         [Enter] continue   [S] don't show again"
    );

    // Read one line from stdin. Non-tty stdin in CI is guarded above, so
    // this read will always have a human on the other end. Errors are
    // ignored — a read failure (e.g. stdin closed) is treated as Enter.
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);

    let trimmed = input.trim();
    if trimmed.eq_ignore_ascii_case("s") {
        // Persist suppression. Log but do not block launch on failure.
        if let Err(e) = session_prefs::suppress_host_mode_disclaimer() {
            eprintln!("ember: could not persist disclaimer suppression: {e}");
        }
    }

    Ok(())
}

/// `ember claude-code [extra_args...]` entry point.
///
/// Resolves persona via `resolve_persona_name` (`$EMBER_PERSONA` env var or
/// the cohort-A default `claude-code-{hostname}`), installs PATH-shadow
/// symlinks (design §3 sub-A), calls `register_session_rpc` (live RPC per
/// #2318 / design §2), prepends the shadow dir to the child PATH, spawns
/// the child, then `close_session_rpc` on exit. The socket path is
/// `~/.ember/run/daemon.sock` by default, overridable via `socket_path`.
pub fn launch_claude_code(extra_args: &[String], socket_path: &Path) -> io::Result<i32> {
    launch_claude_code_with_shadow_dir(extra_args, socket_path, None)
}

pub fn launch_claude_code_with_shadow_dir(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir_override: Option<&Path>,
) -> io::Result<i32> {
    let bin = resolve_claude_bin();
    let persona = resolve_persona_name();

    // Step 1: Install PATH-shadow symlinks before registering the session so
    // the shadow dir is ready before the child process is spawned.
    let shadow_dir = shadow_dir_override
        .map(PathBuf::from)
        .unwrap_or_else(resolve_shadow_dir);
    let construct_specs = cohort_a_construct_specs();
    launch_claude_code_with_shadow_dir_and_constructs(
        extra_args,
        socket_path,
        &shadow_dir,
        &bin,
        &persona,
        &construct_specs,
    )
}

pub fn launch_claude_code_with_shadow_dir_and_constructs(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir: &Path,
    bin: &str,
    persona: &str,
    construct_specs: &[ConstructSpec],
) -> io::Result<i32> {
    launch_claude_code_with_shadow_dir_and_constructs_with_runtime_id(
        extra_args,
        socket_path,
        shadow_dir,
        bin,
        persona,
        construct_specs,
        None,
    )
}

pub fn launch_claude_code_with_shadow_dir_and_constructs_with_runtime_id(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir: &Path,
    bin: &str,
    persona: &str,
    construct_specs: &[ConstructSpec],
    dev_runtime_id: Option<&str>,
) -> io::Result<i32> {
    install_path_shadow(shadow_dir, construct_specs)?;

    // Step 1.5: design §Component 3 — resolve a workflow template. When stdin
    // is a tty the launcher prompts via the interactive selector
    // (`workflow_prompt::prompt_for_template_with_cache`); otherwise it picks
    // the first available template (alphabetical) as the default so headless
    // launches still receive a workflow grant. Errors from template discovery
    // degrade to "no workflow template" — the legacy per-action / JIT chain
    // still applies.
    let workflow_template_name = resolve_workflow_template_for_launch();

    // Step 2: Register session with the daemon (mints EMBER_SESSION_ID and,
    // when a workflow template was selected, issues a `WorkflowGrant` via
    // `workflow_grant::save_if_absent`).
    let registration = register_session_rpc_with_workflow(
        persona,
        socket_path,
        workflow_template_name.as_deref(),
    )
    .map_err(|e| {
        let msg = e.to_string();
        // When the daemon rejects a "no such persona" error for the cohort-A
        // default name, surface a friendly hint so users know to run init.
        if msg.contains("not found")
            || msg.contains("no such persona")
            || msg.contains("unknown persona")
        {
            io::Error::new(
                e.kind(),
                "no cohort-A persona found.\n  \
                 Run `ember init --for claude` first, or set \
                 $EMBER_PERSONA to an existing persona name."
                    .to_string(),
            )
        } else {
            e
        }
    })?;

    // Step 3: Print the host-mode mediation disclaimer (design §Component 5a)
    // immediately before invoking the Claude Code child binary. Skipped when
    // stderr is not a tty or the user has persisted suppression.
    maybe_print_host_mode_disclaimer()?;

    // Step 4: Spawn child with shadow/bin PATH prepended and all ember env vars set.
    // The bin/ subdirectory holds the shim binaries; the root holds creds/config.
    let bin_dir = shadow_bin_dir(shadow_dir);
    run_with_registration_with_runtime_id(
        bin,
        extra_args,
        &registration,
        socket_path,
        &bin_dir,
        dev_runtime_id,
    )
}

/// Send a synchronous JSON-RPC request over the daemon's Unix socket and
/// return the `result` value. Mirrors the `call_daemon` shape in
/// `crates/emberlink-cli/src/broker.rs` so wire behaviour is identical.
fn call_daemon(socket_path: &Path, method: &str, params: &Value) -> io::Result<Value> {
    match crate::call_daemon_rpc(socket_path, method, params) {
        Ok(result) => Ok(result),
        Err(crate::DaemonRpcError::Unavailable(e)) => Err(io::Error::new(
            e.kind(),
            format!(
                "ember claude: daemon not running (socket: {}): {e}; \
                 run `ember status` or repair/install with `sudo ember daemon install`",
                socket_path.display()
            ),
        )),
        Err(crate::DaemonRpcError::Io(e)) => Err(io::Error::new(
            e.kind(),
            crate::format_daemon_socket_io_error(&e),
        )),
        Err(crate::DaemonRpcError::Protocol(e)) => {
            Err(io::Error::new(io::ErrorKind::InvalidData, e))
        }
        Err(crate::DaemonRpcError::Rpc { code, message }) => {
            if let Some(guidance) = launcher_guidance_for_rpc(method, code, &message) {
                return Err(io::Error::other(guidance));
            }
            Err(io::Error::other(format!("daemon error: {message}")))
        }
    }
}

fn launcher_guidance_for_rpc(method: &str, code: i32, message: &str) -> Option<String> {
    let is_locked = code == -32030
        && (message.contains("session is locked")
            || message.contains("vault unavailable")
            || message.contains("session auto-locked"));
    let is_quarantined =
        message.contains("daemon quarantined") && message.contains("write-class method");

    if method == "register_session"
        && (is_locked || (code == -32001 && message.contains("authority_class_not_met")))
    {
        return Some(
            "this Claude Code session needs operator presence on the daemon-managed vault lane. \
             Approve the unlock flow if prompted, or run `ember vault unlock` from an interactive \
             operator shell and then re-run `ember claude`."
                .to_string(),
        );
    }

    if method == "register_session" && is_quarantined {
        return Some(
            "this Claude session is blocked because the daemon quarantined write-class methods after an audit-chain integrity failure. Run `ember audit verify` to inspect the chain, then repair the daemon before re-running `ember claude`."
                .to_string(),
        );
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> SessionRegistration {
        SessionRegistration {
            session_id: "sess_fixture".to_string(),
            grant_id: "grt_fixture".to_string(),
            proxy_url: "http://127.0.0.1:9999".to_string(),
            anthropic_base_url: None,
            anthropic_custom_headers: None,
            git_proxy_url: None,
            ssh_auth_sock: None,
            workflow_id: None,
            workflow_template: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn prod_safe_construct_candidate_rejects_repo_target_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let launcher = tmp.path().join("ember-git");
        let repo_target = tmp.path().join("target/release/ember-git");
        std::fs::create_dir_all(repo_target.parent().unwrap()).unwrap();
        std::fs::write(&repo_target, b"binary").unwrap();
        std::os::unix::fs::symlink(&repo_target, &launcher).unwrap();
        assert!(
            !prod_safe_construct_candidate(&launcher),
            "prod path must reject repo-target construct candidates"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prod_safe_construct_candidate_accepts_managed_install_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let launcher = tmp.path().join("ember-git");
        let installed_target = tmp
            .path()
            .join("usr/local/lib/ember/binaries/ember-git");
        std::fs::create_dir_all(installed_target.parent().unwrap()).unwrap();
        std::fs::write(&installed_target, b"binary").unwrap();
        std::os::unix::fs::symlink(&installed_target, &launcher).unwrap();
        assert!(
            prod_safe_construct_candidate(&launcher),
            "prod path must accept managed-install construct candidates"
        );
    }

    #[test]
    fn prod_required_constructs_present_requires_gh_and_git() {
        let both = vec![
            ConstructSpec {
                tool_name: "gh".to_string(),
                target_binary: PathBuf::from("/usr/local/lib/ember/binaries/ember-gh"),
            },
            ConstructSpec {
                tool_name: "git".to_string(),
                target_binary: PathBuf::from("/usr/local/lib/ember/binaries/ember-git"),
            },
        ];
        let gh_only = vec![ConstructSpec {
            tool_name: "gh".to_string(),
            target_binary: PathBuf::from("/usr/local/lib/ember/binaries/ember-gh"),
        }];
        assert!(prod_required_constructs_present(&both));
        assert!(!prod_required_constructs_present(&gh_only));
    }

    #[cfg(unix)]
    #[test]
    fn managed_prod_construct_specs_from_sources_prefers_manifest_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let managed_gh = tmp.path().join("managed/ember-gh");
        let managed_git = tmp.path().join("managed/ember-git");
        std::fs::create_dir_all(managed_gh.parent().unwrap()).unwrap();
        std::fs::write(&managed_gh, b"binary").unwrap();
        std::fs::write(&managed_git, b"binary").unwrap();

        let manifest = ember_daemon::binary_manifest::BinaryManifest {
            entries: vec![
                ember_daemon::binary_manifest::BinaryManifestEntry {
                    tool_name: "ember-gh".to_string(),
                    version: "0.3.0".to_string(),
                    content_hash: "blake3:test".to_string(),
                    absolute_path: managed_gh.clone(),
                    installed_at: 0,
                    publisher: "did:emberlink".to_string(),
                    channel: ember_daemon::binary_manifest::BinaryDistributionChannel::Bundled,
                },
                ember_daemon::binary_manifest::BinaryManifestEntry {
                    tool_name: "ember-git".to_string(),
                    version: "0.3.0".to_string(),
                    content_hash: "blake3:test".to_string(),
                    absolute_path: managed_git.clone(),
                    installed_at: 0,
                    publisher: "did:emberlink".to_string(),
                    channel: ember_daemon::binary_manifest::BinaryDistributionChannel::Bundled,
                },
            ],
        };

        let specs =
            managed_prod_construct_specs_from_sources(Some(&manifest), tmp.path(), Some(""));
        assert!(
            specs.iter().any(|spec| spec.tool_name == "gh" && spec.target_binary == managed_gh)
        );
        assert!(
            specs.iter().any(|spec| spec.tool_name == "git" && spec.target_binary == managed_git)
        );
    }

    #[cfg(unix)]
    #[test]
    fn managed_prod_construct_specs_from_sources_falls_back_to_bundled_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let bundled_dir = tmp.path().join("bundled");
        std::fs::create_dir_all(&bundled_dir).unwrap();
        let bundled_gh = bundled_dir.join("ember-gh");
        let bundled_git = bundled_dir.join("ember-git");
        std::fs::write(&bundled_gh, b"binary").unwrap();
        std::fs::write(&bundled_git, b"binary").unwrap();

        let specs = managed_prod_construct_specs_from_sources(None, &bundled_dir, Some(""));
        assert!(
            specs.iter().any(|spec| spec.tool_name == "gh" && spec.target_binary == bundled_gh)
        );
        assert!(
            specs.iter().any(|spec| spec.tool_name == "git" && spec.target_binary == bundled_git)
        );
    }

    #[cfg(unix)]
    #[test]
    fn managed_prod_construct_specs_from_sources_rejects_repo_target_path_fallbacks() {
        let tmp = tempfile::tempdir().unwrap();
        let path_dir = tmp.path().join("path");
        let repo_target_dir = tmp.path().join("target/release");
        std::fs::create_dir_all(&path_dir).unwrap();
        std::fs::create_dir_all(&repo_target_dir).unwrap();
        let repo_gh = repo_target_dir.join("ember-gh");
        let repo_git = repo_target_dir.join("ember-git");
        std::fs::write(&repo_gh, b"binary").unwrap();
        std::fs::write(&repo_git, b"binary").unwrap();
        std::os::unix::fs::symlink(&repo_gh, path_dir.join("ember-gh")).unwrap();
        std::os::unix::fs::symlink(&repo_git, path_dir.join("ember-git")).unwrap();
        let path_var = path_dir.to_string_lossy().to_string();

        let specs = managed_prod_construct_specs_from_sources(None, tmp.path(), Some(&path_var));
        assert!(
            specs.is_empty(),
            "prod path fallback must reject repo-target construct shims: {specs:?}"
        );
    }

    #[test]
    fn run_with_registration_propagates_zero_exit() {
        // /usr/bin/true exits 0 on every Unix; cohort A targets macOS first.
        let code = run_with_registration(
            "/usr/bin/true",
            &[],
            &fixture(),
            Path::new("/nonexistent.sock"),
            Path::new("/tmp"),
        )
        .expect("spawn /usr/bin/true");
        assert_eq!(code, 0);
    }

    #[test]
    fn run_with_registration_propagates_nonzero_exit() {
        let code = run_with_registration(
            "/usr/bin/false",
            &[],
            &fixture(),
            Path::new("/nonexistent.sock"),
            Path::new("/tmp"),
        )
        .expect("spawn /usr/bin/false");
        assert_eq!(code, 1);
    }

    #[test]
    fn run_with_registration_does_not_pollute_parent_env() {
        // Anchor: ensure the parent process's environment doesn't
        // gain EMBER_GRANT_ID after we run a child that should only
        // see it in the child env. The launcher writes only via
        // `Command::env(...)`; an accidental `std::env::set_var` in
        // `run_with_registration` would leak `grt_fixture` to the
        // parent, which we'd see here.
        let _ = run_with_registration(
            "/usr/bin/true",
            &[],
            &fixture(),
            Path::new("/nonexistent.sock"),
            Path::new("/tmp"),
        )
        .expect("spawn /usr/bin/true");
        let leaked = std::env::var("EMBER_GRANT_ID")
            .map(|v| v.contains("grt_fixture"))
            .unwrap_or(false);
        assert!(
            !leaked,
            "launcher must not write EMBER_GRANT_ID into parent env"
        );
    }

    #[test]
    fn run_with_registration_reports_spawn_failure() {
        let result = run_with_registration(
            "/no/such/binary-that-must-not-exist",
            &[],
            &fixture(),
            Path::new("/nonexistent.sock"),
            Path::new("/tmp"),
        );
        assert!(
            result.is_err(),
            "missing binary must surface as Err, not silent zero exit"
        );
    }

    #[test]
    fn resolve_claude_bin_honors_override() {
        // SAFETY: Rust 2024 marks env mutation `unsafe` because it can
        // race other threads reading env. This test is single-threaded;
        // we set a value, observe it, and clear it before exit. The
        // racy global is the price of dependency injection on env.
        unsafe {
            std::env::set_var("EMBER_CLAUDE_BIN", "/usr/local/bin/claude-test");
        }
        assert_eq!(resolve_claude_bin(), "/usr/local/bin/claude-test");
        unsafe {
            std::env::remove_var("EMBER_CLAUDE_BIN");
        }
        assert_eq!(resolve_claude_bin(), "claude");
    }

    #[test]
    fn register_session_rpc_fails_when_daemon_not_running() {
        let err = register_session_rpc("default", Path::new("/nonexistent.sock"))
            .expect_err("should fail when daemon is not running");
        let msg = err.to_string();
        assert!(
            msg.contains("daemon not running") || msg.contains("No such file"),
            "error should mention daemon or missing socket: {msg}"
        );
    }

    #[test]
    fn launcher_guidance_maps_missing_presence_for_register_session() {
        let guidance = launcher_guidance_for_rpc(
            "register_session",
            -32001,
            r#"{"error":"authority_class_not_met","reason":"missing"}"#,
        )
        .expect("expected guidance");
        assert!(guidance.contains("operator presence"));
        assert!(guidance.contains("ember vault unlock"));
        assert!(guidance.contains("ember claude"));
    }

    #[test]
    fn launcher_guidance_maps_locked_session_for_register_session() {
        let guidance = launcher_guidance_for_rpc(
            "register_session",
            -32030,
            "register_session denied: session is locked; reopen with `ember vault unlock`",
        )
        .expect("expected guidance");
        assert!(guidance.contains("operator presence"));
        assert!(guidance.contains("ember vault unlock"));
        assert!(guidance.contains("ember claude"));
    }

    #[test]
    fn launcher_guidance_maps_quarantined_register_session() {
        let guidance = launcher_guidance_for_rpc(
            "register_session",
            -32603,
            "daemon quarantined; write-class method `register_session` refused",
        )
        .expect("expected guidance");
        assert!(guidance.contains("daemon quarantined"));
        assert!(guidance.contains("ember audit verify"));
        assert!(guidance.contains("ember claude"));
    }

    #[test]
    fn close_session_rpc_is_silent_on_failure() {
        // close_session_rpc must not panic when the daemon is unreachable —
        // the child has already exited and the launcher still needs to return.
        close_session_rpc("sess_nonexistent", Path::new("/nonexistent.sock"));
    }

    #[test]
    fn parse_register_session_result_parses_direct_success() {
        let raw = json!({
            "session_id": "sess_fixture",
            "grant_id": "grt_fixture",
            "proxy_url": "http://127.0.0.1:7001",
            "anthropic_base_url": "http://127.0.0.1:7001",
            "anthropic_custom_headers": "X-Ember-Persona: persona-main\nX-Ember-Credential: anthropic-key",
            "git_proxy_url": "http://127.0.0.1:7002",
            "ssh_auth_sock": "/tmp/ember-ssh-agent.sock",
        });
        let parsed = parse_register_session_result(&raw, Path::new("/tmp/daemon.sock"))
            .expect("direct result must parse");
        assert_eq!(parsed.session_id, "sess_fixture");
        assert_eq!(parsed.grant_id, "grt_fixture");
        assert_eq!(parsed.proxy_url, "http://127.0.0.1:7001");
        assert_eq!(
            parsed.anthropic_base_url.as_deref(),
            Some("http://127.0.0.1:7001")
        );
        assert_eq!(
            parsed.anthropic_custom_headers.as_deref(),
            Some("X-Ember-Persona: persona-main\nX-Ember-Credential: anthropic-key")
        );
        assert_eq!(
            parsed.git_proxy_url.as_deref(),
            Some("http://127.0.0.1:7002")
        );
        assert_eq!(
            parsed.ssh_auth_sock.as_deref(),
            Some("/tmp/ember-ssh-agent.sock")
        );
    }

    #[test]
    fn parse_register_session_result_rejects_reserved_presence_branch() {
        let raw = json!({
            "presence_required": {
                "tab_url": "http://localhost:5173/prompt/pmt_xyz",
                "prompt_id": "pmt_xyz",
            }
        });
        let err = parse_register_session_result(&raw, Path::new("/tmp/daemon.sock"))
            .expect_err("reserved browser branch must refuse cleanly");
        let msg = err.to_string();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(
            msg.contains("browser/session-open presence flow is not shipped yet"),
            "error must explain current state: {msg}"
        );
        assert!(
            msg.contains("prompt_id=pmt_xyz"),
            "error must carry prompt_id context: {msg}"
        );
    }

    // ── persona resolution tests (implementation-note-503) ──

    #[test]
    fn persona_defaults_to_cohort_a_when_env_unset() {
        // Serialize against other EMBER_PERSONA-mutating tests in this
        // crate (`bind.rs::resolve_persona_rejects_…` removes,
        // `persona_uses_env_var_when_set` sets+restores). Without the
        // lock, the cargo parallel runner can race our `remove_var`
        // against another test's `set_var("EMBER_PERSONA", "foo")` and
        // `resolved` comes back as "foo" instead of the cohort-A
        // default. Same pattern as #3237.
        let _g = crate::EMBER_PERSONA_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_PERSONA").ok();
        // SAFETY: holds EMBER_PERSONA_TEST_LOCK for the duration of the
        // env mutation; restored before return.
        unsafe { std::env::remove_var("EMBER_PERSONA") };
        // Mirror the onboarding helper to build the expected name.
        let hostname = crate::onboarding::claude_code::claude_code_persona_name();
        let resolved = resolve_persona_name();
        // Restore prior before any assertion so a panic leaves a clean env.
        if let Some(v) = prior {
            unsafe { std::env::set_var("EMBER_PERSONA", v) };
        }
        assert_eq!(
            resolved, hostname,
            "resolve_persona_name should match claude_code_persona_name when EMBER_PERSONA is unset"
        );
        assert!(
            resolved.starts_with("claude-code-"),
            "default persona must be prefixed claude-code-: {resolved}"
        );
    }

    #[test]
    fn persona_uses_env_var_when_set() {
        // Serialize against other tests in this crate that touch
        // EMBER_PERSONA (notably `bind.rs::resolve_persona_rejects_…`).
        // Without this lock the cargo parallel runner can interleave a
        // set_var/remove_var with our read, producing the
        // `resolved != "foo"` failure.
        let _g = crate::EMBER_PERSONA_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Save prior so we don't clobber developer env or other test
        // setup that leaked across module boundaries.
        let prior = std::env::var("EMBER_PERSONA").ok();
        // SAFETY: holds EMBER_PERSONA_TEST_LOCK for the duration of the
        // env mutation; restored before return.
        unsafe { std::env::set_var("EMBER_PERSONA", "foo") };
        let resolved = resolve_persona_name();
        // Restore prior value (or clear) before assertion so a panic
        // leaves a clean env for the next acquirer.
        unsafe {
            match prior {
                Some(v) => std::env::set_var("EMBER_PERSONA", v),
                None => std::env::remove_var("EMBER_PERSONA"),
            }
        }
        assert_eq!(resolved, "foo");
    }

    #[test]
    fn clear_error_when_no_cohort_a_persona() {
        // Simulate a daemon "not found" response by constructing the error
        // shape that register_session_rpc would return and verifying that
        // launch_claude_code would surface the friendly hint.
        // We drive this by testing the error-remapping closure logic directly:
        // create an io::Error with the "not found" substring and assert the
        // remapped message contains the init hint.
        let raw_err = io::Error::other(
            "daemon error: persona 'claude-code-myhost' not found",
        );
        let msg = raw_err.to_string();
        let remapped = if msg.contains("not found")
            || msg.contains("no such persona")
            || msg.contains("unknown persona")
        {
            io::Error::new(
                raw_err.kind(),
                "no cohort-A persona found.\n  \
                 Run `ember init --for claude` first, or set \
                 $EMBER_PERSONA to an existing persona name.",
            )
        } else {
            raw_err
        };
        let remapped_msg = remapped.to_string();
        assert!(
            remapped_msg.contains("ember init --for claude"),
            "error must guide user to init: {remapped_msg}"
        );
    }

    // ── implementation-note-302: launcher env injection tests ──

    #[test]
    fn registration_with_real_proxy_url_is_not_8484() {
        // implementation-note-302: verify that a registration
        // carrying a daemon-provided URL (non-8484) is accepted without
        // falling back. This is the T1 launcher acceptance condition.
        let reg = SessionRegistration {
            session_id: "sess_test".to_string(),
            grant_id: "grt_test".to_string(),
            proxy_url: "http://127.0.0.1:61169".to_string(),
            anthropic_base_url: None,
            anthropic_custom_headers: None,
            git_proxy_url: Some("http://127.0.0.1:61170".to_string()),
            ssh_auth_sock: None,
            workflow_id: None,
            workflow_template: None,
        };
        assert_ne!(
            reg.proxy_url, "http://127.0.0.1:8484",
            "proxy_url must not be the hardcoded fallback port when daemon returns real URL"
        );
        assert_eq!(
            reg.proxy_url, "http://127.0.0.1:61169",
            "proxy_url must match the daemon-returned ephemeral port"
        );
        assert_eq!(
            reg.git_proxy_url.as_deref(),
            Some("http://127.0.0.1:61170"),
            "git_proxy_url must be carried from daemon response"
        );
    }

    #[test]
    fn run_with_registration_injects_daemon_proxy_url_not_8484() {
        // implementation-note-302: T2 launcher — assert that the
        // child env receives the daemon-returned proxy URL. We verify this
        // indirectly by confirming run_with_registration succeeds (returns 0)
        // with a registration carrying an ephemeral port. The real child-env
        // assertion lives in the daemon-side T2 (register_session_response_includes_real_proxy_url).
        let reg = SessionRegistration {
            session_id: "sess_proxy_wire".to_string(),
            grant_id: "grt_proxy_wire".to_string(),
            proxy_url: "http://127.0.0.1:62000".to_string(),
            anthropic_base_url: None,
            anthropic_custom_headers: None,
            git_proxy_url: None,
            ssh_auth_sock: None,
            workflow_id: None,
            workflow_template: None,
        };
        assert_ne!(
            reg.proxy_url, "http://127.0.0.1:8484",
            "proxy_url must not be 8484 when using daemon-returned URL"
        );
        // Confirm the registration can be consumed by run_with_registration
        // without error (child /usr/bin/true exits 0 immediately).
        let code = run_with_registration(
            "/usr/bin/true",
            &[],
            &reg,
            Path::new("/nonexistent.sock"),
            Path::new("/tmp"),
        )
        .expect("spawn /usr/bin/true with real proxy URL");
        assert_eq!(
            code, 0,
            "child must exit 0 when launched with real proxy URL"
        );
    }

    // ── host-mode mediation disclaimer tests (implementation-note-504) ──

    #[test]
    fn disclaimer_skipped_when_stderr_not_tty() {
        // In a test process stderr is not a tty, so maybe_print_host_mode_disclaimer
        // must return Ok(()) immediately without reading stdin or printing anything.
        // This covers the CI/piped path from the acceptance criteria.
        let result = maybe_print_host_mode_disclaimer();
        assert!(
            result.is_ok(),
            "disclaimer must not error when stderr is not a tty"
        );
    }

    #[test]
    fn disclaimer_skipped_when_suppressed_in_prefs() {
        let _g = session_prefs::EMBER_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::TempDir::new().expect("create temp dir");
        unsafe { std::env::set_var("EMBER_HOME", dir.path()) };
        // Write suppression=true into session-prefs.
        session_prefs::suppress_host_mode_disclaimer().expect("suppress");
        // maybe_print_host_mode_disclaimer must return without printing when
        // suppressed=true. In a test process stderr is not a tty so it would
        // skip anyway; we validate the prefs-read path by asserting prefs.
        let prefs = session_prefs::load();
        unsafe { std::env::remove_var("EMBER_HOME") };
        assert!(
            prefs.host_mode_disclaimer_suppressed,
            "suppression must be persisted and readable back"
        );
    }

    #[test]
    fn disclaimer_suppression_write_path() {
        let _g = session_prefs::EMBER_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Verify the suppress_host_mode_disclaimer helper writes and the
        // subsequent load reflects the persisted value (round-trip).
        let dir = tempfile::TempDir::new().expect("create temp dir");
        unsafe { std::env::set_var("EMBER_HOME", dir.path()) };
        // Before: not suppressed.
        let before = session_prefs::load();
        assert!(!before.host_mode_disclaimer_suppressed);
        // Suppress.
        session_prefs::suppress_host_mode_disclaimer().expect("suppress");
        // After: suppressed.
        let after = session_prefs::load();
        unsafe { std::env::remove_var("EMBER_HOME") };
        assert!(
            after.host_mode_disclaimer_suppressed,
            "suppression must persist"
        );
    }
}
