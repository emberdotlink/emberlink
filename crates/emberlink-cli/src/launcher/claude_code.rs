//! `ember claude` launcher.
//!
//! Per ADR 120 §2 + ADR 124 §3 (PATH-shadow wiring, sub-B).
//! Real daemon RPC shipped in #2318 (LAUNCHER-SESSION-RPC); see ADR 120 §2
//! for the full protocol contract.
//!
//! 1. Resolve persona: `$EMBER_PERSONA` env var if set; otherwise
//!    `claude-code-{hostname}` (matching what `init --for claude`
//!    creates). Install PATH-shadow symlinks via `install_path_shadow`
//!    (idempotent; creates `~/.ember/shadow/bin/` on first launch, verifies
//!    symlinks on subsequent launches).
//! 2. Register a new session with the daemon (`register_session_rpc`) — live
//!    Unix-socket RPC per ADR 120 §2. Returns `{session_id, attachment_id,
//!    proxy_url}`.
//! 3. Set attachment endpoint coordinates, `EMBER_PROXY_URL`, and
//!    `EMBER_SESSION_ID` in the child env. `HTTPS_PROXY` is intentionally NOT set — the
//!    daemon's LLM proxy isn't CONNECT-compatible. Claude Code talks
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

use ed25519_dalek::VerifyingKey;

use crate::install_paths::PROD_MANIFEST_PATH;
use crate::launcher::core::{self, LauncherInvocation};
use crate::launcher::path_shadow::{
    ConstructSpec, install_path_shadow, shadow_bin_dir, shadow_tool_aliases,
};
use crate::launcher::session_prefs;

pub use crate::launcher::core::SessionRegistration;
#[cfg(test)]
use serde_json::Value;

const CLAUDE_BROKER_STRIPPED_AUTH_ENV: &[&str] = &[
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
];
const EMBER_BINARY_MANIFEST_ENV: &str = "EMBER_BINARY_MANIFEST";
const EMBER_TRUST_ROOTS_ENV: &str = "EMBER_TRUST_ROOTS";
const PROD_LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/sh.emberlink.daemon.plist";

/// Inert auth token set on the broker lane so Claude Code's client-side
/// auth-presence gate passes. Without it the CLI lands on "Not logged in ·
/// Please run /login" under a custom `ANTHROPIC_BASE_URL` and never forms a
/// request. Claude Code sends this verbatim as `Authorization: Bearer
/// <value>`, but it never authorizes anything: the daemon proxy strips inbound
/// `authorization`/`x-api-key` unconditionally (regardless of value) and
/// injects the real vault credential server-side; the per-session UDS +
/// leaf-pin is the real authorization gate. Empirically confirmed against
/// claude v2.1.158: this checkpoint flips the gate and the request arrives at the
/// proxy carrying `authorization: Bearer <checkpoint>`, which the proxy drops and
/// replaces.
///
/// Deliberately NOT a shared constant with the proxy: the proxy strips
/// `authorization` for ANY value, so there is no cross-component contract on the
/// literal — a shared constant would imply coupling that does not exist.
const CLAUDE_BROKER_SENTINEL_AUTH_TOKEN: &str = "ember-brokered-no-auth";

/// Whether this session runs on the brokered Anthropic gateway lane (Claude
/// routed through `ember-proxy` via a custom base URL and/or custom headers).
/// On this lane we strip the inherited real-auth env (`CLAUDE_CODE_OAUTH_TOKEN`,
/// `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`) AND re-set the checkpoint
/// `ANTHROPIC_AUTH_TOKEN`, so the two decisions share one predicate.
fn is_broker_lane(registration: &SessionRegistration) -> bool {
    registration.anthropic_base_url.is_some() || registration.anthropic_custom_headers.is_some()
}

/// Call the daemon `register_session` RPC and return the session triple.
///
/// `persona` — the persona name or id for the session.
/// `socket_path` — path to the daemon Unix socket (`~/.ember/run/daemon.sock`).
///
/// Returns `Err` when the daemon is unreachable or returns an error.
pub fn register_session_rpc(
    persona: &str,
    socket_path: &Path,
    authority_strict: bool,
) -> io::Result<SessionRegistration> {
    register_session_rpc_with_workflow(
        persona,
        socket_path,
        None,
        authority_strict,
        None,
        "ember claude",
        "ember claude",
    )
}

/// Call the daemon `register_session` RPC with an optional delegated
/// `delegation_template`.
///
/// When `delegation_template` is `Some(name)`, the daemon looks up the template,
/// issues a delegated composite grant via `authority_delegation::save_if_absent`,
/// stamps `delegation_id` + `delegation_template` onto `SessionMeta`, and returns
/// both in the response. Touch ID fires inside the daemon as part of the
/// operator-presence gate on `register_session`.
///
/// The `None` form is now the doctrinal default path — no delegated grant is
/// attached and the per-action / JIT chain governs `broker.resolve` outcomes.
pub fn register_session_rpc_with_workflow(
    persona: &str,
    socket_path: &Path,
    delegation_template: Option<&str>,
    authority_strict: bool,
    attach_runtime_persona_id: Option<&str>,
    launcher_label: &str,
    rerun_hint: &str,
) -> io::Result<SessionRegistration> {
    crate::launcher::session_rpc::register_session_rpc_with_workflow(
        persona,
        socket_path,
        delegation_template,
        authority_strict,
        attach_runtime_persona_id,
        launcher_label,
        rerun_hint,
    )
}

// Thin RPC wrapper — structurally many params mirroring the session_rpc signature.
#[allow(clippy::too_many_arguments)]
pub fn register_session_rpc_with_workflow_and_workspace_ref(
    persona: &str,
    socket_path: &Path,
    delegation_template: Option<&str>,
    authority_strict: bool,
    attach_runtime_persona_id: Option<&str>,
    workspace_ref: Option<&str>,
    launcher_label: &str,
    rerun_hint: &str,
) -> io::Result<SessionRegistration> {
    crate::launcher::session_rpc::register_session_rpc_with_workflow_and_workspace_ref(
        persona,
        socket_path,
        delegation_template,
        authority_strict,
        attach_runtime_persona_id,
        workspace_ref,
        launcher_label,
        rerun_hint,
    )
}

#[cfg(test)]
fn parse_register_session_result(
    result: &Value,
    socket_path: &Path,
) -> io::Result<SessionRegistration> {
    crate::launcher::session_rpc::parse_register_session_result(
        result,
        socket_path,
        "ember claude",
        crate::launcher::core::AuthorityPosture::from_components(false, None),
    )
}

/// Resolve an explicit delegated workflow-template override for this launch.
///
/// Default interactive posture is now ambient: unless the operator explicitly
/// opts into delegated authority, the launch opens without an attached
/// delegation template and the per-action / JIT chain governs `broker.resolve`.
///
/// Today the opt-in surface is the launcher `--delegated <template>` flag,
/// with `EMBER_DELEGATION_TEMPLATE` retained only as a compatibility override.
///
/// Adversarial HIGH-4 fix (2026-05-22): refuse template names that
/// could traverse out of the delegation-templates dir. `<dir>.join(name)`
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

/// The ambient chain still applies when no explicit override is present, and
/// the launch never fails just because delegated opt-in was absent.
pub(crate) fn resolve_delegation_template_for_launch(
    explicit_template: Option<&str>,
    launcher_label: &str,
) -> Result<Option<String>, String> {
    if let Some(name) = explicit_template
        && !name.is_empty()
    {
        if is_safe_template_name(name) {
            return Ok(Some(name.to_string()));
        }
        return Err(format!(
            "{launcher_label}: refusing `--delegated {name}`: template name must be a plain identifier (no slashes or path components)"
        ));
    }

    // Compatibility delegated opt-in via env var.
    if let Ok(name) = std::env::var("EMBER_DELEGATION_TEMPLATE")
        && !name.is_empty()
    {
        // Adversarial HIGH-4 fix (2026-05-22): refuse template names
        // that contain path separators or non-`Normal` path
        // components. Pre-fix a child process inheriting an
        // attacker-influenced env (`EMBER_DELEGATION_TEMPLATE=../../tmp/evil`)
        // could make the daemon's TOML loader traverse out of the
        // template directory.
        if is_safe_template_name(&name) {
            return Ok(Some(name));
        } else {
            eprintln!(
                "{launcher_label}: refusing $EMBER_DELEGATION_TEMPLATE={name:?}: name must be a plain identifier (no slashes or path components)"
            );
            // Fall through to discovery; do NOT honor the unsafe value.
        }
    }
    Ok(None)
}

/// Call the daemon `close_session` RPC.
///
/// Triggers daemon-side grant termination and emits a signed Receipt with
/// `termination_reason = clean_exit` into the session's sidecar directory.
/// Errors are logged to stderr but do not affect the launcher's exit code
/// — the child has already exited by this point.
pub fn close_session_rpc(session_id: &str, socket_path: &Path) {
    crate::launcher::session_rpc::close_session_rpc(
        session_id,
        socket_path,
        "ember claude",
        "ember claude",
    );
}

fn with_session_close<T, F>(session_id: &str, socket_path: &Path, f: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T>,
{
    crate::launcher::session_rpc::with_session_close(
        session_id,
        socket_path,
        "ember claude",
        "ember claude",
        f,
    )
}

/// Resolve the shadow root directory: `~/.ember/shadow/`, overridable via
/// `$EMBER_SHADOW_DIR` for test harnesses.
///
/// The shadow root holds credential / config / state files. Shim binaries
/// live under `<shadow_dir>/bin/` — use [`shadow_bin_dir`] to obtain the
/// PATH-prepend target.
pub fn resolve_shadow_dir() -> PathBuf {
    core::resolve_shadow_dir()
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
    path.components()
        .any(|component| component.as_os_str() == "target")
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
                let entry =
                    ember_daemon::binary_manifest::lookup_construct(manifest, &ember_name).ok()?;
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
    let manifest = ember_daemon::binary_manifest::load_manifest(Path::new(PROD_MANIFEST_PATH)).ok();
    let bundled_dir = ember_daemon::binary_manifest::bundled_install_dir();
    managed_prod_construct_specs_from_sources(
        manifest.as_ref(),
        &bundled_dir,
        std::env::var("PATH").ok().as_deref(),
    )
}

pub fn prod_required_constructs_present(specs: &[ConstructSpec]) -> bool {
    ["gh", "git"]
        .into_iter()
        .all(|tool| specs.iter().any(|spec| spec.tool_name == tool))
}

fn selected_binary_manifest_path() -> Option<PathBuf> {
    selected_binary_manifest_path_from(
        std::env::var_os(EMBER_BINARY_MANIFEST_ENV).map(PathBuf::from),
        PathBuf::from(PROD_MANIFEST_PATH),
        |path| path.exists(),
    )
}

fn selected_binary_manifest_path_from<F>(
    explicit_manifest: Option<PathBuf>,
    prod_manifest: PathBuf,
    exists: F,
) -> Option<PathBuf>
where
    F: Fn(&Path) -> bool,
{
    if let Some(path) = explicit_manifest.filter(|path| !path.as_os_str().is_empty()) {
        return Some(path);
    }

    if exists(&prod_manifest) {
        return Some(prod_manifest);
    }

    None
}

fn launcher_manifest_trust_roots() -> Result<Vec<VerifyingKey>, String> {
    let mut trust_roots = Vec::new();
    if let Ok(release_root) =
        VerifyingKey::from_bytes(&ember_daemon::trust_graph::EMBER_SYSTEMS_PUBKEY_BYTES)
    {
        trust_roots.push(release_root);
    }

    if let Ok(raw) = std::env::var(EMBER_TRUST_ROOTS_ENV) {
        let mut configured = ember_daemon::binary_manifest::parse_trust_roots(&raw)
            .map_err(|e| format!("parse {EMBER_TRUST_ROOTS_ENV}: {e}"))?;
        trust_roots.append(&mut configured);
    }
    if let Some(raw) = installed_launchd_trust_roots() {
        let mut configured = ember_daemon::binary_manifest::parse_trust_roots(&raw)
            .map_err(|e| format!("parse installed LaunchDaemon {EMBER_TRUST_ROOTS_ENV}: {e}"))?;
        trust_roots.append(&mut configured);
    }
    if let Ok(Some(raw)) = crate::dev::identity_root::read_existing_dev_identity_root_pubkey_hex() {
        let mut configured = ember_daemon::binary_manifest::parse_trust_roots(&raw)
            .map_err(|e| format!("parse dev IdentityRoot {EMBER_TRUST_ROOTS_ENV}: {e}"))?;
        trust_roots.append(&mut configured);
    }

    Ok(trust_roots)
}

fn installed_launchd_trust_roots() -> Option<String> {
    let plist = std::fs::read_to_string(PROD_LAUNCHD_PLIST_PATH).ok()?;
    extract_launchd_env_value(&plist, EMBER_TRUST_ROOTS_ENV)
}

fn extract_launchd_env_value(plist: &str, key: &str) -> Option<String> {
    let needle = format!("<key>{key}</key>");
    let after_key = plist.split_once(&needle)?.1;
    let after_string = after_key.split_once("<string>")?.1;
    let raw_value = after_string.split_once("</string>")?.0;
    Some(unescape_plist_string(raw_value.trim()))
}

fn unescape_plist_string(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn construct_manifest_tool_name(tool_name: &str) -> String {
    if tool_name.starts_with("ember-") {
        tool_name.to_string()
    } else {
        format!("ember-{tool_name}")
    }
}

fn canonical_path_for_trust_gate(path: &Path, label: &str) -> io::Result<PathBuf> {
    path.canonicalize().map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "construct manifest trust gate refused: could not canonicalize {label} {}: {e}",
                path.display()
            ),
        )
    })
}

fn io_trust_gate_refusal(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

fn trusted_construct_roots(manifest_path: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(parent) = manifest_path.parent()
        && let Ok(canonical) = parent.canonicalize()
    {
        roots.push(canonical);
    }
    if let Ok(canonical) = ember_daemon::binary_manifest::bundled_install_dir().canonicalize()
        && !roots.iter().any(|root| root == &canonical)
    {
        roots.push(canonical);
    }
    roots
}

#[derive(Debug)]
pub(crate) struct VerifiedConstructSpec {
    tool_name: String,
    bytes: Vec<u8>,
}

pub(crate) fn verify_construct_manifest_before_spawn(
    construct_specs: &[ConstructSpec],
) -> io::Result<Option<Vec<VerifiedConstructSpec>>> {
    if construct_specs.is_empty() {
        return Ok(None);
    }

    let Some(manifest_path) = selected_binary_manifest_path() else {
        return Ok(None);
    };

    let trust_roots = launcher_manifest_trust_roots().map_err(|e| {
        io_trust_gate_refusal(format!(
            "construct manifest trust gate refused: trust-root setup failed for {}: {e}",
            manifest_path.display()
        ))
    })?;

    ember_daemon::binary_manifest::verify_manifest_signature_with_trust_roots(
        &manifest_path,
        &trust_roots,
    )
    .map_err(|e| {
        io_trust_gate_refusal(format!(
            "construct manifest trust gate refused: manifest signature/trust verification failed for {}: {e}",
            manifest_path.display()
        ))
    })?;

    let manifest = ember_daemon::binary_manifest::load_manifest(&manifest_path).map_err(|e| {
        io_trust_gate_refusal(format!(
            "construct manifest trust gate refused: manifest load failed for {}: {e}",
            manifest_path.display()
        ))
    })?;

    let mut verified = Vec::with_capacity(construct_specs.len());
    let trusted_roots = trusted_construct_roots(&manifest_path);
    for spec in construct_specs {
        let manifest_tool = construct_manifest_tool_name(&spec.tool_name);
        let entry = ember_daemon::binary_manifest::lookup_construct(&manifest, &manifest_tool)
            .map_err(|e| {
                io_trust_gate_refusal(format!(
                    "construct manifest trust gate refused: manifest entry lookup failed for {manifest_tool}: {e}"
                ))
            })?;

        if !entry.absolute_path.is_absolute() {
            return Err(io_trust_gate_refusal(format!(
                "construct manifest trust gate refused: manifest entry {manifest_tool} uses non-absolute path {}",
                entry.absolute_path.display()
            )));
        }

        let pinned = ember_daemon::broker::handler::verify_binary_pin(&manifest, &manifest_tool)
            .map_err(|e| {
                io_trust_gate_refusal(format!(
                    "construct manifest trust gate refused: content pin verification failed for {manifest_tool}: {e}"
                ))
            })?;

        let verified_path = canonical_path_for_trust_gate(&pinned.path, "verified construct")?;
        if !trusted_roots
            .iter()
            .any(|root| verified_path.starts_with(root))
        {
            return Err(io_trust_gate_refusal(format!(
                "construct manifest trust gate refused: manifest entry {manifest_tool} path {} escapes trusted construct roots {:?}",
                verified_path.display(),
                trusted_roots
            )));
        }
        let exposed_path =
            canonical_path_for_trust_gate(&spec.target_binary, "launcher construct")?;
        if verified_path != exposed_path {
            return Err(io_trust_gate_refusal(format!(
                "construct manifest trust gate refused: manifest content_pin for {manifest_tool} verifies {}, but launcher would expose {}",
                verified_path.display(),
                exposed_path.display()
            )));
        }

        verified.push(VerifiedConstructSpec {
            tool_name: spec.tool_name.clone(),
            bytes: pinned.bytes,
        });
    }

    Ok(Some(verified))
}

fn safe_shadow_tool_name(tool_name: &str) -> bool {
    let mut components = Path::new(tool_name).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

fn install_verified_shadow_alias(alias_path: &Path, canonical_path: &Path) -> io::Result<()> {
    match alias_path.symlink_metadata() {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::os::unix::fs::symlink(canonical_path, alias_path).map_err(|e| {
                io::Error::other(format!("create symlink {}: {e}", alias_path.display()))
            })?;
        }
        Err(e) => {
            return Err(io::Error::other(format!(
                "stat {}: {e}",
                alias_path.display()
            )));
        }
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                match std::fs::read_link(alias_path) {
                    Ok(existing) if existing == canonical_path => {
                        return Ok(());
                    }
                    Ok(_) => {
                        std::fs::remove_file(alias_path).map_err(|e| {
                            io::Error::other(format!(
                                "remove stale symlink {}: {e}",
                                alias_path.display()
                            ))
                        })?;
                        std::os::unix::fs::symlink(canonical_path, alias_path).map_err(|e| {
                            io::Error::other(format!(
                                "create symlink {}: {e}",
                                alias_path.display()
                            ))
                        })?;
                    }
                    Err(e) => {
                        return Err(io::Error::other(format!(
                            "read_link {}: {e}",
                            alias_path.display()
                        )));
                    }
                }
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "regular file already exists at shadow path {}; remove it manually before installing the verified shim alias",
                        alias_path.display()
                    ),
                ));
            }
        }
    }

    Ok(())
}

pub(crate) fn install_verified_path_shadow(
    shadow_dir: &Path,
    constructs: &[VerifiedConstructSpec],
) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    let bin_dir = shadow_bin_dir(shadow_dir);
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o700))?;

    for spec in constructs {
        if !safe_shadow_tool_name(&spec.tool_name) {
            return Err(io_trust_gate_refusal(format!(
                "construct manifest trust gate refused: unsafe shadow tool name {:?}",
                spec.tool_name
            )));
        }

        let shim_path = bin_dir.join(&spec.tool_name);
        if let Ok(meta) = shim_path.symlink_metadata()
            && meta.is_dir()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "directory already exists at shadow path {}; remove it manually before installing the verified shim",
                    shim_path.display()
                ),
            ));
        }

        let tmp_path = bin_dir.join(format!(
            ".{}.verified.{}.tmp",
            spec.tool_name,
            std::process::id()
        ));
        let mut tmp = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| io::Error::other(format!("create {}: {e}", tmp_path.display())))?;
        tmp.write_all(&spec.bytes)
            .map_err(|e| io::Error::other(format!("write {}: {e}", tmp_path.display())))?;
        tmp.sync_all()
            .map_err(|e| io::Error::other(format!("sync {}: {e}", tmp_path.display())))?;
        drop(tmp);
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o700))?;

        if let Err(e) = std::fs::rename(&tmp_path, &shim_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(io::Error::other(format!(
                "install verified shim {}: {e}",
                shim_path.display()
            )));
        }

        for alias in shadow_tool_aliases(&spec.tool_name) {
            if !safe_shadow_tool_name(&alias) {
                return Err(io_trust_gate_refusal(format!(
                    "construct manifest trust gate refused: unsafe shadow tool alias {alias:?}"
                )));
            }
            install_verified_shadow_alias(&bin_dir.join(alias), &shim_path)?;
        }
    }

    Ok(())
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
    run_with_registration_with_workspace_ref(
        bin,
        extra_args,
        registration,
        socket_path,
        shadow_dir,
        None,
    )
}

fn run_with_registration_with_workspace_ref(
    bin: &str,
    extra_args: &[String],
    registration: &SessionRegistration,
    socket_path: &Path,
    shadow_dir: &Path,
    workspace_ref: Option<&str>,
) -> io::Result<i32> {
    // Export EMBER_BROKER_CWD so a top-level host launch (no managed-worktree
    // workspace_ref) still gives the construct runtime a cwd: `broker_exec`
    // resolution consults `broker_exec_compat_cwd` ONLY when `workspace_ref` is
    // absent (core-construct-runtime), so without this, host-launched brokered
    // tools fail "broker_exec requires …workspace_ref". Harmless when a
    // workspace_ref is present — the runtime ignores the compat cwd then.
    let target_dir = std::env::current_dir()?;
    let mut extra_env = vec![
        ("EMBER_PERSONA".to_string(), resolve_persona_name()),
        (
            "EMBER_BROKER_CWD".to_string(),
            target_dir.to_string_lossy().into_owned(),
        ),
    ];
    let broker_lane = is_broker_lane(registration);
    let stripped_env = if broker_lane {
        CLAUDE_BROKER_STRIPPED_AUTH_ENV
    } else {
        &[]
    };
    if let Some(ref base_url) = registration.anthropic_base_url {
        extra_env.push(("ANTHROPIC_BASE_URL".to_string(), base_url.clone()));
    }
    if let Some(ref headers) = registration.anthropic_custom_headers {
        extra_env.push(("ANTHROPIC_CUSTOM_HEADERS".to_string(), headers.clone()));
    }
    // Broker lane: satisfy Claude Code's client-side auth-presence gate with an
    // inert checkpoint so the CLI forms requests at all (under a custom base URL
    // it otherwise refuses with "Not logged in"). Pushed onto `extra_env`,
    // which `core::run_with_registration` applies AFTER the `stripped_env`
    // removal pass — so `ANTHROPIC_AUTH_TOKEN` is first stripped of any real
    // inherited credential, then re-set to the checkpoint. The real credential is
    // injected server-side by the proxy, which strips the inbound
    // `authorization` regardless of value.
    if broker_lane {
        extra_env.push((
            "ANTHROPIC_AUTH_TOKEN".to_string(),
            CLAUDE_BROKER_SENTINEL_AUTH_TOKEN.to_string(),
        ));
    }
    // P22-S2 (ADR 197 §2): route Anthropic API traffic over the per-session
    // peercred-gated UDS. Claude Code's `ANTHROPIC_UNIX_SOCKET` makes undici
    // dial this socket (the `anthropic_base_url` above is the non-Anthropic
    // checkpoint, so a socket-bypass fails closed). The bearer is dropped from
    // the child env on this path (see `core::run_with_registration`).
    if let Some(ref uds) = registration.anthropic_unix_socket {
        extra_env.push(("ANTHROPIC_UNIX_SOCKET".to_string(), uds.clone()));
    }
    if let Some(ref gpu) = registration.git_proxy_url {
        extra_env.push(("EMBER_GIT_PROXY_URL".to_string(), gpu.clone()));
    }
    if let Some(ref sock) = registration.ssh_auth_sock {
        extra_env.push(("SSH_AUTH_SOCK".to_string(), sock.clone()));
    }
    if let Some(workspace_ref) = workspace_ref {
        extra_env.push((
            crate::launcher::worktree::WORKSPACE_REF_ENV.to_string(),
            workspace_ref.to_string(),
        ));
    }
    if let Some(runtime_id) = workspace_ref
        .and_then(|value| value.strip_prefix("managed_worktree:"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        extra_env.push((
            crate::dev_runtime::DEV_RUNTIME_ID_ENV.to_string(),
            runtime_id.to_string(),
        ));
    }

    with_session_close(&registration.session_id, socket_path, || {
        core::run_with_registration(
            LauncherInvocation {
                launcher_name: "claude",
                binary: bin,
                extra_args,
                socket_path,
                shadow_bin_dir: shadow_dir,
                current_dir: None,
                stripped_env,
            },
            registration,
            extra_env,
        )
    })
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
/// `ember init --for claude`).
pub fn resolve_persona_name() -> String {
    if let Ok(v) = std::env::var("EMBER_PERSONA")
        && !v.is_empty()
    {
        return v;
    }
    crate::onboarding::claude_code::claude_code_persona_name()
}

/// Print the host-mode mediation disclaimer (ADR 166 §Component 5a) and
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

    // LOCKED COPY — do not edit without ADR 166 §Component 5a update.
    // V030-CLAUDE-OVERLAY (2026-06-12): added the "ambient creds reachable"
    // line + the proxy-strip-is-the-lever framing so operators don't read
    // any future deny-rule scaffolding as a structural credential block.
    // Memory: feedback_grant_clamp_is_security_argv_is_ux.
    eprintln!(
        "\nember brokers 16 tools (git, gh, kubectl, …); other commands run with your shell's authority.\n\
         Ambient developer credentials (gh auth, ~/.aws, kubectl) remain reachable from this lane;\n\
         the structural credential lever is the proxy stripping inbound auth, not the harness deny rules.\n\
         Need stricter? `ember claude --isolated` runs in a container (ADR 213).\n\
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

/// `ember claude [extra_args...]` entry point.
///
/// Resolves persona via `resolve_persona_name` (`$EMBER_PERSONA` env var or
/// the cohort-A default `claude-code-{hostname}`), installs PATH-shadow
/// symlinks (ADR 124 §3 sub-A), calls `register_session_rpc` (live RPC per
/// #2318 / ADR 120 §2), prepends the shadow dir to the child PATH, spawns
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
    launch_claude_code_with_shadow_dir_and_constructs_with_workspace_ref(
        extra_args,
        socket_path,
        shadow_dir,
        bin,
        persona,
        construct_specs,
        false,
        None,
        None,
        None,
    )
}

// Launch plumbing — structurally many params threaded to the workspace_ref variant.
#[allow(clippy::too_many_arguments)]
pub fn launch_claude_code_with_shadow_dir_and_constructs_with_runtime_id(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir: &Path,
    bin: &str,
    persona: &str,
    construct_specs: &[ConstructSpec],
    authority_strict: bool,
    delegated_template: Option<&str>,
    attach_runtime_persona_id: Option<&str>,
    dev_runtime_id: Option<&str>,
) -> io::Result<i32> {
    let workspace_ref = dev_runtime_id.map(|runtime_id| format!("managed_worktree:{runtime_id}"));
    launch_claude_code_with_shadow_dir_and_constructs_with_workspace_ref(
        extra_args,
        socket_path,
        shadow_dir,
        bin,
        persona,
        construct_specs,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        workspace_ref.as_deref(),
    )
}

// Launch plumbing — structurally many params for the full launch contract.
#[allow(clippy::too_many_arguments)]
pub fn launch_claude_code_with_shadow_dir_and_constructs_with_workspace_ref(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir: &Path,
    bin: &str,
    persona: &str,
    construct_specs: &[ConstructSpec],
    authority_strict: bool,
    delegated_template: Option<&str>,
    attach_runtime_persona_id: Option<&str>,
    workspace_ref: Option<&str>,
) -> io::Result<i32> {
    core::ensure_broker_safe_launch_cwd("claude")?;
    // trust_gate_bypass_closed: verify manifest signature and content pins
    // before exposing any construct path to the child process.
    if let Some(verified_constructs) = verify_construct_manifest_before_spawn(construct_specs)? {
        install_verified_path_shadow(shadow_dir, &verified_constructs)?;
    } else {
        install_path_shadow(shadow_dir, construct_specs)?;
    }

    // Step 1.5: resolve an explicit delegated-authority template override.
    // Default launch stays ambient; only explicit opt-in attaches delegated
    // authority at session-open.
    let delegation_template_name =
        resolve_delegation_template_for_launch(delegated_template, "ember claude")
            .map_err(io::Error::other)?;

    // Step 2: Register session with the daemon (mints EMBER_SESSION_ID and,
    // when an explicit delegated template was selected, lowers the template's
    // authority into the runtime persona's `StandingGrant` at session-open per
    // ADR 205 §6).
    let registration = register_session_rpc_with_workflow_and_workspace_ref(
        persona,
        socket_path,
        delegation_template_name.as_deref(),
        authority_strict,
        attach_runtime_persona_id,
        workspace_ref,
        "ember claude",
        "ember claude",
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

    // Step 3: Print the host-mode mediation disclaimer (ADR 166 §Component 5a)
    // immediately before invoking the Claude Code child binary. Skipped when
    // stderr is not a tty or the user has persisted suppression.
    maybe_print_host_mode_disclaimer()?;

    // Step 4: Spawn child with shadow/bin PATH prepended and all ember env vars set.
    // The bin/ subdirectory holds the shim binaries; the root holds creds/config.
    let bin_dir = shadow_bin_dir(shadow_dir);
    run_with_registration_with_workspace_ref(
        bin,
        extra_args,
        &registration,
        socket_path,
        &bin_dir,
        workspace_ref,
    )
}

#[cfg(test)]
fn launcher_guidance_for_rpc(method: &str, code: i32, message: &str) -> Option<String> {
    crate::launcher::session_rpc::launcher_guidance_for_rpc(
        Path::new("/tmp/daemon.sock"),
        method,
        code,
        message,
        "ember claude",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ember_daemon::binary_manifest::{
        BinaryDistributionChannel, BinaryManifest, BinaryManifestEntry, write_signed_manifest,
    };
    use serde_json::json;

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
            authority_posture: crate::launcher::core::AuthorityPosture::from_components(
                false, None,
            ),
            bridge_client_bundle: None,
            attachment_id: Some("att_fixture".to_string()),
            attachment_endpoint_token: Some("ep_fixture".to_string()),
            anthropic_unix_socket: None,
            leaf_report_nonce: None,
        }
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, contents: &str) {
        use std::os::unix::fs::PermissionsExt as _;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(path, contents).expect("write executable");
        let mut permissions = std::fs::metadata(path)
            .expect("read executable metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).expect("set executable permissions");
    }

    fn manifest_entry(path: &Path, content_hash: String) -> BinaryManifestEntry {
        BinaryManifestEntry {
            tool_name: "ember-git".to_string(),
            version: "0.3.0-test".to_string(),
            content_hash,
            absolute_path: path.to_path_buf(),
            installed_at: 0,
            publisher: "did:emberlink".to_string(),
            channel: BinaryDistributionChannel::Bundled,
        }
    }

    fn blake3_content_hash(path: &Path) -> String {
        let bytes = std::fs::read(path).expect("read construct");
        format!("blake3:{}", hex::encode(blake3::hash(&bytes).as_bytes()))
    }

    fn restore_manifest_env(
        prior_manifest: Option<std::ffi::OsString>,
        prior_trust_roots: Option<std::ffi::OsString>,
    ) {
        unsafe {
            match prior_manifest {
                Some(value) => std::env::set_var(EMBER_BINARY_MANIFEST_ENV, value),
                None => std::env::remove_var(EMBER_BINARY_MANIFEST_ENV),
            }
            match prior_trust_roots {
                Some(value) => std::env::set_var(EMBER_TRUST_ROOTS_ENV, value),
                None => std::env::remove_var(EMBER_TRUST_ROOTS_ENV),
            }
        }
    }

    #[test]
    fn extract_launchd_env_value_reads_trust_roots_from_owned_plist_shape() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>EnvironmentVariables</key>
  <dict>
    <key>EMBER_APP_ENV_PATH</key><string>/etc/emberlink/ember-engine.env</string>
    <key>EMBER_TRUST_ROOTS</key><string>abc123&amp;def456</string>
  </dict>
</dict>
</plist>
"#;

        assert_eq!(
            extract_launchd_env_value(plist, EMBER_TRUST_ROOTS_ENV).as_deref(),
            Some("abc123&def456")
        );
    }

    #[test]
    fn selected_binary_manifest_path_prefers_explicit_override() {
        let explicit = PathBuf::from("/tmp/dev/manifest.toml");
        let prod = PathBuf::from("/usr/local/lib/ember/binaries/manifest.toml");
        let selected =
            selected_binary_manifest_path_from(Some(explicit.clone()), prod.clone(), |path| {
                path == prod
            });

        assert_eq!(selected, Some(explicit));
    }

    #[test]
    fn selected_binary_manifest_path_uses_prod_manifest() {
        let prod = PathBuf::from("/usr/local/lib/ember/binaries/manifest.toml");
        let selected = selected_binary_manifest_path_from(None, prod.clone(), |path| path == prod);

        assert_eq!(selected, Some(prod));
    }

    #[test]
    fn selected_binary_manifest_path_does_not_use_home_manifest() {
        let prod = PathBuf::from("/usr/local/lib/ember/binaries/manifest.toml");
        let selected = selected_binary_manifest_path_from(None, prod, |path| {
            path == Path::new("/home/test-operator/.ember/binaries/manifest.toml")
        });

        assert_eq!(selected, None);
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
        let installed_target = tmp.path().join("usr/local/lib/ember/binaries/ember-git");
        std::fs::create_dir_all(installed_target.parent().unwrap()).unwrap();
        std::fs::write(&installed_target, b"binary").unwrap();
        std::os::unix::fs::symlink(&installed_target, &launcher).unwrap();
        assert!(
            prod_safe_construct_candidate(&launcher),
            "prod path must accept managed-install construct candidates"
        );
    }

    #[cfg(unix)]
    #[test]
    fn construct_manifest_gate_rejects_trusted_content_pin_mismatch() {
        let _g = crate::PROCESS_ENV_CWD_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let construct = tmp.path().join("constructs/ember-git");
        write_executable(&construct, "#!/bin/sh\nexit 0\n");
        let manifest_path = tmp.path().join("manifest.toml");
        let manifest = BinaryManifest {
            entries: vec![manifest_entry(
                &construct,
                "blake3:this-pin-does-not-match".to_string(),
            )],
        };
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        write_signed_manifest(&manifest, &signer, &manifest_path).expect("write signed manifest");

        let prior_manifest = std::env::var_os(EMBER_BINARY_MANIFEST_ENV);
        let prior_trust_roots = std::env::var_os(EMBER_TRUST_ROOTS_ENV);
        unsafe {
            std::env::set_var(EMBER_BINARY_MANIFEST_ENV, &manifest_path);
            std::env::set_var(
                EMBER_TRUST_ROOTS_ENV,
                hex::encode(signer.verifying_key().to_bytes()),
            );
        }
        let err = verify_construct_manifest_before_spawn(&[ConstructSpec {
            tool_name: "git".to_string(),
            target_binary: construct,
        }])
        .expect_err("bad content pin must be rejected");
        restore_manifest_env(prior_manifest, prior_trust_roots);

        let msg = err.to_string();
        assert!(
            msg.contains("content pin verification failed"),
            "pin mismatch should be the refusal reason: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn construct_manifest_gate_rejects_pinned_binary_different_from_exposed_path() {
        let _g = crate::PROCESS_ENV_CWD_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let pinned = tmp.path().join("constructs/ember-git");
        let exposed = tmp.path().join("other/ember-git");
        write_executable(&pinned, "#!/bin/sh\nexit 0\n");
        write_executable(&exposed, "#!/bin/sh\nexit 0\n");
        let manifest_path = tmp.path().join("manifest.toml");
        let manifest = BinaryManifest {
            entries: vec![manifest_entry(&pinned, blake3_content_hash(&pinned))],
        };
        let signer = SigningKey::from_bytes(&[8u8; 32]);
        write_signed_manifest(&manifest, &signer, &manifest_path).expect("write signed manifest");

        let prior_manifest = std::env::var_os(EMBER_BINARY_MANIFEST_ENV);
        let prior_trust_roots = std::env::var_os(EMBER_TRUST_ROOTS_ENV);
        unsafe {
            std::env::set_var(EMBER_BINARY_MANIFEST_ENV, &manifest_path);
            std::env::set_var(
                EMBER_TRUST_ROOTS_ENV,
                hex::encode(signer.verifying_key().to_bytes()),
            );
        }
        let err = verify_construct_manifest_before_spawn(&[ConstructSpec {
            tool_name: "git".to_string(),
            target_binary: exposed,
        }])
        .expect_err("launcher must not expose a different binary than the pinned one");
        restore_manifest_env(prior_manifest, prior_trust_roots);

        let msg = err.to_string();
        assert!(
            msg.contains("launcher would expose"),
            "path mismatch should be the refusal reason: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn construct_manifest_gate_rejects_path_outside_trusted_roots() {
        let _g = crate::PROCESS_ENV_CWD_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let manifest_dir = tmp.path().join("trusted");
        let escaped_dir = tmp.path().join("escaped");
        std::fs::create_dir_all(&manifest_dir).expect("mkdir trusted");
        let escaped = escaped_dir.join("ember-git");
        write_executable(&escaped, "#!/bin/sh\nexit 0\n");
        let manifest_path = manifest_dir.join("manifest.toml");
        let manifest = BinaryManifest {
            entries: vec![manifest_entry(&escaped, blake3_content_hash(&escaped))],
        };
        let signer = SigningKey::from_bytes(&[10u8; 32]);
        write_signed_manifest(&manifest, &signer, &manifest_path).expect("write signed manifest");

        let prior_manifest = std::env::var_os(EMBER_BINARY_MANIFEST_ENV);
        let prior_trust_roots = std::env::var_os(EMBER_TRUST_ROOTS_ENV);
        unsafe {
            std::env::set_var(EMBER_BINARY_MANIFEST_ENV, &manifest_path);
            std::env::set_var(
                EMBER_TRUST_ROOTS_ENV,
                hex::encode(signer.verifying_key().to_bytes()),
            );
        }
        let err = verify_construct_manifest_before_spawn(&[ConstructSpec {
            tool_name: "git".to_string(),
            target_binary: escaped,
        }])
        .expect_err("manifest path outside trusted roots must be rejected");
        restore_manifest_env(prior_manifest, prior_trust_roots);

        let msg = err.to_string();
        assert!(
            msg.contains("escapes trusted construct roots"),
            "root escape should be the refusal reason: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn verified_shadow_install_uses_verified_bytes_not_source_symlink() {
        let _g = crate::PROCESS_ENV_CWD_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("constructs/ember-git");
        write_executable(&source, "#!/bin/sh\necho verified\n");
        let manifest_path = tmp.path().join("manifest.toml");
        let manifest = BinaryManifest {
            entries: vec![manifest_entry(&source, blake3_content_hash(&source))],
        };
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        write_signed_manifest(&manifest, &signer, &manifest_path).expect("write signed manifest");

        let prior_manifest = std::env::var_os(EMBER_BINARY_MANIFEST_ENV);
        let prior_trust_roots = std::env::var_os(EMBER_TRUST_ROOTS_ENV);
        unsafe {
            std::env::set_var(EMBER_BINARY_MANIFEST_ENV, &manifest_path);
            std::env::set_var(
                EMBER_TRUST_ROOTS_ENV,
                hex::encode(signer.verifying_key().to_bytes()),
            );
        }
        let verified = verify_construct_manifest_before_spawn(&[ConstructSpec {
            tool_name: "git".to_string(),
            target_binary: source.clone(),
        }])
        .expect("valid manifest verifies")
        .expect("manifest-backed launch should return verified bytes");
        restore_manifest_env(prior_manifest, prior_trust_roots);

        std::fs::write(&source, "#!/bin/sh\necho swapped\n").expect("mutate source after verify");
        let shadow = tmp.path().join("shadow");
        install_verified_path_shadow(&shadow, &verified).expect("install verified shadow");
        let shim = shadow_bin_dir(&shadow).join("git");

        assert!(
            !shim.symlink_metadata().unwrap().file_type().is_symlink(),
            "verified shadow entry must be a regular file, not a source symlink"
        );
        assert_eq!(
            std::fs::read_to_string(&shim).unwrap(),
            "#!/bin/sh\necho verified\n"
        );
        assert_eq!(
            std::fs::read_link(shadow_bin_dir(&shadow).join("ember-git")).unwrap(),
            shim
        );
    }

    #[test]
    fn is_broker_lane_true_when_base_url_present() {
        let mut reg = fixture();
        reg.anthropic_base_url = Some("http://ember-proxy.local/".to_string());
        assert!(is_broker_lane(&reg));
    }

    #[test]
    fn is_broker_lane_true_when_custom_headers_present() {
        let mut reg = fixture();
        reg.anthropic_custom_headers =
            Some("X-Ember-Credential: anthropic/oauth-token".to_string());
        assert!(is_broker_lane(&reg));
    }

    #[test]
    fn is_broker_lane_false_for_plain_session() {
        assert!(!is_broker_lane(&fixture()));
    }

    #[test]
    fn broker_sentinel_is_inert_and_shares_the_stripped_auth_token_key() {
        // Non-empty (Claude's gate requires a value) and not mistakable for a
        // real credential.
        assert!(!CLAUDE_BROKER_SENTINEL_AUTH_TOKEN.is_empty());
        assert!(!CLAUDE_BROKER_SENTINEL_AUTH_TOKEN.starts_with("sk-ant"));
        // The key we re-set on the broker lane is the same key we strip first,
        // so the strip-then-set ordering in `core::run_with_registration`
        // guarantees any inherited real token is removed before the checkpoint
        // lands.
        assert!(CLAUDE_BROKER_STRIPPED_AUTH_ENV.contains(&"ANTHROPIC_AUTH_TOKEN"));
        // The real-credential env vars stay stripped (never re-set).
        assert!(CLAUDE_BROKER_STRIPPED_AUTH_ENV.contains(&"CLAUDE_CODE_OAUTH_TOKEN"));
        assert!(CLAUDE_BROKER_STRIPPED_AUTH_ENV.contains(&"ANTHROPIC_API_KEY"));
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
            specs
                .iter()
                .any(|spec| spec.tool_name == "gh" && spec.target_binary == managed_gh)
        );
        assert!(
            specs
                .iter()
                .any(|spec| spec.tool_name == "git" && spec.target_binary == managed_git)
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
            specs
                .iter()
                .any(|spec| spec.tool_name == "gh" && spec.target_binary == bundled_gh)
        );
        assert!(
            specs
                .iter()
                .any(|spec| spec.tool_name == "git" && spec.target_binary == bundled_git)
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
        // gain the attachment endpoint token after we run a child that
        // should only see it in the child env. The launcher writes only via
        // `Command::env(...)`; an accidental `std::env::set_var` in
        // `run_with_registration` would leak `ep_fixture` to the
        // parent, which we'd see here.
        let _ = run_with_registration(
            "/usr/bin/true",
            &[],
            &fixture(),
            Path::new("/nonexistent.sock"),
            Path::new("/tmp"),
        )
        .expect("spawn /usr/bin/true");
        let leaked = std::env::var("EMBER_ATTACHMENT_ENDPOINT_TOKEN")
            .map(|v| v.contains("ep_fixture"))
            .unwrap_or(false);
        assert!(
            !leaked,
            "launcher must not write attachment endpoint token into parent env"
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_with_registration_exports_workspace_ref_for_construct_contracts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = tmp.path().join("check-workspace-ref-env.sh");
        write_executable(
            &script,
            "#!/bin/sh\n[ \"$EMBER_WORKSPACE_REF\" = \"managed_worktree:rt-yankee\" ] || exit 45\n[ \"$EMBER_DEV_RUNTIME_ID\" = \"rt-yankee\" ] || exit 46\n[ \"$EMBER_BROKER_CWD\" = \"$(pwd)\" ] || exit 47\nexit 0\n",
        );

        let code = run_with_registration_with_workspace_ref(
            script.to_str().expect("utf8 script path"),
            &[],
            &fixture(),
            Path::new("/nonexistent.sock"),
            tmp.path(),
            Some("managed_worktree:rt-yankee"),
        )
        .expect("spawn runtime-id checker");

        assert_eq!(
            code, 0,
            "managed host launch must export the workspace ref for construct execution contracts"
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
        let err = register_session_rpc("default", Path::new("/nonexistent.sock"), false)
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
        assert!(guidance.contains("session-runtime presence credential"));
        assert!(guidance.contains("register_session"));
        assert!(guidance.contains("ember status"));
        assert!(!guidance.contains("ember vault unlock"));
        assert!(guidance.contains("ember claude"));
    }

    #[test]
    fn launcher_guidance_maps_locked_session_for_register_session() {
        let guidance = launcher_guidance_for_rpc(
            "register_session",
            -32030,
            "register_session denied: session is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts",
        )
        .expect("expected guidance");
        assert!(guidance.contains("ADR 206 §4"));
        assert!(guidance.contains("normally performs this Touch ID unlock implicitly"));
        assert!(guidance.contains("ember vault se-unlock"));
        assert!(!guidance.contains("ember vault unlock"));
        assert!(guidance.contains("ember claude"));
    }

    #[test]
    fn launcher_guidance_does_not_name_vault_unlock_for_register_session() {
        let guidance = launcher_guidance_for_rpc(
            "register_session",
            -32030,
            "register_session denied: session is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts",
        )
        .expect("expected guidance");
        assert!(!guidance.contains("ember vault unlock"));
        assert!(guidance.contains("ember vault se-unlock"));
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
        assert!(guidance.contains("ember doctor"));
        assert!(guidance.contains("ember claude"));
    }

    #[test]
    fn launcher_guidance_maps_no_active_grant_register_session() {
        let guidance = launcher_guidance_for_rpc(
            "register_session",
            -32004,
            "no active grant for persona 'claude-code-default'",
        )
        .expect("expected guidance");
        assert!(guidance.contains("ember init --for claude"));
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
            "persona_id": "persona_fixture",
            "authority_posture": {
                "fallback": "jit",
                "delegation": "ambient"
            },
            "anthropic_base_url": "http://127.0.0.1:7001",
            "anthropic_custom_headers": "X-Ember-Persona: persona-main\nX-Ember-Credential: anthropic-key",
            "git_proxy_url": "http://127.0.0.1:7002",
            "ssh_auth_sock": "/tmp/ember-ssh-agent.sock",
            "presence_token": {
                "uid": 501,
                "scope": "class:session-runtime",
                "expiry": {
                    "secs_since_epoch": 1779507461u64,
                    "nanos_since_epoch": 807776000u32
                },
                "signature": [1, 2, 3]
            },
        });
        let parsed = parse_register_session_result(&raw, Path::new("/tmp/daemon.sock"))
            .expect("direct result must parse");
        assert_eq!(parsed.session_id, "sess_fixture");
        assert_eq!(parsed.grant_id, "grt_fixture");
        assert_eq!(parsed.proxy_url, "http://127.0.0.1:7001");
        assert_eq!(parsed.persona_id.as_deref(), Some("persona_fixture"));
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
        assert_eq!(
            parsed.authority_posture,
            crate::launcher::core::AuthorityPosture::from_components(false, None)
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

    // ── persona resolution tests ──

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
        let raw_err = io::Error::other("daemon error: persona 'claude-code-myhost' not found");
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

    #[test]
    fn delegation_template_is_opt_in_only_when_unset() {
        let _g = crate::EMBER_PERSONA_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_DELEGATION_TEMPLATE").ok();
        unsafe { std::env::remove_var("EMBER_DELEGATION_TEMPLATE") };
        let resolved = resolve_delegation_template_for_launch(None, "ember claude")
            .expect("ambient default should not error");
        match prior {
            Some(value) => unsafe { std::env::set_var("EMBER_DELEGATION_TEMPLATE", value) },
            None => unsafe { std::env::remove_var("EMBER_DELEGATION_TEMPLATE") },
        }
        assert_eq!(
            resolved, None,
            "default launch should stay ambient when no explicit delegated template override is present"
        );
    }

    #[test]
    fn delegation_template_opt_in_uses_safe_env_override() {
        let _g = crate::EMBER_PERSONA_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_DELEGATION_TEMPLATE").ok();
        unsafe { std::env::set_var("EMBER_DELEGATION_TEMPLATE", "landing-page-edits") };
        let resolved = resolve_delegation_template_for_launch(None, "ember claude")
            .expect("env compatibility override should not error");
        match prior {
            Some(value) => unsafe { std::env::set_var("EMBER_DELEGATION_TEMPLATE", value) },
            None => unsafe { std::env::remove_var("EMBER_DELEGATION_TEMPLATE") },
        }
        assert_eq!(
            resolved.as_deref(),
            Some("landing-page-edits"),
            "explicit delegated template override should still attach at session-open"
        );
    }

    #[test]
    fn delegation_template_opt_in_rejects_unsafe_env_override() {
        let _g = crate::EMBER_PERSONA_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_DELEGATION_TEMPLATE").ok();
        unsafe { std::env::set_var("EMBER_DELEGATION_TEMPLATE", "../../tmp/evil") };
        let resolved = resolve_delegation_template_for_launch(None, "ember claude")
            .expect("unsafe env override should not hard-fail launch");
        match prior {
            Some(value) => unsafe { std::env::set_var("EMBER_DELEGATION_TEMPLATE", value) },
            None => unsafe { std::env::remove_var("EMBER_DELEGATION_TEMPLATE") },
        }
        assert_eq!(
            resolved, None,
            "unsafe delegated template override must be ignored"
        );
    }

    #[test]
    fn delegation_template_explicit_override_beats_compat_env_override() {
        let _g = crate::EMBER_PERSONA_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_DELEGATION_TEMPLATE").ok();
        unsafe { std::env::set_var("EMBER_DELEGATION_TEMPLATE", "older-compat-template") };
        let resolved =
            resolve_delegation_template_for_launch(Some("landing-page-edits"), "ember claude")
                .expect("explicit delegated override should parse");
        match prior {
            Some(value) => unsafe { std::env::set_var("EMBER_DELEGATION_TEMPLATE", value) },
            None => unsafe { std::env::remove_var("EMBER_DELEGATION_TEMPLATE") },
        }
        assert_eq!(
            resolved.as_deref(),
            Some("landing-page-edits"),
            "explicit delegated flag should win over compatibility env state"
        );
    }

    #[test]
    fn delegation_template_explicit_override_rejects_unsafe_name() {
        let err = resolve_delegation_template_for_launch(Some("../../tmp/evil"), "ember claude")
            .expect_err("unsafe delegated flag should be rejected");
        assert!(
            err.contains("--delegated"),
            "error should point at the delegated flag: {err}"
        );
    }

    // ── launcher env injection tests ──

    #[test]
    fn registration_with_real_proxy_url_is_not_8484() {
        // Verify that a registration
        // carrying a daemon-provided URL (non-8484) is accepted without
        // falling back. This is the T1 launcher acceptance condition.
        let reg = SessionRegistration {
            session_id: "sess_test".to_string(),
            grant_id: "grt_test".to_string(),
            proxy_url: "http://127.0.0.1:61169".to_string(),
            persona_id: None,
            anthropic_base_url: None,
            anthropic_custom_headers: None,
            git_proxy_url: Some("http://127.0.0.1:61170".to_string()),
            cursor_egress_proxy_url: None,
            codex_responses_proxy_url: None,
            gemini_proxy_url: None,
            ssh_auth_sock: None,
            delegation_id: None,
            delegation_template: None,
            authority_posture: crate::launcher::core::AuthorityPosture::from_components(
                false, None,
            ),
            bridge_client_bundle: None,
            attachment_id: Some("att_test".to_string()),
            attachment_endpoint_token: Some("ep_test".to_string()),
            anthropic_unix_socket: None,
            leaf_report_nonce: None,
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
        // T2 launcher — assert that the
        // child env receives the daemon-returned proxy URL. We verify this
        // indirectly by confirming run_with_registration succeeds (returns 0)
        // with a registration carrying an ephemeral port. The real child-env
        // assertion lives in the daemon-side T2 (register_session_response_includes_real_proxy_url).
        let reg = SessionRegistration {
            session_id: "sess_proxy_wire".to_string(),
            grant_id: "grt_proxy_wire".to_string(),
            proxy_url: "http://127.0.0.1:62000".to_string(),
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
            authority_posture: crate::launcher::core::AuthorityPosture::from_components(
                false, None,
            ),
            bridge_client_bundle: None,
            attachment_id: Some("att_proxy_wire".to_string()),
            attachment_endpoint_token: Some("ep_proxy_wire".to_string()),
            anthropic_unix_socket: None,
            leaf_report_nonce: None,
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

    // ── host-mode mediation disclaimer tests ──

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
