//! Platform-specific service installation for the ember daemon.
//!
//! On macOS this writes a LaunchAgent plist and bootstraps it with `launchctl`.
//! On Linux it writes a systemd user unit and enables it with `systemctl --user`.
//!
//! The generated service is an **always-up** managed process — on SIGTERM it
//! auto-restarts with whatever `ember` binary is currently on disk, which is the
//! primitive `ember daemon reload` depends on for the dev rebuild loop.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// The stable LaunchAgent label / systemd unit basename. Treated as an identifier
/// elsewhere — don't change without bumping the upgrade path.
pub const SERVICE_LABEL: &str = "link.ember.daemon";

/// Default poll cadence while waiting for the old socket to go away and the new
/// daemon to come back up during `reload`.
const RELOAD_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Cap on how long we wait for the old socket to disappear after SIGTERM.
const RELOAD_OLD_SOCKET_TIMEOUT: Duration = Duration::from_secs(2);

/// Env vars we propagate from the installer's environment into the plist /
/// systemd unit. Keeping this narrow is important — the service runs as a
/// login-context process and we don't want to capture the entire shell env.
///
/// If the operator's shell has these set at install time (for QA isolation,
/// passphrase bypass, etc.) they get baked into the unit. Otherwise the daemon
/// falls back to what's in `config.toml`.
const PROPAGATED_ENV_VARS: &[&str] = &[
    "EMBER_KEYRING_SERVICE",
    "EMBER_KEYRING_ACCOUNT",
    "EMBER_VAULT_PASSPHRASE",
    "EMBER_CONFIG",
];

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported platform — manual setup required; see docs")]
    UnsupportedPlatform,
    #[error("could not determine home directory")]
    NoHomeDir,
    #[error("could not determine current executable path: {0}")]
    NoExe(std::io::Error),
    #[error("{tool} failed with status {status}: {stderr}")]
    CommandFailed {
        tool: &'static str,
        status: String,
        stderr: String,
    },
    #[error(
        "daemon is not running — run `ember status` to inspect and `sudo ember daemon install` to install or repair the managed daemon"
    )]
    DaemonNotRunning,
    #[error("daemon reload timed out after {secs}s")]
    ReloadTimeout { secs: u64 },
    #[error("invalid PID {0}")]
    InvalidPid(String),
}

/// Return the user's home directory, bubbling up a clean error if we can't find one.
fn home_dir() -> Result<PathBuf, AgentError> {
    dirs_next::home_dir().ok_or(AgentError::NoHomeDir)
}

/// The plist path for the LaunchAgent. `~/Library/LaunchAgents/<label>.plist`.
pub fn macos_plist_path() -> Result<PathBuf, AgentError> {
    Ok(home_dir()?
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{SERVICE_LABEL}.plist")))
}

/// The systemd user unit path. `~/.config/systemd/user/emberd.service`.
pub fn linux_unit_path() -> Result<PathBuf, AgentError> {
    Ok(home_dir()?
        .join(".config")
        .join("systemd")
        .join("user")
        .join("emberd.service"))
}

/// Directory for daemon logs. `~/.ember/logs/`.
pub fn logs_dir() -> Result<PathBuf, AgentError> {
    Ok(home_dir()?.join(".ember").join("logs"))
}

/// Collect env vars from the current process that should be propagated into
/// the service unit. Returns a sorted map for deterministic plist/unit output.
fn collect_propagated_env() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for key in PROPAGATED_ENV_VARS {
        if let Ok(value) = std::env::var(key)
            && !value.is_empty()
        {
            out.insert((*key).to_string(), value);
        }
    }
    out
}

/// Build the LaunchAgent plist content from inputs. Pure — no filesystem or
/// process access, so this is the unit-test entry point.
///
/// - `ember_path`: absolute path to the `ember` binary launchd should exec.
/// - `config_path`: optional `--config` to pass to `daemon start`.
/// - `stdout_log`, `stderr_log`: absolute paths for launchd stdout/stderr capture.
/// - `env`: key/value env pairs to inject via `EnvironmentVariables`.
pub fn render_plist(
    ember_path: &Path,
    config_path: Option<&Path>,
    stdout_log: &Path,
    stderr_log: &Path,
    env: &BTreeMap<String, String>,
) -> String {
    let mut program_args = vec![
        xml_escape(&ember_path.display().to_string()),
        "daemon".to_string(),
        "start".to_string(),
        "--foreground".to_string(),
    ];
    if let Some(cfg) = config_path {
        program_args.push("--config".to_string());
        program_args.push(xml_escape(&cfg.display().to_string()));
    }

    let mut plist = String::new();
    plist.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    plist.push_str(
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    );
    plist.push_str("<plist version=\"1.0\">\n");
    plist.push_str("<dict>\n");
    plist.push_str("  <key>Label</key>\n");
    plist.push_str(&format!("  <string>{SERVICE_LABEL}</string>\n"));
    plist.push_str("  <key>ProgramArguments</key>\n");
    plist.push_str("  <array>\n");
    for arg in &program_args {
        plist.push_str(&format!("    <string>{arg}</string>\n"));
    }
    plist.push_str("  </array>\n");
    plist.push_str("  <key>RunAtLoad</key>\n");
    plist.push_str("  <true/>\n");
    plist.push_str("  <key>KeepAlive</key>\n");
    plist.push_str("  <true/>\n");
    plist.push_str("  <key>StandardOutPath</key>\n");
    plist.push_str(&format!(
        "  <string>{}</string>\n",
        xml_escape(&stdout_log.display().to_string())
    ));
    plist.push_str("  <key>StandardErrorPath</key>\n");
    plist.push_str(&format!(
        "  <string>{}</string>\n",
        xml_escape(&stderr_log.display().to_string())
    ));
    if !env.is_empty() {
        plist.push_str("  <key>EnvironmentVariables</key>\n");
        plist.push_str("  <dict>\n");
        for (k, v) in env {
            plist.push_str(&format!("    <key>{}</key>\n", xml_escape(k)));
            plist.push_str(&format!("    <string>{}</string>\n", xml_escape(v)));
        }
        plist.push_str("  </dict>\n");
    }
    plist.push_str("</dict>\n");
    plist.push_str("</plist>\n");
    plist
}

/// Build the systemd user unit content. Pure — test entry point.
pub fn render_systemd_unit(
    ember_path: &Path,
    config_path: Option<&Path>,
    stdout_log: &Path,
    stderr_log: &Path,
    env: &BTreeMap<String, String>,
) -> String {
    let mut exec = format!(
        "{} daemon start --foreground",
        shell_quote(&ember_path.display().to_string())
    );
    if let Some(cfg) = config_path {
        exec.push_str(" --config ");
        exec.push_str(&shell_quote(&cfg.display().to_string()));
    }

    let mut unit = String::new();
    unit.push_str("[Unit]\n");
    unit.push_str("Description=Ember trust broker daemon\n");
    unit.push_str("After=network.target\n");
    unit.push('\n');
    unit.push_str("[Service]\n");
    unit.push_str("Type=simple\n");
    unit.push_str(&format!("ExecStart={exec}\n"));
    unit.push_str("Restart=always\n");
    unit.push_str("RestartSec=1s\n");
    unit.push_str(&format!("StandardOutput=append:{}\n", stdout_log.display()));
    unit.push_str(&format!("StandardError=append:{}\n", stderr_log.display()));
    for (k, v) in env {
        // systemd Environment= accepts key=value; values with whitespace must be quoted.
        unit.push_str(&format!("Environment={}={}\n", k, systemd_quote(v)));
    }
    unit.push('\n');
    unit.push_str("[Install]\n");
    unit.push_str("WantedBy=default.target\n");
    unit
}

/// Extremely narrow XML escape — only handles the five entities PLISTs actually
/// care about. Path/env values pass through this before being embedded.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Shell-quote a single path for embedding in a systemd ExecStart line.
/// systemd's unit-file parser accepts POSIX shell-style single-quoting for
/// values that contain whitespace; for simplicity we always single-quote paths
/// unless they are pure "safe" ASCII.
fn shell_quote(s: &str) -> String {
    let safe = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.' | '=' | ':'));
    if safe {
        s.to_string()
    } else {
        // Wrap in single quotes, escaping any embedded single quote via close-quote / escaped / reopen trick.
        let escaped = s.replace('\'', "'\\''");
        format!("'{escaped}'")
    }
}

/// Quote an env value for systemd's `Environment=` line. Values containing
/// whitespace or shell metacharacters must be wrapped in double quotes.
fn systemd_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '/' | '='))
    {
        s.to_string()
    } else {
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    }
}

/// Ensure a file contains the expected contents. Returns `true` if the file
/// was written (new or overwritten), `false` if the content already matched.
fn write_if_changed(path: &Path, content: &str) -> Result<bool, AgentError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        let existing = fs::read_to_string(path)?;
        if existing == content {
            return Ok(false);
        }
    }
    fs::write(path, content)?;
    Ok(true)
}

/// Remove a file if it exists; return `true` if we removed something.
fn remove_if_exists(path: &Path) -> Result<bool, AgentError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(AgentError::Io(e)),
    }
}

/// Summary returned from `install_agent` so the CLI can print a status line.
#[derive(Debug)]
pub struct InstallOutcome {
    /// True if the file was newly written or overwritten (false = already correct).
    pub wrote_file: bool,
    /// True if we ran a bootstrap/enable step.
    pub bootstrapped: bool,
    /// Absolute path of the plist/unit that was installed.
    pub file_path: PathBuf,
}

/// Install the platform-specific always-up service.
///
/// On macOS writes `~/Library/LaunchAgents/link.ember.daemon.plist` and
/// bootstraps it into `gui/$UID`. On Linux writes
/// `~/.config/systemd/user/emberd.service` and enables + starts it.
///
/// `no_autostart=true` writes the file but skips the bootstrap/enable step —
/// useful for scripted installs and tests.
pub fn install_agent(
    config_path: Option<&Path>,
    no_autostart: bool,
) -> Result<InstallOutcome, AgentError> {
    let ember_path = std::env::current_exe().map_err(AgentError::NoExe)?;
    let logs = logs_dir()?;
    fs::create_dir_all(&logs)?;
    let stdout_log = logs.join("daemon.out");
    let stderr_log = logs.join("daemon.err");
    let env = collect_propagated_env();

    if cfg!(target_os = "macos") {
        let plist_path = macos_plist_path()?;
        let content = render_plist(&ember_path, config_path, &stdout_log, &stderr_log, &env);

        // If the file exists with identical content, it's a pure no-op — skip
        // the bootstrap call too, because bootstrapping an already-loaded service
        // fails with "service already loaded" and we'd have to special-case it.
        let existed = plist_path.exists();
        let wrote = write_if_changed(&plist_path, &content)?;
        if !wrote && !no_autostart && !macos_service_loaded()? {
            // File was already correct but the service is NOT currently loaded
            // (e.g. user ran `launchctl bootout` manually). Bootstrap it.
            macos_bootstrap(&plist_path)?;
            return Ok(InstallOutcome {
                wrote_file: false,
                bootstrapped: true,
                file_path: plist_path,
            });
        }
        if !wrote {
            return Ok(InstallOutcome {
                wrote_file: false,
                bootstrapped: false,
                file_path: plist_path,
            });
        }

        if no_autostart {
            return Ok(InstallOutcome {
                wrote_file: true,
                bootstrapped: false,
                file_path: plist_path,
            });
        }

        // If a previous version of the plist is loaded, we must bootout before
        // bootstrapping the new one. Bootout is best-effort — ignore failures
        // if the service isn't loaded.
        if existed {
            let _ = macos_bootout();
        }
        macos_bootstrap(&plist_path)?;
        Ok(InstallOutcome {
            wrote_file: true,
            bootstrapped: true,
            file_path: plist_path,
        })
    } else if cfg!(target_os = "linux") {
        let unit_path = linux_unit_path()?;
        let content = render_systemd_unit(&ember_path, config_path, &stdout_log, &stderr_log, &env);
        let wrote = write_if_changed(&unit_path, &content)?;

        if no_autostart {
            return Ok(InstallOutcome {
                wrote_file: wrote,
                bootstrapped: false,
                file_path: unit_path,
            });
        }

        systemd_daemon_reload()?;
        systemd_enable_now()?;
        Ok(InstallOutcome {
            wrote_file: wrote,
            bootstrapped: true,
            file_path: unit_path,
        })
    } else {
        Err(AgentError::UnsupportedPlatform)
    }
}

/// Summary returned from `uninstall_agent`.
#[derive(Debug)]
pub struct UninstallOutcome {
    pub removed_file: bool,
    pub unbootstrapped: bool,
    pub file_path: PathBuf,
}

/// Uninstall the platform service. Idempotent — does not error if nothing is installed.
pub fn uninstall_agent() -> Result<UninstallOutcome, AgentError> {
    if cfg!(target_os = "macos") {
        let plist_path = macos_plist_path()?;
        // Bootout first so launchd stops the running process.
        let unbootstrapped = macos_bootout().is_ok();
        let removed = remove_if_exists(&plist_path)?;
        Ok(UninstallOutcome {
            removed_file: removed,
            unbootstrapped,
            file_path: plist_path,
        })
    } else if cfg!(target_os = "linux") {
        let unit_path = linux_unit_path()?;
        let unbootstrapped = systemd_disable_now().is_ok();
        let removed = remove_if_exists(&unit_path)?;
        if removed {
            let _ = systemd_daemon_reload();
        }
        Ok(UninstallOutcome {
            removed_file: removed,
            unbootstrapped,
            file_path: unit_path,
        })
    } else {
        Err(AgentError::UnsupportedPlatform)
    }
}

/// Return the current UID as a string by shelling out to `id -u`. Avoids a libc
/// dependency in the CLI crate; `id` is part of POSIX and is present on every
/// macOS / Linux host we support.
fn current_uid() -> String {
    match Command::new("id").arg("-u").output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => std::env::var("UID").unwrap_or_else(|_| "0".to_string()),
    }
}

fn launchctl_domain_target() -> String {
    format!("gui/{}", current_uid())
}

fn macos_bootstrap(plist_path: &Path) -> Result<(), AgentError> {
    let domain = launchctl_domain_target();
    let output = Command::new("launchctl")
        .args(["bootstrap", &domain])
        .arg(plist_path)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    // Fallback for older macOS without bootstrap: `launchctl load -w <plist>`.
    let load_out = Command::new("launchctl")
        .args(["load", "-w"])
        .arg(plist_path)
        .output()?;
    if load_out.status.success() {
        return Ok(());
    }
    // Report the richer of the two error messages.
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let load_stderr = String::from_utf8_lossy(&load_out.stderr).to_string();
    let combined = if load_stderr.is_empty() {
        stderr
    } else {
        format!("{stderr}\nload: {load_stderr}")
    };
    Err(AgentError::CommandFailed {
        tool: "launchctl",
        status: output.status.to_string(),
        stderr: combined,
    })
}

fn macos_bootout() -> Result<(), AgentError> {
    let target = format!("{}/{}", launchctl_domain_target(), SERVICE_LABEL);
    let output = Command::new("launchctl")
        .args(["bootout", &target])
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    // Fallback for older macOS: `launchctl unload -w <plist>`.
    if let Ok(plist_path) = macos_plist_path()
        && plist_path.exists()
    {
        let unload = Command::new("launchctl")
            .args(["unload", "-w"])
            .arg(&plist_path)
            .output()?;
        if unload.status.success() {
            return Ok(());
        }
    }
    Err(AgentError::CommandFailed {
        tool: "launchctl",
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Check whether the LaunchAgent is currently loaded in the GUI domain.
pub fn macos_service_loaded() -> Result<bool, AgentError> {
    let target = format!("{}/{}", launchctl_domain_target(), SERVICE_LABEL);
    let output = Command::new("launchctl")
        .args(["print", &target])
        .output()?;
    Ok(output.status.success())
}

fn systemd_daemon_reload() -> Result<(), AgentError> {
    let output = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(AgentError::CommandFailed {
            tool: "systemctl",
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

fn systemd_enable_now() -> Result<(), AgentError> {
    let output = Command::new("systemctl")
        .args(["--user", "enable", "--now", "emberd.service"])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(AgentError::CommandFailed {
            tool: "systemctl",
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

fn systemd_disable_now() -> Result<(), AgentError> {
    let output = Command::new("systemctl")
        .args(["--user", "disable", "--now", "emberd.service"])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(AgentError::CommandFailed {
            tool: "systemctl",
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

/// Check whether the systemd user service is currently active.
pub fn linux_service_active() -> Result<bool, AgentError> {
    let output = Command::new("systemctl")
        .args(["--user", "is-active", "emberd.service"])
        .output()?;
    // `is-active` exits 0 for "active", non-zero otherwise. We don't care about the reason.
    Ok(output.status.success())
}

/// Is the daemon currently managed by LaunchAgent / systemd?
pub fn is_managed_service() -> bool {
    if cfg!(target_os = "macos") {
        macos_service_loaded().unwrap_or(false)
    } else if cfg!(target_os = "linux") {
        linux_service_active().unwrap_or(false)
    } else {
        false
    }
}

/// Outcome of `reload_daemon`. The new PID is only populated when a managed
/// service successfully came back up.
#[derive(Debug)]
pub struct ReloadOutcome {
    pub old_pid: u32,
    pub new_pid: Option<u32>,
    /// True if the daemon was running under LaunchAgent/systemd at the time
    /// of the reload. Informational — callers should re-check `is_managed_service()`
    /// if they need the current state.
    #[allow(dead_code)]
    pub managed: bool,
}

fn daemon_reload_ready(pid_file: &Path, socket_path: &Path) -> bool {
    matches!(
        emberlink_cli::probe_live_daemon_status(socket_path, pid_file),
        Ok(Some(_))
    )
}

/// Read the daemon PID file. Returns Ok(None) if absent.
fn read_pid(pid_file: &Path) -> Result<Option<u32>, AgentError> {
    match fs::read_to_string(pid_file) {
        Ok(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            trimmed
                .parse::<u32>()
                .map(Some)
                .map_err(|_| AgentError::InvalidPid(trimmed.to_string()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AgentError::Io(e)),
    }
}

/// Is this PID a live process? Uses `kill -0` — same primitive the daemon
/// runtime uses for its own liveness checks.
fn pid_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Send SIGTERM to `pid`. Returns Ok even if the process is already gone.
fn send_sigterm(pid: u32) -> Result<(), AgentError> {
    let status = Command::new("kill").args([&pid.to_string()]).status()?;
    if status.success() || !pid_alive(pid) {
        Ok(())
    } else {
        Err(AgentError::CommandFailed {
            tool: "kill",
            status: status.to_string(),
            stderr: String::new(),
        })
    }
}

/// Tail the last `n` lines of a file. Returns empty string if missing.
/// Used to surface failure context when reload times out.
pub fn tail_file(path: &Path, n: usize) -> String {
    let Ok(file) = fs::File::open(path) else {
        return String::new();
    };
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// Reload the daemon: SIGTERM, wait for the old socket to drop, wait for the
/// managed service to bring up a new process, verify the new PID is different.
///
/// `pid_file` and `socket_path` must match the running daemon's paths (derived
/// from the same `DaemonConfig` the daemon itself was started with).
pub fn reload_daemon(
    pid_file: &Path,
    socket_path: &Path,
    timeout: Duration,
) -> Result<ReloadOutcome, AgentError> {
    let Some(old_pid) = read_pid(pid_file)? else {
        return Err(AgentError::DaemonNotRunning);
    };
    if !pid_alive(old_pid) {
        return Err(AgentError::DaemonNotRunning);
    }
    let managed = is_managed_service();

    send_sigterm(old_pid)?;

    // Phase 1 — wait for the old process to exit. Capped at 2s.
    let old_exit_deadline = Instant::now() + RELOAD_OLD_SOCKET_TIMEOUT;
    while pid_alive(old_pid) && Instant::now() < old_exit_deadline {
        std::thread::sleep(RELOAD_POLL_INTERVAL);
    }

    // Phase 2 — wait for a NEW daemon to come up and answer the live status
    // RPC. A new PID plus socket inode is not enough; operator-facing reload
    // should only succeed once the replacement daemon is actually serving.
    let new_deadline = Instant::now() + timeout;
    loop {
        if let Some(new_pid) = read_pid(pid_file)?
            && new_pid != old_pid
            && pid_alive(new_pid)
            && daemon_reload_ready(pid_file, socket_path)
        {
            return Ok(ReloadOutcome {
                old_pid,
                new_pid: Some(new_pid),
                managed,
            });
        }
        if Instant::now() >= new_deadline {
            return Err(AgentError::ReloadTimeout {
                secs: timeout.as_secs(),
            });
        }
        std::thread::sleep(RELOAD_POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn plist_has_expected_label_and_path() {
        let ember = PathBuf::from("/usr/local/bin/ember");
        let cfg = PathBuf::from("/home/alice/.ember/config.toml");
        let out = PathBuf::from("/home/alice/.ember/logs/daemon.out");
        let err = PathBuf::from("/home/alice/.ember/logs/daemon.err");
        let env = BTreeMap::new();
        let plist = render_plist(&ember, Some(&cfg), &out, &err, &env);

        assert!(
            plist.contains("<string>link.ember.daemon</string>"),
            "missing expected label; got:\n{plist}"
        );
        assert!(
            plist.contains("<string>/usr/local/bin/ember</string>"),
            "missing ember path; got:\n{plist}"
        );
        assert!(
            plist.contains("<string>--foreground</string>"),
            "missing --foreground; got:\n{plist}"
        );
        assert!(
            plist.contains("<string>/home/alice/.ember/config.toml</string>"),
            "missing config path; got:\n{plist}"
        );
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>StandardOutPath</key>"));
        assert!(plist.contains("<key>StandardErrorPath</key>"));
    }

    #[test]
    fn plist_injects_environment_variables() {
        let ember = PathBuf::from("/usr/local/bin/ember");
        let out = PathBuf::from("/tmp/out");
        let err = PathBuf::from("/tmp/err");
        let mut env = BTreeMap::new();
        env.insert("EMBER_KEYRING_SERVICE".to_string(), "ember-qa".to_string());
        let plist = render_plist(&ember, None, &out, &err, &env);
        assert!(plist.contains("<key>EnvironmentVariables</key>"));
        assert!(plist.contains("<key>EMBER_KEYRING_SERVICE</key>"));
        assert!(plist.contains("<string>ember-qa</string>"));
    }

    #[test]
    fn plist_omits_env_dict_when_empty() {
        let ember = PathBuf::from("/usr/local/bin/ember");
        let out = PathBuf::from("/tmp/out");
        let err = PathBuf::from("/tmp/err");
        let env = BTreeMap::new();
        let plist = render_plist(&ember, None, &out, &err, &env);
        assert!(!plist.contains("<key>EnvironmentVariables</key>"));
    }

    #[test]
    fn plist_xml_escapes_special_chars_in_paths() {
        let ember = PathBuf::from("/tmp/ember & co/ember");
        let out = PathBuf::from("/tmp/out");
        let err = PathBuf::from("/tmp/err");
        let env = BTreeMap::new();
        let plist = render_plist(&ember, None, &out, &err, &env);
        assert!(plist.contains("/tmp/ember &amp; co/ember"));
        assert!(!plist.contains("/tmp/ember & co/ember"));
    }

    #[test]
    fn systemd_unit_has_expected_exec_and_restart() {
        let ember = PathBuf::from("/usr/local/bin/ember");
        let cfg = PathBuf::from("/home/alice/.ember/config.toml");
        let out = PathBuf::from("/home/alice/.ember/logs/daemon.out");
        let err = PathBuf::from("/home/alice/.ember/logs/daemon.err");
        let env = BTreeMap::new();
        let unit = render_systemd_unit(&ember, Some(&cfg), &out, &err, &env);

        assert!(
            unit.contains("Description=Ember trust broker daemon"),
            "missing description; got:\n{unit}"
        );
        assert!(
            unit.contains("ExecStart=/usr/local/bin/ember daemon start --foreground --config /home/alice/.ember/config.toml"),
            "unexpected ExecStart; got:\n{unit}"
        );
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("RestartSec=1s"));
        assert!(unit.contains("StandardOutput=append:/home/alice/.ember/logs/daemon.out"));
        assert!(unit.contains("StandardError=append:/home/alice/.ember/logs/daemon.err"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn systemd_unit_injects_environment() {
        let ember = PathBuf::from("/usr/local/bin/ember");
        let out = PathBuf::from("/tmp/out");
        let err = PathBuf::from("/tmp/err");
        let mut env = BTreeMap::new();
        env.insert("EMBER_KEYRING_SERVICE".to_string(), "ember-qa".to_string());
        let unit = render_systemd_unit(&ember, None, &out, &err, &env);
        assert!(unit.contains("Environment=EMBER_KEYRING_SERVICE=ember-qa"));
    }

    #[test]
    fn systemd_unit_quotes_paths_with_spaces() {
        let ember = PathBuf::from("/opt/ember tools/ember");
        let cfg = PathBuf::from("/tmp/my config.toml");
        let out = PathBuf::from("/tmp/out");
        let err = PathBuf::from("/tmp/err");
        let env = BTreeMap::new();
        let unit = render_systemd_unit(&ember, Some(&cfg), &out, &err, &env);
        assert!(
            unit.contains("ExecStart='/opt/ember tools/ember' daemon start --foreground --config '/tmp/my config.toml'"),
            "expected quoted paths; got:\n{unit}"
        );
    }

    #[test]
    fn systemd_quote_quotes_values_with_spaces() {
        assert_eq!(systemd_quote("simple"), "simple");
        assert_eq!(systemd_quote("with space"), "\"with space\"");
        assert_eq!(systemd_quote("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn write_if_changed_skips_identical_content() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("f.txt");
        fs::write(&path, "hello").unwrap();
        let wrote = write_if_changed(&path, "hello").unwrap();
        assert!(!wrote, "identical content should be a no-op");
    }

    #[test]
    fn write_if_changed_overwrites_different_content() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("f.txt");
        fs::write(&path, "old").unwrap();
        let wrote = write_if_changed(&path, "new").unwrap();
        assert!(wrote, "different content should be written");
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn write_if_changed_creates_parent_dir() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nested/deep/f.txt");
        write_if_changed(&path, "hi").unwrap();
        assert!(path.exists());
    }

    #[test]
    fn remove_if_exists_returns_false_when_missing() {
        let tmp = TempDir::new().unwrap();
        let removed = remove_if_exists(&tmp.path().join("nope.txt")).unwrap();
        assert!(!removed);
    }

    #[test]
    fn remove_if_exists_removes_and_returns_true() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("gone.txt");
        fs::write(&path, "bye").unwrap();
        let removed = remove_if_exists(&path).unwrap();
        assert!(removed);
        assert!(!path.exists());
    }

    #[test]
    fn read_pid_returns_none_when_absent() {
        let tmp = TempDir::new().unwrap();
        let pid = read_pid(&tmp.path().join("nope.pid")).unwrap();
        assert!(pid.is_none());
    }

    #[test]
    fn read_pid_parses_valid_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("t.pid");
        fs::write(&path, "12345\n").unwrap();
        assert_eq!(read_pid(&path).unwrap(), Some(12345));
    }

    #[test]
    fn read_pid_errors_on_garbage() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("bad.pid");
        fs::write(&path, "not-a-pid").unwrap();
        match read_pid(&path) {
            Err(AgentError::InvalidPid(s)) => assert_eq!(s, "not-a-pid"),
            other => panic!("expected InvalidPid, got {other:?}"),
        }
    }

    #[test]
    fn reload_errors_cleanly_when_daemon_not_running() {
        let tmp = TempDir::new().unwrap();
        let pid_file = tmp.path().join("missing.pid");
        let socket = tmp.path().join("daemon.sock");
        match reload_daemon(&pid_file, &socket, Duration::from_secs(1)) {
            Err(AgentError::DaemonNotRunning) => {}
            other => panic!("expected DaemonNotRunning, got {other:?}"),
        }
    }

    #[test]
    fn reload_errors_cleanly_when_pid_stale() {
        let tmp = TempDir::new().unwrap();
        let pid_file = tmp.path().join("stale.pid");
        // A very high PID that is virtually guaranteed to be dead.
        let dead_pid: u32 = 999_999;
        let mut f = fs::File::create(&pid_file).unwrap();
        writeln!(f, "{dead_pid}").unwrap();
        let socket = tmp.path().join("daemon.sock");
        match reload_daemon(&pid_file, &socket, Duration::from_secs(1)) {
            Err(AgentError::DaemonNotRunning) => {}
            other => panic!("expected DaemonNotRunning, got {other:?}"),
        }
    }

    #[test]
    fn tail_file_returns_last_n_lines() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("log.txt");
        let content = (1..=10)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, &content).unwrap();
        let tail = tail_file(&path, 3);
        assert_eq!(tail, "line 8\nline 9\nline 10");
    }

    #[test]
    fn tail_file_returns_empty_for_missing_file() {
        let tmp = TempDir::new().unwrap();
        let tail = tail_file(&tmp.path().join("nope.log"), 5);
        assert!(tail.is_empty());
    }

    #[test]
    fn tail_file_returns_all_lines_when_n_exceeds_length() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("short.log");
        fs::write(&path, "only\ntwo").unwrap();
        let tail = tail_file(&path, 100);
        assert_eq!(tail, "only\ntwo");
    }

    #[test]
    fn install_agent_unsupported_platform() {
        // This test only runs meaningfully on non-macOS, non-Linux.
        // On supported platforms it would try to write real plists / units, so
        // we gate it behind cfg.
        if !cfg!(target_os = "macos") && !cfg!(target_os = "linux") {
            match install_agent(None, true) {
                Err(AgentError::UnsupportedPlatform) => {}
                other => panic!("expected UnsupportedPlatform, got {other:?}"),
            }
        }
    }

    #[test]
    fn shell_quote_wraps_paths_with_spaces() {
        assert_eq!(shell_quote("/usr/local/bin/ember"), "/usr/local/bin/ember");
        assert_eq!(shell_quote("/opt/my ember/ember"), "'/opt/my ember/ember'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn xml_escape_handles_all_entities() {
        assert_eq!(xml_escape("a & b"), "a &amp; b");
        assert_eq!(xml_escape("<x>"), "&lt;x&gt;");
        assert_eq!(xml_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(xml_escape("it's"), "it&apos;s");
    }
}
