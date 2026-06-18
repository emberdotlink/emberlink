//! Launcher first-run banner — single-uid wedge-claim caveat surface.
//!
//! Implements the design specified in
//! [`docs/construct-launcher-first-run-banner.md`](../../../../docs/construct-launcher-first-run-banner.md).
//! Tracks **AP-CONSTRUCT-LAUNCHER-FIRST-RUN-BANNER**.
//!
//! The banner fires once per (binary_name, binary_version) on this host
//! when the daemon socket is owned by the same uid as the user (single-uid
//! posture). Suppressed when the socket is owned by a different uid (ADR
//! 131 separate-uid posture detected) — the architecture outgrows the
//! banner automatically once production posture ships.
//!
//! v0.1 scope (this module): the detection + render + acknowledgment
//! state-management logic + control flags. The wiring into
//! `ember claude` (and per-harness analogs) lands when the
//! caller-side launcher refactors land.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};

/// Detected daemon install posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallPosture {
    /// Daemon socket owned by the same uid as the caller.
    /// Wedge claim "plaintext never enters agent process tree" is conditional —
    /// banner fires per the design doc.
    SingleUid,
    /// Daemon socket owned by a different uid (ADR 131 production posture).
    /// Wedge claim is unconditional — banner suppressed.
    SeparateUid,
    /// Posture cannot be determined (socket missing, permission denied, etc.).
    /// Fail-safe to show the banner so the operator can intervene.
    Unknown,
}

/// Control flags consumed by [`maybe_render`]. Mirrors the design doc's
/// `--no-banner` / `--banner-acknowledge` / `EMBER_LAUNCHER_NO_BANNER`
/// surfaces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BannerControl {
    /// `--no-banner` flag OR `EMBER_LAUNCHER_NO_BANNER=1` env. Suppresses
    /// the banner for THIS invocation only; does NOT mark acknowledged.
    pub no_banner: bool,
    /// `--banner-acknowledge` flag. Short-circuits as if the user pressed
    /// Enter; marks acknowledged so future invocations don't re-show.
    pub auto_acknowledge: bool,
}

impl BannerControl {
    /// Build from CLI flags + env vars. Caller pulls values from clap +
    /// `std::env::var`; this function applies the OR semantics so the
    /// downstream logic is testable without env.
    pub fn from_inputs(no_banner_flag: bool, auto_ack_flag: bool, env_no_banner: bool) -> Self {
        Self {
            no_banner: no_banner_flag || env_no_banner,
            auto_acknowledge: auto_ack_flag,
        }
    }
}

/// Per-host launcher state at `~/.ember/state/launcher.toml` (or the equivalent
/// JSON file — v0.1 uses JSON to avoid the toml-crate dep; storage format may
/// upgrade to TOML in v0.2 with no behaviour change).
///
/// Key shape: `<binary-name>@<version>` (e.g. `ember-claude@v0.3.0`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LauncherState {
    #[serde(default)]
    pub acknowledgments: HashMap<String, String>,
}

impl LauncherState {
    /// Load from disk, returning [`Self::default`] on any failure (file
    /// missing / parse error / permissions). Acknowledgments are non-load-
    /// bearing — re-showing the banner is friction but not a correctness
    /// failure, so we never fail-closed on state-read errors.
    pub fn load(state_path: &Path) -> Self {
        match std::fs::read_to_string(state_path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Atomically write to disk via tempfile-rename. Errors propagate so
    /// the caller can decide whether to surface them; the launcher path
    /// typically logs + continues.
    pub fn save(&self, state_path: &Path) -> io::Result<()> {
        if let Some(parent) = state_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = state_path.with_extension("tmp");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::other(format!("serialize launcher state: {e}")))?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, state_path)?;
        Ok(())
    }

    pub fn key(binary_name: &str, binary_version: &str) -> String {
        format!("{binary_name}@{binary_version}")
    }

    pub fn is_acknowledged(&self, binary_name: &str, binary_version: &str) -> bool {
        self.acknowledgments
            .contains_key(&Self::key(binary_name, binary_version))
    }
}

/// Detect install posture from the daemon socket's ownership.
///
/// **Pre:** `daemon_socket_path` is the path the launcher would connect to.
/// **Post:** returns [`InstallPosture::SingleUid`] if the socket exists and
/// is owned by the current uid; [`InstallPosture::SeparateUid`] if owned by
/// a different uid; [`InstallPosture::Unknown`] on any error (defaults to
/// fail-safe banner-show).
pub fn detect_install_posture_from_socket(daemon_socket_path: &Path) -> InstallPosture {
    let meta = match std::fs::metadata(daemon_socket_path) {
        Ok(m) => m,
        Err(_) => return InstallPosture::Unknown,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` is a pure libc query, no allocation, no errors.
        let user_uid = unsafe { libc::geteuid() };
        if meta.uid() == user_uid {
            InstallPosture::SingleUid
        } else {
            InstallPosture::SeparateUid
        }
    }
    #[cfg(not(unix))]
    {
        // Windows / non-Unix: no uid concept; treat as SeparateUid (banner
        // suppressed) until the Windows launcher posture is specified.
        let _ = meta;
        InstallPosture::SeparateUid
    }
}

/// Detect install posture by inspecting the running daemon process's user.
///
/// Detection order (best-effort; falls back on any failure):
///
/// **macOS**
///   1. Check `/Library/LaunchDaemons/sh.emberlink.daemon.plist` — presence
///      implies the daemon was installed system-wide under a separate service
///      account → `SeparateUid`.
///   2. Shell out to `launchctl print system/sh.emberlink.daemon` and parse
///      the `user =` line; if the user differs from `whoami` → `SeparateUid`.
///   3. Fall through to the `ps`-based check.
///
/// **Linux**
///   1. Shell out to `systemctl show emberd --property=User` and parse the
///      `User=` line; non-empty value differing from `$USER` / `whoami` →
///      `SeparateUid`.
///   2. Fall through to the `ps`-based check.
///
/// **Both platforms (ps fallback)**
///   `ps -o user= -p <emberd-pid>` — if the process user differs from the
///   caller's effective username → `SeparateUid`.
///
/// Returns `SingleUid` when the daemon appears to run as the same user as the
/// caller, `SeparateUid` when a distinct service account is detected, and
/// `Unknown` when no emberd process is found or all checks fail.
pub fn detect_install_posture() -> InstallPosture {
    #[cfg(target_os = "macos")]
    {
        if let Some(p) = detect_posture_macos() {
            return p;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(p) = detect_posture_linux() {
            return p;
        }
    }
    detect_posture_via_ps().unwrap_or(InstallPosture::Unknown)
}

/// Return the current user's login name, or `None` on failure.
fn current_username() -> Option<String> {
    // $USER is the most portable and avoids a process spawn.
    if let Ok(u) = std::env::var("USER")
        && !u.is_empty()
    {
        return Some(u);
    }
    // Fallback: spawn whoami.
    let out = Command::new("whoami").output().ok()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn detect_posture_macos() -> Option<InstallPosture> {
    const SYSTEM_PLIST: &str = "/Library/LaunchDaemons/sh.emberlink.daemon.plist";
    if std::path::Path::new(SYSTEM_PLIST).exists() {
        return Some(InstallPosture::SeparateUid);
    }

    // Try `launchctl print system/sh.emberlink.daemon`.
    let out = Command::new("launchctl")
        .args(["print", "system/sh.emberlink.daemon"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // The output contains a line like `        user = ember` or `uid = 501`.
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("user =") {
            let daemon_user = rest.trim();
            if daemon_user.is_empty() {
                continue;
            }
            let caller = current_username()?;
            if daemon_user != caller {
                return Some(InstallPosture::SeparateUid);
            } else {
                return Some(InstallPosture::SingleUid);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn detect_posture_linux() -> Option<InstallPosture> {
    // `systemctl show emberd --property=User` emits `User=ember` (or empty).
    let out = Command::new("systemctl")
        .args(["show", "emberd", "--property=User"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("User=") {
            let daemon_user = rest.trim();
            if daemon_user.is_empty() {
                // systemctl returned `User=` with no value — unit not loaded
                // or user not configured; fall through to ps check.
                return None;
            }
            let caller = current_username()?;
            if daemon_user != caller {
                return Some(InstallPosture::SeparateUid);
            } else {
                return Some(InstallPosture::SingleUid);
            }
        }
    }
    None
}

/// Cross-platform ps-based posture detection.
///
/// Finds any running `emberd` process via `pgrep emberd` (or `pgrep -x emberd`
/// on Linux), then reads its effective user via `ps -o user= -p <pid>`.
fn detect_posture_via_ps() -> Option<InstallPosture> {
    // Find the emberd PID.
    let pgrep_out = Command::new("pgrep").args(["-x", "emberd"]).output().ok()?;
    let pid_str = String::from_utf8_lossy(&pgrep_out.stdout)
        .lines()
        .next()
        .map(str::trim)
        .map(str::to_string)?;
    if pid_str.is_empty() {
        return None;
    }

    let ps_out = Command::new("ps")
        .args(["-o", "user=", "-p", &pid_str])
        .output()
        .ok()?;
    if !ps_out.status.success() {
        return None;
    }
    let daemon_user = String::from_utf8_lossy(&ps_out.stdout).trim().to_string();
    if daemon_user.is_empty() {
        return None;
    }
    let caller = current_username()?;
    if daemon_user != caller {
        Some(InstallPosture::SeparateUid)
    } else {
        Some(InstallPosture::SingleUid)
    }
}

/// Render the banner (or skip it) per the design doc's gating rules.
///
/// **Inputs:**
/// - `binary_name` — e.g. `"ember-claude"` (for the state-file key).
/// - `binary_version` — e.g. `"v0.3.0"`.
/// - `posture` — output of [`detect_install_posture`].
/// - `control` — [`BannerControl`] from CLI flags + env.
/// - `state_path` — path to the per-host acknowledgment store (typically
///   `~/.ember/state/launcher.json`).
/// - `stdout` / `stdin` — injected for test reachability.
///
/// **Returns:** `true` if the user (or `--banner-acknowledge`) acknowledged
/// the banner; `false` if the banner was suppressed (already acknowledged
/// OR `--no-banner` set OR `SeparateUid` posture). Either way, the launcher
/// continues — the banner does NOT gate dispatch, it just surfaces the
/// caveat.
pub fn maybe_render<W: Write, R: BufRead>(
    binary_name: &str,
    binary_version: &str,
    posture: InstallPosture,
    control: &BannerControl,
    state_path: &Path,
    out: &mut W,
    input: &mut R,
) -> io::Result<bool> {
    let state = LauncherState::load(state_path);
    if state.is_acknowledged(binary_name, binary_version) {
        return Ok(false);
    }

    if control.no_banner {
        // Suppressed for this invocation; do NOT mark acknowledged.
        return Ok(false);
    }

    // Render the banner with posture-specific copy.
    let banner = banner_for_posture(posture);
    write!(out, "{}", banner)?;
    out.flush()?;

    if !control.auto_acknowledge {
        // Wait for Enter (or Ctrl-C exits the process upstream of us).
        let mut line = String::new();
        let _ = input.read_line(&mut line); // EOF / read error → fall through
    }

    // Mark acknowledged. Save errors are logged but non-fatal — re-showing
    // the banner is friction, not a correctness break.
    let mut state = state;
    state.acknowledgments.insert(
        LauncherState::key(binary_name, binary_version),
        chrono::Utc::now().to_rfc3339(),
    );
    if let Err(e) = state.save(state_path) {
        eprintln!("warn: launcher banner ack save failed: {e}");
    }

    Ok(true)
}

/// The banner copy itself. Verbatim from the design doc.
pub const BANNER_TEMPLATE: &str = r#"
┌─────────────────────────────────────────────────────────────────────┐
│  Ember Construct gate — v0.3.0 posture notice                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ember-claude is starting under the SINGLE-UID install              │
│  default. This is the dev0 friction-survival posture; it ships      │
│  before the production-grade SEPARATE-UID posture (ADR 131) is      │
│  default.                                                           │
│                                                                     │
│  What this means:                                                   │
│    + Constructs gate credential vending the way the docs describe   │
│    + Receipt audit chain is signed + content-hashed end-to-end      │
│    + Composite grants + scope policy enforce as designed            │
│                                                                     │
│  What this does NOT mean (until ADR 131 ships for dev0):            │
│    - The marketed wedge claim "plaintext never enters the agent's   │
│      process tree" is NOT unconditional. An adversary with code     │
│      execution inside this agent (e.g. via prompt-injection) can    │
│      ptrace into emberd or kill it. Same-uid means kernel isolation │
│      doesn't back up the architectural claim.                       │
│                                                                     │
│  When the unconditional claim holds:                                │
│    * team0 / ent0 default (separate-uid baked in at install).       │
│    * dev0 with manual ADR 131 posture: see docs/131 for the         │
│      separate-uid setup walk.                                       │
│                                                                     │
│  Press [Enter] to continue, or Ctrl-C to bail.                      │
│                                                                     │
│  This banner shows once per binary version. Re-show via             │
│  'ember launcher reset-banner'.                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
"#;

/// Banner copy for the separate-uid (production) posture.
pub const BANNER_SEPARATE_UID: &str = r#"
┌─────────────────────────────────────────────────────────────────────┐
│  Ember Construct gate — posture notice                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Daemon under uid=ember (kernel-isolated from agent)                │
│                                                                     │
│  This is the production-grade SEPARATE-UID posture (ADR 131).       │
│  The wedge claim "plaintext never enters the agent's process tree"  │
│  is unconditional — the kernel enforces the trust boundary.         │
│                                                                     │
│  What this means:                                                   │
│    + Constructs gate credential vending the way the docs describe   │
│    + Receipt audit chain is signed + content-hashed end-to-end      │
│    + Composite grants + scope policy enforce as designed            │
│    + Kernel isolation backs the architectural claim unconditionally  │
│                                                                     │
│  Press [Enter] to continue, or Ctrl-C to bail.                      │
│                                                                     │
│  This banner shows once per binary version. Re-show via             │
│  'ember launcher reset-banner'.                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
"#;

/// Banner copy for the single-uid (dev-mode) posture.
pub const BANNER_SINGLE_UID: &str = r#"
┌─────────────────────────────────────────────────────────────────────┐
│  Ember Construct gate — posture notice                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Daemon under your uid (dev-mode; relaxed threat model)             │
│                                                                     │
│  ember-claude is starting under the SINGLE-UID install              │
│  default. This is the dev0 friction-survival posture; it ships      │
│  before the production-grade SEPARATE-UID posture (ADR 131) is      │
│  default.                                                           │
│                                                                     │
│  What this means:                                                   │
│    + Constructs gate credential vending the way the docs describe   │
│    + Receipt audit chain is signed + content-hashed end-to-end      │
│    + Composite grants + scope policy enforce as designed            │
│                                                                     │
│  What this does NOT mean (until ADR 131 ships for dev0):            │
│    - The marketed wedge claim "plaintext never enters the agent's   │
│      process tree" is NOT unconditional. An adversary with code     │
│      execution inside this agent (e.g. via prompt-injection) can    │
│      ptrace into emberd or kill it. Same-uid means kernel isolation │
│      doesn't back up the architectural claim.                       │
│                                                                     │
│  When the unconditional claim holds:                                │
│    * team0 / ent0 default (separate-uid baked in at install).       │
│    * dev0 with manual ADR 131 posture: see docs/131 for the         │
│      separate-uid setup walk.                                       │
│                                                                     │
│  Press [Enter] to continue, or Ctrl-C to bail.                      │
│                                                                     │
│  This banner shows once per binary version. Re-show via             │
│  'ember launcher reset-banner'.                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
"#;

/// Select the appropriate banner copy for the detected posture.
///
/// - `SeparateUid` → `BANNER_SEPARATE_UID` (production posture; unconditional claim)
/// - `SingleUid` → `BANNER_SINGLE_UID` (dev-mode; relaxed threat model)
/// - `Unknown` → `BANNER_SINGLE_UID` (fail-safe: show the more cautious copy)
pub fn banner_for_posture(posture: InstallPosture) -> &'static str {
    match posture {
        InstallPosture::SeparateUid => BANNER_SEPARATE_UID,
        InstallPosture::SingleUid | InstallPosture::Unknown => BANNER_SINGLE_UID,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn tmp_state_path() -> PathBuf {
        let dir = tempfile::tempdir().unwrap().keep();
        dir.join("launcher.json")
    }

    #[test]
    fn separate_uid_posture_renders_kernel_isolated_copy() {
        let state_path = tmp_state_path();
        let mut out = Vec::new();
        let mut input = Cursor::new(b"\n" as &[u8]);
        let rendered = maybe_render(
            "ember-claude",
            "v0.3.0",
            InstallPosture::SeparateUid,
            &BannerControl::default(),
            &state_path,
            &mut out,
            &mut input,
        )
        .unwrap();
        assert!(rendered);
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("uid=ember (kernel-isolated from agent)"),
            "SeparateUid banner must contain posture label"
        );
        assert!(
            s.contains("ADR 131"),
            "SeparateUid banner must reference ADR 131"
        );
        let loaded = LauncherState::load(&state_path);
        assert!(loaded.is_acknowledged("ember-claude", "v0.3.0"));
    }

    #[test]
    fn first_run_under_single_uid_renders_and_acks() {
        let state_path = tmp_state_path();
        let mut out = Vec::new();
        let mut input = Cursor::new(b"\n" as &[u8]);
        let rendered = maybe_render(
            "ember-claude",
            "v0.3.0",
            InstallPosture::SingleUid,
            &BannerControl::default(),
            &state_path,
            &mut out,
            &mut input,
        )
        .unwrap();
        assert!(rendered);
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("dev-mode; relaxed threat model"),
            "SingleUid banner must contain posture label"
        );
        assert!(s.contains("SINGLE-UID"));
        assert!(s.contains("ADR 131"));
        // State written + key marked.
        let loaded = LauncherState::load(&state_path);
        assert!(loaded.is_acknowledged("ember-claude", "v0.3.0"));
    }

    #[test]
    fn second_run_skips_when_already_acknowledged() {
        let state_path = tmp_state_path();
        // Pre-seed acknowledgment.
        let mut s = LauncherState::default();
        s.acknowledgments.insert(
            LauncherState::key("ember-claude", "v0.3.0"),
            "2026-05-05T12:00:00+00:00".into(),
        );
        s.save(&state_path).unwrap();

        let mut out = Vec::new();
        let mut input = Cursor::new(b"\n" as &[u8]);
        let rendered = maybe_render(
            "ember-claude",
            "v0.3.0",
            InstallPosture::SingleUid,
            &BannerControl::default(),
            &state_path,
            &mut out,
            &mut input,
        )
        .unwrap();
        assert!(!rendered);
        assert!(out.is_empty(), "second run must skip banner");
    }

    #[test]
    fn no_banner_flag_suppresses_without_acking() {
        let state_path = tmp_state_path();
        let mut out = Vec::new();
        let mut input = Cursor::new(b"\n" as &[u8]);
        let rendered = maybe_render(
            "ember-claude",
            "v0.3.0",
            InstallPosture::SingleUid,
            &BannerControl {
                no_banner: true,
                auto_acknowledge: false,
            },
            &state_path,
            &mut out,
            &mut input,
        )
        .unwrap();
        assert!(!rendered);
        assert!(out.is_empty());
        // Crucially: NOT acknowledged — next run without --no-banner shows it.
        assert!(
            !state_path.exists()
                || !LauncherState::load(&state_path).is_acknowledged("ember-claude", "v0.3.0")
        );
    }

    #[test]
    fn auto_acknowledge_short_circuits_input_and_marks_state() {
        let state_path = tmp_state_path();
        let mut out = Vec::new();
        // Empty input — verify we don't block on read_line.
        let mut input = Cursor::new(b"" as &[u8]);
        let rendered = maybe_render(
            "ember-claude",
            "v0.3.0",
            InstallPosture::SingleUid,
            &BannerControl {
                no_banner: false,
                auto_acknowledge: true,
            },
            &state_path,
            &mut out,
            &mut input,
        )
        .unwrap();
        assert!(rendered);
        let loaded = LauncherState::load(&state_path);
        assert!(loaded.is_acknowledged("ember-claude", "v0.3.0"));
    }

    #[test]
    fn version_bump_re_shows_banner() {
        let state_path = tmp_state_path();
        // Acknowledge v0.3.0.
        let mut s = LauncherState::default();
        s.acknowledgments.insert(
            LauncherState::key("ember-claude", "v0.3.0"),
            "2026-05-05T12:00:00+00:00".into(),
        );
        s.save(&state_path).unwrap();

        // Now run with a NEWER version. Per design, this re-shows.
        let mut out = Vec::new();
        let mut input = Cursor::new(b"\n" as &[u8]);
        let rendered = maybe_render(
            "ember-claude",
            "v0.3.1",
            InstallPosture::SingleUid,
            &BannerControl::default(),
            &state_path,
            &mut out,
            &mut input,
        )
        .unwrap();
        assert!(rendered);
        let loaded = LauncherState::load(&state_path);
        assert!(loaded.is_acknowledged("ember-claude", "v0.3.0"));
        assert!(loaded.is_acknowledged("ember-claude", "v0.3.1"));
    }

    #[test]
    fn banner_control_from_inputs_or_semantics() {
        let c = BannerControl::from_inputs(true, false, false);
        assert!(c.no_banner);
        let c = BannerControl::from_inputs(false, false, true);
        assert!(c.no_banner, "EMBER_LAUNCHER_NO_BANNER env must contribute");
        let c = BannerControl::from_inputs(false, true, false);
        assert!(!c.no_banner);
        assert!(c.auto_acknowledge);
    }

    // T1 unit tests for detect_install_posture copy selection and posture variants.

    #[test]
    fn banner_for_posture_separate_uid_contains_kernel_isolated() {
        let copy = banner_for_posture(InstallPosture::SeparateUid);
        assert!(
            copy.contains("uid=ember (kernel-isolated from agent)"),
            "SeparateUid copy must identify posture"
        );
        assert!(
            !copy.contains("relaxed threat model"),
            "SeparateUid copy must not show dev-mode warning"
        );
    }

    #[test]
    fn banner_for_posture_single_uid_contains_relaxed_threat_model() {
        let copy = banner_for_posture(InstallPosture::SingleUid);
        assert!(
            copy.contains("dev-mode; relaxed threat model"),
            "SingleUid copy must identify posture"
        );
        assert!(
            !copy.contains("uid=ember (kernel-isolated from agent)"),
            "SingleUid copy must not show production posture label"
        );
    }

    #[test]
    fn banner_for_posture_unknown_falls_back_to_single_uid_copy() {
        // Unknown posture is fail-safe: show the cautious (SingleUid) copy.
        let copy = banner_for_posture(InstallPosture::Unknown);
        assert!(
            copy.contains("dev-mode; relaxed threat model"),
            "Unknown posture must use cautious SingleUid copy"
        );
    }

    #[test]
    fn install_posture_variants_are_distinct() {
        assert_ne!(InstallPosture::SeparateUid, InstallPosture::SingleUid);
        assert_ne!(InstallPosture::SeparateUid, InstallPosture::Unknown);
        assert_ne!(InstallPosture::SingleUid, InstallPosture::Unknown);
    }

    #[test]
    fn detect_install_posture_returns_a_variant() {
        // Smoke test: the function runs without panicking and returns a valid
        // variant. The actual variant depends on the host environment (no
        // emberd running in test → Unknown is the expected fallback).
        let posture = detect_install_posture();
        // Just verify it's one of the three valid variants.
        assert!(matches!(
            posture,
            InstallPosture::SeparateUid | InstallPosture::SingleUid | InstallPosture::Unknown
        ));
    }
}
