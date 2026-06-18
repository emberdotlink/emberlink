//! Headless pre-flight scope-check substrate (Phase 1).
//!
//! Per ADR 139 §"Pre-flight scope check at enrollment" Layer 2: at
//! enrollment time, the CLI surfaces recent permission-gap entries
//! scoped to the enrolling persona so the operator can widen the
//! template for the enrollment duration.
//!
//! This module is the **shape** of the pre-flight CTA caller. Phase 1
//! ships the substrate — daemon socket call, CTA renderer, and
//! [`PreflightDecision`] enum — without wiring it into an actual
//! `ember headless enroll` command (that command does not yet exist).
//! Phase 2 will:
//!   - wire this helper into the enrollment flow,
//!   - apply per-enrollment template amendments that revert at expiry,
//!   - amend the enrollment Receipt with the widen-template evidence
//!     (needs a new Receipt-kind catalog entry).
//!


use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// One aggregated permission-gap entry as returned by the daemon's
/// `headless_preflight_gaps` socket method. Mirrors
/// `ember_forge::permission_gaps::PermissionGap` on the wire — kept as
/// a local type here so the CLI does not need a direct `internal-automation`
/// dependency for this small wire shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionGap {
    pub command: String,
    pub count: u32,
    pub last_seen: String,
}

/// Caller's decision after viewing the pre-flight CTA. The variants
/// match the brief's `[Y/n/skip]` prompt shape — see ADR 139 §"Pre-flight
/// scope check at enrollment".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightDecision {
    /// `Y` (default): widen the template to include the surfaced
    /// actions, *for this enrollment duration only*. The template
    /// amendment reverts at enrollment expiry. Phase 2 wires the
    /// actual amendment + revert; Phase 1 stops at the decision
    /// shape.
    WidenTemplate,
    /// `n`: cancel enrollment. The caller aborts the enrollment flow.
    Cancel,
    /// `skip`: enroll without amending; later out-of-template tasks
    /// fail-closed. This is also the Phase 1 stubbed default when no
    /// interactive prompt has been wired (see
    /// [`preflight_gaps_cta`]).
    Skip,
}

/// Errors surfaced by the pre-flight helper. Each variant maps to a
/// CLI exit code via the caller (the wiring of this enum into a
/// `ember headless enroll` flow is Phase 2; for now this is the
/// programmatic surface).
#[derive(Debug)]
pub enum PreflightError {
    /// The daemon socket was unreachable. The CLI's caller should
    /// surface the standard `ember status` / `sudo ember daemon install`
    /// repair hint.
    DaemonUnavailable {
        socket: PathBuf,
        source: std::io::Error,
    },
    /// Operator-facing guidance for authority / locked-session failures.
    Guidance(String),
    /// The daemon returned a JSON-RPC error.
    DaemonRpc { code: i32, message: String },
    /// Wire / I/O error talking to the daemon socket.
    Io(String),
    /// Protocol error — malformed JSON-RPC response shape.
    Protocol(String),
}

impl std::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreflightError::DaemonUnavailable { socket, source } => {
                write!(f, "{}", crate::format_daemon_unavailable(socket, source))
            }
            PreflightError::Guidance(s) => write!(f, "{s}"),
            PreflightError::DaemonRpc { code, message } => {
                write!(f, "daemon error ({code}): {message}")
            }
            PreflightError::Io(s) => write!(f, "daemon socket I/O: {s}"),
            PreflightError::Protocol(s) => write!(f, "daemon socket protocol: {s}"),
        }
    }
}

impl std::error::Error for PreflightError {}

/// Default look-back window for Layer 2 historical pre-flight: 7 days,
/// matching the CTA copy in ADR 139.
pub const DEFAULT_LOOKBACK_SECS: u64 = 7 * 86400;

/// Format the CTA bullet block for a non-empty gap list. Returns
/// `None` when `gaps` is empty (the caller skips rendering the CTA
/// entirely in that case). Public so a future Phase 2 caller can
/// snapshot the rendered CTA into the enrollment Receipt.
pub fn format_cta(persona: &str, gaps: &[PermissionGap], lookback: Duration) -> Option<String> {
    if gaps.is_empty() {
        return None;
    }
    let days = (lookback.as_secs() / 86400).max(1);
    let mut buf = String::new();
    buf.push_str(&format!("  Pre-flight check (last {days} days):\n\n"));
    buf.push_str(&format!(
        "  Recent permission gaps for persona \"{persona}\":\n"
    ));
    for gap in gaps {
        buf.push_str(&format!(
            "    • {} — {} fails (last {})\n",
            gap.command, gap.count, gap.last_seen
        ));
    }
    buf.push_str("\n  Widen template to include these actions for this\n");
    buf.push_str("  enrollment? [Y/n/skip]\n");
    Some(buf)
}

/// Pre-flight Layer 2 (historical) CTA entry point.
///
/// Calls the daemon's `headless_preflight_gaps` method, formats the
/// CTA block, and returns the operator's [`PreflightDecision`]. Phase
/// 1 does NOT wire an interactive prompt; instead it returns
/// [`PreflightDecision::Skip`] unconditionally so the substrate
/// compiles and exercises the daemon round-trip end-to-end. Phase 2
/// wires the actual `[Y/n/skip]` prompt against the rendered CTA.
///
/// Returns:
///   - `Ok((decision, Some(cta)))` when gaps exist — the caller would
///     print `cta` and consume `decision` (Phase 1 stub: `Skip`).
///   - `Ok((decision, None))` when no gaps exist — no CTA to render;
///     the caller proceeds straight through. `decision` is `Skip`.
///   - `Err(PreflightError)` on daemon / wire failures.
///
/// `lookback` defaults to [`DEFAULT_LOOKBACK_SECS`] — pass `None` to
/// use the default.
pub fn preflight_gaps_cta(
    socket_path: &Path,
    persona: &str,
    lookback: Option<Duration>,
) -> Result<(PreflightDecision, Option<String>), PreflightError> {
    let lookback = lookback.unwrap_or(Duration::from_secs(DEFAULT_LOOKBACK_SECS));
    let gaps = fetch_gaps(socket_path, persona, lookback)?;
    let cta = format_cta(persona, &gaps, lookback);
    // Phase 1 stub: return `Skip` unconditionally. Phase 2 wires the
    // interactive prompt and the per-enrollment template amendment
    // path once the headless enroll command lands.
    Ok((PreflightDecision::Skip, cta))
}

/// Fetch the gap list from the daemon. Public so Phase 2 callers can
/// re-fetch (e.g. after a retry) without re-rendering the CTA.
pub fn fetch_gaps(
    socket_path: &Path,
    persona: &str,
    lookback: Duration,
) -> Result<Vec<PermissionGap>, PreflightError> {
    let params = json!({
        "persona": persona,
        "since_seconds": lookback.as_secs(),
    });
    let result = call_daemon(socket_path, "headless_preflight_gaps", &params)?;
    serde_json::from_value::<Vec<PermissionGap>>(result)
        .map_err(|e| PreflightError::Protocol(format!("decode PermissionGap list: {e}")))
}

/// Send a synchronous JSON-RPC request over the daemon's Unix-domain
/// socket. Mirrors the call pattern used by `broker.rs::call_daemon`
/// so the wire-level handshake stays identical across CLI surfaces.
fn call_daemon(socket_path: &Path, method: &str, params: &Value) -> Result<Value, PreflightError> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
        PreflightError::DaemonUnavailable {
            socket: socket_path.to_path_buf(),
            source: e,
        }
    })?;

    let mut writer = stream
        .try_clone()
        .map_err(|e| PreflightError::Io(format!("clone socket: {e}")))?;
    let mut reader = BufReader::new(stream);

    let request = json!({
        "id": "1",
        "method": method,
        "params": params,
    });
    let mut line = serde_json::to_string(&request).expect("serialize request");
    line.push('\n');

    writer
        .write_all(line.as_bytes())
        .map_err(|e| PreflightError::Io(format!("write request: {e}")))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| PreflightError::Io(format!("read response: {e}")))?;

    let response: Value = serde_json::from_str(response_line.trim())
        .map_err(|e| PreflightError::Protocol(format!("invalid JSON-RPC response: {e}")))?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        if let Some(guidance) = headless_guidance_for_rpc(method, code, &message) {
            return Err(PreflightError::Guidance(guidance));
        }
        return Err(PreflightError::DaemonRpc { code, message });
    }

    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

fn headless_guidance_for_rpc(method: &str, code: i32, message: &str) -> Option<String> {
    let is_locked = code == -32030
        && (message.contains("session is locked")
            || message.contains("vault unavailable")
            || message.contains("session auto-locked"));

    if matches!(
        method,
        "headless_enroll"
            | "headless_revoke"
            | "headless_status"
            | "headless_preflight_gaps"
            | "headless_preflight_layer1"
    ) && (is_locked || (code == -32001 && message.contains("authority_class_not_met")))
    {
        return Some(
            "this headless action needs operator presence on the daemon-managed vault lane. \
             Use the managed separate-uid biometric unlock flow when available, or restart the \
             daemon with `EMBER_VAULT_PASSPHRASE` for a fresh dev-probe bootstrap; same-daemon \
             operator-uid reopen is intentionally disabled."
                .to_string(),
        );
    }

    None
}

// ─── Headless enroll / revoke / status commands ──────────────────────
//
// CLI surface for the daemon-side `headless_enroll` / `headless_revoke` /
// `headless_status` socket methods that shipped in PR #2578.
// Per ADR 139 §"Headless: attested device, variable enrollment".
// The daemon-side handlers
// now ship a first real local enroll/revoke/status workflow. `headless_enroll`
// installs a fresh headless MEK plus the currently configured local
// broker-authority subset; `headless_revoke` and `headless_status` operate on
// that persisted enrollment substrate. Template-bounded shaping and Receipt
// emission are still follow-up work.
//
// The brief's nominal path was `crates/emberlink-cli/src/commands/headless.rs`;
// the actual home is this top-level file because `commands.rs` is a
// single ~8000-line module rather than a directory (see the
// file-header rationale above). The `cmd_*` functions below are
// invoked from `bin/ember.rs::Commands::Headless`.
//
// **HITL gate:** the CTA-copy-review task locks the wording for
// ADR 139's daemon-vault-unlock posture before this slice merges.
// Implementation can proceed; merge waits on the copy lock.
//
// **T3 lifecycle (manual pre-demo):** the full enroll → autopilot →
// expiry → autopilot-fails round-trip is documented as a qember.sh
// T3 scenario rather than an automated test:
//
//   1. `qember.sh demo up` — clean daemon + vault.
//   2. `ember headless enroll --duration 1m --persona main --yes`
//      → installs the current local broker-authority subset into the
//      headless scope. A future slice adds the `headless_enrollment`
//      Receipt.
//   3. `ember headless status` → shows the active enrollment.
//   4. Wait 1 minute. (Future slice: status flips to expired; subsequent
//      autopilot-credential requests fail with `headless_enrollment_expired`.)
//   5. `ember headless revoke` — cleans up the enrollment.
//
// The clap-level smoke tests live in
// `crates/emberlink-cli/tests/headless_cli_smoke.rs`.

/// Tier-0 (dev0) ceiling on headless enrollment duration. Matches the
/// `MAX_DURATION_DEV0_SECONDS` constant on the daemon side
/// (`crates/ember-daemon/src/infra/handler.rs::headless_enroll` arm).
pub const HEADLESS_TIER0_MAX_SECS: u64 = 7 * 86400;

/// Default enrollment duration for dev0 (4h), mirroring the daemon-side
/// default applied when `duration_seconds` is 0 / unset.
pub const HEADLESS_DEFAULT_DURATION_SECS: u64 = 4 * 3600;

/// Errors specific to the headless command surface. Wraps
/// [`PreflightError`] for daemon-RPC failures and adds the user-facing
/// variants that the interactive enroll flow needs.
#[derive(Debug)]
pub enum HeadlessCommandError {
    /// Duration spec couldn't be parsed (e.g. `"forever"`).
    InvalidDuration(String),
    /// Duration exceeds the tier ceiling at this cohort (`HEADLESS_TIER0_MAX_SECS`).
    DurationExceedsCeiling { requested: u64, max: u64 },
    /// Operator answered `n` at the confirmation prompt.
    Cancelled,
    /// Bounded headless enrollment requires an explicit queued task
    /// declaration so the daemon can derive authority and material subsets.
    MissingTaskDeclaration,
    /// The queued task declaration was absent, empty, or malformed.
    InvalidTaskDeclaration(String),
    /// Daemon-RPC layer surfaced an error (socket, wire, protocol).
    Preflight(PreflightError),
    /// I/O failure reading from stdin / writing to stdout for the
    /// interactive prompt.
    Io(String),
}

impl std::fmt::Display for HeadlessCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeadlessCommandError::InvalidDuration(spec) => {
                write!(
                    f,
                    "invalid duration '{spec}' — expected a value like '4h', '3d', or '1w'"
                )
            }
            HeadlessCommandError::DurationExceedsCeiling { requested, max } => {
                write!(
                    f,
                    "duration {requested}s exceeds tier ceiling {max}s ({}d at dev0)",
                    max / 86400
                )
            }
            HeadlessCommandError::Cancelled => write!(f, "enrollment cancelled"),
            HeadlessCommandError::MissingTaskDeclaration => write!(
                f,
                "bounded headless enrollment requires `--input <tasks.json>`; run `ember headless preflight --input <tasks.json>` first, then enroll with the same file"
            ),
            HeadlessCommandError::InvalidTaskDeclaration(message) => {
                write!(f, "invalid headless task declaration: {message}")
            }
            HeadlessCommandError::Preflight(e) => write!(f, "{e}"),
            HeadlessCommandError::Io(s) => write!(f, "interactive prompt I/O: {s}"),
        }
    }
}

impl std::error::Error for HeadlessCommandError {}

impl From<PreflightError> for HeadlessCommandError {
    fn from(e: PreflightError) -> Self {
        HeadlessCommandError::Preflight(e)
    }
}

/// CLI arguments for `ember headless enroll`. Mirrored on the clap
/// side in `bin/ember.rs::EnrollArgs`. Kept here so non-binary callers
/// (tests, future SDK wrappers) can construct the same input shape.
#[derive(Debug, Clone, Default)]
pub struct EnrollArgs {
    /// Path to a JSON file containing at least `{ "tasks": [...] }`.
    /// The same file should be used with `ember headless preflight`.
    pub input_json_path: Option<PathBuf>,
    /// Duration spec; `None` falls back to the 4h default.
    pub duration: Option<String>,
    /// Persona to enroll; `None` uses `"main"` (matches the daemon-side
    /// default persona in the `headless_enroll` handler).
    pub persona: Option<String>,
    /// Skip the interactive `[Y/n]` confirm — useful for scripted use
    /// (qember.sh T3, smoke tests).
    pub yes: bool,
}

/// CLI arguments for `ember headless revoke`.
#[derive(Debug, Clone, Default)]
pub struct RevokeArgs {
    /// Enrollment ID to revoke. When `None`, the daemon revokes the
    /// only active enrollment (Phase 2 semantics — today the daemon
    /// stub does not require this field).
    pub enrollment_id: Option<String>,
}

/// Parse a duration spec like `"4h"`, `"3d"`, `"1w"`, `"30m"`, `"5s"`
/// into seconds. Returns [`HeadlessCommandError::InvalidDuration`] on
/// any parse failure (empty string, unknown suffix, non-numeric body).
///
/// Recognized suffixes (single-character): `s` seconds, `m` minutes,
/// `h` hours, `d` days, `w` weeks. Bare integers (no suffix) are
/// rejected so the operator can't accidentally pass `"4"` (4 of what?).
pub fn parse_duration_spec(spec: &str) -> Result<Duration, HeadlessCommandError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(HeadlessCommandError::InvalidDuration(spec.to_string()));
    }
    let (body, unit) = spec.split_at(spec.len() - 1);
    let body = body.trim();
    let n: u64 = body
        .parse()
        .map_err(|_| HeadlessCommandError::InvalidDuration(spec.to_string()))?;
    let secs = match unit {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        "d" => n.saturating_mul(86400),
        "w" => n.saturating_mul(7 * 86400),
        _ => return Err(HeadlessCommandError::InvalidDuration(spec.to_string())),
    };
    Ok(Duration::from_secs(secs))
}

/// Render the CTA copy block printed before the `[Y/n]` confirm during
/// `ember headless enroll`. The exact wording is locked by ADR 139's
/// CTA copy review; this implementation matches the brief's snapshot
/// of that copy. Public
/// so the rendered string can be snapshot-tested AND so a future Phase 2
/// caller can embed the rendered CTA into the enrollment Receipt.
pub fn render_enroll_cta(duration_display: &str) -> String {
    let mut buf = String::new();
    buf.push_str("\n  Enable bounded headless work — for how long?\n\n");
    buf.push_str("  Default: 4 hours.\n");
    buf.push_str("  You can choose anything up to 7 days.\n\n");
    buf.push_str("  Posture: strict + delegated. Out-of-scope work denies\n");
    buf.push_str("  instead of prompting while you're away.\n\n");
    buf.push_str("  Scope: derived from the queued tasks in `--input` plus their\n");
    buf.push_str("  declared vault/env/file materials. Undeclared material is not\n");
    buf.push_str("  carried into the unattended lane.\n\n");
    buf.push_str("  Evidence: enrollment emits a receipt; revoke or expiry closes\n");
    buf.push_str("  the unattended window.\n\n");
    buf.push_str("  Revoke any time: `ember headless revoke`.\n\n");
    buf.push_str(&format!("  Duration [{duration_display}]:\n"));
    buf.push_str(&format!(
        "  Confirm enrollment for {duration_display}? [Y/n]:\n"
    ));
    buf
}

/// Format a duration as `"<N>(h|d|w)"` using the largest clean unit that
/// divides without remainder. Falls back to `"<seconds>s"` for awkward
/// values. Used to render the CTA copy + the daemon's response.
fn format_duration_display(secs: u64) -> String {
    if secs == 0 {
        return "0s".to_string();
    }
    if secs.is_multiple_of(7 * 86400) {
        return format!("{}w", secs / (7 * 86400));
    }
    if secs.is_multiple_of(86400) {
        return format!("{}d", secs / 86400);
    }
    if secs.is_multiple_of(3600) {
        return format!("{}h", secs / 3600);
    }
    if secs.is_multiple_of(60) {
        return format!("{}m", secs / 60);
    }
    format!("{secs}s")
}

/// `ember headless enroll [--duration <spec>] [--persona <id>] [--yes]`.
///
/// Interactive flow:
///   1. Resolve duration (CLI arg → default 4h).
///   2. Validate against `HEADLESS_TIER0_MAX_SECS` (CLI-side; the
///      daemon re-checks).
///   3. Load a non-empty queued task declaration from `--input`.
///   4. Print the CTA copy (Y/n confirm). `--yes` skips this.
///   5. Call `headless_enroll` socket method on the daemon.
///   6. Print the daemon's response.
pub fn cmd_enroll(socket_path: &Path, args: EnrollArgs) -> Result<(), HeadlessCommandError> {
    let duration = match &args.duration {
        Some(spec) => parse_duration_spec(spec)?,
        None => Duration::from_secs(HEADLESS_DEFAULT_DURATION_SECS),
    };
    let secs = duration.as_secs();
    if secs > HEADLESS_TIER0_MAX_SECS {
        return Err(HeadlessCommandError::DurationExceedsCeiling {
            requested: secs,
            max: HEADLESS_TIER0_MAX_SECS,
        });
    }
    let persona = args.persona.as_deref().unwrap_or("main");
    let duration_display = format_duration_display(secs);
    let input_path = args
        .input_json_path
        .as_ref()
        .ok_or(HeadlessCommandError::MissingTaskDeclaration)?;
    let input = read_json_file(input_path)?;
    let tasks = require_non_empty_tasks(&input)?;

    if !args.yes {
        print!("{}", render_enroll_cta(&duration_display));
        // Read a line; bare Enter accepts the default (Y).
        use std::io::Write as _;
        std::io::stdout()
            .flush()
            .map_err(|e| HeadlessCommandError::Io(format!("flush stdout: {e}")))?;
        let mut response = String::new();
        std::io::stdin()
            .read_line(&mut response)
            .map_err(|e| HeadlessCommandError::Io(format!("read stdin: {e}")))?;
        if !confirm_response_accepts(&response) {
            return Err(HeadlessCommandError::Cancelled);
        }
    }

    let params = json!({
        "persona_id": persona,
        "duration_seconds": secs,
        "tasks": tasks,
    });
    let result = call_daemon(socket_path, "headless_enroll", &params)?;
    println!(
        "enrollment: {}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );
    Ok(())
}

/// `ember headless revoke [--enrollment-id <id>]`.
pub fn cmd_revoke(socket_path: &Path, args: RevokeArgs) -> Result<(), HeadlessCommandError> {
    let params = match args.enrollment_id {
        Some(id) => json!({ "enrollment_id": id }),
        None => json!({}),
    };
    let result = call_daemon(socket_path, "headless_revoke", &params)?;
    println!(
        "revoked: {}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );
    Ok(())
}

/// `ember headless status`. Prints the daemon's `active_enrollment`
/// payload (or `none` when Phase 1 stub returns null).
pub fn cmd_status(socket_path: &Path) -> Result<(), HeadlessCommandError> {
    let result = call_daemon(socket_path, "headless_status", &json!({}))?;
    let active = result
        .get("active_enrollment")
        .cloned()
        .unwrap_or(Value::Null);
    if active.is_null() {
        println!("active enrollment: none");
    } else {
        println!(
            "active enrollment: {}",
            serde_json::to_string_pretty(&active).unwrap_or_default()
        );
    }
    Ok(())
}

// ─── Layer 1 pre-flight Constructs — CLI surface ──────────────────────
//
//
// `ember headless preflight` shells the daemon's
// `headless_preflight_layer1` RPC, then renders the gap list as a
// human-readable table (or `no gaps` when the response is empty). Per
// ADR 139 §"Pre-flight scope check at enrollment" Layer 1: this surface
// gives the operator a way to dry-run a candidate queue against the
// enrolled persona's template before autopilot dispatches a task that
// would fail-closed at credential-mint time.
//
// Phase 2 (this slice) ships the wire path + JSON output mode. The
// integration into `ember headless enroll` (so the CTA renders the
// Layer 1 gap list inline) is gated on the brief lock for the L1 CTA
// copy — out of scope for this slice.

/// One Layer-1 pre-flight gap row, mirroring the daemon's wire shape
/// from `handle_headless_preflight_layer1`. Local type so the CLI does
/// not need a direct `internal-automation` dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightLayer1Gap {
    pub task_id: String,
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// One task entry consumed by [`cmd_preflight`]. Mirrors the daemon's
/// wire shape `{ task_id, constructs }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightTaskInput {
    pub task_id: String,
    #[serde(default)]
    pub constructs: Vec<String>,
}

/// CLI arguments for `ember headless preflight`. The L1 resolver needs a
/// task list + template; this slice accepts both as inline JSON arrays
/// so the surface compiles + tests cleanly without an upstream loader.
/// A follow-up will wire `--from-tasks-toml` to load ready-state tasks
/// from `tasks.toml` automatically.
#[derive(Debug, Clone, Default)]
pub struct PreflightArgs {
    /// Path to a JSON file containing the input shape
    /// `{ "tasks": [...], "template": [...] }`. When `None`, the
    /// command sends an empty input (useful for smoke-testing the
    /// RPC's round-trip without authoring fixtures).
    pub input_json_path: Option<PathBuf>,
    /// Emit the daemon's raw JSON gap list instead of the human-readable
    /// table. Useful for scripting + CI assertions.
    pub json: bool,
}

/// Format a non-empty gap list as a fixed-width table. Returns the
/// canonical "no gaps" line when `gaps` is empty. Public so a future
/// caller can snapshot the rendered output for tests.
pub fn format_preflight_gap_table(gaps: &[PreflightLayer1Gap]) -> String {
    if gaps.is_empty() {
        return "no gaps — autopilot can run the queue under the enrolled template\n".to_string();
    }
    // Column widths: max content width within each column, with a
    // minimum-of-header floor so the header always fits.
    let id_w = gaps
        .iter()
        .map(|g| g.task_id.len())
        .max()
        .unwrap_or(0)
        .max("TASK".len());
    let perm_w = gaps
        .iter()
        .map(|g| g.identifier.len())
        .max()
        .unwrap_or(0)
        .max("PERMISSION".len());

    let mut buf = String::new();
    buf.push_str(&format!(
        "{:id_w$}  {:perm_w$}  SCOPE\n",
        "TASK",
        "PERMISSION",
        id_w = id_w,
        perm_w = perm_w
    ));
    for gap in gaps {
        buf.push_str(&format!(
            "{:id_w$}  {:perm_w$}  {}\n",
            gap.task_id,
            gap.identifier,
            gap.scope.as_deref().unwrap_or("-"),
            id_w = id_w,
            perm_w = perm_w
        ));
    }
    buf.push_str(&format!(
        "\n{} gap(s) — widen the template or shrink the queue\n",
        gaps.len()
    ));
    buf
}

/// `ember headless preflight [--input <path>] [--json]`.
///
/// Calls the daemon's `headless_preflight_layer1` socket method with
/// the supplied task list + template and prints the gap list. The input
/// JSON shape is `{ "tasks": [{ "task_id", "constructs" }], "template": [..] }`.
/// When `--input` is omitted, the command sends `{ "tasks": [] }` — a
/// smoke probe that exercises the round-trip without requiring fixture
/// authoring. Returns a non-zero exit code when the daemon RPC returns
/// an error.
pub fn cmd_preflight(socket_path: &Path, args: PreflightArgs) -> Result<(), HeadlessCommandError> {
    let params = match &args.input_json_path {
        Some(path) => read_json_file(path)?,
        None => json!({ "tasks": [] }),
    };
    let result = call_daemon(socket_path, "headless_preflight_layer1", &params)?;
    let gaps: Vec<PreflightLayer1Gap> = serde_json::from_value(result.clone())
        .map_err(|e| PreflightError::Protocol(format!("decode gap list: {e}")))?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&gaps).unwrap_or_else(|_| "[]".to_string())
        );
    } else {
        print!("{}", format_preflight_gap_table(&gaps));
    }
    Ok(())
}

fn read_json_file(path: &Path) -> Result<Value, HeadlessCommandError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| HeadlessCommandError::Io(format!("read {}: {e}", path.display())))?;
    serde_json::from_str::<Value>(&raw)
        .map_err(|e| HeadlessCommandError::Io(format!("parse {}: {e}", path.display())))
}

fn require_non_empty_tasks(input: &Value) -> Result<Value, HeadlessCommandError> {
    let tasks = input.get("tasks").ok_or_else(|| {
        HeadlessCommandError::InvalidTaskDeclaration(
            "missing top-level `tasks` array in input JSON".to_string(),
        )
    })?;
    match tasks.as_array() {
        Some(tasks) if !tasks.is_empty() => Ok(Value::Array(tasks.clone())),
        Some(_) => Err(HeadlessCommandError::InvalidTaskDeclaration(
            "`tasks` must contain at least one queued task".to_string(),
        )),
        None => Err(HeadlessCommandError::InvalidTaskDeclaration(
            "`tasks` must be an array".to_string(),
        )),
    }
}

/// True iff the operator's response to the `[Y/n]` confirm accepts the
/// enrollment. Empty (bare Enter) and `y`/`Y`/`yes`/`Yes` accept;
/// anything else (including `n`, `no`, `skip`, garbage) cancels. The
/// `skip` variant from the pre-flight prompt is NOT recognized here —
/// this is the enroll-confirm, not the pre-flight CTA.
pub fn confirm_response_accepts(response: &str) -> bool {
    let trimmed = response.trim().to_ascii_lowercase();
    trimmed.is_empty() || trimmed == "y" || trimmed == "yes"
}

// ─── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty gap list → no CTA block to render.
    #[test]
    fn format_cta_returns_none_for_empty_gaps() {
        let cta = format_cta("main", &[], Duration::from_secs(7 * 86400));
        assert!(cta.is_none(), "empty gaps should suppress the CTA");
    }

    /// Single-gap list renders the canonical CTA block per ADR 139's
    /// example copy.
    #[test]
    fn format_cta_renders_canonical_shape() {
        let gaps = vec![PermissionGap {
            command: "ember-gh.pr.merge".to_string(),
            count: 3,
            last_seen: "2026-05-10T11:30:00Z".to_string(),
        }];
        let cta = format_cta("main", &gaps, Duration::from_secs(7 * 86400)).expect("non-empty");

        // Spot-check the load-bearing lines — the full block format
        // is documented in ADR 139's CTA example. Use `contains` to
        // keep the test loose on whitespace.
        assert!(cta.contains("Pre-flight check (last 7 days):"));
        assert!(cta.contains("Recent permission gaps for persona \"main\":"));
        assert!(cta.contains("• ember-gh.pr.merge — 3 fails"));
        assert!(cta.contains("Widen template to include these actions"));
        assert!(cta.contains("[Y/n/skip]"));
    }

    /// Multiple gaps render multiple bullets in the order received
    /// (the daemon side sorts deterministically; the CLI does not
    /// re-sort).
    #[test]
    fn format_cta_renders_multiple_bullets_in_order() {
        let gaps = vec![
            PermissionGap {
                command: "ember-gh.pr.merge".to_string(),
                count: 3,
                last_seen: "2026-05-10T11:30:00Z".to_string(),
            },
            PermissionGap {
                command: "ember-git.push to forks/*".to_string(),
                count: 2,
                last_seen: "2026-05-09T09:00:00Z".to_string(),
            },
        ];
        let cta = format_cta("main", &gaps, Duration::from_secs(7 * 86400)).expect("non-empty");

        // First gap must appear before second.
        let idx_a = cta.find("ember-gh.pr.merge").expect("first gap present");
        let idx_b = cta.find("ember-git.push").expect("second gap present");
        assert!(idx_a < idx_b, "bullets must render in received order");
    }

    /// Lookback duration shows up in the CTA header. A 1-hour lookback
    /// rounds to "1 days" (min clamp); a 14-day lookback shows as
    /// "14 days". The CTA copy is informational — the actual filter
    /// is daemon-side.
    #[test]
    fn format_cta_renders_lookback_days() {
        let gaps = vec![PermissionGap {
            command: "x".to_string(),
            count: 1,
            last_seen: "2026-05-10T11:30:00Z".to_string(),
        }];
        let cta = format_cta("main", &gaps, Duration::from_secs(14 * 86400)).expect("non-empty");
        assert!(cta.contains("last 14 days"));
    }

    /// `PreflightDecision` enum is `Copy`-able so callers can fan it
    /// across structured-return paths without lifetime gymnastics.
    /// This is a compile-time check disguised as a test.
    #[test]
    fn preflight_decision_is_copy() {
        fn requires_copy<T: Copy>(_t: T) {}
        requires_copy(PreflightDecision::WidenTemplate);
        requires_copy(PreflightDecision::Cancel);
        requires_copy(PreflightDecision::Skip);
    }

    // ─── Headless enroll / revoke / status helper tests ───────────────

    #[test]
    fn parse_duration_spec_recognizes_canonical_units() {
        assert_eq!(parse_duration_spec("4h").unwrap().as_secs(), 4 * 3600);
        assert_eq!(parse_duration_spec("3d").unwrap().as_secs(), 3 * 86400);
        assert_eq!(parse_duration_spec("1w").unwrap().as_secs(), 7 * 86400);
        assert_eq!(parse_duration_spec("30m").unwrap().as_secs(), 30 * 60);
        assert_eq!(parse_duration_spec("60s").unwrap().as_secs(), 60);
    }

    #[test]
    fn parse_duration_spec_rejects_garbage() {
        assert!(matches!(
            parse_duration_spec(""),
            Err(HeadlessCommandError::InvalidDuration(_))
        ));
        assert!(matches!(
            parse_duration_spec("forever"),
            Err(HeadlessCommandError::InvalidDuration(_))
        ));
        // No suffix → rejected (operator must say which unit).
        assert!(matches!(
            parse_duration_spec("4"),
            Err(HeadlessCommandError::InvalidDuration(_))
        ));
        // Unknown suffix → rejected.
        assert!(matches!(
            parse_duration_spec("4y"),
            Err(HeadlessCommandError::InvalidDuration(_))
        ));
    }

    #[test]
    fn render_enroll_cta_includes_locked_copy() {
        let cta = render_enroll_cta("4h");
        // Spot-check the load-bearing lines from the locked CTA copy.
        assert!(cta.contains("Enable bounded headless work"));
        assert!(cta.contains("Default: 4 hours."));
        assert!(cta.contains("anything up to 7 days"));
        assert!(cta.contains("strict + delegated"));
        assert!(cta.contains("declared vault/env/file materials"));
        assert!(cta.contains("enrollment emits a receipt"));
        assert!(cta.contains("ember headless revoke"));
        assert!(cta.contains("Duration [4h]:"));
        assert!(cta.contains("Confirm enrollment for 4h? [Y/n]:"));
    }

    #[test]
    fn require_non_empty_tasks_accepts_declared_queue() {
        let input = json!({
            "tasks": [
                {"task_id": "task-1", "constructs": ["ember-gh.pr_merge"]}
            ],
            "template": [],
        });
        let tasks = require_non_empty_tasks(&input).expect("tasks");
        assert_eq!(tasks.as_array().unwrap().len(), 1);
        assert_eq!(tasks[0]["task_id"], "task-1");
    }

    #[test]
    fn require_non_empty_tasks_rejects_missing_or_empty_queue() {
        assert!(matches!(
            require_non_empty_tasks(&json!({})),
            Err(HeadlessCommandError::InvalidTaskDeclaration(_))
        ));
        assert!(matches!(
            require_non_empty_tasks(&json!({"tasks": []})),
            Err(HeadlessCommandError::InvalidTaskDeclaration(_))
        ));
        assert!(matches!(
            require_non_empty_tasks(&json!({"tasks": "task-1"})),
            Err(HeadlessCommandError::InvalidTaskDeclaration(_))
        ));
    }

    #[test]
    fn enroll_refuses_before_daemon_when_input_is_missing() {
        let err = cmd_enroll(
            Path::new("/no/such/socket"),
            EnrollArgs {
                input_json_path: None,
                duration: Some("4h".to_string()),
                persona: None,
                yes: true,
            },
        )
        .expect_err("missing input should fail before daemon socket use");
        assert!(matches!(err, HeadlessCommandError::MissingTaskDeclaration));
    }

    #[test]
    fn confirm_response_accepts_canonical_yes() {
        assert!(confirm_response_accepts(""));
        assert!(confirm_response_accepts("\n"));
        assert!(confirm_response_accepts("y"));
        assert!(confirm_response_accepts("Y\n"));
        assert!(confirm_response_accepts("yes"));
        assert!(confirm_response_accepts("Yes\n"));
    }

    #[test]
    fn confirm_response_rejects_no_or_garbage() {
        assert!(!confirm_response_accepts("n"));
        assert!(!confirm_response_accepts("no"));
        assert!(!confirm_response_accepts("skip"));
        assert!(!confirm_response_accepts("?"));
        assert!(!confirm_response_accepts("nope"));
    }

    #[test]
    fn format_duration_display_picks_largest_clean_unit() {
        assert_eq!(format_duration_display(7 * 86400), "1w");
        assert_eq!(format_duration_display(14 * 86400), "2w");
        assert_eq!(format_duration_display(3 * 86400), "3d");
        assert_eq!(format_duration_display(4 * 3600), "4h");
        assert_eq!(format_duration_display(30 * 60), "30m");
        assert_eq!(format_duration_display(45), "45s");
        assert_eq!(format_duration_display(0), "0s");
    }

    #[test]
    fn headless_guidance_maps_missing_presence() {
        let guidance = headless_guidance_for_rpc(
            "headless_enroll",
            -32001,
            r#"{"error":"authority_class_not_met","reason":"missing"}"#,
        )
        .expect("expected guidance");
        assert!(guidance.contains("operator presence"));
        assert!(guidance.contains("managed separate-uid biometric unlock"));
        assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
    }

    #[test]
    fn headless_guidance_maps_locked_session() {
        let guidance = headless_guidance_for_rpc(
            "headless_status",
            -32030,
            "headless_status denied: session is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts",
        )
        .expect("expected guidance");
        assert!(guidance.contains("operator presence"));
        assert!(guidance.contains("managed separate-uid biometric unlock"));
        assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
    }

    // ─── Layer 1 pre-flight Constructs — CLI table tests ─────────────

    #[test]
    fn preflight_table_renders_no_gaps_message_for_empty_input() {
        let out = format_preflight_gap_table(&[]);
        assert!(
            out.contains("no gaps"),
            "empty gap list renders the no-gaps message; got:\n{out}"
        );
    }

    #[test]
    fn preflight_table_renders_header_and_rows() {
        let gaps = vec![
            PreflightLayer1Gap {
                task_id: "TASK-AP-PR-MERGE".into(),
                identifier: "ember-gh.pr_merge".into(),
                scope: None,
            },
            PreflightLayer1Gap {
                task_id: "TASK-AP-K8S-APPLY".into(),
                identifier: "ember-kubectl.kubectl.apply".into(),
                scope: Some("staging/*".into()),
            },
        ];
        let out = format_preflight_gap_table(&gaps);
        assert!(out.contains("TASK"), "header includes TASK column");
        assert!(
            out.contains("PERMISSION"),
            "header includes PERMISSION column"
        );
        assert!(out.contains("SCOPE"), "header includes SCOPE column");
        assert!(out.contains("TASK-AP-PR-MERGE"));
        assert!(out.contains("ember-gh.pr_merge"));
        assert!(out.contains("TASK-AP-K8S-APPLY"));
        assert!(out.contains("staging/*"));
        assert!(
            out.contains("2 gap(s)"),
            "footer reports gap count; got:\n{out}"
        );
    }

    #[test]
    fn preflight_table_renders_dash_when_scope_is_none() {
        let gaps = vec![PreflightLayer1Gap {
            task_id: "TASK-X".into(),
            identifier: "ember-gh.pr_create".into(),
            scope: None,
        }];
        let out = format_preflight_gap_table(&gaps);
        assert!(
            out.contains(" -"),
            "missing scope renders as '-'; got:\n{out}"
        );
    }

    #[test]
    fn preflight_layer1_gap_round_trips_through_json() {
        let gap = PreflightLayer1Gap {
            task_id: "TASK-RT".into(),
            identifier: "ember-gh.pr_merge".into(),
            scope: Some("forks/*".into()),
        };
        let wire = serde_json::to_value(&gap).expect("serialize");
        // scope is preserved on the wire when Some.
        assert_eq!(wire["task_id"], "TASK-RT");
        assert_eq!(wire["identifier"], "ember-gh.pr_merge");
        assert_eq!(wire["scope"], "forks/*");
        let back: PreflightLayer1Gap = serde_json::from_value(wire).expect("deserialize");
        assert_eq!(back, gap);
    }

    #[test]
    fn preflight_layer1_gap_decodes_daemon_wire_shape_with_null_scope() {
        // The daemon emits `scope: null` for unscoped gaps; verify the
        // CLI's `Option<String>` decoder accepts that shape.
        let wire = json!({
            "task_id": "TASK-NULL-SCOPE",
            "identifier": "ember-gh.pr_create",
            "scope": null,
        });
        let gap: PreflightLayer1Gap = serde_json::from_value(wire).expect("deserialize");
        assert_eq!(gap.task_id, "TASK-NULL-SCOPE");
        assert_eq!(gap.identifier, "ember-gh.pr_create");
        assert!(gap.scope.is_none());
    }
}
