//! In-container bridge-cert refresh client (ADR 173 §Component 1 + §Component 5,
//! META-AP-EMBERLINK-MCP-CERT-REFRESH-CLIENT / M6).
//!
//! Replaces the earlier single-shot 90%-TTL warn-only timer with the
//! 4-band refresh-aware model from ADR 173 §Component 1:
//!
//! | Band     | TTL elapsed | Behaviour                                             |
//! |----------|-------------|-------------------------------------------------------|
//! | 50%      | first       | Fire `refresh_cert` RPC; success → hot-swap + done.   |
//! | 75%      | retry       | If 50% attempt failed, retry escalation continues.    |
//! | 90%      | failsafe    | Existing `bridge.cert_expiring_soon` warning fires;   |
//! |          |             | from here on, NEW RPCs fail-closed with               |
//! |          |             | [`RefreshClientError::RefreshFailing`].               |
//! | 99% /    | hard cutoff | Stop retrying; emit terminal                          |
//! | `not_after - 30s` |   | `bridge.cert_refresh_failed`.                         |
//!
//! Search anchor: `emberlink_mcp_cert_refresh_client_landed`.
//!
//! ## Timing discipline
//!
//! All band deadlines are wallclock-anchored against the cert
//! `not_before` / `not_after` (NOT monotonic-since-handshake). The
//! scheduler clamps each computed band against `max(not_before, now)`
//! so a daemon restart that respawns the MCP server mid-cert-life still
//! observes the correct band offsets.
//!
//! ## Retry / backoff
//!
//! Per ADR 173 §Component 5: exponential backoff with **full jitter**
//! between attempts within a band. Per-tier caps:
//! - `dev0` — 5 min between attempts (longer TTL, lighter cadence)
//! - `team0` / `ent0` — 60 s (tighter TTL, aggressive retry)
//!
//! Every retry train hard-stops at `not_after - 30s`, regardless of
//! cause.
//!
//! ## Failure-cause buckets
//!
//! The daemon's `refresh_cert` response carries a `denied: true |
//! false` discriminator plus, on denial, a `failure_cause` snake-case
//! enum mirrored in [`RefreshFailureCause`]. The client maps each
//! variant into one of three buckets ([`FailureBucket`]):
//!
//! - [`FailureBucket::Transport`] → retry on exp-backoff.
//! - [`FailureBucket::Auth`] → REFUSE retry; emit terminal failure
//!   event and stop the chain. The agent's bridge session ends with
//!   the existing cert.
//! - [`FailureBucket::Mint`] → slow-retry (transient daemon condition).
//!
//! ## Events emitted
//!
//! Per ADR 118 Extension 5 / ADR 173 §Component 7:
//! - `bridge.cert_refresh_attempted` — fire-and-forget event per
//!   attempt, carries `trigger_band` + `attempt_seq`.
//! - `bridge.cert_refresh_failed` — terminal failure (rare); emitted
//!   when the retry chain hits the hard cutoff or an auth-failure
//!   refuses retry.
//! - `bridge.cert_expiring_soon` — kept at the 90% band for backward
//!   compatibility with the M5 wiring; the warning still surfaces
//!   even if the client successfully refreshed earlier (the daemon
//!   side filters on its own state — the client just fires).
//!
//! All three calls are best-effort: if the daemon doesn't recognize
//! the method (e.g. in tests / older builds), the local tracing line
//! still fires and the chain proceeds.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::CertificateDer;
use x509_parser::prelude::FromDer;

use crate::daemon_transport::{
    DaemonTransport, LoadedBridgeCert, MtlsBridgeConfig, build_client_tls_config,
};

/// Parsed cert validity window — Unix seconds at both bounds. Returned
/// by [`parse_cert_validity`] so the scheduler can compute band
/// deadlines without re-parsing on every call.
#[derive(Debug, Clone, Copy)]
pub struct CertValidity {
    pub not_before: i64,
    pub not_after: i64,
}

impl CertValidity {
    /// Total TTL in seconds. Clamped to 1 so divide-by-zero is impossible
    /// even if the cert validity window is degenerate.
    pub fn total_secs(&self) -> i64 {
        (self.not_after - self.not_before).max(1)
    }

    /// Unix timestamp at which N% of the cert's TTL is elapsed.
    /// Integer math (no f64) so the deadline is bit-exact reproducible
    /// across platforms — TTLs round to seconds in this codebase anyway.
    fn percent_deadline(&self, percent: i64) -> i64 {
        let total = self.total_secs();
        self.not_before + (total * percent / 100)
    }

    /// Unix timestamp at which 50% of the cert's TTL is elapsed (first refresh attempt).
    pub fn fifty_percent_deadline(&self) -> i64 {
        self.percent_deadline(50)
    }

    /// Unix timestamp at which 75% of the cert's TTL is elapsed (retry escalation).
    pub fn seventy_five_percent_deadline(&self) -> i64 {
        self.percent_deadline(75)
    }

    /// Unix timestamp at which 90% of the cert's TTL is elapsed (10% remaining).
    /// The fire-time for the `bridge.cert_expiring_soon` warning AND the soft
    /// fail-closed threshold for new RPCs.
    pub fn ninety_percent_deadline(&self) -> i64 {
        self.percent_deadline(90)
    }

    /// Hard-cutoff timestamp: `not_after - 30s`. Per ADR 173 §Component 1
    /// the retry train STOPS here regardless of band/cause. The 30s
    /// safety margin guarantees the cert is still valid when the
    /// terminal `bridge.cert_refresh_failed` event flushes.
    pub fn hard_cutoff(&self) -> i64 {
        self.not_after - 30
    }
}

/// Parse the client cert's `not_before` / `not_after` from its DER bytes.
/// Pure function — no I/O, no global state — so it's trivially unit-testable.
pub fn parse_cert_validity(cert_der: &CertificateDer<'_>) -> Result<CertValidity, String> {
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| format!("parse cert DER: {e}"))?;
    Ok(CertValidity {
        not_before: parsed.tbs_certificate.validity.not_before.timestamp(),
        not_after: parsed.tbs_certificate.validity.not_after.timestamp(),
    })
}

/// Current Unix-seconds wallclock. Wrapped here so unit tests can mock
/// `now_ts` independently — the in-process tokio time clock has its own
/// `pause()` machinery but the brief's TTL-band math is wallclock-anchored
/// so the scheduler reads SystemTime.
pub fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Compute the `sleep` duration until the given deadline fires, given
/// the current wallclock. Returns `Duration::ZERO` when the deadline is
/// in the past (fire immediately).
pub fn duration_until(deadline_ts: i64, now: i64) -> Duration {
    if deadline_ts <= now {
        Duration::ZERO
    } else {
        Duration::from_secs((deadline_ts - now) as u64)
    }
}

/// Back-compat alias for the 90% warn-only deadline calculation that
/// pre-M6 callers used. New code uses [`CertValidity::ninety_percent_deadline`]
/// or [`duration_until`] directly.
pub fn duration_until_deadline(validity: CertValidity, now: i64) -> Duration {
    duration_until(validity.ninety_percent_deadline(), now)
}

/// One of the four trigger bands from ADR 173 §Component 1. Carries the
/// integer TTL-percent so the `trigger_band` event field reads as a
/// human-meaningful number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerBand {
    Fifty,
    SeventyFive,
    Ninety,
    NinetyNine,
}

impl TriggerBand {
    /// Wire-format string used in `bridge.cert_refresh_attempted` events.
    pub fn as_str(&self) -> &'static str {
        match self {
            TriggerBand::Fifty => "50",
            TriggerBand::SeventyFive => "75",
            TriggerBand::Ninety => "90",
            TriggerBand::NinetyNine => "99",
        }
    }
}

/// Compute the four band deadlines for a cert, clamped to `>= now`.
///
/// Clamping protects against the case where the MCP server starts up
/// past the 50% / 75% / 90% mark (e.g. daemon restart mid-cert-life) —
/// the band still fires, just immediately.
pub fn compute_band_deadlines(validity: CertValidity, now: i64) -> [(TriggerBand, i64); 4] {
    let clamp = |t: i64| t.max(validity.not_before).max(now);
    [
        (TriggerBand::Fifty, clamp(validity.fifty_percent_deadline())),
        (
            TriggerBand::SeventyFive,
            clamp(validity.seventy_five_percent_deadline()),
        ),
        (
            TriggerBand::Ninety,
            clamp(validity.ninety_percent_deadline()),
        ),
        (TriggerBand::NinetyNine, clamp(validity.hard_cutoff())),
    ]
}

/// Per ADR 173 §Component 5 — three failure-cause buckets the client
/// uses to decide retry vs. give-up vs. slow-retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureBucket {
    /// Network / wire-level failure — retry on exp-backoff.
    Transport,
    /// Authority denied (revoked / expired / unknown persona) — REFUSE
    /// retry; the chain terminates with a `bridge.cert_refresh_failed`
    /// event.
    Auth,
    /// Daemon-side mint problem (vault sealed, internal error) —
    /// slow-retry.
    Mint,
}

/// Mirror of the daemon's `RefreshFailureCause` enum (see
/// `crates/ember-daemon/src/broker/handler/runtime_authority.rs`). Used
/// for direct deserialization of the `failure_cause` field on a denied
/// refresh response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshFailureCause {
    TransportError,
    AuthFailureRevoked,
    AuthFailureExpired,
    AuthFailurePersonaUnknown,
    MintFailureVaultSealed,
    MintFailureInternal,
    ExhaustedRetries,
    NotImplemented,
    /// Wire variant the client doesn't recognize — treated as transport
    /// for retry purposes (better to keep trying than silently give up
    /// on a daemon that's added a new cause we haven't taught the
    /// client about).
    Unknown,
}

impl RefreshFailureCause {
    /// Parse the snake_case string the daemon emits on the wire.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "transport_error" => Self::TransportError,
            "auth_failure_revoked" => Self::AuthFailureRevoked,
            "auth_failure_expired" => Self::AuthFailureExpired,
            "auth_failure_persona_unknown" => Self::AuthFailurePersonaUnknown,
            "mint_failure_vault_sealed" => Self::MintFailureVaultSealed,
            "mint_failure_internal" => Self::MintFailureInternal,
            "exhausted_retries" => Self::ExhaustedRetries,
            "not_implemented" => Self::NotImplemented,
            _ => Self::Unknown,
        }
    }

    /// Wire-format string for events.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TransportError => "transport_error",
            Self::AuthFailureRevoked => "auth_failure_revoked",
            Self::AuthFailureExpired => "auth_failure_expired",
            Self::AuthFailurePersonaUnknown => "auth_failure_persona_unknown",
            Self::MintFailureVaultSealed => "mint_failure_vault_sealed",
            Self::MintFailureInternal => "mint_failure_internal",
            Self::ExhaustedRetries => "exhausted_retries",
            Self::NotImplemented => "not_implemented",
            Self::Unknown => "unknown",
        }
    }

    /// Map onto one of the three behavior buckets per ADR 173 §Component 5.
    pub fn bucket(&self) -> FailureBucket {
        match self {
            // Auth-related: REFUSE retry.
            Self::AuthFailureRevoked
            | Self::AuthFailureExpired
            | Self::AuthFailurePersonaUnknown => FailureBucket::Auth,
            // Mint-related: slow-retry (transient daemon condition).
            Self::MintFailureVaultSealed | Self::MintFailureInternal => FailureBucket::Mint,
            // Transport / retry-exhaustion / not-implemented / unknown:
            // retry on exp-backoff. ExhaustedRetries here is the
            // daemon telling us it ratelimited us; backing off is the
            // right response. NotImplemented means an older daemon —
            // retrying buys nothing immediately but is harmless.
            Self::TransportError
            | Self::ExhaustedRetries
            | Self::NotImplemented
            | Self::Unknown => FailureBucket::Transport,
        }
    }
}

/// Deployment-tier discriminator for backoff caps. Per ADR 173
/// §Component 5: `dev0` caps at 5min between attempts; `team0` and
/// `ent0` cap at 60s (tighter TTL → more aggressive retry).
///
/// Sourced from the `EMBER_TIER` env var (canonical convention; see
/// `docs/grill-transcripts/20260507-132613-MODEL-CONFIG.md`). Defaults
/// to `dev0` when unset — the safe choice (longer cap, fewer RPCs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Dev0,
    Team0,
    Ent0,
}

impl Tier {
    /// Read `EMBER_TIER` from the environment. Unknown values fall back
    /// to `Dev0`.
    pub fn from_env() -> Self {
        match std::env::var("EMBER_TIER").as_deref() {
            Ok("team0") => Self::Team0,
            Ok("ent0") => Self::Ent0,
            _ => Self::Dev0,
        }
    }

    /// Per-tier backoff cap in seconds.
    pub fn backoff_cap_secs(&self) -> u64 {
        match self {
            Self::Dev0 => 300,           // 5 min
            Self::Team0 | Self::Ent0 => 60,
        }
    }
}

/// Compute the next exp-backoff sleep with full jitter, capped at the
/// tier max AND clamped so the resulting wake-time never exceeds the
/// hard cutoff.
///
/// Formula (ADR 173 §Component 5): `sleep = random(0, base * 2^attempt)`
/// capped at `tier_cap_secs`. `base` is fixed at 2s — small enough that
/// the first attempt's backoff window stays short, large enough that
/// `base * 2^N` reaches the cap within a handful of attempts.
///
/// `attempt` is 0-indexed (the FIRST retry after a fired attempt is
/// `attempt = 0`). `jitter_rand` is a `[0, 1)` random value injected
/// here so tests can pin the schedule deterministically.
pub fn compute_backoff(
    attempt: u32,
    tier_cap_secs: u64,
    jitter_rand: f64,
    now: i64,
    hard_cutoff: i64,
) -> Duration {
    const BASE_SECS: u64 = 2;
    let exp = BASE_SECS.saturating_mul(1u64.checked_shl(attempt).unwrap_or(u64::MAX));
    let capped_window = exp.min(tier_cap_secs);
    // Full jitter: uniform [0, capped_window).
    let jittered = (capped_window as f64 * jitter_rand.clamp(0.0, 1.0)) as u64;
    // Clamp against the hard cutoff so retry never overruns
    // `not_after - 30s`.
    let max_until_cutoff = (hard_cutoff - now).max(0) as u64;
    Duration::from_secs(jittered.min(max_until_cutoff))
}

/// Payload metadata that rides along with refresh events. Captured at
/// startup from the orchestrator-supplied env so events carry the
/// persona/container identity even if the cert SAN parse fails.
#[derive(Debug, Clone)]
pub struct ExpiryEventContext {
    pub persona_id: Option<String>,
    pub container_id: Option<String>,
}

impl ExpiryEventContext {
    /// Read `EMBER_PERSONA_ID` and `EMBER_CONTAINER_ID` from the
    /// environment. Both are best-effort — events still fire with
    /// `None` values if the orchestrator hasn't populated them.
    pub fn from_env() -> Self {
        Self {
            persona_id: std::env::var("EMBER_PERSONA_ID").ok(),
            container_id: std::env::var("EMBER_CONTAINER_ID").ok(),
        }
    }
}

/// Shared mutable refresh state. Wrapped in `Arc<RwLock<...>>` so the
/// refresh task can update it while the `is_refresh_failing()`
/// observer (used by `DaemonTransport` to gate NEW RPCs at the 90%
/// soft-fail-closed threshold) reads it cheaply.
#[derive(Debug, Default)]
pub struct RefreshState {
    /// Monotonic counter incremented on every attempt fire — surfaces
    /// as `attempt_seq` on `bridge.cert_refresh_attempted` events.
    pub attempt_seq: u64,
    /// Set to `true` once we're past the 90% band with no successful
    /// refresh yet. Once `true`, [`RefreshClientError::RefreshFailing`]
    /// is the typed reason callers see when they try to start a new
    /// RPC; in-flight RPCs are not interrupted (per ADR 173 §Component 5).
    pub failing: bool,
    /// Set to `true` once the chain has reached its terminal state —
    /// either a successful refresh occurred (no further retries needed
    /// until the NEXT cert lifecycle), or the hard cutoff fired with an
    /// emitted `bridge.cert_refresh_failed`.
    pub terminated: bool,
    /// Count of failed attempts since the last successful refresh (or
    /// start of timer). Resets to 0 on success. Used to drive the
    /// exp-backoff window.
    pub failed_attempts: u32,
}

/// Errors the client surfaces to RPC callers when refresh state
/// requires soft fail-closing new traffic. Distinct from
/// [`crate::daemon_transport::DaemonTransportError`] so the gate is a
/// typed signal — callers can match on this specifically and surface a
/// clean "cert refresh failing" message rather than papering over with
/// a generic transport error.
#[derive(Debug)]
pub enum RefreshClientError {
    /// At ≥90% TTL with no successful refresh; refuse new RPCs while
    /// preserving in-flight ones. Mapped to the typed error type per
    /// ADR 173 §Component 5 "Soft fail-closed at 90%".
    RefreshFailing,
}

impl std::fmt::Display for RefreshClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RefreshFailing => write!(
                f,
                "bridge cert refresh has been failing past the 90% TTL band; \
                 new RPCs are refused until the chain recovers or the cert is replaced"
            ),
        }
    }
}

impl std::error::Error for RefreshClientError {}

/// Spawn the background task that runs the refresh client.
///
/// Lifecycle:
/// 1. Sleep to the 50% band, fire first attempt.
/// 2. If success → hot-swap the `MtlsBridgeConfig`'s `ClientConfig`,
///    re-parse the new cert, recompute bands, loop.
/// 3. If failure (transport / mint bucket) → exp-backoff retry, escalate
///    at the 75% band, continue to 90% (flip `failing = true`), stop at
///    `not_after - 30s` and emit terminal failure event.
/// 4. If failure (auth bucket) → emit terminal failure event immediately;
///    no further retries. The agent's bridge session ends with the
///    existing cert.
///
/// `bridge_config` is the swap substrate — the same `MtlsBridgeConfig`
/// the live `DaemonTransport`s share. `transport` is a dedicated
/// transport for the refresh RPCs themselves.
///
/// Dropping the returned join handle (or the runtime) cancels the
/// chain. The task is a single tokio task — no fan-out.
///
/// Anchor: `emberlink_mcp_cert_refresh_client_landed`.
pub fn spawn_refresh_client(
    runtime: Arc<tokio::runtime::Runtime>,
    initial_validity: CertValidity,
    context: ExpiryEventContext,
    transport: Arc<DaemonTransport>,
    bridge_config: MtlsBridgeConfig,
    state: Arc<RwLock<RefreshState>>,
    tier: Tier,
) -> tokio::task::JoinHandle<()> {
    runtime.spawn(async move {
        let mut validity = initial_validity;
        loop {
            match run_refresh_chain(&context, &transport, &bridge_config, &state, tier, validity)
                .await
            {
                ChainOutcome::Refreshed(new_validity) => {
                    // Successful refresh — reset state and recompute bands
                    // for the new cert lifecycle. Clear the soft-fail-
                    // closed flag so new RPCs flow again.
                    {
                        let mut guard = state.write().expect("RefreshState lock poisoned");
                        guard.failed_attempts = 0;
                        guard.failing = false;
                        guard.terminated = false;
                    }
                    bridge_config.set_refresh_failing(false);
                    validity = new_validity;
                    // Continue the outer loop — schedule the next
                    // 50% / 75% / 90% / 99% bands on the refreshed cert.
                    continue;
                }
                ChainOutcome::TerminallyFailed => {
                    // Hard cutoff hit or auth-bucket terminal failure.
                    // Mark terminated and exit. The MCP process keeps
                    // running on the existing cert until it expires;
                    // the listener will eventually close on `not_after`.
                    let mut guard = state.write().expect("RefreshState lock poisoned");
                    guard.terminated = true;
                    return;
                }
            }
        }
    })
}

/// Legacy entry point — kept so direct callers of the original 90% warn
/// timer still compile. New code should prefer
/// [`spawn_refresh_client`].
///
/// Behaviour mirrors the pre-M6 timer: sleep to 90% TTL elapsed, fire a
/// single `bridge.cert_expiring_soon` warning + best-effort daemon
/// notify, exit. No refresh attempts are made.
pub fn spawn_expiry_timer(
    runtime: Arc<tokio::runtime::Runtime>,
    validity: CertValidity,
    context: ExpiryEventContext,
    transport: Arc<DaemonTransport>,
) -> tokio::task::JoinHandle<()> {
    runtime.spawn(async move {
        let sleep_for = duration_until_deadline(validity, now_ts());
        tokio::time::sleep(sleep_for).await;
        emit_cert_expiring_soon(&context, &transport, validity);
    })
}

/// Outcome of one cert-lifecycle refresh chain. Encoded as a flat enum
/// rather than a Result so the success-path carries the new validity.
enum ChainOutcome {
    /// Refresh succeeded; the chain should re-arm against the new
    /// cert lifecycle.
    Refreshed(CertValidity),
    /// Either the hard cutoff fired or an auth-bucket failure halted
    /// retries. The chain exits.
    TerminallyFailed,
}

/// Run one cert-lifecycle refresh chain: 50% → 75% → 90% → 99% bands.
///
/// Returns `Refreshed` on first successful refresh and `TerminallyFailed`
/// on hard cutoff or auth failure.
async fn run_refresh_chain(
    context: &ExpiryEventContext,
    transport: &DaemonTransport,
    bridge_config: &MtlsBridgeConfig,
    state: &Arc<RwLock<RefreshState>>,
    tier: Tier,
    validity: CertValidity,
) -> ChainOutcome {
    let bands = compute_band_deadlines(validity, now_ts());
    let hard_cutoff = validity.hard_cutoff();
    let cap = tier.backoff_cap_secs();

    for (band_idx, (band, band_deadline)) in bands.iter().enumerate() {
        // Sleep to band deadline.
        tokio::time::sleep(duration_until(*band_deadline, now_ts())).await;

        // 90% band fires the existing daemon-side warning + flips the
        // soft-fail-closed switch. The flag lives both on the shared
        // `RefreshState` (for any direct observers — tests / future
        // dashboards) AND on the `MtlsBridgeConfig::refresh_failing`
        // atomic that `DaemonTransport::call_tool` actually gates on.
        if matches!(band, TriggerBand::Ninety) {
            emit_cert_expiring_soon(context, transport, validity);
            {
                let mut guard = state.write().expect("RefreshState lock poisoned");
                guard.failing = true;
            }
            bridge_config.set_refresh_failing(true);
        }

        // 99% band is the hard cutoff. Don't attempt — emit terminal
        // failure and exit.
        if matches!(band, TriggerBand::NinetyNine) {
            emit_cert_refresh_failed(
                context,
                transport,
                validity,
                RefreshFailureCause::ExhaustedRetries,
                "hard cutoff reached at not_after - 30s with no successful refresh",
            );
            return ChainOutcome::TerminallyFailed;
        }

        // Otherwise: attempt the refresh. Loop on exp-backoff until
        // success, auth failure, or the NEXT band's deadline elapses
        // (handed off to the next iteration of the outer for-loop).
        let next_band_deadline = if band_idx + 1 < bands.len() {
            bands[band_idx + 1].1
        } else {
            hard_cutoff
        };

        match try_band(
            context,
            transport,
            bridge_config,
            state,
            *band,
            tier,
            cap,
            hard_cutoff,
            next_band_deadline,
        )
        .await
        {
            BandOutcome::Refreshed(new) => return ChainOutcome::Refreshed(new),
            BandOutcome::AuthDenied(cause, reason) => {
                emit_cert_refresh_failed(context, transport, validity, cause, &reason);
                return ChainOutcome::TerminallyFailed;
            }
            BandOutcome::BandTimedOut => {
                // Move on to the next band.
                continue;
            }
        }
    }

    // Should be unreachable — the 99% band always emits terminal +
    // returns above. Defensive return to keep the compiler honest.
    ChainOutcome::TerminallyFailed
}

/// Outcome of trying refresh attempts within a single band's window.
enum BandOutcome {
    /// A refresh attempt succeeded; the cert was hot-swapped and the
    /// new validity is returned.
    Refreshed(CertValidity),
    /// An auth-bucket failure denied the refresh; the chain must
    /// terminate.
    AuthDenied(RefreshFailureCause, String),
    /// The band's window elapsed with no terminal outcome; the caller
    /// advances to the next band.
    BandTimedOut,
}

/// Drive exp-backoff retries within a single band's window.
///
/// The argument count is intentional — each parameter carries
/// independent state that the band-loop needs to evaluate per-attempt
/// (context for events, transport for RPCs, swap target, shared state,
/// tier for backoff caps, time bounds). Bundling them into a struct
/// would add a type for nothing.
#[allow(clippy::too_many_arguments)]
async fn try_band(
    context: &ExpiryEventContext,
    transport: &DaemonTransport,
    bridge_config: &MtlsBridgeConfig,
    state: &Arc<RwLock<RefreshState>>,
    band: TriggerBand,
    tier: Tier,
    cap: u64,
    hard_cutoff: i64,
    next_band_deadline: i64,
) -> BandOutcome {
    loop {
        // Bump attempt_seq + emit `bridge.cert_refresh_attempted`.
        let attempt_seq = {
            let mut guard = state.write().expect("RefreshState lock poisoned");
            guard.attempt_seq = guard.attempt_seq.saturating_add(1);
            guard.attempt_seq
        };
        emit_cert_refresh_attempted(context, transport, band, attempt_seq);

        // Fire the `refresh_cert` RPC. The current attempt counter
        // (failed_attempts at this point) feeds the exp-backoff window
        // on failure.
        match transport.call_raw("refresh_cert", &serde_json::json!({})) {
            Ok(response) => {
                if response
                    .get("denied")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    let cause_str = response
                        .get("failure_cause")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let reason = response
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("denied")
                        .to_string();
                    let cause = RefreshFailureCause::from_wire(cause_str);
                    match cause.bucket() {
                        FailureBucket::Auth => {
                            return BandOutcome::AuthDenied(cause, reason);
                        }
                        FailureBucket::Transport | FailureBucket::Mint => {
                            // Bump failed-attempt counter; the backoff
                            // window grows with attempts.
                            let attempts = {
                                let mut guard =
                                    state.write().expect("RefreshState lock poisoned");
                                guard.failed_attempts =
                                    guard.failed_attempts.saturating_add(1);
                                guard.failed_attempts
                            };
                            tracing::warn!(
                                trigger_band = band.as_str(),
                                attempt_seq,
                                failure_cause = cause.as_str(),
                                reason = %reason,
                                "bridge.cert_refresh_attempted: refresh denied; backing off"
                            );
                            if !sleep_backoff_or_timeout(
                                attempts,
                                tier,
                                cap,
                                hard_cutoff,
                                next_band_deadline,
                            )
                            .await
                            {
                                return BandOutcome::BandTimedOut;
                            }
                            continue;
                        }
                    }
                } else {
                    // Success — apply the cert and return.
                    match apply_refresh_response(bridge_config, &response) {
                        Ok(new_validity) => return BandOutcome::Refreshed(new_validity),
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "bridge cert_refresh succeeded on the wire but the response \
                                 could not be applied to the local ClientConfig; treating as \
                                 transport failure"
                            );
                            let attempts = {
                                let mut guard =
                                    state.write().expect("RefreshState lock poisoned");
                                guard.failed_attempts =
                                    guard.failed_attempts.saturating_add(1);
                                guard.failed_attempts
                            };
                            if !sleep_backoff_or_timeout(
                                attempts,
                                tier,
                                cap,
                                hard_cutoff,
                                next_band_deadline,
                            )
                            .await
                            {
                                return BandOutcome::BandTimedOut;
                            }
                            continue;
                        }
                    }
                }
            }
            Err(e) => {
                // Transport-level error — exp-backoff and continue.
                let attempts = {
                    let mut guard = state.write().expect("RefreshState lock poisoned");
                    guard.failed_attempts = guard.failed_attempts.saturating_add(1);
                    guard.failed_attempts
                };
                tracing::warn!(
                    trigger_band = band.as_str(),
                    attempt_seq,
                    error = %e,
                    "bridge.cert_refresh_attempted: transport error; backing off"
                );
                if !sleep_backoff_or_timeout(
                    attempts,
                    tier,
                    cap,
                    hard_cutoff,
                    next_band_deadline,
                )
                .await
                {
                    return BandOutcome::BandTimedOut;
                }
                continue;
            }
        }
    }
}

/// Sleep for the next exp-backoff window. Returns `false` when the
/// sleep would push past either the next-band deadline or the
/// hard cutoff (caller advances to the next band / terminates).
async fn sleep_backoff_or_timeout(
    attempts: u32,
    tier: Tier,
    _cap_secs: u64,
    hard_cutoff: i64,
    next_band_deadline: i64,
) -> bool {
    let now = now_ts();
    // Effective deadline for this backoff sleep is the earlier of the
    // next band and the hard cutoff. If we're already past it, return
    // false immediately.
    let deadline = next_band_deadline.min(hard_cutoff);
    if now >= deadline {
        return false;
    }
    let jitter = rand_jitter();
    let backoff = compute_backoff(
        attempts.saturating_sub(1),
        tier.backoff_cap_secs(),
        jitter,
        now,
        deadline,
    );
    if backoff.is_zero() && now >= deadline {
        return false;
    }
    tokio::time::sleep(backoff).await;
    now_ts() < deadline
}

/// Deterministic-enough jitter for the backoff window. We avoid pulling
/// in the `rand` crate for one float — `SystemTime` nanoseconds mod
/// 10_000 / 10_000.0 gives a well-distributed `[0, 1)` value that's
/// good enough for full-jitter backoff. Pure timer noise; not a
/// cryptographic source.
fn rand_jitter() -> f64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos % 10_000) as f64 / 10_000.0
}

/// Apply a successful `refresh_cert` response: parse the PEM bundle,
/// build a new `ClientConfig`, hot-swap into `bridge_config`. Returns
/// the new cert's validity for the next-band scheduling.
fn apply_refresh_response(
    bridge_config: &MtlsBridgeConfig,
    response: &serde_json::Value,
) -> Result<CertValidity, String> {
    let client_cert_pem = response
        .get("client_cert_pem")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "refresh response missing client_cert_pem".to_string())?;
    let client_key_pem = response
        .get("client_key_pem")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "refresh response missing client_key_pem".to_string())?;
    let ca_cert_pem = response
        .get("ca_cert_pem")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "refresh response missing ca_cert_pem".to_string())?;

    let loaded = parse_pem_bundle(client_cert_pem, client_key_pem, ca_cert_pem)?;
    // Capture leaf DER for validity parsing BEFORE handing `loaded` to
    // the TLS builder (which moves out of it).
    let leaf_der = loaded
        .client_certs
        .first()
        .cloned()
        .ok_or_else(|| "refreshed cert bundle contained no leaf cert".to_string())?;

    let new_config =
        build_client_tls_config(loaded).map_err(|e| format!("build new TLS config: {e}"))?;
    bridge_config.swap_client_config(new_config);

    parse_cert_validity(&leaf_der)
}

/// Parse PEM strings (the daemon's `refresh_cert` response shape) into a
/// `LoadedBridgeCert`. Lives here to keep `cert_expiry.rs` self-contained
/// for the refresh-client lane — the on-disk loader in
/// `daemon_transport.rs` reads from `std::fs`; this reads from owned
/// strings.
fn parse_pem_bundle(
    cert_pem: &str,
    key_pem: &str,
    ca_pem: &str,
) -> Result<LoadedBridgeCert, String> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let client_certs: Vec<CertificateDer<'static>> = {
        let mut cursor = std::io::Cursor::new(cert_pem.as_bytes());
        rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse refreshed client cert PEM: {e}"))?
    };
    if client_certs.is_empty() {
        return Err("refreshed client cert PEM contained no certificates".to_string());
    }

    let client_key: PrivateKeyDer<'static> = {
        let mut cursor = std::io::Cursor::new(key_pem.as_bytes());
        rustls_pemfile::private_key(&mut cursor)
            .map_err(|e| format!("parse refreshed client key PEM: {e}"))?
            .ok_or_else(|| "refreshed client key PEM contained no private key".to_string())?
    };

    let ca_certs: Vec<CertificateDer<'static>> = {
        let mut cursor = std::io::Cursor::new(ca_pem.as_bytes());
        rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse refreshed CA cert PEM: {e}"))?
    };
    if ca_certs.is_empty() {
        return Err("refreshed CA cert PEM contained no certificates".to_string());
    }

    Ok(LoadedBridgeCert {
        client_certs,
        client_key,
        ca_certs,
    })
}

/// Emit a `bridge.cert_refresh_attempted` event per ADR 173 §Component 7.
/// Fire-and-forget: locally log a debug line, best-effort daemon RPC.
fn emit_cert_refresh_attempted(
    context: &ExpiryEventContext,
    transport: &DaemonTransport,
    band: TriggerBand,
    attempt_seq: u64,
) {
    tracing::debug!(
        trigger_band = band.as_str(),
        attempt_seq,
        persona_id = ?context.persona_id,
        container_id = ?context.container_id,
        "bridge.cert_refresh_attempted: firing refresh attempt"
    );
    let params = serde_json::json!({
        "persona_id": context.persona_id,
        "container_id": context.container_id,
        "trigger_band": band.as_str(),
        "attempt_seq": attempt_seq,
    });
    let _ = transport.call_raw("bridge_cert_refresh_attempted", &params);
}

/// Emit the `bridge.cert_expiring_soon` warning per the pre-M6 contract.
/// Kept identical-on-the-wire so the daemon-side warning handler doesn't
/// need to change.
fn emit_cert_expiring_soon(
    context: &ExpiryEventContext,
    transport: &DaemonTransport,
    validity: CertValidity,
) {
    let remaining = (validity.not_after - now_ts()).max(0);
    tracing::warn!(
        persona_id = ?context.persona_id,
        container_id = ?context.container_id,
        ttl_remaining_secs = remaining,
        not_after = validity.not_after,
        "bridge.cert_expiring_soon: in-container client cert has <10% TTL remaining"
    );
    let params = serde_json::json!({
        "persona_id": context.persona_id,
        "container_id": context.container_id,
        "ttl_remaining_secs": remaining,
        "not_after": validity.not_after,
    });
    let _ = transport.call_raw("bridge_cert_expiring_soon", &params);
}

/// Emit the terminal `bridge.cert_refresh_failed` event when the chain
/// gives up.
fn emit_cert_refresh_failed(
    context: &ExpiryEventContext,
    transport: &DaemonTransport,
    validity: CertValidity,
    cause: RefreshFailureCause,
    reason: &str,
) {
    tracing::error!(
        persona_id = ?context.persona_id,
        container_id = ?context.container_id,
        failure_cause = cause.as_str(),
        reason,
        not_after = validity.not_after,
        "bridge.cert_refresh_failed: terminal refresh failure; bridge session will end at not_after"
    );
    let params = serde_json::json!({
        "persona_id": context.persona_id,
        "container_id": context.container_id,
        "failure_cause": cause.as_str(),
        "reason": reason,
        "not_after": validity.not_after,
    });
    let _ = transport.call_raw("bridge_cert_refresh_failed", &params);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Pure-math tier: bands + backoff + classification -----

    #[test]
    fn band_deadlines_are_at_50_75_90_offsets() {
        // A 10000-second cert: 50% at +5000, 75% at +7500, 90% at +9000,
        // hard cutoff at not_after - 30 = +9970.
        let v = CertValidity {
            not_before: 1_700_000_000,
            not_after: 1_700_010_000,
        };
        assert_eq!(v.fifty_percent_deadline(), 1_700_005_000);
        assert_eq!(v.seventy_five_percent_deadline(), 1_700_007_500);
        assert_eq!(v.ninety_percent_deadline(), 1_700_009_000);
        assert_eq!(v.hard_cutoff(), 1_700_009_970);
    }

    #[test]
    fn ninety_percent_deadline_at_correct_offset() {
        // Back-compat: the pre-M6 callers exercised this exact offset.
        let v = CertValidity {
            not_before: 1_700_000_000,
            not_after: 1_700_010_000,
        };
        assert_eq!(v.total_secs(), 10_000);
        assert_eq!(v.ninety_percent_deadline(), 1_700_009_000);
    }

    #[test]
    fn total_secs_clamps_degenerate_window() {
        let v = CertValidity {
            not_before: 1_700_000_000,
            not_after: 1_700_000_000,
        };
        assert_eq!(v.total_secs(), 1);
    }

    #[test]
    fn duration_until_deadline_handles_past_deadline() {
        let v = CertValidity {
            not_before: 1_700_000_000,
            not_after: 1_700_010_000,
        };
        let now = 1_700_100_000;
        assert_eq!(duration_until_deadline(v, now), Duration::ZERO);
    }

    #[test]
    fn duration_until_deadline_handles_future_deadline() {
        let v = CertValidity {
            not_before: 1_700_000_000,
            not_after: 1_700_010_000,
        };
        let now = 1_700_001_000;
        assert_eq!(duration_until_deadline(v, now), Duration::from_secs(8_000));
    }

    #[test]
    fn compute_band_deadlines_clamps_past_bands_to_now() {
        // Cert is 10000s long; now is at 60% TTL elapsed. The 50% band
        // should clamp to now (already past), 75% should still be in
        // the future.
        let v = CertValidity {
            not_before: 1_700_000_000,
            not_after: 1_700_010_000,
        };
        let now = 1_700_006_000; // 60% elapsed
        let bands = compute_band_deadlines(v, now);
        assert_eq!(bands[0].0, TriggerBand::Fifty);
        assert_eq!(bands[0].1, now); // clamped to now
        assert_eq!(bands[1].0, TriggerBand::SeventyFive);
        assert_eq!(bands[1].1, 1_700_007_500); // unchanged
        assert_eq!(bands[2].0, TriggerBand::Ninety);
        assert_eq!(bands[2].1, 1_700_009_000);
        assert_eq!(bands[3].0, TriggerBand::NinetyNine);
        assert_eq!(bands[3].1, 1_700_009_970);
    }

    // ----- T2: 4-band timer fires at correct bands -----

    #[test]
    fn t2_band_timer_fires_at_50_and_75_correctly() {
        // T2 acceptance: with `now_ts` injection, band deadlines align
        // with the 50% / 75% TTL marks for a 1000-second cert.
        let v = CertValidity {
            not_before: 1_000_000,
            not_after: 1_001_000,
        };
        // now = not_before, ALL bands in future.
        let bands = compute_band_deadlines(v, 1_000_000);
        assert_eq!(bands[0].1, 1_000_500, "50% band at not_before + 500");
        assert_eq!(bands[1].1, 1_000_750, "75% band at not_before + 750");
        assert_eq!(bands[2].1, 1_000_900, "90% band at not_before + 900");
        assert_eq!(bands[3].1, 1_000_970, "hard cutoff at not_after - 30");

        // duration_until is monotonically increasing for an at-not_before
        // start.
        assert_eq!(duration_until(bands[0].1, 1_000_000), Duration::from_secs(500));
        assert_eq!(duration_until(bands[1].1, 1_000_000), Duration::from_secs(750));
        assert_eq!(duration_until(bands[2].1, 1_000_000), Duration::from_secs(900));
        assert_eq!(duration_until(bands[3].1, 1_000_000), Duration::from_secs(970));
    }

    // ----- T2: exp-backoff sequence + per-tier caps -----

    #[test]
    fn t2_backoff_grows_exponentially_until_cap_dev0() {
        // dev0 cap = 300s. base = 2s. With jitter = 1.0 (use full
        // window), attempts 0..N grow 2, 4, 8, 16, 32, 64, 128, 256,
        // 300 (cap), 300, ...
        let cap = Tier::Dev0.backoff_cap_secs();
        let now = 1_000;
        // Huge hard cutoff so the per-cutoff clamp doesn't fire.
        let hard = 1_000_000;
        let attempts = [
            (0u32, 2u64),
            (1, 4),
            (2, 8),
            (3, 16),
            (4, 32),
            (5, 64),
            (6, 128),
            (7, 256),
            (8, 300), // capped
            (9, 300), // still capped
        ];
        for (n, expected) in attempts {
            let d = compute_backoff(n, cap, 1.0, now, hard);
            assert_eq!(
                d.as_secs(),
                expected,
                "dev0 backoff at attempt={n} with full jitter"
            );
        }
    }

    #[test]
    fn t2_backoff_caps_at_60s_for_team0() {
        let cap = Tier::Team0.backoff_cap_secs();
        assert_eq!(cap, 60);
        // base = 2s. attempts 0..4: 2, 4, 8, 16, 32, 60 (capped).
        let now = 1_000;
        let hard = 1_000_000;
        assert_eq!(compute_backoff(0, cap, 1.0, now, hard).as_secs(), 2);
        assert_eq!(compute_backoff(4, cap, 1.0, now, hard).as_secs(), 32);
        assert_eq!(compute_backoff(5, cap, 1.0, now, hard).as_secs(), 60);
        assert_eq!(compute_backoff(100, cap, 1.0, now, hard).as_secs(), 60);
    }

    #[test]
    fn t2_backoff_caps_at_60s_for_ent0() {
        assert_eq!(Tier::Ent0.backoff_cap_secs(), 60);
    }

    #[test]
    fn backoff_full_jitter_uniform_zero_to_window() {
        // With jitter = 0.0, backoff is 0.
        // With jitter = 0.5, backoff is window/2 (rounded down).
        let cap = 300;
        let now = 1_000;
        let hard = 1_000_000;
        assert_eq!(compute_backoff(8, cap, 0.0, now, hard).as_secs(), 0);
        assert_eq!(compute_backoff(8, cap, 0.5, now, hard).as_secs(), 150);
        assert_eq!(compute_backoff(8, cap, 1.0, now, hard).as_secs(), 300);
    }

    #[test]
    fn backoff_clamps_at_hard_cutoff() {
        // hard cutoff is 100s away; even with cap = 300 and full jitter,
        // backoff cannot exceed (hard_cutoff - now) = 100.
        let cap = 300;
        let now = 1_000;
        let hard = 1_100;
        assert_eq!(compute_backoff(8, cap, 1.0, now, hard).as_secs(), 100);
    }

    #[test]
    fn backoff_clamps_to_zero_past_hard_cutoff() {
        // now > hard cutoff: window is 0.
        let cap = 300;
        let now = 2_000;
        let hard = 1_000;
        assert_eq!(compute_backoff(8, cap, 1.0, now, hard).as_secs(), 0);
    }

    // ----- T2: each failure-cause bucket produces correct client behavior -----

    #[test]
    fn t2_auth_failures_route_to_auth_bucket() {
        // ADR 173 §Component 5: auth_failure_* MUST refuse retry.
        assert_eq!(
            RefreshFailureCause::AuthFailureRevoked.bucket(),
            FailureBucket::Auth
        );
        assert_eq!(
            RefreshFailureCause::AuthFailureExpired.bucket(),
            FailureBucket::Auth
        );
        assert_eq!(
            RefreshFailureCause::AuthFailurePersonaUnknown.bucket(),
            FailureBucket::Auth
        );
    }

    #[test]
    fn t2_mint_failures_route_to_mint_bucket() {
        // ADR 173 §Component 5: mint_failure_* → slow-retry.
        assert_eq!(
            RefreshFailureCause::MintFailureVaultSealed.bucket(),
            FailureBucket::Mint
        );
        assert_eq!(
            RefreshFailureCause::MintFailureInternal.bucket(),
            FailureBucket::Mint
        );
    }

    #[test]
    fn t2_transport_error_routes_to_transport_bucket() {
        assert_eq!(
            RefreshFailureCause::TransportError.bucket(),
            FailureBucket::Transport
        );
        // Unknown / NotImplemented variants are treated as transport
        // so retry happens — we'd rather over-retry than silently
        // give up.
        assert_eq!(
            RefreshFailureCause::Unknown.bucket(),
            FailureBucket::Transport
        );
        assert_eq!(
            RefreshFailureCause::NotImplemented.bucket(),
            FailureBucket::Transport
        );
        assert_eq!(
            RefreshFailureCause::ExhaustedRetries.bucket(),
            FailureBucket::Transport
        );
    }

    #[test]
    fn refresh_failure_cause_wire_format_roundtrip() {
        // Every named variant roundtrips through the wire format.
        let variants = [
            RefreshFailureCause::TransportError,
            RefreshFailureCause::AuthFailureRevoked,
            RefreshFailureCause::AuthFailureExpired,
            RefreshFailureCause::AuthFailurePersonaUnknown,
            RefreshFailureCause::MintFailureVaultSealed,
            RefreshFailureCause::MintFailureInternal,
            RefreshFailureCause::ExhaustedRetries,
            RefreshFailureCause::NotImplemented,
        ];
        for v in variants {
            assert_eq!(RefreshFailureCause::from_wire(v.as_str()), v);
        }
    }

    #[test]
    fn refresh_failure_cause_unknown_wire_value() {
        assert_eq!(
            RefreshFailureCause::from_wire("brand_new_cause"),
            RefreshFailureCause::Unknown
        );
    }

    // ----- Refresh state lifecycle -----

    #[test]
    fn refresh_state_default_is_not_failing() {
        let s = RefreshState::default();
        assert_eq!(s.attempt_seq, 0);
        assert!(!s.failing);
        assert!(!s.terminated);
        assert_eq!(s.failed_attempts, 0);
    }

    #[test]
    fn refresh_client_error_display_mentions_band() {
        let e = RefreshClientError::RefreshFailing;
        let s = e.to_string();
        assert!(s.contains("90%"), "RefreshFailing display should mention 90% band; got: {s}");
        assert!(s.contains("refused"), "should mention RPCs are refused; got: {s}");
    }

    // ----- Tier resolution -----
    //
    // The three EMBER_TIER tests share a process-level mutex so they
    // never race on env-var reads — cargo runs lib tests in parallel
    // threads by default and env is process-global.

    static TIER_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn tier_from_env_team0_caps_at_60s() {
        let _g = TIER_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: the mutex makes the set / read / remove sequence
        // exclusive across the lib's test binary.
        unsafe {
            std::env::set_var("EMBER_TIER", "team0");
        }
        let t = Tier::from_env();
        assert_eq!(t, Tier::Team0);
        assert_eq!(t.backoff_cap_secs(), 60);
        unsafe {
            std::env::remove_var("EMBER_TIER");
        }
    }

    #[test]
    fn tier_from_env_defaults_to_dev0_when_unset() {
        let _g = TIER_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            std::env::remove_var("EMBER_TIER");
        }
        let t = Tier::from_env();
        assert_eq!(t, Tier::Dev0);
        assert_eq!(t.backoff_cap_secs(), 300);
    }

    #[test]
    fn tier_from_env_unknown_value_falls_back_to_dev0() {
        let _g = TIER_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            std::env::set_var("EMBER_TIER", "experimental");
        }
        let t = Tier::from_env();
        assert_eq!(t, Tier::Dev0);
        unsafe {
            std::env::remove_var("EMBER_TIER");
        }
    }

    // ----- ExpiryEventContext env reads -----

    #[test]
    fn expiry_event_context_reads_env() {
        // SAFETY: same caveat as tier_from_env_team0_caps_at_60s.
        unsafe {
            std::env::set_var("EMBER_PERSONA_ID", "persona-test-expiry");
            std::env::set_var("EMBER_CONTAINER_ID", "ctr-test-expiry");
        }
        let ctx = ExpiryEventContext::from_env();
        assert_eq!(ctx.persona_id.as_deref(), Some("persona-test-expiry"));
        assert_eq!(ctx.container_id.as_deref(), Some("ctr-test-expiry"));
        unsafe {
            std::env::remove_var("EMBER_PERSONA_ID");
            std::env::remove_var("EMBER_CONTAINER_ID");
        }
    }

    // ----- Trigger band wire format -----

    #[test]
    fn trigger_band_wire_format() {
        assert_eq!(TriggerBand::Fifty.as_str(), "50");
        assert_eq!(TriggerBand::SeventyFive.as_str(), "75");
        assert_eq!(TriggerBand::Ninety.as_str(), "90");
        assert_eq!(TriggerBand::NinetyNine.as_str(), "99");
    }

    // ----- PEM parsing -----

    #[test]
    fn parse_pem_bundle_rejects_empty_cert() {
        let err = parse_pem_bundle("", "", "").unwrap_err();
        assert!(err.contains("no certificates") || err.contains("private key"));
    }
}
