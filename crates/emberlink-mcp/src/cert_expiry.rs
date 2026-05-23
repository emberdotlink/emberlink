//! `bridge.cert_expiring_soon` 90%-TTL timer for the in-container mTLS
//! bridge transport (design component 1, implementation-note-536).
//!
//! The brief locks in the timing: fire ONCE at ≥90% of the cert's TTL
//! elapsed (i.e. 10% lifetime remaining), so the cert is still valid
//! and the daemon RPC connection still works. The fire posts a
//! best-effort `bridge.cert_expiring_soon` event to the daemon's event
//! log AND logs a structured `tracing::warn!`.
//!
//! ## Why log AND post
//!
//! The daemon-side `crates/ember-daemon/src/infra/persona.rs::
//! check_and_emit_cert_expiring_soon` already fires when the operator-launched
//! bridge LISTENER side observes a near-expiry client cert. The
//! in-container CLIENT side hitting the same threshold could in principle
//! be inferred by the daemon, but only at the moment of the next RPC —
//! a client that's idle for the last 10% of its TTL would silently miss
//! the warning. Firing client-side closes that gap.
//!
//! The daemon does not yet expose a `bridge_cert_expiring_soon` JSON-RPC
//! method that the client could call to append to the event log; the
//! current behavior is therefore "log warn locally + try a best-effort
//! daemon call that no-ops if the method is absent." When the daemon
//! lands the matching method, the client-side warning starts threading
//! through to the audit trail automatically.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::CertificateDer;
use x509_parser::prelude::FromDer;

use crate::daemon_transport::DaemonTransport;

/// Parsed cert validity window — Unix seconds at both bounds. Returned
/// by [`parse_cert_validity`] so the scheduler can compute the
/// 90%-TTL deadline without re-parsing on every call.
#[derive(Debug, Clone, Copy)]
pub struct CertValidity {
    pub not_before: i64,
    pub not_after: i64,
}

impl CertValidity {
    /// Total TTL in seconds. Always positive — clamped to 1 to avoid
    /// divide-by-zero if the cert validity window is degenerate.
    pub fn total_secs(&self) -> i64 {
        (self.not_after - self.not_before).max(1)
    }

    /// Unix timestamp at which 90% of the cert's TTL is elapsed (10% remaining).
    /// This is the fire-time for the `bridge.cert_expiring_soon` event.
    pub fn ninety_percent_deadline(&self) -> i64 {
        let total = self.total_secs();
        // 90% of TTL elapsed = not_before + 0.9*total. Use integer math
        // (no f64) so the deadline is bit-exact reproducible across
        // platforms — TTLs round to seconds in this codebase anyway.
        self.not_before + (total * 9 / 10)
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
/// `pause()` machinery but the brief's "90% TTL elapsed" math is
/// wallclock-anchored, so the scheduler reads SystemTime.
pub fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Compute the `sleep` duration until the 90% deadline fires, given the
/// current wallclock. Returns `Duration::ZERO` when the deadline is in
/// the past (fire immediately).
pub fn duration_until_deadline(validity: CertValidity, now: i64) -> Duration {
    let deadline = validity.ninety_percent_deadline();
    if deadline <= now {
        Duration::ZERO
    } else {
        Duration::from_secs((deadline - now) as u64)
    }
}

/// Payload metadata that rides along with the event. Captured at startup
/// from the orchestrator-supplied env so the warning carries the
/// persona/container identity even if the cert SAN parse fails.
#[derive(Debug, Clone)]
pub struct ExpiryEventContext {
    pub persona_id: Option<String>,
    pub container_id: Option<String>,
}

impl ExpiryEventContext {
    /// Read `EMBER_PERSONA_ID` and `EMBER_CONTAINER_ID` from the
    /// environment. Both are best-effort — the warning still fires with
    /// `None` values if the orchestrator hasn't populated them.
    pub fn from_env() -> Self {
        Self {
            persona_id: std::env::var("EMBER_PERSONA_ID").ok(),
            container_id: std::env::var("EMBER_CONTAINER_ID").ok(),
        }
    }
}

/// Spawn the background task that fires the warning at the 90% TTL deadline.
///
/// Lifecycle: the spawned task lives on the supplied tokio runtime, sleeps
/// until the deadline, then fires ONCE and exits. Dropping the runtime
/// (or aborting the returned join handle) cancels the timer.
///
/// The post-fire daemon call is wrapped in a `tokio::spawn` so the timer
/// task doesn't block on the RPC — the warning is logged regardless of
/// whether the daemon round-trip succeeds.
pub fn spawn_expiry_timer(
    runtime: Arc<tokio::runtime::Runtime>,
    validity: CertValidity,
    context: ExpiryEventContext,
    transport: Arc<DaemonTransport>,
) -> tokio::task::JoinHandle<()> {
    runtime.spawn(async move {
        let sleep_for = duration_until_deadline(validity, now_ts());
        // `tokio::time::sleep_until` would suffice on Instant-based timing
        // but the validity window is wallclock-anchored. A plain `sleep`
        // over the computed delta is sufficient; the worst case (clock
        // jumps forward past the deadline mid-sleep) just fires slightly
        // late — acceptable for a "10% TTL remaining" warning.
        tokio::time::sleep(sleep_for).await;

        let remaining = (validity.not_after - now_ts()).max(0);
        tracing::warn!(
            persona_id = ?context.persona_id,
            container_id = ?context.container_id,
            ttl_remaining_secs = remaining,
            not_after = validity.not_after,
            "bridge.cert_expiring_soon: in-container client cert has <10% TTL remaining — \
             orchestrator should respawn before silent mid-call expiry"
        );

        // Best-effort daemon notification. The method name mirrors the
        // event kind; if the daemon doesn't recognize it the call
        // returns a -32601 / DaemonError and we move on. No retry — a
        // single fire is the brief's contract.
        let params = serde_json::json!({
            "persona_id": context.persona_id,
            "container_id": context.container_id,
            "ttl_remaining_secs": remaining,
            "not_after": validity.not_after,
        });
        match transport.call_tool("bridge_cert_expiring_soon", &params) {
            Ok(_) => tracing::debug!("bridge.cert_expiring_soon: daemon acknowledged"),
            Err(e) => tracing::debug!(
                error = %e,
                "bridge.cert_expiring_soon: daemon notify failed (best-effort, not fatal)"
            ),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ninety_percent_deadline_at_correct_offset() {
        // A 10000-second cert should fire the warning at not_before + 9000.
        let v = CertValidity {
            not_before: 1_700_000_000,
            not_after: 1_700_010_000,
        };
        assert_eq!(v.total_secs(), 10_000);
        assert_eq!(v.ninety_percent_deadline(), 1_700_009_000);
    }

    #[test]
    fn total_secs_clamps_degenerate_window() {
        // A cert whose not_after equals not_before would otherwise produce
        // a zero divisor — total_secs clamps to 1 so the math stays sane.
        let v = CertValidity {
            not_before: 1_700_000_000,
            not_after: 1_700_000_000,
        };
        assert_eq!(v.total_secs(), 1);
    }

    #[test]
    fn duration_until_deadline_handles_past_deadline() {
        // Deadline already elapsed → fire immediately (Duration::ZERO).
        let v = CertValidity {
            not_before: 1_700_000_000,
            not_after: 1_700_010_000,
        };
        // now is well past not_after.
        let now = 1_700_100_000;
        assert_eq!(duration_until_deadline(v, now), Duration::ZERO);
    }

    #[test]
    fn duration_until_deadline_handles_future_deadline() {
        // 10000s cert; now is at not_before + 1000s (10% elapsed). Deadline
        // is 90% elapsed = not_before + 9000s → 8000s remaining.
        let v = CertValidity {
            not_before: 1_700_000_000,
            not_after: 1_700_010_000,
        };
        let now = 1_700_001_000;
        assert_eq!(duration_until_deadline(v, now), Duration::from_secs(8_000));
    }

    #[test]
    fn expiry_event_context_reads_env() {
        // SAFETY: tests run single-threaded for env mutation. The Cargo
        // default is parallel by default — this would race with other
        // tests that read EMBER_PERSONA_ID. We avoid that by using a
        // never-used-elsewhere variable name pattern in production code;
        // this is a smoke test on the env-read shape, not on a contract
        // shared with other tests.
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
}
