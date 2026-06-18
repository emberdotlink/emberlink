//! CLASSIFICATION: PUBLIC
//!
//! EventSink trait + GrantEvent types — extracted from ember-daemon
//! per ADR 147 (ARCH-PROXY-TRAITS-EXPAND Slice A). ember-daemon's
//! infra/events.rs gets a re-export in Slice B so existing callers
//! don't break.
//!
//! The `GrantEvent` enum mirrors `ember_daemon::infra::events::GrantEvent`
//! verbatim so a downstream `pub use core_proxy_forward::GrantEvent;`
//! is byte-compatible with today's call sites. The new helper types
//! (`ThresholdAxis`, `ThresholdBand`) are higher-level abstractions used
//! by `EventSink::record_threshold_crossing` — they do not collide with
//! the `&'static str` axis / `&'static str` percent fields the enum
//! variants already carry on the wire.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Server-initiated grant-state event broadcast to connected clients.
///
/// Mirrors `ember_daemon::infra::events::GrantEvent` exactly so the
/// daemon's `infra/events.rs` can collapse into a re-export (Slice B).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrantEvent {
    /// A grant has been revoked. Connected agents should zeroize any cached
    /// credential material tied to `grant_id` for `persona_id`.
    Revoked {
        grant_id: String,
        persona_id: String,
    },
    /// A Statement's per-axis usage crossed an 80% or 95% threshold band.
    /// Informational — the grant stays active. Agents MAY surface the warning
    /// to the user or pre-request a budget extension.
    BudgetWarning {
        grant_id: String,
        statement_sid: String,
        axis: &'static str,
        used: u64,
        budget: u64,
        /// Band label crossed, one of `"80"` or `"95"`.
        percent: &'static str,
    },
    /// A Statement's per-axis usage reached 100%. The proxy will reject
    /// subsequent calls that depend on that statement with a
    /// `budget_exhausted` 429; the grant as a whole flips to
    /// `ExhaustedByBudget` only when every applicable statement is exhausted.
    BudgetExhausted {
        grant_id: String,
        statement_sid: String,
        axis: &'static str,
        used: u64,
        budget: u64,
    },
}

/// Per-axis identity for budget thresholds passed to
/// `EventSink::record_threshold_crossing`. Higher-level than the
/// `&'static str` axis fields carried on the wire — the sink
/// implementation projects this back down to a string when fanning out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThresholdAxis {
    Tokens,
    Cents,
    Requests,
    WallSeconds,
}

/// Threshold band crossed for a given axis. Maps to the wire-format
/// `percent` field (`"80"`/`"95"` for Warning, `100` for Exhausted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThresholdBand {
    Warning,
    Exhausted,
}

/// Errors returned by `EventSink` operations.
#[derive(Debug)]
pub enum EventError {
    Log(String),
    Broadcast(String),
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventError::Log(msg) => write!(f, "event log error: {msg}"),
            EventError::Broadcast(msg) => write!(f, "event broadcast error: {msg}"),
        }
    }
}

impl std::error::Error for EventError {}

/// Trait that decouples proxy pipeline logic from its audit log and
/// grant-event broadcast channel.
///
/// The daemon's in-process implementation (Slice B) writes to the
/// SQLite audit table and the `tokio::sync::broadcast` channel. A
/// remote implementation (Slice C) will RPC over a Unix-domain socket
/// instead.
// pub trait EventSink — ARCH-PROXY-TRAITS-EXPAND-A
#[async_trait]
pub trait EventSink: Send + Sync + 'static {
    /// Append an audit-log entry.
    ///
    /// Parameter shape mirrors `PolicyBackend::log_event` so Slice B
    /// can route a single call site to either trait without reshaping.
    async fn log_event(
        &self,
        persona_id: Option<&str>,
        event_kind: &str,
        credential_name: Option<&str>,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<(), EventError>;

    /// Broadcast a grant-lifecycle event to subscribers.
    ///
    /// Implementations SHOULD be non-blocking — slow subscribers must
    /// not stall the proxy hot path.
    async fn broadcast(&self, event: GrantEvent);

    /// Record that a Statement's per-axis usage crossed `band` on `axis`,
    /// returning `true` if this is the first crossing for that
    /// `(grant_id, statement_sid, axis, band)` tuple. Idempotent — a
    /// repeat call with the same tuple returns `false` and does not
    /// re-broadcast.
    async fn record_threshold_crossing(
        &self,
        grant_id: &str,
        statement_sid: &str,
        axis: ThresholdAxis,
        band: ThresholdBand,
    ) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_event_variants_construct() {
        let _ = GrantEvent::Revoked {
            grant_id: "g-1".into(),
            persona_id: "p-1".into(),
        };
        let _ = GrantEvent::BudgetWarning {
            grant_id: "g-1".into(),
            statement_sid: "s-1".into(),
            axis: "tokens",
            used: 800,
            budget: 1000,
            percent: "80",
        };
        let _ = GrantEvent::BudgetExhausted {
            grant_id: "g-1".into(),
            statement_sid: "s-1".into(),
            axis: "tokens",
            used: 1000,
            budget: 1000,
        };
    }

    #[test]
    fn threshold_types_construct() {
        let _ = ThresholdAxis::Tokens;
        let _ = ThresholdAxis::Cents;
        let _ = ThresholdAxis::Requests;
        let _ = ThresholdAxis::WallSeconds;
        let _ = ThresholdBand::Warning;
        let _ = ThresholdBand::Exhausted;
    }

    #[test]
    fn event_error_display() {
        let err = EventError::Log("boom".into());
        assert!(err.to_string().contains("boom"));
        let err = EventError::Broadcast("kaboom".into());
        assert!(err.to_string().contains("kaboom"));
    }
}
