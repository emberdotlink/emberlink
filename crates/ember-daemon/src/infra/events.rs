//! Server-initiated events pushed to connected socket clients.
//!
//! When a grant is revoked (or later, other grant state changes), the daemon
//! fans the event out over a broadcast channel. Each connected client's
//! connection handler subscribes and forwards matching events to the client
//! as JSON-RPC notifications.
//!
//! Notifications carry only the bare identifiers needed for the client to
//! invalidate cached state (`grant_id`, `persona_id`). They intentionally do
//! not carry scope, credential name, timestamps, or revocation reason — those
//! could constitute a timing or metadata leak to an agent that merely holds
//! a cached handle. Agents can re-query `list_grants` if they need more.
//!
//! ARCH-PROXY-TRAITS-EXPAND-B: the `GrantEvent` type itself now lives in
//! `core-proxy-forward` so the EventSink trait (also in that crate) can take
//! it as its native event type. This module re-exports it for back-compat
//! with existing call sites (`use crate::infra::events::GrantEvent;`) and
//! provides an extension trait `GrantEventExt` for the daemon-side helper
//! methods that can't live on the foreign type.

pub use core_proxy_forward::GrantEvent;

/// Daemon-side helpers on `GrantEvent` — the wire-format method name and
/// JSON-RPC params shape. Lives as an extension trait because Rust forbids
/// inherent `impl` blocks on foreign types (`GrantEvent` now ships from
/// `core-proxy-forward`).
///
/// Bring into scope with `use crate::infra::events::GrantEventExt;` at any
/// call site that needs `.method_name()` / `.params()`.
pub trait GrantEventExt {
    /// The JSON-RPC method name used when this event is forwarded to a client
    /// over the unix socket.
    ///
    /// Budget events use dot-separated names (`budget.warning`,
    /// `budget.exhausted`) because the TS/Py agent SDKs demultiplex on those
    /// exact strings; revocation keeps the historical `grant_revoked` shape.
    fn method_name(&self) -> &'static str;

    /// JSON params payload for the notification wire format.
    fn params(&self) -> serde_json::Value;
}

impl GrantEventExt for GrantEvent {
    fn method_name(&self) -> &'static str {
        match self {
            GrantEvent::Revoked { .. } => "grant_revoked",
            GrantEvent::BudgetWarning { .. } => "budget.warning",
            GrantEvent::BudgetExhausted { .. } => "budget.exhausted",
        }
    }

    fn params(&self) -> serde_json::Value {
        match self {
            GrantEvent::Revoked {
                grant_id,
                persona_id,
            } => serde_json::json!({
                "grant_id": grant_id,
                "persona_id": persona_id,
            }),
            GrantEvent::BudgetWarning {
                grant_id,
                statement_sid,
                axis,
                used,
                budget,
                percent,
            } => {
                // percent is the band label ("80"/"95"); parse into a number
                // so the wire payload matches the TS `BudgetWarningNotification`
                // shape (numeric `percent`).
                let pct: u32 = percent.parse().unwrap_or(0);
                serde_json::json!({
                    "grant_id": grant_id,
                    "statement_sid": statement_sid,
                    "axis": axis,
                    "used": used,
                    "budget": budget,
                    "percent": pct,
                    "threshold_band": "warning",
                })
            }
            GrantEvent::BudgetExhausted {
                grant_id,
                statement_sid,
                axis,
                used,
                budget,
            } => serde_json::json!({
                "grant_id": grant_id,
                "statement_sid": statement_sid,
                "axis": axis,
                "used": used,
                "budget": budget,
                "percent": 100,
                "threshold_band": "exhausted",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_method_name() {
        let ev = GrantEvent::Revoked {
            grant_id: "grant-1".into(),
            persona_id: "persona-1".into(),
        };
        assert_eq!(ev.method_name(), "grant_revoked");
    }

    #[test]
    fn revoked_params_shape() {
        let ev = GrantEvent::Revoked {
            grant_id: "grant-1".into(),
            persona_id: "persona-1".into(),
        };
        let params = ev.params();
        assert_eq!(params["grant_id"], "grant-1");
        assert_eq!(params["persona_id"], "persona-1");
        // Only these two fields — no scope, no credential_name, no timestamp.
        assert_eq!(params.as_object().unwrap().len(), 2);
    }

    #[test]
    fn budget_warning_method_and_params_match_sdk_contract() {
        // The TS/Py SDKs demux on exactly these method strings and param
        // shapes — changing either breaks the wire contract.
        let ev = GrantEvent::BudgetWarning {
            grant_id: "grant-1".into(),
            statement_sid: "S1".into(),
            axis: "tokens",
            used: 8_000,
            budget: 10_000,
            percent: "80",
        };
        assert_eq!(ev.method_name(), "budget.warning");
        let params = ev.params();
        assert_eq!(params["grant_id"], "grant-1");
        assert_eq!(params["statement_sid"], "S1");
        assert_eq!(params["axis"], "tokens");
        assert_eq!(params["used"], 8_000);
        assert_eq!(params["budget"], 10_000);
        assert_eq!(params["percent"], 80);
        assert_eq!(params["threshold_band"], "warning");
    }

    #[test]
    fn budget_exhausted_method_and_params_match_sdk_contract() {
        let ev = GrantEvent::BudgetExhausted {
            grant_id: "grant-2".into(),
            statement_sid: "S1".into(),
            axis: "cents",
            used: 100,
            budget: 100,
        };
        assert_eq!(ev.method_name(), "budget.exhausted");
        let params = ev.params();
        assert_eq!(params["percent"], 100);
        assert_eq!(params["threshold_band"], "exhausted");
        assert_eq!(params["axis"], "cents");
    }
}
