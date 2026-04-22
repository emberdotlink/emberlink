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

use serde::{Deserialize, Serialize};

/// Server-initiated grant-state event broadcast to connected clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrantEvent {
    /// A grant has been revoked. Connected agents should zeroize any cached
    /// credential material tied to `grant_id` for `persona_id`.
    Revoked {
        grant_id: String,
        persona_id: String,
    },
}

impl GrantEvent {
    /// The JSON-RPC method name used when this event is forwarded to a client
    /// over the unix socket.
    pub fn method_name(&self) -> &'static str {
        match self {
            GrantEvent::Revoked { .. } => "grant_revoked",
        }
    }

    /// JSON params payload for the notification wire format.
    pub fn params(&self) -> serde_json::Value {
        match self {
            GrantEvent::Revoked {
                grant_id,
                persona_id,
            } => serde_json::json!({
                "grant_id": grant_id,
                "persona_id": persona_id,
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
}
