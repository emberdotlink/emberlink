//! JSON protocol types for the agent stdio interface.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Request envelope
// ---------------------------------------------------------------------------

/// A single request from the agent.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentRequest {
    /// Unique request ID for correlation.
    pub id: String,
    /// Method name.
    pub method: String,
    /// Method-specific parameters.
    #[serde(default)]
    pub params: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Response envelope
// ---------------------------------------------------------------------------

/// A single response to the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AgentError>,
}

impl AgentResponse {
    pub fn ok(id: impl Into<String>, result: serde_json::Value) -> Self {
        Self {
            id: id.into(),
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: impl Into<String>, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            result: None,
            error: Some(AgentError {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentError {
    pub code: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Method-specific parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct RequestGrantParams {
    /// Desired capability (e.g., "ReadCredential", "UsePasskey").
    pub scope: String,
    /// Specific resource ID, or omit for "any."
    pub resource_id: Option<String>,
    /// Desired duration in seconds.
    pub duration_secs: Option<u64>,
    /// Human-readable reason for the request.
    pub reason: Option<String>,
    /// Name of the agent tool or action that triggered this request.
    /// Maps to the NOTIF-1 `tool_name` banner field.
    pub tool_name: Option<String>,
    /// Target URL the tool is acting on (e.g. an API endpoint).
    /// Maps to the NOTIF-1 `target_url` banner field; `target_host` is
    /// derived from it in the runtime when present.
    pub target_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GrantStatusParams {
    pub grant_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UseCredentialParams {
    pub grant_id: String,
    pub credential_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayRequestGrantParams {
    /// WebSocket relay URL (e.g., "wss://relay.example.com").
    pub relay: String,
    /// Target identity to request a grant from.
    pub target: String,
    /// Desired capability scope.
    pub scope: String,
    /// Human-readable justification.
    pub justification: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayGrantStatusParams {
    /// WebSocket relay URL.
    pub relay: String,
    /// Target identity whose pending requests to fetch.
    pub target: String,
}

// ---------------------------------------------------------------------------
// Response payloads
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct WhoamiResponse {
    pub persona_id: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GrantInfo {
    pub grant_id: String,
    pub issuer_id: String,
    pub capability: String,
    pub status: String,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestGrantResponse {
    pub request_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialInfo {
    pub credential_id: String,
    pub label: Option<String>,
    /// Credential class (e.g., "password", "api_key", "ssh_key").
    pub credential_class: Option<String>,
}

/// Known method names.
pub mod methods {
    pub const WHOAMI: &str = "whoami";
    pub const LIST_GRANTS: &str = "list_grants";
    pub const REQUEST_GRANT: &str = "request_grant";
    pub const GRANT_STATUS: &str = "grant_status";
    pub const USE_CREDENTIAL: &str = "use_credential";
    pub const RELAY_REQUEST_GRANT: &str = "relay_request_grant";
    pub const RELAY_GRANT_STATUS: &str = "relay_grant_status";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_deserializes() {
        let json = r#"{"id":"req-1","method":"whoami","params":{}}"#;
        let req: AgentRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, "req-1");
        assert_eq!(req.method, "whoami");
    }

    #[test]
    fn request_with_params() {
        let json = r#"{"id":"req-2","method":"request_grant","params":{"scope":"ReadCredential","resource_id":"cred-1","duration_secs":3600,"reason":"need it"}}"#;
        let req: AgentRequest = serde_json::from_str(json).unwrap();
        let params: RequestGrantParams = serde_json::from_value(req.params).unwrap();
        assert_eq!(params.scope, "ReadCredential");
        assert_eq!(params.duration_secs, Some(3600));
    }

    #[test]
    fn response_ok_serializes() {
        let resp = AgentResponse::ok("req-1", serde_json::json!({"persona_id": "p-1"}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("persona_id"));
        assert!(!json.contains("error"));
    }

    #[test]
    fn response_err_serializes() {
        let resp = AgentResponse::err("req-1", "NOT_FOUND", "Grant not found");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("NOT_FOUND"));
        assert!(!json.contains("result"));
    }

    #[test]
    fn request_without_params_uses_default() {
        let json = r#"{"id":"req-3","method":"list_grants"}"#;
        let req: AgentRequest = serde_json::from_str(json).unwrap();
        assert!(req.params.is_null());
    }
}
