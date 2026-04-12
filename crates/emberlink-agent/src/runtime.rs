//! Agent runtime — processes protocol commands against local state.

use std::rc::Rc;

use core_state::EventStore;
use core_types::PresentationAudienceKind;

use crate::protocol::*;

/// Configuration for the agent runtime.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// The persona ID this agent operates as.
    pub persona_id: String,
    /// Human-readable label for this agent.
    pub label: Option<String>,
}

/// The agent runtime dispatches protocol requests against the EventStore.
pub struct AgentRuntime {
    config: AgentConfig,
    store: Rc<EventStore>,
}

impl AgentRuntime {
    pub fn new(config: AgentConfig, store: Rc<EventStore>) -> Self {
        Self { config, store }
    }

    /// Dispatch a single request and return the response.
    pub fn handle(&self, request: &AgentRequest) -> AgentResponse {
        match request.method.as_str() {
            methods::WHOAMI => self.handle_whoami(&request.id),
            methods::LIST_GRANTS => self.handle_list_grants(&request.id),
            methods::REQUEST_GRANT => self.handle_request_grant(request),
            methods::GRANT_STATUS => self.handle_grant_status(request),
            methods::USE_CREDENTIAL => self.handle_use_credential(request),
            _ => AgentResponse::err(
                &request.id,
                "UNKNOWN_METHOD",
                format!("Unknown method: {}", request.method),
            ),
        }
    }

    fn handle_whoami(&self, id: &str) -> AgentResponse {
        let resp = WhoamiResponse {
            persona_id: self.config.persona_id.clone(),
            label: self.config.label.clone(),
        };
        AgentResponse::ok(id, serde_json::to_value(resp).unwrap())
    }

    fn handle_list_grants(&self, id: &str) -> AgentResponse {
        // Query EventStore for grants where this agent's persona is the recipient.
        // Use Peer kind — agents are persona-based peers in the trust model.
        let grants = match self.store.list_grants_for_recipient(
            PresentationAudienceKind::Peer,
            &self.config.persona_id,
        ) {
            Ok(g) => g,
            Err(e) => {
                return AgentResponse::err(
                    id,
                    "STORE_ERROR",
                    format!("Failed to query grants: {e}"),
                );
            }
        };

        let infos: Vec<GrantInfo> = grants
            .into_iter()
            .map(|g| GrantInfo {
                grant_id: g.id,
                issuer_id: g.issuing_persona_id,
                capability: format!("{} capabilities", g.capability_count),
                status: g.status.as_str().to_string(),
                expires_at: g.expires_at,
            })
            .collect();

        AgentResponse::ok(id, serde_json::to_value(infos).unwrap())
    }

    fn handle_request_grant(&self, request: &AgentRequest) -> AgentResponse {
        let params: RequestGrantParams = match serde_json::from_value(request.params.clone()) {
            Ok(p) => p,
            Err(e) => {
                return AgentResponse::err(
                    &request.id,
                    "INVALID_PARAMS",
                    format!("Invalid request_grant params: {e}"),
                );
            }
        };

        // TODO: create ApprovalRequest in the approval queue
        AgentResponse::err(
            &request.id,
            "PENDING_APPROVAL",
            format!(
                "Grant request submitted for {} — awaiting human approval",
                params.scope
            ),
        )
    }

    fn handle_grant_status(&self, request: &AgentRequest) -> AgentResponse {
        let params: GrantStatusParams = match serde_json::from_value(request.params.clone()) {
            Ok(p) => p,
            Err(e) => {
                return AgentResponse::err(
                    &request.id,
                    "INVALID_PARAMS",
                    format!("Invalid grant_status params: {e}"),
                );
            }
        };

        // Query EventStore for the specific grant.
        let grant = match self.store.access_grant(&params.grant_id) {
            Ok(Some(g)) => g,
            Ok(None) => {
                return AgentResponse::err(
                    &request.id,
                    "NOT_FOUND",
                    format!("Grant {} not found", params.grant_id),
                );
            }
            Err(e) => {
                return AgentResponse::err(
                    &request.id,
                    "STORE_ERROR",
                    format!("Failed to query grant: {e}"),
                );
            }
        };

        let info = GrantInfo {
            grant_id: grant.id,
            issuer_id: grant.issuing_persona_id,
            capability: format!("{} capabilities", grant.capabilities.len()),
            status: grant.status.as_str().to_string(),
            expires_at: grant.expires_at,
        };

        AgentResponse::ok(&request.id, serde_json::to_value(info).unwrap())
    }

    fn handle_use_credential(&self, request: &AgentRequest) -> AgentResponse {
        let _params: UseCredentialParams = match serde_json::from_value(request.params.clone()) {
            Ok(p) => p,
            Err(e) => {
                return AgentResponse::err(
                    &request.id,
                    "INVALID_PARAMS",
                    format!("Invalid use_credential params: {e}"),
                );
            }
        };

        // TODO(+): check grant is active, not revoked, within scope,
        // then return credential metadata (handles actual delivery)
        AgentResponse::err(
            &request.id,
            "NOT_IMPLEMENTED",
            "Credential use via grants is not yet wired (see /)",
        )
    }
}

/// Process a single JSON line and return the response JSON line.
pub fn process_line(runtime: &AgentRuntime, line: &str) -> String {
    let request: AgentRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            let resp = AgentResponse::err("unknown", "PARSE_ERROR", format!("Invalid JSON: {e}"));
            return serde_json::to_string(&resp).unwrap();
        }
    };
    let response = runtime.handle(&request);
    serde_json::to_string(&response).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_runtime() -> AgentRuntime {
        let store = Rc::new(EventStore::open_in_memory().unwrap());
        AgentRuntime::new(
            AgentConfig {
                persona_id: "agent-test-001".into(),
                label: Some("Test Agent".into()),
            },
            store,
        )
    }

    #[test]
    fn whoami_returns_persona() {
        let rt = test_runtime();
        let line = r#"{"id":"1","method":"whoami","params":{}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["persona_id"], "agent-test-001");
        assert_eq!(result["label"], "Test Agent");
    }

    #[test]
    fn list_grants_returns_empty() {
        let rt = test_runtime();
        let line = r#"{"id":"2","method":"list_grants"}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert!(result.as_array().unwrap().is_empty());
    }

    #[test]
    fn unknown_method_returns_error() {
        let rt = test_runtime();
        let line = r#"{"id":"3","method":"fly_to_moon","params":{}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, "UNKNOWN_METHOD");
    }

    #[test]
    fn invalid_json_returns_parse_error() {
        let rt = test_runtime();
        let resp_json = process_line(&rt, "not json at all");
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "PARSE_ERROR");
    }

    #[test]
    fn request_grant_returns_pending() {
        let rt = test_runtime();
        let line = r#"{"id":"4","method":"request_grant","params":{"scope":"ReadCredential","reason":"test"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "PENDING_APPROVAL");
    }

    #[test]
    fn grant_status_not_found() {
        let rt = test_runtime();
        let line = r#"{"id":"5","method":"grant_status","params":{"grant_id":"nonexistent"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "NOT_FOUND");
    }

    #[test]
    fn use_credential_not_implemented() {
        let rt = test_runtime();
        let line = r#"{"id":"6","method":"use_credential","params":{"grant_id":"g1","credential_id":"c1"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "NOT_IMPLEMENTED");
    }

    #[test]
    fn request_grant_invalid_params() {
        let rt = test_runtime();
        // Missing required "scope" field
        let line = r#"{"id":"7","method":"request_grant","params":{"reason":"no scope"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "INVALID_PARAMS");
    }
}
