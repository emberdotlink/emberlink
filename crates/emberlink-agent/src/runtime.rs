//! Agent runtime — processes protocol commands against local state.

use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use core_state::EventStore;
use core_types::approval::{ApprovalRequest, RequestedScope};
use core_types::{AccessGrantStatus, PresentationAudienceKind};

use crate::protocol::{
    methods, AgentRequest, AgentResponse, GrantInfo, GrantStatusParams, RelayGrantStatusParams,
    RelayRequestGrantParams, RequestGrantParams, RequestGrantResponse, UseCredentialParams,
    WhoamiResponse,
};

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
            methods::RELAY_REQUEST_GRANT => self.handle_relay_request_grant(request),
            methods::RELAY_GRANT_STATUS => self.handle_relay_grant_status(request),
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

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let request_id = format!("req-{created_at}");

        let scope = RequestedScope {
            capability: params.scope.clone(),
            resource_id: params.resource_id.clone(),
            constraints: vec![],
        };

        let approval_req = ApprovalRequest::new(
            request_id.clone(),
            self.config.persona_id.clone(),
            self.config.label.clone(),
            scope,
            params.duration_secs,
            params.reason.clone(),
            created_at,
        );

        if let Err(e) = self.store.insert_approval_request(&approval_req) {
            return AgentResponse::err(
                &request.id,
                "STORE_ERROR",
                format!("Failed to queue approval request: {e}"),
            );
        }

        let resp = RequestGrantResponse {
            request_id,
            status: "pending".to_string(),
        };
        AgentResponse::ok(&request.id, serde_json::to_value(resp).unwrap())
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
                // Not a grant — check the approval queue for a pending request.
                return match self.store.get_approval_request(&params.grant_id) {
                    Ok(Some(row)) => {
                        let resp = RequestGrantResponse {
                            request_id: row.request_id,
                            status: row.status,
                        };
                        AgentResponse::ok(&request.id, serde_json::to_value(resp).unwrap())
                    }
                    Ok(None) => AgentResponse::err(
                        &request.id,
                        "NOT_FOUND",
                        format!("Grant or approval request {} not found", params.grant_id),
                    ),
                    Err(e) => AgentResponse::err(
                        &request.id,
                        "STORE_ERROR",
                        format!("Failed to query approval request: {e}"),
                    ),
                };
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
        let params: UseCredentialParams = match serde_json::from_value(request.params.clone()) {
            Ok(p) => p,
            Err(e) => {
                return AgentResponse::err(
                    &request.id,
                    "INVALID_PARAMS",
                    format!("Invalid use_credential params: {e}"),
                );
            }
        };

        // Step 1: Look up the grant and verify it exists and is active.
        let grant = match self.store.access_grant(&params.grant_id) {
            Ok(Some(g)) => g,
            Ok(None) => {
                let _ = self.store.log_credential_access(
                    &params.grant_id,
                    &self.config.persona_id,
                    &params.credential_id,
                    "denied:grant_not_found",
                );
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

        // Step 2: Verify the grant is active (not revoked, not expired).
        if grant.status != AccessGrantStatus::Active {
            let outcome = format!("denied:grant_{}", grant.status.as_str());
            let _ = self.store.log_credential_access(
                &params.grant_id,
                &self.config.persona_id,
                &params.credential_id,
                &outcome,
            );
            return AgentResponse::err(
                &request.id,
                "GRANT_INACTIVE",
                format!(
                    "Grant {} is {} and cannot be used",
                    params.grant_id,
                    grant.status.as_str()
                ),
            );
        }

        // Step 3: Fetch the credential deposit for this grant.
        let deposit = match self.store.fetch_credential_deposit(&params.grant_id) {
            Ok(Some(d)) => d,
            Ok(None) => {
                let _ = self.store.log_credential_access(
                    &params.grant_id,
                    &self.config.persona_id,
                    &params.credential_id,
                    "denied:no_deposit",
                );
                return AgentResponse::err(
                    &request.id,
                    "NO_CREDENTIAL",
                    "Credential not yet deposited — issuer must deposit first",
                );
            }
            Err(e) => {
                return AgentResponse::err(
                    &request.id,
                    "STORE_ERROR",
                    format!("Failed to fetch credential deposit: {e}"),
                );
            }
        };

        // Step 4: Log the successful access.
        let _ = self.store.log_credential_access(
            &params.grant_id,
            &self.config.persona_id,
            &deposit.credential_id,
            "granted",
        );

        // Step 5: Return the credential info to the caller.
        let result = serde_json::json!({
            "status": "ok",
            "credential": {
                "value": deposit.encrypted_blocks_json,
                "scope": deposit.credential_id,
                "grant_id": deposit.grant_id,
            }
        });
        AgentResponse::ok(&request.id, result)
    }

    fn handle_relay_request_grant(&self, request: &AgentRequest) -> AgentResponse {
        let params: RelayRequestGrantParams = match serde_json::from_value(request.params.clone())
        {
            Ok(p) => p,
            Err(e) => {
                return AgentResponse::err(
                    &request.id,
                    "INVALID_PARAMS",
                    format!("Invalid relay_request_grant params: {e}"),
                );
            }
        };

        match crate::relay::request_grant(
            &params.relay,
            &params.target,
            &self.config.persona_id,
            &params.scope,
            &params.justification,
        ) {
            Ok(request_id) => {
                let resp = serde_json::json!({
                    "request_id": request_id,
                    "status": "pending",
                });
                AgentResponse::ok(&request.id, resp)
            }
            Err(e) => AgentResponse::err(&request.id, "RELAY_ERROR", e),
        }
    }

    fn handle_relay_grant_status(&self, request: &AgentRequest) -> AgentResponse {
        let params: RelayGrantStatusParams = match serde_json::from_value(request.params.clone()) {
            Ok(p) => p,
            Err(e) => {
                return AgentResponse::err(
                    &request.id,
                    "INVALID_PARAMS",
                    format!("Invalid relay_grant_status params: {e}"),
                );
            }
        };

        match crate::relay::fetch_grant_requests(&params.relay, &params.target) {
            Ok(requests) => {
                let resp = serde_json::json!({ "requests": requests });
                AgentResponse::ok(&request.id, resp)
            }
            Err(e) => AgentResponse::err(&request.id, "RELAY_ERROR", e),
        }
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
    fn request_grant_creates_db_record() {
        let store = Rc::new(EventStore::open_in_memory().unwrap());
        let rt = AgentRuntime::new(
            AgentConfig {
                persona_id: "agent-test-001".into(),
                label: Some("Test Agent".into()),
            },
            Rc::clone(&store),
        );
        let line = r#"{"id":"4","method":"request_grant","params":{"scope":"ReadCredential","reason":"test"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        assert!(resp.error.is_none(), "expected success, got error: {:?}", resp.error);
        let result = resp.result.unwrap();
        assert_eq!(result["status"], "pending");
        let request_id = result["request_id"].as_str().unwrap().to_string();
        assert!(request_id.starts_with("req-"), "request_id should start with 'req-'");

        // Verify the record is in the DB.
        let row = store.get_approval_request(&request_id).unwrap().unwrap();
        assert_eq!(row.status, "pending");
        assert_eq!(row.requester_id, "agent-test-001");
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
    fn use_credential_grant_not_found() {
        let rt = test_runtime();
        let line = r#"{"id":"6","method":"use_credential","params":{"grant_id":"g-nonexistent","credential_id":"c1"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "NOT_FOUND");
    }

    #[test]
    fn use_credential_invalid_params_returns_error() {
        let rt = test_runtime();
        // Missing required credential_id field.
        let line = r#"{"id":"7","method":"use_credential","params":{"grant_id":"g1"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "INVALID_PARAMS");
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

    #[test]
    fn relay_request_grant_invalid_params() {
        let rt = test_runtime();
        // Missing required fields
        let line = r#"{"id":"8","method":"relay_request_grant","params":{"relay":"wss://x"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "INVALID_PARAMS");
    }

    #[test]
    fn relay_grant_status_invalid_params() {
        let rt = test_runtime();
        // Missing required fields
        let line = r#"{"id":"9","method":"relay_grant_status","params":{}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "INVALID_PARAMS");
    }

    #[test]
    fn relay_request_grant_bad_url() {
        let rt = test_runtime();
        // Valid params but unreachable URL — should return RELAY_ERROR
        let line = r#"{"id":"10","method":"relay_request_grant","params":{"relay":"wss://127.0.0.1:1","target":"alice","scope":"read","justification":"test"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "RELAY_ERROR");
    }

    #[test]
    fn relay_grant_status_bad_url() {
        let rt = test_runtime();
        let line = r#"{"id":"11","method":"relay_grant_status","params":{"relay":"wss://127.0.0.1:1","target":"alice"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "RELAY_ERROR");
    }
}
