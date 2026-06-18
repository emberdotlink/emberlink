//! Agent runtime — processes protocol commands against local state.

use std::cell::RefCell;
use std::rc::Rc;

use core_state::EventStore;

use crate::protocol::{
    AgentRequest, AgentResponse, GrantInfo, GrantStatusParams, RelayGrantStatusParams,
    RelayRequestGrantParams, RequestGrantParams, RequestGrantResponse, UseCredentialParams,
    WhoamiResponse, methods,
};

/// Extract the host (authority) component from a URL string.
///
/// Strips the scheme prefix (`https://`, `http://`, etc.) and discards
/// the path, query, and fragment, returning only `host[:port]`. Returns
/// `None` when the URL has no recognizable authority (e.g. bare paths,
/// empty strings). Used to populate the NOTIF-1 `target_host` banner
/// field from a caller-supplied `target_url`.
fn extract_host(url: &str) -> Option<String> {
    // Strip scheme — find "://" and take everything after it.
    let after_scheme = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };
    if after_scheme.is_empty() {
        return None;
    }
    // Authority ends at the first '/', '?', or '#'.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    if authority.is_empty() {
        None
    } else {
        Some(authority.to_owned())
    }
}

/// Errors returned by a [`DaemonClient`] when forwarding a request.
///
/// Kept small and structural so the runtime can surface a generic
/// `ACCESS_DENIED` or `DAEMON_UNAVAILABLE` without leaking daemon-internal
/// error text to the caller.
#[derive(Debug)]
pub enum DaemonClientError {
    /// Connection/I/O failure — daemon is unreachable.
    Unavailable,
    /// Daemon returned a protocol-level or server-side error.
    Daemon,
}

/// Abstraction over the agent runtime's link to the ember daemon's policy
/// engine. The real implementation uses a Unix socket
/// ([`crate::socket_transport::SocketTransport`]); tests substitute a mock.
///
/// The runtime holds this trait object behind a [`RefCell`] and borrows
/// mutably per call so the underlying transport can maintain its own
/// read/write state.
pub trait DaemonClient {
    /// Forward a `request_access` call to the daemon and return the raw
    /// result JSON (which contains `status`, optional `grant_id`,
    /// optional `approval_id`, etc.).
    ///
    /// Callers MUST route all agent-initiated credential requests through
    /// this method so the daemon's pre-evaluation rate limiter, standing
    /// grants, and policy engine all run. See TODO 69.1 / ADR 047.
    fn request_access(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError>;

    /// Forward a `list_grants` call to the daemon. The response is the
    /// raw JSON array the daemon returns; callers are expected to map it
    /// onto their own wire shape. Routing through here (rather than the
    /// agent's local `EventStore`) is mandatory so the daemon remains the
    /// single source of truth for active grants — see TODO 69I.1.
    fn list_grants(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError>;

    /// Forward a `grant_status` call to the daemon. The daemon's reply
    /// distinguishes between an issued grant (`kind: "grant"`) and a
    /// pending approval (`kind: "approval"`) so a single id can be polled
    /// through from `request_grant` to issuance. See TODO 69I.1.
    fn grant_status(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError>;

    /// Forward a `use_credential` call to the daemon. The daemon enforces
    /// the grant's rate limit, allowed-hours window, and persona-ownership
    /// check, and returns the credential value. Routing through here
    /// ensures these checks apply to all MCP-initiated reads — see
    /// TODO 69I.1.
    fn use_credential(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError>;
}

/// Configuration for the agent runtime.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// The persona ID this agent operates as.
    pub persona_id: String,
    /// Human-readable label for this agent.
    pub label: Option<String>,
}

/// The agent runtime dispatches protocol requests against the EventStore.
///
/// Agent-initiated credential requests are forwarded to the daemon via the
/// injected [`DaemonClient`] so policy evaluation, rate limiting, and
/// standing grants all apply. If no client is configured, those requests
/// fail closed with `DAEMON_UNAVAILABLE`.
pub struct AgentRuntime {
    config: AgentConfig,
    /// Retained for API compatibility and in case future handlers (e.g.
    /// local audit logging, relay cache) need it. All credential/grant
    /// paths now route through `daemon` — see TODO 69I.1. Kept private
    /// so we can decide later whether to remove it entirely.
    #[allow(dead_code)]
    store: Rc<EventStore>,
    daemon: Option<RefCell<Box<dyn DaemonClient>>>,
}

impl AgentRuntime {
    /// Build a runtime WITHOUT a daemon link. `request_grant` will fail
    /// closed in this configuration — callers that need to issue grant
    /// requests MUST use [`Self::with_daemon`].
    pub fn new(config: AgentConfig, store: Rc<EventStore>) -> Self {
        Self {
            config,
            store,
            daemon: None,
        }
    }

    /// Build a runtime that forwards `request_grant` to the daemon via
    /// the supplied [`DaemonClient`].
    pub fn with_daemon(
        config: AgentConfig,
        store: Rc<EventStore>,
        daemon: Box<dyn DaemonClient>,
    ) -> Self {
        Self {
            config,
            store,
            daemon: Some(RefCell::new(daemon)),
        }
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

    /// Handle `list_grants` by forwarding to the daemon so the agent's
    /// local `EventStore` can't drift from the daemon's SQLite state.
    ///
    /// Security properties (TODO 69I.1):
    /// - **Fail closed**: no daemon → `DAEMON_UNAVAILABLE`. We never fall
    ///   back to the local store — that's the bypass T1c6 closed for
    ///   `request_grant` and is extended here for the read path.
    /// - **Persona-scoped**: we forward our own `persona_id` as a filter
    ///   so an agent cannot enumerate other personas' grants.
    /// - **Error minimization**: daemon-side errors surface as generic
    ///   `ACCESS_DENIED` without echoing server text.
    fn handle_list_grants(&self, id: &str) -> AgentResponse {
        let daemon = match self.daemon.as_ref() {
            Some(d) => d,
            None => {
                tracing::warn!("list_grants rejected — no daemon link configured");
                return AgentResponse::err(
                    id,
                    "DAEMON_UNAVAILABLE",
                    "access denied: daemon unreachable",
                );
            }
        };

        let params = serde_json::json!({"persona_id": self.config.persona_id});
        let result = match daemon.borrow_mut().list_grants(&params) {
            Ok(v) => v,
            Err(DaemonClientError::Unavailable) => {
                return AgentResponse::err(
                    id,
                    "DAEMON_UNAVAILABLE",
                    "access denied: daemon unreachable",
                );
            }
            Err(DaemonClientError::Daemon) => {
                return AgentResponse::err(id, "ACCESS_DENIED", "access denied");
            }
        };

        let entries = result.as_array().cloned().unwrap_or_default();

        let infos: Vec<GrantInfo> = entries
            .into_iter()
            .map(|g| GrantInfo {
                grant_id: g
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                issuer_id: "daemon".to_string(),
                capability: g
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                status: g
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("active")
                    .to_string(),
                // Daemon emits `expires_at` as an rfc3339 string. The agent
                // protocol carries it as `Option<u64>` seconds-since-epoch,
                // so we parse-and-convert. A parse failure maps to `None`
                // rather than failing the whole response — status + scope
                // are still useful for the caller.
                expires_at: g
                    .get("expires_at")
                    .and_then(|v| v.as_str())
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.timestamp() as u64),
            })
            .collect();

        AgentResponse::ok(id, serde_json::to_value(infos).unwrap())
    }

    /// Handle an agent-initiated `request_grant` by forwarding to the
    /// daemon's `request_access` method so the policy engine and
    /// pre-evaluation rate limiter both run.
    ///
    /// Security properties (TODO 69.1 follow-up):
    /// - **Fail closed**: with no daemon client configured the call returns
    ///   `DAEMON_UNAVAILABLE`. There is no fallback path that would write
    ///   an approval request directly to the local store (that path was the
    ///   bypass this fix closes).
    /// - **No scope broadening**: all caller-supplied fields are forwarded
    ///   verbatim. The synthesized `action` string uses only the caller's
    ///   `resource_id` so it cannot widen the policy match.
    /// - **Error minimization**: daemon-side errors are coerced to generic
    ///   `ACCESS_DENIED` / `DAEMON_ERROR` without echoing raw server text
    ///   back to the calling agent.
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

        // Fail closed: if no daemon link is wired up, we cannot consult
        // the policy engine, so we MUST NOT grant or queue anything.
        let daemon = match self.daemon.as_ref() {
            Some(d) => d,
            None => {
                tracing::warn!(
                    "request_grant rejected — agent runtime has no daemon link; \
                     policy engine cannot be consulted"
                );
                return AgentResponse::err(
                    &request.id,
                    "DAEMON_UNAVAILABLE",
                    "access denied: policy engine unreachable",
                );
            }
        };

        // The daemon's `request_access` requires a credential_name. The
        // agent protocol carries this as `resource_id`. Without it we have
        // no way to name the credential in the policy, so fail closed
        // rather than synthesize an empty string the daemon will reject
        // and that could match an unintended rule.
        let credential_name = match params.resource_id.as_deref() {
            Some(s) if !s.is_empty() => s,
            _ => {
                return AgentResponse::err(
                    &request.id,
                    "INVALID_PARAMS",
                    "resource_id required to route request_grant through policy engine",
                );
            }
        };

        // Synthesized action mirrors the MCP transport's convention
        // (daemon_transport.rs::translate_request_grant). The caller
        // cannot override it — this prevents spoofing a weaker rule.
        let action = format!("credential.access.{credential_name}");

        let mut daemon_params = serde_json::json!({
            "persona_id": self.config.persona_id,
            "credential_name": credential_name,
            "scope": params.scope,
            "action": action,
            // NOTIF-1: agent-SDK path always identifies itself so the
            // notification banner can show the framework badge.
            "agent_framework": "emberlink-agent",
        });
        if let Some(ttl) = params.duration_secs {
            daemon_params["ttl_secs"] = serde_json::json!(ttl);
        }
        if let Some(ref tool) = params.tool_name {
            daemon_params["tool_name"] = serde_json::json!(tool);
        }
        if let Some(ref url) = params.target_url {
            daemon_params["target_url"] = serde_json::json!(url);
            // Derive target_host from the URL: strip scheme and take the
            // authority component (host[:port]). Mirrors the extract_host
            // logic used in the MCP path.
            if let Some(host) = extract_host(url) {
                daemon_params["target_host"] = serde_json::json!(host);
            }
        }

        let result = match daemon.borrow_mut().request_access(&daemon_params) {
            Ok(v) => v,
            Err(DaemonClientError::Unavailable) => {
                return AgentResponse::err(
                    &request.id,
                    "DAEMON_UNAVAILABLE",
                    "access denied: policy engine unreachable",
                );
            }
            Err(DaemonClientError::Daemon) => {
                return AgentResponse::err(&request.id, "ACCESS_DENIED", "access denied");
            }
        };

        // Map the daemon's `request_access` response shape onto the
        // agent protocol's `RequestGrantResponse { request_id, status }`.
        // A successful call returns one of:
        //   { status: "approved",  grant_id: "..."      }
        //   { status: "pending",   approval_id: "..."   }
        //   { status: "denied",    reason: "..."        }
        let status = result
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let request_id = result
            .get("grant_id")
            .or_else(|| result.get("approval_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let resp = RequestGrantResponse { request_id, status };
        AgentResponse::ok(&request.id, serde_json::to_value(resp).unwrap())
    }

    /// Handle `grant_status` by forwarding to the daemon's `grant_status`
    /// method. The daemon resolves the id against both grants and pending
    /// approvals so callers can poll a `request_grant` result through to
    /// issuance. See TODO 69I.1.
    ///
    /// Security properties mirror `handle_list_grants`: fail-closed on no
    /// daemon / unreachable daemon, daemon errors collapse to
    /// `ACCESS_DENIED` / `NOT_FOUND`. We pin the caller's `persona_id`
    /// so an id leak cannot be used to probe another persona's status.
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

        let daemon = match self.daemon.as_ref() {
            Some(d) => d,
            None => {
                tracing::warn!("grant_status rejected — no daemon link configured");
                return AgentResponse::err(
                    &request.id,
                    "DAEMON_UNAVAILABLE",
                    "access denied: daemon unreachable",
                );
            }
        };

        let daemon_params = serde_json::json!({
            "id": params.grant_id,
            "persona_id": self.config.persona_id,
        });

        let result = match daemon.borrow_mut().grant_status(&daemon_params) {
            Ok(v) => v,
            Err(DaemonClientError::Unavailable) => {
                return AgentResponse::err(
                    &request.id,
                    "DAEMON_UNAVAILABLE",
                    "access denied: daemon unreachable",
                );
            }
            Err(DaemonClientError::Daemon) => {
                // The daemon collapses several failures (not found, wrong
                // persona, store error) into a single error. We surface
                // them as NOT_FOUND — it's the historical shape of this
                // call and doesn't leak which of those it actually was.
                return AgentResponse::err(
                    &request.id,
                    "NOT_FOUND",
                    format!("Grant or approval request {} not found", params.grant_id),
                );
            }
        };

        // The daemon returns `{ kind: "grant"|"approval", ... }`. Map onto
        // the agent protocol's two historical shapes: a `GrantInfo` for a
        // live grant, a `RequestGrantResponse` for a pending approval.
        let kind = result.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if kind == "approval" {
            let request_id = result
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let status = result
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("pending")
                .to_string();
            let resp = RequestGrantResponse { request_id, status };
            return AgentResponse::ok(&request.id, serde_json::to_value(resp).unwrap());
        }

        // Treat anything else as a grant payload (the daemon's only other
        // response shape).
        let info = GrantInfo {
            grant_id: result
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            issuer_id: "daemon".to_string(),
            capability: result
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            status: result
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("active")
                .to_string(),
            expires_at: result
                .get("expires_at")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.timestamp() as u64),
        };

        AgentResponse::ok(&request.id, serde_json::to_value(info).unwrap())
    }

    /// Handle `use_credential` by forwarding to the daemon's
    /// `use_credential` method. The daemon enforces the grant's rate
    /// limit, allowed-hours window, and persona-ownership check, then
    /// returns the credential value from its vault. We pin the caller's
    /// `persona_id` so a leaked `grant_id` cannot be redeemed by a
    /// different agent. See TODO 69I.1.
    ///
    /// Fail-closed: no daemon link → `DAEMON_UNAVAILABLE`; daemon
    /// `Unavailable` → `DAEMON_UNAVAILABLE`; daemon `Daemon` error →
    /// `ACCESS_DENIED` (the daemon groups not-found / inactive / wrong
    /// persona / rate-limited under one error shape so we don't echo
    /// which specific failure it was).
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

        let daemon = match self.daemon.as_ref() {
            Some(d) => d,
            None => {
                tracing::warn!("use_credential rejected — no daemon link configured");
                return AgentResponse::err(
                    &request.id,
                    "DAEMON_UNAVAILABLE",
                    "access denied: daemon unreachable",
                );
            }
        };

        // Forward the caller's (grant_id, credential_id) along with our
        // `persona_id` so the daemon can both look up the grant and verify
        // it belongs to us. `credential_name` is forwarded as a fallback
        // for the classic daemon calling convention — the daemon picks
        // the grant_id branch when present.
        let daemon_params = serde_json::json!({
            "persona_id": self.config.persona_id,
            "grant_id": params.grant_id,
            "credential_name": params.credential_id,
        });

        let result = match daemon.borrow_mut().use_credential(&daemon_params) {
            Ok(v) => v,
            Err(DaemonClientError::Unavailable) => {
                return AgentResponse::err(
                    &request.id,
                    "DAEMON_UNAVAILABLE",
                    "access denied: daemon unreachable",
                );
            }
            Err(DaemonClientError::Daemon) => {
                return AgentResponse::err(&request.id, "ACCESS_DENIED", "access denied");
            }
        };

        // Translate the daemon's shape into the agent protocol's wire
        // format. Daemon: `{credential: "<text>", grant_id, credential_name, scope}`.
        // Agent: `{status: "ok", credential: {value, scope, grant_id}}`.
        let value = result
            .get("credential")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let grant_id = result
            .get("grant_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&params.grant_id)
            .to_string();
        let scope = result
            .get("scope")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                result
                    .get("credential_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| params.credential_id.clone());

        let response = serde_json::json!({
            "status": "ok",
            "credential": {
                "value": value,
                "scope": scope,
                "grant_id": grant_id,
            }
        });
        AgentResponse::ok(&request.id, response)
    }

    fn handle_relay_request_grant(&self, request: &AgentRequest) -> AgentResponse {
        let params: RelayRequestGrantParams = match serde_json::from_value(request.params.clone()) {
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
    fn list_grants_fails_closed_without_daemon() {
        // Post-TODO-69I.1 behavior: `list_grants` routes through the
        // daemon. Without a daemon link it MUST fail closed — the agent
        // used to answer from its disjoint local EventStore, which was
        // the split-brain bug that motivated this change.
        let rt = test_runtime();
        let line = r#"{"id":"2","method":"list_grants"}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        assert!(resp.result.is_none(), "must not succeed without a daemon");
        let err = resp.error.unwrap();
        assert_eq!(err.code, "DAEMON_UNAVAILABLE");
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

    // ---------------------------------------------------------------------
    // request_grant policy-engine routing (TODO 69.1 follow-up)
    //
    // Prior to this fix, `handle_request_grant` wrote an approval request
    // straight into the local EventStore without consulting the daemon's
    // policy engine, standing grants, or rate limiter. These tests lock
    // in the new behavior: the call is forwarded to the daemon, and if
    // no daemon is configured the call fails closed.
    // ---------------------------------------------------------------------

    /// A recorded call against the mock — which method, what params.
    #[derive(Clone, Debug)]
    struct CapturedCall {
        method: &'static str,
        params: serde_json::Value,
    }

    /// Programmable mock daemon used by the runtime tests. Every trait
    /// method looks up a pre-set response; if none is set for that
    /// method, the mock returns `Unavailable` so tests can assert
    /// fail-closed behavior on a dropped socket. All calls are recorded
    /// into `captured` so tests can assert forwarded params.
    struct MockDaemon {
        captured: std::rc::Rc<std::cell::RefCell<Vec<CapturedCall>>>,
        request_access_response: Option<serde_json::Value>,
        list_grants_response: Option<serde_json::Value>,
        grant_status_response: Option<serde_json::Value>,
        use_credential_response: Option<serde_json::Value>,
        /// If set, the given method will return `Err(Daemon)` instead of
        /// `Ok(...)`. Used to exercise the daemon-error mapping path.
        error_on: Option<&'static str>,
    }

    impl MockDaemon {
        fn new() -> Self {
            Self {
                captured: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
                request_access_response: None,
                list_grants_response: None,
                grant_status_response: None,
                use_credential_response: None,
                error_on: None,
            }
        }

        fn captured(&self) -> std::rc::Rc<std::cell::RefCell<Vec<CapturedCall>>> {
            std::rc::Rc::clone(&self.captured)
        }
    }

    fn respond_or_default(
        method: &'static str,
        response: &Option<serde_json::Value>,
        error_on: &Option<&'static str>,
    ) -> Result<serde_json::Value, DaemonClientError> {
        if error_on.as_deref() == Some(method) {
            return Err(DaemonClientError::Daemon);
        }
        match response {
            Some(v) => Ok(v.clone()),
            None => Err(DaemonClientError::Unavailable),
        }
    }

    impl DaemonClient for MockDaemon {
        fn request_access(
            &mut self,
            params: &serde_json::Value,
        ) -> Result<serde_json::Value, DaemonClientError> {
            self.captured.borrow_mut().push(CapturedCall {
                method: "request_access",
                params: params.clone(),
            });
            respond_or_default(
                "request_access",
                &self.request_access_response,
                &self.error_on,
            )
        }

        fn list_grants(
            &mut self,
            params: &serde_json::Value,
        ) -> Result<serde_json::Value, DaemonClientError> {
            self.captured.borrow_mut().push(CapturedCall {
                method: "list_grants",
                params: params.clone(),
            });
            respond_or_default("list_grants", &self.list_grants_response, &self.error_on)
        }

        fn grant_status(
            &mut self,
            params: &serde_json::Value,
        ) -> Result<serde_json::Value, DaemonClientError> {
            self.captured.borrow_mut().push(CapturedCall {
                method: "grant_status",
                params: params.clone(),
            });
            respond_or_default("grant_status", &self.grant_status_response, &self.error_on)
        }

        fn use_credential(
            &mut self,
            params: &serde_json::Value,
        ) -> Result<serde_json::Value, DaemonClientError> {
            self.captured.borrow_mut().push(CapturedCall {
                method: "use_credential",
                params: params.clone(),
            });
            respond_or_default(
                "use_credential",
                &self.use_credential_response,
                &self.error_on,
            )
        }
    }

    /// Kept for the legacy `request_access`-only tests that existed prior
    /// to TODO 69I.1. Creates a fresh [`MockDaemon`] with just the
    /// `request_access` branch primed.
    fn mock_daemon_with_response(
        captured: &std::rc::Rc<std::cell::RefCell<Vec<CapturedCall>>>,
        response: serde_json::Value,
    ) -> Box<dyn DaemonClient> {
        Box::new(MockDaemon {
            captured: std::rc::Rc::clone(captured),
            request_access_response: Some(response),
            list_grants_response: None,
            grant_status_response: None,
            use_credential_response: None,
            error_on: None,
        })
    }

    fn captured_cell() -> std::rc::Rc<std::cell::RefCell<Vec<CapturedCall>>> {
        std::rc::Rc::new(std::cell::RefCell::new(Vec::new()))
    }

    fn first_request_access_call(
        captured: &std::rc::Rc<std::cell::RefCell<Vec<CapturedCall>>>,
    ) -> Option<serde_json::Value> {
        captured
            .borrow()
            .iter()
            .find(|c| c.method == "request_access")
            .map(|c| c.params.clone())
    }

    #[test]
    fn request_grant_forwards_to_daemon_with_synthesized_action() {
        let store = Rc::new(EventStore::open_in_memory().unwrap());
        let captured = captured_cell();
        let daemon = mock_daemon_with_response(
            &captured,
            serde_json::json!({
                "status": "approved",
                "grant_id": "g-xyz",
                "decision": "auto_approve",
                "risk": "low",
            }),
        );
        let rt = AgentRuntime::with_daemon(
            AgentConfig {
                persona_id: "agent-test-001".into(),
                label: Some("Test Agent".into()),
            },
            Rc::clone(&store),
            daemon,
        );
        let line = r#"{"id":"4","method":"request_grant","params":{"scope":"repo:read","resource_id":"github-token","duration_secs":3600,"reason":"test"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        assert!(
            resp.error.is_none(),
            "expected success, got: {:?}",
            resp.error
        );

        let sent = first_request_access_call(&captured).expect("daemon was not called");
        assert_eq!(sent["persona_id"], "agent-test-001");
        assert_eq!(sent["credential_name"], "github-token");
        assert_eq!(sent["scope"], "repo:read");
        // Synthesized action — prevents rule-name spoofing.
        assert_eq!(sent["action"], "credential.access.github-token");
        assert_eq!(sent["ttl_secs"], 3600);

        // And the approved grant_id is surfaced to the agent caller.
        let result = resp.result.unwrap();
        assert_eq!(result["status"], "approved");
        assert_eq!(result["request_id"], "g-xyz");

        // Critical: no local approval_request was inserted behind the
        // daemon's back (that was the bypass).
        assert!(store.get_approval_request("g-xyz").unwrap().is_none());
    }

    #[test]
    fn request_grant_maps_pending_to_approval_id() {
        let captured = captured_cell();
        let daemon = mock_daemon_with_response(
            &captured,
            serde_json::json!({
                "status": "pending",
                "approval_id": "appr-42",
                "decision": "require_approval",
                "risk": "medium",
            }),
        );
        let rt = AgentRuntime::with_daemon(
            AgentConfig {
                persona_id: "agent-test-001".into(),
                label: None,
            },
            Rc::new(EventStore::open_in_memory().unwrap()),
            daemon,
        );
        let line =
            r#"{"id":"5","method":"request_grant","params":{"scope":"s","resource_id":"c"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["status"], "pending");
        assert_eq!(result["request_id"], "appr-42");
    }

    #[test]
    fn request_grant_fails_closed_without_daemon() {
        // No daemon configured → the call MUST NOT succeed and MUST NOT
        // write anything to the local store. This is the bypass closure.
        let store = Rc::new(EventStore::open_in_memory().unwrap());
        let rt = AgentRuntime::new(
            AgentConfig {
                persona_id: "agent-test-001".into(),
                label: None,
            },
            Rc::clone(&store),
        );
        let line =
            r#"{"id":"6","method":"request_grant","params":{"scope":"s","resource_id":"c"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        assert!(resp.result.is_none(), "must not succeed without a daemon");
        let err = resp.error.unwrap();
        assert_eq!(err.code, "DAEMON_UNAVAILABLE");

        // No leftover approval row.
        assert!(store.list_pending_approvals().unwrap().is_empty());
    }

    #[test]
    fn request_grant_fails_closed_when_daemon_unreachable() {
        // MockDaemon with no response set returns
        // `DaemonClientError::Unavailable` — simulating a dropped socket.
        let captured = captured_cell();
        let daemon = Box::new(MockDaemon {
            captured: std::rc::Rc::clone(&captured),
            request_access_response: None,
            list_grants_response: None,
            grant_status_response: None,
            use_credential_response: None,
            error_on: None,
        });
        let store = Rc::new(EventStore::open_in_memory().unwrap());
        let rt = AgentRuntime::with_daemon(
            AgentConfig {
                persona_id: "agent-test-001".into(),
                label: None,
            },
            Rc::clone(&store),
            daemon,
        );
        let line =
            r#"{"id":"7","method":"request_grant","params":{"scope":"s","resource_id":"c"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "DAEMON_UNAVAILABLE");
        assert!(store.list_pending_approvals().unwrap().is_empty());
    }

    #[test]
    fn request_grant_requires_resource_id() {
        // Without a resource_id there is no credential name to pin the
        // policy rule to, so we fail closed (INVALID_PARAMS) rather than
        // synthesize an empty-string action that might match an
        // unintended wildcard rule.
        let captured = captured_cell();
        let daemon = mock_daemon_with_response(
            &captured,
            serde_json::json!({"status": "approved", "grant_id": "g-1"}),
        );
        let store = Rc::new(EventStore::open_in_memory().unwrap());
        let rt = AgentRuntime::with_daemon(
            AgentConfig {
                persona_id: "agent-test-001".into(),
                label: None,
            },
            Rc::clone(&store),
            daemon,
        );
        let line = r#"{"id":"8","method":"request_grant","params":{"scope":"s"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "INVALID_PARAMS");

        // Daemon must NOT have been called — the pre-flight INVALID_PARAMS
        // check happens before we consult the daemon.
        assert!(captured.borrow().is_empty());
    }

    #[test]
    fn grant_status_fails_closed_without_daemon() {
        // Mirrors `list_grants_fails_closed_without_daemon` — the daemon
        // is the only authority on grant state post-TODO-69I.1.
        let rt = test_runtime();
        let line = r#"{"id":"5","method":"grant_status","params":{"grant_id":"nonexistent"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "DAEMON_UNAVAILABLE");
    }

    #[test]
    fn use_credential_fails_closed_without_daemon() {
        // Without a daemon, `use_credential` MUST NOT read from the local
        // EventStore (the pre-fix behavior). Fail closed instead.
        let rt = test_runtime();
        let line = r#"{"id":"6","method":"use_credential","params":{"grant_id":"g-nonexistent","credential_id":"c1"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "DAEMON_UNAVAILABLE");
    }

    #[test]
    fn use_credential_invalid_params_returns_error() {
        let rt = test_runtime();
        // Missing required credential_id field — this is a pre-flight
        // check that runs before we consult the daemon, so it fires even
        // without a daemon link configured.
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

    // --- NOTIF-1: agent-SDK seeding of approval banner fields ---

    /// Verify that every `request_grant` forwarded to the daemon carries
    /// `agent_framework = "emberlink-agent"`. This is the minimum required
    /// by NOTIF-1 so the notification banner can show which SDK originated
    /// the request. Also verifies `tool_name` and `target_host`/`target_url`
    /// are forwarded when supplied by the caller.
    #[test]
    fn agent_approval_request_populates_framework_field() {
        let captured = captured_cell();
        let daemon = mock_daemon_with_response(
            &captured,
            serde_json::json!({
                "status": "pending",
                "approval_id": "appr-notif1",
            }),
        );
        let rt = AgentRuntime::with_daemon(
            AgentConfig {
                persona_id: "agent-notif-001".into(),
                label: None,
            },
            Rc::new(EventStore::open_in_memory().unwrap()),
            daemon,
        );

        // Include optional NOTIF-1 fields alongside the required ones.
        let line = r#"{
            "id": "n1",
            "method": "request_grant",
            "params": {
                "scope": "repo:read",
                "resource_id": "github-token",
                "tool_name": "fetch_pr_comments",
                "target_url": "https://api.github.com/repos/foo/bar/pulls/1"
            }
        }"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        assert!(
            resp.error.is_none(),
            "expected success, got: {:?}",
            resp.error
        );

        let sent = first_request_access_call(&captured).expect("daemon must be called");

        // The primary NOTIF-1 assertion: agent_framework must be populated.
        assert!(
            sent["agent_framework"].as_str().is_some(),
            "agent_framework must be set; got: {:?}",
            sent["agent_framework"]
        );
        assert_eq!(sent["agent_framework"], "emberlink-agent");

        // Optional fields forwarded when supplied.
        assert_eq!(sent["tool_name"], "fetch_pr_comments");
        assert_eq!(
            sent["target_url"],
            "https://api.github.com/repos/foo/bar/pulls/1"
        );
        // target_host derived from target_url.
        assert_eq!(sent["target_host"], "api.github.com");
    }

    #[test]
    fn extract_host_strips_scheme_and_path() {
        assert_eq!(
            extract_host("https://api.github.com/repos/x/y"),
            Some("api.github.com".to_string())
        );
        assert_eq!(
            extract_host("http://example.com:8080/path?q=1"),
            Some("example.com:8080".to_string())
        );
        assert_eq!(
            extract_host("https://example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host("example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(extract_host(""), None);
        assert_eq!(extract_host("https://"), None);
    }

    #[test]
    fn agent_approval_request_framework_set_without_optional_fields() {
        // agent_framework must be present even when tool_name / target_url
        // are absent — it is unconditionally seeded by the runtime.
        let captured = captured_cell();
        let daemon = mock_daemon_with_response(
            &captured,
            serde_json::json!({"status": "pending", "approval_id": "appr-min"}),
        );
        let rt = AgentRuntime::with_daemon(
            AgentConfig {
                persona_id: "agent-notif-002".into(),
                label: None,
            },
            Rc::new(EventStore::open_in_memory().unwrap()),
            daemon,
        );
        let line =
            r#"{"id":"n2","method":"request_grant","params":{"scope":"s","resource_id":"c"}}"#;
        let resp_json = process_line(&rt, line);
        let resp: AgentResponse = serde_json::from_str(&resp_json).unwrap();
        assert!(resp.error.is_none());

        let sent = first_request_access_call(&captured).expect("daemon must be called");
        assert_eq!(sent["agent_framework"], "emberlink-agent");
        // tool_name and target_url absent → not forwarded.
        assert!(sent["tool_name"].is_null());
        assert!(sent["target_url"].is_null());
        assert!(sent["target_host"].is_null());
    }

    // ---------------------------------------------------------------------
    // MCP daemon-routing (TODO 69I.1)
    //
    // Pre-fix, `list_grants` / `grant_status` / `use_credential` all
    // answered from the agent's local EventStore — split-brained from the
    // daemon's SQLite store. These tests lock in the new behavior: all
    // three route through the daemon client, and all three fail closed
    // when the daemon link is missing or unreachable.
    // ---------------------------------------------------------------------

    fn runtime_with_mock(mock: MockDaemon) -> AgentRuntime {
        let store = Rc::new(EventStore::open_in_memory().unwrap());
        AgentRuntime::with_daemon(
            AgentConfig {
                persona_id: "agent-test-001".into(),
                label: None,
            },
            store,
            Box::new(mock),
        )
    }

    #[test]
    fn list_grants_forwards_persona_filter_and_maps_response() {
        let mut mock = MockDaemon::new();
        mock.list_grants_response = Some(serde_json::json!([
            {
                "id": "grant-aaa",
                "persona_id": "agent-test-001",
                "credential_name": "github-token",
                "scope": "repo:read",
                "expires_at": "2026-12-31T00:00:00Z",
                "status": "active"
            },
            {
                "id": "grant-bbb",
                "persona_id": "agent-test-001",
                "credential_name": "slack-token",
                "scope": "chat:read",
                "expires_at": null,
                "status": "active"
            }
        ]));
        let captured = mock.captured();
        let rt = runtime_with_mock(mock);
        let line = r#"{"id":"1","method":"list_grants","params":{}}"#;
        let resp: AgentResponse = serde_json::from_str(&process_line(&rt, line)).unwrap();
        assert!(
            resp.error.is_none(),
            "expected success, got {:?}",
            resp.error
        );
        let arr = resp.result.unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["grant_id"], "grant-aaa");
        assert_eq!(arr[0]["capability"], "repo:read");
        assert_eq!(arr[0]["status"], "active");
        assert!(arr[0]["expires_at"].is_u64());
        assert_eq!(arr[1]["grant_id"], "grant-bbb");
        // Daemon was called with persona_id filter — prevents an agent
        // from enumerating another persona's grants.
        let call = captured.borrow();
        let call = call.iter().find(|c| c.method == "list_grants").unwrap();
        assert_eq!(call.params["persona_id"], "agent-test-001");
    }

    #[test]
    fn list_grants_fails_closed_when_daemon_unreachable() {
        // No list_grants_response set → MockDaemon returns Unavailable.
        let mock = MockDaemon::new();
        let rt = runtime_with_mock(mock);
        let line = r#"{"id":"1","method":"list_grants"}"#;
        let resp: AgentResponse = serde_json::from_str(&process_line(&rt, line)).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "DAEMON_UNAVAILABLE");
    }

    #[test]
    fn list_grants_daemon_error_becomes_access_denied() {
        let mut mock = MockDaemon::new();
        mock.list_grants_response = Some(serde_json::json!([]));
        mock.error_on = Some("list_grants");
        let rt = runtime_with_mock(mock);
        let line = r#"{"id":"1","method":"list_grants"}"#;
        let resp: AgentResponse = serde_json::from_str(&process_line(&rt, line)).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "ACCESS_DENIED");
    }

    #[test]
    fn grant_status_routes_approval_kind_to_request_response() {
        // When the daemon reports the id refers to a pending approval,
        // the runtime surfaces a RequestGrantResponse shape so the MCP
        // client can continue polling.
        let mut mock = MockDaemon::new();
        mock.grant_status_response = Some(serde_json::json!({
            "kind": "approval",
            "id": "approval-42",
            "persona_id": "agent-test-001",
            "credential_name": "github-token",
            "scope": "repo:read",
            "status": "pending",
            "action": "credential.access.github-token",
            "risk_level": "medium"
        }));
        let captured = mock.captured();
        let rt = runtime_with_mock(mock);
        let line = r#"{"id":"1","method":"grant_status","params":{"grant_id":"approval-42"}}"#;
        let resp: AgentResponse = serde_json::from_str(&process_line(&rt, line)).unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["request_id"], "approval-42");
        assert_eq!(result["status"], "pending");

        // Persona pinned on the way out so a leaked id can't probe
        // another persona's approval state.
        let call = captured.borrow();
        let call = call.iter().find(|c| c.method == "grant_status").unwrap();
        assert_eq!(call.params["id"], "approval-42");
        assert_eq!(call.params["persona_id"], "agent-test-001");
    }

    #[test]
    fn grant_status_routes_grant_kind_to_grant_info() {
        let mut mock = MockDaemon::new();
        mock.grant_status_response = Some(serde_json::json!({
            "kind": "grant",
            "id": "grant-xyz",
            "persona_id": "agent-test-001",
            "credential_name": "github-token",
            "scope": "repo:write",
            "status": "active",
            "expires_at": "2026-12-31T00:00:00Z"
        }));
        let rt = runtime_with_mock(mock);
        let line = r#"{"id":"1","method":"grant_status","params":{"grant_id":"grant-xyz"}}"#;
        let resp: AgentResponse = serde_json::from_str(&process_line(&rt, line)).unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["grant_id"], "grant-xyz");
        assert_eq!(result["capability"], "repo:write");
        assert_eq!(result["status"], "active");
        assert!(result["expires_at"].is_u64());
    }

    #[test]
    fn grant_status_daemon_error_becomes_not_found() {
        // The daemon's `grant_status` collapses not-found, wrong-persona,
        // and store errors into a single `Daemon` error for the agent's
        // trait boundary. The runtime surfaces this as NOT_FOUND — the
        // historical shape — without leaking which underlying case fired.
        let mut mock = MockDaemon::new();
        mock.grant_status_response = Some(serde_json::json!({}));
        mock.error_on = Some("grant_status");
        let rt = runtime_with_mock(mock);
        let line = r#"{"id":"1","method":"grant_status","params":{"grant_id":"gone"}}"#;
        let resp: AgentResponse = serde_json::from_str(&process_line(&rt, line)).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "NOT_FOUND");
    }

    #[test]
    fn use_credential_forwards_persona_and_returns_value() {
        let mut mock = MockDaemon::new();
        mock.use_credential_response = Some(serde_json::json!({
            "credential": "ghp_realsecretvalue",
            "grant_id": "grant-xyz",
            "credential_name": "github-token",
            "scope": "repo:read"
        }));
        let captured = mock.captured();
        let rt = runtime_with_mock(mock);
        let line = r#"{"id":"1","method":"use_credential","params":{"grant_id":"grant-xyz","credential_id":"github-token"}}"#;
        let resp: AgentResponse = serde_json::from_str(&process_line(&rt, line)).unwrap();
        assert!(
            resp.error.is_none(),
            "expected success, got {:?}",
            resp.error
        );
        let result = resp.result.unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["credential"]["value"], "ghp_realsecretvalue");
        assert_eq!(result["credential"]["grant_id"], "grant-xyz");
        assert_eq!(result["credential"]["scope"], "repo:read");

        let call = captured.borrow();
        let call = call.iter().find(|c| c.method == "use_credential").unwrap();
        assert_eq!(call.params["persona_id"], "agent-test-001");
        assert_eq!(call.params["grant_id"], "grant-xyz");
        assert_eq!(call.params["credential_name"], "github-token");
    }

    #[test]
    fn use_credential_daemon_error_becomes_access_denied() {
        let mut mock = MockDaemon::new();
        mock.use_credential_response = Some(serde_json::json!({}));
        mock.error_on = Some("use_credential");
        let rt = runtime_with_mock(mock);
        let line =
            r#"{"id":"1","method":"use_credential","params":{"grant_id":"g","credential_id":"c"}}"#;
        let resp: AgentResponse = serde_json::from_str(&process_line(&rt, line)).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "ACCESS_DENIED");
    }

    #[test]
    fn use_credential_fails_closed_when_daemon_unreachable() {
        let mock = MockDaemon::new();
        let rt = runtime_with_mock(mock);
        let line =
            r#"{"id":"1","method":"use_credential","params":{"grant_id":"g","credential_id":"c"}}"#;
        let resp: AgentResponse = serde_json::from_str(&process_line(&rt, line)).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, "DAEMON_UNAVAILABLE");
    }

    #[test]
    fn full_loop_request_grant_approve_status_use_end_to_end() {
        // The canonical MCP demo loop (see TODO §P69I repro steps):
        //
        //   1. request_grant → pending, request_id = approval-XXX
        //   2. human approves — daemon issues grant-YYY
        //   3. grant_status(approval-XXX) → approval row still traceable
        //      OR grant_status(grant-YYY) → live grant
        //   4. use_credential(grant-YYY, credential_id) → real credential
        //
        // We simulate the daemon's side with a MockDaemon whose canned
        // responses cover each step. The assertions prove the agent
        // runtime actually reaches across to the daemon for every step —
        // no step silently falls back to the local store.
        let store = Rc::new(EventStore::open_in_memory().unwrap());
        let mut mock = MockDaemon::new();
        mock.request_access_response = Some(serde_json::json!({
            "status": "pending",
            "approval_id": "approval-XXX",
            "decision": "require_approval",
            "risk": "medium"
        }));
        mock.grant_status_response = Some(serde_json::json!({
            "kind": "grant",
            "id": "grant-YYY",
            "persona_id": "agent-test-001",
            "credential_name": "github-token",
            "scope": "repo:read",
            "status": "active",
            "expires_at": "2026-12-31T00:00:00Z"
        }));
        mock.use_credential_response = Some(serde_json::json!({
            "credential": "ghp_realsecret",
            "grant_id": "grant-YYY",
            "credential_name": "github-token",
            "scope": "repo:read"
        }));
        let captured = mock.captured();
        let rt = AgentRuntime::with_daemon(
            AgentConfig {
                persona_id: "agent-test-001".into(),
                label: None,
            },
            Rc::clone(&store),
            Box::new(mock),
        );

        // Step 1: request_grant → returns approval id, pending.
        let r1: AgentResponse = serde_json::from_str(&process_line(
            &rt,
            r#"{"id":"1","method":"request_grant","params":{"scope":"repo:read","resource_id":"github-token","duration_secs":3600}}"#,
        ))
        .unwrap();
        assert!(r1.error.is_none(), "step 1 failed: {:?}", r1.error);
        let r1 = r1.result.unwrap();
        assert_eq!(r1["status"], "pending");
        assert_eq!(r1["request_id"], "approval-XXX");

        // Step 2 happens externally (human approves in the daemon). We
        // model it by the mock returning a `grant` payload for the
        // subsequent `grant_status` call.

        // Step 3: grant_status(grant-YYY) → live grant.
        let r3: AgentResponse = serde_json::from_str(&process_line(
            &rt,
            r#"{"id":"3","method":"grant_status","params":{"grant_id":"grant-YYY"}}"#,
        ))
        .unwrap();
        assert!(r3.error.is_none(), "step 3 failed: {:?}", r3.error);
        let r3 = r3.result.unwrap();
        assert_eq!(r3["grant_id"], "grant-YYY");
        assert_eq!(r3["status"], "active");
        assert_eq!(r3["capability"], "repo:read");

        // Step 4: use_credential(grant-YYY, github-token) → real value.
        let r4: AgentResponse = serde_json::from_str(&process_line(
            &rt,
            r#"{"id":"4","method":"use_credential","params":{"grant_id":"grant-YYY","credential_id":"github-token"}}"#,
        ))
        .unwrap();
        assert!(r4.error.is_none(), "step 4 failed: {:?}", r4.error);
        let r4 = r4.result.unwrap();
        assert_eq!(r4["status"], "ok");
        assert_eq!(r4["credential"]["value"], "ghp_realsecret");
        assert_eq!(r4["credential"]["grant_id"], "grant-YYY");

        // Every step hit the daemon — none fell back to the local store.
        let calls = captured.borrow();
        let methods: Vec<&str> = calls.iter().map(|c| c.method).collect();
        assert!(
            methods.contains(&"request_access"),
            "step 1 should call request_access"
        );
        assert!(
            methods.contains(&"grant_status"),
            "step 3 should call grant_status"
        );
        assert!(
            methods.contains(&"use_credential"),
            "step 4 should call use_credential"
        );

        // Nothing was written to the agent's local store on the
        // side-channel that this fix closes.
        assert!(store.list_pending_approvals().unwrap().is_empty());
    }
}
