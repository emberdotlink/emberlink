//! MCP (Model Context Protocol) server for Emberlink agent authorization.
//!
//! Wraps the agent protocol as an MCP server using JSON-RPC 2.0 over stdio.
//! Each tool maps 1:1 to an AgentRuntime method.

pub mod daemon_transport;

use std::path::PathBuf;

use daemon_transport::{DaemonTransport, DaemonTransportError};
use emberlink_agent::protocol::methods::{
    GRANT_STATUS, LIST_GRANTS, REQUEST_GRANT, USE_CREDENTIAL, WHOAMI,
};
use emberlink_agent::protocol::AgentRequest;
use emberlink_agent::runtime::AgentRuntime;
use serde::{Deserialize, Serialize};

// --- JSON-RPC 2.0 types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// --- MCP tool definitions ---

fn tool_definitions() -> serde_json::Value {
    serde_json::json!([
        {
            "name": "whoami",
            "description": "Get agent identity",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "list_grants",
            "description": "List active grants for this agent",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "request_grant",
            "description": "Request a new grant with scope and duration. Subject to the daemon's policy engine and pre-evaluation rate limit — the request may be auto-approved, queued for human approval, or denied.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "scope": { "type": "string" },
                    "resource_id": { "type": "string" },
                    "duration_secs": { "type": "integer" },
                    "reason": { "type": "string" }
                },
                "required": ["scope", "resource_id", "duration_secs"]
            }
        },
        {
            "name": "grant_status",
            "description": "Check status of a grant",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "grant_id": { "type": "string" }
                },
                "required": ["grant_id"]
            }
        },
        {
            "name": "use_credential",
            "description": "Use a credential via an active grant",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "grant_id": { "type": "string" },
                    "credential_id": { "type": "string" }
                },
                "required": ["grant_id", "credential_id"]
            }
        },
        {
            "name": "list_receipts",
            "description": "List Grant Receipts — signed artifacts emitted when a grant reaches terminal state. Optionally filter by persona.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "persona_id": { "type": "string" }
                }
            }
        },
        {
            "name": "get_receipt",
            "description": "Fetch a single Grant Receipt by id. Returns the signed JSON body including Evidence (Ed25519 signature + signer pubkey).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": { "type": "string" }
                },
                "required": ["id"]
            }
        }
    ])
}

// --- MCP server ---

/// MCP server wrapping an AgentRuntime.
///
/// Optionally holds a [`DaemonTransport`] for read-only observability
/// tools (`list_receipts`, `get_receipt`) that bypass the agent runtime
/// and route directly through the daemon socket. The runtime is still
/// used for credential-touching tools.
pub struct McpServer {
    runtime: AgentRuntime,
    daemon_transport: Option<DaemonTransport>,
}

impl McpServer {
    pub fn new(runtime: AgentRuntime) -> Self {
        Self { runtime, daemon_transport: None }
    }

    /// Build a server with daemon-transport observability tools wired.
    /// `list_receipts` and `get_receipt` call through the transport.
    pub fn with_daemon_socket(runtime: AgentRuntime, socket: PathBuf) -> Self {
        Self {
            runtime,
            daemon_transport: Some(DaemonTransport::new(socket)),
        }
    }

    /// Handle a single JSON-RPC request and return a JSON-RPC response.
    pub fn handle_request(&self, req: &JsonRpcRequest) -> Option<JsonRpcResponse> {
        match req.method.as_str() {
            "initialize" => Some(self.handle_initialize(req)),
            "notifications/initialized" => None, // notification, no response
            "tools/list" => Some(self.handle_tools_list(req)),
            "tools/call" => Some(self.handle_tools_call(req)),
            _ => Some(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id.clone(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("method not found: {}", req.method),
                    data: None,
                }),
            }),
        }
    }

    /// Process a JSON line and return an optional JSON response line.
    pub fn process_line(&self, line: &str) -> Option<String> {
        let req: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                let resp = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: None,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("parse error: {e}"),
                        data: None,
                    }),
                };
                return Some(serde_json::to_string(&resp).unwrap_or_default());
            }
        };

        self.handle_request(&req)
            .map(|resp| serde_json::to_string(&resp).unwrap_or_default())
    }

    fn handle_initialize(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: req.id.clone(),
            result: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "emberlink-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            error: None,
        }
    }

    fn handle_tools_list(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: req.id.clone(),
            result: Some(serde_json::json!({
                "tools": tool_definitions()
            })),
            error: None,
        }
    }

    /// Route an observability tool (`list_receipts` / `get_receipt`)
    /// through the daemon transport. Fails closed with a descriptive
    /// error when no transport is configured.
    fn handle_receipt_tool(
        &self,
        req: &JsonRpcRequest,
        tool_name: &str,
        arguments: &serde_json::Value,
    ) -> JsonRpcResponse {
        let transport = match self.daemon_transport.as_ref() {
            Some(t) => t,
            None => {
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id.clone(),
                    result: Some(serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": "daemon unreachable — receipts tools require --daemon-socket"
                        }],
                        "isError": true
                    })),
                    error: None,
                };
            }
        };

        match transport.call_tool(tool_name, arguments) {
            Ok(result) => {
                let text = serde_json::to_string_pretty(&result).unwrap_or_default();
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id.clone(),
                    result: Some(serde_json::json!({
                        "content": [{ "type": "text", "text": text }]
                    })),
                    error: None,
                }
            }
            Err(e) => {
                let (msg, code) = match e {
                    DaemonTransportError::Io(io) => {
                        (format!("daemon unreachable: {io}"), -32000)
                    }
                    DaemonTransportError::Protocol(s) => (format!("protocol: {s}"), -32002),
                    DaemonTransportError::DaemonError(s) => (format!("daemon: {s}"), -32004),
                    DaemonTransportError::UnknownTool(t) => {
                        (format!("unknown tool: {t}"), -32602)
                    }
                };
                let _ = code;
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id.clone(),
                    result: Some(serde_json::json!({
                        "content": [{ "type": "text", "text": msg }],
                        "isError": true
                    })),
                    error: None,
                }
            }
        }
    }

    fn handle_tools_call(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        let params = req.params.as_ref();
        let tool_name = params
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let arguments = params
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        // Observability tools route directly through the daemon socket
        // when one is configured — they never touch the agent runtime.
        if matches!(tool_name, "list_receipts" | "get_receipt") {
            return self.handle_receipt_tool(req, tool_name, &arguments);
        }

        // Map MCP tool name to agent method
        let agent_method = match tool_name {
            "whoami" => WHOAMI,
            "list_grants" => LIST_GRANTS,
            "request_grant" => REQUEST_GRANT,
            "grant_status" => GRANT_STATUS,
            "use_credential" => USE_CREDENTIAL,
            other => {
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id.clone(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: format!("unknown tool: {other}"),
                        data: None,
                    }),
                };
            }
        };

        let agent_req = AgentRequest {
            id: req.id.as_ref().map(|v| v.to_string()).unwrap_or_default(),
            method: agent_method.to_string(),
            params: arguments,
        };

        let resp = self.runtime.handle(&agent_req);

        if let Some(err) = &resp.error {
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id.clone(),
                result: Some(serde_json::json!({
                    "content": [{ "type": "text", "text": err.message }],
                    "isError": true
                })),
                error: None,
            }
        } else {
            let text = serde_json::to_string_pretty(&resp.result).unwrap_or_default();
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id.clone(),
                result: Some(serde_json::json!({
                    "content": [{ "type": "text", "text": text }]
                })),
                error: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;
    use emberlink_agent::runtime::{AgentConfig, AgentRuntime};

    fn test_server() -> McpServer {
        let store = Rc::new(core_state::EventStore::default());
        let runtime = AgentRuntime::new(
            AgentConfig {
                persona_id: "persona-test".to_string(),
                label: Some("test-mcp".to_string()),
            },
            store,
        );
        McpServer::new(runtime)
    }

    #[test]
    fn initialize_returns_capabilities() {
        let server = test_server();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "initialize".to_string(),
            params: None,
        };
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "emberlink-mcp");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[test]
    fn initialized_notification_returns_none() {
        let server = test_server();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: "notifications/initialized".to_string(),
            params: None,
        };
        assert!(server.handle_request(&req).is_none());
    }

    #[test]
    fn tools_list_returns_all_tools() {
        let server = test_server();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(2)),
            method: "tools/list".to_string(),
            params: None,
        };
        let resp = server.handle_request(&req).unwrap();
        let tools = resp.result.unwrap()["tools"].as_array().unwrap().clone();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert_eq!(
            names,
            vec![
                "whoami",
                "list_grants",
                "request_grant",
                "grant_status",
                "use_credential",
                "list_receipts",
                "get_receipt"
            ]
        );
    }

    #[test]
    fn tools_call_whoami() {
        let server = test_server();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(3)),
            method: "tools/call".to_string(),
            params: Some(serde_json::json!({
                "name": "whoami",
                "arguments": {}
            })),
        };
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let content = &result["content"][0];
        assert_eq!(content["type"], "text");
        let text: serde_json::Value = serde_json::from_str(content["text"].as_str().unwrap()).unwrap();
        assert_eq!(text["persona_id"], "persona-test");
    }

    #[test]
    fn tools_call_list_grants_without_daemon_fails_closed() {
        // Post-TODO-69I.1 behavior: `list_grants` now routes through the
        // daemon so the agent can't serve stale state out of its local
        // EventStore. The legacy in-process test server has no daemon
        // link, so the call MUST fail closed with `DAEMON_UNAVAILABLE`.
        let server = test_server();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(4)),
            method: "tools/call".to_string(),
            params: Some(serde_json::json!({
                "name": "list_grants",
                "arguments": {}
            })),
        };
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none(), "tool calls surface agent errors via isError");
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], serde_json::json!(true), "expected isError=true for fail-closed");
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("daemon unreachable"),
            "expected 'daemon unreachable' in error text, got: {text}"
        );
    }

    #[test]
    fn tools_call_request_grant_without_daemon_fails_closed() {
        // TODO 69.1 follow-up: when the wrapped `AgentRuntime` has no daemon
        // link (as in this legacy in-process MCP bridge), `request_grant`
        // MUST fail closed rather than silently write an approval into the
        // local store. This locks in the bypass closure.
        let server = test_server();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(5)),
            method: "tools/call".to_string(),
            params: Some(serde_json::json!({
                "name": "request_grant",
                "arguments": {
                    "scope": "read:passwords",
                    "resource_id": "passwords",
                    "duration_secs": 3600,
                    "reason": "need access"
                }
            })),
        };
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_none(), "tool calls surface agent errors via isError");
        let result = resp.result.unwrap();
        assert_eq!(
            result["isError"], true,
            "request_grant without a daemon link must be reported as an error"
        );
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("access denied") || text.contains("policy engine"),
            "error text should indicate the bypass was closed, got: {text}"
        );
    }

    #[test]
    fn tools_call_request_grant_missing_scope_is_error() {
        let server = test_server();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(6)),
            method: "tools/call".to_string(),
            params: Some(serde_json::json!({
                "name": "request_grant",
                "arguments": { "duration_secs": 3600 }
            })),
        };
        let resp = server.handle_request(&req).unwrap();
        // Agent errors are returned as tool results with isError=true
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], true);
    }

    #[test]
    fn tools_call_unknown_tool() {
        let server = test_server();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(7)),
            method: "tools/call".to_string(),
            params: Some(serde_json::json!({
                "name": "nonexistent",
                "arguments": {}
            })),
        };
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn unknown_method_returns_error() {
        let server = test_server();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(8)),
            method: "bogus/method".to_string(),
            params: None,
        };
        let resp = server.handle_request(&req).unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[test]
    fn process_line_parse_error() {
        let server = test_server();
        let result = server.process_line("not json at all");
        let resp: JsonRpcResponse = serde_json::from_str(&result.unwrap()).unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32700);
    }

    #[test]
    fn process_line_roundtrip() {
        let server = test_server();
        let input = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let result = server.process_line(&serde_json::to_string(&input).unwrap());
        let resp: JsonRpcResponse = serde_json::from_str(&result.unwrap()).unwrap();
        assert!(resp.error.is_none());
        assert_eq!(resp.id, Some(serde_json::json!(1)));
    }

    #[test]
    fn full_mcp_flow() {
        let server = test_server();

        // 1. Initialize
        let init_req = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": { "name": "test", "version": "0.1" } }
        });
        let resp = server.process_line(&serde_json::to_string(&init_req).unwrap()).unwrap();
        let init_resp: JsonRpcResponse = serde_json::from_str(&resp).unwrap();
        assert!(init_resp.error.is_none());

        // 2. Initialized notification (no response)
        let notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        assert!(server.process_line(&serde_json::to_string(&notif).unwrap()).is_none());

        // 3. List tools
        let list_req = serde_json::json!({
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/list"
        });
        let resp = server.process_line(&serde_json::to_string(&list_req).unwrap()).unwrap();
        let list_resp: JsonRpcResponse = serde_json::from_str(&resp).unwrap();
        let tools = list_resp.result.unwrap()["tools"].as_array().unwrap().len();
        assert_eq!(tools, 7);

        // 4. Call a tool
        let call_req = serde_json::json!({
            "jsonrpc": "2.0", "id": 3,
            "method": "tools/call",
            "params": { "name": "whoami", "arguments": {} }
        });
        let resp = server.process_line(&serde_json::to_string(&call_req).unwrap()).unwrap();
        let call_resp: JsonRpcResponse = serde_json::from_str(&resp).unwrap();
        assert!(call_resp.error.is_none());
        let content = &call_resp.result.unwrap()["content"][0];
        assert_eq!(content["type"], "text");
    }
}
