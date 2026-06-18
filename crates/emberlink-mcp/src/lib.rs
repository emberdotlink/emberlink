//! MCP (Model Context Protocol) server for Emberlink agent authorization.
//!
//! Exposes Emberlink's canonical daemon control surface over JSON-RPC 2.0
//! stdio. Dot-named canonical tools route through the daemon; the MCP
//! process does not mint or expose credential material.

pub mod cert_expiry;
pub mod daemon_transport;

use std::path::PathBuf;

use daemon_transport::{DaemonTransport, DaemonTransportError};

// --- JSON-RPC 2.0 types (shared via core-mcp; DRY-5) ---

pub use core_mcp::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};

const CANONICAL_CONTROL_TOOLS: &[&str] = &[
    "session.describe",
    "catalog.search_actions",
    "access.request",
    "grant.list",
    "status.get",
    "evidence.query",
    "evidence.get",
];

fn is_canonical_control_tool(tool_name: &str) -> bool {
    CANONICAL_CONTROL_TOOLS.contains(&tool_name)
}

// --- MCP tool definitions ---

fn tool_definitions() -> serde_json::Value {
    serde_json::json!([
        {
            "name": "session.describe",
            "description": "Describe a live Runtime Persona attach target without exposing endpoint credentials.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "runtime_persona_id": { "type": "string" }
                },
                "required": ["runtime_persona_id"]
            }
        },
        {
            "name": "catalog.search_actions",
            "description": "Search the daemon's Action Manifest catalog projection. Results name package-scoped actions; invocation still requires a separate execution contract and authority check.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "service": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100 }
                }
            }
        },
        {
            "name": "access.request",
            "description": "Request authority for a manifest action through the daemon. The daemon resolves authority need from the Action Manifest; resource_id or a typed target selects the concrete resource.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "persona_id": { "type": "string" },
                    "action_ref": { "type": "string" },
                    "credential_name": { "type": "string" },
                    "resource_id": { "type": "string" },
                    "target": {
                        "type": "object",
                        "properties": {
                            "kind": { "type": "string", "enum": ["github_repo"] },
                            "provider": { "type": "string", "enum": ["github"] },
                            "repo": { "type": "string", "description": "Exact GitHub repository in owner/name form." }
                        },
                        "required": ["kind", "repo"]
                    },
                    "ttl_secs": { "type": "integer" },
                    "reason": { "type": "string" },
                    "tool_name": { "type": "string" },
                    "target_host": { "type": "string" },
                    "target_url": { "type": "string" }
                },
                "required": ["persona_id", "action_ref", "credential_name"],
                "anyOf": [
                    { "required": ["resource_id"] },
                    { "required": ["target"] }
                ]
            }
        },
        {
            "name": "grant.list",
            "description": "List active grants visible to the caller, scoped by the daemon's trusted-principal rules.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "persona_id": { "type": "string" }
                }
            }
        },
        {
            "name": "status.get",
            "description": "Get the daemon status projection for the caller's runtime and authority posture.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "evidence.query",
            "description": "Query receipt evidence with daemon-side filtering.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor": { "type": "string" },
                    "kind": { "type": "string" },
                    "grant_id": { "type": "string" },
                    "resource": { "type": "string" },
                    "since": { "type": "string" },
                    "limit": { "type": "integer" }
                }
            }
        },
        {
            "name": "evidence.get",
            "description": "Fetch one receipt or terminal-grant receipt by id.",
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

/// MCP server for Emberlink's canonical daemon control/read surface.
pub struct McpServer {
    daemon_transport: Option<DaemonTransport>,
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            daemon_transport: None,
        }
    }

    /// Build a server with daemon-transport control tools wired.
    pub fn with_daemon_socket(socket: PathBuf) -> Self {
        Self {
            daemon_transport: Some(DaemonTransport::new(socket)),
        }
    }

    /// Build a server with a pre-constructed daemon transport. Used by the
    /// in-container mTLS bridge path (META-AP-EMBERLINK-MCP-MTLS-CLIENT)
    /// where the transport is an `Mtls` variant rather than a UDS path.
    /// Same control-surface semantics as [`Self::with_daemon_socket`].
    pub fn with_daemon_transport(transport: DaemonTransport) -> Self {
        Self {
            daemon_transport: Some(transport),
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

    /// Route a canonical control/read tool through the daemon transport.
    /// Fails closed with a descriptive error when no transport is configured.
    fn handle_daemon_control_tool(
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
                            "text": "daemon unreachable - daemon-routed MCP tools require --daemon-socket"
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
                    DaemonTransportError::Io(io) => (format!("daemon unreachable: {io}"), -32000),
                    DaemonTransportError::Protocol(s) => (format!("protocol: {s}"), -32002),
                    DaemonTransportError::DaemonError(s) => (format!("daemon: {s}"), -32004),
                    DaemonTransportError::UnknownTool(t) => (format!("unknown tool: {t}"), -32602),
                    // ADR 173 §Component 5 "Soft fail-closed at 90% TTL":
                    // typed refusal surfaced as an MCP isError result so
                    // the agent can see the cert is failing-to-refresh.
                    DaemonTransportError::RefreshFailing => (
                        "bridge cert refresh failing past 90% TTL band; new RPCs refused"
                            .to_string(),
                        -32001,
                    ),
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

        // Canonical MCP tools route directly through the daemon socket.
        if is_canonical_control_tool(tool_name) {
            return self.handle_daemon_control_tool(req, tool_name, &arguments);
        }

        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: req.id.clone(),
            result: None,
            error: Some(JsonRpcError {
                code: -32602,
                message: format!("unknown tool: {tool_name}"),
                data: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_server() -> McpServer {
        McpServer::new()
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
                "session.describe",
                "catalog.search_actions",
                "access.request",
                "grant.list",
                "status.get",
                "evidence.query",
                "evidence.get"
            ]
        );
    }

    #[test]
    fn canonical_control_tool_set_excludes_materialization_tools() {
        assert_eq!(
            CANONICAL_CONTROL_TOOLS,
            &[
                "session.describe",
                "catalog.search_actions",
                "access.request",
                "grant.list",
                "status.get",
                "evidence.query",
                "evidence.get",
            ]
        );
        assert!(
            !is_canonical_control_tool("use_credential"),
            "credential materialization is not exposed as a canonical MCP tool"
        );
        assert!(
            !is_canonical_control_tool("action.invoke"),
            "generic action.invoke is intentionally not part of the public control surface"
        );
    }

    #[test]
    fn access_request_schema_names_manifest_target_contract() {
        let defs = tool_definitions();
        let tools = defs.as_array().unwrap();
        let tool = tools
            .iter()
            .find(|t| t["name"] == "access.request")
            .unwrap();
        assert!(
            tool["inputSchema"]["properties"].get("action").is_none(),
            "legacy action field must not be advertised"
        );
        assert!(
            tool["inputSchema"]["properties"].get("scope").is_none(),
            "legacy scope field must not be advertised"
        );
        let required = tool["inputSchema"]["required"].as_array().unwrap();
        let required_fields: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            required_fields.contains(&"action_ref"),
            "canonical access requests should name an action_ref"
        );
        assert!(
            required_fields.contains(&"credential_name"),
            "canonical access requests should name a credential class"
        );
        let any_of = tool["inputSchema"]["anyOf"]
            .as_array()
            .expect("access.request schema should require resource_id or target");
        assert_eq!(
            any_of,
            &vec![
                serde_json::json!({"required": ["resource_id"]}),
                serde_json::json!({"required": ["target"]}),
            ]
        );
    }

    #[test]
    fn removed_legacy_tools_are_unknown() {
        let server = test_server();
        for name in [
            "whoami",
            "list_grants",
            "request_grant",
            "grant_status",
            "use_credential",
        ] {
            let req = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(serde_json::json!(6)),
                method: "tools/call".to_string(),
                params: Some(serde_json::json!({
                    "name": name,
                    "arguments": {}
                })),
            };
            let resp = server.handle_request(&req).unwrap();
            assert!(resp.error.is_some(), "{name} should be a removed MCP tool");
            assert_eq!(resp.error.unwrap().code, -32602);
        }
    }

    #[test]
    fn canonical_tool_without_daemon_fails_closed() {
        let server = test_server();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(7)),
            method: "tools/call".to_string(),
            params: Some(serde_json::json!({
                "name": "catalog.search_actions",
                "arguments": { "query": "github" }
            })),
        };
        let resp = server.handle_request(&req).unwrap();
        assert!(
            resp.error.is_none(),
            "daemon-routed tool failures are surfaced as MCP isError results"
        );
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("daemon unreachable"),
            "expected daemon unreachable error, got: {text}"
        );
    }

    #[test]
    fn tools_call_unknown_tool() {
        let server = test_server();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(8)),
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
            id: Some(serde_json::json!(9)),
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
        let resp = server
            .process_line(&serde_json::to_string(&init_req).unwrap())
            .unwrap();
        let init_resp: JsonRpcResponse = serde_json::from_str(&resp).unwrap();
        assert!(init_resp.error.is_none());

        // 2. Initialized notification (no response)
        let notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        assert!(
            server
                .process_line(&serde_json::to_string(&notif).unwrap())
                .is_none()
        );

        // 3. List tools
        let list_req = serde_json::json!({
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/list"
        });
        let resp = server
            .process_line(&serde_json::to_string(&list_req).unwrap())
            .unwrap();
        let list_resp: JsonRpcResponse = serde_json::from_str(&resp).unwrap();
        let tools = list_resp.result.unwrap()["tools"].as_array().unwrap().len();
        assert_eq!(tools, CANONICAL_CONTROL_TOOLS.len());

        // 4. Canonical tools fail closed without a daemon transport.
        let call_req = serde_json::json!({
            "jsonrpc": "2.0", "id": 3,
            "method": "tools/call",
            "params": { "name": "catalog.search_actions", "arguments": { "query": "github" } }
        });
        let resp = server
            .process_line(&serde_json::to_string(&call_req).unwrap())
            .unwrap();
        let call_resp: JsonRpcResponse = serde_json::from_str(&resp).unwrap();
        assert!(call_resp.error.is_none());
        let result = call_resp.result.unwrap();
        assert_eq!(result["isError"], true);
    }
}
