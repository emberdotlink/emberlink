use std::path::Path;

/// MCP transport that routes tool calls through the ember daemon socket.
pub struct DaemonTransport {
    socket_path: std::path::PathBuf,
}

impl DaemonTransport {
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self { socket_path: socket_path.as_ref().to_path_buf() }
    }

    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Map MCP tool name to daemon socket method name.
    ///
    /// Note: `request_grant` is intentionally NOT in this map. It is
    /// handled by a special-case branch in [`Self::call_tool`] that routes
    /// it through `request_access` so the policy engine and pre-eval rate
    /// limiter both run. See design and TODO 69.1.
    fn map_tool_to_method(tool_name: &str) -> Option<&str> {
        match tool_name {
            // Credential access
            "use_credential" => Some("use_credential"),
            "list_grants" => Some("list_grants"),
            "grant_status" => Some("evaluate_grant"),
            "revoke_grant" => Some("revoke_grant"),
            "delegate_grant" => Some("delegate_grant"),
            "grant_summary" => Some("grant_summary"),
            // Persona management
            "whoami" => Some("list_personas"),
            "create_persona" => Some("create_persona"),
            // Approval workflow
            "request_access" => Some("request_access"),
            "list_approvals" => Some("list_pending_approvals"),
            "submit_approval" => Some("submit_approval"),
            // Observability
            "audit_query" => Some("audit_query"),
            "detect_anomalies" => Some("detect_anomalies"),
            // Receipts (Stream D)
            "list_receipts" => Some("list_receipts"),
            "get_receipt" => Some("get_receipt"),
            "daemon_identity" => Some("daemon_identity"),
            // Vault
            "vault_list" => Some("vault_list"),
            // Health
            "ping" => Some("ping"),
            _ => None,
        }
    }

    /// Translate a `request_grant` MCP call into `request_access` daemon
    /// parameters by synthesizing the `action` field from `credential_name`.
    ///
    /// This ensures agent-initiated credential requests route through the
    /// policy engine AND the pre-evaluation rate limiter (see TODO 69.1).
    /// All other fields are forwarded unchanged — no parameter tampering.
    ///
    /// Fails closed: returns `Protocol` error if `credential_name` is
    /// missing rather than silently passing an empty action string.
    fn translate_request_grant(
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonTransportError> {
        let credential_name = arguments
            .get("credential_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                DaemonTransportError::Protocol(
                    "missing credential_name for request_grant".to_string(),
                )
            })?;

        let action = format!("credential.access.{credential_name}");

        // Clone the caller's arguments and add the synthesized action.
        // If `action` was already supplied by the caller, the synthesized
        // value overrides it to prevent callers from bypassing the naming
        // convention the policy engine expects.
        let mut augmented = match arguments {
            serde_json::Value::Object(_) => arguments.clone(),
            _ => serde_json::Value::Object(serde_json::Map::new()),
        };
        if let Some(obj) = augmented.as_object_mut() {
            obj.insert("action".to_string(), serde_json::Value::String(action));
        }
        Ok(augmented)
    }

    /// Execute an MCP tool call by routing through the daemon.
    pub fn call_tool(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonTransportError> {
        // Special case: `request_grant` routes through `request_access` so
        // policy evaluation AND the pre-eval rate limiter both apply.
        // TODO 69.1 / design. `translated` owns the augmented params so a
        // borrow survives the rest of the call.
        let translated: Option<serde_json::Value> = if tool_name == "request_grant" {
            Some(Self::translate_request_grant(arguments)?)
        } else {
            None
        };
        let (method, params_ref): (&str, &serde_json::Value) = if tool_name == "request_grant" {
            ("request_access", translated.as_ref().expect("translated set above"))
        } else {
            let m = Self::map_tool_to_method(tool_name)
                .ok_or_else(|| DaemonTransportError::UnknownTool(tool_name.to_string()))?;
            (m, arguments)
        };

        // Connect to daemon socket
        let stream = std::os::unix::net::UnixStream::connect(&self.socket_path)
            .map_err(DaemonTransportError::Io)?;

        let mut writer = stream.try_clone().map_err(DaemonTransportError::Io)?;
        let mut reader = std::io::BufReader::new(stream);

        // Build request
        let request = serde_json::json!({
            "id": "1",
            "method": method,
            "params": params_ref,
        });
        let mut line = serde_json::to_string(&request)
            .map_err(|e| DaemonTransportError::Protocol(e.to_string()))?;
        line.push('\n');

        use std::io::Write;
        writer.write_all(line.as_bytes()).map_err(DaemonTransportError::Io)?;

        // Read response
        use std::io::BufRead;
        let mut response_line = String::new();
        reader.read_line(&mut response_line).map_err(DaemonTransportError::Io)?;

        let response: serde_json::Value = serde_json::from_str(response_line.trim())
            .map_err(|e| DaemonTransportError::Protocol(e.to_string()))?;

        if let Some(error) = response.get("error").filter(|e| !e.is_null()) {
            let msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("unknown error");
            return Err(DaemonTransportError::DaemonError(msg.to_string()));
        }

        Ok(response.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }
}

#[derive(Debug)]
pub enum DaemonTransportError {
    Io(std::io::Error),
    Protocol(String),
    DaemonError(String),
    UnknownTool(String),
}

impl std::fmt::Display for DaemonTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Protocol(s) => write!(f, "protocol error: {s}"),
            Self::DaemonError(s) => write!(f, "daemon error: {s}"),
            Self::UnknownTool(s) => write!(f, "unknown tool: {s}"),
        }
    }
}

impl std::error::Error for DaemonTransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_tool_to_method_credential_tools() {
        // `request_grant` is intentionally NOT in the static map. It is
        // handled by a special-case branch in `call_tool` that routes it
        // through `request_access` so the policy engine and pre-eval rate
        // limiter both apply. See TODO 69.1.
        assert_eq!(DaemonTransport::map_tool_to_method("request_grant"), None);
        assert_eq!(DaemonTransport::map_tool_to_method("use_credential"), Some("use_credential"));
        assert_eq!(DaemonTransport::map_tool_to_method("list_grants"), Some("list_grants"));
        assert_eq!(DaemonTransport::map_tool_to_method("grant_status"), Some("evaluate_grant"));
        assert_eq!(DaemonTransport::map_tool_to_method("revoke_grant"), Some("revoke_grant"));
        assert_eq!(DaemonTransport::map_tool_to_method("delegate_grant"), Some("delegate_grant"));
        assert_eq!(DaemonTransport::map_tool_to_method("grant_summary"), Some("grant_summary"));
    }

    #[test]
    fn translate_request_grant_synthesizes_action() {
        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "credential_name": "github-token",
            "scope": "repo:read",
            "ttl_secs": 3600
        });
        let translated = DaemonTransport::translate_request_grant(&args).unwrap();
        assert_eq!(translated["action"], "credential.access.github-token");
        // Other fields must be forwarded unchanged (no parameter tampering).
        assert_eq!(translated["persona_id"], "persona-abc");
        assert_eq!(translated["credential_name"], "github-token");
        assert_eq!(translated["scope"], "repo:read");
        assert_eq!(translated["ttl_secs"], 3600);
    }

    #[test]
    fn translate_request_grant_missing_credential_name_fails_closed() {
        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "scope": "repo:read",
        });
        let err = DaemonTransport::translate_request_grant(&args).unwrap_err();
        match err {
            DaemonTransportError::Protocol(msg) => {
                assert!(msg.contains("credential_name"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn translate_request_grant_overrides_caller_supplied_action() {
        // A caller cannot bypass the policy naming convention by supplying
        // their own `action` — the synthesized value wins.
        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "credential_name": "github-token",
            "scope": "repo:read",
            "action": "credential.access.something-else"
        });
        let translated = DaemonTransport::translate_request_grant(&args).unwrap();
        assert_eq!(translated["action"], "credential.access.github-token");
    }

    #[test]
    fn translate_request_grant_non_object_fails_closed() {
        let args = serde_json::json!("not-an-object");
        let err = DaemonTransport::translate_request_grant(&args).unwrap_err();
        match err {
            DaemonTransportError::Protocol(msg) => {
                assert!(msg.contains("credential_name"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_to_method_persona_tools() {
        assert_eq!(DaemonTransport::map_tool_to_method("whoami"), Some("list_personas"));
        assert_eq!(DaemonTransport::map_tool_to_method("create_persona"), Some("create_persona"));
    }

    #[test]
    fn map_tool_to_method_approval_tools() {
        assert_eq!(DaemonTransport::map_tool_to_method("request_access"), Some("request_access"));
        assert_eq!(DaemonTransport::map_tool_to_method("list_approvals"), Some("list_pending_approvals"));
        assert_eq!(DaemonTransport::map_tool_to_method("submit_approval"), Some("submit_approval"));
    }

    #[test]
    fn map_tool_to_method_observability_tools() {
        assert_eq!(DaemonTransport::map_tool_to_method("audit_query"), Some("audit_query"));
        assert_eq!(DaemonTransport::map_tool_to_method("detect_anomalies"), Some("detect_anomalies"));
    }

    #[test]
    fn map_tool_to_method_vault_and_health_tools() {
        assert_eq!(DaemonTransport::map_tool_to_method("vault_list"), Some("vault_list"));
        assert_eq!(DaemonTransport::map_tool_to_method("ping"), Some("ping"));
    }

    #[test]
    fn map_tool_to_method_unknown_returns_none() {
        assert_eq!(DaemonTransport::map_tool_to_method("nonexistent"), None);
        assert_eq!(DaemonTransport::map_tool_to_method(""), None);
        assert_eq!(DaemonTransport::map_tool_to_method("WHOAMI"), None);
    }

    #[test]
    fn error_display_io() {
        let e = DaemonTransportError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "no socket"));
        assert!(e.to_string().starts_with("I/O error:"));
    }

    #[test]
    fn error_display_protocol() {
        let e = DaemonTransportError::Protocol("bad json".to_string());
        assert_eq!(e.to_string(), "protocol error: bad json");
    }

    #[test]
    fn error_display_daemon_error() {
        let e = DaemonTransportError::DaemonError("not authorized".to_string());
        assert_eq!(e.to_string(), "daemon error: not authorized");
    }

    #[test]
    fn error_display_unknown_tool() {
        let e = DaemonTransportError::UnknownTool("foo".to_string());
        assert_eq!(e.to_string(), "unknown tool: foo");
    }
}
