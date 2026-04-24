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
            // Budget status (P69K-F1)
            "grant_budget_status" => Some("grant_budget_status"),
            // Vault
            "vault_list" => Some("vault_list"),
            // Health
            "ping" => Some("ping"),
            _ => None,
        }
    }

    /// Extract the host component from a string that may be a URL or a bare
    /// hostname/path. Returns `None` if the string is clearly not URL-like.
    ///
    /// Parsing strategy (no added deps):
    /// 1. If the string contains `://`, split on `://` and take the authority
    ///    portion (everything before the first `/` after the scheme).
    /// 2. Otherwise, take the portion before the first `/` — bare hostnames
    ///    like `api.github.com` or paths like `api.github.com/repos/...`.
    /// 3. Strip any `user@` prefix and `:port` suffix.
    /// 4. Return `None` for empty results or strings that look like simple
    ///    credential names (no `.` and no `/`).
    fn extract_host(s: &str) -> Option<String> {
        let authority = if let Some(after_scheme) = s.split("://").nth(1) {
            after_scheme.split('/').next().unwrap_or("")
        } else {
            s.split('/').next().unwrap_or("")
        };
        // Strip user@ prefix and :port suffix.
        let host_port = authority.split('@').next_back().unwrap_or(authority);
        let host = host_port.split(':').next().unwrap_or(host_port);
        // Reject empty or plain words with no structure (looks like a
        // credential name, not a hostname).
        if host.is_empty() || (!host.contains('.') && !host.contains(':')) {
            return None;
        }
        Some(host.to_string())
    }

    /// Translate a `request_grant` MCP call into `request_access` daemon
    /// parameters by synthesizing the `action` field from `credential_name`.
    ///
    /// This ensures agent-initiated credential requests route through the
    /// policy engine AND the pre-evaluation rate limiter (see TODO 69.1).
    /// All other fields are forwarded unchanged — no parameter tampering.
    ///
    /// Also injects NOTIF-1 banner fields (`tool_name`, `target_host`,
    /// `target_url`, `agent_framework`) so the approval banner in the
    /// daemon shows richer context for MCP-originated requests.
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

            // NOTIF-1: inject banner fields for the daemon's approval
            // notification. These are set only when not already present so
            // callers that supply richer context aren't overwritten.
            obj.entry("tool_name")
                .or_insert_with(|| serde_json::Value::String("mcp/request_grant".to_string()));
            obj.entry("agent_framework")
                .or_insert_with(|| serde_json::Value::String("mcp".to_string()));

            // Derive target_host from `resource_id` when present. This field
            // often carries a URL-like path (e.g. "api.github.com/repos/...").
            // Fall back to `credential_name` if `resource_id` is absent.
            let url_candidate = arguments
                .get("resource_id")
                .and_then(|v| v.as_str())
                .or(Some(credential_name));
            if let Some(host) = url_candidate.and_then(Self::extract_host) {
                obj.entry("target_host")
                    .or_insert_with(|| serde_json::Value::String(host.clone()));
                obj.entry("target_url")
                    .or_insert_with(|| serde_json::Value::String(host));
            }
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
    fn map_tool_to_method_grant_budget_status_routes_to_daemon() {
        // `grant_budget_status` is a read-only observability tool that bypasses
        // the agent runtime and talks directly to the daemon socket — mirrors
        // the `list_receipts` / `get_receipt` pattern.
        assert_eq!(
            DaemonTransport::map_tool_to_method("grant_budget_status"),
            Some("grant_budget_status")
        );
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

    // --- NOTIF-1: MCP approval-request banner fields ---

    #[test]
    fn mcp_approval_request_populates_tool_fields() {
        // request_grant with a URL-like resource_id should populate
        // tool_name and target_host in the translated params so the
        // daemon's approval banner shows richer context.
        let args = serde_json::json!({
            "credential_name": "github-token",
            "resource_id": "api.github.com/repos/emberdotlink/emberlink",
            "scope": "repo:push",
            "ttl_secs": 3600
        });
        let translated = DaemonTransport::translate_request_grant(&args).unwrap();
        assert!(
            translated["tool_name"].as_str().map(|s| s.starts_with("mcp")).unwrap_or(false),
            "tool_name should start with 'mcp', got: {:?}",
            translated["tool_name"]
        );
        assert!(
            translated["target_host"].is_string(),
            "target_host should be present when resource_id contains a hostname"
        );
        assert_eq!(
            translated["target_host"].as_str(),
            Some("api.github.com"),
            "target_host should be the authority portion of resource_id"
        );
        assert_eq!(translated["agent_framework"], "mcp");
    }

    #[test]
    fn mcp_approval_request_no_resource_id_falls_back_to_credential_name() {
        // When resource_id is absent, the host extraction falls back to
        // credential_name. A plain name like "github-token" has no dot so
        // target_host stays None — that's expected and correct.
        let args = serde_json::json!({
            "credential_name": "github-token",
            "scope": "repo:read"
        });
        let translated = DaemonTransport::translate_request_grant(&args).unwrap();
        assert_eq!(translated["tool_name"], "mcp/request_grant");
        assert_eq!(translated["agent_framework"], "mcp");
        // Plain credential name has no dot → no host extracted.
        assert!(
            translated.get("target_host").is_none()
                || translated["target_host"].is_null(),
            "plain credential name should not produce a target_host"
        );
    }

    #[test]
    fn extract_host_url_with_scheme() {
        assert_eq!(
            DaemonTransport::extract_host("https://api.github.com/repos/foo"),
            Some("api.github.com".to_string())
        );
    }

    #[test]
    fn extract_host_bare_path() {
        assert_eq!(
            DaemonTransport::extract_host("api.github.com/repos/foo"),
            Some("api.github.com".to_string())
        );
    }

    #[test]
    fn extract_host_plain_name_returns_none() {
        assert_eq!(DaemonTransport::extract_host("github-token"), None);
        assert_eq!(DaemonTransport::extract_host("my_credential"), None);
    }

    #[test]
    fn extract_host_strips_port() {
        assert_eq!(
            DaemonTransport::extract_host("https://api.example.com:8443/path"),
            Some("api.example.com".to_string())
        );
    }
}
