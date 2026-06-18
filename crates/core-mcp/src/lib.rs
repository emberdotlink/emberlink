//! Shared JSON-RPC 2.0 types and stdio transport for MCP servers.
//!
//! Provides the protocol types (`JsonRpcRequest`, `JsonRpcResponse`,
//! `JsonRpcError`), the `MAX_LINE_BYTES` guard, and a `serve_stdio`
//! function that runs the request/response loop.  Two transport variants
//! are available:
//!
//! * **sync** (`serve_stdio_sync`) — plain `std::io`, used by
//!   `internal-automation`.
//! * **async** (`serve_stdio_async`, feature `async-stdio`) — tokio
//!   `AsyncBufRead`, used by `emberlink-mcp`.
//!
//! Callers implement the `Handler` trait (sync) or `AsyncHandler` trait
//! (async) to plug in their dispatch logic.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── JSON-RPC 2.0 types ────────────────────────────────────────────────────

/// Maximum allowed line length (1 MiB). Lines exceeding this are rejected
/// to prevent memory exhaustion from a malicious or buggy client.
pub const MAX_LINE_BYTES: usize = 1_048_576;

/// JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// ── Response helpers ──────────────────────────────────────────────────────

/// Build a JSON-RPC error response.
pub fn error_response(id: Option<Value>, code: i64, message: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
            data: None,
        }),
    }
}

/// Serialise a `JsonRpcResponse` to a newline-terminated byte vector.
pub fn response_bytes(resp: &JsonRpcResponse) -> Vec<u8> {
    let mut out = serde_json::to_vec(resp).unwrap_or_else(|_| b"{}".to_vec());
    out.push(b'\n');
    out
}

/// Serialise a JSON value to a newline-terminated byte vector.
/// Used for the oversize-line error which is assembled as a raw `json!`.
pub fn value_bytes(v: &Value) -> Vec<u8> {
    let mut out = serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec());
    out.push(b'\n');
    out
}

// ── Sync Handler + serve_stdio_sync ──────────────────────────────────────

/// Sync request handler — implement this on your server struct.
///
/// Return `Some(response)` to write a reply; `None` to silently discard
/// (e.g. for notification messages like `notifications/initialized`).
pub trait Handler {
    fn handle(&self, req: &JsonRpcRequest) -> Option<JsonRpcResponse>;
}

/// Run the synchronous stdio loop.
///
/// Reads newline-delimited JSON from `reader`, writes newline-delimited
/// JSON to `writer`.  Enforces `MAX_LINE_BYTES`.  Returns when EOF is
/// reached or a write error occurs.
pub fn serve_stdio_sync<H, R, W>(handler: &H, reader: R, mut writer: W)
where
    H: Handler,
    R: std::io::BufRead,
    W: std::io::Write,
{
    for raw in reader.lines() {
        let line = match raw {
            Ok(l) => l,
            Err(e) => {
                eprintln!("core-mcp: stdin read error: {e}");
                break;
            }
        };

        if line.len() > MAX_LINE_BYTES {
            let err = serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": { "code": -32600, "message": "request exceeds 1MB limit" }
            });
            if writer.write_all(&value_bytes(&err)).is_err() {
                break;
            }
            let _ = writer.flush();
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let err = error_response(None, -32700, &format!("parse error: {e}"));
                if writer.write_all(&response_bytes(&err)).is_err() {
                    break;
                }
                let _ = writer.flush();
                continue;
            }
        };

        if let Some(resp) = handler.handle(&req) {
            if writer.write_all(&response_bytes(&resp)).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    }
}

// ── Async Handler + serve_stdio_async ────────────────────────────────────

#[cfg(feature = "async-stdio")]
pub mod r#async {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    /// Async request handler — implement this on your async server struct.
    pub trait AsyncHandler {
        fn handle(&self, req: &JsonRpcRequest) -> Option<JsonRpcResponse>;
    }

    /// Run the async stdio loop (tokio).
    pub async fn serve_stdio_async<H, R, W>(handler: &H, reader: R, mut writer: W)
    where
        H: AsyncHandler,
        R: tokio::io::AsyncBufRead + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let mut lines = reader.lines();

        while let Ok(Some(line)) = lines.next_line().await {
            if line.len() > MAX_LINE_BYTES {
                let err = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32600, "message": "request exceeds 1MB limit" }
                });
                if writer.write_all(&value_bytes(&err)).await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
                continue;
            }

            let trimmed = line.trim().to_string();
            if trimmed.is_empty() {
                continue;
            }

            let req: JsonRpcRequest = match serde_json::from_str(&trimmed) {
                Ok(r) => r,
                Err(e) => {
                    let err = error_response(None, -32700, &format!("parse error: {e}"));
                    if writer.write_all(&response_bytes(&err)).await.is_err() {
                        break;
                    }
                    if writer.flush().await.is_err() {
                        break;
                    }
                    continue;
                }
            };

            if let Some(resp) = handler.handle(&req) {
                if writer.write_all(&response_bytes(&resp)).await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Minimal handler that echoes the method back in the result.
    struct EchoHandler;

    impl Handler for EchoHandler {
        fn handle(&self, req: &JsonRpcRequest) -> Option<JsonRpcResponse> {
            if req.method == "notifications/ignore" {
                return None;
            }
            Some(JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: req.id.clone(),
                result: Some(json!({ "method": req.method })),
                error: None,
            })
        }
    }

    fn run_sync(input: &str) -> String {
        let mut output = Vec::new();
        serve_stdio_sync(&EchoHandler, std::io::Cursor::new(input), &mut output);
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn valid_request_round_trips() {
        let out = run_sync(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
        let v: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["result"]["method"], "ping");
        assert_eq!(v["id"], 1);
    }

    #[test]
    fn malformed_json_returns_parse_error() {
        let out = run_sync("not-json\n");
        let v: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["error"]["code"], -32700);
        let msg = v["error"]["message"].as_str().unwrap();
        assert!(msg.starts_with("parse error:"));
    }

    #[test]
    fn oversize_line_returns_request_too_large() {
        let big = "x".repeat(MAX_LINE_BYTES + 1);
        let out = run_sync(&big);
        let v: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["error"]["code"], -32600);
        assert!(v["error"]["message"].as_str().unwrap().contains("1MB"));
    }

    #[test]
    fn missing_method_field_returns_parse_error() {
        // A JSON object without "method" fails deserialization.
        let out = run_sync(r#"{"jsonrpc":"2.0","id":2}"#);
        let v: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["error"]["code"], -32700);
    }

    #[test]
    fn notification_produces_no_output() {
        let out = run_sync(r#"{"jsonrpc":"2.0","method":"notifications/ignore"}"#);
        assert!(out.trim().is_empty());
    }

    #[test]
    fn empty_lines_are_skipped() {
        let out = run_sync("\n\n\n");
        assert!(out.trim().is_empty());
    }

    #[test]
    fn jsonrpc_request_deserialises_params_optional() {
        let r: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":null,"method":"x"}"#).unwrap();
        assert!(r.params.is_none());
        assert!(r.id.is_none());
    }

    #[test]
    fn jsonrpc_response_skips_none_fields() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(json!(3)),
            result: Some(json!({"ok": true})),
            error: None,
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(!s.contains("error"));
        assert!(!s.contains("null"));
    }

    #[test]
    fn error_response_helper_sets_code_and_message() {
        let r = error_response(Some(json!(5)), -32601, "method not found");
        assert_eq!(r.error.as_ref().unwrap().code, -32601);
        assert_eq!(r.error.as_ref().unwrap().message, "method not found");
        assert_eq!(r.id, Some(json!(5)));
    }

    #[test]
    fn max_line_bytes_constant_is_one_mib() {
        assert_eq!(MAX_LINE_BYTES, 1_048_576);
    }
}
