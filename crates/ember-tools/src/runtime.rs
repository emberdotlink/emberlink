//! Wasm-runtime trait surface and stub implementation.
//!
//! The `WasmTool` trait describes a single capability-scoped tool that can be
//! invoked with a JSON input and returns a JSON output. The real
//! wasmtime-backed implementation lands in `implementation-note-433`; this
//! module ships a `StubRuntime` whose `invoke` always returns
//! `ToolError::NotImplemented` so callers can wire against the trait today.

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;

/// Errors returned by a `WasmTool::invoke` call.
#[derive(Debug, Error)]
pub enum ToolError {
    /// The runtime has not implemented this capability yet. Used by
    /// `StubRuntime` until the wasmtime wire-up follow-up lands.
    #[error("not implemented")]
    NotImplemented,
    /// The Wasm module reported a runtime error (trap, host-function failure,
    /// etc.). Free-form message; structured error categories will land with
    /// the real runtime.
    #[error("wasm runtime error: {0}")]
    Runtime(String),
    /// The tool input failed validation against the tool's declared schema.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// A capability-scoped Wasm tool.
///
/// Implementors expose a stable `name()` (used for routing + audit) and an
/// `invoke()` that takes JSON in and returns JSON out. Credentials are never
/// passed across this boundary — capabilities are brokered separately.
#[async_trait]
pub trait WasmTool: Send + Sync {
    /// Stable identifier for this tool. Used for routing, audit, and
    /// capability scoping.
    fn name(&self) -> &str;

    /// Invoke the tool with a JSON input. Returns a JSON output or a
    /// `ToolError`. The real implementation will execute the Wasm module
    /// inside a sandboxed wasmtime store; the stub returns
    /// `ToolError::NotImplemented`.
    async fn invoke(&self, input: Value) -> Result<Value, ToolError>;
}

/// Placeholder runtime that returns `ToolError::NotImplemented` for every
/// invocation. Replaced by the wasmtime-backed runtime in
/// `implementation-note-433`.
pub struct StubRuntime {
    name: String,
}

impl StubRuntime {
    /// Construct a new stub with the given tool name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl WasmTool for StubRuntime {
    fn name(&self) -> &str {
        &self.name
    }

    async fn invoke(&self, _input: Value) -> Result<Value, ToolError> {
        Err(ToolError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn stub_returns_not_implemented() {
        let tool = StubRuntime::new("noop");
        let err = tool
            .invoke(json!({"hello": "world"}))
            .await
            .expect_err("stub runtime must not return Ok");
        assert!(matches!(err, ToolError::NotImplemented));
    }

    #[tokio::test]
    async fn tool_name_round_trips() {
        let tool = StubRuntime::new("capability.read-file");
        assert_eq!(tool.name(), "capability.read-file");
    }
}
