//! ember-tools — Wasm runtime scaffold for capability-scoped tool execution.
//!
//! Agents run Wasm modules through a capability-scoped runtime; never see
//! raw credentials. This crate provides the trait surface (`WasmTool`) and a
//! `StubRuntime` that returns `ToolError::NotImplemented` until the real
//! wasmtime integration lands in `implementation-note-433`.

pub mod runtime;
