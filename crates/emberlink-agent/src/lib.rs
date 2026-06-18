//! Emberlink Agent Protocol (P30).
//!
//! JSON-over-stdio protocol for AI agent integration. Agents connect via
//! stdin/stdout and can list grants, request access, use credentials, and
//! check status — all through the Emberlink trust model.
//!
//! Protocol: one JSON object per line on stdin, one JSON response per line
//! on stdout. Compatible with MCP, LangChain, and any tool-use framework.

#[cfg(unix)]
pub mod async_client;
pub mod cached_secret;
pub mod protocol;
pub mod relay;
pub mod revocation;
pub mod runtime;
#[cfg(unix)]
pub mod socket_transport;
