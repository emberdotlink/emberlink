//! CLASSIFICATION: PUBLIC
//!
//! `ember status` support modules. The CLI status entrypoint itself
//! lives in `bin/ember/status.rs`; this module is the home for status
//! helpers that ship as part of the library surface (and are therefore
//! reachable from integration tests).
//!
//! See [`troubleshoot`] for the F-code-driven diagnostic appendix
//! invoked by `ember status --troubleshoot` per ADR 161 §Component 3.

pub mod troubleshoot;
