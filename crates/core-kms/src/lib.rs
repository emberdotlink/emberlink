//! `core-kms` — Vault Transit-compatible KMS surface for the Emberlink daemon.
//!
//! Implements the minimum subset of the HashiCorp Vault Transit API required by
//! Mozilla SOPS (`hc_vault_transit_uri`) and Pulumi (`hashivault://` secrets
//! provider) to target the Emberlink daemon as a localhost KMS.
//!
//! # Surface
//!
//! - `POST /v1/<engine>/encrypt/<key>` — wrap a caller-supplied DEK
//! - `POST /v1/<engine>/decrypt/<key>` — unwrap a previously wrapped DEK
//!
//! Both routes are stubs in this scaffold and currently return
//! `501 Not Implemented`; subsequent tasks wire the real wrap/unwrap call paths
//! into the AEAD primitives in `core-crypto`.
//!
//! # Auth
//!
//! Bearer-token validation lives in [`server::auth_middleware`]. v1 accepts any
//! non-empty `Authorization: Bearer <token>` (token-table lookup is downstream).
//! Missing or malformed headers return `401 Unauthorized`.
//!
//! # Listening surface — hard invariant
//!
//! [`KmsServer`] only binds to `127.0.0.1`. Refusing `0.0.0.0` and any
//! non-loopback address is a hard invariant; see ADR 100 §"Listening surface".
//!
//! # WASM
//!
//! This crate is **not** wasm-eligible — `axum` + `tokio` are app-tier deps.
//! Do not add `crates/core-kms` to the `wasm32-unknown-unknown` CI gate.

mod server;
pub mod transit;

pub use server::{DEFAULT_KMS_PORT, KmsServer, KmsServerError, NoopReceiptSink, ReceiptSink, run};
pub use transit::TransitKeyring;
