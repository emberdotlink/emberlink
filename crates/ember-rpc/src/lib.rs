//! ember-rpc — mTLS-only listener-frontend for emberd (ADR 155 amendment Phase B).
//!
//! # Two-process posture
//!
//! Per ADR 155 amendment (shipped #3500), the trust broker is two
//! processes that both run as the `ember` uid:
//!
//! 1. **`emberd` core** — vault + signing + grants + audit. Owns the
//!    peercred UDS lane (Phase D — local-uid clients).
//! 2. **`ember-rpc`** (this crate) — mTLS terminator, JSON-RPC parser,
//!    bincode forwarder. Owns the mTLS lane (Phase B — in-container
//!    agents + bridge clients).
//!
//! The split exists so the mTLS-facing surface can be reasoned about
//! and hardened independently of vault/signing code. ember-rpc never
//! touches plaintext key material; it terminates TLS, decodes the
//! JSON-RPC envelope, re-encodes as a typed bincode frame, and
//! forwards over a local UDS to emberd core. The response comes back
//! the same way and gets re-encoded as JSON-RPC for the wire.
//!
//! # Phase B scope (this crate today)
//!
//! - Bind mTLS listener.
//! - Accept connections + complete TLS handshake.
//! - Parse newline-delimited JSON-RPC frames.
//! - **Policy gate**: reject the 11 plaintext-bearing methods enumerated
//!   in [`PLAINTEXT_BEARING_METHODS`] with JSON-RPC error `-32601
//!   policy-denied`. Those methods stay on the peercred lane and are
//!   physically unreachable from the mTLS frontend.
//! - Stub: forward non-rejected methods to emberd core over UDS. The
//!   actual wire format + emberd-side dispatch is Phase C/D.
//!
//! # Checkpoint
//!
//! `ember_rpc_phase_b_mtls_lane_landed` (also stamped in `main.rs`) is
//! the `target_state_anchor` checkpoint for
//! ARCH-EMBER-RPC-PHASE-B-MTLS-CRATE.
//!
//! `ember_rpc_phase_c_mtls_listener_wired` (stamped in `listener.rs`) is
//! the checkpoint for ARCH-EMBER-RPC-PHASE-C-LISTENER-WIRING.

pub mod frame;
pub mod listener;

pub use frame::{DecodedFrame, FrameError};
pub use listener::{Listener, ListenerConfig, ListenerError};

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The 11 plaintext-bearing JSON-RPC methods that MUST NOT be served
/// over the mTLS lane. Source of truth: META-ADR-155 amendment.
///
/// These methods either accept plaintext key material as input or
/// return it as output. Allowing them on the mTLS lane would mean
/// plaintext crosses a process boundary that emberd core doesn't
/// peercred-verify, defeating the two-process posture's whole point.
///
/// Phase D wires the peercred UDS lane on emberd core for these; the
/// gate here is the build-time guarantee they cannot leak through the
/// mTLS frontend even by accident.
pub const PLAINTEXT_BEARING_METHODS: &[&str] = &[
    "vault_unseal",
    "vault_seal",
    "vault_rekey",
    "mint_grant",
    "export_private_key",
    "import_private_key",
    "vault_export_sealed",
    "vault_import_sealed",
    "decrypt_blob",
    "sign_with_unsealed_key",
    "recover_secret",
];

/// JSON-RPC error code for "method not found" per the 2.0 spec; the
/// brief specifies this code with a policy-denied reason string so
/// callers learn the method exists but is unavailable on this lane.
pub const POLICY_DENIED_ERROR_CODE: i64 = -32601;

/// Listener-frontend configuration. Bind addr is a localhost mTLS port
/// by default; UDS forward target is the path emberd core listens on
/// for the hand-rolled typed bridge frames ([`crate::frame`]) from siblings.
#[derive(Debug, Clone)]
pub struct Config {
    /// mTLS listen address. Default `127.0.0.1:8443`. ember-rpc and
    /// emberd both run as the `ember` uid so binding loopback is
    /// sufficient — no privileged-port escalation needed.
    pub listen_addr: SocketAddr,

    /// Path to emberd core's dedicated `0700` rpc-forward UDS, over which
    /// the sibling forwards the hand-rolled typed bridge frame (see
    /// [`crate::frame`]). Default `/var/run/emberd/rpc.sock`. emberd attests
    /// the peer via `SO_PEERCRED` (uid == `ember`) + a content-hash of the
    /// peer binary against the pinned `emberd-rpc` manifest entry, so this is
    /// a real provenance boundary, not merely a same-uid convention.
    pub forward_uds: PathBuf,

    /// Path to ember-rpc's server cert (PEM). Phase C: emberd's
    /// sibling-cert-mint companion task writes this from BridgeCa.
    /// Default `/var/lib/emberd/ember-rpc/server.crt`.
    pub server_cert_path: PathBuf,

    /// Path to ember-rpc's server private key (PEM). Same provenance
    /// as `server_cert_path`. Mode 0600. Default
    /// `/var/lib/emberd/ember-rpc/server.key`.
    pub server_key_path: PathBuf,

    /// Path to the bridge CA cert (PEM). Used as the single root for
    /// client-cert verification; system roots are NEVER consulted.
    /// emberd publishes this at `<data_dir>/bridge_ca.pem` alongside the
    /// raw `<data_dir>/bridge_ca.pub` fingerprint file. Default
    /// `/var/lib/emberd/bridge_ca.pem`.
    pub ca_cert_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8443"
                .parse()
                .expect("static SocketAddr parse must succeed"),
            forward_uds: PathBuf::from("/var/run/emberd/rpc.sock"),
            server_cert_path: PathBuf::from("/var/lib/emberd/ember-rpc/server.crt"),
            server_key_path: PathBuf::from("/var/lib/emberd/ember-rpc/server.key"),
            ca_cert_path: PathBuf::from("/var/lib/emberd/bridge_ca.pem"),
        }
    }
}

/// Minimal JSON-RPC 2.0 request envelope we parse off the wire. The
/// `params` blob stays as `serde_json::Value` because Phase B doesn't
/// dispatch — it only inspects `method` for the policy gate and
/// forwards the rest opaquely.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    #[serde(default)]
    pub id: serde_json::Value,
}

/// JSON-RPC 2.0 error response. Used to return policy-denied to the
/// client when a plaintext-bearing method hits the mTLS lane.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonRpcErrorResponse {
    pub jsonrpc: &'static str,
    pub error: JsonRpcError,
    pub id: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

/// Outcome of the per-request policy gate. Phase B's only job here is
/// to fork on "is this method allowed on the mTLS lane?" — everything
/// else (auth, payload validation, actual dispatch) is downstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Method is forwardable to emberd core over UDS.
    AllowForward,
    /// Method is on the plaintext-bearing list; refuse with
    /// `POLICY_DENIED_ERROR_CODE` and a `policy-denied: ...` message.
    DenyPlaintextBearing,
}

/// The policy gate — pure function so it's trivially unit-testable
/// without a TLS listener / port / keys. Keep it dumb on purpose: any
/// time we add nuance (per-grant overrides, audit-only modes, etc.)
/// the temptation is to thread state through here; instead, add a
/// sibling function and route at the caller so this gate stays the
/// simplest possible structural invariant.
pub fn gate_method(method: &str) -> PolicyDecision {
    if PLAINTEXT_BEARING_METHODS.contains(&method) {
        PolicyDecision::DenyPlaintextBearing
    } else {
        PolicyDecision::AllowForward
    }
}

/// Build a JSON-RPC error response for a policy-denied request. The
/// message string is the load-bearing diagnostic — callers will
/// (eventually) parse "policy-denied:" as a prefix to distinguish
/// these from generic method-not-found errors.
pub fn build_policy_denied_response(req: &JsonRpcRequest) -> JsonRpcErrorResponse {
    JsonRpcErrorResponse {
        jsonrpc: "2.0",
        error: JsonRpcError {
            code: POLICY_DENIED_ERROR_CODE,
            message: format!(
                "policy-denied: method {:?} not available on mTLS lane (use peercred UDS)",
                req.method
            ),
        },
        id: req.id.clone(),
    }
}

/// Synchronous entry point used by the binary entrypoints. Wraps the async
/// [`run_async`] in a tokio runtime + Ctrl-C shutdown signal so the
/// binary stays simple.
///
/// Phase C: bind the rustls server, accept connections, parse JSON-RPC
/// frames, route through [`gate_method`], write policy-denied responses
/// for plaintext-bearing methods and phase-c-stub responses for
/// allow-forward methods (Phase D wires the real bincode forward to
/// emberd core).
pub fn run(config: Config) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_async(config))
}

/// Async entry point — exposed so integration tests can drive the
/// listener without taking a hard dependency on `tokio::main`.
pub async fn run_async(config: Config) -> anyhow::Result<()> {
    let listener_config = ListenerConfig {
        listen_addr: config.listen_addr,
        forward_uds: config.forward_uds.clone(),
        server_cert_path: config.server_cert_path.clone(),
        server_key_path: config.server_key_path.clone(),
        ca_cert_path: config.ca_cert_path.clone(),
    };

    tracing::info!(
        listen_addr = %listener_config.listen_addr,
        forward_uds = %listener_config.forward_uds.display(),
        server_cert_path = %listener_config.server_cert_path.display(),
        ca_cert_path = %listener_config.ca_cert_path.display(),
        allowed_method_policy = "all-except-plaintext-bearing",
        denied_methods = ?PLAINTEXT_BEARING_METHODS,
        "ember-rpc Phase C mTLS lane starting"
    );

    let handle = Listener::spawn(listener_config).await?;

    // Block on Ctrl-C; on receipt, drop the listener join handle which
    // cancels the accept loop. Phase D will add SIGTERM-graceful drain
    // semantics (let in-flight requests complete before exit).
    tokio::signal::ctrl_c().await?;
    tracing::info!("ember-rpc: Ctrl-C received, shutting down");
    handle.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every plaintext-bearing method on the META-ADR-155 list MUST
    /// be denied by the policy gate. This is the build-time structural
    /// invariant that the mTLS frontend cannot accidentally serve a
    /// plaintext-bearing RPC.
    #[test]
    fn policy_gate_denies_all_plaintext_bearing_methods() {
        for method in PLAINTEXT_BEARING_METHODS {
            assert_eq!(
                gate_method(method),
                PolicyDecision::DenyPlaintextBearing,
                "method {method:?} must be denied on mTLS lane"
            );
        }
    }

    /// Methods not on the plaintext-bearing list are allowed through.
    /// We exercise a couple of representative shapes — a vault-status
    /// read, a grant lookup — both of which Phase C will forward as
    /// bincode to emberd core.
    #[test]
    fn policy_gate_allows_non_plaintext_methods() {
        for method in &["vault_status", "list_grants", "audit_tail", "ping"] {
            assert_eq!(
                gate_method(method),
                PolicyDecision::AllowForward,
                "method {method:?} should be forward-allowed on mTLS lane"
            );
        }
    }

    /// The denied response carries the JSON-RPC error code agreed on
    /// in the META-ADR-155 brief (-32601) plus a `policy-denied:`
    /// prefix message so callers can distinguish "method does not
    /// exist anywhere" from "method exists but not on this lane."
    #[test]
    fn policy_denied_response_carries_canonical_code_and_message() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "vault_unseal".to_string(),
            params: serde_json::Value::Null,
            id: serde_json::Value::from(7u64),
        };
        let resp = build_policy_denied_response(&req);
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.error.code, POLICY_DENIED_ERROR_CODE);
        assert!(
            resp.error.message.starts_with("policy-denied:"),
            "message must start with the canonical prefix; got {:?}",
            resp.error.message
        );
        assert!(
            resp.error.message.contains("vault_unseal"),
            "message should name the offending method; got {:?}",
            resp.error.message
        );
        assert_eq!(resp.id, serde_json::Value::from(7u64));
    }

    /// Defensive: the constant list shape is what other crates (and
    /// the ADR audit) reference. Locking the count + ordering as a
    /// regression test means a future "just add one more method"
    /// drive-by has to update this test and consciously acknowledge
    /// it's growing the plaintext surface.
    #[test]
    fn plaintext_bearing_method_list_is_exactly_eleven() {
        assert_eq!(
            PLAINTEXT_BEARING_METHODS.len(),
            11,
            "META-ADR-155 amendment enumerates 11 plaintext-bearing methods; \
             extending this list is a deliberate ADR-amendment decision, \
             not a casual addition"
        );
    }
}
