//! CLASSIFICATION: PUBLIC
//!
//! META-AP-CAPABILITY-ISOLATION-MAP-CONSUMER — T2 integration tests.
//!
//! Verifies the production read-site for `core_grant_types::capabilities::
//! CAPABILITY_ISOLATION_MAP` inside the `broker.mint_sub_persona` RPC
//! handler. Until this consumer landed, the 565-LOC map was declarative-
//! only — no production reads, ergo zero runtime protection. These tests
//! lock the fail-closed contract end-to-end:
//!
//! 1. An unclassified capability in `capabilities` MUST fail closed at
//!    RPC code `-32603` BEFORE the unsupported-scaffold lane (`-32000`)
//!    runs. Order matters: if the scaffold ran first the daemon would
//!    surface the wrong posture (scaffold not implemented) and the
//!    capability gate would be invisible to operators.
//! 2. A fully classified `capabilities` array passes the gate and reaches
//!    the existing scaffold at `-32000`. The gate must not refuse a
//!    well-formed request.
//! 3. Empty `capabilities` array passes the gate (no isolation-requiring
//!    capability to drive a split) and reaches the scaffold.
//! 4. A non-array `capabilities` value is rejected at `-32602`
//!    (InvalidParams) — input-shape error, not a capability-classification
//!    error.
//! 5. A non-string element inside the `capabilities` array is rejected at
//!    `-32602` for the same input-shape reason.
//!
//! Anchor: `capability_isolation_map_consumed`. Scoped to the daemon
//! crate so the test exercises the public RPC entry point exactly as a
//! socket client would.

use ember_daemon::broker::handler::handle_broker_mint_sub_persona;
use ember_daemon::infra::store::DaemonStore;
use serde_json::json;

/// (1) Unclassified capability MUST fail closed at `-32603` BEFORE the
/// unsupported-scaffold lane (`-32000`) runs. If this test starts seeing
/// `-32000` the gate has been reordered into a no-op — that is the
/// regression we are guarding against.
#[tokio::test]
async fn unclassified_capability_fails_closed_at_neg_32603_before_scaffold() {
    let store = DaemonStore::open_in_memory().unwrap();
    let params = json!({
        "parent_persona_id": "persona-abc123",
        "child_label": "worker-1",
        "scope": "*",
        "capabilities": ["not_a_real_capability"],
    });
    let result = handle_broker_mint_sub_persona(&store, &params).await;
    match result {
        Err((code, msg)) => {
            assert_eq!(
                code, -32603,
                "unclassified capability must surface -32603 (InternalError), \
                 not the -32000 unsupported-scaffold lane — got {code} ({msg})"
            );
            assert!(
                msg.contains("not_a_real_capability"),
                "error must name the offending capability, got: {msg}"
            );
            assert!(
                msg.contains("fail-closed"),
                "error must surface the fail-closed posture literally, got: {msg}"
            );
        }
        Ok(v) => panic!("expected Err but got Ok({v})"),
    }
}

/// (2) Classified capabilities pass the gate and reach the existing
/// scaffold at `-32000`. The gate's job is to refuse unclassified
/// inputs, not to refuse well-formed ones; a classified request must
/// fall through to the same unsupported-scaffold lane that a
/// no-`capabilities` request hits.
#[tokio::test]
async fn classified_capabilities_pass_gate_and_reach_scaffold_at_neg_32000() {
    let store = DaemonStore::open_in_memory().unwrap();
    let params = json!({
        "parent_persona_id": "persona-abc123",
        "child_label": "worker-1",
        "scope": "*",
        "capabilities": ["read_files", "git_op"],
    });
    let result = handle_broker_mint_sub_persona(&store, &params).await;
    match result {
        Err((code, msg)) => {
            assert_eq!(
                code, -32000,
                "classified capabilities must pass the gate and reach the \
                 scaffold's -32000 unsupported lane, got {code} ({msg})"
            );
            assert!(
                msg.contains("fail-closed") || msg.contains("not implemented"),
                "scaffold lane should surface its own unsupported posture, got: {msg}"
            );
        }
        Ok(v) => panic!("expected Err but got Ok({v})"),
    }
}

/// (3) Empty `capabilities` array passes the gate. There is no
/// isolation-requiring capability to drive a split; the request reaches
/// the existing scaffold lane. Empty-input must not be confused with
/// missing-classification.
#[tokio::test]
async fn empty_capabilities_array_passes_gate() {
    let store = DaemonStore::open_in_memory().unwrap();
    let params = json!({
        "parent_persona_id": "persona-abc123",
        "child_label": "worker-1",
        "scope": "*",
        "capabilities": [],
    });
    let result = handle_broker_mint_sub_persona(&store, &params).await;
    match result {
        Err((code, _msg)) => {
            assert_eq!(
                code, -32000,
                "empty capabilities array must pass the gate (no isolation-\
                 requiring capability) and reach the scaffold, got {code}"
            );
        }
        Ok(v) => panic!("expected Err but got Ok({v})"),
    }
}

/// (4) Non-array `capabilities` is rejected at `-32602` (InvalidParams).
/// This is an input-shape error: the client sent a value of the wrong
/// JSON type. It must not be conflated with the classification gate's
/// `-32603` posture.
#[tokio::test]
async fn non_array_capabilities_rejected_at_neg_32602() {
    let store = DaemonStore::open_in_memory().unwrap();
    let params = json!({
        "parent_persona_id": "persona-abc123",
        "child_label": "worker-1",
        "scope": "*",
        "capabilities": "read_files",
    });
    let result = handle_broker_mint_sub_persona(&store, &params).await;
    match result {
        Err((code, msg)) => {
            assert_eq!(
                code, -32602,
                "non-array capabilities must be rejected as InvalidParams, \
                 got {code} ({msg})"
            );
            assert!(
                msg.contains("capabilities"),
                "error must name the offending field, got: {msg}"
            );
        }
        Ok(v) => panic!("expected Err but got Ok({v})"),
    }
}

/// (5) A non-string element inside the `capabilities` array is rejected
/// at `-32602`. Same input-shape posture as (4); the array shape is
/// valid but one element is not the expected string scalar.
#[tokio::test]
async fn non_string_element_in_capabilities_rejected_at_neg_32602() {
    let store = DaemonStore::open_in_memory().unwrap();
    let params = json!({
        "parent_persona_id": "persona-abc123",
        "child_label": "worker-1",
        "scope": "*",
        "capabilities": ["read_files", 42, "git_op"],
    });
    let result = handle_broker_mint_sub_persona(&store, &params).await;
    match result {
        Err((code, msg)) => {
            assert_eq!(
                code, -32602,
                "non-string element must be rejected as InvalidParams, got \
                 {code} ({msg})"
            );
            assert!(
                msg.contains("capabilities"),
                "error must name the offending field path, got: {msg}"
            );
        }
        Ok(v) => panic!("expected Err but got Ok({v})"),
    }
}
