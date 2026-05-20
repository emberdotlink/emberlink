//! implementation-note-238 (design §"In-container
//! extension") — T2 integration tests for per-socket Persona
//! enrollment.
//!
//! These tests assert that any RPC arriving on a per-agent UDS socket
//! (`/run/emberd/agent-<uuid>.sock`) resolves its calling principal
//! from the `agent_socket_enrollments` table rather than from the
//! wire-claimed `caller_persona_id` / `caller_grant_id`. The
//! spawn-time enrollment IS the identity claim; wire payload fields
//! that disagree are silently overridden so a forged grant_id over a
//! worker's own socket cannot impersonate the orchestrator.
//!
//! Four shapes are exercised:
//!
//! 1. `test_rpc_on_agent_socket_uses_enrollment_not_wire` — enroll
//!    persona P for agent socket S; RPC on S with payload claiming
//!    persona Q resolves to P, not Q.
//! 2. `test_rpc_on_unenrolled_socket_refused` — RPC on a socket whose
//!    path matches the per-agent shape but has no enrollment row →
//!    `HandlerError::PrincipalNotEnrolled` (JSON-RPC `-32401`).
//! 3. `test_worker_b_cannot_impersonate_orchestrator` — enroll
//!    orchestrator O on socket S_o; enroll worker B on S_b;
//!    `delegate_grant` RPC on S_b claiming O's grant_id is refused.
//! 4. `test_revoked_enrollment_refuses_rpcs` — revoke enrollment for
//!    S; subsequent RPC on S → `PrincipalNotEnrolled`.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use ember_daemon::infra::handler::{
    EnrolledPrincipal, HandlerError, PeerCred, RequestContext, dispatch_method_with_context,
    enroll_container_persona,
};
use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::receipt::init_identity;
use ember_daemon::infra::runtime::PeerCredPrincipal;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::policy::PolicyEngine;
use rusqlite::params;
use serde_json::json;

const TEST_VAULT_KEY: [u8; 32] = [0xABu8; 32];

fn store_with_vault() -> DaemonStore {
    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    store.set_vault(Rc::new(Vault::new(TEST_VAULT_KEY)));
    store
}

fn test_policy() -> PolicyEngine {
    PolicyEngine::default()
}

fn test_rl() -> RefCell<RateLimiter> {
    RefCell::new(RateLimiter::default())
}

fn test_vault() -> Vault {
    Vault::new(TEST_VAULT_KEY)
}

/// Initialise the process-singleton daemon identity (idempotent — first
/// caller wins). Required for the `delegate_grant` path to mint Receipts.
fn ensure_test_identity() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir for daemon identity");
    let _ = init_identity(dir.path());
    dir
}

/// Build a `RequestContext` from a per-agent socket path so the
/// dispatch layer takes the enrolled-principal branch.
// container_persona_enrollment_tests_green_sentinel
// (implementation-note-235):
// Use `RequestContext::socket_for_test(peer)` to get a ctx with a
// synthetic presence_token bound to `peer.uid`. The cfg(test)
// synthesis in `RequestContext::socket` is unreachable from
// integration tests in `tests/` by Rust language semantics —
// `socket_for_test` is the pub helper that mints the same stub-
// signed presence_token without the cfg(test) gate.
fn ctx_for_per_agent_socket(socket_path: PathBuf) -> RequestContext {
    let principal = PeerCredPrincipal::new(1001, 12345, socket_path);
    let peer = PeerCred {
        uid: 1001,
        pid: Some(12345),
    };
    RequestContext::socket_for_test(peer).with_peer_cred_principal(Some(principal))
}

// ---------------------------------------------------------------------------
// 1. test_rpc_on_agent_socket_uses_enrollment_not_wire
// ---------------------------------------------------------------------------

/// Enroll persona P for agent socket S; RPC on S with payload that
/// claims a DIFFERENT persona Q resolves to P, not Q.
///
/// Exercised via the `delegate_grant` arm because it inspects
/// `params["caller_persona_id"]` directly: if the dispatch layer
/// overrides that field with the enrolled persona, the handler will
/// see the enrolled value and either match or mismatch the parent
/// grant's owner accordingly. Concretely: P owns the parent grant;
/// the wire payload names Q (a different persona) as
/// `caller_persona_id`. Without the per-socket enrollment override,
/// the request would refuse "caller does not own parent grant". With
/// the override, dispatch silently rewrites the field to P and the
/// delegation succeeds.
#[tokio::test]
async fn test_rpc_on_agent_socket_uses_enrollment_not_wire() {
    let _id = ensure_test_identity();
    let store = store_with_vault();
    let policy = test_policy();
    let rl = test_rl();
    let vault = test_vault();

    // Mint persona P (the enrolled-on-socket persona) + child Q.
    let persona_p = store.create_persona("persona-P").expect("create P");
    let persona_q = store.create_persona("persona-Q").expect("create Q");

    // Mint a parent grant owned by P so delegate_grant has a non-trivial
    // ownership check to apply.
    let parent_grant = store
        .create_grant(&persona_p.id, "test-cred", "read", Some(3600))
        .expect("create parent grant");
    // `create_grant` leaves `max_delegation_depth = NULL`, which
    // forces every child delegation to refuse with "parent does not
    // allow delegation". The dispatch-layer behaviour under test is
    // upstream of that refusal — we want to assert the principal
    // override fires before the depth check runs — so patch the
    // column directly to >=1 so the depth gate is permissive.
    store
        .conn()
        .execute(
            "UPDATE grants SET max_delegation_depth = 3 WHERE id = ?1",
            params![parent_grant.id],
        )
        .expect("patch max_delegation_depth");

    // Build a per-agent socket path under the tempdir; record the
    // enrollment so dispatch resolves the socket → P.
    let tmp = tempfile::tempdir().expect("tempdir for sockets");
    let socket_path = tmp.path().join("agent-aaaaaaaa.sock");
    store
        .record_agent_socket_enrollment(
            socket_path.to_str().unwrap(),
            &persona_p.id,
            &parent_grant.id,
            "blake3:test-brief-hash-aaaa",
            None,
            None,
            None,
        )
        .expect("record enrollment");

    // Build the RequestContext that wears the per-agent socket path.
    let ctx = ctx_for_per_agent_socket(socket_path.clone());

    // Wire payload deliberately claims Q's identity. If the
    // enrollment override did not fire, delegate_grant would compare
    // Q against P (parent's owner) and refuse with -32002. With the
    // override, dispatch rewrites caller_persona_id to P, ownership
    // check passes, and the delegation succeeds.
    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "delegate_grant",
        &json!({
            "parent_grant_id": parent_grant.id,
            "child_persona_id": persona_q.id,
            "scope": "read",
            "ttl_secs": 1800u64,
            "caller_persona_id": persona_q.id,
        }),
    )
    .await;

    assert!(
        result.is_ok(),
        "delegate_grant must succeed when the enrollment-derived persona owns the parent grant, \
         even though the wire payload named a different persona; got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. test_rpc_on_unenrolled_socket_refused
// ---------------------------------------------------------------------------

/// RPC on a socket path that matches the per-agent shape but has no
/// enrollment row → `HandlerError::PrincipalNotEnrolled` (JSON-RPC
/// code `-32401`).
#[tokio::test]
async fn test_rpc_on_unenrolled_socket_refused() {
    let _id = ensure_test_identity();
    let store = store_with_vault();
    let policy = test_policy();
    let rl = test_rl();
    let vault = test_vault();

    let tmp = tempfile::tempdir().expect("tempdir for sockets");
    let socket_path = tmp.path().join("agent-bbbbbbbb.sock");
    // No record_agent_socket_enrollment call — the socket has the
    // per-agent shape but is not enrolled.

    let ctx = ctx_for_per_agent_socket(socket_path.clone());

    // Use a low-risk method (`ping`) so the test isolates the
    // enrollment gate from downstream handler logic.
    let result =
        dispatch_method_with_context(&store, &vault, &policy, &rl, None, ctx, "ping", &json!({}))
            .await;

    let (code, msg) = result.expect_err("RPC on unenrolled per-agent socket must refuse");
    assert_eq!(
        code,
        HandlerError::PrincipalNotEnrolled.to_jsonrpc().0,
        "expected PrincipalNotEnrolled JSON-RPC code, got {code}: {msg}"
    );
}

// ---------------------------------------------------------------------------
// 3. test_worker_b_cannot_impersonate_orchestrator
// ---------------------------------------------------------------------------

/// Enroll orchestrator O on socket S_o; enroll worker B on socket S_b.
/// A `delegate_grant` RPC arriving on S_b that claims O's grant_id is
/// refused, because dispatch resolves the principal from S_b's
/// enrollment (B) — not from the payload — and B does not own O's
/// parent grant.
#[tokio::test]
async fn test_worker_b_cannot_impersonate_orchestrator() {
    let _id = ensure_test_identity();
    let store = store_with_vault();
    let policy = test_policy();
    let rl = test_rl();
    let vault = test_vault();

    // Two personas, two parent grants, two sockets.
    let orchestrator = store.create_persona("orchestrator-O").expect("create O");
    let worker_b = store.create_persona("worker-B").expect("create B");
    let orch_grant = store
        .create_grant(&orchestrator.id, "test-cred", "read", Some(3600))
        .expect("create O's grant");
    let _b_grant = store
        .create_grant(&worker_b.id, "test-cred", "read", Some(3600))
        .expect("create B's grant");
    // Patch O's grant to allow delegation — otherwise delegate_grant
    // refuses with "parent does not allow delegation" before the
    // ownership gate fires, which would mask the impersonation
    // check under test.
    store
        .conn()
        .execute(
            "UPDATE grants SET max_delegation_depth = 3 WHERE id = ?1",
            params![orch_grant.id],
        )
        .expect("patch O's max_delegation_depth");

    let tmp = tempfile::tempdir().expect("tempdir for sockets");
    let socket_o = tmp.path().join("agent-cccccccc.sock");
    let socket_b = tmp.path().join("agent-dddddddd.sock");
    store
        .record_agent_socket_enrollment(
            socket_o.to_str().unwrap(),
            &orchestrator.id,
            &orch_grant.id,
            "blake3:orchestrator-brief",
            None,
            None,
            None,
        )
        .expect("enroll O");
    store
        .record_agent_socket_enrollment(
            socket_b.to_str().unwrap(),
            &worker_b.id,
            &_b_grant.id,
            "blake3:worker-b-brief",
            None,
            None,
            None,
        )
        .expect("enroll B");

    // Build a delegate_grant RPC arriving on B's socket but claiming
    // O's grant_id. Without per-socket enrollment override the
    // request would proceed under O's identity (impersonation); with
    // the override, dispatch rewrites caller_persona_id to B, which
    // does not own O's grant, and the request is refused.
    let target_child = store.create_persona("target-child").expect("create target");
    let ctx = ctx_for_per_agent_socket(socket_b.clone());

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "delegate_grant",
        &json!({
            // Forged: claim the orchestrator's grant_id.
            "parent_grant_id": orch_grant.id,
            "child_persona_id": target_child.id,
            "scope": "read",
            "ttl_secs": 1800u64,
            // Forged: claim to be the orchestrator.
            "caller_persona_id": orchestrator.id,
        }),
    )
    .await;

    let (code, msg) = result.expect_err(
        "worker B must NOT be able to delegate against the orchestrator's grant by forging caller_persona_id",
    );
    assert_eq!(
        code, -32002,
        "expected ownership-refusal -32002, got {code}: {msg}"
    );
    assert!(
        msg.contains("does not own parent grant"),
        "error must name the ownership violation, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// 4. test_revoked_enrollment_refuses_rpcs
// ---------------------------------------------------------------------------

/// Enroll persona P for socket S, then revoke the enrollment. Any
/// subsequent RPC on S → `PrincipalNotEnrolled`. The row stays in
/// the table (state='revoked') so post-mortem audits can see the
/// tombstone, but lookups filter on `state='active'`.
#[tokio::test]
async fn test_revoked_enrollment_refuses_rpcs() {
    let _id = ensure_test_identity();
    let store = store_with_vault();
    let policy = test_policy();
    let rl = test_rl();
    let vault = test_vault();

    let persona = store
        .create_persona("persona-revoked")
        .expect("create persona");
    let grant = store
        .create_grant(&persona.id, "test-cred", "read", Some(3600))
        .expect("create grant");

    let tmp = tempfile::tempdir().expect("tempdir for sockets");
    let socket_path = tmp.path().join("agent-eeeeeeee.sock");
    store
        .record_agent_socket_enrollment(
            socket_path.to_str().unwrap(),
            &persona.id,
            &grant.id,
            "blake3:revoked-brief",
            None,
            None,
            None,
        )
        .expect("record enrollment");

    // Sanity: the helper resolves before revoke.
    let resolved =
        enroll_container_persona(&store, &socket_path).expect("enrollment resolves before revoke");
    assert_eq!(
        resolved,
        EnrolledPrincipal {
            persona_id: persona.id.clone(),
            grant_id: grant.id.clone(),
            brief_content_hash: "blake3:revoked-brief".to_string(),
        }
    );

    // Revoke the enrollment.
    store
        .revoke_agent_socket_enrollment(socket_path.to_str().unwrap())
        .expect("revoke enrollment");

    // After revoke, the helper refuses.
    let err = enroll_container_persona(&store, &socket_path)
        .expect_err("revoked enrollment must not resolve");
    assert_eq!(err, HandlerError::PrincipalNotEnrolled);

    // After revoke, dispatch refuses RPCs on the socket.
    let ctx = ctx_for_per_agent_socket(socket_path.clone());
    let result =
        dispatch_method_with_context(&store, &vault, &policy, &rl, None, ctx, "ping", &json!({}))
            .await;
    let (code, msg) = result.expect_err("RPC on revoked socket must refuse");
    assert_eq!(
        code,
        HandlerError::PrincipalNotEnrolled.to_jsonrpc().0,
        "expected PrincipalNotEnrolled JSON-RPC code, got {code}: {msg}"
    );
}
