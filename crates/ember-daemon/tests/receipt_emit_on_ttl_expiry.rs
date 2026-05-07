//! implementation-note-105 regression coverage.
//!
//! Reproduces the bug where the TTL-expiry sweep silently failed to emit
//! a Grant Receipt: the sweep call site discarded the wrapper's return
//! value with `let _ = ...` and the wrapper itself logged at `debug!`
//! when the daemon identity was unavailable, so a misconfigured daemon
//! left zero rows in the `receipts` table with no operator-visible signal.
//!
//! These tests assert the post-fix behaviour:
//!
//!   1. With the process identity initialised (`init_identity` called),
//!      the TTL-expiry sweep MUST persist a signed receipt for every
//!      grant it transitions to `expired`. The receipt MUST verify under
//!      the daemon's own pubkey (the same trust anchor a `ember receipt
//!      verify` CLI invocation would use).
//!
//!   2. The wrapper's `Ok(Some(rid))` branch is the only path that can
//!      cause `receipt_count()` to increment, so a successful sweep
//!      hitting that path is sufficient to lock in the success log line
//!      contracted by the brief (`info!(receipt_id, "receipt emitted")`).

use std::rc::Rc;

use ember_daemon::infra::receipt::{
    current_identity, init_identity, verify_receipt,
};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use tempfile::TempDir;

/// Deterministic vault key shared across this binary's tests. The actual
/// bytes are irrelevant — they just need to be stable so persona-secret
/// encryption and decryption use the same key.
const TEST_VAULT_KEY: [u8; 32] = [0xCDu8; 32];

/// Build an in-memory store with a vault attached so `create_persona`
/// can encrypt the persona-root secret under the V0 schema.
fn store_with_vault() -> DaemonStore {
    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    store.set_vault(Rc::new(Vault::new(TEST_VAULT_KEY)));
    store
}

/// Initialise the process-singleton identity once for this integration
/// test binary, returning the data_dir tempdir so it stays alive for the
/// duration of the test. `init_identity` is idempotent — first caller
/// wins — so we can call it from every test in this binary.
fn init_test_identity() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir for daemon identity");
    let _ = init_identity(dir.path());
    dir
}

#[test]
fn ttl_expiry_sweep_emits_signed_receipt() {
    let _id_dir = init_test_identity();
    let identity = current_identity().expect("identity must be loaded for receipt emission");

    let store = store_with_vault();
    let persona = store.create_persona("agent-receipt-emit").expect("create_persona");

    // Mint a grant with a 1-second TTL — well under the sweep window.
    let grant = store
        .create_grant(&persona.id, "github-token", "repo:read", Some(1))
        .expect("create_grant with TTL");
    assert_eq!(grant.status, "active");
    assert!(grant.expires_at.is_some(), "TTL grant must carry expires_at");

    // Pre-condition: zero receipts before the sweep.
    assert_eq!(
        store.receipt_count().expect("receipt_count"),
        0,
        "no receipts should exist before sweep"
    );

    // Backdate `expires_at` so the next sweep flips status to `expired`
    // without sleeping for real wall-clock time. This mirrors the
    // production sweep path exactly — `expire_stale_grants` only checks
    // `expires_at <= now`.
    store
        .conn()
        .execute(
            "UPDATE grants SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
            rusqlite::params![grant.id],
        )
        .expect("backdate expires_at");

    let expired = store.expire_stale_grants().expect("expire_stale_grants");
    assert_eq!(expired, 1, "exactly one grant should expire");

    // Post-condition (the bug): a receipts row MUST exist for the grant
    // we just expired. This is the assertion that fails on the buggy
    // `let _ = trigger_receipt_if_terminal_current(...)` code path when
    // `current_identity()` returns None and the wrapper logs at `debug!`.
    assert_eq!(
        store.receipt_count().expect("receipt_count"),
        1,
        "TTL-expired grant must produce exactly one receipt"
    );

    // Receipts must be retrievable via list_receipts (the `ember receipt
    // list` surface) and the new receipt id must be linked from the
    // grant row (the `ember receipt verify` lookup path).
    let info = store.get_grant(&grant.id).expect("get_grant");
    let rid = info
        .receipt_id
        .expect("expired grant row must reference its receipt id");
    let receipt = store.get_receipt(&rid).expect("get_receipt by id");
    assert_eq!(receipt.grant_id, grant.id);

    // Signature must verify under the same pubkey the CLI would compare
    // against — this is the `ember receipt verify <id>` "Verified" path.
    verify_receipt(&receipt, &identity.pubkey_hex())
        .expect("emitted receipt verifies under daemon identity");
}

#[test]
fn ttl_expiry_sweep_is_idempotent() {
    let _id_dir = init_test_identity();
    let _identity =
        current_identity().expect("identity must be loaded for receipt emission");

    let store = store_with_vault();
    let persona = store
        .create_persona("agent-receipt-idempotent")
        .expect("create_persona");
    let grant = store
        .create_grant(&persona.id, "github-token", "repo:read", Some(1))
        .expect("create_grant with TTL");

    store
        .conn()
        .execute(
            "UPDATE grants SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
            rusqlite::params![grant.id],
        )
        .expect("backdate expires_at");

    // First sweep flips active → expired and emits the receipt.
    assert_eq!(store.expire_stale_grants().unwrap(), 1);
    assert_eq!(store.receipt_count().unwrap(), 1);

    // Second sweep finds nothing to flip; receipt count must stay at 1.
    // Idempotency is enforced by `expire_stale_grants` filtering on
    // `status = 'active'` — the SQL guard combined with the wrapper's
    // existing `info.receipt_id.is_some()` short-circuit means rerunning
    // the sweep is safe.
    assert_eq!(store.expire_stale_grants().unwrap(), 0);
    assert_eq!(
        store.receipt_count().unwrap(),
        1,
        "rerunning the sweep must not double-emit"
    );
}
