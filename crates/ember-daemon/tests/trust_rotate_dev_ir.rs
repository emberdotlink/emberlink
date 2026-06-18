//! T2 integration tests for the dev-IR rotation handlers
//! (META-TRUST-ROTATE-DEV-IR, ADR 162 §Component 3).
//!
//! Exercises the JSON-RPC handler entry points directly against the
//! daemon's process-global rotation registry. Skips the full socket
//! round-trip — covered separately by the daemon-startup integration
//! tests — but proves the end-to-end shape: register → status → expire
//! → snapshot evict.

use ember_daemon::binary_manifest::{TrustRootRecord, TrustRootSource};
use ember_daemon::trust::rotation::{
    DEFAULT_GRACE_WINDOW_SECS, clear_registry_for_test, evict_from_trust_root_snapshot,
    expire_rotation, handle_trust_rotate_dev_ir, handle_trust_rotation_status,
    set_clock_for_test,
};
use serde_json::{Value, json};

fn fp(byte: u8) -> String {
    let mut s = String::with_capacity(64);
    for _ in 0..32 {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// Full round-trip: register the rotation via `handle_trust_rotate_dev_ir`,
/// surface it through `handle_trust_rotation_status`, then expire it +
/// verify the snapshot drops the old root.
#[test]
fn trust_rotate_dev_ir_round_trip_register_status_expire() {
    let _guard = ember_daemon::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    clear_registry_for_test();
    set_clock_for_test(Some(2_000_000));

    // Seed snapshot: old root + a release root. Rotation should leave
    // the release root alone and evict the old dev root once expire +
    // evict run.
    let old_fp = fp(0xAA);
    let new_fp = fp(0xBB);
    let release_fp = fp(0xCC);
    ember_daemon::binary_manifest::set_trust_roots_snapshot(vec![
        TrustRootRecord {
            fingerprint_hex: release_fp.clone(),
            source: TrustRootSource::Release,
        },
        TrustRootRecord {
            fingerprint_hex: old_fp.clone(),
            source: TrustRootSource::Operator,
        },
    ]);

    // 1. Register the rotation.
    let req = json!({
        "old_fingerprint_hex": &old_fp,
        "new_fingerprint_hex": &new_fp,
        "grace_window_secs": DEFAULT_GRACE_WINDOW_SECS,
        "reason": "integration-test rotation",
    });
    let resp = handle_trust_rotate_dev_ir(&req).expect("register must succeed");
    assert_eq!(resp["old_fingerprint_hex"], old_fp);
    assert_eq!(resp["new_fingerprint_hex"], new_fp);
    assert_eq!(
        resp["grace_window_end_secs"].as_u64().unwrap(),
        2_000_000 + DEFAULT_GRACE_WINDOW_SECS
    );

    // 2. Status surface shows the in-flight rotation + both roots
    //    still in the snapshot.
    let status = handle_trust_rotation_status(&Value::Null).expect("status must succeed");
    let in_flight = status["in_flight"].as_array().unwrap();
    assert_eq!(in_flight.len(), 1);
    assert_eq!(in_flight[0]["old_fingerprint_hex"], old_fp);
    let roots = status["trust_roots"].as_array().unwrap();
    assert_eq!(roots.len(), 2);
    assert!(roots.iter().any(|r| r["fingerprint_hex"] == release_fp));
    assert!(roots.iter().any(|r| r["fingerprint_hex"] == old_fp));

    // 3. Expire the rotation + evict the old root.
    let expired = expire_rotation(&new_fp).expect("expire must succeed");
    assert_eq!(expired.old_fingerprint_hex, old_fp);
    let did_evict = evict_from_trust_root_snapshot(&old_fp);
    assert!(did_evict, "snapshot must drop the old fingerprint");

    // 4. Post-expiry status: registry empty + snapshot has only the
    //    release root left.
    let status = handle_trust_rotation_status(&Value::Null).expect("status must succeed");
    assert!(status["in_flight"].as_array().unwrap().is_empty());
    let roots = status["trust_roots"].as_array().unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0]["fingerprint_hex"], release_fp);
}

/// Re-registering the same (old, new) pair should fail with a stable
/// duplicate error so a re-running CLI can detect the prior partial
/// rotation cleanly.
#[test]
fn trust_rotate_dev_ir_duplicate_is_rejected_with_stable_code() {
    let _guard = ember_daemon::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    clear_registry_for_test();
    set_clock_for_test(Some(2_000_000));

    let req = json!({
        "old_fingerprint_hex": fp(0x11),
        "new_fingerprint_hex": fp(0x22),
    });
    handle_trust_rotate_dev_ir(&req).expect("first register must succeed");

    let err = handle_trust_rotate_dev_ir(&req).expect_err("second register must fail");
    assert_eq!(err.0, -32004, "duplicate must surface stable not-found code");
    assert!(err.1.contains("rotation already in flight"));
}

/// `trust.rotate_dev_ir` request body MUST require both fingerprints —
/// missing `old_fingerprint_hex` should fail with -32602 invalid-params.
#[test]
fn trust_rotate_dev_ir_missing_old_fingerprint_returns_invalid_params() {
    let _guard = ember_daemon::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    clear_registry_for_test();

    let req = json!({
        "new_fingerprint_hex": fp(0x22),
    });
    let err = handle_trust_rotate_dev_ir(&req).expect_err("missing old must fail");
    assert_eq!(err.0, -32602);
    assert!(err.1.contains("old_fingerprint_hex"));
}
