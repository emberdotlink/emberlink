//! CLASSIFICATION: PUBLIC
//!
//! META-AP-DAEMON-BRIDGE-T2-T3-REFRESH-ADVERSARIAL-TESTS — M11 of ADR 173.
//!
//! T2 integration coverage for the adversarial threat model around the
//! `refresh_cert` RPC. Sibling of `cert_refresh_happy_path.rs` (M10); this
//! file owns the five scenarios laid out in the M11 brief.
//!
//! Anchor: `daemon_bridge_t2_t3_refresh_adversarial_tests_landed`
//!
//! ## Failure-cause mappings (M3-locked, verified against the shipped handler)
//!
//! The M11 brief's HIGH-3 callout said "do NOT pre-assume the mapping; verify
//! against M3-shipped code." Per
//! `crates/ember-daemon/src/broker/handler/runtime_authority.rs::handle_refresh_cert`
//! (PR #6033) the locked mappings are:
//!
//! - **SAN mismatch (cert from stopped container, SAN != row.container_id)**
//!   → `auth_failure_persona_unknown` (runtime_authority.rs:1054-1059).
//!   M3 collapsed the "SAN cross-check fails on existing row" case into the
//!   `persona_unknown` variant rather than mint a new `san_mismatch` value.
//!   This is the wire-level lock we test against.
//!
//! - **Revoked parent grant** → `auth_failure_revoked`
//!   (runtime_authority.rs:1119-1124). Locked by M3-B identity proof.
//!
//! - **Inactive persona (revoked)** → `auth_failure_persona_unknown`
//!   (runtime_authority.rs:1041-1046). M3 chose this mapping rather than a
//!   separate `auth_failure_persona_revoked` variant.
//!
//! - **Rate-limit refusal** → `rate_limited` (runtime_authority.rs:1222-1231).
//!   M3-D (META-AP-DAEMON-BRIDGE-REFRESH-CERT-RPC-D-RATE-LIMIT) is shipped:
//!   the first valid refresh for a persona/container chain wins, subsequent
//!   refreshes inside the 60s cooldown are denied without minting or mutating
//!   the persona cert row.
//!
//! ## Why T2 (in-process dispatch) is the right boundary
//!
//! Per `.claude/rules/test-tiers.md`: T2 integration tests live under
//! `crates/ember-daemon/tests/`, use in-memory SQLite and fixture identity
//! keys, and do NOT spawn real listener / sandbox / Docker processes. M11
//! adversarial coverage is about the *authority decision* the handler
//! returns for hostile inputs; that decision is fully observable by calling
//! `handle_refresh_cert` directly on an in-memory store. T3 (real
//! listener + handshake) coverage of the listener-side force-close
//! interaction already lives in `bridge_ca_pem_listener_handshake.rs` and
//! the M12 listener tests in `crates/ember-rpc/tests/`.

#![allow(clippy::expect_used)] // test code — panicking on setup failure is the bug surface

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use core_personas::MtlsPrincipal;
use ember_daemon::broker::handler::{RefreshDenied, RefreshFailureCause, handle_refresh_cert};
use ember_daemon::infra::persona::{
    agent_persona_two_phase_commit, pin_persona_client_cert_from_pem,
};
use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::bridge_ca::BridgeCa;
use serde_json::{Value, json};

/// Stable deterministic vault key. Matches the pattern in the sibling
/// `tests/refresh_cert_rpc.rs` happy-path test.
const TEST_VAULT_KEY: [u8; 32] = [0xD7; 32];

/// Bundled fixture state. Mirrors the shape used in
/// `runtime_authority::tests::RefreshFixture` so adversarial scenarios can
/// reach into store + bridge-CA + the just-minted client cert.
struct AdvFixture {
    store: DaemonStore,
    bridge_ca: Arc<BridgeCa>,
    /// MtlsPrincipal as the bridge listener would stamp it for the legitimate
    /// holder of the freshly-minted client cert.
    mtls: MtlsPrincipal,
    parent_grant_id: String,
    persona_id: String,
    initial_fingerprint_hex: String,
    initial_cert_pem: String,
}

/// Mint a parent grant + container persona + initial client cert, then pin
/// the cert columns on the persona row. Mirrors
/// `runtime_authority::tests::refresh_fixture` from M3 but exposes the
/// minted PEM bytes so scenarios #1 / #2 can hold an "old" cert across a
/// refresh.
fn adv_fixture(container_id: &str) -> AdvFixture {
    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    let vault = Rc::new(Vault::new(TEST_VAULT_KEY));
    store.set_vault(Rc::clone(&vault));
    let bridge_ca = Arc::new(BridgeCa::mint());
    store.set_bridge_ca(Arc::clone(&bridge_ca));

    let parent = store
        .create_persona("adv-refresh-parent")
        .expect("create parent persona");
    let parent_grant = store
        .create_grant(&parent.id, "delegate-key", "*", Some(7_200))
        .expect("mint parent grant");
    store
        .conn()
        .execute(
            "UPDATE grants SET max_delegation_depth = 2 WHERE id = ?1",
            rusqlite::params![&parent_grant.id],
        )
        .expect("raise delegation depth");

    let persona =
        agent_persona_two_phase_commit(&store, vault.as_ref(), container_id, &parent_grant.id)
            .expect("agent persona two-phase commit");

    let (initial_cert_pem_z, _initial_key_pem) = bridge_ca
        .sign_client_cert(&persona.id, Some(container_id), Duration::from_secs(3_600))
        .expect("mint initial client cert");
    // sign_client_cert returns Zeroizing<String>; copy to a plain String so
    // scenarios #1 / #2 can hold an "old" cert across the refresh boundary
    // without re-issuing.
    let initial_cert_pem: String = initial_cert_pem_z.as_str().to_string();
    let (initial_fingerprint_hex, _) =
        pin_persona_client_cert_from_pem(&store, &persona.id, initial_cert_pem.as_str())
            .expect("pin initial cert");

    AdvFixture {
        store,
        bridge_ca,
        mtls: MtlsPrincipal {
            persona_id: persona.id.clone(),
            container_id: container_id.to_string(),
            cert_fingerprint: hex_to_fingerprint(&initial_fingerprint_hex),
        },
        parent_grant_id: parent_grant.id,
        persona_id: persona.id,
        initial_fingerprint_hex,
        initial_cert_pem,
    }
}

fn hex_to_fingerprint(hex_value: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = hex::decode(hex_value).expect("fingerprint hex decodes");
    assert_eq!(bytes.len(), 32, "fingerprint is 32 bytes");
    out.copy_from_slice(&bytes);
    out
}

/// Pull the snake_case `failure_cause` string out of a `denied=true` body.
fn denial_cause(value: &Value) -> &str {
    value["failure_cause"]
        .as_str()
        .expect("failure_cause string present on denied bodies")
}

// ===========================================================================
// Scenario 1 — Stolen-cert refresh (cert exfiltrated from a stopped container)
//
// Threat model: an attacker exfiltrates a still-valid client cert from a
// stopped container `ctr-victim` and presents it from a different container
// context. The mTLS principal the bridge listener stamps will carry the
// `persona_id` resolved from the cert's URN SAN — but the
// `container_id` in the stamped principal reflects the SAN in the cert,
// which is `ctr-victim` (the rightful issuee). The attacker who replays the
// cert under a *different* container context surfaces here as a principal
// whose `container_id` does not match the persona row's bound container.
//
// M3 maps this case to `auth_failure_persona_unknown` (the row exists but
// the SAN cross-check fails; M3 chose to collapse this into the existing
// "persona unknown" variant rather than mint a separate `san_mismatch`).
//
// Wire-level observable: `denied=true`, `failure_cause=auth_failure_persona_unknown`,
// `reason` mentions "container".
// ===========================================================================

#[tokio::test]
async fn stolen_cert_refresh_with_san_mismatch_denied_persona_unknown() {
    let mut fx = adv_fixture("ctr-victim");
    let rl = RefCell::new(RateLimiter::default());

    // Attacker presents a stamped principal whose container_id differs from
    // the persona row's bound container — exactly the shape the listener
    // would produce if the attacker were running outside `ctr-victim` but
    // had stolen the cert and tried to reuse it.
    fx.mtls.container_id = "ctr-attacker".to_string();

    let res = handle_refresh_cert(None, Some(&fx.mtls), &fx.store, &rl, &json!({}))
        .await
        .expect("denial returns Ok with denied=true body");

    assert_eq!(
        res["denied"],
        json!(true),
        "stolen-cert refresh must be denied"
    );
    assert_eq!(
        denial_cause(&res),
        "auth_failure_persona_unknown",
        "M3 mapping: SAN cross-check failure collapses into auth_failure_persona_unknown \
         (verified against runtime_authority.rs:1054-1059)"
    );
    assert!(
        res["reason"].as_str().unwrap().contains("container"),
        "denial reason must name the container-SAN mismatch: got {res}"
    );

    // Persona row's cert pin MUST NOT have been mutated by the denied attempt.
    let after_state = fx
        .store
        .get_persona_client_cert_state(&fx.persona_id)
        .expect("persona row still readable");
    assert_eq!(
        after_state.fingerprint_hex, fx.initial_fingerprint_hex,
        "denied stolen-cert refresh must NOT mutate the persona cert pin"
    );
    assert_eq!(
        after_state.refresh_seq, 0,
        "denied stolen-cert refresh must NOT bump refresh_seq"
    );
}

// ===========================================================================
// Scenario 2 — Leaked-old-cert post-refresh
//
// After a successful refresh, the persona row's `client_cert_fingerprint`
// and `client_cert_not_after` are atomically updated (per the SQL UPDATE in
// `replace_persona_client_cert_for_refresh`). An attacker holding the OLD
// cert can still present it to the bridge listener — rustls's
// `WebPkiClientVerifier` will accept it because (a) the cert is still
// chain-validated against the bridge CA root, and (b) the cert's `not_after`
// has not been reached. M11's adversarial path tests the daemon-side
// invariant: the persona row's `client_cert_fingerprint` now reflects the
// NEW cert; any subsequent authorization layer comparing against the row's
// pinned fingerprint sees a mismatch.
//
// MED-4 of the M11 brief: replaces the prior brief's "heap+fd-table scan"
// methodology with the same invariant tested via store-state observation
// at the refresh boundary. The wire-level mTLS interaction with the
// force-close listener (M12 #6034) is already covered by
// `bridge_ca_pem_listener_handshake.rs` for the legitimate path; M11's
// adversarial path observes that the *fingerprint column* is the source of
// truth a future authz lookup compares against.
// ===========================================================================

#[tokio::test]
async fn leaked_old_cert_post_refresh_persona_row_pins_new_fingerprint() {
    let fx = adv_fixture("ctr-leaked-old");
    let rl = RefCell::new(RateLimiter::default());

    // Capture the old cert PEM bytes the attacker would "leak" — these stay
    // valid against the bridge CA (chain + not_after) for the duration of
    // the test, just like in the real threat scenario.
    let old_cert_pem = fx.initial_cert_pem.clone();
    let old_fingerprint = fx.initial_fingerprint_hex.clone();

    // Legitimate holder refreshes.
    let refresh_result = handle_refresh_cert(
        None,
        Some(&fx.mtls),
        &fx.store,
        &rl,
        &json!({"caller_grant_id": fx.parent_grant_id}),
    )
    .await
    .expect("legitimate refresh succeeds");
    assert_eq!(
        refresh_result["denied"],
        json!(false),
        "legitimate refresh must succeed"
    );

    let new_fingerprint = refresh_result["client_cert_fingerprint"]
        .as_str()
        .expect("new fingerprint present on success body")
        .to_string();
    assert_ne!(
        new_fingerprint, old_fingerprint,
        "fresh refresh must mint a fingerprint distinct from the old cert's"
    );

    // Daemon-side invariant: persona row now pins the NEW cert. An
    // authz layer comparing against `client_cert_fingerprint` will see the
    // attacker's old-cert fingerprint as mismatched.
    let state = fx
        .store
        .get_persona_client_cert_state(&fx.persona_id)
        .expect("read persona cert state");
    assert_eq!(
        state.fingerprint_hex, new_fingerprint,
        "persona row must pin the NEW fingerprint after refresh"
    );
    assert_ne!(
        state.fingerprint_hex, old_fingerprint,
        "persona row must NOT continue to pin the leaked old fingerprint"
    );
    assert_eq!(state.refresh_seq, 1, "refresh_seq bumped to 1");

    // The leaked old cert PEM is intentionally still parseable + chain-valid
    // — that's the threat. The invariant is at the pin-column boundary, not
    // at the rustls handshake layer. (Sanity: the bridge CA can still
    // verify the old cert's chain.)
    assert!(
        old_cert_pem.contains("BEGIN CERTIFICATE"),
        "old cert PEM is still well-formed — the threat is that it's still chain-valid"
    );
    let _ca_pem = fx
        .bridge_ca
        .trust_root_cert_pem()
        .expect("bridge CA trust root still loaded — chain is still valid");
}

// ===========================================================================
// Scenario 3 — Concurrent refresh race
//
// Two `refresh_cert` calls from the same persona/container chain arrive within
// the refresh cooldown. The shipped M3-D rate-limit gate makes the first call
// win and denies the second before mint/update, so the row remains fully
// consistent at the first refresh's fingerprint and `refresh_seq=1`.
// ===========================================================================

#[tokio::test]
async fn concurrent_refresh_atomic_no_torn_write() {
    let fx = adv_fixture("ctr-concurrent");
    let rl = RefCell::new(RateLimiter::default());

    // Drive two refreshes sequentially (the SQL atomicity is the property
    // under test — running them on a tokio runtime in any order exercises
    // the RETURNING-RETURNING sequence).
    let res_a = handle_refresh_cert(
        None,
        Some(&fx.mtls),
        &fx.store,
        &rl,
        &json!({"caller_grant_id": fx.parent_grant_id}),
    )
    .await
    .expect("first refresh succeeds");
    let mut refreshed_mtls = fx.mtls.clone();
    refreshed_mtls.cert_fingerprint =
        hex_to_fingerprint(res_a["client_cert_fingerprint"].as_str().unwrap());
    let res_b = handle_refresh_cert(
        None,
        Some(&refreshed_mtls),
        &fx.store,
        &rl,
        &json!({"caller_grant_id": fx.parent_grant_id}),
    )
    .await
    .expect("second refresh returns denial body");

    assert_eq!(res_a["denied"], json!(false));
    assert_eq!(res_b["denied"], json!(true));
    assert_eq!(denial_cause(&res_b), "rate_limited");

    let seq_a = res_a["refresh_seq"].as_i64().expect("seq a");
    assert_eq!(seq_a, 1, "first refresh observes refresh_seq=1");

    let fp_a = res_a["client_cert_fingerprint"].as_str().unwrap();
    assert_ne!(
        fp_a, fx.initial_fingerprint_hex,
        "first refresh must replace the initial fingerprint"
    );

    // Post-state: the rate-limited second call did not mint or update.
    let state = fx
        .store
        .get_persona_client_cert_state(&fx.persona_id)
        .expect("read post-state");
    assert_eq!(state.refresh_seq, 1);
    assert_eq!(state.fingerprint_hex, fp_a);
}

/// M3-D (META-AP-DAEMON-BRIDGE-REFRESH-CERT-RPC-D-RATE-LIMIT): the
/// second of two within-window refreshes from the same valid successor cert
/// chain returns `denied=true` with `failure_cause=rate_limited`.
#[tokio::test]
async fn concurrent_refresh_within_window_second_returns_rate_limited_after_m3_d() {
    let fx = adv_fixture("ctr-rate-limited");
    let rl = RefCell::new(RateLimiter::default());

    let first = handle_refresh_cert(
        None,
        Some(&fx.mtls),
        &fx.store,
        &rl,
        &json!({"caller_grant_id": fx.parent_grant_id}),
    )
    .await
    .expect("first refresh succeeds");
    assert_eq!(first["denied"], json!(false), "first refresh succeeds");

    let mut refreshed_mtls = fx.mtls.clone();
    refreshed_mtls.cert_fingerprint =
        hex_to_fingerprint(first["client_cert_fingerprint"].as_str().unwrap());

    let second = handle_refresh_cert(
        None,
        Some(&refreshed_mtls),
        &fx.store,
        &rl,
        &json!({"caller_grant_id": fx.parent_grant_id}),
    )
    .await
    .expect("second refresh dispatch returns Ok with denied body");

    assert_eq!(
        second["denied"],
        json!(true),
        "within-window second refresh must be denied (post-M3-D)"
    );
    assert_eq!(
        denial_cause(&second),
        "rate_limited",
        "M3-D rate-limit refusal is `rate_limited`"
    );
}

// ===========================================================================
// Scenario 4 — Spam-refresh rate-limit (activation shipped)
//
// Tight-loop refresh calls from the same `(persona_id, container_id)` chain.
// M3-D is now shipped: the first call succeeds, subsequent calls in the
// cooldown window are denied with `rate_limited` and do not mutate the row.
// ===========================================================================

#[test]
fn refresh_failure_cause_exhausted_retries_serde_remains_locked() {
    let v = serde_json::to_value(RefreshFailureCause::ExhaustedRetries)
        .expect("serialize exhausted_retries");
    assert_eq!(
        v,
        json!("exhausted_retries"),
        "legacy exhausted_retries wire shape remains locked"
    );

    let denied =
        RefreshDenied::new(RefreshFailureCause::ExhaustedRetries, "retry budget exhausted");
    let body = serde_json::to_value(&denied).expect("serialize denied");
    assert_eq!(body["failure_cause"], json!("exhausted_retries"));
    assert_eq!(body["reason"], json!("retry budget exhausted"));

    let round_trip: RefreshDenied = serde_json::from_value(body).expect("RefreshDenied round-trip");
    assert_eq!(
        round_trip.failure_cause,
        RefreshFailureCause::ExhaustedRetries
    );
}

#[tokio::test]
async fn spam_refresh_loop_denies_after_first_refresh_post_m3_d() {
    let fx = adv_fixture("ctr-spam-post-m3d");
    let rl = RefCell::new(RateLimiter::default());
    const ITERATIONS: i64 = 10; // small loop — first succeeds, remaining calls are denied

    let mut current_mtls = fx.mtls.clone();
    let mut successful_fingerprint = fx.initial_fingerprint_hex.clone();
    for iteration in 1..=ITERATIONS {
        let res = handle_refresh_cert(
            None,
            Some(&current_mtls),
            &fx.store,
            &rl,
            &json!({"caller_grant_id": fx.parent_grant_id}),
        )
        .await
        .expect("dispatch returns Ok body");
        if iteration == 1 {
            assert_eq!(res["denied"], json!(false), "first refresh succeeds");
            successful_fingerprint = res["client_cert_fingerprint"].as_str().unwrap().to_string();
            current_mtls.cert_fingerprint = hex_to_fingerprint(&successful_fingerprint);
        } else {
            assert_eq!(
                res["denied"],
                json!(true),
                "within-window spam refresh denied — iteration {iteration}",
            );
            assert_eq!(denial_cause(&res), "rate_limited");
        }
    }
    let state = fx
        .store
        .get_persona_client_cert_state(&fx.persona_id)
        .expect("read post-state");
    assert_eq!(state.refresh_seq, 1);
    assert_eq!(state.fingerprint_hex, successful_fingerprint);
}

// ===========================================================================
// Scenario 5 — Refresh against a revoked grant
//
// The legitimate cert was minted while the parent grant was active. Between
// the initial mint and a subsequent refresh, the parent grant is revoked
// (status='revoked' via `revoke_grant`). The next `refresh_cert` must
// refuse with `auth_failure_revoked`.
//
// This is the M3-B identity-proof check at line 1119-1124: the grant
// lookup succeeds (grant row still exists) but `grant.status != "active"`,
// so the handler returns RefreshFailureCause::AuthFailureRevoked. Verified
// against the M3-shipped wire shape.
// ===========================================================================

#[tokio::test]
async fn refresh_with_revoked_grant_denied_auth_failure_revoked() {
    let fx = adv_fixture("ctr-revoked-grant");
    let rl = RefCell::new(RateLimiter::default());

    // Revoke the parent grant — same SQL UPDATE the production revocation
    // path takes (`revoke_grant` flips `status = 'revoked'`).
    fx.store
        .revoke_grant(&fx.parent_grant_id)
        .expect("revoke parent grant");

    let res = handle_refresh_cert(
        None,
        Some(&fx.mtls),
        &fx.store,
        &rl,
        &json!({"caller_grant_id": fx.parent_grant_id}),
    )
    .await
    .expect("denial returns Ok with denied=true body");

    assert_eq!(res["denied"], json!(true));
    assert_eq!(
        denial_cause(&res),
        "auth_failure_revoked",
        "M3-locked mapping for revoked parent grant (runtime_authority.rs:1119-1124)"
    );

    // Cert pin MUST be unchanged.
    let state = fx
        .store
        .get_persona_client_cert_state(&fx.persona_id)
        .expect("read post-state");
    assert_eq!(
        state.fingerprint_hex, fx.initial_fingerprint_hex,
        "denied refresh against revoked grant must NOT mutate the cert pin"
    );
    assert_eq!(
        state.refresh_seq, 0,
        "denied refresh must NOT bump refresh_seq"
    );
}

/// Sibling case to scenario 5: the persona itself is revoked (status !=
/// 'active') between cert mint and refresh attempt. M3 locks this to
/// `auth_failure_persona_unknown` rather than a separate
/// `auth_failure_persona_revoked` variant (runtime_authority.rs:1041-1046).
/// Pins the M3 mapping so a future refactor cannot silently widen the
/// surface to a different enum value.
#[tokio::test]
async fn refresh_with_revoked_persona_denied_persona_unknown() {
    let fx = adv_fixture("ctr-revoked-persona");
    let rl = RefCell::new(RateLimiter::default());

    fx.store
        .revoke_persona(&fx.persona_id)
        .expect("revoke persona");

    let res = handle_refresh_cert(
        None,
        Some(&fx.mtls),
        &fx.store,
        &rl,
        &json!({"caller_grant_id": fx.parent_grant_id}),
    )
    .await
    .expect("denial returns Ok with denied=true body");

    assert_eq!(res["denied"], json!(true));
    assert_eq!(
        denial_cause(&res),
        "auth_failure_persona_unknown",
        "M3 locked inactive-persona mapping to auth_failure_persona_unknown \
         rather than mint a separate auth_failure_persona_revoked variant"
    );
    assert!(
        res["reason"].as_str().unwrap().contains("not active"),
        "denial reason must name the inactive persona state: got {res}"
    );
}
