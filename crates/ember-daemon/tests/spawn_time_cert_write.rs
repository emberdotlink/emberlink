//! CLASSIFICATION: PUBLIC
//!
//! META-AP-DAEMON-BRIDGE-SPAWN-TIME-CERT-WRITE — T2 integration coverage
//! for ADR 173 CRIT-2: the spawn-enrollment path populates
//! `client_cert_fingerprint` + `client_cert_not_after` on the persona row.
//!
//! Before this fix, #3664 added the two columns but every fresh-spawned
//! row sat at empty-string fingerprint / zero not_after. The M3
//! `refresh_cert` 3-way grant-active / SPIFFE / cert-fingerprint check
//! cannot validate against an empty column, so the column has to be
//! pinned at spawn-enrollment time (this test) or surfaced as
//! `AuthFailurePersonaUnknown` at the refresh path (a follow-up M3 task).
//!
//! Acceptance asserted here (verbatim from the brief):
//!
//! 1. `pin_persona_client_cert_from_pem` populates both columns on the
//!    persona row at enrollment time.
//! 2. Fingerprint matches `blake3(cert_der)` hex-lower — the shape ADR
//!    173 §Component 2 §"Persona table columns" pins for the M3 refresh
//!    handler to compare against.
//! 3. `personas.client_cert_not_after` matches the cert's `not_after`
//!    field (Unix seconds).
//!
//! Anchor: `spawn_time_cert_write_landed`.
//!
//! Per `.claude/rules/test-tiers.md`, integration tests under `tests/`
//! always count as T2 regardless of what they spin up. There's no daemon
//! process, no socket, no Anthropic SDK — just a `TempDir`, a `Vault`,
//! the existing `load_or_mint_bridge_ca` helper, and the new
//! `pin_persona_client_cert_from_pem` helper this PR introduces.

use std::time::Duration;

use ember_daemon::infra::persona::{
    PinClientCertError, agent_persona_two_phase_commit, pin_persona_client_cert_from_pem,
};
use ember_daemon::infra::runtime::load_or_mint_bridge_ca;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use std::rc::Rc;
use tempfile::TempDir;
use x509_parser::prelude::FromDer;

/// Stable deterministic vault key. Matches the pattern used in
/// `tests/bridge_ca_persistence.rs`.
const TEST_VAULT_KEY: [u8; 32] = [0x42u8; 32];

/// Mint a parent grant suitable for the agent-persona two-phase commit.
/// Returns `(parent_persona_id, parent_grant_id)`. Mirrors the pattern in
/// `infra/persona.rs::tests::mint_delegatable_parent_grant`: create + then
/// raise the delegation depth so the two-phase commit's attenuation step
/// succeeds.
fn seed_parent_grant(store: &DaemonStore) -> (String, String) {
    let parent = store
        .create_persona("spawn-time-cert-write-parent")
        .expect("create parent persona");
    let grant = store
        .create_grant(&parent.id, "delegate-key", "*", Some(3_600))
        .expect("mint parent grant");
    store
        .conn()
        .execute(
            "UPDATE grants SET max_delegation_depth = 2 WHERE id = ?1",
            rusqlite::params![&grant.id],
        )
        .expect("raise parent grant delegation depth");
    (parent.id, grant.id)
}

/// AC-1 + AC-2 + AC-3: the spawn-time helper writes both columns with the
/// fingerprint + not_after values that match the freshly-minted cert.
#[test]
fn pin_persona_client_cert_from_pem_writes_both_columns() {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path();
    let vault = Rc::new(Vault::new(TEST_VAULT_KEY));

    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    store.set_vault(Rc::clone(&vault));

    // Mint a real Bridge CA against the on-disk data_dir + vault — same
    // path the production daemon walks at startup.
    let bridge_ca = load_or_mint_bridge_ca(data_dir, vault.as_ref()).expect("mint bridge CA");

    // Run the same two-phase commit `create_agent_persona` uses so the
    // persona row exists in `active` state before the cert is pinned.
    let (_parent_persona_id, parent_grant_id) = seed_parent_grant(&store);
    let persona = agent_persona_two_phase_commit(
        &store,
        vault.as_ref(),
        "ctr-spawn-cert-1",
        &parent_grant_id,
    )
    .expect("two-phase commit mints active persona");

    // Mint a real client cert against the Bridge CA. 1h TTL matches
    // `ISOLATED_BRIDGE_CLIENT_CERT_TTL` floor; the test cares about the
    // not_after value being non-zero and matching what the helper extracts,
    // not the exact duration.
    let (client_cert_pem, _client_key_pem) = bridge_ca
        .sign_client_cert(
            &persona.id,
            Some("ctr-spawn-cert-1"),
            Duration::from_secs(3_600),
        )
        .expect("sign client cert");

    // ── Pre-condition: persona row carries the default empty fingerprint
    // / zero not_after (the column-add migration in `store.rs` lands the
    // defaults; a fresh row has not been pinned yet).
    let (pre_fp, pre_na): (String, i64) = store
        .conn()
        .query_row(
            "SELECT client_cert_fingerprint, client_cert_not_after \
             FROM personas WHERE id = ?1",
            rusqlite::params![&persona.id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .expect("read fresh persona cert columns");
    assert_eq!(
        pre_fp, "",
        "fresh persona row must default to empty-string fingerprint"
    );
    assert_eq!(
        pre_na, 0,
        "fresh persona row must default to zero not_after"
    );

    // ── Act: pin the columns via the new spawn-time helper.
    let (returned_fp, returned_na) =
        pin_persona_client_cert_from_pem(&store, &persona.id, client_cert_pem.as_str())
            .expect("pin client cert columns");

    // ── AC-2: returned fingerprint is blake3(cert_der) hex-lower —
    // verify by re-deriving from the PEM contents.
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(client_cert_pem.as_bytes()).expect("PEM decodes");
    let expected_fp = hex::encode(blake3::hash(&pem.contents).as_bytes());
    assert_eq!(
        returned_fp, expected_fp,
        "helper return value must be blake3(DER) hex-lower"
    );

    // ── AC-3: returned not_after matches the cert's `not_after`.
    let (_, cert) =
        x509_parser::certificate::X509Certificate::from_der(&pem.contents).expect("DER decodes");
    let expected_na = cert.tbs_certificate.validity.not_after.timestamp();
    assert_eq!(
        returned_na, expected_na,
        "helper return value must equal the cert's `not_after` Unix seconds"
    );

    // ── AC-1: the persona row now carries the same values (the helper
    // performed the UPDATE, not just returned values).
    let (post_fp, post_na): (String, i64) = store
        .conn()
        .query_row(
            "SELECT client_cert_fingerprint, client_cert_not_after \
             FROM personas WHERE id = ?1",
            rusqlite::params![&persona.id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .expect("read pinned persona cert columns");
    assert_eq!(
        post_fp, expected_fp,
        "post-pin persona row fingerprint must match blake3(DER) hex"
    );
    assert_eq!(
        post_na, expected_na,
        "post-pin persona row not_after must match the cert"
    );
    assert!(
        !post_fp.is_empty(),
        "post-pin persona row fingerprint must be non-empty (defeats #3664 regression)"
    );
    assert!(
        post_na > 0,
        "post-pin persona row not_after must be a positive Unix timestamp"
    );
}

/// Idempotency: pinning the SAME persona a second time with a freshly-
/// minted cert overwrites the columns with the new values (ADR 173
/// §Component 7 §"Atomicity — option (a) immediate replace"). A second
/// call must not error and must observe the new fingerprint.
#[test]
fn pin_persona_client_cert_from_pem_overwrites_on_second_call() {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path();
    let vault = Rc::new(Vault::new(TEST_VAULT_KEY));

    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    store.set_vault(Rc::clone(&vault));
    let bridge_ca = load_or_mint_bridge_ca(data_dir, vault.as_ref()).expect("mint bridge CA");

    let (_parent_persona_id, parent_grant_id) = seed_parent_grant(&store);
    let persona = agent_persona_two_phase_commit(
        &store,
        vault.as_ref(),
        "ctr-spawn-cert-2",
        &parent_grant_id,
    )
    .expect("two-phase commit");

    let (cert_a, _) = bridge_ca
        .sign_client_cert(
            &persona.id,
            Some("ctr-spawn-cert-2"),
            Duration::from_secs(3_600),
        )
        .expect("first client cert");
    let (fp_a, _) =
        pin_persona_client_cert_from_pem(&store, &persona.id, cert_a.as_str()).expect("first pin");

    let (cert_b, _) = bridge_ca
        .sign_client_cert(
            &persona.id,
            Some("ctr-spawn-cert-2"),
            Duration::from_secs(7_200),
        )
        .expect("second client cert");
    let (fp_b, _) = pin_persona_client_cert_from_pem(&store, &persona.id, cert_b.as_str())
        .expect("second pin (idempotent overwrite)");

    assert_ne!(
        fp_a, fp_b,
        "second mint of the same (persona, container) yields a fresh leaf-key cert; \
         fingerprints must differ — if they match, the helper isn't actually re-hashing"
    );

    let (db_fp, _): (String, i64) = store
        .conn()
        .query_row(
            "SELECT client_cert_fingerprint, client_cert_not_after \
             FROM personas WHERE id = ?1",
            rusqlite::params![&persona.id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .expect("read overwritten persona cert columns");
    assert_eq!(
        db_fp, fp_b,
        "persona row must carry the SECOND pin's fingerprint (immediate-replace semantics)"
    );
}

/// Failure mode: a missing persona row surfaces as `Store(NotFound)` so
/// the caller can distinguish "row never existed" from a real SQLite or
/// PEM failure. Mirrors `increment_refresh_seq`'s NotFound mapping.
#[test]
fn pin_persona_client_cert_from_pem_unknown_persona_returns_not_found() {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path();
    let vault = Rc::new(Vault::new(TEST_VAULT_KEY));

    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    store.set_vault(Rc::clone(&vault));
    let bridge_ca = load_or_mint_bridge_ca(data_dir, vault.as_ref()).expect("mint bridge CA");

    let (cert_pem, _) = bridge_ca
        .sign_client_cert("orphan-persona", None, Duration::from_secs(3_600))
        .expect("sign client cert");

    let err = pin_persona_client_cert_from_pem(&store, "persona-no-such-row", cert_pem.as_str())
        .expect_err("unknown persona must surface a NotFound");
    match err {
        PinClientCertError::Store(ember_daemon::infra::store::StoreError::NotFound) => {}
        other => panic!("expected Store(NotFound), got {other:?}"),
    }
}

/// Failure mode: a malformed PEM surfaces as `Pem(_)`. Defends against
/// silently writing an empty fingerprint when the upstream mint helper
/// produces a degenerate value.
#[test]
fn pin_persona_client_cert_from_pem_rejects_garbage_pem() {
    let vault = Rc::new(Vault::new(TEST_VAULT_KEY));
    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    store.set_vault(Rc::clone(&vault));
    let (_parent_persona_id, parent_grant_id) = seed_parent_grant(&store);
    let persona = agent_persona_two_phase_commit(
        &store,
        vault.as_ref(),
        "ctr-spawn-cert-garbage",
        &parent_grant_id,
    )
    .expect("two-phase commit");

    let err = pin_persona_client_cert_from_pem(&store, &persona.id, "not-a-pem-blob")
        .expect_err("garbage PEM must surface a Pem error");
    match err {
        PinClientCertError::Pem(_) => {}
        other => panic!("expected Pem(_), got {other:?}"),
    }

    // The persona row must still carry the empty defaults — failure
    // path does not partially mutate the row.
    let (post_fp, post_na): (String, i64) = store
        .conn()
        .query_row(
            "SELECT client_cert_fingerprint, client_cert_not_after \
             FROM personas WHERE id = ?1",
            rusqlite::params![&persona.id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .expect("read persona cert columns after PEM-decode failure");
    assert_eq!(
        post_fp, "",
        "PEM failure must not write the fingerprint column"
    );
    assert_eq!(
        post_na, 0,
        "PEM failure must not write the not_after column"
    );
}
