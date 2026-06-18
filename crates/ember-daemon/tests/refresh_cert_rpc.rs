//! CLASSIFICATION: PUBLIC
//!
//! T2 integration coverage for ADR 173 M3 `refresh_cert`: a bridge-sourced
//! dispatch round-trip mints a fresh client cert and atomically updates the
//! persona cert columns plus `client_cert_refresh_seq`.
//!
//! Sentinels covered by the code under test:
//! - `daemon_refresh_cert_rpc_landed`
//! - `refresh_cert_identity_proof_landed`
//! - `refresh_cert_mint_landed`

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use core_personas::MtlsPrincipal;
use ember_daemon::infra::handler::{PeerCred, RequestContext, dispatch_method_with_context};
use ember_daemon::infra::persona::{
    agent_persona_two_phase_commit, pin_persona_client_cert_from_pem,
};
use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::bridge_ca::BridgeCa;
use ember_daemon::trust::policy::PolicyEngine;
use serde_json::json;

const TEST_VAULT_KEY: [u8; 32] = [0xC7; 32];

fn seed_refresh_fixture() -> (DaemonStore, Vault, MtlsPrincipal, String, String) {
    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    let vault = Rc::new(Vault::new(TEST_VAULT_KEY));
    store.set_vault(Rc::clone(&vault));
    let bridge_ca = Arc::new(BridgeCa::mint());
    store.set_bridge_ca(Arc::clone(&bridge_ca));

    let parent = store
        .create_persona("refresh-cert-t2-parent")
        .expect("parent persona");
    let parent_grant = store
        .create_grant(&parent.id, "delegate-key", "*", Some(7_200))
        .expect("parent grant");
    store
        .conn()
        .execute(
            "UPDATE grants SET max_delegation_depth = 2 WHERE id = ?1",
            rusqlite::params![&parent_grant.id],
        )
        .expect("raise delegation depth");

    let persona =
        agent_persona_two_phase_commit(&store, vault.as_ref(), "ctr-refresh-t2", &parent_grant.id)
            .expect("agent persona two-phase commit");
    let (initial_cert_pem, _initial_key_pem) = bridge_ca
        .sign_client_cert(
            &persona.id,
            Some("ctr-refresh-t2"),
            Duration::from_secs(3_600),
        )
        .expect("initial client cert");
    let (initial_fingerprint, _) =
        pin_persona_client_cert_from_pem(&store, &persona.id, initial_cert_pem.as_str())
            .expect("pin initial cert");

    let mtls = MtlsPrincipal {
        persona_id: persona.id.clone(),
        container_id: "ctr-refresh-t2".to_string(),
        cert_fingerprint: hex_to_fingerprint(&initial_fingerprint),
    };

    (
        store,
        Vault::new(TEST_VAULT_KEY),
        mtls,
        parent_grant.id,
        initial_fingerprint,
    )
}

fn hex_to_fingerprint(hex_value: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = hex::decode(hex_value).expect("fingerprint hex decodes");
    assert_eq!(bytes.len(), 32, "fingerprint is 32 bytes");
    out.copy_from_slice(&bytes);
    out
}

#[tokio::test]
async fn refresh_cert_bridge_dispatch_round_trip_mints_and_updates_row() {
    let (store, vault, mtls, parent_grant_id, initial_fingerprint) = seed_refresh_fixture();
    let policy = PolicyEngine::default();
    let rl = RefCell::new(RateLimiter::default());
    let ctx = RequestContext::bridge(
        Some(PeerCred {
            uid: 501,
            pid: Some(12_345),
        }),
        mtls,
    );

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "refresh_cert",
        &json!({"caller_grant_id": parent_grant_id}),
    )
    .await
    .expect("refresh_cert dispatch succeeds");

    assert_eq!(result["denied"], json!(false));
    assert_eq!(result["container_id"], json!("ctr-refresh-t2"));
    assert_eq!(result["refresh_seq"], json!(1));
    assert!(
        result["client_cert_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    assert!(
        result["client_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );

    let persona_id = result["persona_id"].as_str().expect("persona id");
    let state = store
        .get_persona_client_cert_state(persona_id)
        .expect("read refreshed cert state");
    assert_eq!(
        state.fingerprint_hex,
        result["client_cert_fingerprint"].as_str().unwrap()
    );
    assert_ne!(state.fingerprint_hex, initial_fingerprint);
    assert_eq!(
        state.not_after_unix,
        result["client_cert_not_after"].as_i64().unwrap()
    );
    assert_eq!(state.refresh_seq, 1);
}
