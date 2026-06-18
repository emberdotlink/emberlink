use super::*;

/// ADR 200 §5 — `identity.device.enroll` RPC glue end-to-end with a synthetic
/// P256 presence device standing in for the YubiKey/SE. Exercises the
/// prepare→commit two-call ceremony through `handle_identity_device_enroll`
/// (param parse → `genesis_enroll_plan` / `commit_first_run_enrollment` →
/// persisted identity store), then re-verifies the materialized operator chain.
#[test]
fn identity_device_enroll_prepare_commit_materializes_operator_identity() {
    use core_crypto::{DOMAIN_EVENT, P256Signer, Signer, sign_with_context};

    let dir = tempfile::TempDir::new().unwrap();
    // DaemonStore::open derives data_dir from the db path's parent, so the
    // handler's `open_identity_store(data_dir)` lands `identity-events.db` in
    // the same temp dir.
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();

    let device = P256Signer::from_scalar_bytes(&[0x5E; 32]).unwrap();
    let device_key = device.public_key().0; // p256:<sec1-hex>
    // ADR 206 §4: a DISTINCT ECIES recipient key (a second SE key).
    let encryption_signer = P256Signer::from_scalar_bytes(&[0xA1; 32]).unwrap();
    let encryption_key = encryption_signer.public_key().0;
    let label = "Test Presence Device";

    // PREPARE — no signatures. Pure: returns the bytes to sign off-host.
    let prepared = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": device_key,
            "encryption_key": encryption_key,
            "device_label": label,
        }),
    )
    .expect("prepare must succeed");
    assert_eq!(prepared["mode"], "prepare");
    let steps = prepared["to_sign"].as_array().expect("to_sign array");
    assert_eq!(steps.len(), 3, "first-run plan = root + persona + device");
    let operator_root_id = prepared["operator_root_id"].as_str().unwrap().to_string();
    let prepared_device_id = prepared["device_id"].as_str().unwrap().to_string();

    // Sign each prepared blob with the synthetic device, sending the DER hex
    // back (the handler accepts the un-tagged hex form).
    let signatures: Vec<serde_json::Value> = steps
        .iter()
        .map(|s| {
            let bytes = hex::decode(s["bytes_hex"].as_str().unwrap()).unwrap();
            let sig = sign_with_context(DOMAIN_EVENT, &device, &bytes);
            let der_hex = sig.0.strip_prefix("p256sig:").unwrap().to_string();
            serde_json::Value::String(der_hex)
        })
        .collect();

    // COMMIT — append + verify the genesis/enroll events.
    let committed = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": device_key,
            "encryption_key": encryption_key,
            "device_label": label,
            "signatures": signatures,
        }),
    )
    .expect("commit must succeed");
    assert_eq!(committed["mode"], "committed");
    let device_id = committed["device_id"].as_str().unwrap().to_string();
    assert_eq!(
        device_id, prepared_device_id,
        "prepare/commit device_id agree"
    );
    assert_eq!(
        committed["operator_root_id"].as_str().unwrap(),
        operator_root_id
    );

    // Re-open the persisted identity store and assert the operator identity
    // materialized and the enrolled device is the operator's active key.
    let identity_store =
        crate::infra::identity_substrate::open_identity_store(store.data_dir().unwrap()).unwrap();
    let state = identity_store.materialized();
    assert!(
        state.root(&operator_root_id).is_some(),
        "operator root materialized"
    );
    let dev = state
        .device(&device_id)
        .expect("presence device materialized");
    assert_eq!(dev.custody_class, core_event_types::CustodyClass::Presence);
    assert_eq!(
        dev.attestation_tier,
        core_event_types::AttestationTier::None
    );
    // ADR 206 §4 acceptance: the enrolled device's §4 ECIES recipient key is
    // DISTINCT from its signing key (the sign==decrypt reuse the cut kills).
    assert_eq!(dev.active_encryption_key.public_key, encryption_key);
    assert_ne!(
        dev.active_encryption_key.public_key, dev.active_key.public_key,
        "the §4 recipient must not reuse the signing key"
    );
    assert!(
        crate::infra::operator_identity::is_active_persona_key_under_operator_root(
            state,
            &device.public_key().0
        )
    );

    // AC-1: an independent verifier holding only the device pubkey re-verifies
    // the materialized operator chain.
    let chain: Vec<core_events::EventEnvelope> = identity_store
        .events()
        .iter()
        .filter(|e| e.body.root_id() == Some(operator_root_id.as_str()))
        .cloned()
        .collect();
    let anchor = core_crypto::PublicKey(device.public_key().0);
    assert!(
        matches!(
            core_eventlog::verify::verify_chain(&chain, &anchor),
            core_eventlog::verify::VerifyOutcome::Pass { .. }
        ),
        "operator chain must verify under the device anchor after persist+reload (AC-1)"
    );

    // A clean re-commit is an idempotent no-op (not a refusal).
    let recommit = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": device_key,
            "encryption_key": encryption_key,
            "device_label": label,
            "signatures": signatures,
        }),
    )
    .expect("idempotent re-commit must succeed");
    assert_eq!(recommit["device_id"].as_str().unwrap(), device_id);
}

#[test]
fn identity_device_enroll_backup_prepare_commit_materializes_backup_device() {
    use core_crypto::{DOMAIN_EVENT, P256Signer, Signer, sign_with_context};

    let dir = tempfile::TempDir::new().unwrap();
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();

    let primary = P256Signer::from_scalar_bytes(&[0x61; 32]).unwrap();
    let primary_key = primary.public_key().0;
    let primary_enc = P256Signer::from_scalar_bytes(&[0x62; 32]).unwrap();
    let primary_enc_key = primary_enc.public_key().0;
    let primary_prepared = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": primary_key,
            "encryption_key": primary_enc_key,
            "device_label": "Primary Presence Device",
        }),
    )
    .expect("primary prepare");
    let primary_steps = primary_prepared["to_sign"]
        .as_array()
        .expect("primary steps");
    let primary_signatures: Vec<serde_json::Value> = primary_steps
        .iter()
        .map(|s| {
            let bytes = hex::decode(s["bytes_hex"].as_str().unwrap()).unwrap();
            let sig = sign_with_context(DOMAIN_EVENT, &primary, &bytes);
            serde_json::Value::String(sig.0.strip_prefix("p256sig:").unwrap().to_string())
        })
        .collect();
    let primary_committed = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": primary_key,
            "encryption_key": primary_enc_key,
            "device_label": "Primary Presence Device",
            "signatures": primary_signatures,
        }),
    )
    .expect("primary commit");
    let operator_root_id = primary_committed["operator_root_id"]
        .as_str()
        .unwrap()
        .to_string();

    let backup = P256Signer::from_scalar_bytes(&[0x63; 32]).unwrap();
    let backup_key = backup.public_key().0;
    let backup_enc = P256Signer::from_scalar_bytes(&[0x64; 32]).unwrap();
    let backup_enc_key = backup_enc.public_key().0;
    let backup_params = json!({
        "authority_device_key": primary_key,
        "device_key": backup_key,
        "encryption_key": backup_enc_key,
        "device_label": "Backup Presence Device",
    });

    let prepared =
        handle_identity_device_enroll_backup_plan(&store, &backup_params).expect("backup prepare");
    assert_eq!(prepared["mode"], "prepare");
    assert_eq!(prepared["operator_root_id"], operator_root_id);
    assert_eq!(prepared["authority_device_key"], primary_key);
    let steps = prepared["to_sign"].as_array().expect("backup to_sign");
    assert_eq!(
        steps.len(),
        1,
        "backup enroll signs one DeviceEnrolled event"
    );
    assert_eq!(
        steps[0]["purpose"],
        "operator-backup-presence-device-enroll"
    );
    let backup_device_id = prepared["device_id"].as_str().unwrap().to_string();

    let bytes = hex::decode(steps[0]["bytes_hex"].as_str().unwrap()).unwrap();
    let sig = sign_with_context(DOMAIN_EVENT, &primary, &bytes);
    let der_hex = sig.0.strip_prefix("p256sig:").unwrap().to_string();
    let committed = handle_identity_device_enroll_backup(
        &store,
        &json!({
            "authority_device_key": primary_key,
            "device_key": backup_key,
            "encryption_key": backup_enc_key,
            "device_label": "Backup Presence Device",
            "signatures": [der_hex],
        }),
    )
    .expect("backup commit");
    assert_eq!(committed["mode"], "committed");
    assert_eq!(committed["operator_root_id"], operator_root_id);
    assert_eq!(committed["device_id"], backup_device_id);

    let identity_store =
        crate::infra::identity_substrate::open_identity_store(store.data_dir().unwrap()).unwrap();
    let state = identity_store.materialized();
    let backup_device = state
        .device(&backup_device_id)
        .expect("backup presence device materialized");
    assert_eq!(
        backup_device.custody_class,
        core_event_types::CustodyClass::Presence
    );
    assert_eq!(backup_device.active_key.public_key, backup_key);
    assert_eq!(
        backup_device.active_encryption_key.public_key,
        backup_enc_key
    );
    let active =
        crate::infra::operator_identity::active_presence_device_keys_under_operator_root(state);
    assert!(active.contains(&primary.public_key().0));
    assert!(active.contains(&backup.public_key().0));

    let chain: Vec<core_events::EventEnvelope> = identity_store
        .events()
        .iter()
        .filter(|e| e.body.root_id() == Some(operator_root_id.as_str()))
        .cloned()
        .collect();
    let anchor = core_crypto::PublicKey(primary.public_key().0);
    assert!(
        matches!(
            core_eventlog::verify::verify_chain(&chain, &anchor),
            core_eventlog::verify::VerifyOutcome::Pass { .. }
        ),
        "operator chain with backup device must verify under the primary operator anchor"
    );
}

/// Tap-reduction Fix 2: the read-only `identity.device.enroll_plan` method
/// must return the SAME plan as `identity.device.enroll`'s PREPARE branch
/// (byte-identical `to_sign`). ADR 206 slice 4 C: BOTH the PREPARE read and
/// the COMMIT are `ConnectOnly` — enroll is genesis-self-anchored (the
/// founding device's P-256 signature is verified at COMMIT append time), not
/// vault-widening, so it does not depend on the §4 unlock window (which cannot
/// exist before the first device is enrolled).
#[test]
fn enroll_plan_is_connectonly_and_matches_enroll_prepare() {
    use core_crypto::Signer;

    // Classification boundary: both PREPARE read and COMMIT are ConnectOnly.
    assert_eq!(
        authority_class_for_method("identity.device.enroll_plan"),
        Some(AuthorityClass::ConnectOnly),
        "read-only PREPARE must be ConnectOnly (no native-unlock tap)"
    );
    assert_eq!(
        authority_class_for_method("identity_device_enroll_plan"),
        Some(AuthorityClass::ConnectOnly),
    );
    assert_eq!(
        authority_class_for_method("identity.device.enroll"),
        Some(AuthorityClass::ConnectOnly),
        "ADR 206 slice 4 C: COMMIT is genesis-self-anchored (SE sig verified at \
             append time), reclassified OperatorPresence → ConnectOnly"
    );

    let dir = tempfile::TempDir::new().unwrap();
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();
    let device = core_crypto::P256Signer::from_scalar_bytes(&[0x42; 32]).unwrap();
    let encryption_device = core_crypto::P256Signer::from_scalar_bytes(&[0x43; 32]).unwrap();
    let params = json!({
        "device_key": device.public_key().0,
        "encryption_key": encryption_device.public_key().0,
        "device_label": "Plan Device",
    });

    let via_plan = handle_identity_device_enroll_plan(&store, &params).expect("plan");
    let via_prepare = handle_identity_device_enroll(&store, &params).expect("enroll prepare");

    assert_eq!(via_plan["mode"], "prepare");
    assert_eq!(
        via_plan, via_prepare,
        "enroll_plan must be byte-identical to enroll's no-signatures PREPARE"
    );
    assert_eq!(via_plan["to_sign"].as_array().unwrap().len(), 3);

    // The plan is pure: calling it never materializes an operator identity.
    let identity_store =
        crate::infra::identity_substrate::open_identity_store(store.data_dir().unwrap()).unwrap();
    assert!(
        identity_store.events().is_empty(),
        "PREPARE must not mutate the identity store"
    );
}

/// ADR 206 §4 AC-4: the distinctness guard must refuse a `encryption_key` that
/// is the SIGNING key merely re-cased. `p256:<hex>` decodes identically across
/// hex case, so a raw string `==` would let the same physical key pass as the
/// "distinct" §4 recipient — the sign==decrypt collapse the cut kills.
#[test]
fn enroll_refuses_recased_signing_key_as_ecies_recipient() {
    use core_crypto::Signer;

    let device = core_crypto::P256Signer::from_scalar_bytes(&[0x77; 32]).unwrap();
    let device_key = device.public_key().0; // p256:04<lower-hex>
    // Same key, hex upper-cased after the `p256:` tag.
    let hex_part = device_key.strip_prefix("p256:").unwrap();
    let recased = format!("p256:{}", hex_part.to_ascii_uppercase());
    assert_ne!(recased, device_key, "fixture: the strings differ by case");

    let err = parse_enroll_device_material(&json!({
        "device_key": device_key,
        "encryption_key": recased,
        "device_label": "x",
    }))
    .expect_err("a re-cased signing key must be refused as the ECIES recipient");
    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("DISTINCT"),
        "error must name the distinctness rule, got: {}",
        err.1
    );
}

/// The retired `presence/enroll` WebAuthn-passkey enrollment entry point no
/// longer dispatches — a well-formed call gets the JSON-RPC unknown-method
/// contract (-32601), not the old explicit stub.
#[tokio::test]
async fn retired_presence_enroll_returns_method_not_found() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let ctx = RequestContext::internal("test: retired presence/enroll");
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "presence/enroll",
        &json!({ "persona_id": "p", "credential_bytes": "deadbeef" }),
    )
    .await
    .expect_err("retired presence/enroll must not dispatch");
    assert_eq!(
        err.0, -32601,
        "retired method must surface unknown-method: {err:?}"
    );
}

/// ADR 200 §3 — `presence/request_nonce` end-to-end: the daemon mints a
/// nonce + emits the exact canonical intent bytes; a synthetic P256 presence
/// device signs them off-host; `require_authority` verifies the resulting
/// proof (PresenceVerified) and rejects a tampered op_id; the nonce is
/// single-use; a non-widening method is refused.
#[test]
fn presence_request_nonce_round_trips_through_require_authority() {
    use crate::auth::presence_gate::{
        AuthorityOutcome, PresenceProof, canonical_presence_intent_bytes, presence_params_digest,
        require_authority,
    };
    use p256::ecdsa::signature::Signer as _;

    let dir = tempfile::TempDir::new().unwrap();
    // Ensure SOME daemon identity exists (process singleton; first init wins).
    let _ = crate::infra::receipt::init_identity(dir.path());
    let store = DaemonStore::open_in_memory().unwrap();
    let ctx = RequestContext::socket(Some(PeerCred {
        uid: 1000,
        pid: Some(4242),
    }));

    // The op the operator intends (its authority-relevant params). The signer
    // computes the digest over THIS; the daemon recomputes it at consume.
    let op_params = json!({ "scope": "repo:read", "persona": "demo", "ttl": "7d" });
    let digest = presence_params_digest(&op_params).unwrap();

    // 1) Request a nonce for a widening op, committing the params digest.
    let resp = handle_presence_request_nonce(
        &store,
        &ctx,
        &json!({ "op_id": "op-rt-1", "method": "create_grant", "params_digest": digest }),
    )
    .expect("request_nonce must succeed for a widening method");
    let nonce = resp["nonce"].as_str().unwrap().to_string();
    let fp = resp["daemon_fingerprint"].as_str().unwrap().to_string();
    let intent_bytes = hex::decode(resp["intent_bytes_hex"].as_str().unwrap()).unwrap();
    assert!(!nonce.is_empty() && !fp.is_empty());
    assert_eq!(resp["params_digest"].as_str().unwrap(), digest);

    // The returned bytes are byte-identical to what the verifier reconstructs.
    assert_eq!(
        intent_bytes,
        canonical_presence_intent_bytes("create_grant", "op-rt-1", &nonce, &fp, &digest)
    );

    // 2) Operator signs the bytes off-host (synthetic P256 presence device).
    let sk = p256::ecdsa::SigningKey::from_bytes(&[0x7E; 32].into()).unwrap();
    let device_pub = format!(
        "p256:{}",
        hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes())
    );
    let sig: p256::ecdsa::Signature = sk.sign(&intent_bytes);
    let signature =
        core_crypto::Signature(format!("p256sig:{}", hex::encode(sig.to_der().as_bytes())));

    // 3) require_authority verifies the proof end-to-end.
    let proof = PresenceProof {
        op_id: "op-rt-1",
        nonce: &nonce,
        daemon_fingerprint: &fp,
        params_digest: &digest,
        device_public_key: &device_pub,
        signature: &signature,
    };
    assert_eq!(
        require_authority("create_grant", false, Some(&proof)),
        AuthorityOutcome::PresenceVerified
    );

    // 4) Tampered op_id → the signature no longer matches the reconstructed bytes.
    let bad = PresenceProof {
        op_id: "op-DIFFERENT",
        nonce: &nonce,
        daemon_fingerprint: &fp,
        params_digest: &digest,
        device_public_key: &device_pub,
        signature: &signature,
    };
    assert!(matches!(
        require_authority("create_grant", false, Some(&bad)),
        AuthorityOutcome::PresenceRequired(_)
    ));

    // 4b) Substituted params (different digest) → the proof no longer verifies
    // even though method/op_id/nonce are intact (approval-laundering Finding 1).
    let laundered_digest =
        presence_params_digest(&json!({ "scope": "*:admin", "persona": "attacker" })).unwrap();
    let laundered = PresenceProof {
        op_id: "op-rt-1",
        nonce: &nonce,
        daemon_fingerprint: &fp,
        params_digest: &laundered_digest,
        device_public_key: &device_pub,
        signature: &signature,
    };
    assert!(
        matches!(
            require_authority("create_grant", false, Some(&laundered)),
            AuthorityOutcome::PresenceRequired(_)
        ),
        "a proof signed over read:foo must not authorize *:admin"
    );

    // 5) The nonce is single-use, bound to (op_id, fingerprint, method, digest).
    store
        .consume_presence_nonce(&nonce, "op-rt-1", &fp, "create_grant", &digest)
        .expect("first consume ok");
    assert!(
        store
            .consume_presence_nonce(&nonce, "op-rt-1", &fp, "create_grant", &digest)
            .is_err(),
        "nonce replay must fail (single-use)"
    );

    // 6) A non-widening method is refused — no presence nonce is needed.
    let err =
        handle_presence_request_nonce(&store, &ctx, &json!({ "op_id": "x", "method": "ping" }))
            .expect_err("non-widening method must be refused");
    assert_eq!(err.0, -32602);
}

// ===== ADR 206 §1 — presence chokepoint enforcement =====

/// Structural coverage: every authority-MINTING widening op (the
/// `presence_chokepoint_applies` subset) is refused without a `_presence_proof`,
/// while the carved-out arms (`register_session`, `presence/request_proof`,
/// `audit_repair_chain`) and routine ops pass the chokepoint. Locks the
/// fail-closed default and the carve-out boundary in one place.
#[test]
fn presence_chokepoint_refuses_every_minting_arm_without_proof() {
    let _enforce = PresenceChokepointEnforceGuard::on();
    let store = DaemonStore::open_in_memory().unwrap();
    let empty = json!({});

    // The authority-minting widening set — refused without a proof (-32030).
    for method in [
        "create_persona",
        "build_init_first_grant_receipt",
        "create_grant",
        "create_composite_grant",
        "delegate_grant",
        "extend_grant",
        "grant.extend",
        "propose_grant",
        "create_standing_grant",
        "save_delegation_template",
        "resolve_approval",
        "approval.resolve",
        "approval_resolve",
        "approval.narrow",
        "approval_narrow",
        "vault_add",
        "vault_put",
        "vault_migrate_acl",
        "vault_rotate_execute",
        "local_state_key_rotate_and_reencrypt",
        "binary_pin_generate",
        "sops_unwrap_dek",
        "sops.unwrap",
    ] {
        assert!(
            presence_chokepoint_applies(method),
            "{method} must be a chokepoint-covered minting op"
        );
        let err = enforce_presence_chokepoint(&store, method, &empty)
            .expect_err("widening op must be refused without a presence proof");
        assert_eq!(err.0, -32030, "{method} refusal must be -32030: {err:?}");
        assert!(
            err.1.contains("presence-Device signature"),
            "{method} refusal must name the missing proof: {}",
            err.1
        );
    }

    // Carved-out arms + a routine op pass the chokepoint (Ok) with no proof.
    for method in [
        "register_session",
        "presence/request_proof",
        "presence_request_proof",
        "audit_repair_chain",
        "headless_enroll",
        "broker_exec",
        "vault_remove",
        "ping",
    ] {
        assert!(
            !presence_chokepoint_applies(method),
            "{method} must NOT be chokepoint-covered"
        );
        assert!(
            enforce_presence_chokepoint(&store, method, &empty).is_ok(),
            "{method} must pass the chokepoint without a proof"
        );
    }
}

/// Cross-crate contract guard: the CLI's `should_acquire_presence_proof`
/// triggers its acquire-and-retry on a `-32030` error whose message contains
/// the substring "presence-Device signature". This test pins that phrase in
/// the daemon's missing-proof refusal so a reword here can't silently disable
/// the CLI retry (adversarial finding LOW). If you change the wording, update
/// `emberlink-cli::should_acquire_presence_proof` in lockstep.
#[test]
fn chokepoint_missing_proof_message_matches_cli_retry_trigger() {
    let _enforce = PresenceChokepointEnforceGuard::on();
    let store = DaemonStore::open_in_memory().unwrap();
    let err = enforce_presence_chokepoint(&store, "create_grant", &json!({}))
        .expect_err("missing proof must refuse");
    assert_eq!(err.0, -32030);
    assert!(
        err.1.contains("presence-Device signature"),
        "CLI retry trigger phrase must be present in the refusal: {}",
        err.1
    );
}

/// The chokepoint fires inside the real dispatch path: a widening op arriving
/// on a Socket connection with no `_presence_proof` is refused (-32030) before
/// the legacy OperatorPresence block, and internal callers stay exempt.
#[tokio::test]
async fn presence_chokepoint_fires_in_socket_dispatch() {
    let _enforce = PresenceChokepointEnforceGuard::on();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Socket source, no proof → chokepoint refuses with -32030.
    let socket_ctx = RequestContext::socket(Some(PeerCred {
        uid: 1000,
        pid: Some(4242),
    }));
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        socket_ctx,
        "create_grant",
        &json!({ "persona_id": "p", "credential_name": "c" }),
    )
    .await
    .expect_err("widening op on a socket without a proof must be refused");
    assert_eq!(err.0, -32030, "must be the chokepoint refusal: {err:?}");
    assert!(err.1.contains("presence-Device signature"), "{}", err.1);

    // Internal callers retain the established carve-out (A2 forward note): the
    // chokepoint does not fire, so the request falls through to its other
    // gates rather than being refused for a missing presence proof.
    let internal_err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        RequestContext::internal("test: internal exempt from chokepoint"),
        "create_grant",
        &json!({ "persona_id": "p", "credential_name": "c" }),
    )
    .await
    .err();
    if let Some((code, msg)) = internal_err {
        assert_ne!(
            code, -32030,
            "internal callers must not be refused by the presence chokepoint: {msg}"
        );
    }
}

/// End-to-end accept + reject through `enforce_presence_chokepoint` against a
/// real on-disk operator identity: genesis-enroll a synthetic P256 presence
/// Device, mint a nonce, sign the daemon-computed intent bytes, and assert the
/// chokepoint admits the valid proof — then rejects a missing proof, a
/// wrong-key signature, a tampered op_id, a non-enrolled signer, and a replay.
#[test]
fn presence_chokepoint_accepts_valid_proof_and_rejects_forgeries() {
    use core_crypto::{DOMAIN_EVENT, P256Signer, Signer, sign_with_context};

    let _enforce = PresenceChokepointEnforceGuard::on();
    let dir = tempfile::TempDir::new().unwrap();
    // Process-singleton daemon identity (first init wins) — supplies the
    // daemon fingerprint the nonce + intent bytes are bound to.
    let _ = crate::infra::receipt::init_identity(dir.path());
    // On-disk store so the chokepoint can open the identity substrate.
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();

    // Genesis-enroll a synthetic presence Device (stands in for YubiKey/SE).
    let device = P256Signer::from_scalar_bytes(&[0x5E; 32]).unwrap();
    let device_key = device.public_key().0;
    let encryption_key = P256Signer::from_scalar_bytes(&[0xA1; 32])
        .unwrap()
        .public_key()
        .0;
    let prepared = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": device_key,
            "encryption_key": encryption_key,
            "device_label": "Test Presence Device",
        }),
    )
    .expect("prepare");
    let signatures: Vec<serde_json::Value> = prepared["to_sign"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let bytes = hex::decode(s["bytes_hex"].as_str().unwrap()).unwrap();
            let sig = sign_with_context(DOMAIN_EVENT, &device, &bytes);
            serde_json::Value::String(sig.0.strip_prefix("p256sig:").unwrap().to_string())
        })
        .collect();
    handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": device_key,
            "encryption_key": encryption_key,
            "device_label": "Test Presence Device",
            "signatures": signatures,
        }),
    )
    .expect("commit");

    // Helper: mint a nonce for (op_id, method) committing the digest of
    // `op_params`, sign the daemon's intent bytes with `signer`, and return the
    // FULL params object (op_params + `_presence_proof`) the chokepoint will see.
    // The chokepoint recomputes the digest over these params (minus the envelope
    // field), so the committed and recomputed digests agree iff op_params match.
    let ctx = RequestContext::socket(Some(PeerCred {
        uid: 1000,
        pid: Some(4242),
    }));
    let make_proof = |op_id: &str, method: &str, signer: &P256Signer, op_params: &Value| -> Value {
        let digest = crate::auth::presence_gate::presence_params_digest(op_params).unwrap();
        let resp = handle_presence_request_nonce(
            &store,
            &ctx,
            &json!({ "op_id": op_id, "method": method, "params_digest": digest }),
        )
        .expect("request_nonce");
        let nonce = resp["nonce"].as_str().unwrap().to_string();
        let intent = hex::decode(resp["intent_bytes_hex"].as_str().unwrap()).unwrap();
        let sig = signer.sign(&intent); // p256sig:<der-hex> over the intent bytes
        let mut params = op_params.clone();
        params["_presence_proof"] = json!({ "op_id": op_id, "nonce": nonce, "signature": sig.0 });
        params
    };

    // Happy path: valid proof by the enrolled device over the SAME params → admitted.
    let op = json!({ "scope": "repo:read" });
    let good = make_proof("op-ok", "create_grant", &device, &op);
    assert!(
        enforce_presence_chokepoint(&store, "create_grant", &good).is_ok(),
        "a valid proof by the enrolled presence Device must be admitted"
    );

    // Missing proof → refused.
    assert_eq!(
        enforce_presence_chokepoint(&store, "create_grant", &json!({}))
            .expect_err("missing proof")
            .0,
        -32030
    );

    // Param substitution (approval-laundering Finding 1): a proof minted over
    // `scope:repo:read` must NOT authorize a dispatch carrying `scope:*:admin`.
    // The daemon recomputes the digest over the substituted params and the nonce
    // consume rejects on digest mismatch (-32030).
    let mut laundered = make_proof(
        "op-launder",
        "create_grant",
        &device,
        &json!({ "scope": "repo:read" }),
    );
    laundered["scope"] = json!("*:admin");
    assert_eq!(
        enforce_presence_chokepoint(&store, "create_grant", &laundered)
            .expect_err("substituted params")
            .0,
        -32030,
        "a proof signed over repo:read must not authorize *:admin"
    );

    // Wrong-key signature: a non-enrolled device signs the (valid) nonce.
    let intruder = P256Signer::from_scalar_bytes(&[0x99; 32]).unwrap();
    let bad_op = json!({ "scope": "repo:read" });
    let bad_digest = crate::auth::presence_gate::presence_params_digest(&bad_op).unwrap();
    let resp = handle_presence_request_nonce(
        &store,
        &ctx,
        &json!({ "op_id": "op-bad-key", "method": "create_grant", "params_digest": bad_digest }),
    )
    .unwrap();
    let nonce = resp["nonce"].as_str().unwrap().to_string();
    let intent = hex::decode(resp["intent_bytes_hex"].as_str().unwrap()).unwrap();
    let intruder_sig = intruder.sign(&intent);
    let wrong_key = json!({ "scope": "repo:read", "_presence_proof": { "op_id": "op-bad-key", "nonce": nonce, "signature": intruder_sig.0 } });
    assert_eq!(
        enforce_presence_chokepoint(&store, "create_grant", &wrong_key)
            .expect_err("non-enrolled signer")
            .0,
        -32030
    );

    // Tampered op_id: the proof's op_id no longer matches the minted nonce's
    // binding → nonce consume fails (-32030).
    let mut tampered = make_proof("op-real", "create_grant", &device, &op);
    tampered["_presence_proof"]["op_id"] = json!("op-FORGED");
    assert_eq!(
        enforce_presence_chokepoint(&store, "create_grant", &tampered)
            .expect_err("tampered op_id")
            .0,
        -32030
    );

    // Replay: a valid proof is single-use — re-submitting it fails (nonce
    // tombstoned on first consume).
    let replay = make_proof("op-replay", "create_grant", &device, &op);
    assert!(enforce_presence_chokepoint(&store, "create_grant", &replay).is_ok());
    assert_eq!(
        enforce_presence_chokepoint(&store, "create_grant", &replay)
            .expect_err("replayed nonce")
            .0,
        -32030
    );
}

/// ADR 206 §1 (AC-2/AC-3) — the transient-KEK widening path: a `create_persona`
/// (a minting widening op that seals under `KEK_s`) carrying a VERIFIED §1 proof
/// AND an operator-supplied `scope_kek` succeeds, AND leaves the presence window
/// LOCKED + the live-vault slot EVICTED afterward (no standing window, KEK_s
/// wiped). This is the eviction / no-window proof.
#[tokio::test]
async fn create_persona_with_proof_and_scope_kek_succeeds_then_evicts_no_window() {
    use core_crypto::{DOMAIN_EVENT, P256Signer, Signer, sign_with_context};

    // `test_state_guard()` itself takes `PROCESS_TEST_LOCK`, serializing this
    // test against every other presence/vault/install test (do NOT also lock
    // it directly — the std Mutex is non-reentrant and would deadlock).
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    let _enforce = PresenceChokepointEnforceGuard::on();
    interactive_unlock::reset_for_tests();
    // The window starts LOCKED — the transient path must engage (install +
    // evict), not ride a pre-existing standing window.
    crate::trust::presence::lock();

    let dir = tempfile::TempDir::new().unwrap();
    let _ = crate::infra::receipt::init_identity(dir.path());
    // On-disk store so the chokepoint can open the identity substrate, and so
    // create_persona's seal lands in a real DB.
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();

    // Register the interactive-unlock config + vault slot so the transient
    // install can open a §4 scope-KEK vault and attach it to the store's slot.
    let config = crate::infra::config::DaemonConfig::for_test(dir.path());
    interactive_unlock::register_config(config);
    interactive_unlock::register_vault_slot(store.vault_slot());

    // Genesis-enroll a synthetic presence Device so the chokepoint can verify
    // the §1 proof against an enrolled presence-Device key.
    let device = P256Signer::from_scalar_bytes(&[0x5E; 32]).unwrap();
    let device_key = device.public_key().0;
    let encryption_key = P256Signer::from_scalar_bytes(&[0xA1; 32])
        .unwrap()
        .public_key()
        .0;
    let prepared = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": device_key,
            "encryption_key": encryption_key,
            "device_label": "Test Presence Device",
        }),
    )
    .expect("prepare");
    let signatures: Vec<serde_json::Value> = prepared["to_sign"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let bytes = hex::decode(s["bytes_hex"].as_str().unwrap()).unwrap();
            let sig = sign_with_context(DOMAIN_EVENT, &device, &bytes);
            serde_json::Value::String(sig.0.strip_prefix("p256sig:").unwrap().to_string())
        })
        .collect();
    handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": device_key,
            "encryption_key": encryption_key,
            "device_label": "Test Presence Device",
            "signatures": signatures,
        }),
    )
    .expect("commit");

    // Build a valid §1 proof for create_persona, committing the digest of the
    // op's authority params (just `name` here — `_presence_proof` and `scope_kek`
    // are envelope fields the digest helper strips on both sides).
    let ctx_nonce = RequestContext::socket(Some(PeerCred {
        uid: 1000,
        pid: Some(4242),
    }));
    let op_params = json!({ "name": "transient-kek-persona" });
    let digest = crate::auth::presence_gate::presence_params_digest(&op_params).unwrap();
    let resp = handle_presence_request_nonce(
        &store,
        &ctx_nonce,
        &json!({ "op_id": "op-persona", "method": "create_persona", "params_digest": digest }),
    )
    .expect("request_nonce");
    let nonce = resp["nonce"].as_str().unwrap().to_string();
    let intent = hex::decode(resp["intent_bytes_hex"].as_str().unwrap()).unwrap();
    let sig = device.sign(&intent);

    // The operator-session CLI's own se_unwrap output — any 32-byte KEK_s opens
    // a fresh first-run §4 vault; create_persona seals under it.
    let scope_kek_hex = hex::encode([0x42u8; 32]);

    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let ctx = RequestContext::socket(Some(PeerCred {
        uid: 1000,
        pid: Some(4242),
    }));
    let params = json!({
        "name": "transient-kek-persona",
        "_presence_proof": { "op_id": "op-persona", "nonce": nonce, "signature": sig.0 },
        "scope_kek": scope_kek_hex,
    });

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "create_persona",
        &params,
    )
    .await
    .expect("create_persona with verified proof + scope_kek must succeed");
    assert!(
        result["id"].as_str().is_some(),
        "create_persona must return the new persona id, got {result:?}"
    );

    // EVICTION / NO-WINDOW PROOF (AC-2):
    // 1. The presence window is LOCKED — the transient path never marked it
    //    unlocked, so no standing window survives the op.
    let (unlocked, _) = crate::trust::presence::snapshot();
    assert!(
        !unlocked,
        "transient-KEK widening must leave the presence window LOCKED (no standing window)"
    );
    // 2. The live-vault slot is EVICTED — the KEK_s vault installed for the op
    //    was dropped on return (Rc<Vault> drop → ZeroizeOnDrop wipes KEK_s).
    assert!(
        store.vault().is_none(),
        "transient-KEK widening must EVICT the live KEK_s vault after the op"
    );

    // 3. A SECOND create_persona with NO fresh proof + NO scope_kek must fail
    //    closed — there is no standing window to ride.
    let ctx2 = RequestContext::socket(Some(PeerCred {
        uid: 1000,
        pid: Some(4242),
    }));
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx2,
        "create_persona",
        &json!({ "name": "no-window-ride" }),
    )
    .await
    .expect_err("a second create_persona must fail closed — the transient KEK_s was evicted");
    // Missing proof at the chokepoint → -32030.
    assert_eq!(
        err.0, -32030,
        "second create_persona must fail at the presence chokepoint (no proof), got {err:?}"
    );
}

/// ADR 206 backward-compatibility: a covered widening op WITHOUT `scope_kek`
/// takes the unchanged §4 standing-window path. With the window OPEN and a valid
/// presence_token, create_persona succeeds and the transient path does NOT
/// engage (the window is left intact / managed by the existing machinery).
#[tokio::test]
async fn create_persona_without_scope_kek_uses_unchanged_window_path() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::reset_for_tests();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    // Attach a vault so create_persona's seal succeeds on the legacy path.
    store.set_vault(std::rc::Rc::new(Vault::new([0x31u8; 32])));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    let ctx = RequestContext::socket(Some(PeerCred {
        uid: 501,
        pid: Some(1234),
    }))
    .with_presence_token(Some(test_presence_token(501)));

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "create_persona",
        &json!({ "name": "legacy-window-persona" }),
    )
    .await;
    match result {
        Ok(v) => assert!(v["id"].as_str().is_some()),
        Err((code, msg)) => assert_ne!(
            code, -32001,
            "absent scope_kek, the unchanged window+token path must authorize create_persona; got {msg}"
        ),
    }

    // The window remains as the existing machinery left it (still unlocked) —
    // the transient eviction did NOT engage (no scope_kek was supplied).
    let (unlocked, _) = crate::trust::presence::snapshot();
    assert!(
        unlocked,
        "absent scope_kek, the standing window must be untouched by the transient path"
    );
}

#[test]
fn widening_transient_kek_applies_covers_only_the_safe_minting_subset() {
    for m in [
        "create_persona",
        "create_grant",
        "create_composite_grant",
        "create_standing_grant",
        "propose_grant",
        "save_delegation_template",
        "resolve_approval",
        "approval.resolve",
        "approval_resolve",
        "approval.narrow",
        "approval_narrow",
        "build_init_first_grant_receipt",
    ] {
        assert!(
            widening_transient_kek_applies(m),
            "{m} must be in the transient-KEK widening set"
        );
    }
    // Excluded: rotations, sops_unwrap, session-open, vault writes — they have
    // their own lifecycle and must NOT ride the transient one-shot install.
    for m in [
        "vault_rotate_execute",
        "vault_add",
        "sops_unwrap_dek",
        "local_state_key_rotate_and_reencrypt",
        "register_session",
        "delegate_grant",
        "extend_grant",
        "grant.extend",
    ] {
        assert!(
            !widening_transient_kek_applies(m),
            "{m} must NOT be in the transient-KEK widening set"
        );
    }
}

// ── META-V030-DEVICE-REVOKE-LIST-LAST-AUTHORITY-FLAG — handler integration ─

/// META-V030-DEVICE-REVOKE-LIST-LAST-AUTHORITY-FLAG (F9.3 LOW): when only ONE
/// Active `presence`-class Device is enrolled under the operator root,
/// `identity.device.list` MUST surface `is_last_authority: true` on that
/// device (and only that device). Computed from the same
/// `active_presence_device_keys_under_operator_root` filter the structural
/// last-presence-device revoke guard uses, so the surface and the guard
/// cannot drift apart.
///
/// Anchor: `device_list_is_last_authority_flag_landed`.
#[tokio::test(flavor = "current_thread")]
async fn identity_device_list_flags_only_presence_device_as_last_authority() {
    use crate::infra::handler::presence_runtime::handle_identity_device_list;
    use core_crypto::{DOMAIN_EVENT, P256Signer, Signer, sign_with_context};

    let dir = tempfile::TempDir::new().unwrap();
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();

    // Bootstrap ONLY the primary presence Device (no backup).
    let primary = P256Signer::from_scalar_bytes(&[0xB1; 32]).unwrap();
    let primary_key = primary.public_key().0;
    let primary_enc = P256Signer::from_scalar_bytes(&[0xB2; 32]).unwrap();
    let primary_enc_key = primary_enc.public_key().0;
    let prepared = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": primary_key,
            "encryption_key": primary_enc_key,
            "device_label": "Primary Presence Device",
        }),
    )
    .expect("primary prepare");
    let sigs: Vec<serde_json::Value> = prepared["to_sign"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let bytes = hex::decode(s["bytes_hex"].as_str().unwrap()).unwrap();
            let sig = sign_with_context(DOMAIN_EVENT, &primary, &bytes);
            serde_json::Value::String(sig.0.strip_prefix("p256sig:").unwrap().to_string())
        })
        .collect();
    let committed = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": primary_key,
            "encryption_key": primary_enc_key,
            "device_label": "Primary Presence Device",
            "signatures": sigs,
        }),
    )
    .expect("primary commit");
    let primary_device_id = committed["device_id"].as_str().unwrap().to_string();

    // identity.device.list — the single presence Device is the only-authority.
    let response = handle_identity_device_list(&store).expect("device list");
    let devices = response["devices"].as_array().expect("devices array");
    assert_eq!(devices.len(), 1, "exactly one device enrolled");
    assert_eq!(devices[0]["device_id"].as_str().unwrap(), primary_device_id);
    assert_eq!(
        devices[0]["is_last_authority"].as_bool(),
        Some(true),
        "the sole presence Device must be flagged is_last_authority=true"
    );
}

/// META-V030-DEVICE-REVOKE-LIST-LAST-AUTHORITY-FLAG (F9.3 LOW): with TWO
/// active presence Devices under the root, NEITHER is the last-authority
/// (revoking either leaves the other to sign the next widening op). The
/// flag MUST be `false` for both — never an opportunistic guess based on
/// stable-sort position.
///
/// Anchor: `device_list_is_last_authority_flag_landed`.
#[tokio::test(flavor = "current_thread")]
async fn identity_device_list_flags_neither_device_when_two_presence_enrolled() {
    use crate::infra::handler::presence_runtime::handle_identity_device_list;
    use core_crypto::{DOMAIN_EVENT, P256Signer, Signer, sign_with_context};

    let dir = tempfile::TempDir::new().unwrap();
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();

    // 1) Primary enroll.
    let primary = P256Signer::from_scalar_bytes(&[0xC1; 32]).unwrap();
    let primary_key = primary.public_key().0;
    let primary_enc = P256Signer::from_scalar_bytes(&[0xC2; 32]).unwrap();
    let primary_enc_key = primary_enc.public_key().0;
    let prepared = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": primary_key,
            "encryption_key": primary_enc_key,
            "device_label": "Primary Presence Device",
        }),
    )
    .expect("primary prepare");
    let sigs: Vec<serde_json::Value> = prepared["to_sign"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let bytes = hex::decode(s["bytes_hex"].as_str().unwrap()).unwrap();
            let sig = sign_with_context(DOMAIN_EVENT, &primary, &bytes);
            serde_json::Value::String(sig.0.strip_prefix("p256sig:").unwrap().to_string())
        })
        .collect();
    handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": primary_key,
            "encryption_key": primary_enc_key,
            "device_label": "Primary Presence Device",
            "signatures": sigs,
        }),
    )
    .expect("primary commit");

    // 2) Backup enroll.
    let backup = P256Signer::from_scalar_bytes(&[0xC3; 32]).unwrap();
    let backup_key = backup.public_key().0;
    let backup_enc = P256Signer::from_scalar_bytes(&[0xC4; 32]).unwrap();
    let backup_enc_key = backup_enc.public_key().0;
    let backup_prepared = handle_identity_device_enroll_backup(
        &store,
        &json!({
            "authority_device_key": primary_key,
            "device_key": backup_key,
            "encryption_key": backup_enc_key,
            "device_label": "Backup Presence Device",
        }),
    )
    .expect("backup prepare");
    let bytes = hex::decode(
        backup_prepared["to_sign"][0]["bytes_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let sig = sign_with_context(DOMAIN_EVENT, &primary, &bytes);
    let der_hex = sig.0.strip_prefix("p256sig:").unwrap().to_string();
    handle_identity_device_enroll_backup(
        &store,
        &json!({
            "authority_device_key": primary_key,
            "device_key": backup_key,
            "encryption_key": backup_enc_key,
            "device_label": "Backup Presence Device",
            "signatures": [der_hex],
        }),
    )
    .expect("backup commit");

    let response = handle_identity_device_list(&store).expect("device list");
    let devices = response["devices"].as_array().expect("devices array");
    assert_eq!(devices.len(), 2);
    for d in devices {
        assert_eq!(
            d["is_last_authority"].as_bool(),
            Some(false),
            "with 2 active presence Devices, neither is the last-authority; got: {d:?}"
        );
    }
}

// ── V030-EMBER-DEVICE-REVOKE — handler integration ─────────────────────────

/// T2 — end-to-end through `handle_identity_device_revoke`: prepare→commit
/// against a real `DaemonStore`, then re-verify (a) the device's status
/// flipped to Revoked in the materialized state and (b) the operator's
/// presence-authority set drops the revoked key.
///
/// V030-EMBER-DEVICE-REVOKE F4.1 — the handler is async (it acquires
/// `DaemonStore::identity_mutation_lock` across the open → guard → commit
/// window), so this is now `#[tokio::test]`. `flavor = "current_thread"`
/// is required because `DaemonStore` is `!Send`.
#[tokio::test(flavor = "current_thread")]
async fn identity_device_revoke_prepare_commit_flips_status_and_drops_authority_key() {
    use core_crypto::{DOMAIN_EVENT, P256Signer, Signer, sign_with_context};

    let dir = tempfile::TempDir::new().unwrap();
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();

    // 1) Bootstrap the operator root via the primary enroll handler.
    let primary = P256Signer::from_scalar_bytes(&[0x81; 32]).unwrap();
    let primary_key = primary.public_key().0;
    let primary_enc = P256Signer::from_scalar_bytes(&[0x82; 32]).unwrap();
    let primary_enc_key = primary_enc.public_key().0;
    let primary_prepared = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": primary_key,
            "encryption_key": primary_enc_key,
            "device_label": "Primary Presence Device",
        }),
    )
    .expect("primary prepare");
    let primary_signatures: Vec<serde_json::Value> = primary_prepared["to_sign"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let bytes = hex::decode(s["bytes_hex"].as_str().unwrap()).unwrap();
            let sig = sign_with_context(DOMAIN_EVENT, &primary, &bytes);
            serde_json::Value::String(sig.0.strip_prefix("p256sig:").unwrap().to_string())
        })
        .collect();
    let primary_committed = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": primary_key,
            "encryption_key": primary_enc_key,
            "device_label": "Primary Presence Device",
            "signatures": primary_signatures,
        }),
    )
    .expect("primary commit");
    let operator_root_id = primary_committed["operator_root_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 2) Enroll a backup Device so the authority set has TWO keys (revoke of
    //    one of them is then allowed by the last-device guard).
    let backup = P256Signer::from_scalar_bytes(&[0x83; 32]).unwrap();
    let backup_key = backup.public_key().0;
    let backup_enc = P256Signer::from_scalar_bytes(&[0x84; 32]).unwrap();
    let backup_enc_key = backup_enc.public_key().0;
    let backup_prepared = handle_identity_device_enroll_backup(
        &store,
        &json!({
            "authority_device_key": primary_key,
            "device_key": backup_key,
            "encryption_key": backup_enc_key,
            "device_label": "Backup Presence Device",
        }),
    )
    .expect("backup prepare");
    let backup_steps = backup_prepared["to_sign"].as_array().unwrap();
    let bytes = hex::decode(backup_steps[0]["bytes_hex"].as_str().unwrap()).unwrap();
    let sig = sign_with_context(DOMAIN_EVENT, &primary, &bytes);
    let der_hex = sig.0.strip_prefix("p256sig:").unwrap().to_string();
    let backup_committed = handle_identity_device_enroll_backup(
        &store,
        &json!({
            "authority_device_key": primary_key,
            "device_key": backup_key,
            "encryption_key": backup_enc_key,
            "device_label": "Backup Presence Device",
            "signatures": [der_hex],
        }),
    )
    .expect("backup commit");
    let backup_device_id = backup_committed["device_id"].as_str().unwrap().to_string();

    // 3) PREPARE the revoke: target = backup, authority = primary.
    let prepared = handle_identity_device_revoke(
        &store,
        &json!({
            "device_id": backup_device_id,
            "authority_device_key": primary_key,
            "reason": "test revoke",
        }),
    )
    .await
    .expect("revoke prepare");
    assert_eq!(prepared["mode"], "prepare");
    assert_eq!(prepared["operator_root_id"], operator_root_id);
    assert_eq!(prepared["device_id"], backup_device_id);
    assert_eq!(prepared["authority_device_key"], primary_key);
    let revoke_steps = prepared["to_sign"].as_array().expect("revoke to_sign");
    assert_eq!(
        revoke_steps.len(),
        1,
        "revoke signs one DeviceRevoked event"
    );
    assert_eq!(revoke_steps[0]["purpose"], "operator-device-revoke");

    // 4) Sign the bytes off-host (synthetic) and COMMIT.
    let bytes = hex::decode(revoke_steps[0]["bytes_hex"].as_str().unwrap()).unwrap();
    let revoke_sig = sign_with_context(DOMAIN_EVENT, &primary, &bytes);
    let revoke_der_hex = revoke_sig.0.strip_prefix("p256sig:").unwrap().to_string();
    let committed = handle_identity_device_revoke(
        &store,
        &json!({
            "device_id": backup_device_id,
            "authority_device_key": primary_key,
            "reason": "test revoke",
            "signatures": [revoke_der_hex],
        }),
    )
    .await
    .expect("revoke commit");
    assert_eq!(committed["mode"], "committed");
    assert_eq!(committed["device_id"], backup_device_id);
    assert_eq!(committed["reason"], "test revoke");
    assert_eq!(committed["operator_root_id"], operator_root_id);

    // 5) Materialized state: revoked device's status flipped; authority set
    //    drops the revoked key (presence-gate filter at line ~131 of
    //    operator_identity.rs already excludes revoked devices).
    let identity_store =
        crate::infra::identity_substrate::open_identity_store(store.data_dir().unwrap()).unwrap();
    let state = identity_store.materialized();
    let device = state
        .device(&backup_device_id)
        .expect("revoked device record still exists (status flipped, not deleted)");
    assert_eq!(device.status, core_state::DeviceStatus::Revoked);
    let active =
        crate::infra::operator_identity::active_presence_device_keys_under_operator_root(state);
    assert!(
        active.contains(&primary_key),
        "primary remains in the authority set"
    );
    assert!(
        !active.contains(&backup_key),
        "revoked backup must drop out of the presence authority set"
    );
}

/// T2 — last-device guard at the handler boundary. Refuses both PREPARE and
/// COMMIT when only one active presence Device remains under the root, so the
/// CLI never asks the operator to tap for an op the daemon would refuse.
#[tokio::test(flavor = "current_thread")]
async fn identity_device_revoke_refuses_last_presence_device_at_handler() {
    use core_crypto::{DOMAIN_EVENT, P256Signer, Signer, sign_with_context};

    let dir = tempfile::TempDir::new().unwrap();
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();

    // Bootstrap ONLY the primary presence Device (no backup).
    let primary = P256Signer::from_scalar_bytes(&[0x91; 32]).unwrap();
    let primary_key = primary.public_key().0;
    let primary_enc = P256Signer::from_scalar_bytes(&[0x92; 32]).unwrap();
    let primary_enc_key = primary_enc.public_key().0;
    let primary_prepared = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": primary_key,
            "encryption_key": primary_enc_key,
            "device_label": "Primary Presence Device",
        }),
    )
    .expect("primary prepare");
    let primary_signatures: Vec<serde_json::Value> = primary_prepared["to_sign"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let bytes = hex::decode(s["bytes_hex"].as_str().unwrap()).unwrap();
            let sig = sign_with_context(DOMAIN_EVENT, &primary, &bytes);
            serde_json::Value::String(sig.0.strip_prefix("p256sig:").unwrap().to_string())
        })
        .collect();
    let primary_committed = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": primary_key,
            "encryption_key": primary_enc_key,
            "device_label": "Primary Presence Device",
            "signatures": primary_signatures,
        }),
    )
    .expect("primary commit");
    let primary_device_id = primary_committed["device_id"].as_str().unwrap().to_string();

    // PREPARE the revoke of the LAST device — must refuse with the typed
    // last-device error (no tap is even asked of the operator).
    let err = handle_identity_device_revoke(
        &store,
        &json!({
            "device_id": primary_device_id,
            "authority_device_key": primary_key,
            "reason": "would brick",
        }),
    )
    .await
    .unwrap_err();
    // META-V030-DEVICE-REVOKE-ERROR-CODE-SUBSPACE: the structural
    // last-presence-device guard surfaces -32032 (split out of the
    // generic -32030 presence-refusal bucket) so the CLI can render a
    // typed "enroll a replacement first" affordance instead of the
    // generic "presence locked" help. Anchor:
    // device_revoke_last_device_distinct_error_code_landed.
    assert_eq!(
        err.0, -32032,
        "last-presence-device guard has its own wire code (-32032), got: {}",
        err.0
    );
    assert!(
        err.1.contains("last active presence Device") && err.1.contains("brick"),
        "refusal message must name the structural reason; got: {}",
        err.1
    );
}

// ── V030-EMBER-DEVICE-REVOKE F4.1 — concurrent-COMMIT race regression ──────

/// F4.1 — two concurrent revoke COMMITs targeting the two remaining devices
/// in a 2-device authority set must NOT both succeed.
///
/// Adversarial finding F1.1 / F4.1 on PR #5898: each handler call opens its
/// own `EventStore` from disk; without serialization, two concurrent COMMITs
/// could each independently load materialized state showing 2 devices, each
/// independently pass `revoke_count_active_presence_devices_excluding ≥ 1`,
/// and both append — bricking the authority set despite the structural
/// last-presence-device guard. The fix in `handle_identity_device_revoke`
/// acquires `DaemonStore::identity_mutation_lock` across the open → guard →
/// commit window so the second caller observes the first's commit before
/// re-running its guard.
///
/// This test drives both COMMITs through `handle_identity_device_revoke` via
/// `tokio::join!` and asserts exactly ONE succeeded; the other was refused
/// with the structural last-device error.
#[tokio::test(flavor = "current_thread")]
async fn identity_device_revoke_concurrent_commits_serialize_via_mutation_lock() {
    use core_crypto::{DOMAIN_EVENT, P256Signer, Signer, sign_with_context};

    let dir = tempfile::TempDir::new().unwrap();
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();

    // 1) Bootstrap the operator root via the primary enroll handler.
    let primary = P256Signer::from_scalar_bytes(&[0xA1; 32]).unwrap();
    let primary_key = primary.public_key().0;
    let primary_enc = P256Signer::from_scalar_bytes(&[0xA2; 32]).unwrap();
    let primary_enc_key = primary_enc.public_key().0;
    let primary_prepared = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": primary_key,
            "encryption_key": primary_enc_key,
            "device_label": "Primary Presence Device",
        }),
    )
    .expect("primary prepare");
    let primary_signatures: Vec<serde_json::Value> = primary_prepared["to_sign"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let bytes = hex::decode(s["bytes_hex"].as_str().unwrap()).unwrap();
            let sig = sign_with_context(DOMAIN_EVENT, &primary, &bytes);
            serde_json::Value::String(sig.0.strip_prefix("p256sig:").unwrap().to_string())
        })
        .collect();
    let primary_committed = handle_identity_device_enroll(
        &store,
        &json!({
            "device_key": primary_key,
            "encryption_key": primary_enc_key,
            "device_label": "Primary Presence Device",
            "signatures": primary_signatures,
        }),
    )
    .expect("primary commit");
    let primary_device_id = primary_committed["device_id"].as_str().unwrap().to_string();

    // 2) Enroll a backup Device — now the authority set has TWO presence keys
    //    (the structural floor MIN_ACTIVE_PRESENCE_DEVICES_AFTER_REVOKE is 1,
    //    so EITHER device is individually revocable but BOTH together is not).
    let backup = P256Signer::from_scalar_bytes(&[0xA3; 32]).unwrap();
    let backup_key = backup.public_key().0;
    let backup_enc = P256Signer::from_scalar_bytes(&[0xA4; 32]).unwrap();
    let backup_enc_key = backup_enc.public_key().0;
    let backup_prepared = handle_identity_device_enroll_backup(
        &store,
        &json!({
            "authority_device_key": primary_key,
            "device_key": backup_key,
            "encryption_key": backup_enc_key,
            "device_label": "Backup Presence Device",
        }),
    )
    .expect("backup prepare");
    let backup_steps = backup_prepared["to_sign"].as_array().unwrap();
    let bytes = hex::decode(backup_steps[0]["bytes_hex"].as_str().unwrap()).unwrap();
    let sig = sign_with_context(DOMAIN_EVENT, &primary, &bytes);
    let der_hex = sig.0.strip_prefix("p256sig:").unwrap().to_string();
    let backup_committed = handle_identity_device_enroll_backup(
        &store,
        &json!({
            "authority_device_key": primary_key,
            "device_key": backup_key,
            "encryption_key": backup_enc_key,
            "device_label": "Backup Presence Device",
            "signatures": [der_hex],
        }),
    )
    .expect("backup commit");
    let backup_device_id = backup_committed["device_id"].as_str().unwrap().to_string();

    // 3) PREPARE both revokes — each signed by the OTHER device (the
    //    authority must itself be an Active presence Device; once a device
    //    is revoked it cannot authorize its own revoke). Primary signs the
    //    revoke of backup; backup signs the revoke of primary.
    let revoke_backup_prepared = handle_identity_device_revoke(
        &store,
        &json!({
            "device_id": backup_device_id,
            "authority_device_key": primary_key,
            "reason": "race-A: revoke backup",
        }),
    )
    .await
    .expect("revoke backup prepare");
    let backup_revoke_bytes = hex::decode(
        revoke_backup_prepared["to_sign"][0]["bytes_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let backup_revoke_sig = sign_with_context(DOMAIN_EVENT, &primary, &backup_revoke_bytes);
    let backup_revoke_der = backup_revoke_sig
        .0
        .strip_prefix("p256sig:")
        .unwrap()
        .to_string();

    let revoke_primary_prepared = handle_identity_device_revoke(
        &store,
        &json!({
            "device_id": primary_device_id,
            "authority_device_key": backup_key,
            "reason": "race-B: revoke primary",
        }),
    )
    .await
    .expect("revoke primary prepare");
    let primary_revoke_bytes = hex::decode(
        revoke_primary_prepared["to_sign"][0]["bytes_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let primary_revoke_sig = sign_with_context(DOMAIN_EVENT, &backup, &primary_revoke_bytes);
    let primary_revoke_der = primary_revoke_sig
        .0
        .strip_prefix("p256sig:")
        .unwrap()
        .to_string();

    // 4) Concurrent COMMITs via `tokio::join!`. The identity-mutation lock
    //    serializes them so the second-to-acquire opens its `EventStore`
    //    AFTER the first's commit has flushed — its pre-flight then sees
    //    only one active presence Device and the last-device guard fires.
    //
    //    `let` bindings for the params are required so the temporaries
    //    outlive the `tokio::join!` (the futures borrow them by reference).
    let params_a = json!({
        "device_id": backup_device_id,
        "authority_device_key": primary_key,
        "reason": "race-A: revoke backup",
        "signatures": [backup_revoke_der],
    });
    let params_b = json!({
        "device_id": primary_device_id,
        "authority_device_key": backup_key,
        "reason": "race-B: revoke primary",
        "signatures": [primary_revoke_der],
    });
    let commit_backup = handle_identity_device_revoke(&store, &params_a);
    let commit_primary = handle_identity_device_revoke(&store, &params_b);
    let (result_a, result_b) = tokio::join!(commit_backup, commit_primary);

    // 5) Exactly ONE must succeed; the other must be refused with the
    //    structural last-device error. The bug (without the mutation
    //    lock) would let both succeed — bricking the authority set.
    let oks = [&result_a, &result_b].iter().filter(|r| r.is_ok()).count();
    let errs = [&result_a, &result_b].iter().filter(|r| r.is_err()).count();
    assert_eq!(
        oks, 1,
        "exactly one concurrent revoke must succeed; got a={:?} b={:?}",
        result_a, result_b
    );
    assert_eq!(
        errs, 1,
        "exactly one concurrent revoke must be refused; got a={:?} b={:?}",
        result_a, result_b
    );

    // The failing one must carry the structural last-device error (not a
    // generic conflict / signature failure) so the operator gets the right
    // diagnostic.
    let err = if let Err(e) = &result_a {
        e
    } else if let Err(e) = &result_b {
        e
    } else {
        panic!("at least one must be Err — exactly-one check above")
    };
    // META-V030-DEVICE-REVOKE-ERROR-CODE-SUBSPACE: the second-to-acquire
    // COMMIT hits the structural last-presence-device guard re-run inside
    // `commit_device_revoke` (the mutation lock serialized the window so
    // the second handler call now sees a 1-device authority set). That
    // refusal surfaces -32032 (split out of the generic -32030 bucket) so
    // the CLI can render the typed "enroll a replacement first" affordance.
    // Anchor: device_revoke_last_device_distinct_error_code_landed.
    assert_eq!(
        err.0, -32032,
        "second-to-acquire must hit the typed last-presence-device guard code; got {:?}",
        err
    );
    assert!(
        err.1.contains("last active presence Device") && err.1.contains("brick"),
        "second-to-acquire must hit the structural last-device guard; got: {}",
        err.1
    );

    // 6) Final disk state: exactly one device is Active, the other Revoked.
    //    Bricking would leave ZERO Active devices.
    let identity_store =
        crate::infra::identity_substrate::open_identity_store(store.data_dir().unwrap()).unwrap();
    let state = identity_store.materialized();
    let active =
        crate::infra::operator_identity::active_presence_device_keys_under_operator_root(state);
    assert_eq!(
        active.len(),
        1,
        "authority set must retain exactly one active presence Device — the lock prevents both revokes from landing (would brick to 0)"
    );
}
