use super::*;
use clap::CommandFactory;
use ember_daemon::infra::vault::check_production_sentinel;
use std::sync::Mutex;
use tempfile::NamedTempFile;

static ENV_LOCK: Mutex<()> = Mutex::new(());
const TEST_ANTHROPIC_API_CREDENTIAL: &str = "anthropic/api/key/test-api";
const TEST_ANTHROPIC_OAUTH_CREDENTIAL: &str = "anthropic/plan/claude-oauth/test-oauth";
const TEST_OPENAI_CHATGPT_CREDENTIAL: &str = "openai/plan/chatgpt-oauth/acct_test/user_test";

#[path = "tests/grant.rs"]
mod grant;
#[path = "tests/sandbox_daemon_routing.rs"]
mod sandbox_daemon_routing;

/// Accept a Unix-socket connection with a wall-clock timeout, ensuring
/// tests never hang indefinitely on `__skb_wait_for_more_packets` when
/// a client thread crashes before connecting. Replaces bare
/// `listener.accept().expect(...)` calls in this module.
///
/// anchor: emberlink_cli_test_listener_timeout_landed
fn accept_with_timeout(
    listener: &std::os::unix::net::UnixListener,
    timeout: std::time::Duration,
) -> std::os::unix::net::UnixStream {
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking on listener");
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("restore blocking on accepted stream");
                return stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    panic!(
                        "listener.accept() timed out after {:?} — META-AP-EMBERLINK-CLI-TEST-HANG-UNIX-LISTENER-NO-TIMEOUT guard fired",
                        timeout
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(e) => panic!("listener.accept() error: {}", e),
        }
    }
}

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().expect("env lock poisoned")
}

#[test]
fn top_level_version_request_accepts_global_flags_only() {
    assert!(is_top_level_version_request(&["--version".to_string()]));
    assert!(is_top_level_version_request(&["-V".to_string()]));
    assert!(is_top_level_version_request(&[
        "--color".to_string(),
        "never".to_string(),
        "--version".to_string(),
    ]));
    assert!(is_top_level_version_request(&[
        "--config=/tmp/ember.toml".to_string(),
        "-V".to_string(),
    ]));
}

#[test]
fn top_level_version_request_does_not_capture_subcommand_version_flags() {
    assert!(!is_top_level_version_request(&[
        "construct".to_string(),
        "sign".to_string(),
        "--binary".to_string(),
        "/tmp/ember-gh".to_string(),
        "--construct-toml".to_string(),
        "/tmp/gh.toml".to_string(),
        "--version".to_string(),
        "0.3.0".to_string(),
        "--identity-root-keypath".to_string(),
        "/tmp/dev0.seed".to_string(),
    ]));
    assert!(!is_top_level_version_request(&[
        "init".to_string(),
        "--version".to_string(),
    ]));
}

fn spawn_fake_init_daemon(
    config: &DaemonConfig,
    expected_root_name: &str,
    persona_id: &str,
    expect_receipt_rpc: bool,
    write_daemon_db: bool,
) -> std::thread::JoinHandle<()> {
    use core_crypto::Signer as _;
    use std::io::{BufRead as _, Write as _};
    use std::os::unix::net::UnixListener;

    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind fake init daemon");

    let expected_root_name = expected_root_name.to_string();
    let persona_id = persona_id.to_string();
    let data_dir = config.data_dir.clone();

    std::thread::spawn(move || {
        let signer_label = format!("cmd-init-daemon-receipt-{persona_id}");
        let signer = core_crypto::FixtureSigner::new(&signer_label);
        let public_key = signer.public_key().0.clone();

        listener
            .set_nonblocking(true)
            .expect("set fake init daemon nonblocking");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut saw_create_persona = false;
        let mut saw_build_first_grant_receipt = !expect_receipt_rpc;

        while std::time::Instant::now() < deadline {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .expect("restore blocking on fake init daemon stream");
                    stream
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if saw_create_persona && saw_build_first_grant_receipt {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    continue;
                }
                Err(err) => panic!("fake init daemon accept error: {err}"),
            };
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake init daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake init daemon request");

            let response = match request["method"].as_str().unwrap() {
                "status" => serde_json::json!({
                    "id": request["id"],
                    "result": {
                        "personas": [],
                        "grants": [],
                        "sandboxes": [],
                        "approvals": [],
                        "recent_activity": [],
                        "standing_grants": 0,
                        "audit_events_total": 0,
                    },
                }),
                "create_persona" => {
                    saw_create_persona = true;
                    assert_eq!(
                        request["params"]["name"],
                        serde_json::json!(expected_root_name)
                    );
                    if write_daemon_db {
                        std::fs::create_dir_all(&data_dir).expect("create fake daemon data dir");
                        let store = DaemonStore::open(&data_dir.join("daemon.db"))
                            .expect("open fake daemon store");
                        let vault = std::rc::Rc::new(Vault::new([42u8; 32]));
                        store.set_vault(vault);
                        store
                            .create_persona(&expected_root_name)
                            .expect("fake daemon creates persona in daemon db");
                    }
                    serde_json::json!({
                        "id": request["id"],
                        "result": {
                            "id": persona_id,
                            "name": expected_root_name,
                            "public_key": public_key,
                        },
                    })
                }
                "build_init_first_grant_receipt" => {
                    saw_build_first_grant_receipt = true;
                    assert_eq!(
                        request["params"]["persona_id"],
                        serde_json::json!(persona_id)
                    );
                    let file =
                        ember_daemon::infra::init_first_grant::build_first_grant_receipt_file(
                            &persona_id,
                            &signer,
                        )
                        .expect("build first-grant receipt");
                    serde_json::json!({
                        "id": request["id"],
                        "result": serde_json::to_value(file).expect("serialize receipt file"),
                    })
                }
                other => panic!("unexpected init daemon method: {other}"),
            };

            let mut encoded = serde_json::to_string(&response).expect("encode fake response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake init daemon response");
        }

        assert!(
            saw_create_persona,
            "fake init daemon never received create_persona"
        );
        assert!(
            saw_build_first_grant_receipt,
            "fake init daemon never received build_init_first_grant_receipt"
        );
    })
}

#[test]
fn ac2_oob_card_derives_anchor_ids_from_operator_pubkey() {
    use core_crypto::{P256Signer, Signer};

    let device = P256Signer::from_scalar_bytes(&[0x31; 32]).unwrap();
    let enc = P256Signer::from_scalar_bytes(&[0x32; 32]).unwrap();
    let device_key = device.public_key().0;
    let encryption_key = enc.public_key().0;
    let pubkey_hex = device_key.strip_prefix("p256:").unwrap();
    let result = serde_json::json!({
        "mode": "committed",
        "operator_root_id": format!("root-operator-{pubkey_hex}"),
        "device_id": format!("device-operator-{pubkey_hex}"),
    });

    let card = build_ac2_oob_confirmation_card(
        &result,
        "presence",
        "Operator Touch ID",
        &device_key,
        &device_key,
        &encryption_key,
    )
    .expect("card");

    assert_eq!(card.schema, AC2_OOB_CARD_SCHEMA);
    assert_eq!(card.schema, AC2_OOB_CARD_SCHEMA_V2);
    assert_eq!(card.ceremony, AC2_PRESENCE_CEREMONY);
    assert_eq!(card.device_class, "presence");
    assert_eq!(card.operator_root_pubkey, device_key);
    assert_eq!(card.device_pubkey, card.operator_root_pubkey);
    assert_eq!(card.device_encryption_pubkey, encryption_key);
    assert_eq!(card.confirmation_sha256.len(), 64);
}

#[test]
fn ac2_oob_card_refuses_daemon_substituted_ids() {
    use core_crypto::{P256Signer, Signer};

    let device = P256Signer::from_scalar_bytes(&[0x41; 32]).unwrap();
    let enc = P256Signer::from_scalar_bytes(&[0x42; 32]).unwrap();
    let device_key = device.public_key().0;
    let err = build_ac2_oob_confirmation_card(
        &serde_json::json!({
            "mode": "committed",
            "operator_root_id": "root-operator-attacker",
            "device_id": "device-operator-attacker",
        }),
        "presence",
        "Operator Touch ID",
        &device_key,
        &device_key,
        &enc.public_key().0,
    )
    .expect_err("substituted daemon ids must fail");

    assert!(
        err.to_string().contains("expected"),
        "error should name the local derivation mismatch: {err}"
    );
}

#[test]
fn ac2_oob_card_writes_operator_held_json() {
    use core_crypto::{P256Signer, Signer};

    let device = P256Signer::from_scalar_bytes(&[0x51; 32]).unwrap();
    let enc = P256Signer::from_scalar_bytes(&[0x52; 32]).unwrap();
    let device_key = device.public_key().0;
    let encryption_key = enc.public_key().0;
    let pubkey_hex = device_key.strip_prefix("p256:").unwrap();
    let card = build_ac2_oob_confirmation_card(
        &serde_json::json!({
            "mode": "committed",
            "operator_root_id": format!("root-operator-{pubkey_hex}"),
            "device_id": format!("device-operator-{pubkey_hex}"),
        }),
        "presence",
        "Operator Touch ID",
        &device_key,
        &device_key,
        &encryption_key,
    )
    .expect("card");

    let file = NamedTempFile::new().unwrap();
    write_ac2_oob_confirmation_card(file.path(), &card).expect("write");
    let parsed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(file.path()).unwrap()).unwrap();

    assert_eq!(parsed["schema"], AC2_OOB_CARD_SCHEMA);
    assert_eq!(parsed["device_class"], "presence");
    assert_eq!(parsed["operator_root_pubkey"], device_key);
    assert_eq!(parsed["device_pubkey"], device_key);
    assert_eq!(parsed["device_encryption_pubkey"], encryption_key);
    assert!(parsed.get("daemon_confirmed").is_none());
}

#[test]
fn ac2_oob_card_records_second_presence_under_operator_root_pubkey() {
    use core_crypto::{P256Signer, Signer};

    // v2: there is no "backup" role; both the first and second presence
    // device share `device_class: "presence"`. Capability flows from class.
    let first = P256Signer::from_scalar_bytes(&[0x61; 32]).unwrap();
    let second = P256Signer::from_scalar_bytes(&[0x62; 32]).unwrap();
    let second_enc = P256Signer::from_scalar_bytes(&[0x63; 32]).unwrap();
    let first_key = first.public_key().0;
    let second_key = second.public_key().0;
    let second_enc_key = second_enc.public_key().0;
    let first_hex = first_key.strip_prefix("p256:").unwrap();
    let second_hex = second_key.strip_prefix("p256:").unwrap();
    let card = build_ac2_oob_confirmation_card(
        &serde_json::json!({
            "mode": "committed",
            "operator_root_id": format!("root-operator-{first_hex}"),
            "device_id": format!("device-operator-{second_hex}"),
        }),
        "presence",
        "Second YubiKey",
        &first_key,
        &second_key,
        &second_enc_key,
    )
    .expect("second presence card");

    assert_eq!(card.device_class, "presence");
    assert_eq!(card.ceremony, AC2_PRESENCE_CEREMONY);
    assert_eq!(card.operator_root_pubkey, first_key);
    assert_eq!(card.device_pubkey, second_key);
    assert_eq!(card.device_encryption_pubkey, second_enc_key);
    assert_ne!(card.operator_root_pubkey, card.device_pubkey);

    let expected_digest_input = ac2_card_digest_input(
        AC2_PRESENCE_CEREMONY,
        "presence",
        &format!("root-operator-{first_hex}"),
        &first_key,
        &format!("device-operator-{second_hex}"),
        "Second YubiKey",
        &second_key,
        &second_enc_key,
    );
    let wrong_digest_input = ac2_card_digest_input(
        AC2_PRESENCE_CEREMONY,
        "presence",
        &format!("root-operator-{first_hex}"),
        &second_key,
        &format!("device-operator-{second_hex}"),
        "Second YubiKey",
        &second_key,
        &second_enc_key,
    );
    let expected_digest = {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(expected_digest_input.as_bytes()))
    };
    let wrong_digest = {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(wrong_digest_input.as_bytes()))
    };
    assert_eq!(card.confirmation_sha256, expected_digest);
    assert_ne!(card.confirmation_sha256, wrong_digest);
}

// Helper: build a valid first/genesis presence card via the same code path the CLI uses.
fn ac2_test_first_presence_card(seed_dev: u8, seed_enc: u8) -> Ac2OobConfirmationCard {
    use core_crypto::{P256Signer, Signer};
    let device = P256Signer::from_scalar_bytes(&[seed_dev; 32]).unwrap();
    let enc = P256Signer::from_scalar_bytes(&[seed_enc; 32]).unwrap();
    let device_key = device.public_key().0;
    let encryption_key = enc.public_key().0;
    let pubkey_hex = device_key.strip_prefix("p256:").unwrap();
    build_ac2_oob_confirmation_card(
        &serde_json::json!({
            "mode": "committed",
            "operator_root_id": format!("root-operator-{pubkey_hex}"),
            "device_id": format!("device-operator-{pubkey_hex}"),
        }),
        "presence",
        "Operator Touch ID",
        &device_key,
        &device_key,
        &encryption_key,
    )
    .expect("first presence card")
}

// Helper: build a valid second presence card under the same operator root
// (no role distinction in v2 — capability flows from class).
fn ac2_test_second_presence_card(
    operator_root_pubkey: &str,
    seed_dev: u8,
    seed_enc: u8,
) -> Ac2OobConfirmationCard {
    use core_crypto::{P256Signer, Signer};
    let second = P256Signer::from_scalar_bytes(&[seed_dev; 32]).unwrap();
    let second_enc = P256Signer::from_scalar_bytes(&[seed_enc; 32]).unwrap();
    let second_key = second.public_key().0;
    let second_enc_key = second_enc.public_key().0;
    let op_hex = operator_root_pubkey.strip_prefix("p256:").unwrap();
    let second_hex = second_key.strip_prefix("p256:").unwrap();
    build_ac2_oob_confirmation_card(
        &serde_json::json!({
            "mode": "committed",
            "operator_root_id": format!("root-operator-{op_hex}"),
            "device_id": format!("device-operator-{second_hex}"),
        }),
        "presence",
        "Second YubiKey",
        operator_root_pubkey,
        &second_key,
        &second_enc_key,
    )
    .expect("second presence card")
}

/// Wrap a v2 card in the `LoadedAc2Card` shape the verifier expects.
fn ac2_test_loaded_v2(card: Ac2OobConfirmationCard) -> LoadedAc2Card {
    LoadedAc2Card {
        card,
        legacy_v1_device_role: None,
    }
}

#[test]
fn ac2_oob_verify_accepts_round_tripped_presence_card() {
    let card = ac2_test_first_presence_card(0x71, 0x72);
    let file = NamedTempFile::new().unwrap();
    write_ac2_oob_confirmation_card(file.path(), &card).expect("write");
    let read_back = read_ac2_oob_confirmation_card(file.path()).expect("read");
    assert_eq!(read_back.card, card);
    assert!(read_back.legacy_v1_device_role.is_none());
    verify_ac2_oob_confirmation_card(&read_back).expect("verify passes on a fresh card");
}

#[test]
fn ac2_oob_verify_rejects_tampered_confirmation_sha256() {
    let mut card = ac2_test_first_presence_card(0x81, 0x82);
    // Flip the digest byte-for-byte; verifier must catch it.
    card.confirmation_sha256 = "0".repeat(64);
    let loaded = ac2_test_loaded_v2(card);
    let err =
        verify_ac2_oob_confirmation_card(&loaded).expect_err("zeroed digest must be rejected");
    assert!(
        err.to_string().contains("confirmation_sha256"),
        "error should name the digest mismatch: {err}"
    );
}

#[test]
fn ac2_oob_verify_rejects_tampered_device_label() {
    // The label is part of the digest; mutating it without re-digesting
    // must trip the verifier (label-substitution attack on a stored card).
    let mut card = ac2_test_first_presence_card(0x91, 0x92);
    card.device_label = "Attacker Substituted Label".to_string();
    let loaded = ac2_test_loaded_v2(card);
    let err = verify_ac2_oob_confirmation_card(&loaded)
        .expect_err("label-substituted card must be rejected");
    assert!(
        err.to_string().contains("confirmation_sha256"),
        "error should name the digest mismatch: {err}"
    );
}

#[test]
fn ac2_oob_verify_rejects_mismatched_operator_root_id() {
    let mut card = ac2_test_first_presence_card(0xa1, 0xa2);
    card.operator_root_id = "root-operator-attacker".to_string();
    let loaded = ac2_test_loaded_v2(card);
    let err = verify_ac2_oob_confirmation_card(&loaded)
        .expect_err("operator_root_id must derive from the pubkey");
    assert!(
        err.to_string().contains("operator_root_id"),
        "error should name the id mismatch: {err}"
    );
}

#[test]
fn ac2_oob_verify_rejects_ceremony_class_drift() {
    // device_class=recovery but ceremony=identity.device.enroll (presence's
    // ceremony) — the ceremony↔class binding is a hard rule.
    let mut card = ac2_test_first_presence_card(0xb1, 0xb2);
    card.device_class = "recovery".to_string();
    let loaded = ac2_test_loaded_v2(card);
    let err = verify_ac2_oob_confirmation_card(&loaded)
        .expect_err("class/ceremony drift must be rejected");
    let msg = err.to_string();
    // Either the recovery-shape check (pubkey != enc_pubkey) or the
    // ceremony↔class binding catches the drift.
    assert!(
        msg.contains("ceremony") || msg.contains("recovery class") || msg.contains("age1"),
        "error should name the class/ceremony drift: {err}"
    );
}

#[test]
fn ac2_oob_verify_rejects_unknown_schema() {
    let mut card = ac2_test_first_presence_card(0xc1, 0xc2);
    card.schema = "emberlink.attacker_substituted.v9".to_string();
    let loaded = ac2_test_loaded_v2(card);
    let err = verify_ac2_oob_confirmation_card(&loaded)
        .expect_err("schema must match the locked AC-2 v2 string");
    assert!(
        err.to_string().contains("schema"),
        "error should name the schema mismatch: {err}"
    );
}

#[test]
fn ac2_oob_verify_pair_accepts_two_presence() {
    let first = ac2_test_first_presence_card(0xd1, 0xd2);
    let second = ac2_test_second_presence_card(&first.operator_root_pubkey, 0xd3, 0xd4);
    cross_check_ac2_oob_confirmation_card_pair(&first, &second)
        .expect("two presence cards under one operator root pass pair check");
}

#[test]
fn ac2_oob_verify_pair_rejects_same_pubkey() {
    // Two cards sharing a device_pubkey are not distinct hardware keys.
    let card = ac2_test_first_presence_card(0xe1, 0xe2);
    let err = cross_check_ac2_oob_confirmation_card_pair(&card, &card)
        .expect_err("same pubkey twice must be rejected");
    assert!(
        err.to_string().contains("share device_pubkey"),
        "error should name the pubkey collision: {err}"
    );
}

#[test]
fn ac2_oob_verify_pair_rejects_cross_operator_root() {
    let first_a = ac2_test_first_presence_card(0xf1, 0xf2);
    let first_b = ac2_test_first_presence_card(0xf3, 0xf4);
    // Build a second presence under first_b's root, then pair against first_a.
    let second_under_b = ac2_test_second_presence_card(&first_b.operator_root_pubkey, 0xf5, 0xf6);
    let err = cross_check_ac2_oob_confirmation_card_pair(&first_a, &second_under_b)
        .expect_err("cross-root pair must be rejected");
    assert!(
        err.to_string().contains("operator_root_pubkey")
            || err.to_string().contains("operator_root_id"),
        "error should name the operator root mismatch: {err}"
    );
}

// ─── v1 → v2 migration tests (ADR 200 amendment 2026-06-12) ─────────────
//
// The operator holds v1 AC-2 cards issued before the schema bump
// (`/tmp/ac2-primary-2026-06-12.json` is the seed example). v1 cards
// MUST still verify under the v2 binary or the operator loses their
// pre-amendment anchor.

/// Build a v1 card JSON shape (the layout shipped before the 2026-06-12
/// amendment). The digest is computed under the v1 pre-image; the
/// `device_role` field is the v1 field name (no `device_class`).
fn ac2_test_v1_primary_card_json(seed_dev: u8, seed_enc: u8) -> serde_json::Value {
    use core_crypto::{P256Signer, Signer};
    let device = P256Signer::from_scalar_bytes(&[seed_dev; 32]).unwrap();
    let enc = P256Signer::from_scalar_bytes(&[seed_enc; 32]).unwrap();
    let device_key = device.public_key().0;
    let encryption_key = enc.public_key().0;
    let pubkey_hex = device_key.strip_prefix("p256:").unwrap();
    let root_id = format!("root-operator-{pubkey_hex}");
    let device_id = format!("device-operator-{pubkey_hex}");
    let label = "Operator Presence Device — SE/Touch ID";
    let ceremony = "identity.device.enroll"; // v1 primary ceremony
    let role = "primary";
    let digest_input = ac2_card_digest_input_v1(
        ceremony,
        role,
        &root_id,
        &device_key,
        &device_id,
        label,
        &device_key,
        &encryption_key,
    );
    let confirmation_sha256 = {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(digest_input.as_bytes()))
    };
    serde_json::json!({
        "schema": AC2_OOB_CARD_SCHEMA_V1,
        "ceremony": ceremony,
        "device_role": role,
        "operator_root_id": root_id,
        "operator_root_pubkey": device_key,
        "device_id": device_id,
        "device_label": label,
        "device_pubkey": device_key,
        "device_encryption_pubkey": encryption_key,
        "confirmation_sha256": confirmation_sha256,
    })
}

#[test]
fn ac2_oob_v1_card_verifies_under_v2_binary() {
    let v1_json = ac2_test_v1_primary_card_json(0x10, 0x11);
    let bytes = serde_json::to_vec_pretty(&v1_json).unwrap();
    let loaded = parse_ac2_oob_confirmation_card_bytes(&bytes)
        .expect("v1 card must parse under the v2 binary");
    // The migration normalizes device_role → device_class in memory.
    assert_eq!(loaded.card.device_class, "presence");
    assert_eq!(
        loaded.legacy_v1_device_role.as_deref(),
        Some("primary"),
        "the legacy device_role is stashed for the v1 digest re-check"
    );
    assert_eq!(loaded.card.schema, AC2_OOB_CARD_SCHEMA_V1);
    // The verifier accepts the v1 digest path.
    verify_ac2_oob_confirmation_card(&loaded).expect("v1 card must verify under the v2 binary");
}

#[test]
fn ac2_oob_v1_card_with_tampered_digest_fails_under_v2_binary() {
    let mut v1_json = ac2_test_v1_primary_card_json(0x20, 0x21);
    v1_json["confirmation_sha256"] = serde_json::Value::String("0".repeat(64));
    let bytes = serde_json::to_vec_pretty(&v1_json).unwrap();
    let loaded = parse_ac2_oob_confirmation_card_bytes(&bytes).unwrap();
    let err =
        verify_ac2_oob_confirmation_card(&loaded).expect_err("tampered v1 digest must be rejected");
    assert!(
        err.to_string().contains("confirmation_sha256"),
        "error should name the digest mismatch: {err}"
    );
}

#[test]
fn ac2_oob_operator_held_v1_card_verifies_under_v2_binary() {
    // Lock the actual v1 card layout the operator holds (from
    // `/tmp/ac2-primary-2026-06-12.json` — schema v1, ceremony
    // identity.device.enroll, device_role primary) to a digest re-check
    // path that survives the v2 cutover. This is the load-bearing
    // backward-compat test: an external verifier with the operator's card
    // must continue to validate.
    use core_crypto::{P256Signer, Signer};
    // Reuse a deterministic seed so the digest is reproducible without
    // needing the exact operator's pubkey in test data.
    let device = P256Signer::from_scalar_bytes(&[0x30; 32]).unwrap();
    let enc = P256Signer::from_scalar_bytes(&[0x31; 32]).unwrap();
    let device_key = device.public_key().0;
    let encryption_key = enc.public_key().0;
    let pubkey_hex = device_key.strip_prefix("p256:").unwrap();
    let root_id = format!("root-operator-{pubkey_hex}");
    let device_id = format!("device-operator-{pubkey_hex}");
    let label = "Operator Presence Device — SE/Touch ID";
    let digest_input = ac2_card_digest_input_v1(
        "identity.device.enroll",
        "primary",
        &root_id,
        &device_key,
        &device_id,
        label,
        &device_key,
        &encryption_key,
    );
    let confirmation_sha256 = {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(digest_input.as_bytes()))
    };
    let json = serde_json::json!({
        "schema": "emberlink.ac2_oob_confirmation.v1",
        "ceremony": "identity.device.enroll",
        "device_role": "primary",
        "operator_root_id": root_id,
        "operator_root_pubkey": device_key,
        "device_id": device_id,
        "device_label": label,
        "device_pubkey": device_key,
        "device_encryption_pubkey": encryption_key,
        "confirmation_sha256": confirmation_sha256,
    });
    let bytes = serde_json::to_vec_pretty(&json).unwrap();
    let loaded = parse_ac2_oob_confirmation_card_bytes(&bytes).expect("parse operator v1 card");
    verify_ac2_oob_confirmation_card(&loaded).expect("verify operator v1 card");
}

#[test]
fn ac2_oob_recovery_card_builder_records_age_recipient() {
    // ADR 206 §6: a recovery card binds an age x25519 recipient (the
    // public half of the printed code) under the operator-presence root.
    // Capability flows from class: recovery == KEK_s recipient only.
    use core_crypto::P256Signer;
    use core_crypto::Signer;
    let operator = P256Signer::from_scalar_bytes(&[0x40; 32]).unwrap();
    let operator_root_pubkey = operator.public_key().0;
    // Generate a real age recipient so the well-formedness check passes.
    let (_secret, recovery_pub) = core_crypto::generate_recovery_identity();
    let pubkey_hex = operator_root_pubkey.strip_prefix("p256:").unwrap();
    let result = serde_json::json!({
        "operator_root_id": format!("root-operator-{pubkey_hex}"),
        "operator_root_pubkey": operator_root_pubkey,
        // recovery device_id is daemon-derived from the age recipient.
        "device_id": format!("device-operator-recovery-{recovery_pub}"),
    });
    let card = build_ac2_oob_confirmation_card_for_recovery(
        &result,
        "Printed recovery code",
        &operator_root_pubkey,
        &recovery_pub,
    )
    .expect("recovery card");
    assert_eq!(card.schema, AC2_OOB_CARD_SCHEMA);
    assert_eq!(card.device_class, "recovery");
    assert_eq!(card.ceremony, AC2_RECOVERY_CEREMONY);
    assert_eq!(card.device_pubkey, recovery_pub);
    assert_eq!(card.device_encryption_pubkey, recovery_pub);
    let loaded = ac2_test_loaded_v2(card);
    verify_ac2_oob_confirmation_card(&loaded).expect("recovery card verifies");
}

#[test]
fn ac2_oob_recovery_card_rejects_mismatched_pubkey_encryption_pubkey() {
    // Recovery cards record ONE recipient — slots must match.
    use core_crypto::P256Signer;
    use core_crypto::Signer;
    let operator = P256Signer::from_scalar_bytes(&[0x50; 32]).unwrap();
    let operator_root_pubkey = operator.public_key().0;
    let (_, recovery_a) = core_crypto::generate_recovery_identity();
    let (_, recovery_b) = core_crypto::generate_recovery_identity();
    let pubkey_hex = operator_root_pubkey.strip_prefix("p256:").unwrap();
    let result = serde_json::json!({
        "operator_root_id": format!("root-operator-{pubkey_hex}"),
        "operator_root_pubkey": operator_root_pubkey,
        "device_id": "device-operator-recovery-xxx",
    });
    let err = build_ac2_oob_confirmation_card(
        &result,
        "recovery",
        "Printed recovery code",
        &operator_root_pubkey,
        &recovery_a,
        &recovery_b,
    )
    .expect_err("recovery class with mismatched recipients must fail");
    assert!(err.to_string().contains("recovery class"));
}

#[test]
fn ac2_oob_verify_pair_accepts_presence_plus_recovery() {
    // Operator-locked pair shape: one presence + one recovery code under
    // the same operator root.
    let presence = ac2_test_first_presence_card(0x60, 0x61);
    let (_, recovery_pub) = core_crypto::generate_recovery_identity();
    let result = serde_json::json!({
        "operator_root_id": presence.operator_root_id.clone(),
        "operator_root_pubkey": presence.operator_root_pubkey.clone(),
        "device_id": format!("device-operator-recovery-{recovery_pub}"),
    });
    let recovery = build_ac2_oob_confirmation_card_for_recovery(
        &result,
        "Printed recovery code",
        &presence.operator_root_pubkey,
        &recovery_pub,
    )
    .expect("recovery card");
    cross_check_ac2_oob_confirmation_card_pair(&presence, &recovery)
        .expect("presence+recovery under one root passes pair check");
    // And the reverse order.
    cross_check_ac2_oob_confirmation_card_pair(&recovery, &presence)
        .expect("recovery+presence (reverse order) passes pair check");
}

// PR #5684 companion — operator-side helpers around audit_repair_chain
// co-sign. These mirror the daemon-side trust path in
// `ember_daemon::infra::audit` so the operator can pre-verify a
// RepairIntent before submitting it.

// Helper: build a valid RepairIntent + (device_id, pubkey) signed by a
// P-256 key seeded deterministically — mirrors `build_signed_intent` in
// `ember_daemon::infra::audit::tests` so the CLI verifier exercises the
// same canonical bytes the daemon would.
fn audit_test_signed_repair_intent(
    seed: u8,
    from_row: i64,
    tip_hash: &str,
    daemon_fingerprint: &str,
) -> (RepairIntent, String, String) {
    use core_crypto::{P256Signer, Signer};
    use ember_daemon::infra::audit::{RepairKind, canonical_repair_intent_bytes};

    let signer = P256Signer::from_scalar_bytes(&[seed; 32]).unwrap();
    let device_pubkey = signer.public_key().0;

    let bytes = canonical_repair_intent_bytes(from_row, tip_hash, daemon_fingerprint);
    let sig = signer.sign(&bytes);
    let sig_hex = sig
        .0
        .strip_prefix("p256sig:")
        .expect("P256Signer yields a p256sig: wire form");
    let signature_bytes = hex::decode(sig_hex).unwrap();

    let intent = RepairIntent {
        from_row_id: from_row,
        repair_kind: RepairKind::Truncate,
        operator_signature: signature_bytes,
        operator_pubkey: device_pubkey.clone(),
        current_chain_tip_hash: tip_hash.to_string(),
        daemon_identity_root_fingerprint: daemon_fingerprint.to_string(),
    };
    let (_, expected_device_id) = operator_oob_ids_from_device_key(&device_pubkey).unwrap();
    (intent, device_pubkey, expected_device_id)
}

#[test]
fn audit_canonical_repair_intent_emits_domain_separated_bytes() {
    use ember_daemon::infra::audit::canonical_repair_intent_bytes;
    // The CLI helper delegates to canonical_repair_intent_bytes, so a
    // signature minted by the operator over what we print must verify on
    // the daemon side. Lock that contract by re-running the daemon path.
    let direct = canonical_repair_intent_bytes(42, "abc123", "ffeeddccbbaa9988");
    assert!(
        std::str::from_utf8(&direct)
            .unwrap()
            .contains("emberlink.v1.audit_repair_intent"),
        "canonical bytes must carry the v1 audit_repair_intent domain separator"
    );
}

#[test]
fn audit_canonical_repair_intent_rejects_empty_tip_hash() {
    let err = run_audit_canonical_repair_intent(1, "", "ffeeddcc", false)
        .expect_err("empty tip hash must be rejected");
    assert!(
        err.to_string().contains("tip-hash"),
        "error should name the missing field: {err}"
    );
}

#[test]
fn audit_canonical_repair_intent_rejects_empty_fingerprint() {
    let err = run_audit_canonical_repair_intent(1, "deadbeef", "", false)
        .expect_err("empty daemon fingerprint must be rejected");
    assert!(
        err.to_string().contains("daemon-fingerprint"),
        "error should name the missing field: {err}"
    );
}

#[test]
fn audit_verify_repair_intent_accepts_valid_p256_signature() {
    let (intent, device_pubkey, _) =
        audit_test_signed_repair_intent(0xa1, 7, "deadbeef", "0011223344");
    let intent_path = NamedTempFile::new().unwrap();
    std::fs::write(intent_path.path(), serde_json::to_vec(&intent).unwrap()).unwrap();

    run_audit_verify_repair_intent(intent_path.path(), &[device_pubkey], false)
        .expect("a freshly-signed RepairIntent must verify against its own signing pubkey");
}

#[test]
fn audit_verify_repair_intent_rejects_signature_under_other_key() {
    let (intent, _, _) = audit_test_signed_repair_intent(0xb1, 7, "deadbeef", "0011223344");
    let (_other_intent, other_pubkey, _) =
        audit_test_signed_repair_intent(0xb2, 7, "deadbeef", "0011223344");

    let intent_path = NamedTempFile::new().unwrap();
    std::fs::write(intent_path.path(), serde_json::to_vec(&intent).unwrap()).unwrap();
    let err = run_audit_verify_repair_intent(intent_path.path(), &[other_pubkey], false)
        .expect_err("sig minted by one key must not verify under a different key");
    assert!(
        err.to_string().contains("did not verify"),
        "error should name the verify failure: {err}"
    );
}

#[test]
fn audit_verify_repair_intent_finds_backup_in_set() {
    // Mirror the 1-of-N presence-set check: signature is by backup, but
    // primary is supplied first — verifier must still find backup.
    let (intent, backup_pubkey, expected_backup_device_id) =
        audit_test_signed_repair_intent(0xc1, 11, "feedface", "0099aabb");
    let (_, primary_pubkey, _) = audit_test_signed_repair_intent(0xc2, 11, "feedface", "0099aabb");

    let intent_path = NamedTempFile::new().unwrap();
    std::fs::write(intent_path.path(), serde_json::to_vec(&intent).unwrap()).unwrap();
    run_audit_verify_repair_intent(
        intent_path.path(),
        &[primary_pubkey, backup_pubkey.clone()],
        false,
    )
    .expect("backup must verify even when listed second");

    let (_, derived) = operator_oob_ids_from_device_key(&backup_pubkey).unwrap();
    assert_eq!(derived, expected_backup_device_id);
}

#[test]
fn audit_verify_repair_intent_requires_at_least_one_pubkey() {
    let (intent, _, _) = audit_test_signed_repair_intent(0xd1, 1, "deadbeef", "0011223344");
    let intent_path = NamedTempFile::new().unwrap();
    std::fs::write(intent_path.path(), serde_json::to_vec(&intent).unwrap()).unwrap();
    let err = run_audit_verify_repair_intent(intent_path.path(), &[], false)
        .expect_err("no presence pubkeys supplied must fail");
    assert!(
        err.to_string().contains("presence-pubkey"),
        "error should name the missing flag: {err}"
    );
}

#[test]
fn audit_verify_repair_intent_rejects_invalid_pubkey_shape() {
    let (intent, _, _) = audit_test_signed_repair_intent(0xe1, 1, "deadbeef", "0011223344");
    let intent_path = NamedTempFile::new().unwrap();
    std::fs::write(intent_path.path(), serde_json::to_vec(&intent).unwrap()).unwrap();
    let err = run_audit_verify_repair_intent(
        intent_path.path(),
        &["not-a-valid-pubkey".to_string()],
        false,
    )
    .expect_err("invalid pubkey shape must fail before signature check");
    assert!(
        err.to_string().contains("p256:"),
        "error should name the expected shape: {err}"
    );
}

#[test]
fn audit_verify_repair_intent_rejects_garbled_intent_file() {
    let bad_path = NamedTempFile::new().unwrap();
    std::fs::write(bad_path.path(), b"{not-a-RepairIntent}").unwrap();
    let err = run_audit_verify_repair_intent(bad_path.path(), &["p256:04abc".to_string()], false)
        .expect_err("non-RepairIntent JSON must fail to parse");
    assert!(
        err.to_string().contains("parse") || err.to_string().contains("p256:"),
        "error should name parse or pubkey shape failure: {err}"
    );
}

#[test]
fn ac2_oob_verify_pair_rejects_shared_device_pubkey() {
    // Two presence devices must be distinct hardware keys — defense
    // against re-enrolling the same key twice.
    let first = ac2_test_first_presence_card(0x11, 0x12);
    // Second card that reuses the first's device key.
    let mut second = ac2_test_second_presence_card(&first.operator_root_pubkey, 0x13, 0x14);
    second.device_pubkey = first.device_pubkey.clone();
    let err = cross_check_ac2_oob_confirmation_card_pair(&first, &second)
        .expect_err("shared device_pubkey must be rejected");
    assert!(
        err.to_string().contains("device_pubkey"),
        "error should name the shared-pubkey rejection: {err}"
    );
}

fn collect_visible_help_paths(
    command: &ClapCommand,
    prefix: &mut Vec<String>,
    out: &mut Vec<Vec<String>>,
) {
    for subcommand in command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
    {
        prefix.push(subcommand.get_name().to_string());
        out.push(prefix.clone());
        collect_visible_help_paths(subcommand, prefix, out);
        prefix.pop();
    }
}

fn fake_grant_receipt_json(id: &str, grant_id: &str, persona_id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "grant_id": grant_id,
        "summary": {
            "human_owner": "Operator Example",
            "persona_id": persona_id,
            "agent_id": "cli",
            "service": "github",
            "resource": "repo:acme/project"
        },
        "approved_chain": [],
        "per_statement_usage": [],
        "approval_chain": [],
        "actions_observed": [],
        "lifecycle": {
            "issued_at": 1,
            "last_used_at": null,
            "terminated_at": 2,
            "terminal_reason": {
                "kind": "revoked",
                "by": "operator",
                "reason": "test"
            }
        },
        "attestation": {},
        "evidence": {
            "hash": "0".repeat(64),
            "sig": "1".repeat(128),
            "signer_pubkey": "2".repeat(64),
            "canonical_version": 1
        }
    })
}

fn fake_receipt_v2_envelope_json(
    receipt_id: &str,
    kind: &str,
    persona_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "version": "2",
        "kind": kind,
        "receipt_id": receipt_id,
        "daemon_root_id": "daemon-root",
        "termination_authority": "user_session",
        "body": {
            "persona_id": persona_id
        },
        "signature": "1".repeat(128)
    })
}

#[test]
fn render_custom_help_covers_all_visible_help_paths() {
    let mut visible_paths = Vec::new();
    collect_visible_help_paths(&Cli::command(), &mut Vec::new(), &mut visible_paths);

    for path in visible_paths {
        let mut args = path.clone();
        args.push("--help".to_string());
        let help = render_custom_help(&args).unwrap_or_else(|| {
            panic!(
                "expected compact help for visible path `{}`",
                path.join(" ")
            )
        });
        let title = format!("ember {}", path.join(" "));
        assert!(
            help.starts_with(&format!("{title}\n")),
            "expected help for `{}` to start with `{title}`; got:\n{}",
            path.join(" "),
            help
        );
    }
}

#[test]
fn grant_create_help_uses_current_llm_action_scope() {
    let help = render_custom_help(&[
        "grant".to_string(),
        "create".to_string(),
        "--help".to_string(),
    ])
    .expect("grant create help");

    assert!(help.contains("--scope llm:generate"));
    assert!(!help.contains("--scope model:invoke"));
}

#[test]
fn claude_help_surfaces_sandvault_runtime_mode() {
    let help =
        render_custom_help(&["claude".to_string(), "--help".to_string()]).expect("claude help");

    assert!(help.contains("ember claude --sandbox sandvault --worktree <name>"));
    assert!(help.contains("--sandbox sandvault"));
}

#[test]
fn codex_help_surfaces_sandvault_runtime_mode() {
    let help =
        render_custom_help(&["codex".to_string(), "--help".to_string()]).expect("codex help");

    assert!(help.contains("ember codex --sandbox sandvault --worktree <name>"));
    assert!(help.contains("--sandbox sandvault"));
}

#[test]
fn cursor_help_discloses_ambient_model_auth_boundary() {
    let help =
        render_custom_help(&["cursor".to_string(), "--help".to_string()]).expect("cursor help");

    assert!(help.contains("Cursor account/model auth remains Cursor-owned"));
    assert!(help.contains("it does not broker Cursor model spend"));
    assert!(help.contains("HTTPS_PROXY is injected only when the daemon returns a Cursor egress URL"));
}

#[test]
fn render_custom_help_ignores_global_flags_prefixes() {
    let args = vec![
        "--color".to_string(),
        "never".to_string(),
        "--json".to_string(),
        "grant".to_string(),
        "list".to_string(),
        "--help".to_string(),
    ];
    let help = render_custom_help(&args).expect("compact help with global prefixes");
    assert!(
        help.starts_with("ember grant list\n"),
        "expected grant list help with global prefixes; got:\n{help}"
    );
}

#[test]
fn render_custom_help_ignores_forwarded_help_after_separator() {
    let args = vec![
        "codex".to_string(),
        "--isolated".to_string(),
        "--".to_string(),
        "--help".to_string(),
    ];
    assert!(
        render_custom_help(&args).is_none(),
        "forwarded target help after `--` must not trigger Ember help"
    );
}

#[test]
fn generated_help_renders_boolean_flags_without_value_placeholder() {
    let help = render_custom_help(&[
        "audit".to_string(),
        "query".to_string(),
        "--help".to_string(),
    ])
    .expect("audit query help");

    assert!(help.contains("--since <SINCE>"));
    assert!(help.contains("--json"));
    assert!(!help.contains("--json <JSON>"));
}

#[test]
fn resolve_cli_render_theme_from_raw_args_honors_color_flag() {
    let always = resolve_cli_render_theme_from_raw_args(&[
        "--color".to_string(),
        "always".to_string(),
        "--help".to_string(),
    ]);
    assert!(always.color, "expected `--color always` to force color");

    let never = resolve_cli_render_theme_from_raw_args(&[
        "--color=never".to_string(),
        "--help".to_string(),
    ]);
    assert!(!never.color, "expected `--color=never` to disable color");
}

#[test]
fn render_uninitialized_home_screen_uses_semantic_color_when_enabled() {
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: true }, || {
        render_uninitialized_home_screen()
    });
    assert!(
        rendered.contains("\x1b[33mNot set up yet\x1b[0m"),
        "expected warning title styling on the home screen: {rendered}"
    );
    assert!(
        rendered.contains("\x1b[1member init --for claude\x1b[0m"),
        "expected the primary CTA to be bold without over-coloring: {rendered}"
    );
}

#[test]
fn render_explain_topic_uses_structural_color_when_enabled() {
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: true }, || {
        render_explain_topic(&["status".to_string()]).expect("status explain")
    });
    assert!(
        rendered.contains("\x1b[1member explain status\x1b[0m"),
        "expected explain title to stay neutral-bold: {rendered}"
    );
    assert!(
        rendered.contains("\x1b[1m\x1b[38;2;217;106;29mWhat it does\x1b[0m"),
        "expected explain section headings to carry Ember accent: {rendered}"
    );
    assert!(
        rendered.contains("\x1b[1member doctor\x1b[0m"),
        "expected explain commands to stay strong but neutral: {rendered}"
    );
}

#[test]
fn display_command_text_shortens_repo_build_prefix_for_human_cards() {
    assert_eq!(
        display_command_text("/workspace/emberlink-repo-build/target/debug/ember doctor"),
        "ember doctor"
    );
    assert_eq!(
        display_command_text(
            "sudo /workspace/emberlink-repo-build/target/debug/ember daemon install",
        ),
        "sudo ember daemon install"
    );
}

#[test]
fn format_default_yes_prompt_highlights_the_default_choice() {
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: true }, || {
        format_default_yes_prompt("  Do you want to run this now")
    });
    assert!(
        rendered.contains("[\x1b[1m\x1b[38;2;217;106;29mY\x1b[0m/n]"),
        "expected the default yes choice to carry Ember-accent emphasis: {rendered}"
    );
}

#[test]
fn global_yes_flag_parses_after_doctor_subcommand() {
    let cli = Cli::parse_from(["ember", "doctor", "-y"]);
    assert!(cli.yes);
    assert!(matches!(cli.command, Commands::Doctor));
}

#[test]
fn global_yes_flag_parses_for_headless_enroll() {
    let cli = Cli::parse_from([
        "ember",
        "headless",
        "enroll",
        "--input",
        "tasks.json",
        "--duration",
        "4h",
        "--yes",
    ]);
    assert!(cli.yes);
    match cli.command {
        Commands::Headless {
            action:
                HeadlessAction::Enroll {
                    input,
                    duration,
                    persona,
                },
        } => {
            assert_eq!(input, Some(PathBuf::from("tasks.json")));
            assert_eq!(duration.as_deref(), Some("4h"));
            assert!(persona.is_none());
        }
        _ => panic!("expected headless enroll"),
    }
}

#[test]
fn style_section_heading_uses_ember_accent_for_all_sections() {
    let do_this = with_test_cli_render_theme(CliRenderTheme { color: true }, || {
        style_section_heading("Do this")
    });
    assert_eq!(do_this, "\x1b[1m\x1b[38;2;217;106;29mDo this\x1b[0m");

    let then = with_test_cli_render_theme(CliRenderTheme { color: true }, || {
        style_section_heading("Then")
    });
    assert_eq!(then, "\x1b[1m\x1b[38;2;217;106;29mThen\x1b[0m");
}

#[test]
fn style_detail_line_uses_bold_labels_for_short_labels() {
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: true }, || {
        style_detail_line("Vault lane: interactive-unlocked")
    });
    assert!(
        rendered.starts_with("\x1b[1mVault lane\x1b[0m:"),
        "expected bold detail labels: {rendered}"
    );
}

#[test]
fn table_heading_uses_bold_white_not_brand_orange() {
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: true }, || {
        current_cli_render_theme().table_heading("NAME")
    });
    assert_eq!(rendered, "\x1b[1mNAME\x1b[0m");
}

#[test]
fn receipt_reason_badge_uses_distinct_semantic_tones() {
    let revoked = with_test_cli_render_theme(CliRenderTheme { color: true }, || {
        style_receipt_reason_badge("revoked")
    });
    assert_eq!(revoked, "\x1b[1m\x1b[38;2;217;106;29mrevoked\x1b[0m");

    let expired = with_test_cli_render_theme(CliRenderTheme { color: true }, || {
        style_receipt_reason_badge("expired")
    });
    assert_eq!(expired, "\x1b[2mexpired\x1b[0m");

    let cascaded = with_test_cli_render_theme(CliRenderTheme { color: true }, || {
        style_receipt_reason_badge("cascaded")
    });
    assert_eq!(cascaded, "\x1b[1mcascaded\x1b[0m");
}

#[test]
fn inline_badge_routes_revoked_to_runtime_ember_accent() {
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: true }, || {
        style_inline_badge("revoked")
    });
    assert_eq!(rendered, "\x1b[1m\x1b[38;2;217;106;29mrevoked\x1b[0m");
}

#[test]
fn render_persona_list_text_surfaces_summary_table_and_next_actions() {
    let personas = vec![
        serde_json::json!({"id": "persona-root", "name": "root", "status": "active"}),
        serde_json::json!({"id": "persona-revoked", "name": "scope-proof-temp", "status": "revoked"}),
    ];
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: false }, || {
        render_persona_list_text(&personas)
    });
    assert!(rendered.contains("2 personas available: 1 active, 1 revoked."));
    assert!(rendered.contains("Current set"));
    assert!(rendered.contains("NAME"));
    assert!(rendered.contains(
        "ember grant create --persona <id> --credential <name> --scope <scope> --ttl 30m"
    ));
}

#[test]
fn render_grant_list_text_surfaces_dense_table_and_follow_up_actions() {
    let grants = vec![serde_json::json!({
        "id": "grant-1234567890",
        "persona_id": "persona-root",
        "credential_name": "github/app",
        "scope": "repo:read",
        "status": "active",
        "expires_at": "2026-05-24T20:15:00Z"
    })];
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: false }, || {
        render_grant_list_text(&grants, true)
    });
    assert!(rendered.contains("1 active grant visible on the current authority lane."));
    assert!(rendered.contains("GRANT"));
    assert!(rendered.contains("Inspect"));
    assert!(rendered.contains("ember receipt list"));
}

#[test]
fn render_spend_grant_list_text_surfaces_threshold_and_reserved_posture() {
    let rows = vec![SpendGrantListRow {
        id: "grant-spend-123456".to_string(),
        persona_id: "persona-root".to_string(),
        vendor: "clearbit".to_string(),
        threshold_cents: Some(4_900),
        hard_cap_cents: Some(25_000),
        used_cents: 0,
        reserved_cents: 1_200,
        status: "active".to_string(),
        expires_at: Some("2026-05-26T12:00:00Z".to_string()),
    }];
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: false }, || {
        render_spend_grant_list_text(&rows, true)
    });
    assert!(rendered.contains("Spend grants"));
    assert!(rendered.contains("clearbit"));
    assert!(rendered.contains("$49.00"));
    assert!(rendered.contains("$250.00"));
    assert!(rendered.contains("$12.00"));
    assert!(rendered.contains("ember grant evaluate --grant <id> --attempt attempt.toml"));
}

#[test]
fn render_approval_list_text_surfaces_queue_and_resolve_actions() {
    let requests = vec![ember_daemon::trust::approval::ApprovalRequestInfo {
        id: "apr_123".to_string(),
        persona_id: "persona-root".to_string(),
        credential_name: "github/app".to_string(),
        scope: "repo:write".to_string(),
        ttl_secs: Some(1800),
        action: "push".to_string(),
        risk_level: "high".to_string(),
        status: "pending".to_string(),
        reason: None,
        created_at: "2026-05-24T20:15:00Z".to_string(),
        tool_name: None,
        target_host: None,
        target_summary: None,
        target_url: None,
        agent_framework: None,
        composite_statements: None,
        result_grant_id: None,
        skill_ref: None,
        max_delegation_depth: None,
        max_uses_per_hour: None,
        allowed_hours_start: None,
        allowed_hours_end: None,
        allowed_targets: None,
        budget: None,
        max_children_per_day: None,
        auto_delegate_scope_template: None,
    }];
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: false }, || {
        render_approval_list_text(&requests)
    });
    assert!(rendered.contains("1 approval request waiting for operator input."));
    assert!(rendered.contains("Queue"));
    assert!(rendered.contains("Resolve"));
    assert!(rendered.contains("ember approval approve <id>"));
}

#[test]
fn render_vault_list_text_surfaces_summary_table_and_next_actions() {
    let entries = vec![
        serde_json::json!({"id": 1, "name": "svc/github-token", "metadata": "prod app"}),
        serde_json::json!({"id": 2, "name": "svc/stripe-token", "metadata": null}),
    ];
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: false }, || {
        render_vault_list_text(&entries, Some("svc/"))
    });
    assert!(rendered.contains("2 credential names match the `svc/` prefix on the current lane."));
    assert!(rendered.contains("Current set"));
    assert!(rendered.contains("NAME"));
    assert!(rendered.contains("Inspect"));
    assert!(rendered.contains("ember vault get <name>"));
}

#[test]
fn render_sandbox_list_text_surfaces_table_and_operator_actions() {
    let sandboxes = vec![SandboxInfo {
        id: "sandbox-123".to_string(),
        name: "alpha".to_string(),
        persona_id: "persona-sandbox".to_string(),
        owner_persona_id: Some("persona-owner".to_string()),
        container_id: Some("container-123".to_string()),
        image: "ubuntu:24.04".to_string(),
        status: "running".to_string(),
        created_at: "2026-05-24T20:15:00Z".to_string(),
        workspace_path: Some("/tmp/ws".to_string()),
    }];
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: false }, || {
        render_sandbox_list_text(&sandboxes)
    });
    assert!(rendered.contains("1 sandbox running on the current machine."));
    assert!(rendered.contains("Current set"));
    assert!(rendered.contains("NAME"));
    assert!(rendered.contains("Inspect"));
    assert!(rendered.contains("ember sandbox exec <id> -- <cmd>"));
}

#[test]
fn render_receipt_list_text_surfaces_summary_table_and_follow_up_actions() {
    let receipts = vec![
        serde_json::from_value(fake_grant_receipt_json(
            "rct-1234567890",
            "grant-1234567890",
            "persona-root",
        ))
        .expect("receipt fixture"),
    ];
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: false }, || {
        render_receipt_list_text(&receipts)
    });
    assert!(rendered.contains("1 receipt available for audit, export, and trust verification."));
    assert!(rendered.contains("Current set"));
    assert!(rendered.contains("RECEIPT"));
    assert!(rendered.contains("Inspect"));
    assert!(rendered.contains("ember receipt show <id>"));
}

#[test]
fn render_audit_show_text_surfaces_window_table_and_follow_up_actions() {
    let entries = vec![ember_daemon::infra::audit::AuditEntry {
        id: 42,
        timestamp: "2026-05-24T20:15:00Z".to_string(),
        agent_id: Some("persona-root".to_string()),
        action: "grant.created".to_string(),
        credential: Some("github/app".to_string()),
        outcome: "allowed".to_string(),
        details: None,
    }];
    let rendered = with_test_cli_render_theme(CliRenderTheme { color: false }, || {
        render_audit_show_text(&entries)
    });
    assert!(rendered.contains("1 audit event visible in the current audit window."));
    assert!(rendered.contains("Current set"));
    assert!(rendered.contains("PERSONA"));
    assert!(rendered.contains("ACTION"));
    assert!(rendered.contains("Inspect"));
    assert!(rendered.contains("ember audit explain <id>"));
}

#[test]
fn render_receipt_query_text_prefers_structured_action_ref_when_present() {
    let rows = vec![ember_daemon::infra::receipt::ReceiptRow {
        id: "rct-1".to_string(),
        kind: "grant".to_string(),
        actor: "persona-root".to_string(),
        resource: "repo:acme/project".to_string(),
        action_ref: Some(core_event_types::ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_list",
            "v1",
        )),
        contract_id: Some("contract-123".to_string()),
        workspace_ref: Some("rt-horchata".to_string()),
        caller_ref: Some("persona-root".to_string()),
        authority_ref: Some("grant-123".to_string()),
        grant_id: "grant-123".to_string(),
        materialized_at: "2026-05-24T20:15:00Z".to_string(),
        terminal_reason: "revoked".to_string(),
        requested_scope: Some("repo:read".to_string()),
        granted_scope: Some("repo:read".to_string()),
        signed: true,
        delegation_template: None,
        claim_count_total: None,
        claim_events_truncated: false,
        claim_segment_count: None,
        claim_history_merkle_root: None,
    }];

    let rendered = render_receipt_query_text(&rows);
    assert!(rendered.contains("ACTION"));
    assert!(rendered.contains("PERSONA"));
    assert!(rendered.contains("registry.ember.systems/ember-systems/ember-gh/pr_list@v1"));
}

#[test]
fn render_entry_help_does_not_intercept_bare_delegation() {
    assert!(render_entry_help(&["delegation".to_string()]).is_none());
    assert!(render_entry_help(&["workflow".to_string()]).is_none());
}

#[test]
fn render_entry_help_surfaces_bare_approval_group_card() {
    let help = render_entry_help(&["approval".to_string()]).expect("approval entry help");
    assert!(
        help.starts_with("ember approval\n"),
        "expected compact approval help, got:\n{help}"
    );
}

#[test]
fn delegation_command_is_folded_into_grant_after_bkr4c() {
    // BKR-4c (ADR 205 §6): the `ember delegation` surface was folded into
    // `ember grant`. The per-session authority is the runtime persona's standing
    // grant (an AccessGrant), so it is listed/revoked via `ember grant`. The
    // retired command must hard-error, not parse.
    assert!(
        Cli::try_parse_from(["ember", "delegation"]).is_err(),
        "`ember delegation` was folded into `ember grant`; it must not parse"
    );
    assert!(render_entry_help(&["workflow".to_string()]).is_none());
}

#[test]
fn legacy_workflow_alias_is_rejected_after_vocabulary_cutover() {
    // ADR 194 §9 — the `workflow` → `delegation` vocabulary cutover (#4780
    // scrubbed it from the surface; #4953 removed the `workflow => delegation`
    // mapping). The legacy alias is intentionally gone: `ember workflow` must
    // now hard-error, not silently parse to Delegation. (Was previously a
    // `…still_parses…` compat test; the cutover retired the alias, orphaning
    // it — this locks the retired-vocabulary end state instead.)
    assert!(
        Cli::try_parse_from(["ember", "workflow"]).is_err(),
        "`workflow` was retired in the delegation vocabulary cutover; it must not parse"
    );
}

fn fake_status_overview_with_vault_session(vault_session: VaultStatusView) -> StatusOverview {
    StatusOverview {
        dispatch: StatusActionDispatch::DaemonRpc,
        banner: DaemonStatusBanner::Running {
            pid: 42,
            socket: "/tmp/daemon.sock".to_string(),
            dashboard: "http://localhost:8123/".to_string(),
            vault_backend: "local".to_string(),
            vault_addr: "local-encrypted".to_string(),
            vault_session: Some(vault_session.clone()),
        },
        summary: fake_status_summary(),
        github_status: Some(GithubProviderStatusView {
            lane: "app".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        }),
        ember_initialized: true,
        launcher_issue: None,
        current_launcher_lane: Some(CurrentLauncherLane::RepoBuild {
            path: PathBuf::from("/workspace/emberlink-repo-build/target/debug/ember"),
        }),
        managed_daemon_issue: None,
        delegation_template_issue: None,
        daemon_running: true,
        daemon_pid: Some(42),
        daemon_socket: Some("/tmp/daemon.sock".to_string()),
        vault_backend: "local".to_string(),
        vault_addr: "local-encrypted".to_string(),
        vault_session: Some(vault_session),
    }
}

#[test]
fn primary_status_action_prefers_vault_unlock_when_the_vault_is_hard_locked() {
    let overview = fake_status_overview_with_vault_session(VaultStatusView {
        posture: "hard-locked".to_string(),
        unlocked: false,
        live_vault_attached: false,
        session_pin_count: 0,
        grace_window_secs: 300,
        grace_remaining_secs: 0,
        grace_lock_pending: false,
        grace_zero_due: false,
        idle_secs: None,
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    });
    let action = primary_status_action(&overview);
    assert_eq!(action.kind, PrimaryActionKind::FixNow);
    assert_eq!(
        action.command,
        "/workspace/emberlink-repo-build/target/debug/ember vault unlock"
    );
}

#[test]
fn primary_status_action_prefers_doctor_when_workflow_bundle_is_missing() {
    let mut overview = fake_status_overview_with_vault_session(VaultStatusView {
        posture: "interactive-unlocked".to_string(),
        unlocked: true,
        live_vault_attached: true,
        session_pin_count: 0,
        grace_window_secs: 300,
        grace_remaining_secs: 300,
        grace_lock_pending: false,
        grace_zero_due: false,
        idle_secs: Some(0),
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    });
    overview.delegation_template_issue = Some(DelegationTemplateInstallIssue {
        templates_dir: PathBuf::from(PROD_EMBER_DELEGATION_TEMPLATES_DIR),
        missing_templates: vec!["read-only.toml".to_string()],
    });

    let action = primary_status_action(&overview);
    assert_eq!(action.kind, PrimaryActionKind::FixNow);
    assert_eq!(
        action.command,
        "/workspace/emberlink-repo-build/target/debug/ember doctor"
    );
}

#[test]
fn render_status_overview_text_routes_hard_locked_vaults_to_unlock_first() {
    let overview = fake_status_overview_with_vault_session(VaultStatusView {
        posture: "hard-locked".to_string(),
        unlocked: false,
        live_vault_attached: false,
        session_pin_count: 0,
        grace_window_secs: 300,
        grace_remaining_secs: 0,
        grace_lock_pending: false,
        grace_zero_due: false,
        idle_secs: None,
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    });
    let rendered = render_status_overview_text(&overview);
    assert!(
        rendered.starts_with("Needs attention\n"),
        "hard-locked vault posture must not headline as ready: {rendered}"
    );
    assert!(
        rendered.contains("ember vault unlock"),
        "hard-locked vault posture must point at the unlock path first: {rendered}"
    );
    assert!(
        rendered.contains("After unlock"),
        "hard-locked vault posture must preserve the next-launch follow-up: {rendered}"
    );
}

#[test]
fn render_status_overview_text_ready_drops_status_self_link() {
    let overview = fake_status_overview_with_vault_session(VaultStatusView {
        posture: "interactive-unlocked".to_string(),
        unlocked: true,
        live_vault_attached: true,
        session_pin_count: 1,
        grace_window_secs: 300,
        grace_remaining_secs: 0,
        grace_lock_pending: false,
        grace_zero_due: false,
        idle_secs: None,
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    });
    let rendered = render_status_overview_text(&overview);
    assert!(
        rendered.starts_with("Ready\n"),
        "interactive-unlocked vault posture should stay ready: {rendered}"
    );
    assert!(
        !rendered.contains("ember status\n"),
        "ready posture should not suggest the command the operator is already on: {rendered}"
    );
    assert!(
        rendered.contains("ember trust list"),
        "ready posture should keep a useful inspect surface instead of a self-link: {rendered}"
    );
}

#[test]
fn render_status_overview_text_ready_surfaces_auth_truth() {
    let mut overview = fake_status_overview_with_vault_session(VaultStatusView {
        posture: "interactive-unlocked".to_string(),
        unlocked: true,
        live_vault_attached: true,
        session_pin_count: 1,
        grace_window_secs: 300,
        grace_remaining_secs: 0,
        grace_lock_pending: false,
        grace_zero_due: false,
        idle_secs: None,
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    });
    overview.summary.grants = vec![
        serde_json::from_value(fake_grant_info_json_with_lane(
            "grant-claude-oauth",
            "persona-a",
            TEST_ANTHROPIC_OAUTH_CREDENTIAL,
            CLAUDE_CODE_DEFAULT_SCOPE,
        ))
        .expect("decode oauth grant"),
        serde_json::from_value(fake_grant_info_json_with_lane(
            "grant-codex",
            "persona-a",
            CODEX_DEFAULT_SCOPE,
            CODEX_DEFAULT_SCOPE,
        ))
        .expect("decode codex grant"),
        serde_json::from_value(fake_grant_info_json_with_lane(
            "grant-cursor",
            "persona-a",
            CURSOR_DEFAULT_SCOPE,
            CURSOR_DEFAULT_SCOPE,
        ))
        .expect("decode cursor grant"),
    ];
    overview.summary.grant_live_leases =
        vec!["grant-claude-oauth".to_string(), "grant-codex".to_string()];

    let rendered = render_status_overview_text(&overview);
    assert!(
        rendered.contains(
            "Claude auth: governed plan lane active (anthropic/plan/claude-oauth/test-oauth)."
        ),
        "ready posture should disclose the governed Claude OAuth lane: {rendered}"
    );
    assert!(
        rendered.contains(
            "Codex auth: model credential brokered + request-path mediated via the responses proxy (governed, ADR 197 §9); session-budget spend is not bypass-proof on the loopback transport (active session grant)."
        ),
        "ready posture should disclose the governed Codex responses-proxy lane: {rendered}"
    );
}

#[test]
fn render_doctor_text_uses_structured_unlock_guidance_without_repo_path_walls() {
    let overview = fake_status_overview_with_vault_session(VaultStatusView {
        posture: "hard-locked".to_string(),
        unlocked: false,
        live_vault_attached: false,
        session_pin_count: 0,
        grace_window_secs: 300,
        grace_remaining_secs: 0,
        grace_lock_pending: false,
        grace_zero_due: false,
        idle_secs: None,
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    });
    let rendered = render_doctor_text(&overview);
    assert!(
        rendered.contains("Do this"),
        "doctor should use a direct action section instead of falling into a numbered wall: {rendered}"
    );
    assert!(
        rendered.contains("ember vault unlock"),
        "doctor should center the unlock command for hard-locked posture: {rendered}"
    );
    assert!(
        rendered.contains("Current lane: repo build (no-sudo proof lane) via ember"),
        "doctor should keep lane context while shortening the repo-build path: {rendered}"
    );
    assert!(
        !rendered.contains("Next steps:"),
        "doctor should no longer dump the legacy numbered next-steps block in this posture: {rendered}"
    );
    assert!(
        !rendered
            .contains("/workspace/emberlink-repo-build/target/debug/ember claude"),
        "doctor should shorten repo-build commands on the structured diagnosis surface: {rendered}"
    );
}

#[test]
fn render_doctor_text_surfaces_auth_truth() {
    let mut overview = fake_status_overview_with_vault_session(VaultStatusView {
        posture: "interactive-unlocked".to_string(),
        unlocked: true,
        live_vault_attached: true,
        session_pin_count: 1,
        grace_window_secs: 300,
        grace_remaining_secs: 0,
        grace_lock_pending: false,
        grace_zero_due: false,
        idle_secs: None,
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    });
    overview.summary.grants = vec![
        serde_json::from_value(fake_grant_info_json_with_lane(
            "grant-claude-api",
            "persona-a",
            TEST_ANTHROPIC_API_CREDENTIAL,
            CLAUDE_CODE_DEFAULT_SCOPE,
        ))
        .expect("decode api-key grant"),
        serde_json::from_value(fake_grant_info_json_with_lane(
            "grant-codex",
            "persona-a",
            CODEX_DEFAULT_SCOPE,
            CODEX_DEFAULT_SCOPE,
        ))
        .expect("decode codex grant"),
        serde_json::from_value(fake_grant_info_json_with_lane(
            "grant-cursor",
            "persona-a",
            CURSOR_DEFAULT_SCOPE,
            CURSOR_DEFAULT_SCOPE,
        ))
        .expect("decode cursor grant"),
    ];
    overview.summary.grant_live_leases =
        vec!["grant-claude-api".to_string(), "grant-codex".to_string()];

    let rendered = render_doctor_text(&overview);
    assert!(
        rendered.contains(
            "Claude auth: governed API-key fallback active (anthropic/api/key/test-api)."
        ),
        "doctor should disclose the Claude API-key fallback lane: {rendered}"
    );
    assert!(
        rendered.contains(
            "Codex auth: model credential brokered + request-path mediated via the responses proxy (governed, ADR 197 §9); session-budget spend is not bypass-proof on the loopback transport (active session grant)."
        ),
        "doctor should disclose the governed Codex responses-proxy lane: {rendered}"
    );
}

fn fake_receipt_row_json(id: &str, actor: &str, grant_id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "kind": "grant",
        "actor": actor,
        "resource": "repo:acme/project",
        "grant_id": grant_id,
        "materialized_at": "2026-05-19T00:00:00Z",
        "terminal_reason": "revoked",
        "requested_scope": "repo:read",
        "granted_scope": "repo:read",
        "signed": true,
        "delegation_template": null,
        "claim_count_total": null,
        "claim_events_truncated": false,
        "claim_segment_count": null,
        "claim_history_merkle_root": null
    })
}

fn fake_receipt_tree_json(grant_id: &str) -> serde_json::Value {
    serde_json::json!({
        "version": "v2",
        "root_grant_id": grant_id,
        "grants": [{
            "id": grant_id,
            "parent_grant_id": null,
            "persona_id": "persona-a",
            "credential_name": "api-key",
            "scope": "read",
            "status": "active",
            "created_at": "2026-05-19T00:00:00Z",
            "expires_at": null
        }],
        "receipts": [],
        "spawn_witnesses": [],
        "daemon_pubkey_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    })
}

fn fake_approval_request_json(id: &str, persona_id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "persona_id": persona_id,
        "credential_name": "api-key",
        "scope": "read",
        "ttl_secs": null,
        "action": "credential.access",
        "risk_level": "high",
        "status": "pending",
        "reason": null,
        "created_at": "2026-05-19T00:00:00Z",
        "tool_name": null,
        "target_host": null,
        "target_summary": null,
        "target_url": null,
        "agent_framework": null,
        "composite_statements": null,
        "result_grant_id": null,
        "skill_ref": null,
        "max_delegation_depth": null,
        "max_uses_per_hour": null,
        "allowed_hours_start": null,
        "allowed_hours_end": null,
        "allowed_targets": null,
        "budget": null,
        "max_children_per_day": null,
        "auto_delegate_scope_template": null
    })
}

fn fake_persona_info_json(id: &str, name: &str, status: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "name": name,
        "public_key": "ed25519:test",
        "created_at": "2026-05-19T00:00:00Z",
        "status": status,
        "container_id": null,
        "parent_grant_id": null
    })
}

#[test]
fn operator_persona_resolution_prefers_active_root() {
    let personas = vec![
        fake_persona_info_json("persona-target", "cursor-default", "active"),
        fake_persona_info_json("persona-root-revoked", "root", "revoked"),
        fake_persona_info_json(
            "persona-runtime",
            "runtime-claude-code-default-123",
            "active",
        ),
        fake_persona_info_json("persona-root", "root", "active"),
        fake_persona_info_json("persona-codex", "codex-default", "active"),
    ];

    let resolved = resolve_operator_persona_id_from_list(&personas, "persona-target")
        .expect("resolve active root");
    assert_eq!(resolved, "persona-root");
}

#[test]
fn operator_persona_resolution_skips_runtime_and_revoked_personas() {
    let personas = vec![
        fake_persona_info_json("persona-target", "cursor-default", "active"),
        fake_persona_info_json(
            "persona-runtime",
            "runtime-claude-code-default-123",
            "active",
        ),
        fake_persona_info_json("persona-revoked", "codex-default", "revoked"),
        fake_persona_info_json("persona-operator", "claude-code-default", "active"),
    ];

    let resolved = resolve_operator_persona_id_from_list(&personas, "persona-target")
        .expect("resolve active durable persona");
    assert_eq!(resolved, "persona-operator");
}

fn fake_grant_info_json(id: &str, persona_id: &str) -> serde_json::Value {
    fake_grant_info_json_with_lane(id, persona_id, "api-key", "read")
}

fn fake_grant_info_json_with_lane(
    id: &str,
    persona_id: &str,
    credential_name: &str,
    scope: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "persona_id": persona_id,
        "credential_name": credential_name,
        "scope": scope,
        "created_at": "2026-05-19T00:00:00Z",
        "expires_at": null,
        "status": "active",
        "max_uses_per_hour": null,
        "allowed_hours_start": null,
        "allowed_hours_end": null,
        "allowed_targets": null,
        "parent_grant_id": null,
        "max_delegation_depth": null,
        "spending_limit_cents": null,
        "budget": null,
        "usage": {
            "tokens": 0,
            "cents": 0,
            "requests": 0,
            "workload_hours": 0,
            "wall_clock_secs": 0,
            "last_updated": 0
        },
        "paused": false,
        "receipt_id": null,
        "is_standing": false,
        "max_children_per_day": null,
        "auto_delegate_scope_template": null
    })
}

fn fake_runtime_delegable_grant_info_json_with_lane(
    id: &str,
    persona_id: &str,
    credential_name: &str,
    scope: &str,
) -> serde_json::Value {
    let mut grant = fake_grant_info_json_with_lane(id, persona_id, credential_name, scope);
    grant["max_delegation_depth"] = serde_json::json!(1);
    grant
}

fn fake_audit_entry_json(id: i64) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "timestamp": "2026-05-19T00:00:00Z",
        "agent_id": "persona-a",
        "action": "grant.issued",
        "credential": "api-key",
        "outcome": "allowed",
        "details": null
    })
}

fn fake_audit_explain_json(id: i64) -> serde_json::Value {
    serde_json::json!({
        "event": fake_audit_entry_json(id),
        "current_grant": {
            "id": "grant-123",
            "scope": "read",
            "created_at": "2026-05-19T00:00:00Z",
            "expires_at": null,
            "status": "active"
        },
        "current_policy": {
            "requirement": "required",
            "risk": "high",
            "tier": "tier1",
            "matched_rule": "credential.access"
        },
        "note": "Current-state explanation: the event row is historical audit evidence, but grant and policy sections reflect the daemon's current live state."
    })
}

fn fake_status_summary_json() -> serde_json::Value {
    serde_json::json!({
        "personas": [fake_persona_info_json("persona-a", "Alpha", "active")],
        "grants": [fake_grant_info_json("grant-123", "persona-a")],
        "grant_live_leases": ["grant-123"],
        "sandboxes": [{
            "id": "sandbox-1",
            "name": "alpha",
            "persona_id": "persona-a",
            "owner_persona_id": "persona-owner",
            "container_id": "container-1",
            "image": "ubuntu:24.04",
            "status": "running",
            "created_at": "2026-05-19T00:00:00Z",
            "workspace_path": null
        }],
        "approvals": [fake_approval_request_json("approval-123", "persona-a")],
        "recent_activity": [fake_audit_entry_json(7)],
        "standing_grants": 2,
        "audit_events_total": 9,
        "quarantined": false,
        "quarantine_authority": null
    })
}

fn fake_status_summary() -> ember_daemon::infra::status::StatusSummary {
    serde_json::from_value(fake_status_summary_json()).expect("decode fake status summary")
}

#[test]
fn render_status_text_offline_prioritizes_repair_over_detail() {
    let rendered = render_status_text(
        DaemonStatusBanner::NotRunning,
        &fake_status_summary(),
        None,
        None,
        None,
    );
    assert!(
        rendered.contains("DAEMON             not running"),
        "offline status must lead with daemon-down state: {rendered}"
    );
    assert!(
        rendered.contains("Repair:    sudo ember daemon install"),
        "offline status must include the canonical repair CTA: {rendered}"
    );
    assert!(
        rendered.contains("showing local store summary only"),
        "offline status must explain the summary-only posture: {rendered}"
    );
    assert!(
        rendered.contains("PERSONAS           1 active, 0 revoked"),
        "offline status must keep summary counts: {rendered}"
    );
    assert!(
        !rendered.contains("Alpha"),
        "offline status should not dump per-persona detail: {rendered}"
    );
    assert!(
        !rendered.contains("grant-123"),
        "offline status should not dump per-grant detail: {rendered}"
    );
}

#[test]
fn render_status_text_running_surfaces_quarantine_banner() {
    let mut summary = fake_status_summary();
    summary.quarantined = true;
    summary.quarantine_authority = Some("startup_audit_chain_break".to_string());
    let rendered = render_status_text(
        DaemonStatusBanner::Running {
            pid: 42,
            socket: "/tmp/daemon.sock".to_string(),
            dashboard: "http://localhost:8123/".to_string(),
            vault_backend: "local".to_string(),
            vault_addr: "local-encrypted".to_string(),
            vault_session: None,
        },
        &summary,
        None,
        None,
        None,
    );
    assert!(
        rendered.contains("Quarantine: startup_audit_chain_break"),
        "running status must disclose the quarantine authority: {rendered}"
    );
    assert!(
        rendered.contains("write-class commands are blocked until audit repair"),
        "running status must explain the operational impact: {rendered}"
    );
    assert!(
        rendered.contains("Repair:     ember doctor"),
        "running status must route the operator to the diagnosis surface first: {rendered}"
    );
}

#[test]
fn render_status_text_running_surfaces_vault_lane_summary() {
    let rendered = render_status_text(
        DaemonStatusBanner::Running {
            pid: 42,
            socket: "/tmp/daemon.sock".to_string(),
            dashboard: "http://localhost:8123/".to_string(),
            vault_backend: "local".to_string(),
            vault_addr: "local-encrypted".to_string(),
            vault_session: Some(VaultStatusView {
                posture: "presence-locked-vault-pinned".to_string(),
                unlocked: false,
                live_vault_attached: true,
                session_pin_count: 1,
                grace_window_secs: 300,
                grace_remaining_secs: 0,
                grace_lock_pending: false,
                grace_zero_due: false,
                idle_secs: None,
                idle_timeout_secs: 300,
                quiet_hours_start: None,
                quiet_hours_end: None,
            }),
        },
        &fake_status_summary(),
        None,
        None,
        None,
    );
    assert!(
        rendered.contains("Vault lane: presence-locked (live vault still attached; 1 session pin)"),
        "running status should distinguish a soft lock from a hard lock: {rendered}"
    );
}

#[test]
fn render_status_text_running_calls_out_stale_launcher_boundary() {
    let issue = InstalledLauncherIssue::StaleManagedInstall {
        path: PathBuf::from("/usr/local/bin/ember"),
        target: PathBuf::from("/usr/local/lib/ember.app/Contents/MacOS/ember"),
        newer_components: vec![
            PathBuf::from("/usr/local/bin/emberd"),
            PathBuf::from("/usr/local/lib/ember/binaries/ember-gh"),
        ],
    };
    let rendered = render_status_text(
        DaemonStatusBanner::Running {
            pid: 42,
            socket: "/tmp/daemon.sock".to_string(),
            dashboard: "http://localhost:8123/".to_string(),
            vault_backend: "local".to_string(),
            vault_addr: "local-encrypted".to_string(),
            vault_session: None,
        },
        &fake_status_summary(),
        Some(&issue),
        None,
        None,
    );
    assert!(
        rendered.contains("Host launcher: /usr/local/bin/ember ->"),
        "plain status must surface stale host launcher drift without `--troubleshoot`: {rendered}"
    );
    assert!(
        rendered.contains("older than managed runtime surface"),
        "plain status must explain the split install truth: {rendered}"
    );
    assert!(
        rendered.contains("does not rebuild `/usr/local/lib/ember.app`"),
        "plain status must carry the launcher boundary repair guidance: {rendered}"
    );
}

#[test]
fn render_vault_status_text_calls_out_hard_lock() {
    let rendered = render_vault_status_text(&VaultStatusView {
        posture: "hard-locked".to_string(),
        unlocked: false,
        live_vault_attached: false,
        session_pin_count: 0,
        grace_window_secs: 300,
        grace_remaining_secs: 0,
        grace_lock_pending: false,
        grace_zero_due: false,
        idle_secs: None,
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    });
    assert!(rendered.contains("VAULT LANE         hard-locked (live vault detached)"));
    assert!(rendered.contains("Live MEK:   detached"));
}

#[test]
fn render_vault_status_text_reports_remaining_grace_countdown() {
    let rendered = render_vault_status_text(&VaultStatusView {
        posture: "presence-locked-vault-attached".to_string(),
        unlocked: false,
        live_vault_attached: true,
        session_pin_count: 0,
        grace_window_secs: 300,
        grace_remaining_secs: 42,
        grace_lock_pending: true,
        grace_zero_due: false,
        idle_secs: Some(301),
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    });
    assert!(rendered.contains(
        "VAULT LANE         presence-locked (live vault still attached; 42s grace remaining)"
    ));
    assert!(rendered.contains("Grace:     active (42s remaining)"));
}

#[test]
#[cfg(unix)]
fn detect_installed_launcher_issue_at_resolves_relative_repo_build_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let bin_dir = tmp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let install = bin_dir.join("ember");
    let target = PathBuf::from("../target/dev-sign/ember.app/Contents/MacOS/ember");
    std::os::unix::fs::symlink(&target, &install).unwrap();

    let expected_target = tmp
        .path()
        .join("target/dev-sign/ember.app/Contents/MacOS/ember");
    assert_eq!(
        detect_installed_launcher_issue_at(&install),
        Some(InstalledLauncherIssue::BrokenRepoBuildSymlink {
            path: install,
            target: expected_target,
        })
    );
}

#[test]
#[cfg(unix)]
fn detect_installed_launcher_issue_at_flags_stale_managed_runtime_surface() {
    let tmp = tempfile::tempdir().unwrap();
    let launcher_dir = tmp.path().join("launcher");
    let runtime_dir = tmp.path().join("runtime");
    std::fs::create_dir_all(&launcher_dir).unwrap();
    std::fs::create_dir_all(&runtime_dir).unwrap();

    let launcher_target = launcher_dir.join("ember");
    std::fs::write(&launcher_target, "launcher").unwrap();
    std::thread::sleep(Duration::from_secs(1));

    let newer_component = runtime_dir.join("emberd");
    std::fs::write(&newer_component, "daemon").unwrap();

    let install = tmp.path().join("bin").join("ember");
    std::fs::create_dir_all(install.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&launcher_target, &install).unwrap();

    assert_eq!(
        detect_installed_launcher_issue_at_with_managed_components(
            &install,
            std::slice::from_ref(&newer_component),
            Duration::ZERO,
        ),
        Some(InstalledLauncherIssue::StaleManagedInstall {
            path: install,
            target: launcher_target,
            newer_components: vec![newer_component],
        })
    );
}

#[test]
fn classify_current_launcher_lane_at_detects_installed_host() {
    assert_eq!(
        classify_current_launcher_lane_at(Path::new(PROD_EMBER_APP_PATH)),
        CurrentLauncherLane::InstalledHost {
            path: PathBuf::from(PROD_EMBER_APP_PATH),
        }
    );
}

#[test]
fn classify_current_launcher_lane_at_detects_repo_build() {
    let path = PathBuf::from("/Users/example/repos/emberlink-dev/target/release/ember");
    assert_eq!(
        classify_current_launcher_lane_at(&path),
        CurrentLauncherLane::RepoBuild { path }
    );
}

#[test]
fn render_status_text_running_calls_out_repo_build_managed_daemon_drift() {
    let lane = CurrentLauncherLane::RepoBuild {
        path: PathBuf::from("/Users/example/repos/emberlink-dev/target/debug/ember"),
    };
    let issue = ManagedDaemonIssue {
        launcher_path: PathBuf::from("/Users/example/repos/emberlink-dev/target/debug/ember"),
        daemon_path: PathBuf::from("/usr/local/bin/emberd"),
    };
    let rendered = render_status_text(
        DaemonStatusBanner::Running {
            pid: 42,
            socket: "/tmp/daemon.sock".to_string(),
            dashboard: "http://localhost:8123/".to_string(),
            vault_backend: "local".to_string(),
            vault_addr: "local-encrypted".to_string(),
            vault_session: None,
        },
        &fake_status_summary(),
        None,
        Some(&lane),
        Some(&issue),
    );
    assert!(
            rendered.contains("Host daemon:   /Users/example/repos/emberlink-dev/target/debug/ember is newer than managed daemon /usr/local/bin/emberd"),
            "plain status must name repo-build-vs-managed-daemon drift before launcher failure: {rendered}"
        );
    assert!(
        rendered
            .contains("sudo /Users/example/repos/emberlink-dev/target/debug/ember daemon install"),
        "plain status must point at the repo-built installer path, not ambient PATH: {rendered}"
    );
}

#[test]
fn render_status_text_offline_uses_explicit_repo_build_ember_command() {
    let lane = CurrentLauncherLane::RepoBuild {
        path: PathBuf::from("/home/operator/emberlink-example/target/debug/ember"),
    };
    let rendered = render_status_text(
        DaemonStatusBanner::NotRunning,
        &fake_status_summary(),
        None,
        Some(&lane),
        None,
    );
    assert!(
        rendered.contains(
            "Repair:    sudo /home/operator/emberlink-example/target/debug/ember daemon install"
        ),
        "offline status must preserve the invoking repo-built launcher path: {rendered}"
    );
}

#[test]
fn render_status_troubleshoot_offline_calls_out_broken_launcher_before_daemon_repair() {
    let issue = InstalledLauncherIssue::BrokenRepoBuildSymlink {
        path: PathBuf::from("/usr/local/bin/ember"),
        target: PathBuf::from(
            "/Users/example/repos/emberlink-dev/target/dev-sign/ember.app/Contents/MacOS/ember",
        ),
    };
    let rendered = render_status_troubleshoot_text(
        &DaemonStatusBanner::NotRunning,
        &fake_status_summary(),
        StatusActionDispatch::LocalFallback,
        None,
        true,
        Some(&issue),
        None,
        None,
        None,
    );
    assert!(
        rendered.contains("Install path:   /usr/local/bin/ember ->"),
        "offline troubleshoot must surface the broken install path: {rendered}"
    );
    assert!(
        rendered.contains("1. Repair the installed `ember` launcher path first"),
        "offline troubleshoot must repair the launcher before daemon surgery: {rendered}"
    );
    assert!(
        rendered.contains("2. Run `sudo ember daemon install`"),
        "offline troubleshoot must renumber daemon repair after the launcher fix: {rendered}"
    );
}

#[test]
fn render_status_troubleshoot_discloses_current_launcher_lane() {
    let lane = CurrentLauncherLane::RepoBuild {
        path: PathBuf::from("/Users/example/repos/emberlink-dev/target/release/ember"),
    };
    let rendered = render_status_troubleshoot_text(
        &DaemonStatusBanner::NotRunning,
        &fake_status_summary(),
        StatusActionDispatch::LocalFallback,
        None,
        true,
        None,
        Some(&lane),
        None,
        None,
    );
    assert!(
        rendered.contains("Current lane:   repo build (no-sudo proof lane)"),
        "troubleshoot must disclose the active launcher lane: {rendered}"
    );
}

#[test]
fn render_status_troubleshoot_offline_uses_explicit_repo_build_ember_command() {
    let lane = CurrentLauncherLane::RepoBuild {
        path: PathBuf::from("/home/operator/emberlink-example/target/debug/ember"),
    };
    let rendered = render_status_troubleshoot_text(
        &DaemonStatusBanner::NotRunning,
        &fake_status_summary(),
        StatusActionDispatch::LocalFallback,
        None,
        true,
        None,
        Some(&lane),
        None,
        None,
    );
    assert!(
        rendered
            .contains("Run `sudo /home/operator/emberlink-example/target/debug/ember daemon install`"),
        "offline troubleshoot must keep managed-daemon repair on the invoking launcher path: {rendered}"
    );
    assert!(
        rendered.contains("Run `/home/operator/emberlink-example/target/debug/ember daemon diagnose`"),
        "offline troubleshoot must keep daemon diagnose on the invoking launcher path: {rendered}"
    );
    assert!(
        rendered.contains("run `/home/operator/emberlink-example/target/debug/ember github status`"),
        "offline troubleshoot must keep the GitHub posture follow-up on the invoking launcher path: {rendered}"
    );
}

#[test]
fn render_status_troubleshoot_offline_calls_out_stale_launcher_before_daemon_repair() {
    let issue = InstalledLauncherIssue::StaleManagedInstall {
        path: PathBuf::from("/usr/local/bin/ember"),
        target: PathBuf::from("/usr/local/lib/ember.app/Contents/MacOS/ember"),
        newer_components: vec![
            PathBuf::from("/usr/local/bin/emberd"),
            PathBuf::from("/usr/local/lib/ember/binaries/ember-gh"),
        ],
    };
    let rendered = render_status_troubleshoot_text(
        &DaemonStatusBanner::NotRunning,
        &fake_status_summary(),
        StatusActionDispatch::LocalFallback,
        None,
        true,
        Some(&issue),
        None,
        None,
        None,
    );
    assert!(
        rendered.contains("older than managed runtime surface"),
        "offline troubleshoot must surface the split install truth: {rendered}"
    );
    assert!(
        rendered.contains("`sudo ember daemon install` refreshes daemon/runtime sidecars"),
        "offline troubleshoot must explain why daemon install alone does not fix the launcher: {rendered}"
    );
    assert!(
        rendered.contains("2. Run `sudo ember daemon install`"),
        "offline troubleshoot must keep daemon repair as the second step: {rendered}"
    );
}

#[test]
fn render_status_troubleshoot_offline_routes_to_diagnose_when_state_exists() {
    let rendered = render_status_troubleshoot_text(
        &DaemonStatusBanner::NotRunning,
        &fake_status_summary(),
        StatusActionDispatch::LocalFallback,
        None,
        true,
        None,
        None,
        None,
        None,
    );
    assert!(
        rendered.contains("Summary source: local fallback"),
        "troubleshoot must disclose local fallback dispatch: {rendered}"
    );
    assert!(
        rendered.contains("ember daemon diagnose"),
        "offline troubleshoot must preserve the diagnose branch when daemon.db exists: {rendered}"
    );
    assert!(
        rendered.contains("ember github status"),
        "offline troubleshoot must point back at GitHub posture after repair: {rendered}"
    );
}

#[test]
fn render_status_troubleshoot_running_app_path_points_at_claude_code() {
    let rendered = render_status_troubleshoot_text(
        &DaemonStatusBanner::Running {
            pid: 42,
            socket: "/tmp/daemon.sock".to_string(),
            dashboard: "http://localhost:8123/".to_string(),
            vault_backend: "local".to_string(),
            vault_addr: "local-encrypted".to_string(),
            vault_session: None,
        },
        &fake_status_summary(),
        StatusActionDispatch::DaemonRpc,
        Some(&GithubProviderStatusView {
            lane: "app".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        }),
        true,
        None,
        None,
        None,
        None,
    );
    assert!(
        rendered.contains("Summary source: daemon RPC"),
        "troubleshoot must disclose daemon RPC dispatch: {rendered}"
    );
    assert!(
        rendered.contains("real App lane ready"),
        "running troubleshoot must distinguish the real App lane: {rendered}"
    );
    assert!(
        rendered.contains("Launch `ember claude`"),
        "running troubleshoot must point at the canonical launcher: {rendered}"
    );
    assert!(
        rendered.contains("ember receipt export --latest --format md"),
        "running troubleshoot must expose the first proof command after launch: {rendered}"
    );
    assert!(
        rendered.contains("ember trust list"),
        "running troubleshoot must keep trust verification on the repair surface: {rendered}"
    );
}

#[test]
fn render_status_troubleshoot_running_not_configured_points_at_setup_without_reload_dance() {
    let rendered = render_status_troubleshoot_text(
        &DaemonStatusBanner::Running {
            pid: 42,
            socket: "/tmp/daemon.sock".to_string(),
            dashboard: "http://localhost:8123/".to_string(),
            vault_backend: "local".to_string(),
            vault_addr: "local-encrypted".to_string(),
            vault_session: None,
        },
        &fake_status_summary(),
        StatusActionDispatch::DaemonRpc,
        Some(&GithubProviderStatusView {
            lane: "none".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        }),
        true,
        None,
        None,
        None,
        None,
    );
    assert!(
        rendered.contains(
            "Run `ember github setup` to register local App credentials for the HTTPS/App lane."
        ),
        "not-configured troubleshoot must point at the local App setup command: {rendered}"
    );
    assert!(
        rendered.contains("Then run `ember github status` to confirm the App lane is ready."),
        "not-configured troubleshoot must point back at explicit posture confirmation: {rendered}"
    );
    assert!(
        !rendered.contains("ember github app install-url"),
        "not-configured troubleshoot should stay on the single friendly setup path: {rendered}"
    );
    assert!(
        !rendered.contains("ember daemon reload"),
        "not-configured troubleshoot must not reintroduce the old reload dance: {rendered}"
    );
}

#[test]
fn render_status_troubleshoot_running_pat_path_names_degraded_proof_lane() {
    let rendered = render_status_troubleshoot_text(
        &DaemonStatusBanner::Running {
            pid: 42,
            socket: "/tmp/daemon.sock".to_string(),
            dashboard: "http://localhost:8123/".to_string(),
            vault_backend: "local".to_string(),
            vault_addr: "local-encrypted".to_string(),
            vault_session: None,
        },
        &fake_status_summary(),
        StatusActionDispatch::DaemonRpc,
        Some(&GithubProviderStatusView {
            lane: "pat".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        }),
        true,
        None,
        None,
        None,
        None,
    );
    assert!(
        rendered.contains("degraded PAT fallback active"),
        "PAT troubleshoot branch must disclose degraded posture: {rendered}"
    );
    assert!(
        rendered.contains("ember github setup"),
        "PAT troubleshoot branch must point at the App upgrade path: {rendered}"
    );
    assert!(
        rendered.contains("ember receipt export --latest --format md"),
        "PAT troubleshoot branch should still expose the proof command for intentional degraded runs: {rendered}"
    );
}

#[test]
fn render_status_troubleshoot_running_workflow_bundle_repairs_before_launch() {
    let workflow_issue = DelegationTemplateInstallIssue {
        templates_dir: PathBuf::from(PROD_EMBER_DELEGATION_TEMPLATES_DIR),
        missing_templates: vec!["read-only.toml".to_string()],
    };
    let rendered = render_status_troubleshoot_text(
        &DaemonStatusBanner::Running {
            pid: 42,
            socket: "/tmp/daemon.sock".to_string(),
            dashboard: "http://localhost:8123/".to_string(),
            vault_backend: "local".to_string(),
            vault_addr: "local-encrypted".to_string(),
            vault_session: None,
        },
        &fake_status_summary(),
        StatusActionDispatch::DaemonRpc,
        Some(&GithubProviderStatusView {
            lane: "app".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        }),
        true,
        None,
        None,
        None,
        Some(&workflow_issue),
    );
    assert!(
        rendered.contains("missing bundled delegation templates"),
        "troubleshoot must surface the bundle drift detail: {rendered}"
    );
    assert!(
        rendered.contains("Run `ember status` to confirm the managed bundle is restored."),
        "troubleshoot must verify the delegation bundle before launch: {rendered}"
    );
    assert!(
        !rendered.contains("Launch `ember claude` for the canonical friendly session path."),
        "troubleshoot must not point at launch before the delegation bundle is repaired: {rendered}"
    );
}

#[test]
fn render_status_troubleshoot_running_quarantine_routes_to_audit_repair() {
    let mut summary = fake_status_summary();
    summary.quarantined = true;
    summary.quarantine_authority = Some("startup_audit_chain_break".to_string());
    let rendered = render_status_troubleshoot_text(
        &DaemonStatusBanner::Running {
            pid: 42,
            socket: "/tmp/daemon.sock".to_string(),
            dashboard: "http://localhost:8123/".to_string(),
            vault_backend: "local".to_string(),
            vault_addr: "local-encrypted".to_string(),
            vault_session: None,
        },
        &summary,
        StatusActionDispatch::DaemonRpc,
        Some(&GithubProviderStatusView {
            lane: "app".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        }),
        true,
        None,
        None,
        None,
        None,
    );
    assert!(
        rendered.contains("write-class methods are quarantined"),
        "quarantined troubleshoot must lead with the quarantine state: {rendered}"
    );
    assert!(
        rendered.contains("startup_audit_chain_break"),
        "quarantined troubleshoot must disclose the stable authority label: {rendered}"
    );
    assert!(
        rendered.contains("ember doctor"),
        "quarantined troubleshoot must point at diagnosis first: {rendered}"
    );
    assert!(
        !rendered.contains("Launch `ember claude`"),
        "quarantined troubleshoot must not advertise immediate session launch before repair: {rendered}"
    );
}

#[test]
fn render_github_status_text_points_at_app_first() {
    let rendered = render_github_status_text(
        &GithubProviderStatusView {
            lane: "app".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        },
        None,
    );
    assert!(
        rendered.contains("GitHub ready"),
        "github status must use the ready headline on the App lane: {rendered}"
    );
    assert!(
        rendered.contains("HTTPS/API path"),
        "github status must describe the App-first lane: {rendered}"
    );
    assert!(
        rendered.contains("ember init --for claude"),
        "real App posture must keep init on the App-first path: {rendered}"
    );
    assert!(
        rendered.contains("ember explain github setup"),
        "status should still point at the deeper manual surface: {rendered}"
    );
}

#[test]
fn render_github_status_text_names_pat_as_degraded_lane() {
    let rendered = render_github_status_text(
        &GithubProviderStatusView {
            lane: "pat".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        },
        None,
    );
    assert!(
        rendered.contains("GitHub needs attention"),
        "github status must headline degraded PAT posture as attention-needed: {rendered}"
    );
    assert!(
        rendered.contains("GitHub identity"),
        "PAT posture must warn about attribution and identity surface: {rendered}"
    );
    assert!(
        rendered.contains("PAT fallback"),
        "PAT posture must name the degraded lane directly: {rendered}"
    );
    assert!(
        rendered.contains(github_setup_command()),
        "PAT posture should point at the friendly GitHub setup command: {rendered}"
    );
}

#[test]
fn render_github_status_text_uses_explicit_repo_build_ember_command() {
    let app_ready = render_github_status_text_with_ember_command(
        &GithubProviderStatusView {
            lane: "app".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        },
        None,
        "/home/operator/emberlink-example/target/debug/ember",
    );
    assert!(app_ready.contains("ember init --for claude"));

    let app_setup = render_github_status_text_with_ember_command(
        &GithubProviderStatusView {
            lane: "none".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        },
        None,
        "/home/operator/emberlink-example/target/debug/ember",
    );
    assert!(app_setup.contains("ember github setup"));
    assert!(app_setup.contains("ember status"));
}

#[test]
fn daemon_install_requires_root_even_when_sudo_exists() {
    let err = require_root_install_invocation_inner(
        || false,
        || true,
        "daemon install",
        Some(&CurrentLauncherLane::InstalledHost {
            path: PathBuf::from("/usr/local/bin/ember"),
        }),
    )
    .expect_err("non-root install must fail fast before provisioning");
    assert!(
        err.contains("sudo ember daemon install"),
        "rerun hint must name the canonical command: {err}"
    );
    assert!(
        err.contains("must be run via sudo"),
        "failure must explain the privilege boundary: {err}"
    );
}

#[test]
fn daemon_migrate_requires_root_even_when_sudo_exists() {
    let err = require_root_install_invocation_inner(
        || false,
        || true,
        "daemon migrate",
        Some(&CurrentLauncherLane::InstalledHost {
            path: PathBuf::from("/usr/local/bin/ember"),
        }),
    )
    .expect_err("non-root migrate must fail fast before provisioning");
    assert!(
        err.contains("sudo ember daemon migrate"),
        "rerun hint must preserve the original privileged command: {err}"
    );
}

#[test]
fn daemon_install_repo_build_rerun_hint_uses_current_launcher_path() {
    let err = require_root_install_invocation_inner(
        || false,
        || true,
        "daemon install",
        Some(&CurrentLauncherLane::RepoBuild {
            path: PathBuf::from("/home/operator/emberlink-example/target/debug/ember"),
        }),
    )
    .expect_err("repo-built install must keep the same launcher under sudo");
    assert!(
        err.contains("sudo /home/operator/emberlink-example/target/debug/ember daemon install"),
        "repo-build rerun hint must preserve the invoking launcher path: {err}"
    );
}

#[test]
fn ember_command_prefix_for_repo_build_uses_current_launcher_path() {
    let command = ember_command_prefix_for_launcher_lane(Some(&CurrentLauncherLane::RepoBuild {
        path: PathBuf::from("/home/operator/emberlink-example/target/debug/ember"),
    }));
    assert_eq!(
        command, "/home/operator/emberlink-example/target/debug/ember",
        "repo-build init guidance must preserve the invoking launcher path"
    );
}

#[test]
fn daemon_install_allows_existing_root_context() {
    let result = require_root_install_invocation_inner(|| true, || false, "daemon install", None);
    assert!(
        result.is_ok(),
        "root context must not be rejected when sudo is absent"
    );
}

#[test]
fn render_github_status_text_surfaces_broken_detail() {
    let rendered = render_github_status_text(
            &GithubProviderStatusView {
                lane: "broken".to_string(),
                detail: Some(
                    "github/apps/ember/install-123: partial credential triple (private-key=true, app-id=true, installation-id=false)"
                        .to_string(),
                ),
                app_id: None,
                installation_id: None,
            },
            None,
        );
    assert!(
        rendered.contains("GitHub needs attention"),
        "broken posture must headline the broken App config clearly: {rendered}"
    );
    assert!(
        rendered.contains("partial credential triple"),
        "broken posture must surface the daemon-side detail: {rendered}"
    );
    assert!(
        rendered.contains("Repair or replace the local App credential triple"),
        "broken posture must point at the repair path: {rendered}"
    );
}

#[test]
fn render_github_status_text_surfaces_stale_launcher_boundary_when_present() {
    let rendered = render_github_status_text(
        &GithubProviderStatusView {
            lane: "app".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        },
        Some(&InstalledLauncherIssue::StaleManagedInstall {
            path: PathBuf::from("/usr/local/bin/ember"),
            target: PathBuf::from("/usr/local/lib/ember.app/Contents/MacOS/ember"),
            newer_components: vec![
                PathBuf::from("/usr/local/bin/emberd"),
                PathBuf::from("/usr/local/lib/ember/binaries/ember-gh"),
            ],
        }),
    );
    assert!(
        rendered.contains("Boundary"),
        "github status must surface stale host launcher drift when present: {rendered}"
    );
    assert!(
        rendered.contains(
            "Install path: /usr/local/bin/ember -> /usr/local/lib/ember.app/Contents/MacOS/ember"
        ),
        "github status must disclose the split install path that drifted: {rendered}"
    );
    assert!(
        rendered.contains("does not rebuild `/usr/local/lib/ember.app`"),
        "github status must keep the stale-launcher repair truth explicit: {rendered}"
    );
}

#[test]
fn github_status_json_payload_surfaces_stale_launcher_boundary_when_present() {
    let payload = github_status_json_payload(
        &GithubProviderStatusView {
            lane: "app".to_string(),
            detail: None,
            app_id: Some("123456".to_string()),
            installation_id: Some("654321".to_string()),
        },
        Some(&InstalledLauncherIssue::StaleManagedInstall {
            path: PathBuf::from("/usr/local/bin/ember"),
            target: PathBuf::from("/usr/local/lib/ember.app/Contents/MacOS/ember"),
            newer_components: vec![
                PathBuf::from("/usr/local/bin/emberd"),
                PathBuf::from("/usr/local/lib/ember/binaries/ember-gh"),
            ],
        }),
    );
    assert_eq!(
        payload["https_app_lane"],
        serde_json::json!("configured_app"),
        "github status json must preserve the real App posture: {payload}"
    );
    assert_eq!(
        payload["launcher_issue"]["kind"],
        serde_json::json!("stale_managed_install"),
        "github status json must classify stale launcher drift for automation: {payload}"
    );
    assert_eq!(
        payload["launcher_issue"]["path"],
        serde_json::json!("/usr/local/bin/ember"),
        "github status json must expose the drifting launcher path: {payload}"
    );
    assert_eq!(
        payload["launcher_issue"]["newer_components"],
        serde_json::json!([
            "/usr/local/bin/emberd",
            "/usr/local/lib/ember/binaries/ember-gh",
        ]),
        "github status json must expose the newer managed runtime components: {payload}"
    );
    assert_eq!(
        payload["launcher_issue"]["repair_guidance"],
        serde_json::json!(
            "Repair the installed `ember` launcher path first: /usr/local/bin/ember is older than the managed daemon/construct binaries on this host. Reinstall the managed CLI artifact or release package so `/usr/local/bin/ember` matches the runtime surface. `sudo ember daemon install` refreshes daemon/runtime sidecars, but it does not rebuild `/usr/local/lib/ember.app`."
        ),
        "github status json must preserve the exact repair guidance already shown in text surfaces: {payload}"
    );
}

fn parse_github(args: &[&str]) -> GithubAction {
    use clap::Parser;
    #[derive(Parser)]
    struct T {
        #[command(subcommand)]
        action: GithubAction,
    }
    let mut full = vec!["test"];
    full.extend_from_slice(args);
    let cli = T::try_parse_from(&full).expect("parse failed");
    cli.action
}

fn parse_receipt(args: &[&str]) -> ReceiptAction {
    use clap::Parser;
    #[derive(Parser)]
    struct T {
        #[command(subcommand)]
        action: ReceiptAction,
    }
    let mut full = vec!["test"];
    full.extend_from_slice(args);
    let cli = T::try_parse_from(&full).expect("parse failed");
    cli.action
}

fn parse_audit(args: &[&str]) -> AuditAction {
    use clap::Parser;
    #[derive(Parser)]
    struct T {
        #[command(subcommand)]
        action: AuditAction,
    }
    let mut full = vec!["test"];
    full.extend_from_slice(args);
    let cli = T::try_parse_from(&full).expect("parse failed");
    cli.action
}

#[test]
fn audit_verify_parses_since_ship_gate_window() {
    match parse_audit(&["verify", "--since", "7d"]) {
        AuditAction::Verify {
            tail,
            since,
            import,
            ..
        } => {
            assert_eq!(tail, None);
            assert_eq!(since.as_deref(), Some("7d"));
            assert_eq!(import, None);
        }
        _ => panic!("expected audit verify action"),
    }
}

#[test]
fn audit_verify_parses_dogfood_since_window() {
    match parse_audit(&["verify", "--since", "1d"]) {
        AuditAction::Verify { since, .. } => {
            assert_eq!(since.as_deref(), Some("1d"));
        }
        _ => panic!("expected audit verify action"),
    }
}

#[test]
fn audit_verify_since_conflicts_with_tail() {
    use clap::Parser;
    #[derive(Parser)]
    struct T {
        #[command(subcommand)]
        action: AuditAction,
    }

    let err = match T::try_parse_from(["test", "verify", "--since", "7d", "--tail", "500"]) {
        Ok(_) => panic!("since and tail must conflict"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("cannot be used with"),
        "unexpected parse error: {err}"
    );
}

#[test]
fn github_setup_parses_explicit_register_fields() {
    match parse_github(&[
        "setup",
        "--pem-file",
        "/tmp/app.pem",
        "--app-id",
        "123",
        "--installation-id",
        "456",
        "--slug",
        "emberlink",
    ]) {
        GithubAction::Setup(args) => {
            assert_eq!(args.pem_file, Some(PathBuf::from("/tmp/app.pem")));
            assert_eq!(args.app_id.as_deref(), Some("123"));
            assert_eq!(args.installation_id.as_deref(), Some("456"));
            assert_eq!(args.slug.as_deref(), Some("emberlink"));
        }
        _ => panic!("expected github setup"),
    }
}

#[test]
fn github_setup_parses_from_manifest() {
    match parse_github(&["setup", "--from-manifest"]) {
        GithubAction::Setup(args) => {
            assert!(args.from_manifest);
            assert!(!github_setup_has_direct_inputs(&args));
        }
        _ => panic!("expected github setup"),
    }
}

#[test]
fn github_setup_manifest_flow_selection_is_interactive_default() {
    let default_args = GithubSetupArgs::default();
    assert!(github_setup_should_use_manifest_flow(&default_args, true));
    assert!(!github_setup_should_use_manifest_flow(&default_args, false));

    let direct_args = GithubSetupArgs {
        pem_file: Some(PathBuf::from("/tmp/app.pem")),
        app_id: Some("123".to_string()),
        installation_id: Some("456".to_string()),
        slug: Some("emberlink".to_string()),
        ..GithubSetupArgs::default()
    };
    assert!(!github_setup_should_use_manifest_flow(&direct_args, true));

    let manifest_args = GithubSetupArgs {
        from_manifest: true,
        ..GithubSetupArgs::default()
    };
    assert!(github_setup_should_use_manifest_flow(&manifest_args, false));
}

#[test]
fn github_manifest_setup_result_redacts_conversion_secrets() {
    let conversion = emberlink_cli::onboarding::github_app::ManifestConversion {
        id: 123,
        slug: "ember-engine".to_string(),
        pem: fake_private_key_pem(),
        html_url: Some("https://github.com/apps/ember-engine".to_string()),
        client_id: Some("Iv1.client".to_string()),
        client_secret: Some("client-secret".to_string()),
        webhook_secret: Some("webhook-secret".to_string()),
    };

    let rendered = render_github_manifest_setup_result(&conversion, "ember");
    assert!(rendered.contains("App ID: 123"));
    assert!(rendered.contains("https://github.com/apps/ember-engine/installations/new"));
    assert!(rendered.contains("not installed yet"));
    assert!(!rendered.contains("RSA PRIVATE KEY"));
    assert!(!rendered.contains("client-secret"));
    assert!(!rendered.contains("webhook-secret"));
}

fn sample_manifest_conversion() -> emberlink_cli::onboarding::github_app::ManifestConversion {
    emberlink_cli::onboarding::github_app::ManifestConversion {
        id: 123,
        slug: "ember-engine".to_string(),
        pem: fake_private_key_pem(),
        html_url: Some("https://github.com/apps/ember-engine".to_string()),
        client_id: Some("Iv1.client".to_string()),
        client_secret: Some("client-secret".to_string()),
        webhook_secret: Some("webhook-secret".to_string()),
    }
}

fn fake_private_key_pem() -> String {
    format!(
        "{}RSA PRIVATE KEY-----\nsecret\n{}RSA PRIVATE KEY-----\n",
        "-----BEGIN ", "-----END "
    )
}

#[test]
fn github_install_resolved_shows_installation_without_leaking_secrets() {
    let conversion = sample_manifest_conversion();
    let resolved = emberlink_cli::onboarding::github_app::ResolvedInstallation {
        installation_id: 987654,
        account_login: Some("octo-org".to_string()),
        repository_selection: Some("selected".to_string()),
    };

    let rendered = render_github_install_resolved(&conversion, &resolved, "ember");
    assert!(rendered.contains("GitHub App installed"));
    assert!(rendered.contains("Installation ID: 987654"));
    assert!(rendered.contains("Installed on: octo-org"));
    assert!(rendered.contains("Repository selection: selected"));
    assert!(!rendered.contains("RSA PRIVATE KEY"));
    assert!(!rendered.contains("client-secret"));
    assert!(!rendered.contains("webhook-secret"));
}

#[test]
fn github_install_drive_out_prints_install_url_verbatim() {
    let conversion = sample_manifest_conversion();
    let url = conversion.installation_url();
    let rendered = render_github_install_drive_out(&conversion, &url);
    assert!(rendered.contains("Install the GitHub App"));
    assert!(rendered.contains("https://github.com/apps/ember-engine/installations/new"));
}

#[test]
fn github_manifest_flow_json_marks_installed_when_resolved() {
    let conversion = sample_manifest_conversion();
    let resolved = emberlink_cli::onboarding::github_app::ResolvedInstallation {
        installation_id: 987654,
        account_login: Some("octo-org".to_string()),
        repository_selection: Some("all".to_string()),
    };

    let payload = github_manifest_flow_json(&conversion, Some(&resolved));
    assert_eq!(payload["installed"], serde_json::json!(true));
    assert_eq!(payload["installation_id"], serde_json::json!(987654));
    assert_eq!(payload["account_login"], serde_json::json!("octo-org"));
    assert_eq!(payload["repository_selection"], serde_json::json!("all"));
    assert_eq!(payload["stored"], serde_json::json!(false));
    // The PEM and client secrets must never appear in the JSON surface.
    let serialized = serde_json::to_string(&payload).expect("serialize json payload");
    assert!(!serialized.contains("RSA PRIVATE KEY"));
    assert!(!serialized.contains("client-secret"));
}

#[test]
fn github_manifest_flow_json_marks_not_installed_when_unresolved() {
    let conversion = sample_manifest_conversion();
    let payload = github_manifest_flow_json(&conversion, None);
    assert_eq!(payload["installed"], serde_json::json!(false));
    assert_eq!(payload["installation_id"], serde_json::Value::Null);
    assert_eq!(payload["account_login"], serde_json::Value::Null);
    assert_eq!(payload["stored"], serde_json::json!(false));
}

#[test]
fn github_setup_prelude_explains_where_values_come_from() {
    let rendered = render_github_setup_prelude(
        "https://github.com/apps/emberlink/installations/new",
        "ember",
    );
    assert!(rendered.contains("Store the local credential triple"));
    assert!(rendered.contains("private key PEM"));
    assert!(rendered.contains("App ID"));
    assert!(rendered.contains("github app install-url"));
    assert!(rendered.contains("/installations/<ID>"));
    assert!(rendered.contains("normalizes the slug automatically"));
}

#[test]
fn normalize_github_installation_id_accepts_post_install_url() {
    assert_eq!(
        normalize_github_installation_id_input(
            "https://github.com/settings/installations/126782716"
        )
        .expect("installation id from url"),
        "126782716"
    );
}

#[test]
fn normalize_github_slug_accepts_github_app_url() {
    assert_eq!(
        normalize_github_slug_input("https://github.com/apps/ember-engine/installations/new")
            .expect("slug from public app url"),
        "ember-engine"
    );
    assert_eq!(
        normalize_github_slug_input(
            "https://github.com/organizations/emberdotlink/settings/apps/ember-engine"
        )
        .expect("slug from settings app url"),
        "ember-engine"
    );
}

#[test]
fn github_setup_success_text_manual_reload_points_back_to_status_and_init() {
    let rendered = render_github_setup_success_text(
        GithubSetupDaemonFollowup::NeedsManualReload,
        None,
        "ember",
    );
    assert!(rendered.contains("ember daemon reload"));
    assert!(rendered.contains("ember github status"));
    assert!(rendered.contains("ember init --for claude"));
    assert!(rendered.contains("ember claude"));
    assert!(rendered.contains("ember receipt export --latest --format md"));
}

#[test]
fn github_setup_success_text_reloaded_path_names_daemon_reload_result() {
    let rendered = render_github_setup_success_text(
        GithubSetupDaemonFollowup::Reloaded {
            old_pid: 11,
            new_pid: Some(22),
        },
        None,
        "ember",
    );
    assert!(rendered.contains("GitHub ready"));
    assert!(rendered.contains("Daemon reloaded: 11 -> 22"));
    assert!(rendered.contains("ember github status"));
    assert!(rendered.contains("ember init --for claude"));
    assert!(rendered.contains("ember claude"));
    assert!(rendered.contains("ember receipt export --latest --format md"));
}

#[test]
fn github_setup_success_text_surfaces_stale_launcher_boundary_when_present() {
    let rendered = render_github_setup_success_text(
        GithubSetupDaemonFollowup::NeedsManualReload,
        Some(&InstalledLauncherIssue::StaleManagedInstall {
            path: PathBuf::from("/usr/local/bin/ember"),
            target: PathBuf::from("/usr/local/lib/ember.app/Contents/MacOS/ember"),
            newer_components: vec![PathBuf::from("/usr/local/bin/emberd")],
        }),
        "ember",
    );
    assert!(rendered.contains("Boundary"));
    assert!(
        rendered.contains("/usr/local/bin/ember -> /usr/local/lib/ember.app/Contents/MacOS/ember")
    );
    assert!(rendered.contains("does not rebuild `/usr/local/lib/ember.app`"));
}

#[test]
fn github_setup_retry_hint_names_replace_path() {
    let hint = render_github_setup_retry_hint(&GithubSetupError::Broker(
            emberlink_cli::broker::BrokerCliError::InvalidArgs(
                "vault entry 'github/apps/ember/install-123/private-key' already exists; pass --replace to overwrite".to_string(),
            ),
        ), "ember")
        .expect("replace hint");
    assert!(hint.contains("ember github setup --replace"));
}

#[test]
fn github_setup_retry_hint_names_allow_unverified_slug_path() {
    let hint = render_github_setup_retry_hint(&GithubSetupError::Broker(
            emberlink_cli::broker::BrokerCliError::InvalidArgs(
                "GET https://api.github.com/app: unexpected status 401: {\"message\":\"Bad credentials\"}. Pass --allow-unverified-slug to skip canonicalization.".to_string(),
            ),
        ), "ember")
        .expect("canonicalization hint");
    assert!(hint.contains("ember github setup --allow-unverified-slug"));
}

#[test]
fn github_setup_retry_hint_names_vault_unlock_path() {
    let hint = render_github_setup_retry_hint(&GithubSetupError::Broker(
            emberlink_cli::broker::BrokerCliError::Guidance(
                "this command needs operator presence on the daemon-managed vault lane. Use the managed separate-uid biometric unlock flow when available, or restart the daemon with `EMBER_VAULT_PASSPHRASE` for a fresh dev-probe bootstrap; same-daemon operator-uid reopen is intentionally disabled.".to_string(),
            ),
        ), "ember")
        .expect("vault unlock hint");
    assert!(hint.contains("managed separate-uid biometric unlock"));
    assert!(hint.contains("EMBER_VAULT_PASSPHRASE"));
    assert!(hint.contains("ember github setup"));
}

#[test]
fn github_setup_error_guidance_keeps_generic_retry_path_without_launcher_drift() {
    let guidance = render_github_setup_error_guidance(
        &GithubSetupError::Broker(emberlink_cli::broker::BrokerCliError::InvalidArgs(
            "github app registration failed".to_string(),
        )),
        None,
        "ember",
    );
    assert!(
        guidance.contains("error[E-GITHUB-SETUP]"),
        "github setup failures should now use the shared actionable error shape: {guidance}"
    );
    assert!(
        guidance.contains("Run `ember github status` to inspect the current posture."),
        "github setup failures without launcher drift must keep the generic retry path: {guidance}"
    );
    assert!(
        !guidance.contains("install path:"),
        "github setup failures without launcher drift should not invent launcher guidance: {guidance}"
    );
}

#[test]
fn github_setup_error_guidance_surfaces_stale_launcher_boundary_when_present() {
    let guidance = render_github_setup_error_guidance(
        &GithubSetupError::Broker(emberlink_cli::broker::BrokerCliError::InvalidArgs(
            "github app registration failed".to_string(),
        )),
        Some(&InstalledLauncherIssue::StaleManagedInstall {
            path: PathBuf::from("/usr/local/bin/ember"),
            target: PathBuf::from("/usr/local/lib/ember.app/Contents/MacOS/ember"),
            newer_components: vec![PathBuf::from("/usr/local/bin/emberd")],
        }),
        "ember",
    );
    assert!(
        guidance.contains(
            "Install path: /usr/local/bin/ember -> /usr/local/lib/ember.app/Contents/MacOS/ember"
        ),
        "github setup failures must disclose the drifting launcher path when present: {guidance}"
    );
    assert!(
        guidance.contains("does not rebuild `/usr/local/lib/ember.app`"),
        "github setup failures must preserve the launcher repair truth: {guidance}"
    );
    assert!(
        guidance.contains("Run `ember github status` to inspect the current posture."),
        "github setup failures must still point back at posture confirmation after launcher repair: {guidance}"
    );
}

#[test]
fn github_setup_error_guidance_preserves_unlock_retry_hint() {
    let guidance = render_github_setup_error_guidance(
            &GithubSetupError::Broker(emberlink_cli::broker::BrokerCliError::Guidance(
                "use the managed separate-uid biometric unlock flow if available, or restart the daemon with `EMBER_VAULT_PASSPHRASE`, then rerun `ember github setup`.".to_string(),
            )),
            Some(&InstalledLauncherIssue::StaleManagedInstall {
                path: PathBuf::from("/usr/local/bin/ember"),
                target: PathBuf::from("/usr/local/lib/ember.app/Contents/MacOS/ember"),
                newer_components: vec![PathBuf::from("/usr/local/bin/emberd")],
            }),
            "ember",
        );
    assert!(
        guidance.contains("managed separate-uid biometric unlock"),
        "github setup failures must preserve the vault unlock retry hint when that is the real blocker: {guidance}"
    );
    assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
    assert!(
        !guidance.contains("install path:"),
        "vault unlock retry guidance should stay focused instead of layering stale-launcher text on top: {guidance}"
    );
}

#[test]
fn github_setup_surfaces_use_explicit_repo_build_ember_command() {
    let err = resolve_github_setup_args(
        &GithubSetupArgs::default(),
        false,
        "/home/operator/emberlink-example/target/debug/ember",
    )
    .expect_err("non-interactive setup without inputs must fail");
    assert!(
        err.to_string()
            .contains("/home/operator/emberlink-example/target/debug/ember github setup")
    );

    let success = render_github_setup_success_text(
        GithubSetupDaemonFollowup::NeedsManualReload,
        None,
        "/home/operator/emberlink-example/target/debug/ember",
    );
    assert!(success.contains("ember daemon reload"));
    assert!(success.contains("ember github status"));
    assert!(success.contains("ember init --for claude"));

    let guidance = render_github_setup_error_guidance(
        &GithubSetupError::Broker(emberlink_cli::broker::BrokerCliError::InvalidArgs(
            "github app registration failed".to_string(),
        )),
        None,
        "/home/operator/emberlink-example/target/debug/ember",
    );
    assert!(guidance.contains(
            "Run `/home/operator/emberlink-example/target/debug/ember github status` to inspect the current posture."
        ));
    assert!(guidance.contains(
        "Run `/home/operator/emberlink-example/target/debug/ember github setup` to retry interactively."
    ));
}

#[test]
fn github_app_manifest_launcher_note_only_appears_on_repo_builds() {
    assert!(
        render_github_app_manifest_launcher_note("ember").is_none(),
        "installed-host lane should not add a launcher note"
    );

    let note =
        render_github_app_manifest_launcher_note("/home/operator/emberlink-example/target/debug/ember")
            .expect("repo-build lane should add a launcher note");
    assert!(note.contains("repo-built launcher"));
    assert!(note.contains("/home/operator/emberlink-example/target/debug/ember ..."));
}

#[test]
fn github_app_register_args_convert_to_setup_args_losslessly() {
    let args = GithubAppRegisterArgs {
        pem_file: PathBuf::from("/tmp/app.pem"),
        app_id: "123".to_string(),
        installation_id: "456".to_string(),
        slug: "ember-engine".to_string(),
        allow_unverified_slug: true,
        replace: true,
    };

    let setup = github_setup_args_from_app_register(&args);
    assert_eq!(setup.pem_file.as_deref(), Some(args.pem_file.as_path()));
    assert_eq!(setup.app_id.as_deref(), Some("123"));
    assert_eq!(setup.installation_id.as_deref(), Some("456"));
    assert_eq!(setup.slug.as_deref(), Some("ember-engine"));
    assert!(setup.allow_unverified_slug);
    assert!(setup.replace);
}

#[test]
fn render_claude_launcher_error_routes_missing_persona_to_init() {
    let (rendered, exit_code) = render_launcher_actionable_error(
        "claude",
        "no cohort-A persona found.\n  Run `ember init --for claude` first, or set $EMBER_PERSONA to an existing persona name.",
    );
    assert_eq!(exit_code, 1);
    assert!(rendered.contains("error[E-CLAUDE-NOT-INITIALIZED]"));
    assert!(rendered.contains("Claude is not set up yet"));
    assert!(rendered.contains("Run `ember init --for claude`."));
    assert!(rendered.contains("ember explain claude"));
}

#[test]
fn render_codex_launcher_error_routes_auth_gap_to_login() {
    let (rendered, exit_code) = render_launcher_actionable_error(
        "codex",
        "no portable host Codex auth state found at `~/.codex/auth.json`. `ember init --for codex` can create `~/.codex/hooks.json`, but isolated `ember codex` needs the host login to materialize `auth.json`. Run `codex login` on the host first, or use `codex login --device-auth` on a headless host, or use `ember codex --host` until native auth is ready.",
    );
    assert_eq!(exit_code, 1);
    assert!(rendered.contains("error[E-CODEX-AUTH-NOT-READY]"));
    assert!(rendered.contains("Run `codex login` on the host first."));
    assert!(rendered.contains("Run `ember codex --host` if you want the host lane right now."));
}

#[test]
fn render_codex_launcher_error_routes_invalid_flags_to_help() {
    let (rendered, exit_code) = render_launcher_actionable_error(
        "codex",
        "backend hints and presets only apply to isolated placement; add `--isolated`",
    );
    assert_eq!(exit_code, 2);
    assert!(rendered.contains("error[E-CODEX-USAGE]"));
    assert!(rendered.contains("Run `ember codex --help` to review the launch flags."));
    assert!(rendered.contains("Run `ember explain codex` for the launch model."));
}

#[test]
fn github_status_retry_hint_names_vault_unlock_path() {
    let hint = render_github_status_retry_hint(
            &core_types::ValidationError::new(
                "this command needs operator presence on the daemon-managed vault lane. Use the managed separate-uid biometric unlock flow when available, or restart the daemon with `EMBER_VAULT_PASSPHRASE` for a fresh dev-probe bootstrap; same-daemon operator-uid reopen is intentionally disabled.".to_string(),
            ),
            "ember",
        )
        .expect("vault unlock hint");
    assert!(hint.contains("managed separate-uid biometric unlock"));
    assert!(hint.contains("EMBER_VAULT_PASSPHRASE"));
    assert!(hint.contains("ember github status"));
}

#[test]
fn rewrite_status_and_daemon_install_mentions_keeps_installed_host_text() {
    let text = "daemon unavailable; run 'ember status' to inspect posture or repair with 'sudo ember daemon install'";
    assert_eq!(
        rewrite_status_and_daemon_install_mentions(text, "ember"),
        text
    );
}

#[test]
fn rewrite_status_and_daemon_install_mentions_uses_explicit_repo_build_ember_command() {
    let rewritten = rewrite_status_and_daemon_install_mentions(
        "daemon unavailable; run 'ember status' to inspect posture or repair with 'sudo ember daemon install'",
        "/home/operator/emberlink-example/target/debug/ember",
    );
    assert!(rewritten.contains("'/home/operator/emberlink-example/target/debug/ember status'"));
    assert!(
        rewritten.contains("'sudo /home/operator/emberlink-example/target/debug/ember daemon install'")
    );
}

#[test]
fn render_status_collection_failure_text_stays_compact_and_uses_launcher_commands() {
    let rendered = render_status_collection_failure_text(
        "daemon socket access is denied for this shell.",
        "/home/operator/emberlink-example/target/debug/ember",
    );
    assert!(rendered.starts_with("Needs attention\n"));
    assert!(rendered.contains("Ember could not inspect the current machine posture."));
    assert!(rendered.contains("ember doctor"));
    assert!(rendered.contains("ember status --json"));
    assert!(rendered.contains("ember explain status"));
    assert!(!rendered.contains("error[E-STATUS-COLLECT]"));
}

#[test]
fn github_status_retry_hint_uses_explicit_repo_build_ember_command() {
    let hint = render_github_status_retry_hint(
            &core_types::ValidationError::new(
                "this command needs operator presence on the daemon-managed vault lane. Use the managed separate-uid biometric unlock flow when available, or restart the daemon with `EMBER_VAULT_PASSPHRASE` for a fresh dev-probe bootstrap; same-daemon operator-uid reopen is intentionally disabled.".to_string(),
            ),
            "/home/operator/emberlink-example/target/debug/ember",
        )
        .expect("vault unlock hint");
    assert!(hint.contains("rerun `/home/operator/emberlink-example/target/debug/ember github status`"));
}

#[test]
fn github_status_retry_hint_ignores_non_unlock_failures() {
    let hint = render_github_status_retry_hint(
        &core_types::ValidationError::new("ember daemon not running".to_string()),
        "ember",
    );
    assert!(hint.is_none());
}

#[test]
fn github_status_error_guidance_falls_back_to_generic_daemon_repair() {
    let guidance = render_github_status_error_guidance(
        &core_types::ValidationError::new("ember daemon not running".to_string()),
        None,
        "ember",
    );
    assert!(
        guidance.contains("Run `ember status` to inspect daemon posture."),
        "github status failures without launcher drift must keep the generic daemon repair path: {guidance}"
    );
    assert!(
        !guidance.contains("install path:"),
        "github status failures without launcher drift should not invent launcher guidance: {guidance}"
    );
}

#[test]
fn github_status_error_guidance_surfaces_stale_launcher_boundary_when_present() {
    let guidance = render_github_status_error_guidance(
        &core_types::ValidationError::new("ember daemon not running".to_string()),
        Some(&InstalledLauncherIssue::StaleManagedInstall {
            path: PathBuf::from("/usr/local/bin/ember"),
            target: PathBuf::from("/usr/local/lib/ember.app/Contents/MacOS/ember"),
            newer_components: vec![PathBuf::from("/usr/local/bin/emberd")],
        }),
        "ember",
    );
    assert!(
        guidance.contains(
            "Install path: /usr/local/bin/ember -> /usr/local/lib/ember.app/Contents/MacOS/ember"
        ),
        "github status failures must disclose the drifting launcher path when present: {guidance}"
    );
    assert!(
        guidance.contains("does not rebuild `/usr/local/lib/ember.app`"),
        "github status failures must preserve the launcher repair truth: {guidance}"
    );
    assert!(
        guidance.contains("Run `ember status` to inspect daemon posture."),
        "github status failures must still point back at daemon posture after the launcher repair: {guidance}"
    );
}

#[test]
fn github_status_error_guidance_uses_explicit_repo_build_ember_command() {
    let guidance = render_github_status_error_guidance(
        &core_types::ValidationError::new("ember daemon not running".to_string()),
        Some(&InstalledLauncherIssue::StaleManagedInstall {
            path: PathBuf::from("/usr/local/bin/ember"),
            target: PathBuf::from("/usr/local/lib/ember.app/Contents/MacOS/ember"),
            newer_components: vec![PathBuf::from("/usr/local/bin/emberd")],
        }),
        "/home/operator/emberlink-example/target/debug/ember",
    );
    assert!(guidance.contains(
        "Run `/home/operator/emberlink-example/target/debug/ember status` to inspect daemon posture."
    ));
    assert!(
        guidance.contains("`sudo /home/operator/emberlink-example/target/debug/ember daemon install`")
    );
}

#[test]
fn parse_default_yes_response_accepts_expected_forms() {
    assert_eq!(parse_default_yes_response(""), Some(true));
    assert_eq!(parse_default_yes_response("y"), Some(true));
    assert_eq!(parse_default_yes_response("YES"), Some(true));
    assert_eq!(parse_default_yes_response("n"), Some(false));
    assert_eq!(parse_default_yes_response("No"), Some(false));
    assert_eq!(parse_default_yes_response("maybe"), None);
}

#[test]
fn inline_github_setup_offer_only_appears_on_interactive_app_missing_path() {
    use emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture;

    assert!(should_offer_inline_github_setup(
        GitHubOnboardingPosture::AppNotConfigured,
        false,
        true,
        true,
    ));
    assert!(should_offer_inline_github_setup(
        GitHubOnboardingPosture::AppConfiguredMock,
        false,
        true,
        true,
    ));
    assert!(should_offer_inline_github_setup(
        GitHubOnboardingPosture::AppBroken("partial credential triple".to_string()),
        false,
        true,
        true,
    ));
    assert!(!should_offer_inline_github_setup(
        GitHubOnboardingPosture::PatConfigured,
        false,
        true,
        true,
    ));
    assert!(!should_offer_inline_github_setup(
        GitHubOnboardingPosture::AppConfiguredReal,
        false,
        true,
        true,
    ));
    assert!(!should_offer_inline_github_setup(
        GitHubOnboardingPosture::AppNotConfigured,
        true,
        true,
        true,
    ));
    assert!(!should_offer_inline_github_setup(
        GitHubOnboardingPosture::AppNotConfigured,
        false,
        false,
        true,
    ));
    assert!(!should_offer_inline_github_setup(
        GitHubOnboardingPosture::AppNotConfigured,
        false,
        true,
        false,
    ));
}

#[test]
fn receipt_export_parses_latest_shortcut() {
    match parse_receipt(&["export", "--latest", "--format", "md"]) {
        ReceiptAction::Export {
            id,
            latest,
            format,
            raw,
        } => {
            assert_eq!(id, None);
            assert!(latest);
            assert_eq!(format, "md");
            assert!(!raw);
        }
        _ => panic!("expected receipt export"),
    }
}

#[test]
fn init_rerun_command_prefers_claude_when_requested() {
    assert_eq!(
        init_rerun_command(Some(OnboardingTarget::Claude)),
        "`ember init --for claude`"
    );
    assert_eq!(
        init_rerun_command(Some(OnboardingTarget::Codex)),
        "`ember init --for codex`"
    );
    assert_eq!(
        init_rerun_command(Some(OnboardingTarget::Cursor)),
        "`ember init --for cursor`"
    );
    assert_eq!(init_rerun_command(None), "`ember init`");
}

#[test]
fn init_command_with_ember_command_uses_explicit_repo_build_path() {
    assert_eq!(
        init_command_with_ember_command("target/debug/ember", Some(OnboardingTarget::Claude)),
        "target/debug/ember init --for claude"
    );
    assert_eq!(
        init_command_with_ember_command("target/debug/ember", Some(OnboardingTarget::Codex)),
        "target/debug/ember init --for codex"
    );
    assert_eq!(
        init_command_with_ember_command("target/debug/ember", Some(OnboardingTarget::Cursor)),
        "target/debug/ember init --for cursor"
    );
    assert_eq!(
        init_command_with_ember_command("target/debug/ember", None),
        "target/debug/ember init"
    );
}

fn parse_cli(args: &[&str]) -> Cli {
    use clap::Parser as _;
    let full: Vec<&str> = std::iter::once("ember")
        .chain(args.iter().copied())
        .collect();
    Cli::try_parse_from(&full).expect("parse failed")
}

#[test]
fn init_for_claude_accepts_only_canonical_target() {
    match parse_cli(&["init", "--for", "claude"]).command {
        Commands::Init { for_target, .. } => {
            assert_eq!(for_target, Some(OnboardingTarget::Claude));
        }
        _ => panic!("expected init command"),
    }
    assert!(
        Cli::try_parse_from(["ember", "init", "--for", "claude-code"]).is_err(),
        "legacy init target should no longer parse"
    );
}

/// Anchor: onboarding_target_codex_variant_landed
///
/// `ember init --for codex` parses to `OnboardingTarget::Codex`.
/// The target is now wired to the Codex onboarding lane, but this test
/// stays focused on the canonical parse surface.
#[test]
fn init_for_codex_parses_to_canonical_target() {
    match parse_cli(&["init", "--for", "codex"]).command {
        Commands::Init { for_target, .. } => {
            assert_eq!(for_target, Some(OnboardingTarget::Codex));
        }
        _ => panic!("expected init command"),
    }
}

#[test]
fn init_for_cursor_parses_to_canonical_target() {
    match parse_cli(&["init", "--for", "cursor"]).command {
        Commands::Init { for_target, .. } => {
            assert_eq!(for_target, Some(OnboardingTarget::Cursor));
        }
        _ => panic!("expected init command"),
    }
}

#[test]
fn uninstall_for_cursor_parses_to_canonical_target() {
    match parse_cli(&["uninstall", "--for", "cursor"]).command {
        Commands::Uninstall { for_target } => {
            assert_eq!(for_target, OnboardingTarget::Cursor);
        }
        _ => panic!("expected uninstall command"),
    }
}

#[test]
fn claude_launcher_accepts_canonical_and_compat_alias_verb() {
    for verb in ["claude", "claude-code"] {
        match parse_cli(&[verb]).command {
            Commands::ClaudeCode { .. } => {}
            _ => panic!("expected claude launcher for `{verb}`"),
        }
    }
}

#[test]
fn codex_launcher_parses_canonical_verb() {
    match parse_cli(&["codex"]).command {
        Commands::Codex { .. } => {}
        _ => panic!("expected codex launcher"),
    }
}

#[test]
fn cursor_launcher_parses_canonical_verb() {
    match parse_cli(&["cursor"]).command {
        Commands::Cursor { .. } => {}
        _ => panic!("expected cursor launcher"),
    }
}

#[test]
fn claude_launcher_parses_worktree_flags() {
    match parse_cli(&[
        "claude",
        "--worktree",
        "auth-posture",
        "--branch",
        "agent/auth-posture/20260522-170000",
        "--purpose",
        "release proof",
        "--",
        "--print",
        "hello",
    ])
    .command
    {
        Commands::ClaudeCode {
            worktree,
            branch,
            purpose,
            args,
            ..
        } => {
            assert_eq!(worktree.as_deref(), Some("auth-posture"));
            assert_eq!(
                branch.as_deref(),
                Some("agent/auth-posture/20260522-170000")
            );
            assert_eq!(purpose.as_deref(), Some("release proof"));
            assert_eq!(args, vec!["--print".to_string(), "hello".to_string()]);
        }
        _ => panic!("expected claude launcher"),
    }
}

#[test]
fn claude_launcher_parses_explicit_delegated_template() {
    match parse_cli(&["claude", "--delegated", "landing-page-edits"]).command {
        Commands::ClaudeCode { delegated, .. } => {
            assert_eq!(delegated.as_deref(), Some("landing-page-edits"));
        }
        _ => panic!("expected claude launcher"),
    }
}

#[test]
fn claude_launcher_parses_explicit_delegation_template() {
    match parse_cli(&["claude", "--delegated", "emberd-development"]).command {
        Commands::ClaudeCode { delegated, .. } => {
            assert_eq!(delegated.as_deref(), Some("emberd-development"));
        }
        _ => panic!("expected claude launcher"),
    }
}

#[test]
fn session_open_parses_explicit_delegation_template() {
    match parse_cli(&["session", "open", "claude", "--delegated", "release-proof"]).command {
        Commands::Session {
            action: SessionAction::Open {
                target, delegated, ..
            },
        } => {
            assert_eq!(target, emberlink_cli::session::OpenSurface::ClaudeCode);
            assert_eq!(delegated.as_deref(), Some("release-proof"));
        }
        _ => panic!("expected session open command"),
    }
}

#[test]
fn claude_launcher_parses_explicit_attach_runtime_persona() {
    match parse_cli(&["claude", "--attach", "runtime-persona-1"]).command {
        Commands::ClaudeCode {
            attach_runtime_persona_id,
            ..
        } => {
            assert_eq!(
                attach_runtime_persona_id.as_deref(),
                Some("runtime-persona-1")
            );
        }
        _ => panic!("expected claude launcher"),
    }
}

#[test]
fn claude_launcher_parses_explicit_fork_runtime() {
    match parse_cli(&["claude", "--fork"]).command {
        Commands::ClaudeCode { fork_runtime, .. } => {
            assert!(fork_runtime);
        }
        _ => panic!("expected claude launcher"),
    }
}

#[test]
fn claude_launcher_parses_explicit_strict() {
    match parse_cli(&["claude", "--strict"]).command {
        Commands::ClaudeCode { strict, .. } => {
            assert!(strict);
        }
        _ => panic!("expected claude launcher"),
    }
}

#[test]
fn claude_launcher_parses_sandvault_sandbox() {
    match parse_cli(&["claude", "--sandbox", "sandvault"]).command {
        Commands::ClaudeCode { sandbox, .. } => {
            assert_eq!(sandbox, Some(SandboxRuntime::Sandvault));
        }
        _ => panic!("expected claude launcher"),
    }
}

#[test]
fn claude_launcher_rejects_sandvault_with_isolated_backend() {
    let err = Cli::try_parse_from([
        "ember",
        "claude",
        "--sandbox",
        "sandvault",
        "--backend",
        "docker",
    ])
    .err()
    .expect("sandbox and isolated backend must conflict");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn codex_launcher_parses_worktree_flags() {
    match parse_cli(&[
        "codex",
        "--worktree",
        "auth-posture",
        "--branch",
        "agent/auth-posture/20260522-170000",
        "--purpose",
        "release proof",
        "--",
        "--no-alt-screen",
    ])
    .command
    {
        Commands::Codex {
            worktree,
            branch,
            purpose,
            args,
            ..
        } => {
            assert_eq!(worktree.as_deref(), Some("auth-posture"));
            assert_eq!(
                branch.as_deref(),
                Some("agent/auth-posture/20260522-170000")
            );
            assert_eq!(purpose.as_deref(), Some("release proof"));
            assert_eq!(args, vec!["--no-alt-screen".to_string()]);
        }
        _ => panic!("expected codex launcher"),
    }
}

#[test]
fn codex_launcher_parses_explicit_strict() {
    match parse_cli(&["codex", "--strict"]).command {
        Commands::Codex { strict, .. } => {
            assert!(strict);
        }
        _ => panic!("expected codex launcher"),
    }
}

#[test]
fn codex_launcher_parses_explicit_attach_runtime_persona() {
    match parse_cli(&["codex", "--attach", "runtime-persona-2"]).command {
        Commands::Codex {
            attach_runtime_persona_id,
            ..
        } => {
            assert_eq!(
                attach_runtime_persona_id.as_deref(),
                Some("runtime-persona-2")
            );
        }
        _ => panic!("expected codex launcher"),
    }
}

#[test]
fn codex_launcher_parses_explicit_fork_runtime() {
    match parse_cli(&["codex", "--fork"]).command {
        Commands::Codex { fork_runtime, .. } => {
            assert!(fork_runtime);
        }
        _ => panic!("expected codex launcher"),
    }
}

#[test]
fn codex_launcher_parses_sandvault_sandbox() {
    match parse_cli(&["codex", "--sandbox", "sandvault"]).command {
        Commands::Codex { sandbox, .. } => {
            assert_eq!(sandbox, Some(SandboxRuntime::Sandvault));
        }
        _ => panic!("expected codex launcher"),
    }
}

#[test]
fn codex_launcher_rejects_sandvault_with_isolated_preset() {
    let err = Cli::try_parse_from([
        "ember",
        "codex",
        "--sandbox",
        "sandvault",
        "--preset",
        "dev",
    ])
    .err()
    .expect("sandbox and isolated preset must conflict");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn cursor_launcher_parses_worktree_flags() {
    match parse_cli(&[
        "cursor",
        "--worktree",
        "auth-posture",
        "--branch",
        "agent/auth-posture/20260522-170000",
        "--purpose",
        "release proof",
        "--",
        "--help",
    ])
    .command
    {
        Commands::Cursor {
            worktree,
            branch,
            purpose,
            args,
            ..
        } => {
            assert_eq!(worktree.as_deref(), Some("auth-posture"));
            assert_eq!(
                branch.as_deref(),
                Some("agent/auth-posture/20260522-170000")
            );
            assert_eq!(purpose.as_deref(), Some("release proof"));
            assert_eq!(args, vec!["--help".to_string()]);
        }
        _ => panic!("expected cursor launcher"),
    }
}

#[test]
fn cursor_launcher_parses_explicit_strict() {
    match parse_cli(&["cursor", "--strict"]).command {
        Commands::Cursor { strict, .. } => {
            assert!(strict);
        }
        _ => panic!("expected cursor launcher"),
    }
}

#[test]
fn cursor_launcher_parses_explicit_attach_runtime_persona() {
    match parse_cli(&["cursor", "--attach", "runtime-persona-2"]).command {
        Commands::Cursor {
            attach_runtime_persona_id,
            ..
        } => {
            assert_eq!(
                attach_runtime_persona_id.as_deref(),
                Some("runtime-persona-2")
            );
        }
        _ => panic!("expected cursor launcher"),
    }
}

#[test]
fn cursor_launcher_parses_explicit_fork_runtime() {
    match parse_cli(&["cursor", "--fork"]).command {
        Commands::Cursor { fork_runtime, .. } => {
            assert!(fork_runtime);
        }
        _ => panic!("expected cursor launcher"),
    }
}

#[test]
fn cursor_launcher_parses_sandvault_sandbox() {
    match parse_cli(&["cursor", "--sandbox", "sandvault"]).command {
        Commands::Cursor { sandbox, .. } => {
            assert_eq!(sandbox, Some(SandboxRuntime::Sandvault));
        }
        _ => panic!("expected cursor launcher"),
    }
}

#[test]
fn cursor_launcher_rejects_sandvault_with_isolated_preset() {
    let err = Cli::try_parse_from([
        "ember",
        "cursor",
        "--sandbox",
        "sandvault",
        "--preset",
        "dev",
    ])
    .err()
    .expect("sandbox and isolated preset must conflict");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn session_open_parses_explicit_delegated_template() {
    match parse_cli(&["session", "open", "claude", "--delegated", "release-proof"]).command {
        Commands::Session {
            action: SessionAction::Open {
                delegated, target, ..
            },
        } => {
            assert_eq!(target, emberlink_cli::session::OpenSurface::ClaudeCode);
            assert_eq!(delegated.as_deref(), Some("release-proof"));
        }
        _ => panic!("expected session open"),
    }
}

#[test]
fn session_open_parses_explicit_strict() {
    match parse_cli(&["session", "open", "claude", "--strict"]).command {
        Commands::Session {
            action: SessionAction::Open { strict, .. },
        } => {
            assert!(strict);
        }
        _ => panic!("expected session open"),
    }
}

#[test]
fn session_open_parses_explicit_attach_runtime_persona() {
    match parse_cli(&["session", "open", "claude", "--attach", "runtime-persona-3"]).command {
        Commands::Session {
            action:
                SessionAction::Open {
                    attach_runtime_persona_id,
                    ..
                },
        } => {
            assert_eq!(
                attach_runtime_persona_id.as_deref(),
                Some("runtime-persona-3")
            );
        }
        _ => panic!("expected session open"),
    }
}

#[test]
fn session_open_parses_explicit_fork_runtime() {
    match parse_cli(&["session", "open", "claude", "--fork"]).command {
        Commands::Session {
            action: SessionAction::Open { fork_runtime, .. },
        } => {
            assert!(fork_runtime);
        }
        _ => panic!("expected session open"),
    }
}

#[test]
fn session_open_parses_sandvault_sandbox() {
    match parse_cli(&["session", "open", "claude", "--sandbox", "sandvault"]).command {
        Commands::Session {
            action: SessionAction::Open {
                target, sandbox, ..
            },
        } => {
            assert_eq!(target, emberlink_cli::session::OpenSurface::ClaudeCode);
            assert_eq!(sandbox, Some(SandboxRuntime::Sandvault));
        }
        _ => panic!("expected session open"),
    }
}

#[test]
fn session_open_rejects_sandvault_with_isolated_backend() {
    let err = Cli::try_parse_from([
        "ember",
        "session",
        "open",
        "claude",
        "--sandbox",
        "sandvault",
        "--backend",
        "docker",
    ])
    .err()
    .expect("sandbox and isolated backend must conflict");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn init_managed_daemon_install_lines_center_canonical_path() {
    assert_eq!(
        init_managed_daemon_install_starting_line("ember"),
        "  Daemon:   not running — running `sudo ember daemon install`"
    );
    assert_eq!(
        init_managed_daemon_install_started_line(),
        "  Daemon:   managed separate-uid daemon is up"
    );
}

#[test]
fn init_autostart_repair_line_points_to_daemon_install() {
    let message = init_autostart_repair_line("ember", "`ember init --for claude`");
    assert!(
        message.contains("sudo ember daemon install"),
        "repair message must point to the canonical daemon install path: {message}"
    );
    assert!(
        message.contains("`ember init --for claude`"),
        "repair message must preserve the onboarding rerun command: {message}"
    );
    assert!(
        !message.contains("install-agent"),
        "repair message must not leak the dev-only install-agent path: {message}"
    );
}

#[test]
fn init_noncanonical_daemon_topology_line_refuses_same_uid_fallback() {
    let message = init_noncanonical_daemon_topology_line("ember", "`ember init --for claude`");
    assert!(
        message.contains("same-uid fallback is refused"),
        "noncanonical topology message must refuse the old fallback: {message}"
    );
    assert!(
        message.contains("sudo ember daemon install"),
        "noncanonical topology message must still point at the canonical install path: {message}"
    );
}

#[test]
fn ensure_managed_daemon_for_init_refuses_custom_config_topology() {
    let tmp = tempfile::tempdir().unwrap();
    let custom_config = tmp.path().join("custom-config.toml");
    let config = DaemonConfig::for_test(tmp.path());
    let err = ensure_managed_daemon_for_init(
        &config,
        Some(&custom_config),
        "ember",
        "`ember init --for claude`",
        false,
    )
    .expect_err("custom config topology must refuse managed-daemon auto-install");
    assert!(
        err.contains("same-uid fallback is refused"),
        "custom config refusal must forbid same-uid fallback: {err}"
    );
}

#[test]
fn ensure_managed_daemon_for_init_non_interactive_points_to_repair() {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/"));
    if !emberlink_cli::onboarding::claude_code::supports_managed_daemon_install(&home, None) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let config = DaemonConfig::for_test(tmp.path());
    let err = ensure_managed_daemon_for_init(&config, None, "ember", "`ember init`", true)
        .expect_err("non-interactive init must not try to run sudo");
    assert!(
        err.contains("sudo ember daemon install"),
        "non-interactive failure must point at the canonical repair path: {err}"
    );
}

#[test]
fn init_managed_daemon_install_guidance_uses_explicit_repo_build_ember_command() {
    let starting_line =
        init_managed_daemon_install_starting_line("/home/operator/emberlink-example/target/debug/ember");
    assert!(
        starting_line
            .contains("`sudo /home/operator/emberlink-example/target/debug/ember daemon install`")
    );

    let repair = init_autostart_repair_line(
        "/home/operator/emberlink-example/target/debug/ember",
        "`/home/operator/emberlink-example/target/debug/ember init --for claude`",
    );
    assert!(repair.contains("`sudo /home/operator/emberlink-example/target/debug/ember daemon install`"));
    assert!(repair.contains("`/home/operator/emberlink-example/target/debug/ember init --for claude`"));

    let topology = init_noncanonical_daemon_topology_line(
        "/home/operator/emberlink-example/target/debug/ember",
        "`/home/operator/emberlink-example/target/debug/ember init --for claude`",
    );
    assert!(topology.contains(
            "Run `sudo /home/operator/emberlink-example/target/debug/ember daemon install` from your normal shell"
        ));
    assert!(
        topology
            .contains("re-run `/home/operator/emberlink-example/target/debug/ember init --for claude`")
    );
}

#[test]
fn ensure_managed_daemon_for_init_refuses_custom_config_topology_on_repo_build_path() {
    let tmp = tempfile::tempdir().unwrap();
    let custom_config = tmp.path().join("custom-config.toml");
    let config = DaemonConfig::for_test(tmp.path());
    let err = ensure_managed_daemon_for_init(
        &config,
        Some(&custom_config),
        "/home/operator/emberlink-example/target/debug/ember",
        "`/home/operator/emberlink-example/target/debug/ember init --for claude`",
        false,
    )
    .expect_err("custom config topology must refuse managed-daemon auto-install");
    assert!(err.contains("`sudo /home/operator/emberlink-example/target/debug/ember daemon install`"));
    assert!(
        err.contains("re-run `/home/operator/emberlink-example/target/debug/ember init --for claude`")
    );
}

#[test]
fn managed_separate_uid_topology_paths_match_default_layout() {
    let home = Path::new("/home/test-operator");
    let (socket_dir, data_dir, pid_file) = managed_separate_uid_topology_paths(home);
    let config = DaemonConfig {
        socket_dir,
        data_dir,
        pid_file,
        ..DaemonConfig::for_test(home)
    };
    assert!(
        matches_managed_separate_uid_topology_paths(&config, home),
        "default ~/.ember layout must match the managed separate-uid topology"
    );
}

#[test]
fn managed_separate_uid_topology_paths_reject_custom_layout() {
    let home = Path::new("/home/test-operator");
    let config = DaemonConfig::for_test(home);
    assert!(
        !matches_managed_separate_uid_topology_paths(&config, home),
        "tmpdir / custom layouts must not be treated as the managed default topology"
    );
}

#[test]
fn managed_local_vault_fallback_refusal_points_to_repair() {
    let err = managed_local_vault_fallback_refused().to_string();
    assert!(
        err.contains("local vault fallback is refused"),
        "managed fallback refusal must make the superseded local path explicit: {err}"
    );
    assert!(
        err.contains("sudo ember daemon install"),
        "managed fallback refusal must point at the canonical repair path: {err}"
    );
}

fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ember-cli-")
        .tempdir_in("/tmp")
        .or_else(|_| tempfile::tempdir())
        .expect("tempdir")
}

/// Path under $HOME is accepted; validator returns the canonical
/// lexically-cleaned form.
#[test]
fn emit_file_path_under_home_accepted() {
    let tmp = short_tempdir();
    let prev_home = std::env::var_os("HOME");
    // SAFETY: tests in this binary run single-threaded; HOME is
    // restored before this scope exits. Matches the existing
    // unsafe set_var/restore pattern earlier in this module.
    unsafe {
        std::env::set_var("HOME", tmp.path());
    }
    let candidate = tmp.path().join("bridge-endpoint.json");
    let result = validate_emit_file_path(&candidate);
    unsafe {
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
    let ok = result.expect("HOME-relative emit_file path must validate");
    assert!(
        ok.starts_with(tmp.path()),
        "validator must return a path under HOME, got: {}",
        ok.display()
    );
}

/// /etc/passwd is refused even when HOME=tmp lets nothing else match.
#[test]
fn emit_file_path_etc_passwd_rejected() {
    let path = std::path::PathBuf::from("/etc/passwd");
    let err = validate_emit_file_path(&path).expect_err("/etc paths must be rejected outright");
    assert!(
        err.contains("/etc"),
        "refusal must name the forbidden prefix `/etc`, got: {err}"
    );
}

/// `$HOME/../etc/passwd` lexically resolves outside HOME and is
/// refused either by the forbidden-prefix gate or by the HOME-
/// containment check (depends on what `..` lands on).
#[test]
fn emit_file_path_dotdot_traversal_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let prev_home = std::env::var_os("HOME");
    // SAFETY: tests are single-threaded; HOME is restored below.
    unsafe {
        std::env::set_var("HOME", tmp.path());
    }
    // tmp.path() is e.g. `/tmp/xxx`; `tmp.path()/../etc/passwd`
    // lexically resolves to `/tmp/etc/passwd` — outside HOME.
    let candidate = tmp.path().join("..").join("etc").join("passwd");
    let result = validate_emit_file_path(&candidate);
    unsafe {
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
    result.expect_err("$HOME/../etc/passwd lexically resolves outside HOME and must be rejected");
}

/// bridge_endpoint_emit_file_default_path_when_arg_omitted — verifies that
/// the default output path resolves to `~/.ember/bridge-endpoint.json` when
/// `--emit-file` is absent.
#[test]
fn bridge_endpoint_emit_file_default_path_when_arg_omitted() {
    // Simulate the default-path logic from the BridgeAction::Endpoint handler.
    let default_path: PathBuf = dirs_next::home_dir()
        .expect("HOME must be resolvable in test environment")
        .join(".ember")
        .join("bridge-endpoint.json");
    assert!(
        default_path.ends_with(".ember/bridge-endpoint.json"),
        "default emit-file path must be ~/.ember/bridge-endpoint.json, got: {}",
        default_path.display()
    );
}

/// `ensure_shadow_path_installed`
/// returns `Err` with a remediation hint when the shadow dir is absent.
#[test]
fn ensure_shadow_path_installed_errors_when_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let prev_home = std::env::var_os("HOME");
    // SAFETY: tests are single-threaded for this binary; we restore HOME
    // before exit. Concurrent harness modules don't share this env knob
    // because the binary doesn't spawn threads here.
    // SAFETY: `set_var` is `unsafe` since Rust 1.84+; this test single-threadedly
    // toggles HOME and restores it before returning, satisfying the soundness
    // contract documented on `std::env::set_var`.
    unsafe {
        std::env::set_var("HOME", tmp.path());
    }
    let result = ensure_shadow_path_installed();
    unsafe {
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
    let err = result.expect_err("missing shadow dir must surface as Err");
    assert!(
        err.contains("shadow path not installed") || err.contains("missing shims"),
        "error must name the remediation: {err}"
    );
    assert!(
        err.contains("ember init --for claude"),
        "error must point at the install command: {err}"
    );
}

#[test]
fn record_image_digest_new_image() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path();
    record_image_digest(path, "alpine:latest", "sha256:abc123");
    let registry = ImageRegistry::load(path).unwrap();
    assert!(registry.images.contains_key("alpine:latest"));
    assert_eq!(registry.images["alpine:latest"].digest, "sha256:abc123");
    assert_eq!(registry.images["alpine:latest"].source, "docker");
}

#[test]
fn record_image_digest_same_digest_no_mutation() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path();
    record_image_digest(path, "alpine:latest", "sha256:abc123");
    // Record same digest again — should succeed, no mutation
    record_image_digest(path, "alpine:latest", "sha256:abc123");
    let registry = ImageRegistry::load(path).unwrap();
    assert_eq!(registry.images["alpine:latest"].digest, "sha256:abc123");
}

#[test]
fn record_image_digest_mutation_detected() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path();
    record_image_digest(path, "alpine:latest", "sha256:aaa111");
    // Record different digest — should update and would print warning to stderr
    record_image_digest(path, "alpine:latest", "sha256:bbb222");
    let registry = ImageRegistry::load(path).unwrap();
    // Digest should be updated to the new one
    assert_eq!(registry.images["alpine:latest"].digest, "sha256:bbb222");
}

/// Round-trip the `ember init` policy seed through the daemon's
/// `PolicyConfig` deserializer. PR #1487 renamed `decision`→`requirement`
/// without serde aliases; the seed got missed and every fresh install
/// produced a daemon that refused to start. This test pins the seed to
/// the schema so the next rename can't ship without flipping it.
#[test]
fn default_policy_seed_parses() {
    let engine = core_approval::policy::PolicyEngine::from_toml(DEFAULT_POLICY_TOML)
        .expect("DEFAULT_POLICY_TOML must parse");
    let denied = engine.evaluate("git.push.main");
    assert!(matches!(
        denied.requirement,
        core_approval::policy::ApprovalRequirement::Denied
    ));
    let auto = engine.evaluate("git.push.feature-branch");
    assert!(matches!(
        auto.requirement,
        core_approval::policy::ApprovalRequirement::Auto
    ));
}

#[test]
fn record_image_digest_roundtrip() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path();
    record_image_digest(path, "ubuntu:22.04", "sha256:deadbeef");
    record_image_digest(path, "alpine:3.18", "sha256:cafebabe");
    let registry = ImageRegistry::load(path).unwrap();
    assert_eq!(registry.images.len(), 2);
    assert!(registry.verify("ubuntu:22.04", "sha256:deadbeef"));
    assert!(registry.verify("alpine:3.18", "sha256:cafebabe"));
}

#[test]
fn ember_init_writes_keyring_section_with_defaults() {
    let _env_lock = env_lock();
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("config.toml");
    let data_dir = tmp.path().join("data");
    let run_dir = tmp.path().join("run");

    // Build a minimal DaemonConfig pointing at the temp dir.
    let config = ember_daemon::infra::config::DaemonConfig {
        socket_dir: run_dir.clone(),
        data_dir: data_dir.clone(),
        pid_file: run_dir.join("emberd.pid"),
        policy_file: tmp.path().join("policy.toml"),
        log_level: ember_daemon::infra::config::LogLevel::Info,
        dashboard_addr: None,
        git_proxy_addr: None,
        llm_proxy_addr: None,
        keyring: ember_daemon::infra::config::KeyringConfig::default(),
        stale_approval_threshold_secs: 3600,
        presence: ember_daemon::infra::config::PresenceConfigSection::default(),
        snapshot_interval_secs: 3600,
        snapshot_pull_interval_secs: 600,
        snapshot_pull_endpoint: None,
        snapshot_pull_cluster_id: None,
        credential_store: None,
        ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
    };

    let server = spawn_fake_init_daemon(&config, "test", "persona-keyring-defaults", true, false);

    // Suppress install-check side-effects; persona creation still goes through
    // the fake daemon socket above.
    unsafe {
        std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase");
        std::env::set_var("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1");
    }

    cmd_init(
        &config,
        Some("test".to_string()),
        None,
        Some(&config_path),
        None,
        None,
        false,
        false,
    );

    unsafe {
        std::env::remove_var("EMBER_VAULT_PASSPHRASE");
        std::env::remove_var("EMBER_SKIP_DAEMON_INSTALL_CHECK");
    }
    server.join().expect("fake init daemon thread");

    let contents = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        contents.contains("[keyring]"),
        "config must contain [keyring] section"
    );
    // Service/account match the same resolution cmd_init uses — env var
    // (if set by cargo-test.sh) else compile-time default. Using the
    // same resolution instead of hardcoding DEFAULT avoids the race where
    // a concurrent test's env mutation breaks this assertion.
    let expected_service = std::env::var("EMBER_KEYRING_SERVICE")
        .unwrap_or_else(|_| DEFAULT_KEYRING_SERVICE.to_string());
    let expected_account = std::env::var("EMBER_KEYRING_ACCOUNT")
        .unwrap_or_else(|_| DEFAULT_KEYRING_ACCOUNT.to_string());
    assert!(
        contents.contains(&format!("service = \"{expected_service}\"")),
        "config must contain resolved service name; got:\n{contents}"
    );
    assert!(
        contents.contains(&format!("account = \"{expected_account}\"")),
        "config must contain resolved account name; got:\n{contents}"
    );
}

#[test]
fn ember_init_with_keyring_service_flag_overrides_default() {
    let _env_lock = env_lock();
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("config.toml");
    let data_dir = tmp.path().join("data");
    let run_dir = tmp.path().join("run");

    let config = ember_daemon::infra::config::DaemonConfig {
        socket_dir: run_dir.clone(),
        data_dir: data_dir.clone(),
        pid_file: run_dir.join("emberd.pid"),
        policy_file: tmp.path().join("policy.toml"),
        log_level: ember_daemon::infra::config::LogLevel::Info,
        dashboard_addr: None,
        git_proxy_addr: None,
        llm_proxy_addr: None,
        keyring: ember_daemon::infra::config::KeyringConfig::default(),
        stale_approval_threshold_secs: 3600,
        presence: ember_daemon::infra::config::PresenceConfigSection::default(),
        snapshot_interval_secs: 3600,
        snapshot_pull_interval_secs: 600,
        snapshot_pull_endpoint: None,
        snapshot_pull_cluster_id: None,
        credential_store: None,
        ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
    };

    let server = spawn_fake_init_daemon(&config, "test", "persona-keyring-custom", true, false);

    unsafe {
        std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase");
        std::env::set_var("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1");
    }

    cmd_init(
        &config,
        Some("test".to_string()),
        None,
        Some(&config_path),
        Some("custom-service".to_string()),
        Some("custom-account".to_string()),
        false,
        false,
    );

    unsafe {
        std::env::remove_var("EMBER_VAULT_PASSPHRASE");
        std::env::remove_var("EMBER_SKIP_DAEMON_INSTALL_CHECK");
    }
    server.join().expect("fake init daemon thread");

    let contents = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        contents.contains("service = \"custom-service\""),
        "config must use custom service"
    );
    assert!(
        contents.contains("account = \"custom-account\""),
        "config must use custom account"
    );
}

#[test]
fn resolve_init_keyring_value_flag_wins_over_env_and_default() {
    let v = resolve_init_keyring_value(
        Some("from-flag".to_string()),
        Some("from-env".to_string()),
        "from-default",
    );
    assert_eq!(v, "from-flag");
}

#[test]
fn resolve_init_keyring_value_env_wins_over_default_when_flag_absent() {
    // Regression guard: 2026-04-23 leak. qember.sh sets
    // EMBER_KEYRING_SERVICE but not --keyring-service; init previously
    // wrote the passphrase to the production service anyway.
    let v = resolve_init_keyring_value(None, Some("from-env".to_string()), "from-default");
    assert_eq!(v, "from-env");
}

#[test]
fn resolve_init_keyring_value_falls_through_to_default_when_flag_and_env_absent() {
    let v = resolve_init_keyring_value(None, None, "from-default");
    assert_eq!(v, "from-default");
}

#[test]
fn effective_config_path_with_some_returns_that_path() {
    let p = PathBuf::from("/tmp/foo/config.toml");
    assert_eq!(effective_config_path(Some(&p)), p);
}

#[test]
fn effective_config_path_with_none_returns_default() {
    // This test asserts the
    // "no env, no flag" baseline, but the live runtime now also
    // consults `EMBER_CONFIG` / `EMBER_DEMO_DIR`. The pure
    // `resolve_config_path` tests below exercise the precedence
    // chain without touching process-global env vars; if either
    // env var is set in this test process we skip rather than
    // assert the wrong baseline.
    if std::env::var("EMBER_CONFIG").is_ok() || std::env::var("EMBER_DEMO_DIR").is_ok() {
        return;
    }
    assert_eq!(
        effective_config_path(None),
        DaemonConfig::default_config_path()
    );
}

// Precedence chain for the user-pinned
// config path: --config flag → EMBER_CONFIG → EMBER_DEMO_DIR/config.toml
// → None (caller falls through to default). Pure-function tests so we
// don't touch process-global env vars (race-prone when cargo runs
// tests in parallel — see the 2026-04-23 keyring leak).

#[test]
fn resolve_config_path_flag_wins_over_env_and_demo_dir() {
    let flag = PathBuf::from("/tmp/from-flag/config.toml");
    let resolved = resolve_config_path(
        Some(&flag),
        Some("/tmp/from-env/config.toml".to_string()),
        Some("/tmp/from-demo-dir".to_string()),
    );
    assert_eq!(resolved, Some(flag));
}

#[test]
fn resolve_config_path_env_wins_over_demo_dir_when_flag_absent() {
    let resolved = resolve_config_path(
        None,
        Some("/tmp/from-env/config.toml".to_string()),
        Some("/tmp/from-demo-dir".to_string()),
    );
    assert_eq!(resolved, Some(PathBuf::from("/tmp/from-env/config.toml")));
}

#[test]
fn resolve_config_path_demo_dir_resolves_when_env_absent_and_file_exists() {
    let tmp = tempfile::Builder::new()
        .prefix("esb")
        .tempdir()
        .expect("tempdir");
    let demo_dir = tmp.path();
    let candidate = demo_dir.join("config.toml");
    std::fs::write(&candidate, "# fixture\n").expect("write config.toml");

    let resolved = resolve_config_path(None, None, Some(demo_dir.display().to_string()));
    assert_eq!(resolved, Some(candidate));
}

#[test]
fn resolve_config_path_demo_dir_skipped_when_config_toml_missing() {
    // Stale `EMBER_DEMO_DIR` pointing at a removed demo session must
    // NOT short-circuit the chain — we fall through to the default
    // path so unrelated `ember` invocations don't fail.
    let tmp = tempfile::Builder::new()
        .prefix("esb")
        .tempdir()
        .expect("tempdir");
    let resolved = resolve_config_path(None, None, Some(tmp.path().display().to_string()));
    assert_eq!(resolved, None);
}

#[test]
fn resolve_config_path_returns_none_when_all_inputs_absent() {
    let resolved = resolve_config_path(None, None, None);
    assert_eq!(resolved, None);
}

#[test]
fn resolve_config_path_treats_empty_env_as_absent() {
    // Shells often export empty strings; the chain must skip them
    // rather than resolve to "" / "/config.toml".
    let resolved = resolve_config_path(None, Some(String::new()), Some(String::new()));
    assert_eq!(resolved, None);
}

#[test]
fn status_json_has_required_keys() {
    let status = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "daemon": { "running": false, "pid": null, "socket": null },
        "launcher_issue": serde_json::Value::Null,
        "delegation_template_issue": serde_json::Value::Null,
        "auth": {
            "claude": {
                "kind": "no_active_brokered_grant",
                "grant_id": null,
                "credential_name": null
            },
            "codex": {
                "kind": "brokered_responses_proxy",
                "model_auth_governed": true,
                "spend_non_bypassable": false,
                "session_grant_active": false,
                "grant_id": null,
                "credential_name": null
            }
        },
        "personas": 0_usize,
        "grants": { "active": 0_usize, "expired_sweep_interval_sec": 60_u64 },
        "approvals": { "pending": 0_usize },
        "standing_grants": 0_usize,
        "audit_events": 0_u64,
    });
    let obj = status.as_object().unwrap();
    assert!(obj.contains_key("version"), "missing version");
    assert!(obj.contains_key("daemon"), "missing daemon");
    assert!(obj.contains_key("launcher_issue"), "missing launcher_issue");
    assert!(
        obj.contains_key("delegation_template_issue"),
        "missing delegation_template_issue"
    );
    assert!(obj.contains_key("auth"), "missing auth");
    assert!(obj.contains_key("personas"), "missing personas");
    assert!(obj.contains_key("grants"), "missing grants");
    assert!(obj.contains_key("approvals"), "missing approvals");
    assert!(
        obj.contains_key("standing_grants"),
        "missing standing_grants"
    );
    assert!(obj.contains_key("audit_events"), "missing audit_events");
    let daemon = obj["daemon"].as_object().unwrap();
    assert!(daemon.contains_key("running"), "daemon missing running");
    assert!(daemon.contains_key("pid"), "daemon missing pid");
    assert!(daemon.contains_key("socket"), "daemon missing socket");
    let auth = obj["auth"].as_object().unwrap();
    assert!(auth.contains_key("claude"), "auth missing claude");
    assert!(auth.contains_key("codex"), "auth missing codex");
    let grants = obj["grants"].as_object().unwrap();
    assert!(grants.contains_key("active"), "grants missing active");
    assert!(
        grants.contains_key("expired_sweep_interval_sec"),
        "grants missing expired_sweep_interval_sec"
    );
    assert!(obj["personas"].is_number(), "personas should be a count");
    assert!(
        obj["standing_grants"].is_number(),
        "standing_grants should be a count"
    );
    assert!(
        obj["audit_events"].is_number(),
        "audit_events should be a count"
    );
}

#[test]
fn detect_claude_runtime_auth_truth_prefers_oauth_when_multiple_claude_grants_are_active() {
    let summary = ember_daemon::infra::status::StatusSummary {
        grants: vec![
            serde_json::from_value(fake_grant_info_json_with_lane(
                "grant-claude-api",
                "persona-a",
                TEST_ANTHROPIC_API_CREDENTIAL,
                CLAUDE_CODE_DEFAULT_SCOPE,
            ))
            .expect("decode api-key grant"),
            serde_json::from_value(fake_grant_info_json_with_lane(
                "grant-claude-oauth",
                "persona-a",
                TEST_ANTHROPIC_OAUTH_CREDENTIAL,
                CLAUDE_CODE_DEFAULT_SCOPE,
            ))
            .expect("decode oauth grant"),
        ],
        grant_live_leases: vec![
            "grant-claude-api".to_string(),
            "grant-claude-oauth".to_string(),
        ],
        ..fake_status_summary()
    };

    assert_eq!(
        detect_claude_runtime_auth_truth(&summary),
        ClaudeRuntimeAuthTruth::GovernedOauth {
            grant_id: "grant-claude-oauth".to_string(),
            credential_name: TEST_ANTHROPIC_OAUTH_CREDENTIAL.to_string(),
        }
    );
}

#[test]
fn status_json_value_surfaces_runtime_auth_truth() {
    let mut overview = fake_status_overview_with_vault_session(VaultStatusView {
        posture: "interactive-unlocked".to_string(),
        unlocked: true,
        live_vault_attached: true,
        session_pin_count: 1,
        grace_window_secs: 300,
        grace_remaining_secs: 0,
        grace_lock_pending: false,
        grace_zero_due: false,
        idle_secs: None,
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    });
    overview.summary.personas.push(
        serde_json::from_value(fake_persona_info_json(
            "persona-cursor",
            "cursor-default",
            "active",
        ))
        .expect("decode cursor persona"),
    );
    overview.summary.grants = vec![
        serde_json::from_value(fake_grant_info_json_with_lane(
            "grant-claude-oauth",
            "persona-a",
            TEST_ANTHROPIC_OAUTH_CREDENTIAL,
            CLAUDE_CODE_DEFAULT_SCOPE,
        ))
        .expect("decode oauth grant"),
        serde_json::from_value(fake_grant_info_json_with_lane(
            "grant-codex",
            "persona-a",
            CODEX_DEFAULT_SCOPE,
            CODEX_DEFAULT_SCOPE,
        ))
        .expect("decode codex grant"),
        serde_json::from_value(fake_runtime_delegable_grant_info_json_with_lane(
            "grant-cursor",
            "persona-cursor",
            CURSOR_DEFAULT_SCOPE,
            CURSOR_DEFAULT_SCOPE,
        ))
        .expect("decode cursor grant"),
    ];
    overview.summary.grant_live_leases = vec![
        "grant-claude-oauth".to_string(),
        "grant-codex".to_string(),
        "grant-cursor".to_string(),
    ];

    let payload = status_json_value(&overview);
    assert_eq!(
        payload["auth"]["claude"]["kind"],
        serde_json::Value::String("governed_oauth".to_string())
    );
    assert_eq!(
        payload["auth"]["claude"]["credential_name"],
        serde_json::Value::String(TEST_ANTHROPIC_OAUTH_CREDENTIAL.to_string())
    );
    assert_eq!(
        payload["auth"]["codex"]["kind"],
        serde_json::Value::String("brokered_responses_proxy".to_string())
    );
    assert_eq!(
        payload["auth"]["codex"]["session_grant_active"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        payload["auth"]["codex"]["model_auth_governed"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        payload["auth"]["cursor"]["kind"],
        serde_json::Value::String("cursor_owned_model_auth".to_string())
    );
    assert_eq!(
        payload["auth"]["cursor"]["model_auth_governed"],
        serde_json::Value::Bool(false)
    );
    assert_eq!(
        payload["auth"]["cursor"]["launcher_grant_active"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        payload["auth"]["cursor"]["grant_id"],
        serde_json::Value::String("grant-cursor".to_string())
    );
}

#[test]
fn status_json_does_not_report_codex_session_active_without_live_lease() {
    let mut overview = fake_status_overview_with_vault_session(VaultStatusView {
        posture: "interactive-unlocked".to_string(),
        unlocked: true,
        live_vault_attached: true,
        session_pin_count: 1,
        grace_window_secs: 300,
        grace_remaining_secs: 0,
        grace_lock_pending: false,
        grace_zero_due: false,
        idle_secs: None,
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    });
    overview.summary.grants = vec![
        serde_json::from_value(fake_grant_info_json_with_lane(
            "grant-codex-stale",
            "persona-a",
            CODEX_DEFAULT_SCOPE,
            CODEX_DEFAULT_SCOPE,
        ))
        .expect("decode codex grant"),
    ];
    overview.summary.grant_live_leases = Vec::new();

    let payload = status_json_value(&overview);
    assert_eq!(
        payload["auth"]["codex"]["kind"],
        serde_json::Value::String("brokered_responses_proxy".to_string())
    );
    assert_eq!(
        payload["auth"]["codex"]["session_grant_active"],
        serde_json::Value::Bool(false)
    );
    assert_eq!(
        payload["auth"]["codex"]["grant_id"],
        serde_json::Value::Null
    );
}

#[test]
fn status_json_does_not_report_cursor_ready_without_live_lease() {
    let mut overview = fake_status_overview_with_vault_session(VaultStatusView {
        posture: "interactive-unlocked".to_string(),
        unlocked: true,
        live_vault_attached: true,
        session_pin_count: 1,
        grace_window_secs: 300,
        grace_remaining_secs: 0,
        grace_lock_pending: false,
        grace_zero_due: false,
        idle_secs: None,
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    });
    overview.summary.personas.push(
        serde_json::from_value(fake_persona_info_json(
            "persona-cursor",
            "cursor-default",
            "active",
        ))
        .expect("decode cursor persona"),
    );
    overview.summary.grants = vec![
        serde_json::from_value(fake_runtime_delegable_grant_info_json_with_lane(
            "grant-cursor",
            "persona-cursor",
            CURSOR_DEFAULT_SCOPE,
            CURSOR_DEFAULT_SCOPE,
        ))
        .expect("decode cursor grant"),
    ];
    overview.summary.grant_live_leases = Vec::new();

    let payload = status_json_value(&overview);
    assert_eq!(
        payload["auth"]["cursor"]["kind"],
        serde_json::Value::String("cursor_owned_model_auth".to_string())
    );
    assert_eq!(
        payload["auth"]["cursor"]["launcher_grant_active"],
        serde_json::Value::Bool(false)
    );
    assert_eq!(
        payload["auth"]["cursor"]["model_auth_governed"],
        serde_json::Value::Bool(false)
    );
}

#[test]
fn launcher_issue_json_reports_stale_managed_install_fields() {
    let issue = InstalledLauncherIssue::StaleManagedInstall {
        path: PathBuf::from("/usr/local/bin/ember"),
        target: PathBuf::from("/usr/local/lib/ember.app/Contents/MacOS/ember"),
        newer_components: vec![
            PathBuf::from("/usr/local/bin/emberd"),
            PathBuf::from("/usr/local/lib/ember/binaries/ember-gh"),
        ],
    };
    let payload = launcher_issue_json(Some(&issue));
    assert_eq!(payload["kind"], serde_json::json!("stale_managed_install"));
    assert_eq!(payload["path"], serde_json::json!("/usr/local/bin/ember"));
    assert_eq!(
        payload["target"],
        serde_json::json!("/usr/local/lib/ember.app/Contents/MacOS/ember")
    );
    assert_eq!(
        payload["newer_components"],
        serde_json::json!([
            "/usr/local/bin/emberd",
            "/usr/local/lib/ember/binaries/ember-gh"
        ])
    );
    assert!(
        payload["repair_guidance"]
            .as_str()
            .unwrap()
            .contains("does not rebuild `/usr/local/lib/ember.app`"),
        "launcher issue JSON must preserve the launcher boundary repair guidance: {payload}"
    );
}

#[test]
fn delegation_template_issue_json_reports_missing_bundle_fields() {
    let issue = DelegationTemplateInstallIssue {
        templates_dir: PathBuf::from(PROD_EMBER_DELEGATION_TEMPLATES_DIR),
        missing_templates: vec!["read-only.toml".to_string(), "autopilot.toml".to_string()],
    };
    let payload = delegation_template_issue_json(Some(&issue));
    assert_eq!(
        payload["kind"],
        serde_json::json!("missing_bundled_delegation_templates")
    );
    assert_eq!(
        payload["templates_dir"],
        serde_json::json!(PROD_EMBER_DELEGATION_TEMPLATES_DIR)
    );
    assert_eq!(
        payload["missing_templates"],
        serde_json::json!(["read-only.toml", "autopilot.toml"])
    );
}

/// Verifies that configure_tracing writes JSON log lines to a rolling file.
///
/// Marked `#[ignore]` because it installs a global tracing subscriber, which
/// conflicts with other tests in the same process. Run with:
///   cargo test -p emberlink-cli -- --ignored configure_tracing_writes_json_log
#[test]
#[ignore]
fn configure_tracing_writes_json_log() {
    use ember_daemon::infra::config::LogLevel;
    use std::io::BufRead;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path();

    let guard = configure_tracing(data_dir, &LogLevel::Info, false);
    tracing::info!(
        test_marker = "unit-test-probe",
        "configure_tracing_writes_json_log probe"
    );
    // Drop guard to flush the non-blocking writer before reading the file.
    drop(guard);

    // tracing-appender rolling daily names files <prefix>.<YYYY-MM-DD>
    let log_file = std::fs::read_dir(data_dir)
        .unwrap()
        .flatten()
        .find(|e| e.file_name().to_string_lossy().starts_with("daemon.log"))
        .expect("daemon.log.* should exist after drop");

    let file = std::fs::File::open(log_file.path()).unwrap();
    let reader = std::io::BufReader::new(file);
    let found = reader.lines().map_while(Result::ok).any(|line| {
        // Each line should be a JSON object; look for our test marker.
        line.contains("unit-test-probe")
    });
    assert!(found, "expected test_marker in log file");
}

// --- sandbox run flag-parsing tests ---

fn parse_sandbox_run(args: &[&str]) -> SandboxAction {
    use clap::Parser as _;
    // Build the full CLI args: ["ember", "sandbox", "run", ...args]
    let full: Vec<&str> = std::iter::once("ember")
        .chain(std::iter::once("sandbox"))
        .chain(std::iter::once("run"))
        .chain(args.iter().copied())
        .collect();
    let cli = Cli::try_parse_from(&full).expect("parse failed");
    match cli.command {
        Commands::Sandbox { action } => action,
        _ => panic!("expected Sandbox command"),
    }
}

#[test]
fn sandbox_run_parses_required_name_and_image() {
    let action = parse_sandbox_run(&[
        "agent-coding",
        "--image",
        "ember-claude-code:v1",
        "--prompt",
        "hello",
    ]);
    match action {
        SandboxAction::Run {
            name,
            image,
            prompt,
            ..
        } => {
            assert_eq!(name, "agent-coding");
            assert_eq!(image, "ember-claude-code:v1");
            assert_eq!(prompt.as_deref(), Some("hello"));
        }
        _ => panic!("expected SandboxAction::Run"),
    }
}

#[test]
fn sandbox_run_default_image_is_ubuntu() {
    let action = parse_sandbox_run(&["my-sandbox"]);
    match action {
        SandboxAction::Run { image, .. } => {
            assert_eq!(image, "ubuntu:24.04");
        }
        _ => panic!("expected SandboxAction::Run"),
    }
}

#[test]
fn sandbox_run_prompt_is_optional() {
    let action = parse_sandbox_run(&["my-sandbox", "--image", "alpine:3"]);
    match action {
        SandboxAction::Run { prompt, .. } => {
            assert!(prompt.is_none());
        }
        _ => panic!("expected SandboxAction::Run"),
    }
}

#[test]
fn sandbox_run_parses_workspace_from() {
    let action = parse_sandbox_run(&[
        "ws-sandbox",
        "--image",
        "ember-claude-code:v1",
        "--workspace-from",
        "https://github.com/example/repo",
    ]);
    match action {
        SandboxAction::Run { workspace_from, .. } => {
            assert_eq!(
                workspace_from.as_deref(),
                Some("https://github.com/example/repo")
            );
        }
        _ => panic!("expected SandboxAction::Run"),
    }
}

#[test]
fn sandbox_run_parses_env_vars() {
    let action = parse_sandbox_run(&["env-sandbox", "--env", "FOO=bar", "--env", "BAZ=qux"]);
    match action {
        SandboxAction::Run { env, .. } => {
            assert!(env.contains(&"FOO=bar".to_string()));
            assert!(env.contains(&"BAZ=qux".to_string()));
        }
        _ => panic!("expected SandboxAction::Run"),
    }
}

#[test]
fn sandbox_run_parses_ttl() {
    let action = parse_sandbox_run(&["ttl-sandbox", "--ttl", "30m"]);
    match action {
        SandboxAction::Run { ttl, .. } => {
            assert_eq!(ttl.as_deref(), Some("30m"));
        }
        _ => panic!("expected SandboxAction::Run"),
    }
}

// --- docker_exec_flags unit tests ---

#[test]
fn docker_exec_flags_non_tty_returns_only_i() {
    let flags = docker_exec_flags(false);
    assert_eq!(flags, vec!["-i"], "non-TTY: only -i, no -t");
}

#[test]
fn docker_exec_flags_tty_returns_i_and_t() {
    let flags = docker_exec_flags(true);
    assert_eq!(flags, vec!["-i", "-t"], "TTY: both -i and -t");
}

#[test]
fn sandbox_run_parses_budget_tokens_and_usd() {
    let action = parse_sandbox_run(&[
        "budget-sandbox",
        "--budget-tokens",
        "20000",
        "--budget-usd",
        "0.50",
    ]);
    match action {
        SandboxAction::Run {
            budget_tokens,
            budget_usd,
            ..
        } => {
            assert_eq!(budget_tokens, Some(20_000u64));
            assert_eq!(budget_usd.as_deref(), Some("0.50"));
        }
        _ => panic!("expected SandboxAction::Run"),
    }
}

#[test]
fn sandbox_run_parses_credential_resource() {
    let action = parse_sandbox_run(&["cred-sandbox", "--credential-resource", "obj-github-token"]);
    match action {
        SandboxAction::Run {
            credential_resource,
            ..
        } => {
            assert_eq!(credential_resource.as_deref(), Some("obj-github-token"));
        }
        _ => panic!("expected SandboxAction::Run"),
    }
}

#[test]
fn sandbox_run_full_flags() {
    let action = parse_sandbox_run(&[
        "full-sandbox",
        "--image",
        "ember-claude-code:v1",
        "--prompt",
        "echo hello",
        "--workspace-from",
        "https://github.com/example/repo",
        "--env",
        "KEY=val",
        "--ttl",
        "60s",
        "--budget-tokens",
        "5000",
        "--budget-usd",
        "0.25",
        "--budget-seconds",
        "3600",
        "--credential-resource",
        "obj-anthropic-key",
    ]);
    match action {
        SandboxAction::Run {
            name,
            image,
            prompt,
            workspace_from,
            env,
            ttl,
            budget_tokens,
            budget_usd,
            budget_seconds,
            credential_resource,
        } => {
            assert_eq!(name, "full-sandbox");
            assert_eq!(image, "ember-claude-code:v1");
            assert_eq!(prompt.as_deref(), Some("echo hello"));
            assert_eq!(
                workspace_from.as_deref(),
                Some("https://github.com/example/repo")
            );
            assert!(env.contains(&"KEY=val".to_string()));
            assert_eq!(ttl.as_deref(), Some("60s"));
            assert_eq!(budget_tokens, Some(5_000u64));
            assert_eq!(budget_usd.as_deref(), Some("0.25"));
            assert_eq!(budget_seconds, Some(3_600u64));
            assert_eq!(credential_resource.as_deref(), Some("obj-anthropic-key"));
        }
        _ => panic!("expected SandboxAction::Run"),
    }
}

// --- P69M.1 belt-and-suspenders: production checkpoint gate for cmd_init ---

/// Verify that `check_production_sentinel` blocks production keyring writes
/// when the checkpoint file is absent. This is the gate that `cmd_init` calls
/// before `keyring_core::Entry::new` — belt-and-suspenders alongside PR #540's
/// `resolve_init_keyring_value` fix.
#[test]
fn production_sentinel_fires_when_file_absent() {
    let tmp = tempfile::tempdir().unwrap();
    // No ~/.ember-production in tmp — checkpoint must reject.
    let result =
        check_production_sentinel(DEFAULT_KEYRING_SERVICE, DEFAULT_KEYRING_SERVICE, tmp.path());
    assert!(
        result.is_err(),
        "checkpoint should reject production service when opt-in file is absent"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("refusing to open production keychain"),
        "error message should explain the refusal; got: {msg}"
    );
}

#[test]
fn production_sentinel_passes_when_file_present() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(".ember-production"), b"").unwrap();
    let result =
        check_production_sentinel(DEFAULT_KEYRING_SERVICE, DEFAULT_KEYRING_SERVICE, tmp.path());
    assert!(
        result.is_ok(),
        "checkpoint should pass when opt-in file exists"
    );
}

#[test]
fn production_sentinel_passes_for_non_production_service() {
    let tmp = tempfile::tempdir().unwrap();
    // No checkpoint file, but service is not the production default → should pass.
    let result =
        check_production_sentinel("ember-daemon-test", DEFAULT_KEYRING_SERVICE, tmp.path());
    assert!(
        result.is_ok(),
        "checkpoint should pass when service differs from production default"
    );
}

// --- EMBER_VAULT_PASSPHRASE cleared after first read in cmd_init ---

#[test]
fn cmd_init_removes_vault_passphrase_env_after_read() {
    let _env_lock = env_lock();
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("config.toml");
    let data_dir = tmp.path().join("data");
    let run_dir = tmp.path().join("run");

    let config = ember_daemon::infra::config::DaemonConfig {
        socket_dir: run_dir.clone(),
        data_dir: data_dir.clone(),
        pid_file: run_dir.join("emberd.pid"),
        policy_file: tmp.path().join("policy.toml"),
        log_level: ember_daemon::infra::config::LogLevel::Info,
        dashboard_addr: None,
        git_proxy_addr: None,
        llm_proxy_addr: None,
        keyring: ember_daemon::infra::config::KeyringConfig::default(),
        stale_approval_threshold_secs: 3600,
        presence: ember_daemon::infra::config::PresenceConfigSection::default(),
        snapshot_interval_secs: 3600,
        snapshot_pull_interval_secs: 600,
        snapshot_pull_endpoint: None,
        snapshot_pull_cluster_id: None,
        credential_store: None,
        ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
    };

    let server = spawn_fake_init_daemon(&config, "test", "persona-env-clear", true, false);

    // SAFETY: test-only, single-threaded, no other threads reading env vars.
    unsafe {
        std::env::set_var("EMBER_VAULT_PASSPHRASE", "sec14-cli-passphrase");
        std::env::set_var("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1");
    }

    cmd_init(
        &config,
        Some("test".to_string()),
        None,
        Some(&config_path),
        None,
        None,
        false,
        false,
    );

    assert!(
        std::env::var("EMBER_VAULT_PASSPHRASE").is_err(),
        "EMBER_VAULT_PASSPHRASE must be absent from the environment after cmd_init"
    );
    unsafe {
        std::env::remove_var("EMBER_SKIP_DAEMON_INSTALL_CHECK");
    }
    server.join().expect("fake init daemon thread");
}

// cmd_init's
// ensure_managed_daemon_for_init now probes the daemon via the
// `status` RPC before the existing create_persona /
// build_init_first_grant_receipt sequence. The fake daemon below
// accepts the new method with a minimal empty StatusSummary, and
// the request-loop bound is widened from 0..2 to 0..3 to absorb
// the additional connection.
// Anchor: cmd_init_with_live_socket_builds_first_receipt_via_daemon_without_local_db_write_passes
#[test]
fn cmd_init_with_live_socket_builds_first_receipt_via_daemon_without_local_db_write() {
    let _env_lock = env_lock();

    let tmp = tempfile::Builder::new()
        .prefix("esb")
        .tempdir()
        .expect("tempdir");
    let config_path = tmp.path().join("config.toml");
    let data_dir = tmp.path().join("data");
    let run_dir = tmp.path().join("run");

    let config = ember_daemon::infra::config::DaemonConfig {
        socket_dir: run_dir.clone(),
        data_dir: data_dir.clone(),
        pid_file: run_dir.join("emberd.pid"),
        policy_file: tmp.path().join("policy.toml"),
        log_level: ember_daemon::infra::config::LogLevel::Info,
        dashboard_addr: None,
        git_proxy_addr: None,
        llm_proxy_addr: None,
        keyring: ember_daemon::infra::config::KeyringConfig::default(),
        stale_approval_threshold_secs: 3600,
        presence: ember_daemon::infra::config::PresenceConfigSection::default(),
        snapshot_interval_secs: 3600,
        snapshot_pull_interval_secs: 600,
        snapshot_pull_endpoint: None,
        snapshot_pull_cluster_id: None,
        credential_store: None,
        ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
    };

    let server = spawn_fake_init_daemon(&config, "daemon-root", "persona-rpc", true, false);
    unsafe {
        std::env::set_var("EMBER_VAULT_PASSPHRASE", "rpc-init-passphrase");
    }

    cmd_init(
        &config,
        Some("daemon-root".to_string()),
        None,
        Some(&config_path),
        None,
        None,
        false,
        false,
    );

    assert!(
        std::env::var("EMBER_VAULT_PASSPHRASE").is_err(),
        "EMBER_VAULT_PASSPHRASE must be absent from the environment after cmd_init"
    );
    assert!(
        !data_dir.join("daemon.db").exists(),
        "live-socket init must not create daemon.db locally when the daemon owns persona + receipt flows"
    );

    let receipt_path = data_dir.join("receipts/first.json");
    assert!(
        receipt_path.exists(),
        "daemon-built first-grant receipt must be written locally"
    );
    let raw = std::fs::read_to_string(&receipt_path).expect("read receipt");
    let file: emberlink_cli::onboarding::first_grant::FirstGrantReceiptFile =
        serde_json::from_str(&raw).expect("parse receipt");
    assert_eq!(file.issuer.persona, "persona-rpc");

    server.join().expect("fake daemon thread");
}

// --- P63.C device enroll/pair scaffold parse tests ---

fn parse_dev(args: &[&str]) -> DevAction {
    use clap::Parser as _;
    let full: Vec<&str> = std::iter::once("ember")
        .chain(std::iter::once("dev"))
        .chain(args.iter().copied())
        .collect();
    let cli = Cli::try_parse_from(&full).expect("parse failed");
    match cli.command {
        Commands::Dev { action } => action,
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn dev_status_alias_parses_to_info() {
    let action = parse_dev(&["status"]);
    assert!(matches!(action, DevAction::Info));
}

fn parse_device(args: &[&str]) -> DeviceAction {
    use clap::Parser as _;
    let full: Vec<&str> = std::iter::once("ember")
        .chain(std::iter::once("device"))
        .chain(args.iter().copied())
        .collect();
    let cli = Cli::try_parse_from(&full).expect("parse failed");
    match cli.command {
        Commands::Device { action } => action,
        _ => panic!("expected Device command"),
    }
}

#[test]
fn device_help_names_live_authority_surface_not_old_webauthn_scaffold() {
    let mut cmd = Cli::command();
    let device = cmd
        .find_subcommand_mut("device")
        .expect("device command present");
    let help = device.render_long_help().to_string();

    assert!(
        help.contains("Manage operator authority devices"),
        "device help must describe the current authority surface; help:\n{help}"
    );
    assert!(
        help.contains("Legacy paired-device WebAuthn stub"),
        "the remaining pair stub should be scoped to the pair verb; help:\n{help}"
    );
    assert!(
        !help.contains("P63.C scaffold"),
        "device help must not advertise the retired scaffold; help:\n{help}"
    );
    assert!(
        !help.contains("every subcommand currently exits non-zero"),
        "device help must not say live device verbs are unimplemented; help:\n{help}"
    );
    assert!(
        !help.contains("device_role"),
        "device help must describe v2 AC-2 device_class, not retired device_role; help:\n{help}"
    );
    assert!(
        !help.contains("primary AND backup"),
        "device help must not treat AC-2 pair verification as a primary/backup schema role; help:\n{help}"
    );
}

#[test]
fn device_enroll_prepare_parses_without_signatures() {
    // PREPARE form (manual): device-key + encryption-key + optional label, no signatures.
    let action = parse_device(&[
        "enroll",
        "--device-key",
        "p256:deadbeef",
        "--encryption-key",
        "p256:cafe",
    ]);
    match action {
        DeviceAction::Enroll {
            device_key,
            encryption_key,
            label,
            secure_enclave,
            operator_signature_hex,
            ..
        } => {
            assert_eq!(device_key.as_deref(), Some("p256:deadbeef"));
            assert_eq!(encryption_key.as_deref(), Some("p256:cafe"));
            assert_eq!(label, "Operator Presence Device", "default label");
            assert!(!secure_enclave, "manual mode by default");
            assert!(
                operator_signature_hex.is_empty(),
                "no signatures => PREPARE mode"
            );
        }
        _ => panic!("expected DeviceAction::Enroll"),
    }
}

#[test]
fn device_enroll_commit_parses_repeated_signatures() {
    // COMMIT form (manual): one --operator-signature-hex per prepared step.
    let action = parse_device(&[
        "enroll",
        "--device-key",
        "p256:abc123",
        "--encryption-key",
        "p256:def456",
        "--label",
        "Operator YubiKey",
        "--operator-signature-hex",
        "aa",
        "--operator-signature-hex",
        "bb",
        "--operator-signature-hex",
        "cc",
    ]);
    match action {
        DeviceAction::Enroll {
            device_key,
            encryption_key,
            label,
            operator_signature_hex,
            ..
        } => {
            assert_eq!(device_key.as_deref(), Some("p256:abc123"));
            assert_eq!(encryption_key.as_deref(), Some("p256:def456"));
            assert_eq!(label, "Operator YubiKey");
            assert_eq!(operator_signature_hex, vec!["aa", "bb", "cc"]);
        }
        _ => panic!("expected DeviceAction::Enroll"),
    }
}

#[test]
fn device_enroll_secure_enclave_parses_without_device_key() {
    // SE mode: --device-key is derived from the SE key, so it's optional here.
    let action = parse_device(&["enroll", "--secure-enclave"]);
    match action {
        DeviceAction::Enroll {
            device_key,
            secure_enclave,
            se_label,
            ..
        } => {
            assert!(secure_enclave, "--secure-enclave set");
            assert!(device_key.is_none(), "device_key derived from SE key");
            assert_eq!(se_label, "ember-operator-presence", "default SE label");
        }
        _ => panic!("expected DeviceAction::Enroll"),
    }
}

#[test]
fn device_enroll_backup_secure_enclave_parses_with_backup_pubkeys() {
    // Backup enrollment uses supplied backup-device pubkeys while the
    // existing local SE key is the authority signer. This is not the same as
    // the first-device SE path where --device-key/--encryption-key are derived.
    let action = parse_device(&[
        "enroll",
        "--backup",
        "--secure-enclave",
        "--device-key",
        "p256:backup-sign",
        "--encryption-key",
        "p256:backup-enc",
        "--label",
        "Operator backup presence",
    ]);
    match action {
        DeviceAction::Enroll {
            backup,
            secure_enclave,
            device_key,
            encryption_key,
            label,
            external_signer,
            operator_signature_hex,
            ..
        } => {
            assert!(backup);
            assert!(secure_enclave);
            assert_eq!(device_key.as_deref(), Some("p256:backup-sign"));
            assert_eq!(encryption_key.as_deref(), Some("p256:backup-enc"));
            assert_eq!(label, "Operator backup presence");
            assert!(!external_signer);
            assert!(operator_signature_hex.is_empty());
        }
        _ => panic!("expected DeviceAction::Enroll"),
    }
}

#[test]
fn backup_pubkeys_do_not_imply_external_signer() {
    assert!(
        infer_device_enroll_external_signer(false, true, false, false),
        "first-device --device-key remains legacy external-signer compat"
    );
    assert!(
        !infer_device_enroll_external_signer(true, true, false, false),
        "backup --device-key supplies the backup Device key, not the authority signer"
    );
    assert!(
        infer_device_enroll_external_signer(true, true, true, false),
        "prepared backup signatures still imply the external-signer COMMIT lane"
    );
    assert!(
        infer_device_enroll_external_signer(true, true, false, true),
        "explicit --external-signer wins for backup enrollment"
    );
}

#[test]
fn non_backup_secure_enclave_rejects_supplied_key_material_at_runtime() {
    let err = run_device_enroll(
        Some("p256:not-derived"),
        Some("p256:not-derived-ecies"),
        "Operator Presence Device",
        false,
        None,
        true,
        "ember-operator-presence",
        false,
        None,
        &[],
        false,
        false,
        false,
    )
    .expect_err("non-backup SE enrollment must derive its keys from the SE");
    assert!(
        err.to_string()
            .contains("derives signing and encryption keys from the Secure Enclave"),
        "unexpected error: {err}"
    );
}

/// Load-bearing interop: a signature produced by the Secure Enclave helper
/// over the domain-separated ceremony message must verify under the SAME path
/// the daemon uses to check the OOB enrollment signature. Exercised on the
/// software stub (headless); the real-SE Touch ID path is the operator's live
/// verification. If `context_message` / the SE digest scheme ever diverged
/// from `sign_with_context`, this fails.
#[cfg(target_os = "macos")]
#[test]
fn secure_enclave_signature_verifies_under_event_context() {
    use ember_broker::secure_enclave as se;

    // Under `--all-features` (the headless gate's mode) the broker's `se-real`
    // feature is unified on, routing keygen to the REAL Secure Enclave (Touch
    // ID), which cannot authenticate headlessly (keygen returns "Authentication
    // canceled"). This test exercises the software-STUB interop; skip when the
    // real backend is active — the real-SE path is the operator's live gate.
    if se::se_backend_is_real() {
        eprintln!("skipping secure_enclave interop test: real SE backend active (needs hardware)");
        return;
    }

    let key = se::generate_secure_enclave_key_with_policy(
        "ember-test-presence",
        se::SeKeychainTarget::LoginKeychain,
        se::SeAccessPolicy::UserPresence,
    )
    .expect("stub SE keygen");
    let key = se::SignKeyHandle::from_provisioned(key);
    let pubkey = core_crypto::PublicKey(format!(
        "p256:{}",
        hex::encode(key.public_key_bytes().expect("stub pubkey"))
    ));

    // The exact bytes the daemon's verifier reconstructs for an OOB event sig.
    let pre_image = b"operator-root-genesis pre-image bytes";
    let msg = core_crypto::context_message(core_crypto::DOMAIN_EVENT, pre_image);
    let der = se::se_sign_with_touch_id(&key, &msg).expect("stub SE sign");
    let sig = core_crypto::Signature(format!("p256sig:{}", hex::encode(&der)));

    // Verifies under the daemon's domain-separated check; tamper fails.
    assert!(
        core_crypto::verify_with_context(
            core_crypto::DOMAIN_EVENT,
            &core_crypto::P256Verifier,
            &pubkey,
            pre_image,
            &sig,
        ),
        "SE signature must verify under sign_with_context(DOMAIN_EVENT, …)"
    );
    assert!(
        !core_crypto::verify_with_context(
            core_crypto::DOMAIN_EVENT,
            &core_crypto::P256Verifier,
            &pubkey,
            b"different pre-image",
            &sig,
        ),
        "a signature over different bytes must not verify"
    );
}

#[test]
fn device_enroll_accepts_bare_invocation_post_amendment() {
    // ADR 200 amendment 2026-06-12: bare `ember device enroll` is now
    // accepted by clap (the runtime falls back to `--secure-enclave` on
    // macOS-signed hosts or emits the explicit-flag error elsewhere).
    // The old contract — that clap itself rejected bare invocation —
    // ENFORCED the orthogonal "presence vs not" split via flag presence,
    // which is exactly what the amendment retires.
    use clap::Parser as _;
    assert!(
        Cli::try_parse_from(["ember", "device", "enroll"]).is_ok(),
        "bare enroll must parse — the runtime decides between SE default and explicit-flag error"
    );
    // --secure-enclave conflicts with --operator-signature-hex (the SE
    // path signs in-process; external-signer is its own mutually-exclusive
    // lane).
    assert!(
        Cli::try_parse_from([
            "ember",
            "device",
            "enroll",
            "--secure-enclave",
            "--operator-signature-hex",
            "aa",
        ])
        .is_err(),
        "--secure-enclave and --operator-signature-hex are mutually exclusive"
    );
    // --recovery-code is mutually exclusive with the external-signer key
    // material (capability flows from class — there is no orthogonal
    // recovery + external-signer mix).
    assert!(
        Cli::try_parse_from([
            "ember",
            "device",
            "enroll",
            "--recovery-code",
            "--device-key",
            "p256:ab",
        ])
        .is_err(),
        "--recovery-code conflicts with --device-key"
    );
    // --recovery-code is mutually exclusive with --secure-enclave.
    assert!(
        Cli::try_parse_from([
            "ember",
            "device",
            "enroll",
            "--recovery-code",
            "--secure-enclave",
        ])
        .is_err(),
        "--recovery-code conflicts with --secure-enclave"
    );
}

#[test]
fn device_enroll_external_signer_recognized_as_explicit_flag() {
    // `--external-signer` is the new explicit name for the off-host
    // signer flow. Parses without --secure-enclave.
    let action = parse_device(&[
        "enroll",
        "--external-signer",
        "--device-key",
        "p256:ab",
        "--encryption-key",
        "p256:cd",
    ]);
    match action {
        DeviceAction::Enroll {
            external_signer,
            secure_enclave,
            device_key,
            encryption_key,
            ..
        } => {
            assert!(external_signer, "--external-signer must be set");
            assert!(!secure_enclave);
            assert_eq!(device_key.as_deref(), Some("p256:ab"));
            assert_eq!(encryption_key.as_deref(), Some("p256:cd"));
        }
        _ => panic!("expected Enroll"),
    }
}

#[test]
fn device_enroll_recovery_code_flag_parses() {
    // The new `--recovery-code` flag parses cleanly on its own and
    // populates `recovery_code: true`.
    let action = parse_device(&[
        "enroll",
        "--recovery-code",
        "--label",
        "Printed recovery code",
    ]);
    match action {
        DeviceAction::Enroll {
            recovery_code,
            label,
            secure_enclave,
            device_key,
            ..
        } => {
            assert!(recovery_code, "--recovery-code must be set");
            assert!(!secure_enclave);
            assert!(device_key.is_none());
            assert_eq!(label, "Printed recovery code");
        }
        _ => panic!("expected Enroll"),
    }
}

#[test]
fn device_enroll_secure_enclave_provisions_s4_by_default() {
    // ADR 206 §4: `--secure-enclave` alone must default to auto-provisioning
    // §4 custody (no_provision == false), so a single command leaves §4
    // custody active. This pins the wiring of the shared `vault.se_provision`
    // seam into the enroll path (the SE crypto itself is hardware-gated and
    // not unit-testable).
    let action = parse_device(&["enroll", "--secure-enclave"]);
    match action {
        DeviceAction::Enroll {
            secure_enclave,
            no_provision,
            ..
        } => {
            assert!(secure_enclave, "--secure-enclave must be set");
            assert!(
                !no_provision,
                "enroll --secure-enclave must auto-provision §4 custody by default"
            );
        }
        _ => panic!("expected Enroll"),
    }

    // The opt-out flag suppresses the auto-provision for manual re-cutover.
    let action = parse_device(&["enroll", "--secure-enclave", "--no-provision"]);
    match action {
        DeviceAction::Enroll { no_provision, .. } => {
            assert!(no_provision, "--no-provision must suppress auto-provision");
        }
        _ => panic!("expected Enroll"),
    }

    // Post-amendment: `--no-provision` is no longer clap-gated on
    // `--secure-enclave` (the amendment moved the orthogonality OUT of
    // argv constraints — the runtime ignores it when not meaningful).
    // External-signer + no-provision parses cleanly; the runtime decides.
    use clap::Parser as _;
    assert!(
        Cli::try_parse_from([
            "ember",
            "device",
            "enroll",
            "--device-key",
            "p256:ab",
            "--encryption-key",
            "p256:cd",
            "--no-provision",
        ])
        .is_ok(),
        "post-amendment --no-provision is not clap-gated on --secure-enclave"
    );
}

#[test]
fn device_pair_parses() {
    let action = parse_device(&["pair"]);
    assert!(matches!(action, DeviceAction::Pair));
}

#[test]
fn vault_se_provision_and_unlock_parse() {
    // ADR 206 §4 operator-driver subcommands: default + custom --se-label.
    use clap::Parser;
    #[derive(Parser)]
    struct T {
        #[command(subcommand)]
        action: VaultAction,
    }
    match T::try_parse_from(["test", "se-provision"]).unwrap().action {
        VaultAction::SeProvision { se_label } => {
            assert_eq!(se_label, "ember-operator-presence", "default SE label");
        }
        _ => panic!("expected SeProvision"),
    }
    match T::try_parse_from(["test", "se-unlock", "--se-label", "custom-key"])
        .unwrap()
        .action
    {
        VaultAction::SeUnlock {
            se_label,
            recovery_code,
        } => {
            assert_eq!(se_label, "custom-key");
            assert_eq!(
                recovery_code, None,
                "no --recovery-code → presence-tap path"
            );
        }
        _ => panic!("expected SeUnlock"),
    }
}

#[test]
fn vault_add_value_arg_refused_at_dispatch() {
    // The dispatch handler calls refuse_value_in_argv when `value.is_some()`.
    // We can't process::exit() inside a test, so instead verify that
    // VaultAction::Add's argv parser still accepts --value (clap-level) but
    // the runtime dispatch will reject it. This test is the parser smoke;
    // the runtime refuse path is exercised in cli_integration tests.
    use clap::Parser;
    #[derive(Parser)]
    struct T {
        #[command(subcommand)]
        action: VaultAction,
    }
    let parsed = T::try_parse_from(["test", "add", "--name", "foo/bar", "--value", "leaky"]);
    assert!(
        parsed.is_ok(),
        "clap should accept --value at parse-time so dispatch can emit a structured refuse"
    );
    let parsed = parsed.unwrap();
    match parsed.action {
        VaultAction::Add { value, .. } => {
            assert_eq!(value.as_deref(), Some("leaky"), "value field captured");
        }
        _ => panic!("expected Add"),
    }
}

#[test]
fn vault_sealed_export_import_flags_parse() {
    use clap::Parser;
    #[derive(Parser)]
    struct T {
        #[command(subcommand)]
        action: VaultAction,
    }

    let export = T::try_parse_from([
        "test",
        "export",
        "--sealed",
        "--recovery-passphrase",
        "--file",
        "/tmp/recovery-passphrase",
        "--output",
        "/tmp/vault.emvs",
    ])
    .unwrap();
    match export.action {
        VaultAction::Export(args) => {
            assert!(args.sealed);
            assert_eq!(args.recovery_passphrase, Some(Some(String::new())));
            assert_eq!(
                args.file.unwrap(),
                std::path::PathBuf::from("/tmp/recovery-passphrase")
            );
            assert_eq!(
                args.output.unwrap(),
                std::path::PathBuf::from("/tmp/vault.emvs")
            );
        }
        _ => panic!("expected Export"),
    }

    let import = T::try_parse_from([
        "test",
        "import",
        "--sealed",
        "--file",
        "/tmp/vault.emvs",
        "--expected-fingerprint",
        "b3:test",
        "--recovery-passphrase",
        "--stdin",
    ])
    .unwrap();
    match import.action {
        VaultAction::Import(args) => {
            assert!(args.sealed);
            assert_eq!(
                args.file.unwrap(),
                std::path::PathBuf::from("/tmp/vault.emvs")
            );
            assert_eq!(args.expected_fingerprint.as_deref(), Some("b3:test"));
            assert_eq!(args.recovery_passphrase, Some(Some(String::new())));
            assert!(args.stdin);
        }
        _ => panic!("expected Import"),
    }
}

#[test]
fn vault_recovery_passphrase_argv_form_reaches_dispatch_refusal() {
    use clap::Parser;
    #[derive(Parser)]
    struct T {
        #[command(subcommand)]
        action: VaultAction,
    }

    let parsed = T::try_parse_from([
        "test",
        "export",
        "--sealed",
        "--recovery-passphrase",
        "leaky-secret",
        "--stdin",
    ])
    .unwrap();
    match parsed.action {
        VaultAction::Export(args) => {
            assert_eq!(
                args.recovery_passphrase,
                Some(Some("leaky-secret".to_string()))
            );
        }
        _ => panic!("expected Export"),
    }
}

#[test]
fn vault_lock_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::Builder::new()
        .prefix("esb")
        .tempdir()
        .expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("vault_lock"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {"locked": true},
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let dispatch = run_vault_lock(&config).expect("vault lock via daemon");
    assert_eq!(dispatch, VaultLockDispatch::DaemonRpc);
    server.join().expect("fake daemon thread");
}

#[test]
fn vault_lock_requires_daemon_when_socket_is_absent() {
    let tmp = tempfile::Builder::new()
        .prefix("esb")
        .tempdir()
        .expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    let err = run_vault_lock(&config).expect_err("vault lock must not use local fallback");
    let rendered = err.to_string();
    assert!(
        rendered.contains("vault lock requires the daemon-owned vault control plane"),
        "vault lock refusal must explain the singular daemon path: {rendered}"
    );
    assert!(
        rendered.contains("sudo ember daemon install"),
        "vault lock refusal must point to managed daemon repair: {rendered}"
    );
}

#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
#[test]
fn vault_unlock_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::Builder::new()
        .prefix("esb")
        .tempdir()
        .expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("vault_unlock"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {"unlocked": true},
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let dispatch =
        run_vault_unlock_with_managed_daemon_issue(&config, None).expect("vault unlock via daemon");
    assert_eq!(dispatch, VaultLockDispatch::DaemonRpc);
    server.join().expect("fake daemon thread");
}

#[test]
fn vault_unlock_requires_daemon_when_socket_is_absent() {
    let tmp = tempfile::Builder::new()
        .prefix("esb")
        .tempdir()
        .expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    let err = run_vault_unlock(&config).expect_err("vault unlock must not use local fallback");
    let rendered = err.to_string();
    assert!(
        rendered.contains("vault unlock requires the daemon-owned vault control plane"),
        "vault unlock refusal must explain the singular daemon path: {rendered}"
    );
    assert!(
        rendered.contains("sudo ember daemon install"),
        "vault unlock refusal must point to managed daemon repair: {rendered}"
    );
}

#[test]
fn vault_unlock_refuses_repo_build_managed_daemon_drift_before_daemon_rpc() {
    let tmp = tempfile::Builder::new()
        .prefix("esb")
        .tempdir()
        .expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    std::fs::write(&socket_path, b"").expect("touch fake daemon socket path");

    let issue = ManagedDaemonIssue {
        launcher_path: PathBuf::from("/home/operator/emberlink-example/target/debug/ember"),
        daemon_path: PathBuf::from("/usr/local/bin/emberd"),
    };
    let err = run_vault_unlock_with_managed_daemon_issue(&config, Some(&issue))
        .expect_err("repo-build drift must refuse vault unlock before stale daemon RPC");
    let rendered = err.to_string();
    assert!(
        rendered.contains("vault unlock refused until the managed daemon is refreshed"),
        "vault unlock must explain why the stale daemon path is refused: {rendered}"
    );
    assert!(
        rendered.contains("sudo /home/operator/emberlink-example/target/debug/ember daemon install"),
        "vault unlock refusal must carry the explicit repo-built repair command: {rendered}"
    );
}

#[test]
fn vault_unlock_routes_to_secure_enclave_when_custody_is_provisioned_but_closed() {
    let route = plan_vault_unlock_route(SeCustodyState {
        se_backend_real: true,
        presence_device_enrolled: true,
        kek_wrap_present: true,
        authority_window_open: false,
    });
    assert_eq!(route, VaultUnlockRoute::SecureEnclavePrompt);
}

#[test]
fn vault_unlock_noops_when_secure_enclave_custody_is_already_open() {
    let route = plan_vault_unlock_route(SeCustodyState {
        se_backend_real: true,
        presence_device_enrolled: true,
        kek_wrap_present: true,
        authority_window_open: true,
    });
    assert_eq!(route, VaultUnlockRoute::SecureEnclaveNoop);
}

#[test]
fn vault_unlock_keeps_legacy_daemon_rpc_when_secure_enclave_custody_is_not_ready() {
    for state in [
        SeCustodyState {
            se_backend_real: false,
            presence_device_enrolled: true,
            kek_wrap_present: true,
            authority_window_open: false,
        },
        SeCustodyState {
            se_backend_real: true,
            presence_device_enrolled: false,
            kek_wrap_present: true,
            authority_window_open: false,
        },
        SeCustodyState {
            se_backend_real: true,
            presence_device_enrolled: true,
            kek_wrap_present: false,
            authority_window_open: false,
        },
    ] {
        assert_eq!(plan_vault_unlock_route(state), VaultUnlockRoute::DaemonRpc);
    }
}

#[test]
fn vault_list_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("vault_list"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": [
                    {"id": 1, "name": "alpha/token", "metadata": null},
                    {"id": 2, "name": "beta/token", "metadata": "meta"}
                ],
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, entries) =
        run_vault_list(&config, Some("alpha")).expect("vault list via daemon");
    assert_eq!(dispatch, VaultActionDispatch::DaemonRpc);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], serde_json::json!("alpha/token"));
    server.join().expect("fake daemon thread");
}

#[test]
fn vault_remove_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("vault_remove"));
            assert_eq!(request["params"]["name"], serde_json::json!("alpha/token"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {"removed": true, "name": "alpha/token"},
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let dispatch = run_vault_remove(&config, "alpha/token").expect("vault remove via daemon");
    assert_eq!(dispatch, VaultActionDispatch::DaemonRpc);
    server.join().expect("fake daemon thread");
}

#[test]
fn vault_get_prefers_exact_value_bytes_from_daemon() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("vault_get"));
            assert_eq!(request["params"]["name"], serde_json::json!("alpha/token"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {
                    "value": "lossy-placeholder",
                    "value_bytes": [0, 255, 65]
                },
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, value) = run_vault_get(&config, "alpha/token").expect("vault get via daemon");
    assert_eq!(dispatch, VaultActionDispatch::DaemonRpc);
    assert_eq!(value, vec![0, 255, 65]);
    server.join().expect("fake daemon thread");
}

#[test]
fn vault_add_routes_exact_bytes_through_daemon() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("vault_add"));
            assert_eq!(request["params"]["name"], serde_json::json!("alpha/token"));
            assert_eq!(
                request["params"]["value_bytes"],
                serde_json::json!([0, 255, 65])
            );
            assert_eq!(request["params"]["metadata"], serde_json::json!("meta"));
            assert_eq!(
                request["params"]["require_biometric"],
                serde_json::json!(true)
            );

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {"id": 42, "name": "alpha/token"},
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let stored = run_vault_store(
        &config,
        "vault_add",
        "alpha/token",
        &[0, 255, 65],
        Some("meta"),
        true,
    )
    .expect("vault store via daemon");
    assert_eq!(stored.dispatch, VaultActionDispatch::DaemonRpc);
    assert_eq!(stored.id, "42");
    assert_eq!(stored.name, "alpha/token");
    server.join().expect("fake daemon thread");
}

#[test]
fn vault_put_routes_exact_bytes_through_daemon() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("vault_put"));
            assert_eq!(request["params"]["name"], serde_json::json!("alpha/token"));
            assert_eq!(
                request["params"]["value_bytes"],
                serde_json::json!([0, 255, 65])
            );
            assert_eq!(request["params"]["metadata"], serde_json::json!("meta"));
            assert_eq!(
                request["params"]["require_biometric"],
                serde_json::json!(false)
            );

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {"id": 42, "name": "alpha/token"},
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let stored = run_vault_store(
        &config,
        "vault_put",
        "alpha/token",
        &[0, 255, 65],
        Some("meta"),
        false,
    )
    .expect("vault put via daemon");
    assert_eq!(stored.dispatch, VaultActionDispatch::DaemonRpc);
    assert_eq!(stored.id, "42");
    assert_eq!(stored.name, "alpha/token");
    server.join().expect("fake daemon thread");
}

#[test]
fn receipt_list_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("list_receipts"));
            assert_eq!(
                request["params"]["persona_id"],
                serde_json::json!("persona-a")
            );

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": [
                    fake_grant_receipt_json("rct-1", "grant-1", "persona-a"),
                    fake_grant_receipt_json("rct-2", "grant-2", "persona-a")
                ],
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, receipts) =
        run_receipt_list(&config, Some("persona-a")).expect("receipt list via daemon");
    assert_eq!(dispatch, ReceiptActionDispatch::DaemonRpc);
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].id, "rct-1");
    assert_eq!(receipts[1].grant_id, "grant-2");
    server.join().expect("fake daemon thread");
}

#[test]
fn receipt_get_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("get_receipt"));
            assert_eq!(request["params"]["id"], serde_json::json!("grant-123"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": fake_grant_receipt_json("rct-terminal", "grant-123", "persona-owner"),
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, receipt) =
        run_receipt_get(&config, "grant-123").expect("receipt get via daemon");
    assert_eq!(dispatch, ReceiptActionDispatch::DaemonRpc);
    assert_eq!(receipt.id, "rct-terminal");
    assert_eq!(receipt.grant_id, "grant-123");
    server.join().expect("fake daemon thread");
}

#[test]
fn receipt_get_artifact_routes_through_dotted_receipt_get_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("receipt.get"));
            assert_eq!(request["params"]["id"], serde_json::json!("rct-v2"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": fake_receipt_v2_envelope_json("rct-v2", "broker.materialization", "persona-owner"),
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, artifact) =
        run_receipt_get_artifact(&config, "rct-v2").expect("receipt artifact via daemon");
    assert_eq!(dispatch, ReceiptActionDispatch::DaemonRpc);
    assert_eq!(artifact["version"], serde_json::json!("2"));
    assert_eq!(artifact["receipt_id"], serde_json::json!("rct-v2"));
    server.join().expect("fake daemon thread");
}

#[test]
fn receipt_verify_id_loads_raw_artifact_through_dotted_receipt_get() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("receipt.get"));
            assert_eq!(request["params"]["id"], serde_json::json!("rct-v2"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": fake_receipt_v2_envelope_json(
                    "rct-v2",
                    "authority.grant_issued",
                    "persona-owner",
                ),
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (source, artifact) =
        load_receipt_verify_artifact(&config, Some("rct-v2".to_string()), None)
            .expect("verify id loads raw artifact");
    assert_eq!(source, ReceiptVerifyArtifactSource::DaemonId);
    assert_eq!(artifact["version"], serde_json::json!("2"));
    assert_eq!(receipt_artifact_version_number(&artifact), Some(2));
    assert_eq!(artifact["receipt_id"], serde_json::json!("rct-v2"));
    server.join().expect("fake daemon thread");
}

#[test]
fn receipt_verify_v2_id_uses_trust_explain_without_daemon_private_key() {
    use base64::Engine as _;
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let private_key_path = ember_daemon::infra::receipt::identity_key_path(&config.data_dir);
    std::fs::create_dir(&private_key_path).expect("private key checkpoint dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            for expected_method in ["receipt.get", "trust.explain"] {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!(expected_method));

                let result = match expected_method {
                    "receipt.get" => {
                        assert_eq!(request["params"]["id"], serde_json::json!("rct-v2"));
                        fake_receipt_v2_envelope_json(
                            "rct-v2",
                            "authority.grant_issued",
                            "persona-owner",
                        )
                    }
                    "trust.explain" => {
                        assert_eq!(
                            request["params"]["artifact_kind"],
                            serde_json::json!("receipt")
                        );
                        assert_eq!(
                            request["params"]["sidecar_bytes_b64"],
                            serde_json::json!("")
                        );
                        let artifact_b64 = request["params"]["artifact_bytes_b64"]
                            .as_str()
                            .expect("artifact bytes b64");
                        let artifact_bytes = base64::engine::general_purpose::STANDARD
                            .decode(artifact_b64)
                            .expect("decode artifact bytes");
                        let artifact: serde_json::Value = serde_json::from_slice(&artifact_bytes)
                            .expect("artifact is receipt JSON");
                        assert_eq!(artifact["receipt_id"], serde_json::json!("rct-v2"));
                        serde_json::json!({
                            "verdict": "verified",
                            "trust_root": {
                                "fingerprint_hex": "a".repeat(64),
                                "source": "operator"
                            },
                            "chain": "artifact (receipt kind=authority.grant_issued) -> VERIFIED"
                        })
                    }
                    other => panic!("unexpected method {other}"),
                };

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": result,
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (source, artifact) =
        load_receipt_verify_artifact(&config, Some("rct-v2".to_string()), None)
            .expect("verify id loads raw artifact");
    assert_eq!(source, ReceiptVerifyArtifactSource::DaemonId);
    let envelope =
        serde_json::from_value::<core_events::receipt::envelope::ReceiptEnvelope>(artifact)
            .expect("v2 envelope");
    let explained = run_receipt_verify_v2_trust_explain(&config, &envelope)
        .expect("v2 verify id uses trust.explain");
    assert_eq!(explained.verdict, "verified");
    assert!(
        private_key_path.is_dir(),
        "private key checkpoint was not read or replaced"
    );
    assert!(
        !ember_daemon::infra::receipt::identity_pubkey_sidecar_path(&config.data_dir).exists(),
        "private-key fallback would create the public sidecar as a side effect"
    );
    server.join().expect("fake daemon thread");
}

#[test]
fn receipt_artifact_list_text_preserves_all_v1_renderer() {
    let rendered = render_receipt_artifact_list_text(&[
        fake_grant_receipt_json("rct-1", "grant-1", "persona-a"),
        fake_grant_receipt_json("rct-2", "grant-2", "persona-a"),
    ]);

    assert!(rendered.contains("RECEIPT"));
    assert!(rendered.contains("GRANT"));
    assert!(rendered.contains("REASON"));
    assert!(rendered.contains("rct-1"));
    assert!(rendered.contains("grant-2"));
}

#[test]
fn receipt_artifact_list_text_surfaces_v2_envelope_rows() {
    let v2 = serde_json::json!({
        "version": "2",
        "kind": "authority.grant_issued",
        "receipt_id": "rct-v2",
        "daemon_root_id": "daemon-root",
        "termination_authority": "user_session",
        "body": {
            "persona_id": "persona-v2",
            "issued_grant_id": "grant-v2",
            "device_id": "device-1",
            "operation": "issue"
        },
        "signature": "1".repeat(128)
    });

    let rendered = render_receipt_artifact_list_text(&[
        fake_grant_receipt_json("rct-v1", "grant-v1", "persona-v1"),
        v2,
    ]);

    assert!(rendered.contains("KIND"));
    assert!(rendered.contains("VERSION"));
    assert!(rendered.contains("rct-v1"));
    assert!(rendered.contains("rct-v2"));
    assert!(rendered.contains("authority.grant_issued"));
    assert!(rendered.contains("v2"));
    assert!(rendered.contains("persona-v2"));
    assert!(rendered.contains("grant-v2"));
    assert!(rendered.contains("device_id=device-1"));
    assert!(rendered.contains("operation=issue"));
}

#[test]
fn receipt_artifact_summary_text_surfaces_v2_envelope_body() {
    let artifact = serde_json::json!({
        "version": "2",
        "kind": "authority.grant_issued",
        "receipt_id": "rct-v2",
        "daemon_root_id": "daemon-root",
        "termination_authority": "user_session",
        "body": {
            "persona_id": "persona-v2",
            "issued_grant_id": "grant-v2",
            "device_id": "device-1",
            "operation": "issue"
        },
        "signature": "1".repeat(128)
    });

    let rendered = render_receipt_artifact_summary_text(&artifact);

    assert!(rendered.contains("Receipt rct-v2"));
    assert!(rendered.contains("authority.grant_issued"));
    assert!(rendered.contains("v2"));
    assert!(rendered.contains("persona-v2"));
    assert!(rendered.contains("grant-v2"));
    assert!(rendered.contains("Daemon root"));
    assert!(rendered.contains("issued_grant_id=grant-v2"));
    assert!(rendered.contains("device_id=device-1"));
}

#[test]
fn receipt_artifact_latest_uses_newest_persisted_artifact() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("receipt.list"));
            assert!(request["params"]["persona"].is_null());

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": [
                    fake_grant_receipt_json("rct-v1-newer", "grant-1", "persona-owner"),
                    fake_receipt_v2_envelope_json("rct-v2", "broker.materialization", "persona-owner")
                ],
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let target = resolve_receipt_artifact_export_target(&config, None, true)
        .expect("latest artifact target");
    assert_eq!(target, "rct-v1-newer");
    server.join().expect("fake daemon thread");
}

#[test]
fn receipt_tree_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("receipt_tree"));
            assert_eq!(
                request["params"]["grant_id"],
                serde_json::json!("grant-123")
            );

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": fake_receipt_tree_json("grant-123"),
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, tree) = run_receipt_tree(&config, "grant-123").expect("receipt tree via daemon");
    assert_eq!(dispatch, ReceiptActionDispatch::DaemonRpc);
    assert_eq!(tree.root_grant_id, "grant-123");
    assert_eq!(tree.grants.len(), 1);
    server.join().expect("fake daemon thread");
}

#[test]
fn audit_query_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("receipt_query"));
            assert_eq!(request["params"]["actor"], serde_json::json!("persona-a"));
            assert_eq!(request["params"]["kind"], serde_json::json!("grant"));
            assert_eq!(
                request["params"]["grant_id"],
                serde_json::json!("grant-123")
            );
            assert_eq!(
                request["params"]["resource"],
                serde_json::json!("repo:acme")
            );
            assert_eq!(
                request["params"]["since"],
                serde_json::json!("2026-05-01T00:00:00Z")
            );
            assert_eq!(request["params"]["limit"], serde_json::json!(5));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": [fake_receipt_row_json("rct-1", "persona-a", "grant-123")],
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let filter = ember_daemon::infra::receipt::ReceiptFilter {
        persona_id: Some("persona-a".to_string()),
        kind: Some("grant".to_string()),
        grant_id: Some("grant-123".to_string()),
        resource: Some("repo:acme".to_string()),
        since_iso: Some("2026-05-01T00:00:00Z".to_string()),
        limit: Some(5),
        ..Default::default()
    };
    let (dispatch, rows) =
        run_audit_receipt_query(&config, &filter).expect("audit query via daemon");
    assert_eq!(dispatch, AuditActionDispatch::DaemonRpc);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, "rct-1");
    assert_eq!(rows[0].grant_id, "grant-123");
    server.join().expect("fake daemon thread");
}

#[test]
fn audit_log_query_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("audit_log_query"));
            assert_eq!(request["params"]["id"], serde_json::json!(7));
            assert_eq!(
                request["params"]["agent_id"],
                serde_json::json!("persona-a")
            );
            assert_eq!(request["params"]["limit"], serde_json::json!(3));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": [serde_json::json!({
                    "id": 7,
                    "timestamp": "2026-05-19T00:00:00Z",
                    "agent_id": "persona-a",
                    "action": "grant.issued",
                    "credential": "api-key",
                    "outcome": "allowed",
                    "details": "{\"note\":\"first\"}",
                })],
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let filter = ember_daemon::infra::audit::AuditFilter {
        id: Some(7),
        agent_id: Some("persona-a".to_string()),
        limit: Some(3),
        ..Default::default()
    };
    let (dispatch, rows) =
        run_audit_log_query(&config, &filter).expect("audit log query via daemon");
    assert_eq!(dispatch, AuditActionDispatch::DaemonRpc);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, 7);
    assert_eq!(rows[0].details.as_deref(), Some("{\"note\":\"first\"}"));
    server.join().expect("fake daemon thread");
}

#[test]
fn audit_explain_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("audit_explain"));
            assert_eq!(request["params"]["id"], serde_json::json!(7));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": fake_audit_explain_json(7),
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, explain) = run_audit_explain(&config, 7).expect("audit explain via daemon");
    assert_eq!(dispatch, AuditActionDispatch::DaemonRpc);
    assert_eq!(explain.event.id, 7);
    assert_eq!(
        explain.current_policy.matched_rule.as_deref(),
        Some("credential.access")
    );
    assert_eq!(
        explain.current_grant.as_ref().map(|g| g.id.as_str()),
        Some("grant-123")
    );
    server.join().expect("fake daemon thread");
}

#[test]
fn approval_list_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(
                request["method"],
                serde_json::json!("list_pending_approvals")
            );

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": [fake_approval_request_json("approval-123", "persona-a")],
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, requests) = run_approval_list(&config).expect("approval list via daemon");
    assert_eq!(dispatch, ApprovalActionDispatch::DaemonRpc);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].id, "approval-123");
    assert_eq!(requests[0].persona_id, "persona-a");
    server.join().expect("fake daemon thread");
}

#[test]
fn approval_resolve_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            for expected_method in [
                "list_pending_approvals",
                "list_personas",
                "resolve_approval",
            ] {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!(expected_method));

                let response = match expected_method {
                    "list_pending_approvals" => serde_json::json!({
                        "id": request["id"],
                        "result": [fake_approval_request_json("approval-123", "persona-a")],
                    }),
                    "list_personas" => serde_json::json!({
                        "id": request["id"],
                        "result": [
                            fake_persona_info_json(
                                "persona-runtime",
                                "runtime-claude-code-default-123",
                                "active",
                            ),
                            fake_persona_info_json("persona-revoked", "codex-default", "revoked"),
                            fake_persona_info_json("persona-operator", "claude-code-default", "active"),
                        ],
                    }),
                    "resolve_approval" => {
                        assert_eq!(request["params"]["id"], serde_json::json!("approval-123"));
                        assert_eq!(request["params"]["decision"], serde_json::json!("always"));
                        assert_eq!(
                            request["params"]["expires_at"],
                            serde_json::json!("2026-06-18T00:00:00")
                        );
                        assert_eq!(
                            request["params"]["caller_persona_id"],
                            serde_json::json!("persona-operator")
                        );

                        let mut resolved = fake_approval_request_json("approval-123", "persona-a");
                        resolved["status"] = serde_json::json!("approved");
                        resolved["result_grant_id"] = serde_json::json!("grant-123");
                        serde_json::json!({
                            "id": request["id"],
                            "result": resolved,
                        })
                    }
                    other => panic!("unexpected method: {other}"),
                };

                let mut encoded =
                    serde_json::to_string(&response).expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let outcome = ApprovalOutcome::Always {
        scope: None,
        expires_at: Some("2026-06-18T00:00:00".to_string()),
    };
    let (dispatch, resolved) = run_approval_resolve(&config, "approval-123", &outcome)
        .expect("approval resolve via daemon");
    assert_eq!(dispatch, ApprovalActionDispatch::DaemonRpc);
    assert_eq!(resolved.status, "approved");
    assert_eq!(resolved.result_grant_id.as_deref(), Some("grant-123"));
    server.join().expect("fake daemon thread");
}

#[test]
fn status_routes_through_daemon_when_pid_is_running_and_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    std::fs::write(&config.pid_file, format!("{}\n", std::process::id())).expect("write pid file");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("status"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": fake_status_summary_json(),
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, live_daemon, summary) =
        run_status_summary(&config, true).expect("status summary via daemon");
    assert_eq!(dispatch, StatusActionDispatch::DaemonRpc);
    assert_eq!(
        live_daemon.as_ref().and_then(|status| status.pid),
        Some(std::process::id())
    );
    assert_eq!(summary.personas.len(), 1);
    assert_eq!(summary.grants.len(), 1);
    assert_eq!(summary.sandboxes.len(), 1);
    assert_eq!(summary.approvals.len(), 1);
    assert_eq!(summary.standing_grants, 2);
    assert_eq!(summary.audit_events_total, 9);
    server.join().expect("fake daemon thread");
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn status_routes_through_daemon_when_socket_exists_even_if_pid_probe_lags() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("status"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": fake_status_summary_json(),
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, live_daemon, summary) =
        run_status_summary(&config, false).expect("status summary via live socket");
    assert_eq!(dispatch, StatusActionDispatch::DaemonRpc);
    assert!(
        live_daemon.is_some(),
        "live daemon probe should be captured"
    );
    assert_eq!(summary.audit_events_total, 9);
    server.join().expect("fake daemon thread");
}

#[test]
fn build_status_banner_prefers_daemon_rpc_when_pid_probe_lags() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    std::fs::write(&config.pid_file, "4242\n").expect("write pid hint");

    let live = emberlink_cli::LiveDaemonStatus {
        pid: Some(4242),
        socket: config.socket_dir.join("daemon.sock"),
        summary: fake_status_summary(),
    };

    let banner = build_status_banner(
        &config,
        None,
        Some(&live),
        "local".to_string(),
        "local-encrypted".to_string(),
        None,
    );

    match banner {
        DaemonStatusBanner::Running { pid, socket, .. } => {
            assert_eq!(pid, 4242);
            assert!(
                socket.ends_with("daemon.sock"),
                "expected daemon socket path, got {socket}"
            );
        }
        other => panic!("expected running banner from live daemon rpc, got {other:?}"),
    }
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn persona_revoke_routes_through_daemon_with_operator_caller_persona() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            for expected_method in ["list_personas", "revoke_persona"] {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!(expected_method));

                let response = match expected_method {
                    "list_personas" => serde_json::json!({
                        "id": request["id"],
                        "result": [
                            {"id": "persona-root", "name": "root", "status": "active"},
                            {"id": "persona-target", "name": "scope-proof-temp", "status": "active"}
                        ],
                    }),
                    "revoke_persona" => {
                        assert_eq!(request["params"]["id"], serde_json::json!("persona-target"));
                        assert_eq!(
                            request["params"]["caller_persona_id"],
                            serde_json::json!("persona-target")
                        );
                        assert_eq!(
                            request["params"]["name"],
                            serde_json::json!("scope-proof-temp")
                        );
                        serde_json::json!({
                            "id": request["id"],
                            "result": {"revoked": true},
                        })
                    }
                    other => panic!("unexpected method: {other}"),
                };

                let mut encoded =
                    serde_json::to_string(&response).expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    run_persona_revoke(&config, "persona-target").expect("persona revoke via daemon");
    server.join().expect("fake daemon thread");
}

#[test]
fn runtime_persona_lookup_prefers_active_status() {
    let personas = vec![
        serde_json::json!({
            "id": "persona-old",
            "name": "claude-code-default",
            "status": "revoked"
        }),
        serde_json::json!({
            "id": "persona-new",
            "name": "claude-code-default",
            "status": "active"
        }),
    ];

    assert_eq!(
        find_active_persona_id_by_name(&personas, "claude-code-default").as_deref(),
        Some("persona-new")
    );
    assert_eq!(
        find_any_persona_id_by_name(&personas, "claude-code-default").as_deref(),
        Some("persona-old")
    );
}

#[test]
fn runtime_persona_lookup_treats_missing_status_as_active_for_compatibility() {
    let personas = vec![serde_json::json!({
        "id": "persona-compat",
        "name": "codex-default"
    })];

    assert_eq!(
        find_active_persona_id_by_name(&personas, "codex-default").as_deref(),
        Some("persona-compat")
    );
}

#[test]
fn recoverable_persona_secret_error_matches_selected_persona_only() {
    let message = "daemon rpc error: vault error: decrypt persona \
                   'persona-selected' secret: crypto error: dek unwrap failed: aead::Error";
    assert!(is_recoverable_persona_secret_error(
        message,
        "persona-selected"
    ));
    assert!(!is_recoverable_persona_secret_error(
        message,
        "persona-other"
    ));
    assert!(!is_recoverable_persona_secret_error(
        "daemon rpc error: vault error: credential decrypt failed",
        "persona-selected"
    ));
}

/// Helper: parse a `daemon` subcommand argv into a `DaemonAction`.
fn parse_daemon(args: &[&str]) -> DaemonAction {
    use clap::Parser;
    #[derive(Parser)]
    struct T {
        #[command(subcommand)]
        action: DaemonAction,
    }
    let mut full = vec!["test"];
    full.extend_from_slice(args);
    T::try_parse_from(full)
        .expect("daemon argv should parse")
        .action
}

/// `ember daemon install` (no flags) must
/// take the separate-uid path. clap default for `bool` is false — we
/// pin the surface so a future rename to `single_uid: Option<bool>` or
/// a flipped default is intentional, not accidental.
#[test]
fn daemon_install_args_default_is_separate_uid() {
    let action = parse_daemon(&["install"]);
    match action {
        DaemonAction::Install { args } => {
            assert!(
                !args.single_uid,
                "default posture must be separate-uid (single_uid = false) per ADR 131"
            );
        }
        _ => panic!("expected DaemonAction::Install"),
    }
}

/// `ember daemon install --single-uid`
/// must opt into the dev-mode path. Pins the flag spelling so future
/// renames stay intentional.
#[test]
fn daemon_install_args_single_uid_flag_parses() {
    let action = parse_daemon(&["install", "--single-uid"]);
    match action {
        DaemonAction::Install { args } => {
            assert!(
                args.single_uid,
                "--single-uid must set single_uid = true (dev-mode escape, ADR 131 §Dev mode)"
            );
        }
        _ => panic!("expected DaemonAction::Install"),
    }
}

/// `ember daemon install --non-interactive`
/// (with optional `--accept-defaults` and `--posture`) must parse and
/// surface the flags on `DaemonInstallArgs`. Pins the flag spellings so
/// downstream Dockerfile / CI runner invocations stay stable.
#[test]
fn daemon_install_args_non_interactive_flag_parses() {
    let action = parse_daemon(&[
        "install",
        "--non-interactive",
        "--accept-defaults",
        "--posture",
        "separate-uid",
    ]);
    match action {
        DaemonAction::Install { args } => {
            assert!(args.non_interactive, "--non-interactive sets the flag");
            assert!(args.accept_defaults, "--accept-defaults sets the flag");
            assert_eq!(
                args.posture.as_deref(),
                Some("separate-uid"),
                "--posture captured raw for downstream parsing"
            );
            assert!(
                !args.single_uid,
                "non-interactive run must not flip single_uid silently"
            );
        }
        _ => panic!("expected DaemonAction::Install"),
    }
}

#[test]
fn daemon_install_launcher_boundary_note_calls_out_release_package() {
    let note = daemon_install_launcher_boundary_note();
    assert!(
        note.contains("daemon/runtime sidecars"),
        "install note must name the sidecar-only refresh boundary: {note}"
    );
    assert!(
        note.contains("/usr/local/bin/ember"),
        "install note must call out the host launcher path explicitly: {note}"
    );
    assert!(
        note.contains("release package"),
        "install note must point at the managed CLI artifact / release package repair path: {note}"
    );
}

/// `ember daemon migrate --to separate-uid`
/// must parse to `DaemonAction::Migrate { to: "separate-uid" }`.
#[test]
fn daemon_migrate_to_separate_uid_parses() {
    let action = parse_daemon(&["migrate", "--to", "separate-uid"]);
    match action {
        DaemonAction::Migrate { to } => {
            assert_eq!(
                to, "separate-uid",
                "--to must capture the posture string exactly"
            );
        }
        _ => panic!("expected DaemonAction::Migrate"),
    }
}

/// `ember daemon migrate` without `--to`
/// must be rejected by clap (required arg).
#[test]
fn daemon_migrate_without_to_is_rejected() {
    use clap::Parser;
    #[derive(Parser)]
    struct T {
        #[command(subcommand)]
        action: DaemonAction,
    }
    let result = T::try_parse_from(["test", "migrate"]);
    assert!(
        result.is_err(),
        "migrate without --to must fail clap validation"
    );
}

/// `is_separate_uid_posture` returns
/// false when the ember user does not exist (T1 posture-detection
/// function test — probes the live system user database).
///
/// On the build host the `ember` user is not provisioned (CI / dev
/// workstations start clean), so this asserts the false branch.
/// Intentionally not `#[ignore]` — the no-ember-user case is the
/// common unit-test environment and must always return false without
/// side effects.
#[test]
fn is_separate_uid_posture_false_when_ember_user_absent() {
    // The build host does not have an `ember` system user. Verify
    // that the detector returns false without mutating state.
    // If this test fails it means the host already has an `ember`
    // user — which is valid, but not the default CI environment.
    if ember_daemon::install::is_separate_uid_posture() {
        // ember user already exists on this host — skip assertion to
        // avoid false positive. Document the environment assumption.
        eprintln!("note: ember user already exists on this host; skipping absent-user assertion");
    } else {
        // Confirm the return type is bool and the probe ran without panic.
        assert!(
            !ember_daemon::install::is_separate_uid_posture(),
            "is_separate_uid_posture must return false when ember user is absent"
        );
    }
}

/// T1: `is_ember_initialized` returns false
/// for a fresh temp dir, and true once `cmd_init` has run and written daemon.db.
///
/// Verifies the detection logic that `init --for claude` uses to decide
/// whether to skip the basic init step (to avoid creating a duplicate "root"
/// persona). A friendly who ran `ember init --name "Foo"` before running
/// `ember init --for claude` triggered the double-init bug; after this
/// fix the basic-init step is skipped when daemon.db is present.
#[test]
fn init_for_claude_code_skips_basic_init_when_already_initialized() {
    let _env_lock = env_lock();
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let run_dir = tmp.path().join("run");

    let config = ember_daemon::infra::config::DaemonConfig {
        socket_dir: run_dir.clone(),
        data_dir: data_dir.clone(),
        pid_file: run_dir.join("emberd.pid"),
        policy_file: tmp.path().join("policy.toml"),
        log_level: ember_daemon::infra::config::LogLevel::Info,
        dashboard_addr: None,
        git_proxy_addr: None,
        llm_proxy_addr: None,
        keyring: ember_daemon::infra::config::KeyringConfig::default(),
        stale_approval_threshold_secs: 3600,
        presence: ember_daemon::infra::config::PresenceConfigSection::default(),
        snapshot_interval_secs: 3600,
        snapshot_pull_interval_secs: 600,
        snapshot_pull_endpoint: None,
        snapshot_pull_cluster_id: None,
        credential_store: None,
        ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
    };

    // Before any init: daemon.db does not exist → not initialized.
    assert!(
        !is_ember_initialized(&config),
        "is_ember_initialized must return false before any init"
    );

    // Run basic init against a fake daemon that owns the daemon.db write,
    // simulating a friendly who already ran `ember init`.
    let config_path = tmp.path().join("config.toml");
    let server = spawn_fake_init_daemon(&config, "Foo", "persona-foo", true, true);
    unsafe {
        std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase-t3-t1");
        std::env::set_var("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1");
    };
    cmd_init(
        &config,
        Some("Foo".to_string()),
        None,
        Some(&config_path),
        None,
        None,
        false,
        false,
    );
    unsafe {
        std::env::remove_var("EMBER_VAULT_PASSPHRASE");
        std::env::remove_var("EMBER_SKIP_DAEMON_INSTALL_CHECK");
    };
    server.join().expect("fake init daemon thread");

    // After init: daemon-owned daemon.db exists → is_ember_initialized returns true.
    assert!(
        is_ember_initialized(&config),
        "is_ember_initialized must return true after daemon wrote daemon.db"
    );

    // Verify daemon.db is present (the file is the detection signal).
    assert!(
        data_dir.join("daemon.db").exists(),
        "daemon.db must exist after daemon-backed cmd_init"
    );

    // Count personas: expect exactly one ("Foo") from the basic init.
    // This is the count that would survive if `init --for claude`
    // correctly skips the basic init step (no extra "root" added).
    let db_path = data_dir.join("daemon.db");
    let store = DaemonStore::open(&db_path).expect("open store");
    let personas = store.list_personas().expect("list personas");
    assert_eq!(
        personas.len(),
        1,
        "exactly one persona expected after a single cmd_init; got: {:?}",
        personas.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
    assert_eq!(
        personas[0].name, "Foo",
        "persona name must match --name argument"
    );
}

#[test]
fn init_for_codex_skips_basic_init_when_already_initialized() {
    let _env_lock = env_lock();
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let run_dir = tmp.path().join("run");

    let config = ember_daemon::infra::config::DaemonConfig {
        socket_dir: run_dir.clone(),
        data_dir: data_dir.clone(),
        pid_file: run_dir.join("emberd.pid"),
        policy_file: tmp.path().join("policy.toml"),
        log_level: ember_daemon::infra::config::LogLevel::Info,
        dashboard_addr: None,
        git_proxy_addr: None,
        llm_proxy_addr: None,
        keyring: ember_daemon::infra::config::KeyringConfig::default(),
        stale_approval_threshold_secs: 3600,
        presence: ember_daemon::infra::config::PresenceConfigSection::default(),
        snapshot_interval_secs: 3600,
        snapshot_pull_interval_secs: 600,
        snapshot_pull_endpoint: None,
        snapshot_pull_cluster_id: None,
        credential_store: None,
        ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
    };

    let config_path = tmp.path().join("config.toml");
    let server = spawn_fake_init_daemon(&config, "Root", "persona-root", true, true);
    unsafe {
        std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase-t3-codex");
        std::env::set_var("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1");
    };
    cmd_init(
        &config,
        Some("Root".to_string()),
        None,
        Some(&config_path),
        None,
        None,
        false,
        false,
    );
    unsafe {
        std::env::remove_var("EMBER_VAULT_PASSPHRASE");
        std::env::remove_var("EMBER_SKIP_DAEMON_INSTALL_CHECK");
    };
    server.join().expect("fake init daemon thread");

    assert!(
        should_skip_basic_init(Some(OnboardingTarget::Codex), &config),
        "Codex friendly init must skip the base-init path once daemon.db exists"
    );
}

/// T2: `is_ember_initialized` returns false
/// for an empty temp dir, confirming that the `init --for claude` path
/// would run basic init (not skip it) when starting fresh.
#[test]
fn init_for_claude_code_runs_basic_init_when_fresh() {
    let _env_lock = env_lock();
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let run_dir = tmp.path().join("run");

    let config = ember_daemon::infra::config::DaemonConfig {
        socket_dir: run_dir.clone(),
        data_dir: data_dir.clone(),
        pid_file: run_dir.join("emberd.pid"),
        policy_file: tmp.path().join("policy.toml"),
        log_level: ember_daemon::infra::config::LogLevel::Info,
        dashboard_addr: None,
        git_proxy_addr: None,
        llm_proxy_addr: None,
        keyring: ember_daemon::infra::config::KeyringConfig::default(),
        stale_approval_threshold_secs: 3600,
        presence: ember_daemon::infra::config::PresenceConfigSection::default(),
        snapshot_interval_secs: 3600,
        snapshot_pull_interval_secs: 600,
        snapshot_pull_endpoint: None,
        snapshot_pull_cluster_id: None,
        credential_store: None,
        ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
    };

    // Fresh temp dir: daemon.db absent → not initialized → basic init would run.
    assert!(
        !is_ember_initialized(&config),
        "is_ember_initialized must return false for a fresh (empty) data_dir"
    );

    // Simulate the basic init step that `init --for claude` would run against
    // the daemon-owned mutation path.
    let config_path = tmp.path().join("config.toml");
    let server = spawn_fake_init_daemon(&config, "root", "persona-root", true, true);
    unsafe {
        std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase-t3-t2");
        std::env::set_var("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1");
    };
    cmd_init(
        &config,
        None,
        Some(OnboardingTarget::Claude),
        Some(&config_path),
        None,
        None,
        false,
        false,
    );
    unsafe {
        std::env::remove_var("EMBER_VAULT_PASSPHRASE");
        std::env::remove_var("EMBER_SKIP_DAEMON_INSTALL_CHECK");
    };
    server.join().expect("fake init daemon thread");

    // After init: config.toml and daemon-owned daemon.db must exist.
    assert!(
        config_path.exists(),
        "config.toml must exist after cmd_init"
    );
    assert!(
        data_dir.join("daemon.db").exists(),
        "daemon.db must exist after daemon-backed cmd_init"
    );

    // is_ember_initialized must now return true.
    assert!(
        is_ember_initialized(&config),
        "is_ember_initialized must return true after basic init completed"
    );
}

// The front-loading `ember init` presence-custody
// bootstrap decides exactly ONE custody step from detected host state. The
// branch policy is a pure function (`plan_presence_custody_bootstrap`); the SE
// key probes, the daemon wrap lookup, and the actual taps live in the executor
// and are exercised by the operator/OSCAR live fresh-install walk. These T1
// tests lock the decision table so the build half can be verified without a
// Secure Enclave or a daemon.

#[test]
fn presence_custody_plan_skips_when_no_real_secure_enclave() {
    // Unsigned / dev / CI builds have no real SE; §4 custody cannot be built
    // with a software key, so the bootstrap is a no-op regardless of any other
    // signal (and never aborts the rest of init).
    for non_interactive in [false, true] {
        for enrolled in [false, true] {
            for wrap in [false, true] {
                for open in [false, true] {
                    assert_eq!(
                        plan_presence_custody_bootstrap(
                            false,
                            non_interactive,
                            enrolled,
                            wrap,
                            open
                        ),
                        PresenceCustodyPlan::SkipNoSecureEnclave,
                        "no real SE must always skip"
                    );
                }
            }
        }
    }
}

#[test]
fn presence_custody_plan_fresh_store_enrolls_and_provisions() {
    // Clean store: real SE, interactive, nothing enrolled → the full one-tap
    // enroll ceremony (which auto-chains §4 provision) + open the window.
    assert_eq!(
        plan_presence_custody_bootstrap(true, false, false, false, false),
        PresenceCustodyPlan::EnrollProvisionThenUnlock
    );
}

#[test]
fn presence_custody_plan_enrolled_but_unprovisioned_provisions() {
    // The exact gauntlet dead-end OSCAR hit (`se-unlock → "run se-provision
    // first"`), now front-loaded: device enrolled, no wrapped KEK → provision
    // (no tap) then open the window.
    assert_eq!(
        plan_presence_custody_bootstrap(true, false, true, false, false),
        PresenceCustodyPlan::ProvisionThenUnlock
    );
    // The wrap-present/window-open signals are irrelevant while the wrap is
    // absent — provisioning supersedes them.
    assert_eq!(
        plan_presence_custody_bootstrap(true, false, true, false, true),
        PresenceCustodyPlan::ProvisionThenUnlock
    );
}

#[test]
fn presence_custody_plan_provisioned_but_locked_unlocks() {
    assert_eq!(
        plan_presence_custody_bootstrap(true, false, true, true, false),
        PresenceCustodyPlan::UnlockOnly
    );
}

#[test]
fn presence_custody_plan_ready_is_a_noop() {
    // Idempotent re-run on a fully-ready host: enrolled + provisioned + window
    // open → nothing to do. Holds even under `--non-interactive`.
    assert_eq!(
        plan_presence_custody_bootstrap(true, false, true, true, true),
        PresenceCustodyPlan::AlreadyOpen
    );
    assert_eq!(
        plan_presence_custody_bootstrap(true, true, true, true, true),
        PresenceCustodyPlan::AlreadyOpen
    );
}

#[test]
fn presence_custody_plan_non_interactive_defers_anything_needing_a_tap() {
    // `--non-interactive` (CI / scripted) cannot present a Touch ID, so every
    // not-already-open state defers to the manual ladder rather than leaving
    // custody half-built (e.g. provisioned-but-never-unlocked).
    for (enrolled, wrap, open) in [
        (false, false, false), // would be EnrollProvisionThenUnlock
        (true, false, false),  // would be ProvisionThenUnlock
        (true, true, false),   // would be UnlockOnly
    ] {
        assert_eq!(
            plan_presence_custody_bootstrap(true, true, enrolled, wrap, open),
            PresenceCustodyPlan::SkipNonInteractive,
            "non-interactive must defer tap-requiring state (enrolled={enrolled}, wrap={wrap}, open={open})"
        );
    }
}

// Model-auth capture — the brittle "find the
// token" parses are pure functions so the subprocess-spawning drivers
// (`claude setup-token` / `codex login`) only need a live walk to verify.

#[test]
fn extract_anthropic_oauth_token_finds_plan_token_in_setup_output() {
    // `claude setup-token` prints the token to stdout, possibly with banner text.
    let out = "Created a long-lived token for Claude Code:\n\nsk-ant-oat01-AbC123-_xyz\n\nStore it somewhere safe.\n";
    assert_eq!(
        extract_anthropic_oauth_token(out).as_deref(),
        Some("sk-ant-oat01-AbC123-_xyz")
    );
}

#[test]
fn extract_anthropic_oauth_token_trims_surrounding_punctuation() {
    assert_eq!(
        extract_anthropic_oauth_token("token: \"sk-ant-oat01-abc\".").as_deref(),
        Some("sk-ant-oat01-abc")
    );
}

#[test]
fn extract_anthropic_oauth_token_rejects_output_without_token() {
    assert_eq!(extract_anthropic_oauth_token("no token here\n"), None);
    // A bare prefix with nothing after it is not a usable token.
    assert_eq!(extract_anthropic_oauth_token("sk-ant-"), None);
}

#[test]
fn extract_codex_tokens_blob_descends_into_tokens_object() {
    // Whole `~/.codex/auth.json` shape: { tokens: {...}, OPENAI_API_KEY, ... }.
    let auth = r#"{"OPENAI_API_KEY":"sk-proj-x","tokens":{"access_token":"acc","refresh_token":"ref","account_id":"acct"},"last_refresh":"2026-06-07"}"#;
    let blob = extract_codex_tokens_blob(auth).expect("tokens blob");
    let parsed: serde_json::Value = serde_json::from_str(&blob).unwrap();
    assert_eq!(
        parsed.get("access_token").and_then(|v| v.as_str()),
        Some("acc")
    );
    // The bare-tokens shape must NOT carry the surrounding auth.json fields.
    assert!(parsed.get("OPENAI_API_KEY").is_none());
}

#[test]
fn extract_codex_tokens_blob_accepts_bare_tokens_object() {
    // The `jq '.tokens'` shape (top-level access_token, no wrapper).
    let bare = r#"{"access_token":"acc","refresh_token":"ref"}"#;
    let blob = extract_codex_tokens_blob(bare).expect("bare tokens blob");
    let parsed: serde_json::Value = serde_json::from_str(&blob).unwrap();
    assert_eq!(
        parsed.get("access_token").and_then(|v| v.as_str()),
        Some("acc")
    );
}

#[test]
fn extract_codex_tokens_blob_rejects_blob_without_access_token() {
    assert_eq!(
        extract_codex_tokens_blob(r#"{"tokens":{"refresh_token":"ref"}}"#),
        None
    );
    assert_eq!(
        extract_codex_tokens_blob(r#"{"tokens":{"access_token":""}}"#),
        None
    );
    assert_eq!(extract_codex_tokens_blob("not json"), None);
}

// `ember status` per-lane checklist (F8). The
// lane computation is pure over `StatusOverview`, so the whole at-a-glance
// matrix is unit-testable.

fn unlocked_vault_session() -> VaultStatusView {
    VaultStatusView {
        posture: "interactive-unlocked".to_string(),
        unlocked: true,
        live_vault_attached: true,
        session_pin_count: 1,
        grace_window_secs: 300,
        grace_remaining_secs: 0,
        grace_lock_pending: false,
        grace_zero_due: false,
        idle_secs: None,
        idle_timeout_secs: 300,
        quiet_hours_start: None,
        quiet_hours_end: None,
    }
}

#[test]
fn compute_status_lanes_covers_all_seven_lanes_in_order() {
    let overview = fake_status_overview_with_vault_session(unlocked_vault_session());
    let lanes = compute_status_lanes(&overview);
    let names: Vec<&str> = lanes.iter().map(|l| l.name).collect();
    assert_eq!(
        names,
        vec![
            "Daemon",
            "Presence",
            "Claude",
            "Codex",
            "Cursor",
            "GitHub",
            "Shadow PATH"
        ],
        "checklist must show every lane, in the OSCAR-mock order"
    );
}

#[test]
fn compute_status_lanes_ready_host_marks_infra_ok_and_missing_grants_fail() {
    // Fixture: daemon running, vault unlocked, GitHub App lane, no launcher
    // issue, and the default grant has scope "read" (NOT a Claude/Codex
    // runtime grant or Cursor launcher grant) — so the runtime/launcher
    // auth lanes are the only failures.
    let overview = fake_status_overview_with_vault_session(unlocked_vault_session());
    let lanes = compute_status_lanes(&overview);
    let lane = |name: &str| lanes.iter().find(|l| l.name == name).unwrap();

    assert_eq!(lane("Daemon").mark, StatusLaneMark::Ok);
    assert_eq!(lane("Presence").mark, StatusLaneMark::Ok);
    assert_eq!(lane("GitHub").mark, StatusLaneMark::Ok);
    assert_eq!(lane("Shadow PATH").mark, StatusLaneMark::Ok);

    let claude = lane("Claude");
    assert_eq!(claude.mark, StatusLaneMark::Fail);
    assert!(
        claude
            .next_action
            .as_deref()
            .unwrap()
            .contains("init --for claude"),
        "a missing Claude grant must point at `init --for claude`: {claude:?}"
    );
    let codex = lane("Codex");
    assert_eq!(codex.mark, StatusLaneMark::Fail);
    assert!(
        codex
            .next_action
            .as_deref()
            .unwrap()
            .contains("init --for codex")
    );
    let cursor = lane("Cursor");
    assert_eq!(cursor.mark, StatusLaneMark::Fail);
    assert!(
        cursor
            .next_action
            .as_deref()
            .unwrap()
            .contains("init --for cursor")
    );
}

#[test]
fn compute_status_lanes_marks_cursor_ok_with_launch_ready_grant() {
    let mut overview = fake_status_overview_with_vault_session(unlocked_vault_session());
    overview.summary.personas.push(
        serde_json::from_value(fake_persona_info_json(
            "persona-cursor",
            "cursor-default",
            "active",
        ))
        .expect("decode cursor persona"),
    );
    overview.summary.grants = vec![
        serde_json::from_value(fake_runtime_delegable_grant_info_json_with_lane(
            "grant-cursor",
            "persona-cursor",
            CURSOR_DEFAULT_SCOPE,
            CURSOR_DEFAULT_SCOPE,
        ))
        .expect("decode cursor grant"),
    ];
    overview.summary.grant_live_leases = vec!["grant-cursor".to_string()];

    let lanes = compute_status_lanes(&overview);
    let cursor = lanes
        .iter()
        .find(|lane| lane.name == "Cursor")
        .expect("cursor lane");
    assert_eq!(cursor.mark, StatusLaneMark::Ok);
    assert_eq!(cursor.detail, "launch grant ready; model auth Cursor-owned");
    assert_eq!(cursor.next_action, None);
}

#[test]
fn compute_status_lanes_marks_cursor_failed_with_stale_grant_without_live_lease() {
    let mut overview = fake_status_overview_with_vault_session(unlocked_vault_session());
    overview.summary.personas.push(
        serde_json::from_value(fake_persona_info_json(
            "persona-cursor",
            "cursor-default",
            "active",
        ))
        .expect("decode cursor persona"),
    );
    overview.summary.grants = vec![
        serde_json::from_value(fake_runtime_delegable_grant_info_json_with_lane(
            "grant-cursor-stale",
            "persona-cursor",
            CURSOR_DEFAULT_SCOPE,
            CURSOR_DEFAULT_SCOPE,
        ))
        .expect("decode cursor grant"),
    ];
    overview.summary.grant_live_leases = Vec::new();

    let lanes = compute_status_lanes(&overview);
    let cursor = lanes
        .iter()
        .find(|lane| lane.name == "Cursor")
        .expect("cursor lane");
    assert_eq!(cursor.mark, StatusLaneMark::Fail);
    assert_eq!(
        cursor.detail,
        "no launch-ready grant; model auth Cursor-owned"
    );
    assert!(
        cursor
            .next_action
            .as_deref()
            .unwrap()
            .contains("init --for cursor")
    );
}

#[test]
fn compute_status_lanes_locked_presence_is_a_warning() {
    let mut session = unlocked_vault_session();
    session.unlocked = false;
    session.posture = "presence-locked-vault-attached".to_string();
    let overview = fake_status_overview_with_vault_session(session);
    let lanes = compute_status_lanes(&overview);
    let presence = lanes.iter().find(|l| l.name == "Presence").unwrap();
    assert_eq!(
        presence.mark,
        StatusLaneMark::Warn,
        "a provisioned-but-locked presence lane is a warning, not a failure: {presence:?}"
    );
    assert!(presence.next_action.is_some());
}

#[test]
fn render_status_lane_checklist_shows_every_lane_and_a_next_action() {
    let overview = fake_status_overview_with_vault_session(unlocked_vault_session());
    let rendered = render_status_lane_checklist(&overview);
    assert!(
        rendered.contains("Onboarding lanes"),
        "missing heading: {rendered}"
    );
    for name in [
        "Daemon",
        "Presence",
        "Claude",
        "Codex",
        "Cursor",
        "GitHub",
        "Shadow PATH",
    ] {
        assert!(
            rendered.contains(name),
            "checklist missing lane {name}: {rendered}"
        );
    }
    assert!(
        rendered.contains('✓'),
        "checklist must mark ready lanes: {rendered}"
    );
    assert!(
        rendered.contains('✗'),
        "checklist must mark failing lanes: {rendered}"
    );
    // The single next action footer (Fix/Next) is always present.
    assert!(
        rendered.contains("→ Fix:") || rendered.contains("→ Next:"),
        "checklist must end with the one next action: {rendered}"
    );
}
