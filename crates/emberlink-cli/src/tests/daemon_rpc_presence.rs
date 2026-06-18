use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

static OPERATOR_PRESENCE_TOKEN_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn touch_id_key_use_error_names_biometry_lockout_recovery() {
    let message = format_touch_id_key_use_error(
        "presence-Device signing failed for 'create_composite_grant'",
        "SE sign failed: Biometry is locked out.",
    );

    assert!(message.contains("Biometry is locked out"), "{message}");
    assert!(message.contains("Touch ID is locked out"), "{message}");
    assert!(
        message.contains("unlock this Mac with your account password"),
        "{message}"
    );
    assert!(
        message.contains("rerun the command"),
        "hint should tell the operator the command is safe to retry: {message}"
    );
}

fn fake_presence_token_value_for_scope(uid: u32, scope: &str) -> serde_json::Value {
    use std::time::Duration;
    #[derive(serde::Serialize)]
    struct FakePresenceToken<'a> {
        uid: u32,
        scope: &'a str,
        expiry: SystemTime,
        signature: Vec<u8>,
    }

    serde_json::to_value(FakePresenceToken {
        uid,
        scope,
        expiry: SystemTime::now() + Duration::from_secs(60),
        signature: vec![1, 2, 3, 4],
    })
    .expect("presence token value")
}

/// Accept a Unix-socket connection with a wall-clock timeout, ensuring
/// tests never hang indefinitely on `__skb_wait_for_more_packets` when
/// a client thread crashes before connecting. Replaces bare
/// `listener.accept().expect(...)` calls in this module. Mirrors the
/// same-name helper in `crates/emberlink-cli/src/bin/ember.rs`.
///
/// anchor: emberlink_cli_lib_test_listener_timeout_landed
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
                        "listener.accept() timed out after {:?} — META-AP-EMBERLINK-CLI-LIB-TEST-HANG-UNIX-LISTENER-NO-TIMEOUT guard fired",
                        timeout
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(e) => panic!("listener.accept() error: {}", e),
        }
    }
}

/// ADR 206 §1 — the CLI presence-proof acquisition retry. A widening op
/// refused by the daemon chokepoint (-32030, "presence-Device signature")
/// triggers a `presence/request_nonce` → SE-sign → retry-with-`_presence_proof`
/// round, and the proof'd retry succeeds. Uses a registered stub SE key as the
/// enrolled presence Device (macOS-only — the SE driver is macOS).
#[cfg(target_os = "macos")]
#[test]
fn call_daemon_rpc_acquires_presence_proof_and_retries_for_widening_op() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let _guard = OPERATOR_PRESENCE_TOKEN_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    set_cached_operator_presence_token(None);

    // `presence_device_se_key()` lazily provisions a stub presence Device key
    // under the default label when the real-keychain lookup misses (test
    // affordance), so the acquisition path signs without hardware.
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let socket_path = tmp.path().join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let server = thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            // 1) create_grant (no proof) → chokepoint refusal.
            // 2) presence/request_nonce → mint nonce + intent bytes.
            // 3) create_grant (with _presence_proof) → success.
            for _ in 0..3 {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone stream"));
                let mut line = String::new();
                reader.read_line(&mut line).expect("read request");
                let req: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse request");
                let method = req["method"].as_str().expect("method").to_string();

                let response = if method == "create_grant"
                    && req["params"].get("_presence_proof").is_none()
                {
                    serde_json::json!({
                        "id": req["id"],
                        "error": {
                            "code": -32030,
                            "message": "widening op 'create_grant' requires a presence-Device signature (acquire one via presence/request_nonce and resubmit with _presence_proof)"
                        }
                    })
                } else if method == "presence/request_nonce" || method == "presence_request_nonce" {
                    assert_eq!(req["params"]["method"], serde_json::json!("create_grant"));
                    assert!(
                        req["params"]["op_id"]
                            .as_str()
                            .is_some_and(|s| !s.is_empty()),
                        "request_nonce must carry a non-empty op_id"
                    );
                    // ADR 206 §1.3 / Finding 1 — the CLI must commit the params
                    // digest, and (F2) it re-derives the canonical bytes locally
                    // and refuses if our echo diverges. So this mock daemon must
                    // be HONEST: echo the exact bytes the verifier reconstructs
                    // from the digest the CLI sent.
                    let op_id = req["params"]["op_id"].as_str().unwrap().to_string();
                    let pd = req["params"]["params_digest"]
                        .as_str()
                        .expect("request_nonce must carry params_digest")
                        .to_string();
                    let intent = ember_daemon::auth::presence_gate::canonical_presence_intent_bytes(
                        "create_grant",
                        &op_id,
                        "nonce-abc",
                        "fp-1",
                        &pd,
                    );
                    serde_json::json!({
                        "id": req["id"],
                        "result": {
                            "op_id": req["params"]["op_id"],
                            "method": "create_grant",
                            "nonce": "nonce-abc",
                            "daemon_fingerprint": "fp-1",
                            "params_digest": pd,
                            "expires_at": 9_999_999_999i64,
                            "intent_bytes_hex": hex::encode(&intent),
                        }
                    })
                } else {
                    // The proof'd retry must carry the signed nonce.
                    let proof = &req["params"]["_presence_proof"];
                    assert_eq!(
                        proof["nonce"],
                        serde_json::json!("nonce-abc"),
                        "retry must carry the minted nonce"
                    );
                    assert!(
                        proof["signature"]
                            .as_str()
                            .is_some_and(|s| s.starts_with("p256sig:")),
                        "retry must carry a p256 presence signature"
                    );
                    assert!(proof["op_id"].as_str().is_some_and(|s| !s.is_empty()));
                    serde_json::json!({
                        "id": req["id"],
                        "result": { "grant_id": "grant-1" }
                    })
                };

                let mut encoded = serde_json::to_string(&response).expect("encode response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write response");
            }
        }
    });

    ready_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("wait for fake daemon ready");
    let result = call_daemon_rpc(
        &socket_path,
        "create_grant",
        &serde_json::json!({ "persona_id": "p" }),
    )
    .expect("widening op must succeed after presence-proof acquisition");
    assert_eq!(result["grant_id"], serde_json::json!("grant-1"));
    server.join().expect("fake daemon thread");
}

/// Register a stub ECIES key under the operator-presence ECIES label and
/// return `(ecies_key_id, wrapped_kek_hex)` for a fresh 32-byte scope KEK
/// wrapped to it. The stub `se_wrap`/`se_unwrap` are symmetric by label, so
/// the §4 implicit-unlock helper's `se_unwrap` recovers exactly this KEK —
/// standing in for the hardware presence tap.
#[cfg(target_os = "macos")]
fn register_stub_ecies_and_wrap_kek() -> (String, String) {
    use ember_broker::secure_enclave as se;
    let ecies_label = format!("{OPERATOR_PRESENCE_SE_LABEL}-ecies");
    let handle = new_stub_key(&ecies_label);
    se_register_stub_key(&ecies_label, &handle);
    let pubkey = se::se_pubkey_bytes(&handle).expect("stub ecies pubkey");
    let ecies_key_id = format!("key-operator-ecies-{}", hex::encode(&pubkey));
    let kek = [7u8; 32];
    let role = se::EciesKeyLabel::from_provisioned(ecies_label);
    let wrapped = se::se_wrap(&role, &kek).expect("stub se_wrap KEK");
    (ecies_key_id, hex::encode(wrapped))
}

/// ADR 206 §4 — the CLI implicit-unlock retry. An authority op refused by the
/// daemon's fail-closed §4 gate because the unlock window is LOCKED
/// (`-32001`, reason `"locked"`) triggers, in an interactive/SE-capable
/// context, exactly ONE `se_unlock_begin` → `se_unwrap` tap →
/// `se_unlock_complete` round, then the original RPC is retried once and
/// succeeds. The tap is mocked via a registered stub ECIES key (no hardware).
#[cfg(target_os = "macos")]
#[test]
fn call_daemon_rpc_auto_unlocks_s4_window_and_retries_when_locked_and_capable() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let _guard = OPERATOR_PRESENCE_TOKEN_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    set_cached_operator_presence_token(None);
    SE_UNLOCK_CAPABLE_TEST_OVERRIDE.store(true, std::sync::atomic::Ordering::SeqCst);

    let (ecies_key_id, wrapped_hex) = register_stub_ecies_and_wrap_kek();

    let tmp = tempfile::TempDir::new().expect("temp dir");
    let socket_path = tmp.path().join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    // Count how many times the authority op was refused-for-lock, to prove
    // the retry is bounded to exactly one auto-unlock attempt.
    let lock_refusals = Arc::new(AtomicU64::new(0));
    let begin_calls = Arc::new(AtomicU64::new(0));
    let server = thread::spawn({
        let socket_path = socket_path.clone();
        let lock_refusals = Arc::clone(&lock_refusals);
        let begin_calls = Arc::clone(&begin_calls);
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            // 1) persona_create (locked) → -32001 "locked".
            // 2) vault.se_unlock_begin → return this device's wrap.
            // 3) vault.se_unlock_complete → ok (window opens).
            // 4) persona_create (window open) → success.
            for _ in 0..4 {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone stream"));
                let mut line = String::new();
                reader.read_line(&mut line).expect("read request");
                let req: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse request");
                let method = req["method"].as_str().expect("method").to_string();

                let response = match method.as_str() {
                    "persona_create" => {
                        // First call: locked. After the unlock round, succeed.
                        if begin_calls.load(Ordering::SeqCst) == 0 {
                            lock_refusals.fetch_add(1, Ordering::SeqCst);
                            serde_json::json!({
                                "id": req["id"],
                                "error": {
                                    "code": -32001,
                                    "message": serde_json::json!({
                                        "error": "authority_class_not_met",
                                        "reason": "locked"
                                    }).to_string(),
                                }
                            })
                        } else {
                            serde_json::json!({
                                "id": req["id"],
                                "result": { "persona_id": "persona-1" }
                            })
                        }
                    }
                    "vault.se_unlock_begin" => {
                        begin_calls.fetch_add(1, Ordering::SeqCst);
                        serde_json::json!({
                            "id": req["id"],
                            "result": {
                                "wraps": [{
                                    "ecies_key_id": ecies_key_id,
                                    "wrapped_kek": wrapped_hex,
                                }]
                            }
                        })
                    }
                    "vault.se_unlock_complete" => {
                        // The unwrapped KEK must come back (32 bytes hex).
                        let kek = req["params"]["scope_kek"].as_str().unwrap_or_default();
                        assert_eq!(kek.len(), 64, "scope_kek must be 32 bytes hex");
                        serde_json::json!({
                            "id": req["id"],
                            "result": { "unlocked": true }
                        })
                    }
                    other => panic!("unexpected method {other}"),
                };

                let mut encoded = serde_json::to_string(&response).expect("encode response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write response");
            }
        }
    });

    ready_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("wait for fake daemon ready");
    let result = call_daemon_rpc(
        &socket_path,
        "persona_create",
        &serde_json::json!({ "name": "p" }),
    )
    .expect("authority op must succeed after implicit §4 unlock");
    assert_eq!(result["persona_id"], serde_json::json!("persona-1"));
    // Exactly one auto-unlock attempt: one lock refusal, one unlock_begin.
    assert_eq!(lock_refusals.load(Ordering::SeqCst), 1);
    assert_eq!(begin_calls.load(Ordering::SeqCst), 1);
    server.join().expect("fake daemon thread");
    SE_UNLOCK_CAPABLE_TEST_OVERRIDE.store(false, std::sync::atomic::Ordering::SeqCst);
}

/// ADR 206 §1 (Phase 3) — the ONE-TAP batched widening path. A covered
/// minting widening op (`create_persona`) refused by the chokepoint for a
/// MISSING proof, in an interactive SE-capable context, acquires the §1 proof
/// AND the §4 KEK_s in a SINGLE batched gesture and submits BOTH in ONE retry
/// — there is NO `vault.se_unlock_complete` round-trip (the daemon installs
/// KEK_s transiently from the submitted `scope_kek`) and NO wasted re-sign.
/// The tap is mocked via registered stub SE keys (no hardware).
#[cfg(target_os = "macos")]
#[test]
fn call_daemon_rpc_one_tap_widening_submits_proof_and_scope_kek_together() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let _guard = OPERATOR_PRESENCE_TOKEN_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    set_cached_operator_presence_token(None);
    SE_UNLOCK_CAPABLE_TEST_OVERRIDE.store(true, std::sync::atomic::Ordering::SeqCst);

    let (ecies_key_id, wrapped_hex) = register_stub_ecies_and_wrap_kek();

    let tmp = tempfile::TempDir::new().expect("temp dir");
    let socket_path = tmp.path().join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let unlock_complete_calls = Arc::new(AtomicU64::new(0));
    let begin_calls = Arc::new(AtomicU64::new(0));
    let widened_calls = Arc::new(AtomicU64::new(0));
    let server = thread::spawn({
        let socket_path = socket_path.clone();
        let unlock_complete_calls = Arc::clone(&unlock_complete_calls);
        let begin_calls = Arc::clone(&begin_calls);
        let widened_calls = Arc::clone(&widened_calls);
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            // 1) create_persona (no proof) → -32030 chokepoint refusal.
            // 2) presence/request_nonce → nonce + intent bytes.
            // 3) vault.se_unlock_begin → this device's wrap.
            // 4) create_persona (with _presence_proof AND scope_kek) → success.
            // NOTE: NO vault.se_unlock_complete — the one-tap path submits the
            // KEK_s inline; the daemon installs it transiently.
            for _ in 0..4 {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone stream"));
                let mut line = String::new();
                reader.read_line(&mut line).expect("read request");
                let req: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse request");
                let method = req["method"].as_str().expect("method").to_string();

                let response = match method.as_str() {
                    "create_persona" => {
                        let has_proof = req["params"].get("_presence_proof").is_some();
                        let has_kek = req["params"].get("scope_kek").is_some();
                        if !has_proof {
                            // Chokepoint refusal: missing proof.
                            serde_json::json!({
                                "id": req["id"],
                                "error": {
                                    "code": -32030,
                                    "message": "widening op 'create_persona' requires a presence-Device signature (acquire one via presence/request_nonce and resubmit with _presence_proof)"
                                }
                            })
                        } else {
                            // The one-tap retry MUST carry BOTH proof + scope_kek.
                            widened_calls.fetch_add(1, Ordering::SeqCst);
                            assert!(
                                has_kek,
                                "one-tap retry must carry scope_kek alongside the proof"
                            );
                            let kek = req["params"]["scope_kek"].as_str().unwrap_or_default();
                            assert_eq!(kek.len(), 64, "scope_kek must be 32 bytes hex");
                            let proof = &req["params"]["_presence_proof"];
                            assert!(
                                proof["signature"]
                                    .as_str()
                                    .is_some_and(|s| s.starts_with("p256sig:")),
                                "one-tap retry must carry a p256 presence signature"
                            );
                            serde_json::json!({
                                "id": req["id"],
                                "result": { "id": "persona-1", "name": "p" }
                            })
                        }
                    }
                    "presence/request_nonce" | "presence_request_nonce" => {
                        assert_eq!(req["params"]["method"], serde_json::json!("create_persona"));
                        // Honest mock (F2): echo the canonical bytes the CLI
                        // re-derives from the digest it committed.
                        let op_id = req["params"]["op_id"].as_str().unwrap().to_string();
                        let pd = req["params"]["params_digest"]
                            .as_str()
                            .expect("request_nonce must carry params_digest")
                            .to_string();
                        let intent =
                            ember_daemon::auth::presence_gate::canonical_presence_intent_bytes(
                                "create_persona",
                                &op_id,
                                "nonce-xyz",
                                "fp-1",
                                &pd,
                            );
                        serde_json::json!({
                            "id": req["id"],
                            "result": {
                                "op_id": req["params"]["op_id"],
                                "method": "create_persona",
                                "nonce": "nonce-xyz",
                                "daemon_fingerprint": "fp-1",
                                "params_digest": pd,
                                "expires_at": 9_999_999_999i64,
                                "intent_bytes_hex": hex::encode(&intent),
                            }
                        })
                    }
                    "vault.se_unlock_begin" => {
                        begin_calls.fetch_add(1, Ordering::SeqCst);
                        serde_json::json!({
                            "id": req["id"],
                            "result": {
                                "wraps": [{
                                    "ecies_key_id": ecies_key_id,
                                    "wrapped_kek": wrapped_hex,
                                }]
                            }
                        })
                    }
                    "vault.se_unlock_complete" => {
                        unlock_complete_calls.fetch_add(1, Ordering::SeqCst);
                        serde_json::json!({ "id": req["id"], "result": { "unlocked": true } })
                    }
                    other => panic!("unexpected method {other}"),
                };

                let mut encoded = serde_json::to_string(&response).expect("encode response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write response");
            }
        }
    });

    ready_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("wait for fake daemon ready");
    let result = call_daemon_rpc(
        &socket_path,
        "create_persona",
        &serde_json::json!({ "name": "p" }),
    )
    .expect("one-tap widening must succeed");
    assert_eq!(result["id"], serde_json::json!("persona-1"));
    // Exactly one widened retry, one unlock_begin (the wrap fetch), and ZERO
    // se_unlock_complete calls — the KEK_s rode the inline scope_kek.
    assert_eq!(
        widened_calls.load(Ordering::SeqCst),
        1,
        "exactly one proof+kek retry"
    );
    assert_eq!(
        begin_calls.load(Ordering::SeqCst),
        1,
        "exactly one wrap fetch"
    );
    assert_eq!(
        unlock_complete_calls.load(Ordering::SeqCst),
        0,
        "the one-tap path must NOT call vault.se_unlock_complete"
    );
    server.join().expect("fake daemon thread");
    SE_UNLOCK_CAPABLE_TEST_OVERRIDE.store(false, std::sync::atomic::Ordering::SeqCst);
}

/// ADR 206 §4 — fail-closed in a non-interactive / SE-incapable context. The
/// same locked-window refusal MUST propagate unchanged with NO auto-unlock
/// attempt (no `vault.se_unlock_begin`, no tap), so headless / background
/// callers never loop on a presence dialog they cannot answer.
#[cfg(target_os = "macos")]
#[test]
fn call_daemon_rpc_does_not_auto_unlock_when_not_interactive() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let _guard = OPERATOR_PRESENCE_TOKEN_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    set_cached_operator_presence_token(None);
    // Non-interactive / SE-incapable: the capability gate is closed.
    SE_UNLOCK_CAPABLE_TEST_OVERRIDE.store(false, std::sync::atomic::Ordering::SeqCst);

    let tmp = tempfile::TempDir::new().expect("temp dir");
    let socket_path = tmp.path().join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let saw_unlock_begin = Arc::new(AtomicU64::new(0));
    let server = thread::spawn({
        let socket_path = socket_path.clone();
        let saw_unlock_begin = Arc::clone(&saw_unlock_begin);
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            // Only ONE request is expected: the locked refusal. If the CLI
            // tried to auto-unlock, a second `vault.se_unlock_begin` would
            // arrive — we flag it (and the assertion below catches it).
            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone stream"));
            let mut line = String::new();
            reader.read_line(&mut line).expect("read request");
            let req: serde_json::Value = serde_json::from_str(line.trim()).expect("parse request");
            if req["method"] == serde_json::json!("vault.se_unlock_begin") {
                saw_unlock_begin.fetch_add(1, Ordering::SeqCst);
            }
            let response = serde_json::json!({
                "id": req["id"],
                "error": {
                    "code": -32001,
                    "message": serde_json::json!({
                        "error": "authority_class_not_met",
                        "reason": "locked"
                    }).to_string(),
                }
            });
            let mut encoded = serde_json::to_string(&response).expect("encode response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write response");
        }
    });

    ready_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("wait for fake daemon ready");
    let err = call_daemon_rpc(
        &socket_path,
        "persona_create",
        &serde_json::json!({ "name": "p" }),
    )
    .expect_err("locked window must propagate fail-closed when not interactive");
    match err {
        DaemonRpcError::Rpc { code, message } => {
            assert_eq!(code, -32001);
            assert_eq!(authority_error_reason(&message).as_deref(), Some("locked"));
        }
        other => panic!("expected -32001 locked, got {other:?}"),
    }
    assert_eq!(
        saw_unlock_begin.load(Ordering::SeqCst),
        0,
        "must NOT attempt se_unlock_begin in a non-interactive context"
    );
    server.join().expect("fake daemon thread");
}

#[test]
fn cached_session_runtime_class_token_covers_session_open_and_runtime_methods() {
    let _guard = OPERATOR_PRESENCE_TOKEN_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    set_cached_operator_presence_token(None);
    let token: ember_daemon::auth::presence_token::PresenceToken = serde_json::from_value(
        fake_presence_token_value_for_scope(501, "class:session-runtime"),
    )
    .expect("session-runtime token");
    set_cached_operator_presence_token(Some(token));

    assert!(cached_operator_presence_token_for_method("register_session").is_some());
    assert!(cached_operator_presence_token_for_method("broker_exec").is_some());
    assert!(cached_operator_presence_token_for_method("broker_resolve").is_some());
    assert!(cached_operator_presence_token_for_method("vault_list").is_none());
    assert!(cached_operator_presence_token_for_method("create_persona").is_none());

    set_cached_operator_presence_token(None);
}

#[test]
fn cached_vault_class_token_covers_vault_unlock_and_vault_methods() {
    let _guard = OPERATOR_PRESENCE_TOKEN_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    set_cached_operator_presence_token(None);
    let token: ember_daemon::auth::presence_token::PresenceToken =
        serde_json::from_value(fake_presence_token_value_for_scope(501, "class:vault"))
            .expect("vault token");
    set_cached_operator_presence_token(Some(token));

    assert!(cached_operator_presence_token_for_method("vault_unlock").is_some());
    assert!(cached_operator_presence_token_for_method("vault_list").is_some());
    assert!(cached_operator_presence_token_for_method("broker_exec").is_none());
    assert!(cached_operator_presence_token_for_method("register_session").is_none());

    set_cached_operator_presence_token(None);
}

#[test]
fn daemon_rpc_guidance_maps_locked_retry_exhaustion() {
    let guidance = daemon_rpc_guidance(
        "create_persona",
        -32030,
        "create_persona denied: session is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts. Run `ember vault unlock` to invoke the managed separate-uid biometric unlock flow when available. If you are on a dev probe lane, restart the daemon with `EMBER_VAULT_PASSPHRASE`; future broker-mediated browser auth remains planned",
    )
    .expect("expected guidance");
    assert!(guidance.contains("operator presence"));
    assert!(guidance.contains("managed separate-uid biometric unlock"));
    assert!(guidance.contains("ember vault unlock"));
    assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
}

#[test]
fn daemon_rpc_guidance_maps_register_session_missing_runtime_presence() {
    let guidance = daemon_rpc_guidance(
        "register_session",
        -32001,
        r#"{"error":"authority_class_not_met","reason":"missing"}"#,
    )
    .expect("expected guidance");
    assert!(guidance.contains("session-runtime presence credential"));
    assert!(guidance.contains("register_session"));
    assert!(guidance.contains("ember status"));
    assert!(!guidance.contains("ember vault unlock"));
}

#[test]
fn daemon_rpc_guidance_maps_register_session_locked_to_implicit_se_unlock() {
    let guidance = daemon_rpc_guidance(
        "register_session",
        -32030,
        "register_session: live vault is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts",
    )
    .expect("expected guidance");
    assert!(guidance.contains("ADR 206 §4"));
    assert!(guidance.contains("normally performs this Touch ID unlock implicitly"));
    assert!(guidance.contains("ember vault se-unlock"));
    assert!(!guidance.contains("ember vault unlock"));
}

#[test]
fn daemon_rpc_guidance_names_posture_mismatch_for_vault_unlock() {
    let guidance = daemon_rpc_guidance(
        "vault_unlock",
        -32030,
        "vault_unlock denied: session is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts. Run `ember vault unlock` to invoke the managed separate-uid biometric unlock flow when available. If you are on a dev probe lane, restart the daemon with `EMBER_VAULT_PASSPHRASE`; future broker-mediated browser auth remains planned",
    )
    .expect("expected guidance");
    assert!(guidance.contains("managed separate-uid posture"));
    assert!(guidance.contains("managed separate-uid biometric unlock flow"));
    assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
    assert!(guidance.contains("sudo ember daemon install"));
    assert!(
        !guidance.contains("Run `ember vault unlock` to invoke"),
        "vault_unlock guidance should not tell the operator to rerun the same command: {guidance}"
    );
}

#[test]
fn daemon_rpc_guidance_names_posture_mismatch_when_begin_needs_managed_lane() {
    let guidance = daemon_rpc_guidance(
        "vault_unlock",
        -32030,
        "vault_unlock_begin is only required on the separate-uid managed daemon path",
    )
    .expect("expected guidance");
    assert!(guidance.contains("managed separate-uid posture"));
    assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
    assert!(guidance.contains("sudo ember daemon install"));
    assert!(
        !guidance.contains("Run `ember vault unlock` to invoke"),
        "vault_unlock guidance should stay posture-focused when begin is unavailable: {guidance}"
    );
}

#[test]
fn daemon_rpc_guidance_maps_quarantined_write_class_refusal() {
    let guidance = daemon_rpc_guidance(
        "broker.github_status",
        -32603,
        "daemon quarantined; write-class method `broker.github_status` refused",
    )
    .expect("expected quarantine guidance");
    assert!(guidance.contains("daemon quarantined"), "got: {guidance}");
    assert!(guidance.contains("ember doctor"), "got: {guidance}");
    assert!(guidance.contains("repair the daemon"), "got: {guidance}");
}

#[test]
fn format_daemon_socket_io_error_maps_eperm_to_shell_guidance() {
    let err = std::io::Error::from_raw_os_error(1);
    let message = format_daemon_socket_io_error(&err);
    assert!(message.contains("ember-clients"), "got: {message}");
    assert!(message.contains("fresh login shell"), "got: {message}");
    assert!(
        message.contains("sudo ember daemon install"),
        "got: {message}"
    );
}

#[test]
fn format_daemon_socket_io_error_maps_eacces_to_shell_guidance() {
    let err = std::io::Error::from_raw_os_error(13);
    let message = format_daemon_socket_io_error(&err);
    assert!(message.contains("ember-clients"), "got: {message}");
    assert!(message.contains("fresh login shell"), "got: {message}");
    assert!(
        message.contains("sudo ember daemon install"),
        "got: {message}"
    );
}

#[test]
fn format_daemon_socket_io_error_preserves_non_permission_failures() {
    let err = std::io::Error::other("boom");
    let message = format_daemon_socket_io_error(&err);
    assert!(
        message.starts_with("daemon socket error: boom"),
        "got: {message}"
    );
    assert!(message.contains("ember doctor"), "got: {message}");
}

#[test]
fn format_daemon_socket_io_error_repo_build_preserves_invoking_launcher_path() {
    let err = std::io::Error::from_raw_os_error(13);
    let message = format_daemon_socket_io_error_with_ember_command(
        &err,
        Some("/home/operator/emberlink-example/target/debug/ember"),
    );
    assert!(
        message.contains("sudo /home/operator/emberlink-example/target/debug/ember daemon install"),
        "repo-build socket guidance must preserve the invoking launcher path: {message}"
    );
}

#[test]
fn format_daemon_unavailable_maps_permission_denied_to_shell_guidance() {
    let socket = std::path::Path::new("/tmp/.ember/run/daemon.sock");
    let err = std::io::Error::from_raw_os_error(13);
    let message = format_daemon_unavailable(socket, &err);
    assert!(message.contains(socket.to_str().unwrap()), "got: {message}");
    assert!(message.contains("ember-clients"), "got: {message}");
    assert!(
        message.contains("sudo ember daemon install"),
        "got: {message}"
    );
}

#[test]
fn format_daemon_unavailable_preserves_missing_socket_guidance() {
    let socket = std::path::Path::new("/tmp/.ember/run/daemon.sock");
    let err = std::io::Error::from(std::io::ErrorKind::NotFound);
    let message = format_daemon_unavailable(socket, &err);
    assert!(message.contains("daemon unavailable"), "got: {message}");
    assert!(message.contains("ember status"), "got: {message}");
    assert!(
        message.contains("sudo ember daemon install"),
        "got: {message}"
    );
}

#[test]
fn format_daemon_unavailable_repo_build_preserves_status_and_install_commands() {
    let socket = std::path::Path::new("/tmp/.ember/run/daemon.sock");
    let err = std::io::Error::from(std::io::ErrorKind::NotFound);
    let message = format_daemon_unavailable_with_ember_command(
        socket,
        &err,
        Some("/home/operator/emberlink-example/target/debug/ember"),
    );
    assert!(
        message.contains("`/home/operator/emberlink-example/target/debug/ember status`"),
        "repo-build unavailable guidance must preserve the invoking status command: {message}"
    );
    assert!(
        message.contains("`sudo /home/operator/emberlink-example/target/debug/ember daemon install`"),
        "repo-build unavailable guidance must preserve the invoking repair command: {message}"
    );
}

#[test]
fn call_daemon_method_without_unlock_retry_surfaces_locked_vault_guidance() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::TempDir::new().expect("temp dir");
    let socket_path = tmp.path().join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let server = thread::spawn({
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
                "error": {
                    "code": -32000,
                    "message": "vault list denied: no vault is attached",
                }
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let err = call_daemon_method_without_unlock_retry(
        &socket_path,
        "vault_list",
        &serde_json::Value::Null,
    )
    .expect_err("locked vault should surface guidance without auto-unlock");

    let message = err.to_string();
    assert!(
        message.contains("operator presence on the daemon-managed vault lane"),
        "got: {message}"
    );
    assert!(
        message.contains("same-daemon operator-uid reopen is intentionally disabled"),
        "got: {message}"
    );

    server.join().expect("fake daemon thread");
}
