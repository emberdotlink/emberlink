//! SCION-EMBER-EXEC-F-RECEIPT-V2-EMIT — T2 tests for the emberd-side
//! `exec.completion` Receipt v2 emission path.
//!
//! Two tests:
//!
//!   1. `test_emit_exec_completion_receipt_signs_and_verifies` — direct
//!      unit test of the helper fn. Constructs deterministic inputs,
//!      calls `emit_exec_completion_receipt`, asserts the returned
//!      envelope has the right `kind`, body fields match every input,
//!      and `verify_receipt_v2` succeeds against the signer's public
//!      key. A second call with a tampered field (flipped `exit_code`
//!      bit) fails verification.
//!
//!   2. `test_handle_exit_frame_emits_receipt` — integration through
//!      `handle_broker_exec`'s in-container branch. Stands up a mock
//!      `ember-exec` listener on a tempfile UDS that emits one
//!      `ExecFrame::Exit { code: 0 }`, drives the broker_exec call
//!      end-to-end, asserts exactly one `exec.completion` row appears
//!      in the audit log, the serialized envelope round-trips through
//!      `verify_receipt_v2` against the daemon identity's pubkey, and
//!      the body fields match the inputs the daemon was supposed to
//!      record.
//!
//! All tests are `#[cfg(unix)]` — the in-container exec path is
//! Unix-only by construction (`tokio::net::UnixStream`).

#![cfg(unix)]

use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use core_crypto::{FixtureSigner, FixtureVerifier, Signer};
use core_events::receipt::{ExecCompletionBody, RECEIPT_KIND_EXEC_COMPLETION, verify_receipt_v2};
use ember_daemon::infra::audit::AuditFilter;
use ember_daemon::infra::receipt::{current_identity, init_identity};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::spawn::scion::emit_exec_completion_receipt;
use ember_exec::uds::{ExecFrame, read_frame, write_frame};
use tempfile::TempDir;
use tokio::net::UnixListener;
use uuid::Uuid;

const TEST_VAULT_KEY: [u8; 32] = [0xACu8; 32];

fn write_runner_manifest(
    home: &std::path::Path,
    tool_name: &str,
    binary_path: &std::path::Path,
) -> PathBuf {
    let manifest_dir = home.join(".ember/binaries");
    std::fs::create_dir_all(&manifest_dir).expect("mkdir manifest dir");
    let manifest_path = manifest_dir.join("manifest.toml");
    let manifest_body = format!(
        "\
[[entries]]
tool_name = \"{tool_name}\"
version = \"1.0.0\"
content_hash = \"blake3:test\"
absolute_path = \"{}\"
installed_at = 1735689600
publisher = \"did:emberlink\"
channel = \"bundled\"
",
        binary_path.display()
    );
    std::fs::write(&manifest_path, manifest_body).expect("write runner manifest");
    manifest_path
}

fn write_managed_worktree(home: &std::path::Path, runtime_id: &str) -> PathBuf {
    let worktree_path = home.join("repo/.ember/worktrees/demo");
    std::fs::create_dir_all(worktree_path.join(".git")).expect("mkdir worktree git dir");
    std::fs::write(
        worktree_path.join(".agent-session"),
        format!(
            "runtime_id: {runtime_id}\nworktree_path: {}\n",
            worktree_path.display()
        ),
    )
    .expect("write managed worktree metadata");
    worktree_path
}

struct HomeGuard {
    previous_home: Option<std::ffi::OsString>,
    previous_manifest_path: Option<std::ffi::OsString>,
}

impl HomeGuard {
    fn set(home: &std::path::Path, manifest_path: &std::path::Path) -> Self {
        let previous_home = std::env::var_os("HOME");
        let previous_manifest_path = std::env::var_os("EMBER_MANIFEST_PATH");
        unsafe {
            std::env::set_var("HOME", home);
            std::env::set_var("EMBER_MANIFEST_PATH", manifest_path);
        }
        Self {
            previous_home,
            previous_manifest_path,
        }
    }
}

impl Drop for HomeGuard {
    fn drop(&mut self) {
        match self.previous_home.take() {
            Some(home) => unsafe {
                std::env::set_var("HOME", home);
            },
            None => unsafe {
                std::env::remove_var("HOME");
            },
        }
        match self.previous_manifest_path.take() {
            Some(path) => unsafe {
                std::env::set_var("EMBER_MANIFEST_PATH", path);
            },
            None => unsafe {
                std::env::remove_var("EMBER_MANIFEST_PATH");
            },
        }
    }
}

/// Build an in-memory store with a vault attached so broker_exec
/// auxiliary paths that touch persona-secret encryption have a stable
/// dependency. The vault is irrelevant to the receipt-emission path
/// itself but the store fixtures other test suites use carry it.
fn store_with_vault() -> DaemonStore {
    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    store.set_vault(Rc::new(Vault::new(TEST_VAULT_KEY)));
    store
}

/// Initialise the process-singleton daemon identity once per binary so
/// the broker_exec receipt-emission path can find a signer.
/// `init_identity` is idempotent (first caller wins) so all tests
/// here can call it independently. Returns the temp dir so the
/// caller keeps it alive for the test's lifetime.
fn init_test_identity() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir for daemon identity");
    let _ = init_identity(dir.path());
    dir
}

// ---------------------------------------------------------------------------
// Test 1 — direct unit test of the helper fn (no broker_exec involvement)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_emit_exec_completion_receipt_signs_and_verifies() {
    // Deterministic inputs. Every field is distinct so a serialiser
    // drift in any one is caught by the field-by-field assertions
    // below.
    let persona_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let grant_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
    let binary_path = PathBuf::from("/usr/local/bin/scion-test-binary");
    let binary_blake3 =
        "deadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00d".to_string();
    let target_uid: u32 = 1234;
    let exit_code: i32 = 0;
    let materialized_at = Utc.with_ymd_and_hms(2026, 5, 12, 18, 0, 0).unwrap();

    let signer = FixtureSigner::new("scion-exec-receipt-fixture");
    let public_key = signer.public_key();

    let envelope = emit_exec_completion_receipt(
        persona_id,
        grant_id,
        binary_path.clone(),
        binary_blake3.clone(),
        target_uid,
        exit_code,
        materialized_at,
        &signer,
    )
    .expect("emit_exec_completion_receipt should succeed");

    // Kind discriminator MUST match the new constant.
    assert_eq!(
        envelope.kind, RECEIPT_KIND_EXEC_COMPLETION,
        "kind must be exec.completion"
    );
    assert_eq!(envelope.kind, "exec.completion");

    // Receipt is signed (non-empty signature) and receipt_id is
    // populated (non-empty hex).
    assert!(envelope.signature.is_some(), "signature must be populated");
    assert!(
        !envelope.receipt_id.is_empty(),
        "receipt_id must be non-empty after signing"
    );

    // Body deserializes back to the canonical body struct and every
    // input field round-trips losslessly.
    let body: ExecCompletionBody = serde_json::from_value(envelope.body.clone())
        .expect("body must deserialize as ExecCompletionBody");
    assert_eq!(body.persona_id, persona_id.to_string());
    assert_eq!(body.grant_id, grant_id.to_string());
    assert_eq!(body.binary_path, binary_path.display().to_string());
    assert_eq!(body.binary_blake3, binary_blake3);
    assert_eq!(body.target_uid, target_uid);
    assert_eq!(body.exit_code, exit_code);
    assert_eq!(body.materialized_at, materialized_at.to_rfc3339());

    // ed25519 signature verifies against the signer's public key.
    verify_receipt_v2(&envelope, &public_key, &FixtureVerifier)
        .expect("verify_receipt_v2 should succeed against the signer's public key");

    // Tamper: flip the exit_code in the body and re-attempt
    // verification. The signature MUST fail — that's the whole point
    // of recording the verified hash in the receipt.
    let mut tampered = envelope.clone();
    let mut tampered_body = body.clone();
    tampered_body.exit_code ^= 1; // flip one bit
    tampered.body = serde_json::to_value(&tampered_body).unwrap();
    let r = verify_receipt_v2(&tampered, &public_key, &FixtureVerifier);
    assert!(
        r.is_err(),
        "verify_receipt_v2 must fail after exit_code bit-flip; got {r:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — integration through handle_broker_exec's in-container branch
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_handle_exit_frame_emits_receipt() {
    // Daemon identity is the receipt signer. Initialise once for this
    // binary so `current_identity()` returns Some in the broker_exec
    // path. Keep the tempdir alive for the test.
    let _id_dir = init_test_identity();
    let identity = current_identity().expect("identity must be loaded");
    let daemon_pubkey = identity.pubkey_hex();

    // Stage a tempfile UDS. The mock listener accepts one
    // connection, reads a SpawnDirective, then writes a single
    // `ExecFrame::Exit { code: 0 }` and closes. This is exactly the
    // contract the in-container `ember-exec` receiver presents.
    let tmp = tempfile::Builder::new()
        .prefix("ember-exec-")
        .tempdir_in("/tmp")
        .expect("short socket tempdir");
    let socket_path = tmp.path().join("mock-ember-exec.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind UDS");

    let store = store_with_vault();
    let runner_home = TempDir::new().expect("runner tempdir");
    let fake_gh = runner_home.path().join("bin/ember-gh");
    std::fs::create_dir_all(fake_gh.parent().expect("parent")).expect("mkdir bin dir");
    if std::os::unix::fs::symlink("/usr/bin/true", &fake_gh).is_err() {
        std::fs::write(&fake_gh, b"#!/bin/sh\nexec /usr/bin/true \"$@\"\n").expect("write fake gh");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&fake_gh).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_gh, perms).expect("chmod fake gh");
    }
    let manifest_path = write_runner_manifest(runner_home.path(), "ember-gh", &fake_gh);
    let _home_guard = HomeGuard::set(runner_home.path(), &manifest_path);
    let runtime_id = format!("rt-{}", Uuid::new_v4().simple());
    write_managed_worktree(runner_home.path(), &runtime_id);

    // Build a broker_exec request that routes through the
    // in-container branch via `scion_exec_socket`. The resolved
    // runner binary must still look like an `ember-gh` tool so the
    // daemon-side classifier can map argv back to `pr_merge`; the
    // symlink target is `/usr/bin/true` so the content hash stays
    // stable and universally available.
    let action_ref = core_event_types::ActionRef::new(
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
        "v1",
    );
    let workspace_ref = format!("managed_worktree:{runtime_id}");
    let mut execution_contract = core_event_types::ExecutionContract::new(action_ref.clone());
    execution_contract.workspace_ref = Some(workspace_ref.clone());
    let req = serde_json::json!({
        "execution_contract": execution_contract,
        "argv": ["pr", "merge", "123"],
        "env_passthrough": [],
        "scion_exec_socket": socket_path.to_string_lossy(),
        "scion_target_uid": 4242u32,
        "scion_target_gid": 4242u32,
    });

    // `handle_broker_exec` is async; we need a LocalSet because
    // `DaemonStore` is `!Send`. Drive both the handler and the mock
    // listener on this thread.
    let local = tokio::task::LocalSet::new();
    let resp_value = local
        .run_until(async move {
            // Spawn the mock listener INSIDE the LocalSet so
            // `spawn_local` is valid here. The listener accepts the
            // daemon's connect, reads the SpawnDirective, then writes
            // one Exit frame.
            let mock_handle = tokio::task::spawn_local(async move {
                let (mut stream, _addr) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .expect("accept timeout")
                        .expect("accept failed");

                let _frame = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream))
                    .await
                    .expect("read_frame timeout")
                    .expect("read_frame io error")
                    .expect("read_frame returned None at EOF");

                let exit_frame = ExecFrame::Exit { code: 0 };
                write_frame(&mut stream, &exit_frame)
                    .await
                    .expect("write Exit frame");
            });

            let resp_value = ember_daemon::broker::handler::handle_broker_exec(None, &store, &req)
                .await
                .expect("handle_broker_exec ok");
            // Reap the mock listener — it should have already written
            // the Exit frame and returned.
            mock_handle.await.expect("mock listener task");

            // Assert exactly one exec.completion row in the audit
            // log. The shadow-row pattern persists via `log_event`
            // with `action = "exec.completion"`.
            let entries = store
                .query_audit(&AuditFilter {
                    action: Some("exec.completion".to_string()),
                    ..Default::default()
                })
                .expect("query_audit");
            assert_eq!(
                entries.len(),
                1,
                "expected exactly one exec.completion audit row; got {entries:#?}"
            );
            let row = &entries[0];
            assert_eq!(row.outcome, "success");
            let envelope_json = row
                .details
                .as_deref()
                .expect("audit row must carry envelope JSON in details");

            // Parse the envelope and verify the signature against the
            // daemon's own pubkey. The daemon identity's wire form is
            // `ed25519:<hex>` per `DaemonPersonaSigner::public_key`.
            let envelope: core_events::receipt::ReceiptEnvelope =
                serde_json::from_str(envelope_json).expect("parse envelope JSON");
            assert_eq!(envelope.kind, RECEIPT_KIND_EXEC_COMPLETION);
            let pubkey = core_crypto::PublicKey(format!("ed25519:{daemon_pubkey}"));
            verify_receipt_v2(&envelope, &pubkey, &core_crypto::Ed25519Verifier)
                .expect("verify_receipt_v2 against daemon pubkey");

            // Body field provenance — at minimum the binary_path +
            // exit_code + target_uid + non-empty binary_blake3 must
            // match what the daemon was supposed to record. Persona
            // and grant resolve to Uuid::nil() for this legacy-style
            // caller (no caller_persona in params).
            let body: ExecCompletionBody =
                serde_json::from_value(envelope.body.clone()).expect("body deserialize");
            assert_eq!(body.binary_path, fake_gh.display().to_string());
            assert_eq!(body.exit_code, 0);
            assert_eq!(body.target_uid, 4242);
            assert!(
                body.binary_blake3.len() == 64
                    && body.binary_blake3.chars().all(|c| c.is_ascii_hexdigit()),
                "binary_blake3 must be 64 hex chars; got {:?}",
                body.binary_blake3
            );
            assert_eq!(body.persona_id, Uuid::nil().to_string());
            assert_eq!(body.grant_id, Uuid::nil().to_string());

            resp_value
        })
        .await;

    // The broker_exec response is `BrokerExecResponse` shape; the
    // resp_value carries success=true / exit_code=0 mirroring the
    // mock listener's Exit frame.
    let resp: ember_daemon::broker::handler::BrokerExecResponse =
        serde_json::from_value(resp_value).expect("deserialize BrokerExecResponse");
    assert_eq!(resp.exit_code, 0);
    assert!(resp.success);
}
