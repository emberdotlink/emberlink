mod support;

use ember_authority::{
    action_admission::ActionAdmission,
    action_definition::ActionDefinitionRegistry,
    audit::{decode_canonical, now_unix, sha256},
    control::AuthorityControl,
    device::DeviceCustody,
    identity,
    initialization::ArtifactSource,
    ipc::{FRAME_LIMIT, read_frame},
    kernel::AuthorityKernel,
    model::{
        ACTION_REQUEST_SCHEMA, ActionRef, ActionRequest, DEFINITION_DIGEST, DiagnosticFacts,
        DiagnosticInput, OperationStatus, QualificationCoverage,
    },
    network_enforcement::NetworkEnforcement,
    operation::OperationSettlement,
    receipt::ReceiptProjection,
    runner::JournalHealth,
    runtime_presence::AuthenticatedProcess,
};
use serde::{Deserialize, Serialize};
use std::{io::Cursor, os::unix::net::UnixStream};

use support::{anchor, authority, request as initialization_request};

fn active_session(control: &AuthorityControl, challenge: &str) -> (String, AuthenticatedProcess) {
    let (peer, _other) = UnixStream::pair().unwrap();
    let process =
        ember_authority::runtime_presence::ExecutionBindingAuthority::authenticate_fd(&peer)
            .unwrap();
    let launch = control
        .open_diagnostic_session(challenge, process.uid, "test-session.sock".into())
        .unwrap();
    control
        .activate_session(
            &launch.session_id,
            &launch.execution_binding_id,
            process.pid,
            Some(process.pid_version),
        )
        .unwrap();
    (launch.session_id, process)
}

fn request(submission_id: &str, challenge: &str) -> ActionRequest {
    ActionRequest {
        schema: ACTION_REQUEST_SCHEMA.into(),
        submission_id: submission_id.into(),
        action_ref: ActionRef::diagnostic(),
        definition_digest: DEFINITION_DIGEST.into(),
        input: DiagnosticInput {
            challenge: challenge.into(),
        },
    }
}

#[test]
fn signed_initialization_vector_commits_once_and_rejects_untrusted_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("authority");
    let valid = initialization_request(directory.path(), "initialization");
    let (control, receipt) =
        AuthorityControl::initialize_at(&root, valid, &anchor(), now_unix()).unwrap();
    assert_eq!(receipt.generation, 1);
    ReceiptProjection::verify(control.store(), &receipt.receipt_id).unwrap();
    drop(control);
    AuthorityControl::restore(&root).unwrap();

    let directory = tempfile::tempdir().unwrap();
    let altered = initialization_request(directory.path(), "initialization");
    std::fs::write(&altered.artifacts[0].path, b"altered").unwrap();
    assert_eq!(
        AuthorityControl::initialize_at(
            &directory.path().join("authority"),
            altered,
            &anchor(),
            now_unix(),
        )
        .err()
        .unwrap()
        .code,
        "release_artifact_invalid"
    );

    let directory = tempfile::tempdir().unwrap();
    let mut wrong_root = initialization_request(directory.path(), "initialization");
    wrong_root.intent_signature.push('0');
    assert_eq!(
        AuthorityControl::initialize_at(
            &directory.path().join("authority"),
            wrong_root,
            &anchor(),
            now_unix(),
        )
        .err()
        .unwrap()
        .code,
        "root_intent_signature_invalid"
    );

    let directory = tempfile::tempdir().unwrap();
    let unanchored = initialization_request(directory.path(), "initialization");
    let mut wrong_anchor = anchor();
    wrong_anchor.signer_authorization_chain_digest = sha256(b"untrusted");
    assert_eq!(
        AuthorityControl::initialize_at(
            &directory.path().join("authority"),
            unanchored,
            &wrong_anchor,
            now_unix(),
        )
        .err()
        .unwrap()
        .code,
        "release_manifest_invalid"
    );

    let directory = tempfile::tempdir().unwrap();
    let mut extra = initialization_request(directory.path(), "initialization");
    extra.artifacts.push(ArtifactSource {
        artifact_id: "unanchored:extra".into(),
        path: extra.artifacts[0].path.clone(),
    });
    assert_eq!(
        AuthorityControl::initialize_at(
            &directory.path().join("authority"),
            extra,
            &anchor(),
            now_unix(),
        )
        .err()
        .unwrap()
        .code,
        "release_artifact_invalid"
    );

    let directory = tempfile::tempdir().unwrap();
    let expired = initialization_request(directory.path(), "initialization");
    let expired_at = expired
        .activation_plan
        .maintenance_window_expiry
        .saturating_add(1);
    assert_eq!(
        AuthorityControl::initialize_at(
            &directory.path().join("authority"),
            expired,
            &anchor(),
            expired_at,
        )
        .err()
        .unwrap()
        .code,
        "initialization_invalid"
    );
}

#[test]
fn action_path_settles_once_and_receipt_survives_session_close() {
    let (root, control) = authority("contract-ok");
    let (session_id, process) = active_session(&control, "contract-ok");
    let response = AuthorityKernel::new(control.store().clone())
        .submit(
            &session_id,
            process,
            request("submission-ok", "contract-ok"),
        )
        .unwrap();
    control.close_session(&session_id).unwrap();
    drop(control);

    let restored = AuthorityControl::restore_read_only(&root.path().join("authority")).unwrap();
    let rows = ReceiptProjection::list(restored.store()).unwrap();
    assert_eq!(rows.len(), 2);
    let operation = rows
        .iter()
        .find(|row| row.receipt_id == response.receipt_id)
        .unwrap();
    assert_eq!(operation.terminal_status, OperationStatus::Success);
    let shown = ReceiptProjection::show(restored.store(), &response.receipt_id).unwrap();
    assert!(shown.contains("\"action.operation\""));
    ReceiptProjection::verify(restored.store(), &response.receipt_id).unwrap();
}

#[test]
fn action_boundary_refuses_missing_binding_definition_need_and_replay_conflict() {
    let (_root, control) = authority("allowed");
    let kernel = AuthorityKernel::new(control.store().clone());
    let valid_process = AuthenticatedProcess {
        uid: ember_authority::effective_uid(),
        pid: std::process::id(),
        pid_version: identity::process_pid_version(std::process::id()).unwrap(),
    };
    assert_eq!(
        kernel
            .submit("absent", valid_process, request("missing", "x"))
            .unwrap_err()
            .code,
        "missing_session"
    );
    assert_eq!(
        control
            .open_diagnostic_session(
                "wrong-persona",
                ember_authority::effective_uid().saturating_add(1),
                "wrong-persona.sock".into(),
            )
            .unwrap_err()
            .code,
        "persona_mismatch"
    );

    let (session_id, process) = active_session(&control, "allowed");
    let wrong_process = AuthenticatedProcess {
        pid: process.pid.saturating_add(1),
        ..process
    };
    assert_eq!(
        kernel
            .submit(
                &session_id,
                wrong_process,
                request("wrong-binding", "allowed")
            )
            .unwrap_err()
            .code,
        "session_binding_mismatch"
    );

    let mut unknown = request("unknown", "allowed");
    unknown.action_ref.action_key = "other".into();
    assert_eq!(
        kernel
            .submit(&session_id, process, unknown)
            .unwrap_err()
            .code,
        "unknown_definition"
    );

    let mut altered = request("altered", "allowed");
    altered.definition_digest = format!("sha256:{}", "0".repeat(64));
    assert_eq!(
        kernel
            .submit(&session_id, process, altered)
            .unwrap_err()
            .code,
        "definition_digest_mismatch"
    );

    assert_eq!(
        kernel
            .submit(&session_id, process, request("uncovered", "other"))
            .unwrap_err()
            .code,
        "uncovered_need"
    );

    let original = kernel
        .submit(&session_id, process, request("replay", "allowed"))
        .unwrap();
    let replay = kernel
        .submit(&session_id, process, request("replay", "allowed"))
        .unwrap();
    assert_eq!(original.receipt_id, replay.receipt_id);
    let mut action_conflict = request("replay", "allowed");
    action_conflict.action_ref.action_key = "other".into();
    assert_eq!(
        kernel
            .submit(&session_id, process, action_conflict)
            .unwrap_err()
            .code,
        "replay_conflict"
    );
    let mut conflict = request("replay", "different");
    conflict.definition_digest = DEFINITION_DIGEST.into();
    assert_eq!(
        kernel
            .submit(&session_id, process, conflict)
            .unwrap_err()
            .code,
        "replay_conflict"
    );
    assert_eq!(ReceiptProjection::list(control.store()).unwrap().len(), 2);
}

#[test]
fn expired_authorization_and_duplicate_settlement_fail_closed() {
    let (_root, control) = authority("settlement");
    let (session_id, process) = active_session(&control, "settlement");
    let now = now_unix();
    let request = request("settlement", "settlement");
    let input_digest = sha256(&serde_jcs::to_vec(&request.input).unwrap());
    let snapshot = control.store().snapshot().unwrap();
    let session = snapshot.sessions[&session_id].clone();
    let definition = ActionDefinitionRegistry::restore(&snapshot.registry_bytes)
        .unwrap()
        .resolve(&request.action_ref, &request.definition_digest, now)
        .unwrap();
    let decision = ActionAdmission::admit(
        &session,
        &definition,
        &request.input,
        now,
        &QualificationCoverage::diagnostic(),
    )
    .unwrap();
    let custody = DeviceCustody::restore(&snapshot.devices).unwrap();
    let permit = NetworkEnforcement::issue_action_permit(
        &snapshot.authority_fingerprint,
        snapshot.authority_epoch,
        &snapshot.installation_id,
        &snapshot.release_manifest_digest,
        &session,
        &request,
        &definition,
        &decision,
        &input_digest,
        &custody,
        now,
    )
    .unwrap();
    assert_eq!(
        OperationSettlement::begin(
            control.store(),
            &permit,
            &request,
            &definition,
            &decision,
            &input_digest,
            process,
            permit.expiry,
        )
        .unwrap_err()
        .code,
        "authorization_expired"
    );

    let permit = NetworkEnforcement::issue_action_permit(
        &snapshot.authority_fingerprint,
        snapshot.authority_epoch,
        &snapshot.installation_id,
        &snapshot.release_manifest_digest,
        &session,
        &request,
        &definition,
        &decision,
        &input_digest,
        &custody,
        now,
    )
    .unwrap();
    let operation = OperationSettlement::begin(
        control.store(),
        &permit,
        &request,
        &definition,
        &decision,
        &input_digest,
        process,
        now,
    )
    .unwrap();
    let facts = DiagnosticFacts {
        challenge: "settlement".into(),
        journal_health: "ready".into(),
    };
    let first = OperationSettlement::settle(
        control.store(),
        &operation.operation_id,
        OperationStatus::Success,
        Some(facts.clone()),
        None,
        now,
    )
    .unwrap();
    let identical = OperationSettlement::settle(
        control.store(),
        &operation.operation_id,
        OperationStatus::Success,
        Some(facts),
        None,
        now.saturating_add(1),
    )
    .unwrap();
    assert_eq!(first.1.canonical_bytes, identical.1.canonical_bytes);
    assert_eq!(
        OperationSettlement::settle(
            control.store(),
            &operation.operation_id,
            OperationStatus::ExecutionFailure,
            None,
            Some("runner_failed"),
            now,
        )
        .unwrap_err()
        .code,
        "duplicate_settlement_conflict"
    );
    assert_eq!(ReceiptProjection::list(control.store()).unwrap().len(), 2);
}

#[test]
fn protected_tip_rollback_is_refused() {
    let (directory, control) = authority("rollback");
    let root = directory.path().join("authority");
    let old_tip = std::fs::read(root.join("protected-tip.json")).unwrap();
    let (session_id, process) = active_session(&control, "rollback");
    AuthorityKernel::new(control.store().clone())
        .submit(
            &session_id,
            process,
            request("rollback-operation", "rollback"),
        )
        .unwrap();
    drop(control);
    std::fs::write(root.join("protected-tip.json"), old_tip).unwrap();
    assert_eq!(
        AuthorityControl::restore(&root).err().unwrap().code,
        "continuity_unavailable"
    );
}

#[test]
fn running_operation_recovers_to_effect_unknown_receipt() {
    let (directory, control) = authority("recovery");
    let (session_id, process) = active_session(&control, "recovery");
    let now = now_unix();
    let action = request("recovery-operation", "recovery");
    let input_digest = sha256(&serde_jcs::to_vec(&action.input).unwrap());
    let snapshot = control.store().snapshot().unwrap();
    let session = snapshot.sessions[&session_id].clone();
    let definition = ActionDefinitionRegistry::restore(&snapshot.registry_bytes)
        .unwrap()
        .resolve(&action.action_ref, &action.definition_digest, now)
        .unwrap();
    let decision = ActionAdmission::admit(
        &session,
        &definition,
        &action.input,
        now,
        &QualificationCoverage::diagnostic(),
    )
    .unwrap();
    let custody = DeviceCustody::restore(&snapshot.devices).unwrap();
    let permit = NetworkEnforcement::issue_action_permit(
        &snapshot.authority_fingerprint,
        snapshot.authority_epoch,
        &snapshot.installation_id,
        &snapshot.release_manifest_digest,
        &session,
        &action,
        &definition,
        &decision,
        &input_digest,
        &custody,
        now,
    )
    .unwrap();
    let operation = OperationSettlement::begin(
        control.store(),
        &permit,
        &action,
        &definition,
        &decision,
        &input_digest,
        process,
        now,
    )
    .unwrap();
    let root = directory.path().join("authority");
    drop(control);
    let restored = AuthorityControl::restore(&root).unwrap();
    let recovered =
        restored.store().snapshot().unwrap().operations[&operation.operation_id].clone();
    assert_eq!(recovered.status, OperationStatus::EffectUnknown);
    assert_eq!(recovered.failure_code.as_deref(), Some("effect_unknown"));
    let receipt_id = recovered.receipt_id.unwrap();
    ReceiptProjection::verify(restored.store(), &receipt_id).unwrap();
}

struct FailedJournal;
impl JournalHealth for FailedJournal {
    fn health(&self) -> Result<&'static str, ember_authority::model::Refusal> {
        Err(ember_authority::model::Refusal::new("journal_unavailable"))
    }
}

#[test]
fn runner_failure_settles_a_failure_receipt() {
    let (_root, control) = authority("runner-failure");
    let (session_id, process) = active_session(&control, "runner-failure");
    let error = AuthorityKernel::new(control.store().clone())
        .submit_with_journal_at(
            &session_id,
            process,
            request("runner-failure", "runner-failure"),
            now_unix(),
            &FailedJournal,
        )
        .unwrap_err();
    assert_eq!(error.code, "runner_failed");
    let receipts = ReceiptProjection::list(control.store()).unwrap();
    assert_eq!(receipts.len(), 2);
    let failed = receipts
        .iter()
        .find(|row| row.terminal_status == OperationStatus::ExecutionFailure)
        .unwrap();
    ReceiptProjection::verify(control.store(), &failed.receipt_id).unwrap();
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pad {
    pad: String,
}

#[test]
fn canonical_and_frame_limits_accept_exact_and_refuse_plus_one() {
    const INPUT_LIMIT: usize = 1_048_576;
    let overhead = serde_jcs::to_vec(&Pad { pad: String::new() })
        .unwrap()
        .len();
    let exact = serde_jcs::to_vec(&Pad {
        pad: "x".repeat(INPUT_LIMIT - overhead),
    })
    .unwrap();
    assert_eq!(exact.len(), INPUT_LIMIT);
    decode_canonical::<Pad>(&exact, INPUT_LIMIT, "invalid").unwrap();
    let plus_one = serde_jcs::to_vec(&Pad {
        pad: "x".repeat(INPUT_LIMIT + 1 - overhead),
    })
    .unwrap();
    assert_eq!(
        decode_canonical::<Pad>(&plus_one, INPUT_LIMIT, "invalid")
            .unwrap_err()
            .code,
        "input_too_large"
    );
    let mut framed = Vec::new();
    framed.extend_from_slice(&((FRAME_LIMIT + 1) as u32).to_be_bytes());
    assert_eq!(
        read_frame::<Pad>(&mut Cursor::new(framed))
            .unwrap_err()
            .code,
        "frame_too_large"
    );
    assert_eq!(
        decode_canonical::<serde_json::Value>(br#"{"a":1,"a":2}"#, 64, "invalid")
            .unwrap_err()
            .code,
        "invalid"
    );
}
