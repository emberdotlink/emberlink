mod support;

use core_crypto::Signer as _;
use ember_authority::{
    action_admission::ActionAdmission,
    action_definition::ActionDefinitionRegistry,
    audit::{decode_canonical, now_unix, sha256},
    canonical::encode_action_permit,
    control::AuthorityControl,
    device::DeviceCustody,
    identity,
    initialization::ArtifactSource,
    ipc::{CONTROL_FRAME_LIMIT, FRAME_LIMIT, read_control_frame, read_frame},
    kernel::AuthorityKernel,
    model::{
        ACTION_REQUEST_SCHEMA, ActionPermit, ActionRef, ActionRequest, DiagnosticFacts,
        DiagnosticInput, OperationStatus, QualificationCoverage,
    },
    network_enforcement::NetworkEnforcement,
    operation::OperationSettlement,
    receipt::ReceiptProjection,
    runner::{JournalHealth, RawResultFrame},
    runtime_presence::AuthenticatedProcess,
};
use serde::{Deserialize, Serialize};
use std::{io::Cursor, os::unix::net::UnixStream};

use support::{
    DEFINITION_DIGEST, PUBLISHER_NOT_AFTER, anchor, authority, launch_context,
    request as initialization_request,
};

fn active_session(control: &AuthorityControl, challenge: &str) -> (String, AuthenticatedProcess) {
    let (peer, _other) = UnixStream::pair().unwrap();
    let process =
        ember_authority::runtime_presence::ExecutionBindingAuthority::authenticate_fd(&peer)
            .unwrap();
    let launch = control
        .open_diagnostic_session(
            challenge,
            process.uid,
            &launch_context(),
            "test-session.sock".into(),
        )
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

fn request(submission_label: &str, challenge: &str) -> ActionRequest {
    ActionRequest {
        schema: ACTION_REQUEST_SCHEMA.into(),
        submission_id: deterministic_uuid(submission_label),
        action_ref: ActionRef::diagnostic(),
        definition_digest: Some(DEFINITION_DIGEST.into()),
        input: DiagnosticInput {
            challenge: challenge.into(),
        },
    }
}

fn deterministic_uuid(label: &str) -> String {
    let digest = ember_authority::audit::sha256(label.as_bytes());
    uuid::Uuid::from_bytes(
        hex::decode(&digest["sha256:".len()..]).unwrap()[..16]
            .try_into()
            .unwrap(),
    )
    .to_string()
}

fn resign_permit(permit: &mut ActionPermit, custody: &DeviceCustody) {
    permit.signature.clear();
    let mut preimage = b"ember/action-permit-signature-input/v1\0".to_vec();
    preimage.extend_from_slice(&encode_action_permit(permit, false).unwrap());
    permit.signature = custody.action_permit_signer().unwrap().sign(&preimage).0;
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
    let expired_at = expired.activation_plan.maintenance_window_expiry;
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
    let directory = tempfile::tempdir().unwrap();
    let mut collision = initialization_request(directory.path(), "initialization");
    let mut conflicting = collision.records.action_definitions[0].clone();
    conflicting.signed_bundle.push(' ');
    collision.records.action_definitions.push(conflicting);
    assert_eq!(
        AuthorityControl::initialize_at(
            &directory.path().join("authority"),
            collision,
            &anchor(),
            now_unix(),
        )
        .err()
        .unwrap()
        .code,
        "identity_collision"
    );
}
#[test]
fn failed_initialization_leaves_no_restorable_partial_authority() {
    let directory = tempfile::tempdir().unwrap();
    let oversized_name = "a".repeat(240);
    let malformed_root = directory.path().join(&oversized_name);
    let request = initialization_request(directory.path(), "atomic-initialization");
    assert!(
        AuthorityControl::initialize_at(&malformed_root, request, &anchor(), now_unix()).is_err()
    );
    assert!(!malformed_root.exists());
    assert!(
        !directory
            .path()
            .join(format!("{oversized_name}.high-water.json"))
            .exists()
    );
    assert!(AuthorityControl::restore(&malformed_root).is_err());

    let retry_root = directory.path().join("authority");
    let request = initialization_request(directory.path(), "atomic-initialization-retry");
    AuthorityControl::initialize_at(&retry_root, request, &anchor(), now_unix()).unwrap();
    AuthorityControl::restore(&retry_root).unwrap();
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
                &launch_context(),
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

    let mut missing_digest = request("missing-digest", "allowed");
    missing_digest.definition_digest = None;
    assert_eq!(
        kernel
            .submit(&session_id, process, missing_digest)
            .unwrap_err()
            .code,
        "definition_digest_required"
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
    altered.definition_digest = Some(format!("sha256:{}", "0".repeat(64)));
    assert_eq!(
        kernel
            .submit(&session_id, process, altered)
            .unwrap_err()
            .code,
        "definition_digest_mismatch"
    );

    let snapshot = control.store().snapshot().unwrap();
    let inactive = ActionDefinitionRegistry::restore(&snapshot.registry_bytes).unwrap();
    assert_eq!(
        inactive
            .resolve(
                &ActionRef::diagnostic(),
                DEFINITION_DIGEST,
                PUBLISHER_NOT_AFTER,
            )
            .unwrap_err()
            .code,
        "publisher_not_trusted"
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
    conflict.definition_digest = Some(DEFINITION_DIGEST.into());
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
        .resolve(
            &request.action_ref,
            request.required_definition_digest().unwrap(),
            now,
        )
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

fn mutate_registry(control: &AuthorityControl, mutate: impl FnOnce(&mut serde_json::Value)) {
    control
        .store()
        .transaction(|state| {
            let mut registry: serde_json::Value =
                serde_json::from_str(&state.registry_bytes).unwrap();
            mutate(&mut registry);
            state.registry_bytes = serde_jcs::to_string(&registry).unwrap();
            Ok(())
        })
        .unwrap();
}

#[test]
fn inactive_publisher_and_definition_refuse_before_begin() {
    for field in ["publisher_active", "definition_active"] {
        let (_root, control) = authority(field);
        let (session_id, process) = active_session(&control, field);
        mutate_registry(&control, |registry| registry[field] = false.into());
        let before = control.store().snapshot().unwrap().sequence;
        let error = AuthorityKernel::new(control.store().clone())
            .submit(&session_id, process, request(field, field))
            .unwrap_err();
        assert_eq!(error.code, "definition_inactive");
        let snapshot = control.store().snapshot().unwrap();
        assert_eq!(snapshot.sequence, before);
        assert!(snapshot.operations.is_empty());
        assert_eq!(snapshot.receipts.len(), 1);
    }
}

#[test]
fn changed_signed_definition_byte_is_an_invalid_signature() {
    let (_root, control) = authority("changed-definition-byte");
    let (session_id, process) = active_session(&control, "changed-definition-byte");
    mutate_registry(&control, |registry| {
        let mut envelope: serde_json::Value =
            serde_json::from_str(registry["signed_bundle"].as_str().unwrap()).unwrap();
        envelope["bundle"]["definitions"][0]["action_key"] = "altered".into();
        registry["signed_bundle"] = serde_jcs::to_string(&envelope).unwrap().into();
    });
    let before = control.store().snapshot().unwrap().sequence;
    let error = AuthorityKernel::new(control.store().clone())
        .submit(
            &session_id,
            process,
            request("changed-definition-byte", "changed-definition-byte"),
        )
        .unwrap_err();
    assert_eq!(error.code, "invalid_signature");
    let snapshot = control.store().snapshot().unwrap();
    assert_eq!(snapshot.sequence, before);
    assert!(snapshot.operations.is_empty());
    assert_eq!(snapshot.receipts.len(), 1);
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
        "state_rollback_detected"
    );
}
#[test]
fn missing_high_water_anchor_is_refused() {
    let (directory, control) = authority("missing-high-water");
    let root = directory.path().join("authority");
    drop(control);
    std::fs::remove_file(directory.path().join("authority.high-water.json")).unwrap();
    assert_eq!(
        AuthorityControl::restore(&root).err().unwrap().code,
        "state_rollback_detected"
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
        .resolve(
            &action.action_ref,
            action.required_definition_digest().unwrap(),
            now,
        )
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
struct InvalidResultJournal {
    two_frames: bool,
}

impl JournalHealth for InvalidResultJournal {
    fn health(&self) -> Result<&'static str, ember_authority::model::Refusal> {
        Ok("ready")
    }

    fn raw_result_frames(&self, facts: DiagnosticFacts) -> Vec<RawResultFrame> {
        let frame = RawResultFrame {
            payload_schema_identifier: "wrong.schema".into(),
            payload_schema_version: "v1".into(),
            payload_semantics: "diagnostic-facts".into(),
            payload: facts,
        };
        if self.two_frames {
            vec![frame.clone(), frame]
        } else {
            vec![frame]
        }
    }
}

#[test]
fn unsupported_runner_results_settle_one_failure_without_payload() {
    for (name, two_frames) in [("wrong-tuple", false), ("two-frames", true)] {
        let (_root, control) = authority(name);
        let (session_id, process) = active_session(&control, name);
        let before = control.store().snapshot().unwrap().sequence;
        let error = AuthorityKernel::new(control.store().clone())
            .submit_with_journal_at(
                &session_id,
                process,
                request(name, name),
                now_unix(),
                &InvalidResultJournal { two_frames },
            )
            .unwrap_err();
        assert_eq!(error.code, "runner_failed");
        let snapshot = control.store().snapshot().unwrap();
        assert_eq!(snapshot.sequence, before + 1);
        let operation = snapshot.operations.values().next().unwrap();
        assert_eq!(operation.status, OperationStatus::ExecutionFailure);
        assert!(operation.facts.is_none());
        let receipt_id = operation.receipt_id.as_ref().unwrap();
        assert_eq!(snapshot.receipts.len(), 2);
        ReceiptProjection::verify(control.store(), receipt_id).unwrap();
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
#[test]
fn signed_permit_rejects_every_changed_authority_axis() {
    let (_root, control) = authority("permit-axes");
    let (session_id, _) = active_session(&control, "permit-axes");
    let now = now_unix();
    let request = request("permit-axes", "permit-axes");
    let input_digest = sha256(&serde_jcs::to_vec(&request.input).unwrap());
    let snapshot = control.store().snapshot().unwrap();
    let session = snapshot.sessions[&session_id].clone();
    let definition = ActionDefinitionRegistry::restore(&snapshot.registry_bytes)
        .unwrap()
        .resolve(
            &request.action_ref,
            request.required_definition_digest().unwrap(),
            now,
        )
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
    let mutations: &[fn(&mut ActionPermit)] = &[
        |value| value.authority_fingerprint = sha256(b"other-authority"),
        |value| value.authority_epoch += 1,
        |value| value.installation_id = "other-installation".into(),
        |value| value.release_manifest_digest = None,
        |value| value.session_id = "other-session".into(),
        |value| value.execution_binding_digest = sha256(b"other-binding"),
        |value| value.assurance_profile_id = "other-profile".into(),
        |value| value.assurance_profile_digest = sha256(b"other-profile"),
        |value| value.qualification_coverage_digest = sha256(b"other-coverage"),
        |value| value.action_definition_id = "other-definition".into(),
        |value| value.action_definition_version = "altered".into(),
        |value| value.action_definition_digest = sha256(b"other-definition"),
        |value| value.canonical_typed_input_digest = sha256(b"other-input"),
        |value| value.need_item_id_list.clear(),
        |value| value.grant_use_id_and_ceiling_list.clear(),
        |value| value.credential_slot = Some("forbidden".into()),
        |value| value.execution_lane = "proxy".into(),
        |value| value.target = "other-target".into(),
        |value| value.protocol = "other-protocol".into(),
        |value| value.destination = "other-destination".into(),
        |value| value.operation_class = "other-operation".into(),
        |value| value.request_count_ceiling += 1,
        |value| value.byte_budget += 1,
        |value| value.rate_ceiling += 1,
        |value| value.remaining_use_ceiling += 1,
        |value| value.offline_bound = false,
        |value| value.consequence_class = "other-consequence".into(),
        |value| value.capability = "other-capability".into(),
        |value| value.operation_id = None,
        |value| value.nonce.clear(),
        |value| value.issuance += 1,
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut altered = permit.clone();
        mutate(&mut altered);
        resign_permit(&mut altered, &custody);
        let result = NetworkEnforcement::verify_action_permit(
            &altered,
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
        );
        let expected = if index == 1 {
            "stale_authority_epoch"
        } else {
            "authorization_invalid"
        };
        assert_eq!(
            result.err().map(|error| error.code),
            Some(expected),
            "mutation {index} was accepted"
        );
    }
}

#[test]
fn restore_refuses_owner_committed_altered_receipt_bytes() {
    let (root, control) = authority("altered-receipt");
    let receipt_id = control
        .store()
        .snapshot()
        .unwrap()
        .initialization
        .receipt_id
        .unwrap();
    control
        .store()
        .transaction(|state| {
            state
                .receipts
                .get_mut(&receipt_id)
                .unwrap()
                .canonical_bytes
                .push(' ');
            Ok(())
        })
        .unwrap();
    drop(control);
    assert_eq!(
        AuthorityControl::restore(root.path().join("authority").as_path())
            .err()
            .unwrap()
            .code,
        "receipt_invalid"
    );
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
    let mut oversized_control = Vec::new();
    oversized_control.extend_from_slice(&((CONTROL_FRAME_LIMIT + 1) as u32).to_be_bytes());
    assert_eq!(
        read_control_frame::<Pad>(&mut Cursor::new(oversized_control))
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
    let too_deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    assert_eq!(
        decode_canonical::<serde_json::Value>(too_deep.as_bytes(), INPUT_LIMIT, "invalid",)
            .unwrap_err()
            .code,
        "input_too_large"
    );
    let too_many_items = format!(
        "[{}]",
        std::iter::repeat_n("0", 65_536)
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(
        decode_canonical::<serde_json::Value>(too_many_items.as_bytes(), INPUT_LIMIT, "invalid",)
            .unwrap_err()
            .code,
        "input_too_large"
    );
    let too_many_members = format!(
        "{{{}}}",
        (0..257)
            .map(|index| format!("\"k{index}\":0"))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(
        decode_canonical::<serde_json::Value>(too_many_members.as_bytes(), INPUT_LIMIT, "invalid",)
            .unwrap_err()
            .code,
        "input_too_large"
    );
    let oversized_body = serde_jcs::to_vec(&serde_json::json!({
        "body": "x".repeat(INPUT_LIMIT),
    }))
    .unwrap();
    assert!(oversized_body.len() < 2_097_152);
    assert_eq!(
        decode_canonical::<serde_json::Value>(&oversized_body, 2_097_152, "invalid")
            .unwrap_err()
            .code,
        "input_too_large"
    );
}
