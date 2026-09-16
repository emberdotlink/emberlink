use std::{collections::BTreeMap, str::FromStr, time::Duration};

use ember_authority::{
    host_client::{
        SessionActionRequest, SessionErrorResponse, SessionResultResponse, SessionWireError,
    },
    model::{
        ACTION_REQUEST_SCHEMA, ActionBoundary, ActionRequest, AuditCommitment, DelegationId,
        GitRef, JournalSequence, Need, OPERATION_RESULT_SCHEMA, OperationId, OperationOutcome,
        OperationResult, PackRef, PermissionLevel, PersonaId, ProcessBindingId, RepositoryResource,
        RequestDigest, SessionId, SubmissionId, TerminalStatus,
    },
    pack::{GITHUB_PACK_ADDRESS, GITHUB_PACK_VERSION, GITHUB_PULL_REQUEST_CREATE_ACTION},
    principal::{
        AuthorityError, ExecutableDigest, GrantInstallation, GrantSelection, PersonaAuthority,
        PresenceOperation, PresenceVerifier, ProcessOrigin, ReconnectProof, SessionContext,
    },
};

const NOW: i64 = 1_800_000_000;
const ACTION: &str = "git.publish-ref/v1";
const OTHER_ACTION: &str = "github.create-pull-request/v1";

fn fixed_id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).unwrap()
}

fn fixture_result(submission_id: SubmissionId, request_digest: RequestDigest) -> OperationResult {
    OperationResult {
        schema: OPERATION_RESULT_SCHEMA.to_owned(),
        outcome: OperationOutcome::new(
            fixed_id::<OperationId>("00000000-0000-0000-0000-000000000001"),
            submission_id,
            request_digest,
            JournalSequence::new(1).unwrap(),
            None,
            ActionBoundary::CancelledBeforeEffect,
        ),
        persona_id: fixed_id::<PersonaId>("00000000-0000-0000-0000-000000000002"),
        session_id: fixed_id::<SessionId>("00000000-0000-0000-0000-000000000003"),
        process_binding_id: fixed_id::<ProcessBindingId>("00000000-0000-0000-0000-000000000004"),
        grant_id: None,
        delegation_path: Vec::new(),
        status: TerminalStatus::Refusal,
        action: None,
        approved_input: None,
        resource: None,
        need: None,
        provider: None,
        runner: None,
        facts: None,
        upstream_revoked: false,
        audit: AuditCommitment {
            first_hash: "a".repeat(64),
            last_hash: "b".repeat(64),
            fact_count: 1,
        },
        started_at_unix: 1_800_000_000,
        completed_at_unix: 1_800_000_001,
        message: "authority admission refused".to_owned(),
    }
}

fn fixture_digest(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    hex::encode(Sha256::digest(bytes))
}

#[derive(Default)]
struct Present;

impl PresenceVerifier for Present {
    fn verify_presence(&mut self, _operation: &PresenceOperation) -> bool {
        true
    }
}

fn pack() -> PackRef {
    PackRef {
        address: "github.com/emberdotlink/github".to_owned(),
        version: 1,
    }
}

fn repository() -> RepositoryResource {
    RepositoryResource::from_str("github:org/repo").unwrap()
}

fn permissions(names: &[(&str, PermissionLevel)]) -> BTreeMap<String, PermissionLevel> {
    names
        .iter()
        .map(|(name, level)| ((*name).to_owned(), *level))
        .collect()
}

fn need(names: &[(&str, PermissionLevel)]) -> Need {
    Need {
        provider: "github".to_owned(),
        repository: repository(),
        destination_ref: Some(GitRef::from_str("refs/heads/workstream/topic").unwrap()),
        permissions: permissions(names),
    }
}

fn grant(
    authority: &mut PersonaAuthority,
    present: &mut Present,
    persona: ember_authority::model::PersonaId,
    action: &str,
    allowed: &[(&str, PermissionLevel)],
    expires_at_unix: i64,
) -> ember_authority::model::GrantId {
    let installation = GrantInstallation::new(
        persona,
        pack(),
        action,
        "github",
        repository(),
        Some("refs/heads/workstream/".to_owned()),
        permissions(allowed),
        NOW - 1,
        expires_at_unix,
    )
    .unwrap();
    authority
        .management()
        .install_grant(present, installation)
        .unwrap()
}

fn bound_session(
    authority: &mut PersonaAuthority,
    present: &mut Present,
) -> (
    ember_authority::model::PersonaId,
    ember_authority::model::SessionId,
    ember_authority::model::ProcessBindingId,
    ProcessOrigin,
    SessionContext,
    ReconnectProof,
) {
    let persona = authority.management().install_persona(present).unwrap();
    let digest = ExecutableDigest::from_sha256([7; 32]);
    let (session, challenge) = authority.sessions().create(&persona, digest).unwrap();
    let origin = ProcessOrigin::new(42, 9, 501, 20, digest).unwrap();
    let binding = authority
        .sessions()
        .bind_origin(&session, &challenge, origin)
        .unwrap();
    let (context, proof) = authority
        .sessions()
        .connect(&session, &binding, &origin, None)
        .unwrap();
    (persona, session, binding, origin, context, proof.unwrap())
}

fn attach(
    authority: &mut PersonaAuthority,
    present: &mut Present,
    session: &ember_authority::model::SessionId,
    grant: ember_authority::model::GrantId,
) -> DelegationId {
    let delegation = DelegationId::new();
    authority
        .management()
        .attach_selected_grants(
            present,
            session,
            vec![(delegation.clone(), GrantSelection::whole(grant))],
            NOW,
            Duration::from_secs(300),
        )
        .unwrap();
    delegation
}

#[test]
fn registration_reconnect_and_proof_replay_are_process_bound() {
    let mut authority = PersonaAuthority::new();
    let mut present = Present;
    let (_, session, binding, origin, context, proof) = bound_session(&mut authority, &mut present);

    assert!(matches!(
        authority
            .sessions()
            .connect(&session, &binding, &origin, None),
        Err(AuthorityError::ReconnectProofRequired)
    ));
    assert!(matches!(
        authority.sessions().connect(
            &session,
            &binding,
            &origin,
            Some(&ReconnectProof::from_bytes([3; 32]))
        ),
        Err(AuthorityError::ReconnectProofMismatch)
    ));
    let (reconnected, replacement) = authority
        .sessions()
        .connect(&session, &binding, &origin, Some(&proof))
        .unwrap();
    assert_eq!(authority.execution().identify(&context).unwrap(), session);
    assert_eq!(
        authority.execution().identify(&reconnected).unwrap(),
        session
    );
    assert!(replacement.is_none());
}

#[test]
fn every_exact_process_coordinate_mismatch_terminates_the_session() {
    let variants = [
        ProcessOrigin::new(43, 9, 501, 20, ExecutableDigest::from_sha256([7; 32])).unwrap(),
        ProcessOrigin::new(42, 10, 501, 20, ExecutableDigest::from_sha256([7; 32])).unwrap(),
        ProcessOrigin::new(42, 9, 502, 20, ExecutableDigest::from_sha256([7; 32])).unwrap(),
        ProcessOrigin::new(42, 9, 501, 21, ExecutableDigest::from_sha256([7; 32])).unwrap(),
        ProcessOrigin::new(42, 9, 501, 20, ExecutableDigest::from_sha256([8; 32])).unwrap(),
    ];

    for mismatch in variants {
        let mut authority = PersonaAuthority::new();
        let mut present = Present;
        let (_, session, binding, _, context, proof) = bound_session(&mut authority, &mut present);
        assert!(matches!(
            authority
                .sessions()
                .connect(&session, &binding, &mismatch, Some(&proof)),
            Err(AuthorityError::OriginMismatch)
        ));
        assert_eq!(
            authority.execution().identify(&context),
            Err(AuthorityError::UnknownSession)
        );
    }
}

#[test]
fn reviewed_image_mismatch_consumes_registration_and_ends_session() {
    let mut authority = PersonaAuthority::new();
    let mut present = Present;
    let persona = authority
        .management()
        .install_persona(&mut present)
        .unwrap();
    let reviewed = ExecutableDigest::from_sha256([7; 32]);
    let (session, challenge) = authority.sessions().create(&persona, reviewed).unwrap();
    let mismatch =
        ProcessOrigin::new(42, 9, 501, 20, ExecutableDigest::from_sha256([8; 32])).unwrap();

    assert!(matches!(
        authority
            .sessions()
            .bind_origin(&session, &challenge, mismatch),
        Err(AuthorityError::ExecutableDigestMismatch)
    ));
    assert!(matches!(
        authority.sessions().end_session(&session),
        Err(AuthorityError::UnknownSession)
    ));
}

#[test]
fn admission_refuses_missing_ambiguous_and_overlapping_grants() {
    let mut authority = PersonaAuthority::new();
    let mut present = Present;
    let (persona, session, _, _, context, _) = bound_session(&mut authority, &mut present);
    let requested = need(&[
        ("contents", PermissionLevel::Write),
        ("metadata", PermissionLevel::Read),
    ]);

    assert!(matches!(
        authority
            .execution()
            .admit(&context, &pack(), ACTION, &requested, NOW),
        Err(AuthorityError::NoApplicableGrant)
    ));

    let contents = grant(
        &mut authority,
        &mut present,
        persona.clone(),
        ACTION,
        &[("contents", PermissionLevel::Write)],
        NOW + 600,
    );
    let metadata = grant(
        &mut authority,
        &mut present,
        persona.clone(),
        ACTION,
        &[("metadata", PermissionLevel::Read)],
        NOW + 600,
    );
    attach(&mut authority, &mut present, &session, contents);
    attach(&mut authority, &mut present, &session, metadata);
    assert!(matches!(
        authority
            .execution()
            .admit(&context, &pack(), ACTION, &requested, NOW),
        Err(AuthorityError::OverlappingGrant)
    ));

    let whole_a = grant(
        &mut authority,
        &mut present,
        persona.clone(),
        ACTION,
        &[
            ("contents", PermissionLevel::Write),
            ("metadata", PermissionLevel::Read),
        ],
        NOW + 600,
    );
    let whole_b = grant(
        &mut authority,
        &mut present,
        persona,
        ACTION,
        &[
            ("contents", PermissionLevel::Write),
            ("metadata", PermissionLevel::Read),
        ],
        NOW + 600,
    );
    attach(&mut authority, &mut present, &session, whole_a);
    attach(&mut authority, &mut present, &session, whole_b);
    assert!(matches!(
        authority
            .execution()
            .admit(&context, &pack(), ACTION, &requested, NOW),
        Err(AuthorityError::AmbiguousGrant)
    ));
}

#[test]
fn leaf_and_sibling_revocation_or_expiry_are_isolated() {
    let mut authority = PersonaAuthority::new();
    let mut present = Present;
    let (persona, session, _, _, context, _) = bound_session(&mut authority, &mut present);
    let first_grant = grant(
        &mut authority,
        &mut present,
        persona.clone(),
        ACTION,
        &[("contents", PermissionLevel::Write)],
        NOW + 600,
    );
    let second_grant = grant(
        &mut authority,
        &mut present,
        persona,
        OTHER_ACTION,
        &[("contents", PermissionLevel::Write)],
        NOW + 2,
    );
    let first_leaf = attach(&mut authority, &mut present, &session, first_grant);
    let second_leaf = attach(&mut authority, &mut present, &session, second_grant);
    let requested = need(&[("contents", PermissionLevel::Write)]);

    let first = authority
        .execution()
        .admit(&context, &pack(), ACTION, &requested, NOW)
        .unwrap();
    let second = authority
        .execution()
        .admit(&context, &pack(), OTHER_ACTION, &requested, NOW)
        .unwrap();
    assert_eq!(first.delegation_path, vec![first_leaf.clone()]);
    assert_eq!(second.delegation_path, vec![second_leaf]);

    authority
        .management()
        .revoke_delegation(&first_leaf)
        .unwrap();
    assert!(matches!(
        authority
            .execution()
            .admit(&context, &pack(), ACTION, &requested, NOW),
        Err(AuthorityError::NoApplicableDelegation)
    ));
    assert!(
        authority
            .execution()
            .admit(&context, &pack(), OTHER_ACTION, &requested, NOW)
            .is_ok()
    );
    assert!(matches!(
        authority
            .execution()
            .admit(&context, &pack(), OTHER_ACTION, &requested, NOW + 3),
        Err(AuthorityError::NoApplicableGrant)
    ));
}

#[test]
fn grant_revocation_blocks_new_admission_without_mutating_crossed_work() {
    let mut authority = PersonaAuthority::new();
    let mut present = Present;
    let (persona, session, _, _, context, _) = bound_session(&mut authority, &mut present);
    let grant = grant(
        &mut authority,
        &mut present,
        persona,
        ACTION,
        &[("contents", PermissionLevel::Write)],
        NOW + 600,
    );
    attach(&mut authority, &mut present, &session, grant.clone());
    let requested = need(&[("contents", PermissionLevel::Write)]);
    let crossed = authority
        .execution()
        .admit(&context, &pack(), ACTION, &requested, NOW)
        .unwrap();

    authority.management().revoke_grant(&grant).unwrap();
    assert_eq!(crossed.grant_id, grant);
    assert_eq!(crossed.delegation_path.len(), 1);
    assert!(matches!(
        authority
            .execution()
            .admit(&context, &pack(), ACTION, &requested, NOW),
        Err(AuthorityError::NoApplicableGrant)
    ));
}

#[test]
fn ending_process_removes_session_binding_and_all_leaf_delegations() {
    let mut authority = PersonaAuthority::new();
    let mut present = Present;
    let (persona, session, binding, _, context, _) = bound_session(&mut authority, &mut present);
    let grant = grant(
        &mut authority,
        &mut present,
        persona,
        ACTION,
        &[("contents", PermissionLevel::Write)],
        NOW + 600,
    );
    attach(&mut authority, &mut present, &session, grant);

    assert_eq!(authority.sessions().end_origin(&binding).unwrap(), session);
    assert!(matches!(
        authority.execution().identify(&context),
        Err(AuthorityError::UnknownSession)
    ));
}

#[test]
fn canonical_session_wire_fixtures_are_stable_and_decodable() {
    let submission_id = SubmissionId::from_bytes([0x11; 32]);
    let request = ActionRequest {
        schema: ACTION_REQUEST_SCHEMA.to_owned(),
        pack: PackRef {
            address: GITHUB_PACK_ADDRESS.to_owned(),
            version: GITHUB_PACK_VERSION,
        },
        action: GITHUB_PULL_REQUEST_CREATE_ACTION.to_owned(),
        input: serde_json::json!({
            "repository": "github:emberdotlink/ember",
            "head_ref": "refs/heads/ws/demo/builder-1",
            "base_ref": "refs/heads/main",
            "title": "wb: demo builder-1",
            "body": ""
        }),
        submission_id: Some(submission_id),
    };
    let action = SessionActionRequest::new(request.clone(), 0, Some([0x22; 32]));
    let action_bytes = serde_jcs::to_vec(&action).unwrap();
    let decoded_action: SessionActionRequest = serde_json::from_slice(&action_bytes).unwrap();
    assert_eq!(decoded_action.request(), &request);
    assert_eq!(decoded_action.artifact_length(), 0);
    assert_eq!(decoded_action.reconnect_proof(), Some(&[0x22; 32]));

    let canonical_request = serde_jcs::to_vec(&request).unwrap();
    let request_digest = RequestDigest::of(&canonical_request);
    let result = fixture_result(submission_id, request_digest);
    assert_eq!(result.outcome.submission_id(), submission_id);
    assert_eq!(request.submission_id, Some(result.outcome.submission_id()));
    assert_eq!(result.outcome.request_digest(), request_digest);
    let success = SessionResultResponse::new(result.clone(), Some([0x44; 32]));
    let success_bytes = serde_jcs::to_vec(&success).unwrap();
    let decoded_success: SessionResultResponse = serde_json::from_slice(&success_bytes).unwrap();
    assert_eq!(decoded_success.result(), &result);
    assert_eq!(decoded_success.reconnect_proof(), Some(&[0x44; 32]));

    let error = SessionWireError::new("authority_gap", "authority admission refused");
    let refusal = SessionErrorResponse::new(error.clone(), Some([0x55; 32]));
    let refusal_bytes = serde_jcs::to_vec(&refusal).unwrap();
    let decoded_refusal: SessionErrorResponse = serde_json::from_slice(&refusal_bytes).unwrap();
    assert_eq!(decoded_refusal.error(), &error);
    assert_eq!(decoded_refusal.reconnect_proof(), Some(&[0x55; 32]));

    let expected_action = r#"{"artifact_length":0,"reconnect_proof":[34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34],"request":{"action":"github.pull-request.create/v1","input":{"base_ref":"refs/heads/main","body":"","head_ref":"refs/heads/ws/demo/builder-1","repository":"github:emberdotlink/ember","title":"wb: demo builder-1"},"pack":{"address":"ember.pack/github","version":2},"schema":"ember.action-request/v1","submission_id":[17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17]},"schema":"ember.session-action-request/v1"}"#;
    let expected_success = r#"{"reconnect_proof":[68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68],"result":{"action":null,"approved_input":null,"audit":{"fact_count":1,"first_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","last_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"completed_at_unix":1800000001,"delegation_path":[],"facts":null,"grant_id":null,"message":"authority admission refused","need":null,"outcome":{"boundary":"cancelled-before-effect","materialization_id":null,"operation_id":"00000000-0000-0000-0000-000000000001","request_digest":[237,87,64,218,198,102,109,155,158,226,224,70,253,30,211,13,209,90,48,62,212,239,86,234,161,93,225,56,167,101,35,169],"sequence":1,"submission_id":[17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17]},"persona_id":"00000000-0000-0000-0000-000000000002","process_binding_id":"00000000-0000-0000-0000-000000000004","provider":null,"resource":null,"runner":null,"schema":"ember.operation-result/v1","session_id":"00000000-0000-0000-0000-000000000003","started_at_unix":1800000000,"status":"refusal","upstream_revoked":false},"schema":"ember.session-response/v1"}"#;
    let expected_refusal = r#"{"error":{"code":"authority_gap","message":"authority admission refused"},"reconnect_proof":[85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85],"schema":"ember.session-response/v1"}"#;

    assert_eq!(action_bytes.as_slice(), expected_action.as_bytes());
    assert_eq!(success_bytes.as_slice(), expected_success.as_bytes());
    assert_eq!(refusal_bytes.as_slice(), expected_refusal.as_bytes());
    assert_eq!(
        fixture_digest(&action_bytes),
        "44597acc3e4317b7a2200b1566ffaf821d964f8926f93a1f7be3f934bb387986"
    );
    assert_eq!(
        fixture_digest(&success_bytes),
        "60be0b28f96664439e36d2af9bb3ec15fde47a478374f38b5babdd9950cf746f"
    );
    assert_eq!(
        fixture_digest(&refusal_bytes),
        "6d00faee0083c5ce25e287d76ff06c7ba2af789b9e7c74764e6142d8f89c1405"
    );
}
