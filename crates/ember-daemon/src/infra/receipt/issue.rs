//! Receipt v2 issuance helper for cohort-A `session.claude_code` Receipts.
//!
//! Per ADR 118 §"Envelope" + ADR 120 §7. Builds a `ReceiptEnvelope` wrapping a
//! `ClaudeCodeBody` (claim_events + audit_gaps + permits_merkle_root) at session
//! termination. Signs the envelope in-place using the Daemon Persona key per
//! ADR 116 via `daemon_persona_sign_receipt`.
//!
//! Transitional note: this helper still takes a full `Vec<ClaimEvent>`.
//! `ClaimJournal` is now the canonical session/composite working set, and the
//! long-term receipt materializer must become segment-aware instead of
//! requiring one unbounded in-memory close-time claim vector.

use std::fs;
use std::path::Path;

use core_crypto::Signer;
use core_events::receipt::sign::{SignError, sign_receipt_v2};
use core_events::receipt::{
    AuditGap, ClaimEvent, ClaimSegmentDigest, ClaudeCodeBody, RECEIPT_KIND_CLAUDE_CODE,
    RECEIPT_KIND_HEADLESS_ENROLLMENT, RECEIPT_KIND_HEADLESS_REVOCATION,
    RECEIPT_KIND_SERVICE_INSTALLED_V1, RECEIPT_KIND_SERVICE_UNINSTALLED_V1, ReceiptBody,
    ReceiptEnvelope, ReceiptVersion, ServiceInstalledBody, ServiceUninstalledBody,
    TerminationAuthority, TerminationReason, claim_history_merkle_root, merkle_leaf, merkle_root,
};

use crate::infra::claim_journal::ClosedScopeSummary;
use crate::infra::identity_substrate::{
    PrincipalChainError, SigningAttribution, SigningPrincipalRecord, daemon_principal_record,
    validate_principal_parent_chain,
};

/// Errors raised by [`issue_cohort_a_receipt`].
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error("serialize Receipt body: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("read audit-gaps file at {path}: {source}")]
    AuditGapsRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("sign Receipt v2: {0}")]
    Sign(#[source] SignError),
    #[error("validate signing principal chain: {0}")]
    PrincipalChain(#[source] PrincipalChainError),
}

/// Optional termination metadata injected into the `ClaudeCodeBody` by the
/// dirty-exit path (COHORT-A-V03-HEARTBEAT-TERMINATION). Pass `None` for
/// clean-exit / TTL-expiry / explicit-revoke issuance paths where the reason
/// is not yet known at build time.
pub struct TerminationMeta {
    pub reason: TerminationReason,
    pub last_heartbeat_at: Option<String>,
    pub pid_alive_at_check: Option<bool>,
}

pub(crate) fn stamp_signer_attribution(
    body_value: &mut serde_json::Value,
    attribution: &SigningAttribution,
) {
    if let Some(map) = body_value.as_object_mut() {
        map.entry("principal_id".to_string())
            .or_insert_with(|| serde_json::Value::String(attribution.principal_id.clone()));
        map.entry("signing_device_id".to_string())
            .or_insert_with(|| serde_json::Value::String(attribution.signing_device_id.clone()));
    }
}

pub fn issue_atomic_receipt<T: serde::Serialize>(
    kind: &str,
    body: &T,
    termination_authority: TerminationAuthority,
    daemon_root_id: &str,
    signer: &dyn Signer,
) -> Result<ReceiptEnvelope, IssueError> {
    let principal = daemon_principal_record(daemon_root_id);
    issue_atomic_receipt_with_principal_chain(
        kind,
        body,
        termination_authority,
        daemon_root_id,
        std::slice::from_ref(&principal),
        &principal.principal_id,
        &principal.principal_id,
        signer,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn issue_atomic_receipt_with_principal_chain<T: serde::Serialize>(
    kind: &str,
    body: &T,
    termination_authority: TerminationAuthority,
    daemon_root_id: &str,
    principals: &[SigningPrincipalRecord],
    principal_id: &str,
    trust_anchor_id: &str,
    signer: &dyn Signer,
) -> Result<ReceiptEnvelope, IssueError> {
    validate_principal_parent_chain(principals, principal_id, trust_anchor_id)
        .map_err(IssueError::PrincipalChain)?;
    let principal = principals
        .iter()
        .find(|record| record.principal_id == principal_id)
        .ok_or_else(|| {
            IssueError::PrincipalChain(PrincipalChainError::MissingPrincipal {
                principal_id: principal_id.to_string(),
            })
        })?;
    let attribution = principal
        .signing_attribution()
        .map_err(IssueError::PrincipalChain)?;
    issue_atomic_receipt_with_attribution(
        kind,
        body,
        termination_authority,
        daemon_root_id,
        &attribution,
        signer,
    )
}

fn issue_atomic_receipt_with_attribution<T: serde::Serialize>(
    kind: &str,
    body: &T,
    termination_authority: TerminationAuthority,
    daemon_root_id: &str,
    attribution: &SigningAttribution,
    signer: &dyn Signer,
) -> Result<ReceiptEnvelope, IssueError> {
    let mut body_value = serde_json::to_value(body).map_err(IssueError::Serialize)?;
    stamp_signer_attribution(&mut body_value, attribution);
    let mut envelope = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: kind.into(),
        receipt_id: String::new(),
        daemon_root_id: daemon_root_id.into(),
        traceparent: None,
        termination_authority,
        presence_kind: None,
        body: body_value,
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    sign_receipt_v2(&mut envelope, signer).map_err(IssueError::Sign)?;
    Ok(envelope)
}

pub fn issue_service_installed_receipt(
    body: &ServiceInstalledBody,
    daemon_root_id: &str,
    signer: &dyn Signer,
) -> Result<ReceiptEnvelope, IssueError> {
    issue_atomic_receipt(
        RECEIPT_KIND_SERVICE_INSTALLED_V1,
        body,
        TerminationAuthority::UserSession,
        daemon_root_id,
        signer,
    )
}

pub fn issue_service_uninstalled_receipt(
    body: &ServiceUninstalledBody,
    daemon_root_id: &str,
    signer: &dyn Signer,
) -> Result<ReceiptEnvelope, IssueError> {
    issue_atomic_receipt(
        RECEIPT_KIND_SERVICE_UNINSTALLED_V1,
        body,
        TerminationAuthority::UserSession,
        daemon_root_id,
        signer,
    )
}

pub fn issue_headless_enrollment_receipt(
    body: &core_events::receipt::HeadlessEnrollmentBody,
    daemon_root_id: &str,
    signer: &dyn Signer,
) -> Result<ReceiptEnvelope, IssueError> {
    issue_atomic_receipt(
        RECEIPT_KIND_HEADLESS_ENROLLMENT,
        body,
        TerminationAuthority::UserSession,
        daemon_root_id,
        signer,
    )
}

pub fn issue_headless_revocation_receipt(
    body: &core_events::receipt::HeadlessRevocationBody,
    daemon_root_id: &str,
    signer: &dyn Signer,
) -> Result<ReceiptEnvelope, IssueError> {
    issue_atomic_receipt(
        RECEIPT_KIND_HEADLESS_REVOCATION,
        body,
        TerminationAuthority::UserSession,
        daemon_root_id,
        signer,
    )
}

fn claim_segment_digests_from_summary(summary: &ClosedScopeSummary) -> Vec<ClaimSegmentDigest> {
    summary
        .segments
        .iter()
        .map(|segment| ClaimSegmentDigest {
            segment_no: segment.segment_no as u64,
            first_scope_seq: segment.first_scope_seq as u64,
            last_scope_seq: segment.last_scope_seq as u64,
            claim_count: segment.claim_count as u64,
            started_at: segment.started_at.clone(),
            ended_at: segment.ended_at.clone(),
            merkle_root: segment.merkle_root.clone(),
        })
        .collect()
}

/// Build and sign a cohort-A `session.claude_code` Receipt envelope.
///
/// Steps per ADR 118 §"Envelope" + ADR 116 §"Daemon Persona signing":
/// 1. Build [`ClaudeCodeBody`] from `claim_events` + parsed `audit_gaps.jsonl`
///    (lines parsed individually, malformed lines skipped — fail-open shape
///    matches COHORT-A-9's writer). Optional `termination_meta` injects the
///    reason/heartbeat/pid fields into the body in the same step.
/// 2. Compute `permits_merkle_root` over `claim_events[].input_hash` blake3
///    leaves (ADR 118 §"Merkle leaf format" — leaf form simplified for now;
///    proper canonical leaf payload is a follow-up).
/// 3. Construct [`ReceiptEnvelope`] with `version="2"`, `kind="session.claude_code"`,
///    `daemon_root_id`, `termination_authority`, body=JSON.
/// 4. Sign + stamp `receipt_id` via `sign_receipt_v2` — the single canonical
///    path (JCS-canonical bytes of envelope with receipt_id, without signature,
///    Ed25519-signed by the Daemon Persona key per ADR 116). Signing routes
///    through [`daemon_persona_sign_receipt`] as the named ADR 116 primitive.
///
/// `audit_gaps_path = None` (or a non-existent file) → `audit_gaps = []` —
/// the daemon was reachable for the entire session.
pub fn issue_cohort_a_receipt(
    _session_id: &str,
    claim_events: Vec<ClaimEvent>,
    audit_gaps_path: Option<&Path>,
    termination_authority: TerminationAuthority,
    daemon_root_id: &str,
    termination_meta: Option<TerminationMeta>,
    signer: &dyn Signer,
) -> Result<ReceiptEnvelope, IssueError> {
    issue_session_receipt(
        RECEIPT_KIND_CLAUDE_CODE,
        _session_id,
        claim_events,
        audit_gaps_path,
        termination_authority,
        daemon_root_id,
        termination_meta,
        signer,
    )
}

// RPC/plumbing signature — receipt-issuing params are structurally many; refactor is out of scope for the lint-clear.
#[allow(clippy::too_many_arguments)]
pub fn issue_session_receipt(
    kind: &str,
    _session_id: &str,
    claim_events: Vec<ClaimEvent>,
    audit_gaps_path: Option<&Path>,
    termination_authority: TerminationAuthority,
    daemon_root_id: &str,
    termination_meta: Option<TerminationMeta>,
    signer: &dyn Signer,
) -> Result<ReceiptEnvelope, IssueError> {
    issue_session_receipt_with_body(
        kind,
        claim_events,
        None,
        audit_gaps_path,
        termination_authority,
        daemon_root_id,
        termination_meta,
        signer,
    )
}

pub fn issue_cohort_a_receipt_from_closed_scope(
    _session_id: &str,
    scope_summary: &ClosedScopeSummary,
    audit_gaps_path: Option<&Path>,
    termination_authority: TerminationAuthority,
    daemon_root_id: &str,
    termination_meta: Option<TerminationMeta>,
    signer: &dyn Signer,
) -> Result<ReceiptEnvelope, IssueError> {
    let segment_digests = claim_segment_digests_from_summary(scope_summary);
    let claim_history_root = claim_history_merkle_root(&segment_digests);
    let body = ReceiptBody {
        claim_events: scope_summary.recent_claims.clone(),
        claim_count_total: Some(scope_summary.total_claims as u64),
        claim_events_truncated: scope_summary.recent_claims_truncated,
        claim_segment_summaries: segment_digests,
        claim_history_merkle_root: claim_history_root,
        device_id: None,
        ..Default::default()
    };
    issue_session_receipt_with_body(
        RECEIPT_KIND_CLAUDE_CODE,
        body.claim_events.clone(),
        Some(body),
        audit_gaps_path,
        termination_authority,
        daemon_root_id,
        termination_meta,
        signer,
    )
}

// RPC/plumbing signature — receipt-issuing params are structurally many; refactor is out of scope for the lint-clear.
#[allow(clippy::too_many_arguments)]
pub fn issue_session_receipt_from_closed_scope(
    kind: &str,
    _session_id: &str,
    scope_summary: &ClosedScopeSummary,
    audit_gaps_path: Option<&Path>,
    termination_authority: TerminationAuthority,
    daemon_root_id: &str,
    termination_meta: Option<TerminationMeta>,
    signer: &dyn Signer,
) -> Result<ReceiptEnvelope, IssueError> {
    let segment_digests = claim_segment_digests_from_summary(scope_summary);
    let claim_history_root = claim_history_merkle_root(&segment_digests);
    let body = ReceiptBody {
        claim_events: scope_summary.recent_claims.clone(),
        claim_count_total: Some(scope_summary.total_claims as u64),
        claim_events_truncated: scope_summary.recent_claims_truncated,
        claim_segment_summaries: segment_digests,
        claim_history_merkle_root: claim_history_root,
        device_id: None,
        ..Default::default()
    };
    issue_session_receipt_with_body(
        kind,
        body.claim_events.clone(),
        Some(body),
        audit_gaps_path,
        termination_authority,
        daemon_root_id,
        termination_meta,
        signer,
    )
}

// RPC/plumbing signature — receipt-issuing params are structurally many; refactor is out of scope for the lint-clear.
#[allow(clippy::too_many_arguments)]
fn issue_session_receipt_with_body(
    kind: &str,
    claim_events: Vec<ClaimEvent>,
    base_body_override: Option<ReceiptBody>,
    audit_gaps_path: Option<&Path>,
    termination_authority: TerminationAuthority,
    daemon_root_id: &str,
    termination_meta: Option<TerminationMeta>,
    signer: &dyn Signer,
) -> Result<ReceiptEnvelope, IssueError> {
    // 1. Parse audit gaps (fail-open: skip malformed lines, treat missing
    //    file as "no gaps recorded").
    let audit_gaps = match audit_gaps_path {
        Some(path) if path.exists() => parse_audit_gaps(path)?,
        _ => Vec::new(),
    };

    // 2. Compute Merkle root over claim_events[].input_hash leaves.
    //    Empty claim_events → all-zeros merkle root path (per
    //    `merkle::merkle_root` empty-input contract). We still emit a hex
    //    string for the field so envelope shape stays uniform; an empty
    //    body simply has the zero-root encoded.
    let leaves: Vec<[u8; 32]> = claim_events
        .iter()
        .map(|ce| merkle_leaf(ce.input_hash.as_bytes()))
        .collect();
    let permits_merkle_root = if claim_events.is_empty() {
        // Empty body: leave the field empty so it's omitted from wire form
        // (matches the `skip_serializing_if = "String::is_empty"` on
        // `ReceiptBody.permits_merkle_root`).
        String::new()
    } else {
        hex_lower(&merkle_root(&leaves))
    };

    // 3. Build the body including optional termination metadata so the
    //    signed envelope captures the full body in one atomic step.
    let (termination_reason, last_heartbeat_at, pid_alive_at_check) = match termination_meta {
        Some(m) => (Some(m.reason), m.last_heartbeat_at, m.pid_alive_at_check),
        None => (None, None, None),
    };
    let mut base = base_body_override.unwrap_or_default();
    base.claim_events = claim_events;
    base.permits_merkle_root = permits_merkle_root;
    let body = ClaudeCodeBody {
        base,
        audit_gaps,
        termination_reason,
        last_heartbeat_at,
        pid_alive_at_check,
    };

    // 4/5. Sign through the canonical atomic builder so the session lane and
    // future atomic lanes share one envelope-construction path.
    issue_atomic_receipt(kind, &body, termination_authority, daemon_root_id, signer)
}

/// Parse `~/.ember/sessions/<id>/audit-gaps.jsonl` line-by-line, skipping
/// malformed lines (matches the fail-open posture of COHORT-A-9's writer).
fn parse_audit_gaps(path: &Path) -> Result<Vec<AuditGap>, IssueError> {
    let raw = fs::read_to_string(path).map_err(|source| IssueError::AuditGapsRead {
        path: path.display().to_string(),
        source,
    })?;
    let mut gaps = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(gap) = serde_json::from_str::<AuditGap>(trimmed) {
            gaps.push(gap);
        }
        // Malformed line: silently skipped. The fail-open posture of the
        // writer means a partially-corrupt file shouldn't lose every gap;
        // we recover whatever lines parse cleanly.
    }
    Ok(gaps)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::claim_journal::{
        ClaimScopeKind, ClaimSegmentSummary, ClosedScopeSummary, ScopeRef,
    };
    use crate::infra::identity_substrate::SigningPrincipalRecord;
    use core_crypto::{FixtureSigner, FixtureVerifier};
    use core_events::receipt::body::{ClaimEvent, ClaimKind};
    use core_events::receipt::sign::{compute_receipt_id, verify_receipt_v2};
    use core_events::receipt::{ServiceInstalledBody, ServiceUninstalledBody};
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    fn sample_claim_event(input_hash: &str) -> ClaimEvent {
        ClaimEvent {
            ts: "2026-05-01T12:00:00Z".into(),
            kind: ClaimKind::Approval,
            tool: "Bash".into(),
            action_ref: None,
            input_hash: input_hash.into(),
            input_redacted: serde_json::json!({"command": "echo hi"}),
            resolved: serde_json::json!({"allowed": true}),
        }
    }

    fn fixture_signer() -> FixtureSigner {
        FixtureSigner::new("issue-rs-fixture")
    }

    fn sample_closed_scope_summary() -> ClosedScopeSummary {
        ClosedScopeSummary {
            scope: ScopeRef {
                kind: ClaimScopeKind::AuthorityLane,
                id: "sess-closed-summary".to_string(),
            },
            total_claims: 9,
            segments: vec![ClaimSegmentSummary {
                segment_no: 0,
                first_scope_seq: 1,
                last_scope_seq: 8,
                claim_count: 8,
                started_at: "2026-05-22T12:00:00Z".to_string(),
                ended_at: "2026-05-22T12:05:00Z".to_string(),
                merkle_root: "deadbeef".to_string(),
            }],
            recent_claims: vec![sample_claim_event("tail-hash")],
            recent_claims_truncated: true,
        }
    }

    #[test]
    fn empty_claim_events_omits_merkle_root() {
        let signer = fixture_signer();
        let pk = signer.public_key();
        let env = issue_cohort_a_receipt(
            "sess-1",
            vec![],
            None,
            TerminationAuthority::UserSession,
            "daemon-root-1",
            None,
            &signer,
        )
        .unwrap();
        assert_eq!(env.kind, RECEIPT_KIND_CLAUDE_CODE);
        assert_eq!(env.daemon_root_id, "daemon-root-1");
        assert_eq!(env.version.0, "2");
        // Envelope is now signed — signature must be present and verifiable.
        assert!(env.signature.is_some(), "issue must populate signature");
        verify_receipt_v2(&env, &pk, &FixtureVerifier).unwrap();
        // receipt_id is plain lowercase hex (no `blake3:` prefix) — single
        // canonical path via sign_receipt_v2.
        assert_eq!(env.receipt_id.len(), 64);
        assert!(env.receipt_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!env.receipt_id.contains(':'));
        // Body should serialize without permits_merkle_root (skip_if empty).
        let body_str = serde_json::to_string(&env.body).unwrap();
        assert!(
            !body_str.contains("permits_merkle_root"),
            "empty claim_events should omit permits_merkle_root: {body_str}"
        );
        assert_eq!(env.body["principal_id"], "daemon-root-1");
        assert_eq!(env.body["signing_device_id"], "device-daemon-daemon-root-1");
    }

    #[test]
    fn operator_role_signs_as_child_principal_with_device() {
        let root = SigningPrincipalRecord {
            principal_id: "principal-person-root".to_string(),
            parent_id: "principal-person-root".to_string(),
            signing_device_id: None,
        };
        let role = SigningPrincipalRecord {
            principal_id: "principal-operator-role".to_string(),
            parent_id: root.principal_id.clone(),
            signing_device_id: Some("device-workstation-1".to_string()),
        };
        let signer = fixture_signer();
        let pk = signer.public_key();
        let env = issue_atomic_receipt_with_principal_chain(
            "test.operator_role",
            &serde_json::json!({"intent": "operator-signed"}),
            TerminationAuthority::UserSession,
            "daemon-root-for-operator-role",
            &[root.clone(), role.clone()],
            &role.principal_id,
            &root.principal_id,
            &signer,
        )
        .unwrap();

        verify_receipt_v2(&env, &pk, &FixtureVerifier).unwrap();
        let body_json = serde_json::to_string(&env.body).unwrap();
        let checkpoint = "identity_root_persona_daemon_signing_paths_landed";
        assert_eq!(env.body["principal_id"], "principal-operator-role");
        assert_eq!(env.body["signing_device_id"], "device-workstation-1");
        assert!(body_json.contains("principal_id") && body_json.contains("signing_device_id"));
        assert_eq!(
            checkpoint,
            "identity_root_persona_daemon_signing_paths_landed"
        );
    }

    #[test]
    fn signing_path_rejects_principal_parent_cycle() {
        let a = SigningPrincipalRecord {
            principal_id: "principal-a".to_string(),
            parent_id: "principal-b".to_string(),
            signing_device_id: Some("device-a".to_string()),
        };
        let b = SigningPrincipalRecord {
            principal_id: "principal-b".to_string(),
            parent_id: "principal-a".to_string(),
            signing_device_id: Some("device-b".to_string()),
        };
        let signer = fixture_signer();

        let err = issue_atomic_receipt_with_principal_chain(
            "test.operator_role",
            &serde_json::json!({"intent": "operator-signed"}),
            TerminationAuthority::UserSession,
            "daemon-root-for-operator-role",
            &[a, b],
            "principal-a",
            "principal-a",
            &signer,
        )
        .expect_err("identity_root_persona_daemon_signing_paths_landed");

        assert!(matches!(
            err,
            IssueError::PrincipalChain(PrincipalChainError::Cycle { .. })
        ));
    }

    #[test]
    fn one_claim_event_populates_merkle_root_and_round_trips() {
        let signer = fixture_signer();
        let pk = signer.public_key();
        let env = issue_cohort_a_receipt(
            "sess-2",
            vec![sample_claim_event("blake3:abc123")],
            None,
            TerminationAuthority::DaemonPersona,
            "daemon-root-2",
            None,
            &signer,
        )
        .unwrap();
        // Signed receipt must verify.
        verify_receipt_v2(&env, &pk, &FixtureVerifier).unwrap();
        // Round-trip the envelope through serde_json — guards against any
        // field that isn't (de)serializable.
        let json = serde_json::to_string(&env).unwrap();
        let back: ReceiptEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, RECEIPT_KIND_CLAUDE_CODE);
        assert_eq!(back.receipt_id, env.receipt_id);
        // Body now has a non-empty permits_merkle_root.
        let body_str = serde_json::to_string(&back.body).unwrap();
        assert!(
            body_str.contains("permits_merkle_root"),
            "single claim_event should populate permits_merkle_root: {body_str}"
        );
    }

    #[test]
    fn audit_gaps_file_parses_and_skips_malformed_lines() {
        let signer = fixture_signer();
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"{{"from":"2026-05-01T12:01:00Z","to":"2026-05-01T12:01:30Z","reason":"daemon_unreachable"}}"#
        )
        .unwrap();
        writeln!(f, "garbage line {{ not json").unwrap();
        writeln!(f).unwrap();
        writeln!(
            f,
            r#"{{"from":"2026-05-01T12:05:00Z","to":"2026-05-01T12:05:10Z","reason":"daemon_unreachable"}}"#
        )
        .unwrap();
        f.flush().unwrap();

        let env = issue_cohort_a_receipt(
            "sess-3",
            vec![sample_claim_event("blake3:def456")],
            Some(f.path()),
            TerminationAuthority::UserSession,
            "daemon-root-3",
            None,
            &signer,
        )
        .unwrap();
        let body: ClaudeCodeBody = serde_json::from_value(env.body).unwrap();
        assert_eq!(body.audit_gaps.len(), 2, "should recover both valid lines");
        assert_eq!(body.audit_gaps[0].reason, "daemon_unreachable");
    }

    #[test]
    fn missing_audit_gaps_path_yields_no_gaps() {
        let signer = fixture_signer();
        let env = issue_cohort_a_receipt(
            "sess-4",
            vec![],
            Some(Path::new("/nonexistent/audit-gaps.jsonl")),
            TerminationAuthority::UserSession,
            "daemon-root-4",
            None,
            &signer,
        )
        .unwrap();
        let body: ClaudeCodeBody = serde_json::from_value(env.body).unwrap();
        assert!(body.audit_gaps.is_empty());
    }

    #[test]
    fn closed_scope_summary_populates_segmented_rollup_fields() {
        let signer = fixture_signer();
        let env = issue_cohort_a_receipt_from_closed_scope(
            "sess-closed-summary",
            &sample_closed_scope_summary(),
            None,
            TerminationAuthority::DaemonPersona,
            "daemon-root-closed-summary",
            None,
            &signer,
        )
        .unwrap();
        let body: ClaudeCodeBody = serde_json::from_value(env.body).unwrap();
        assert_eq!(body.base.claim_count_total, Some(9));
        assert!(body.base.claim_events_truncated);
        assert_eq!(body.base.claim_segment_summaries.len(), 1);
        assert!(!body.base.claim_history_merkle_root.is_empty());
        assert!(!body.base.permits_merkle_root.is_empty());
        assert_eq!(body.base.claim_events.len(), 1);
    }

    /// T1 round-trip — `issue_cohort_a_receipt` now signs in-place.
    /// The returned envelope must verify against the signer's public key.
    /// Pins COHORT-A-V03-RECEIPT-PERSONA-SIGNING + ARCH-AUDIT-V2-RECEIPT-WIRE-INCOMPAT.
    #[test]
    fn receipt_id_matches_canonical_compute_and_verifies_after_signing() {
        let signer = FixtureSigner::new("issue-rs-roundtrip");
        let pk = signer.public_key();

        let env = issue_cohort_a_receipt(
            "sess-canonical",
            vec![sample_claim_event("blake3:canon-1")],
            None,
            TerminationAuthority::UserSession,
            "daemon-root-canon",
            None,
            &signer,
        )
        .unwrap();

        // Issuer's `receipt_id` must equal the canonical path's output.
        let canonical = compute_receipt_id(&env).unwrap();
        assert_eq!(
            env.receipt_id, canonical,
            "issue.rs and sign::compute_receipt_id must produce identical receipt_ids"
        );

        // Envelope signed inside issue — must verify without additional sign call.
        assert!(env.signature.is_some(), "issue must sign the envelope");
        verify_receipt_v2(&env, &pk, &FixtureVerifier).unwrap();
    }

    /// T1 negative — tampering with one byte of `body` after signing must
    /// fail [`verify_receipt_v2`].
    #[test]
    fn body_tamper_after_signing_fails_verification() {
        let signer = FixtureSigner::new("issue-rs-tamper");
        let pk = signer.public_key();

        let mut env = issue_cohort_a_receipt(
            "sess-tamper",
            vec![sample_claim_event("blake3:tamper-1")],
            None,
            TerminationAuthority::UserSession,
            "daemon-root-tamper",
            None,
            &signer,
        )
        .unwrap();

        // Tamper one byte of the body — overwrite a known field's value.
        // The receipt body is a serde_json::Value; mutate the
        // `permits_merkle_root` to a different (still hex-shaped) string.
        if let serde_json::Value::Object(map) = &mut env.body {
            map.insert(
                "permits_merkle_root".into(),
                serde_json::Value::String("0".repeat(64)),
            );
        } else {
            panic!("expected body to be a JSON object");
        }

        let r = verify_receipt_v2(&env, &pk, &FixtureVerifier);
        assert!(
            r.is_err(),
            "body tamper after signing should fail verification, got: {r:?}"
        );
    }

    #[test]
    fn service_installed_receipt_uses_canonical_atomic_builder() {
        let signer = fixture_signer();
        let pk = signer.public_key();
        let body = ServiceInstalledBody {
            plugin_address: "registry.ember.systems/ember-systems/ember-gh".into(),
            plugin_version: "0.3.0".into(),
            publisher_id: "publisher-root-001".into(),
            installed_by_persona_id: "persona-installer-001".into(),
            installation_policy: serde_json::json!({"approval": "explicit"}),
            service_label: Some("GitHub".into()),
        };
        let env =
            issue_service_installed_receipt(&body, "daemon-root-service-install", &signer).unwrap();
        assert_eq!(env.kind, RECEIPT_KIND_SERVICE_INSTALLED_V1);
        verify_receipt_v2(&env, &pk, &FixtureVerifier).unwrap();
        let back: ServiceInstalledBody = serde_json::from_value(env.body).unwrap();
        assert_eq!(back, body);
    }

    #[test]
    fn service_uninstalled_receipt_uses_canonical_atomic_builder() {
        let signer = fixture_signer();
        let pk = signer.public_key();
        let body = ServiceUninstalledBody {
            plugin_address: "registry.ember.systems/ember-systems/ember-gh".into(),
            plugin_version: "0.3.0".into(),
            publisher_id: "publisher-root-001".into(),
            uninstalled_by_persona_id: "persona-installer-001".into(),
            uninstall_reason: "operator_removed".into(),
            service_label: Some("GitHub".into()),
        };
        let env =
            issue_service_uninstalled_receipt(&body, "daemon-root-service-uninstall", &signer)
                .unwrap();
        assert_eq!(env.kind, RECEIPT_KIND_SERVICE_UNINSTALLED_V1);
        verify_receipt_v2(&env, &pk, &FixtureVerifier).unwrap();
        let back: ServiceUninstalledBody = serde_json::from_value(env.body).unwrap();
        assert_eq!(back, body);
    }
}
