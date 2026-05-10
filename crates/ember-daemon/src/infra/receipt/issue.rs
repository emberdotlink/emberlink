//! Receipt v2 issuance helper for cohort-A `session.claude_code` Receipts.
//!
//! Per design §"Envelope" + design §7. Builds a `ReceiptEnvelope` wrapping a
//! `ClaudeCodeBody` (claim_events + audit_gaps + permits_merkle_root) at session
//! termination. Signs the envelope in-place using the Daemon Persona key per
//! design via `daemon_persona_sign_receipt`.

use std::fs;
use std::path::Path;

use core_crypto::Signer;
use core_events::receipt::sign::{SignError, sign_receipt_v2};
use core_events::receipt::{
    AuditGap, ClaimEvent, ClaudeCodeBody, ReceiptBody, ReceiptEnvelope, ReceiptVersion,
    RECEIPT_KIND_CLAUDE_CODE, TerminationAuthority, TerminationReason, merkle_leaf, merkle_root,
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
}

/// Optional termination metadata injected into the `ClaudeCodeBody` by the
/// dirty-exit path (implementation-note-13). Pass `None` for
/// clean-exit / TTL-expiry / explicit-revoke issuance paths where the reason
/// is not yet known at build time.
pub struct TerminationMeta {
    pub reason: TerminationReason,
    pub last_heartbeat_at: Option<String>,
    pub pid_alive_at_check: Option<bool>,
}

/// Build and sign a cohort-A `session.claude_code` Receipt envelope.
///
/// Steps per design §"Envelope" + design §"Daemon Persona signing":
/// 1. Build [`ClaudeCodeBody`] from `claim_events` + parsed `audit_gaps.jsonl`
///    (lines parsed individually, malformed lines skipped — fail-open shape
///    matches implementation-note-10's writer). Optional `termination_meta` injects the
///    reason/heartbeat/pid fields into the body in the same step.
/// 2. Compute `permits_merkle_root` over `claim_events[].input_hash` blake3
///    leaves (design §"Merkle leaf format" — leaf form simplified for now;
///    proper canonical leaf payload is a follow-up).
/// 3. Construct [`ReceiptEnvelope`] with `version="2"`, `kind="session.claude_code"`,
///    `daemon_root_id`, `termination_authority`, body=JSON.
/// 4. Sign + stamp `receipt_id` via `sign_receipt_v2` — the single canonical
///    path (JCS-canonical bytes of envelope with receipt_id, without signature,
///    Ed25519-signed by the Daemon Persona key per design). Signing routes
///    through [`daemon_persona_sign_receipt`] as the named design primitive.
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
    let (termination_reason, last_heartbeat_at, pid_alive_at_check) =
        match termination_meta {
            Some(m) => (Some(m.reason), m.last_heartbeat_at, m.pid_alive_at_check),
            None => (None, None, None),
        };
    let body = ClaudeCodeBody {
        base: ReceiptBody {
            claim_events,
            permits_merkle_root,
            device_id: None,
        },
        audit_gaps,
        termination_reason,
        last_heartbeat_at,
        pid_alive_at_check,
    };

    // 4. Build envelope.
    let body_value = serde_json::to_value(&body).map_err(IssueError::Serialize)?;
    let mut envelope = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_CLAUDE_CODE.into(),
        receipt_id: String::new(),
        daemon_root_id: daemon_root_id.into(),
        traceparent: None,
        termination_authority,
        body: body_value,
        // sign_receipt_v2 populates both receipt_id and signature below.
        signature: None,
    };

    // 5. Sign the envelope per design (Daemon Persona signing).
    //
    //    Canonicalization: JCS(envelope with receipt_id, without signature)
    //    per RFC 8785 — UTF-16 key order, I-JSON numbers, minimal escaping.
    //    Bit-stable across serializer upgrades as long as the field set and
    //    serde_jcs version are pinned. Any field addition is a wire-breaking
    //    change requiring a receipt version bump.
    //
    //    sign_receipt_v2 calls daemon_persona_sign_receipt (the design named
    //    primitive in core_crypto::persona) after computing receipt_id.
    sign_receipt_v2(&mut envelope, signer).map_err(IssueError::Sign)?;

    Ok(envelope)
}

/// Parse `~/.ember/sessions/<id>/audit-gaps.jsonl` line-by-line, skipping
/// malformed lines (matches the fail-open posture of implementation-note-10's writer).
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
    use core_crypto::{FixtureSigner, FixtureVerifier, Signer as _};
    use core_events::receipt::body::{ClaimEvent, ClaimKind};
    use core_events::receipt::sign::{compute_receipt_id, verify_receipt_v2};
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    fn sample_claim_event(input_hash: &str) -> ClaimEvent {
        ClaimEvent {
            ts: "2026-05-01T12:00:00Z".into(),
            kind: ClaimKind::Approval,
            tool: "Bash".into(),
            input_hash: input_hash.into(),
            input_redacted: serde_json::json!({"command": "echo hi"}),
            resolved: serde_json::json!({"allowed": true}),
        }
    }

    fn fixture_signer() -> FixtureSigner {
        FixtureSigner::new("issue-rs-fixture")
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

    /// T1 round-trip — `issue_cohort_a_receipt` now signs in-place.
    /// The returned envelope must verify against the signer's public key.
    /// Pins implementation-note-116 + implementation-note-117.
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
}
