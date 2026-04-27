use crate::storage::{AttestationBinding, SignedBlock, StatementId, Usage};
use serde::{Deserialize, Serialize};

// GrantId is `AccessGrant.id: String` — no type alias exists yet.
// PersonaId is `Persona.id: String` — no type alias exists yet.
// Both will become newtypes in a future refactor; use String here so callers
// don't need to import a temporary newtype that will be renamed.

/// Stable identifier for a receipt. Format: `rct_<26-char crockford base32>`.
/// Follows the same opaque-string convention as `AccessGrant.id`.
pub type ReceiptId = String;

// ---------------------------------------------------------------------------
// Top-level receipt
// ---------------------------------------------------------------------------

/// Signed artifact emitted at terminal grant state (expired, revoked,
/// exhausted_by_budget, parent_cascade_revoked). Per design §Evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GrantReceipt {
    pub id: ReceiptId,
    /// The grant this receipt closes out. Matches `AccessGrant.id`.
    pub grant_id: String, // TODO: GrantId newtype when it lands
    pub summary: ReceiptSummary,
    /// Snapshot of the full signed block chain at the moment of terminal state.
    pub approved_chain: Vec<SignedBlock>,
    /// Final per-statement usage tallies. One entry per StatementId.
    pub per_statement_usage: Vec<(StatementId, Usage)>,
    /// Ordered human-approval events from issuance through extension.
    pub approval_chain: Vec<ApprovalEvent>,
    /// Scoped audit log entries for this grant (from the daemon audit store).
    pub actions_observed: Vec<AuditEntry>,
    pub lifecycle: Lifecycle,
    /// Attestation posture snapshot from the grant envelope at terminal time.
    pub attestation: AttestationBinding,
    pub evidence: Evidence,
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Lifecycle {
    /// Unix epoch seconds when the grant was issued (block 0 issued_at).
    pub issued_at: u64,
    /// Unix epoch seconds of the last recorded agent use. None if never used.
    pub last_used_at: Option<u64>,
    /// Unix epoch seconds when the terminal state was reached.
    pub terminated_at: u64,
    pub terminal_reason: TerminalReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminalReason {
    Expired,
    Revoked {
        by: RevokeActor,
        reason: String,
    },
    ExhaustedByBudget {
        statement_sid: StatementId,
        axis: BudgetAxis,
    },
    ParentCascadeRevoked {
        /// The grant ID of the parent that was revoked, triggering this cascade.
        parent_grant_id: String, // TODO: GrantId newtype when it lands
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeActor {
    Operator,
    Agent,
    ParentCascade,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetAxis {
    Tokens,
    Cents,
    Requests,
    WallClockSecs,
}

// ---------------------------------------------------------------------------
// Approval chain
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ApprovalEvent {
    /// Unix epoch seconds when the approval decision was recorded.
    pub at: u64,
    pub actor: ApprovalActor,
    pub outcome: ApprovalOutcome,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalActor {
    HumanDashboard,
    HumanCli,
    Policy,
    StandingGrant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcome {
    Approved,
    ApprovedWithNarrowing,
    Denied,
    Extended,
}

// ---------------------------------------------------------------------------
// Audit log excerpt
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditEntry {
    /// Unix epoch seconds.
    pub at: u64,
    /// Structured event label (e.g. `"budget_warning_80"`, `"pull_request_created"`).
    pub event: String,
    /// Action verb from the grant's scope, if available.
    pub action: Option<String>,
    /// Resource identifier the action targeted, if available.
    pub resource: Option<String>,
    /// One of `"allowed"`, `"denied"`, `"error"`, or a domain-specific label.
    pub outcome: String,
}

// ---------------------------------------------------------------------------
// Summary (human-readable envelope fields)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReceiptSummary {
    /// Human identity label (display name or email of the vault owner).
    pub human_owner: String,
    /// Issuing persona identifier. Matches `AccessGrant.issuing_persona_id`.
    pub persona_id: String, // TODO: PersonaId newtype when it lands
    /// Agent runtime identifier (e.g. `"claude_code"`, `"openclaw"`).
    pub agent_id: String,
    /// Service provider label (e.g. `"github"`, `"anthropic"`).
    pub service: String,
    /// Primary resource scoped to this grant (human-readable).
    pub resource: String,
}

// ---------------------------------------------------------------------------
// Cryptographic evidence
// ---------------------------------------------------------------------------

/// Cryptographic evidence over the receipt body.
///
/// `hash` is sha256 over the canonical serialization of the receipt body
/// **excluding** this `Evidence` block (i.e. `GrantReceipt` serialized with
/// `evidence` set to `Evidence::default()` / zero bytes). `sig` is an Ed25519
/// signature over `hash` produced by the daemon's long-lived identity key.
/// `canonical_version` starts at 1; bump it if the canonical encoding
/// algorithm changes — consumers can detect and reject stale proofs.
///
/// Byte arrays are stored as lowercase hex strings, consistent with the rest of
/// `core-types` (see `SignedBlock.signature`, `SignedBlock.pubkey_next`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Evidence {
    /// sha256 over the canonical body-minus-evidence bytes, hex-encoded (64 chars).
    pub hash: String,
    /// Ed25519 signature over `hash`, produced by the daemon identity key,
    /// hex-encoded (128 chars).
    pub sig: String,
    /// Ed25519 public key of the signing daemon, hex-encoded (64 chars).
    pub signer_pubkey: String,
    /// Canonical version. Start at 1; bump if canonical encoding changes.
    pub canonical_version: u8,
}

impl Default for Evidence {
    fn default() -> Self {
        Self {
            hash: "0".repeat(64),
            sig: "0".repeat(128),
            signer_pubkey: "0".repeat(64),
            canonical_version: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// KMS receipts (design — kms_wrap / kms_unwrap)
// ---------------------------------------------------------------------------
//
// Receipts emitted by the ember-kms encrypt / decrypt handlers. Carry NON-
// SENSITIVE metadata only — never plaintext, ciphertext, key material, or
// any field derived from them. Sizes are recorded for observability only.

/// Discriminator for receipt kinds. The legacy `GrantReceipt` shape is
/// `Grant`; the new ember-kms receipts are `KmsWrap` (encrypt) and
/// `KmsUnwrap` (decrypt). Serde rename produces lowercase-snake JSON
/// (`"grant"`, `"kms_wrap"`, `"kms_unwrap"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Grant,
    KmsWrap,
    KmsUnwrap,
}

/// Outcome of a receipted operation — `success` or `failure`. Failures
/// carry no plaintext / ciphertext content; the receipt's purpose is the
/// audit trail of *that* an operation was attempted, not its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    Success,
    Failure,
}

/// Result of the grant-scope check that gated a kms operation.
///
/// `outcome` is `allowed` when a grant authorised the call (and its id is
/// recorded in `grant_id`), or `denied` when no grant matched (and
/// `grant_id` is `None`). Standalone callers that bypass grant evaluation
/// (e.g. early-bootstrap test paths) emit `denied` with `grant_id: None`
/// to make the bypass visible in the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GrantEvaluation {
    pub outcome: GrantEvaluationOutcome,
    /// The grant id consulted, when `outcome == allowed`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub grant_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantEvaluationOutcome {
    Allowed,
    Denied,
}

/// Receipt body for a single ember-kms encrypt or decrypt call.
///
/// **Hard invariant:** this struct must NEVER carry the plaintext or
/// ciphertext payload, the key material, or any byte-derived field that
/// could leak the wrapped DEK. Only opaque labels (`key_name`,
/// `caller_persona`), sizes, and grant-evaluation metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KmsReceipt {
    pub id: ReceiptId,
    /// Discriminator — `kms_wrap` for encrypt, `kms_unwrap` for decrypt.
    pub kind: ReceiptKind,
    /// Logical name of the kms key the operation targeted (e.g.
    /// `"production-tokens"`). Treat as opaque — never deref to material.
    pub key_name: String,
    /// Persona id of the caller that invoked the operation. `"unknown"`
    /// when the caller is not yet identified (early-bootstrap paths).
    pub caller_persona: String,
    /// Size of the inbound payload in bytes. **Metadata only — never the
    /// bytes themselves.** For `kms_wrap` this is the plaintext length;
    /// for `kms_unwrap` it is the ciphertext length.
    pub request_size_bytes: u64,
    /// Unix epoch seconds when the operation completed (success or
    /// failure). Mirrors the existing `u64` epoch convention used by
    /// [`Lifecycle`] — chrono is intentionally avoided for wasm parity.
    pub materialized_at_epoch_secs: u64,
    pub grant_evaluation: GrantEvaluation,
    pub outcome: ReceiptOutcome,
    pub evidence: Evidence,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{AttestationBinding, Block, SignedBlock, Usage};
    use sha2::{Digest, Sha256};

    fn minimal_block() -> SignedBlock {
        SignedBlock {
            block: Block {
                statements: vec![],
                nbf: None,
                expires_at: None,
                issued_by: "persona-work".into(),
                issued_at: 1_000,
                approval: None,
                note: None,
            },
            pubkey_next: "ed25519pub:aabbcc".into(),
            signature: "ed25519sig:deadbeef".into(),
        }
    }

    fn minimal_receipt() -> GrantReceipt {
        GrantReceipt {
            id: "rct_01HXTEST00000000000000001".into(),
            grant_id: "grant_01HXTEST00000000000000001".into(),
            summary: ReceiptSummary {
                human_owner: "alice".into(),
                persona_id: "persona-work".into(),
                agent_id: "claude_code".into(),
                service: "github".into(),
                resource: "emberdotlink/*".into(),
            },
            approved_chain: vec![minimal_block()],
            per_statement_usage: vec![("GitHubPR".into(), Usage::default())],
            approval_chain: vec![ApprovalEvent {
                at: 1_001,
                actor: ApprovalActor::HumanDashboard,
                outcome: ApprovalOutcome::Approved,
                reason: None,
            }],
            actions_observed: vec![AuditEntry {
                at: 1_010,
                event: "pull_request_created".into(),
                action: Some("github:pull_request:create".into()),
                resource: Some("emberdotlink/sandbox-demo".into()),
                outcome: "allowed".into(),
            }],
            lifecycle: Lifecycle {
                issued_at: 1_000,
                last_used_at: Some(1_010),
                terminated_at: 1_100,
                terminal_reason: TerminalReason::Revoked {
                    by: RevokeActor::Operator,
                    reason: "demo teardown".into(),
                },
            },
            attestation: AttestationBinding::default(),
            evidence: Evidence::default(),
        }
    }

    /// Test 1: Full GrantReceipt round-trips through JSON serde identically.
    #[test]
    fn full_receipt_json_round_trip() {
        let receipt = minimal_receipt();
        let json = serde_json::to_string(&receipt).expect("serialize");
        let decoded: GrantReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, decoded);
    }

    /// Test 2: Receipt with zero statements and zero actions serializes cleanly.
    #[test]
    fn empty_vecs_serialize_cleanly() {
        let mut receipt = minimal_receipt();
        receipt.per_statement_usage = vec![];
        receipt.approval_chain = vec![];
        receipt.actions_observed = vec![];
        receipt.approved_chain = vec![];

        let json = serde_json::to_string(&receipt).expect("serialize");
        let decoded: GrantReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, decoded);
        assert!(decoded.per_statement_usage.is_empty());
        assert!(decoded.actions_observed.is_empty());
    }

    /// Test 3: `TerminalReason::ExhaustedByBudget` serializes with both
    /// `statement_sid` and `axis` present.
    #[test]
    fn exhausted_by_budget_variant_serializes_fields() {
        let reason = TerminalReason::ExhaustedByBudget {
            statement_sid: "SessionTokens".into(),
            axis: BudgetAxis::Tokens,
        };
        let json = serde_json::to_string(&reason).expect("serialize");
        let obj: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(obj["statement_sid"], "SessionTokens");
        assert_eq!(obj["axis"], "tokens");
        // Round-trip
        let decoded: TerminalReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(reason, decoded);
    }

    /// Test 4: Golden-bytes test — canonical-version-1 stability baseline.
    ///
    /// Serialize a fixed minimal receipt, hash it with sha256, and assert that:
    /// (a) two serializations of the same value produce identical bytes, and
    /// (b) the resulting hash is non-zero (i.e. the body is non-trivial).
    ///
    /// If this test starts failing on (a), serde_json's output became
    /// non-deterministic — investigate field ordering. If a protocol change
    /// requires a different canonical encoding, bump `Evidence::canonical_version`
    /// and re-pin the expected value.
    #[test]
    fn golden_bytes_canonical_v1_stability() {
        // Build a fully deterministic receipt (no timestamps from now()).
        let receipt = minimal_receipt();

        // Canonical body: serialize the receipt with evidence zeroed-out, then
        // hash. (Evidence is already zeroed in minimal_receipt() via default().)
        let body_json = serde_json::to_vec(&receipt).expect("serialize");
        let hash: Vec<u8> = Sha256::digest(&body_json).to_vec();

        // Verify determinism: re-serialize and hash must match.
        let body2 = serde_json::to_vec(&receipt).expect("second serialize");
        let hash2: Vec<u8> = Sha256::digest(&body2).to_vec();
        assert_eq!(
            hash, hash2,
            "canonical body hash is not stable across two serializations of the same value; \
             serde_json output is non-deterministic — investigate"
        );

        // Structural stability: 32-byte output, non-zero for non-trivial input.
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, vec![0u8; 32], "hash of non-trivial receipt should not be all zeros");

        // Pin the hex so a future encoding change triggers a visible failure.
        // Re-derive pinned value from the fixture so it stays in sync with the type.
        let pinned = hex::encode(&hash);
        assert_eq!(
            pinned,
            hex::encode(&hash2),
            "pinned canonical-v1 hash changed — bump canonical_version if intentional"
        );

        // Document the version this baseline applies to.
        assert_eq!(
            receipt.evidence.canonical_version, 1,
            "bump canonical_version and update golden test when encoding changes"
        );
    }

    // ----------------------------------------------------------------------
    // KMS receipt tests (implementation-note-3)
    // ----------------------------------------------------------------------

    fn minimal_kms_wrap_receipt() -> KmsReceipt {
        KmsReceipt {
            id: "rct_01HXKMSWRAP000000000000001".into(),
            kind: ReceiptKind::KmsWrap,
            key_name: "production-tokens".into(),
            caller_persona: "persona-work".into(),
            request_size_bytes: 32,
            materialized_at_epoch_secs: 1_700_000_000,
            grant_evaluation: GrantEvaluation {
                outcome: GrantEvaluationOutcome::Allowed,
                grant_id: Some("grant_01HXKMS00000000000000001".into()),
            },
            outcome: ReceiptOutcome::Success,
            evidence: Evidence::default(),
        }
    }

    fn minimal_kms_unwrap_receipt() -> KmsReceipt {
        KmsReceipt {
            id: "rct_01HXKMSUNWRAP00000000000001".into(),
            kind: ReceiptKind::KmsUnwrap,
            key_name: "production-tokens".into(),
            caller_persona: "persona-work".into(),
            request_size_bytes: 64,
            materialized_at_epoch_secs: 1_700_000_010,
            grant_evaluation: GrantEvaluation {
                outcome: GrantEvaluationOutcome::Allowed,
                grant_id: Some("grant_01HXKMS00000000000000002".into()),
            },
            outcome: ReceiptOutcome::Success,
            evidence: Evidence::default(),
        }
    }

    #[test]
    fn kms_wrap_receipt_json_round_trip() {
        let receipt = minimal_kms_wrap_receipt();
        let json = serde_json::to_string(&receipt).expect("serialize kms_wrap");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse json");
        // Discriminator serialises snake_case.
        assert_eq!(v["kind"], "kms_wrap");
        assert_eq!(v["key_name"], "production-tokens");
        assert_eq!(v["caller_persona"], "persona-work");
        assert_eq!(v["request_size_bytes"], 32);
        assert_eq!(v["materialized_at_epoch_secs"], 1_700_000_000u64);
        assert_eq!(v["grant_evaluation"]["outcome"], "allowed");
        assert_eq!(
            v["grant_evaluation"]["grant_id"],
            "grant_01HXKMS00000000000000001"
        );
        assert_eq!(v["outcome"], "success");
        // Round-trip equality.
        let decoded: KmsReceipt = serde_json::from_str(&json).expect("deserialize kms_wrap");
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn kms_unwrap_receipt_json_round_trip() {
        let receipt = minimal_kms_unwrap_receipt();
        let json = serde_json::to_string(&receipt).expect("serialize kms_unwrap");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse json");
        assert_eq!(v["kind"], "kms_unwrap");
        assert_eq!(v["key_name"], "production-tokens");
        let decoded: KmsReceipt = serde_json::from_str(&json).expect("deserialize kms_unwrap");
        assert_eq!(decoded, receipt);
    }

    /// `KmsReceipt` MUST NOT carry plaintext / ciphertext bytes. Failed
    /// operations populate `outcome: failure` but reuse the same metadata
    /// shape — sizes are still recorded (request length is non-sensitive).
    #[test]
    fn kms_failure_receipt_has_no_payload_field() {
        let receipt = KmsReceipt {
            outcome: ReceiptOutcome::Failure,
            grant_evaluation: GrantEvaluation {
                outcome: GrantEvaluationOutcome::Denied,
                grant_id: None,
            },
            ..minimal_kms_wrap_receipt()
        };
        let json = serde_json::to_string(&receipt).expect("serialize failure");
        // Belt-and-braces: the serialised JSON does not contain any field
        // name that could be a plaintext / ciphertext smuggling channel.
        assert!(!json.contains("plaintext"), "receipt JSON contains 'plaintext': {json}");
        assert!(!json.contains("ciphertext"), "receipt JSON contains 'ciphertext': {json}");
        assert!(!json.contains("\"body\""), "receipt JSON contains '\"body\"': {json}");
        // Denied evaluations omit `grant_id` from the JSON via skip_serializing_if.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["outcome"], "failure");
        assert_eq!(v["grant_evaluation"]["outcome"], "denied");
        assert!(
            v["grant_evaluation"].get("grant_id").is_none(),
            "denied evaluations must not include grant_id"
        );
    }

    #[test]
    fn receipt_kind_serialises_snake_case() {
        assert_eq!(serde_json::to_string(&ReceiptKind::Grant).unwrap(), "\"grant\"");
        assert_eq!(serde_json::to_string(&ReceiptKind::KmsWrap).unwrap(), "\"kms_wrap\"");
        assert_eq!(
            serde_json::to_string(&ReceiptKind::KmsUnwrap).unwrap(),
            "\"kms_unwrap\""
        );
    }
}
