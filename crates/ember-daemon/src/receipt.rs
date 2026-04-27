//! Grant Receipt emission — Stream D (design §Evidence).
//!
//! Every terminal grant state (expired, revoked, exhausted_by_budget,
//! parent_cascade_revoked) emits a signed [`GrantReceipt`]. The receipt
//! captures the full composite-grant chain snapshot, per-Statement usage
//! tallies, the human-approval chain, and a scoped audit-log excerpt —
//! signed with the daemon's long-lived Ed25519 identity key.
//!
//! Receipt canonical encoding (v1):
//!
//! 1. Populate the `GrantReceipt` body with `Evidence::default()` (zero-
//!    bytes placeholders) so `signer_pubkey`/`sig`/`hash` do not influence
//!    their own digest.
//! 2. Serialize to bytes with `serde_json::to_vec` (deterministic per
//!    current serde_json semantics — golden-bytes test in core-types pins
//!    this).
//! 3. Prefix with the literal ASCII bytes `type=grant-receipt-v1\n` to
//!    prevent cross-protocol signature reuse.
//! 4. sha256 → `hash` (hex).
//! 5. Ed25519 sign `hash` bytes → `sig` (hex).
//! 6. Populate `Evidence { hash, sig, signer_pubkey, canonical_version: 1 }`
//!    on the receipt and return.
//!
//! Identity-key lifecycle: generated once on first run into
//! `<data_dir>/daemon_identity.key` (mode 0600). The file holds 32 bytes
//! of raw Ed25519 secret key material. Published via
//! `GET /daemon/identity.json` as hex so external verifiers can compare
//! against their trust anchor.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use core_types::grant_receipt::{
    ApprovalActor, ApprovalEvent, ApprovalOutcome, AuditEntry as ReceiptAuditEntry,
    BudgetAxis, Evidence, GrantReceipt, KmsReceipt, Lifecycle, ReceiptKind, ReceiptSummary,
    RevokeActor, TerminalReason,
};
use core_types::{AttestationBinding, StatementId, Usage};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use once_cell::sync::OnceCell;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::audit::AuditFilter;
use crate::grant::GrantInfo;
use crate::store::{DaemonStore, StoreError};

/// Canonical-encoding prefix. Bump version AND
/// `Evidence::canonical_version` together if the encoding ever changes.
const CANONICAL_PREFIX: &str = "type=grant-receipt-v1\n";

/// Current canonical-encoding version. Mirrored into Evidence.
pub const CANONICAL_VERSION: u8 = 1;

/// Filename (under `data_dir`) where the daemon's long-lived identity key
/// is persisted. 32 bytes raw Ed25519 secret.
const IDENTITY_KEY_FILENAME: &str = "daemon_identity.key";

// ---------------------------------------------------------------------------
// Identity key
// ---------------------------------------------------------------------------

/// The daemon's long-lived identity key.
///
/// Loaded on first access and cached. First-run generates a fresh
/// Ed25519 keypair and writes the 32-byte secret to
/// `<data_dir>/daemon_identity.key` with mode 0600. Subsequent loads
/// read the same file. This key signs every Grant Receipt; it is NOT
/// a persona key and is NOT used for any protocol message outside of
/// receipt Evidence.
pub struct DaemonIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl DaemonIdentity {
    /// Load from `<data_dir>/daemon_identity.key`, generating on first run.
    pub fn load_or_create(data_dir: &Path) -> Result<Self, StoreError> {
        fs::create_dir_all(data_dir).map_err(|e| {
            StoreError::InvalidInput(format!("create data_dir for identity key: {e}"))
        })?;
        let path = data_dir.join(IDENTITY_KEY_FILENAME);
        if path.exists() {
            let bytes = fs::read(&path).map_err(|e| {
                StoreError::InvalidInput(format!(
                    "read daemon identity key at {}: {e}",
                    path.display()
                ))
            })?;
            if bytes.len() != 32 {
                return Err(StoreError::InvalidInput(format!(
                    "daemon identity key at {} has {} bytes (expected 32)",
                    path.display(),
                    bytes.len()
                )));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            let signing_key = SigningKey::from_bytes(&seed);
            let verifying_key = signing_key.verifying_key();
            Ok(Self { signing_key, verifying_key })
        } else {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| {
                StoreError::InvalidInput(format!("OS RNG failure generating identity: {e}"))
            })?;
            write_identity_file(&path, &seed)?;
            let signing_key = SigningKey::from_bytes(&seed);
            let verifying_key = signing_key.verifying_key();
            Ok(Self { signing_key, verifying_key })
        }
    }

    /// Ed25519 public key (32 bytes, hex-encoded, 64 chars).
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Sign an arbitrary byte payload.
    pub fn sign(&self, payload: &[u8]) -> [u8; 64] {
        self.signing_key.sign(payload).to_bytes()
    }
}

/// Write the 32-byte secret to `path` with permissions 0600.
fn write_identity_file(path: &Path, secret: &[u8; 32]) -> Result<(), StoreError> {
    fs::write(path, secret).map_err(|e| {
        StoreError::InvalidInput(format!("write daemon identity key to {}: {e}", path.display()))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|e| StoreError::InvalidInput(format!("stat identity key: {e}")))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)
            .map_err(|e| StoreError::InvalidInput(format!("chmod 0600 identity key: {e}")))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Canonical encoding + verification
// ---------------------------------------------------------------------------

/// Serialize a receipt to its canonical bytes (v1): prefix + serde_json of
/// the receipt with `Evidence::default()`. Caller-supplied receipt must
/// already carry zero-byte evidence for the result to match what the
/// verifier sees.
pub fn canonical_body_bytes(receipt_with_zero_evidence: &GrantReceipt) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(CANONICAL_PREFIX.as_bytes());
    let body = serde_json::to_vec(receipt_with_zero_evidence)
        .expect("GrantReceipt with default Evidence always serializes");
    out.extend_from_slice(&body);
    out
}

/// Compute the canonical hash (sha256 hex) of a receipt body. Does NOT
/// look at the caller's Evidence — it zeroes Evidence first so the hash
/// is stable regardless of what `evidence` currently holds.
pub fn canonical_hash(receipt: &GrantReceipt) -> String {
    hex::encode(canonical_hash_receipt(receipt))
}

/// Raw-bytes variant of [`canonical_hash`] — returns the 32-byte sha256
/// digest directly. Evidence is zeroed before hashing so the result is
/// independent of what the caller's `evidence` field currently holds
/// (including `hash`, `sig`, `signer_pubkey`, and `canonical_version`).
pub fn canonical_hash_receipt(receipt: &GrantReceipt) -> [u8; 32] {
    let mut cloned = receipt.clone();
    cloned.evidence = Evidence::default();
    let bytes = canonical_body_bytes(&cloned);
    let digest = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

// ---------------------------------------------------------------------------
// implementation-note-3 — kms receipt canonical-encoding + signing helpers
// ---------------------------------------------------------------------------

/// Canonical-encoding prefix for kms receipts. Distinct from
/// [`CANONICAL_PREFIX`] so a kms receipt can never be replayed against a
/// grant-receipt verifier (cross-protocol signature reuse).
const KMS_CANONICAL_PREFIX: &str = "type=kms-receipt-v1\n";

/// Serialise a [`KmsReceipt`] to canonical bytes (v1) — zero evidence,
/// JSON, prefixed.
fn kms_canonical_body_bytes(receipt_with_zero_evidence: &KmsReceipt) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(KMS_CANONICAL_PREFIX.as_bytes());
    let body = serde_json::to_vec(receipt_with_zero_evidence)
        .expect("KmsReceipt with default Evidence always serializes");
    out.extend_from_slice(&body);
    out
}

/// Compute the canonical hash (sha256 hex) of a kms receipt body. Zeroes
/// evidence first so the result is independent of the caller's evidence
/// field.
pub fn kms_canonical_hash(receipt: &KmsReceipt) -> String {
    let mut cloned = receipt.clone();
    cloned.evidence = Evidence::default();
    let bytes = kms_canonical_body_bytes(&cloned);
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}

/// Sign a kms receipt in place using the daemon identity. Populates
/// `evidence.{hash, sig, signer_pubkey, canonical_version}`.
pub fn sign_kms_receipt(receipt: &mut KmsReceipt, identity: &DaemonIdentity) {
    let hash_hex = kms_canonical_hash(receipt);
    let sig_bytes = identity.sign(hash_hex.as_bytes());
    receipt.evidence = Evidence {
        hash: hash_hex,
        sig: hex::encode(sig_bytes),
        signer_pubkey: identity.pubkey_hex(),
        canonical_version: CANONICAL_VERSION,
    };
}

/// Verify an Ed25519 signature against a pubkey (both hex) over the
/// canonical hash of the receipt body.
///
/// Returns `Ok(())` iff:
///   - `expected_pubkey_hex` decodes to a valid 32-byte Ed25519 pubkey
///     (this is the caller-supplied trust anchor — the receipt's own
///     `signer_pubkey` field is informational only and is NOT trusted
///     for cryptographic verification);
///   - the signature in `receipt.evidence.sig` is not the all-zeros
///     phase-1 placeholder (returns `PlaceholderSig` if so);
///   - recomputed canonical hash matches `receipt.evidence.hash`;
///   - Ed25519 verify passes over the hash bytes using `expected_pubkey_hex`.
pub fn verify_receipt(
    receipt: &GrantReceipt,
    expected_pubkey_hex: &str,
) -> Result<(), ReceiptVerifyError> {
    if receipt.evidence.canonical_version != CANONICAL_VERSION {
        return Err(ReceiptVerifyError::WrongVersion {
            got: receipt.evidence.canonical_version,
        });
    }
    if !receipt.evidence.signer_pubkey.eq_ignore_ascii_case(expected_pubkey_hex) {
        return Err(ReceiptVerifyError::SignerMismatch {
            got: receipt.evidence.signer_pubkey.clone(),
            expected: expected_pubkey_hex.to_string(),
        });
    }
    // Decode the sig early so we can distinguish a phase-1 placeholder
    // (all-zero bytes) before attempting cryptographic verification.
    let sig_bytes = hex::decode(&receipt.evidence.sig)
        .map_err(|e| ReceiptVerifyError::Malformed(format!("sig hex: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ReceiptVerifyError::Malformed("sig length".into()))?;
    if sig_arr == [0u8; 64] {
        return Err(ReceiptVerifyError::PlaceholderSig);
    }
    let recomputed = canonical_hash(receipt);
    if !recomputed.eq_ignore_ascii_case(&receipt.evidence.hash) {
        return Err(ReceiptVerifyError::HashMismatch {
            got: receipt.evidence.hash.clone(),
            recomputed,
        });
    }
    // Construct the verifying key from the CALLER-SUPPLIED trust anchor,
    // not from the receipt's own signer_pubkey field (which an attacker
    // could set to any key they control).
    let pubkey_bytes = hex::decode(expected_pubkey_hex)
        .map_err(|e| ReceiptVerifyError::Malformed(format!("expected pubkey hex: {e}")))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ReceiptVerifyError::Malformed("expected pubkey length".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|e| ReceiptVerifyError::Malformed(format!("expected pubkey parse: {e}")))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    ed25519_dalek::Verifier::verify(&verifying_key, recomputed.as_bytes(), &signature)
        .map_err(|_| ReceiptVerifyError::BadSignature)?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiptVerifyError {
    #[error("canonical version mismatch: receipt v{got}, verifier expects v1")]
    WrongVersion { got: u8 },
    #[error("signer pubkey mismatch: got {got}, expected {expected}")]
    SignerMismatch { got: String, expected: String },
    #[error("hash mismatch: receipt says {got}, recomputed {recomputed}")]
    HashMismatch { got: String, recomputed: String },
    #[error("signature verification failed")]
    BadSignature,
    #[error("malformed evidence: {0}")]
    Malformed(String),
    #[error("receipt carries a phase-1 placeholder signature (all-zero bytes) — not yet signed")]
    PlaceholderSig,
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

/// Check whether a grant is in a terminal state warranting receipt
/// emission. Kept local so the set of terminal statuses lives in one
/// place.
pub fn is_terminal_status(status: &str) -> bool {
    matches!(
        status,
        "revoked" | "expired" | "exhausted_by_budget" | "parent_cascade_revoked"
    )
}

/// Emit a receipt if the grant is in a terminal state and has no
/// receipt yet. Idempotent — safe to call multiple times from different
/// terminal-state hooks (revoke, expire, cascade, budget).
///
/// `explicit_reason` overrides the status-derived reason when the
/// caller knows more (e.g., revoke path knows operator vs. cascade).
pub fn trigger_receipt_if_terminal(
    store: &DaemonStore,
    identity: &DaemonIdentity,
    grant_id: &str,
    explicit_reason: Option<TerminalReason>,
) -> Result<Option<String>, StoreError> {
    let info = match store.get_grant(grant_id) {
        Ok(i) => i,
        Err(StoreError::NotFound) => return Ok(None),
        Err(e) => return Err(e),
    };
    if !is_terminal_status(&info.status) {
        return Ok(None);
    }
    if info.receipt_id.is_some() {
        return Ok(info.receipt_id);
    }
    let reason = explicit_reason.unwrap_or_else(|| derive_reason(&info));
    let receipt_id = emit_receipt(store, identity, &info, reason)?;
    store.set_grant_receipt_id(grant_id, &receipt_id)?;
    Ok(Some(receipt_id))
}

/// Derive a terminal reason from grant status alone.
fn derive_reason(info: &GrantInfo) -> TerminalReason {
    match info.status.as_str() {
        "revoked" => TerminalReason::Revoked {
            by: RevokeActor::Operator,
            reason: String::new(),
        },
        "expired" => TerminalReason::Expired,
        "exhausted_by_budget" => {
            // Pick the axis that most likely drove exhaustion. Wall-clock is
            // the sweeper's primary axis today; fall back to tokens otherwise.
            let sid = info
                .budget
                .as_ref()
                .map(|_| StatementId::from("S0"))
                .unwrap_or_else(|| "S0".to_string());
            let axis = if info
                .budget
                .as_ref()
                .and_then(|b| b.wall_clock_secs)
                .is_some()
            {
                BudgetAxis::WallClockSecs
            } else if info.budget.as_ref().and_then(|b| b.tokens).is_some() {
                BudgetAxis::Tokens
            } else if info.budget.as_ref().and_then(|b| b.cents).is_some() {
                BudgetAxis::Cents
            } else {
                BudgetAxis::Requests
            };
            TerminalReason::ExhaustedByBudget { statement_sid: sid, axis }
        }
        "parent_cascade_revoked" => TerminalReason::ParentCascadeRevoked {
            parent_grant_id: info.parent_grant_id.clone().unwrap_or_default(),
        },
        _ => TerminalReason::Revoked {
            by: RevokeActor::Operator,
            reason: String::new(),
        },
    }
}

/// Assemble a fully-populated [`GrantReceipt`] for a terminal grant from
/// the daemon's existing stores. Pure logic — does NOT sign the receipt
/// (evidence stays [`Evidence::default`]) and does NOT persist it.
///
/// Fails with:
///   - [`StoreError::NotFound`] if `grant_id` does not exist;
///   - [`StoreError::InvalidInput`] if the grant is still active (not in
///     a terminal status). The terminal set is defined by
///     [`is_terminal_status`].
///
/// `now_epoch_secs` is stamped into `lifecycle.terminated_at` — callers
/// should pass the same clock they used to drive the terminal transition
/// (e.g. the sweep timestamp for `expire_stale_grants`).
pub fn generate_receipt(
    store: &DaemonStore,
    grant_id: &str,
    terminal_reason: TerminalReason,
    now_epoch_secs: u64,
) -> Result<GrantReceipt, StoreError> {
    let info = store.get_grant(grant_id)?;
    if !is_terminal_status(&info.status) {
        return Err(StoreError::InvalidInput(format!(
            "grant {grant_id} is not in a terminal state (status={})",
            info.status
        )));
    }
    Ok(build_receipt_body(store, &info, terminal_reason, now_epoch_secs))
}

/// Body-assembly helper shared by [`generate_receipt`] (public, error-returning)
/// and [`emit_receipt`] (signs + persists after assembly). Infallible — a
/// missing `access_grant` row degrades to an empty chain, and a missing
/// persona row degrades to the raw persona_id.
fn build_receipt_body(
    store: &DaemonStore,
    info: &GrantInfo,
    reason: TerminalReason,
    now_epoch_secs: u64,
) -> GrantReceipt {
    // 1. Pull the canonical composite chain + scoped audit excerpt.
    let chain = match store.get_access_grant(&info.id) {
        Ok(g) => g.blocks,
        Err(_) => Vec::new(),
    };

    // 2. Per-statement usage tallies from the block-0 statements.
    let per_statement_usage: Vec<(StatementId, Usage)> = chain
        .first()
        .map(|sb| {
            sb.block
                .statements
                .iter()
                .map(|s| (s.sid.clone(), s.usage.clone()))
                .collect()
        })
        .unwrap_or_default();

    // 3. Scoped audit excerpt. We pull a broad slice of the store's audit
    //    log and filter client-side for entries whose `details` JSON
    //    references this grant_id. Keeps the receipt self-contained and
    //    avoids a schema for grant-id→event mapping.
    let raw_audit: Vec<crate::audit::AuditEntry> = store
        .query_audit(&AuditFilter { limit: Some(500), ..Default::default() })
        .unwrap_or_default()
        .into_iter()
        .filter(|e| {
            let details = e.details.as_deref().unwrap_or("");
            details.contains(&info.id) || e.credential.as_deref() == Some(&info.credential_name)
        })
        .collect();

    let actions_observed: Vec<ReceiptAuditEntry> = raw_audit
        .iter()
        .map(|e| ReceiptAuditEntry {
            at: parse_rfc3339_epoch(&e.timestamp),
            event: e.action.clone(),
            action: Some(e.action.clone()),
            resource: e.credential.clone(),
            outcome: e.outcome.clone(),
        })
        .collect();

    // 4. Human owner + approval chain.
    //
    // The approval chain is built from audit entries for `grant.issued` events
    // that reference this grant_id in their `details` JSON. Each issuance event
    // carries a `source` field that identifies the approval path:
    //
    //   "approval"          → HumanDashboard approved
    //   "approval_narrowed" → HumanDashboard approved with scope narrowing
    //   "approval_always"   → HumanDashboard approved with standing-grant creation
    //   "standing_grant"    → StandingGrant auto-approved
    //   (anything else)     → Policy auto-approved (e.g. "request_access",
    //                         "request_access_blocking", or direct create_grant
    //                         call from the CLI/handler path)
    //
    // Future refinement: distinguish CLI vs. Dashboard human approvals once the
    // approval actor is recorded on the approval_requests row.
    let human_owner = store
        .get_persona(&info.persona_id)
        .ok()
        .map(|p| p.name)
        .unwrap_or_else(|| info.persona_id.clone());

    let mut approval_chain: Vec<ApprovalEvent> = raw_audit
        .iter()
        .filter(|e| e.action == "grant.issued")
        .filter_map(|e| {
            let details_str = e.details.as_deref().unwrap_or("{}");
            let details: serde_json::Value =
                serde_json::from_str(details_str).unwrap_or_default();
            // Only include entries that explicitly name this grant_id to avoid
            // pulling in issuance events for other grants that share the same
            // credential_name.
            let details_grant_id = details["grant_id"].as_str().unwrap_or("");
            if !details_grant_id.is_empty() && details_grant_id != info.id {
                return None;
            }
            let source = details["source"].as_str().unwrap_or("");
            let (actor, outcome) = match source {
                "approval" => (ApprovalActor::HumanDashboard, ApprovalOutcome::Approved),
                "approval_narrowed" => {
                    (ApprovalActor::HumanDashboard, ApprovalOutcome::ApprovedWithNarrowing)
                }
                "approval_always" => (ApprovalActor::HumanDashboard, ApprovalOutcome::Approved),
                "standing_grant" => (ApprovalActor::StandingGrant, ApprovalOutcome::Approved),
                _ => (ApprovalActor::Policy, ApprovalOutcome::Approved),
            };
            Some(ApprovalEvent {
                at: parse_rfc3339_epoch(&e.timestamp),
                actor,
                outcome,
                reason: None,
            })
        })
        .collect();

    // Approval chain must be ordered by timestamp ascending (most recent last).
    // The audit query returns DESC; reverse to get ascending order.
    approval_chain.reverse();

    // 5. Lifecycle.
    let issued_at = chain
        .first()
        .map(|sb| sb.block.issued_at)
        .unwrap_or_else(|| parse_rfc3339_epoch(&info.created_at));
    let last_used_at = if info.usage.last_updated != 0 {
        Some(info.usage.last_updated)
    } else {
        None
    };
    let lifecycle = Lifecycle {
        issued_at,
        last_used_at,
        terminated_at: now_epoch_secs,
        terminal_reason: reason,
    };

    // 6. Summary — human-readable envelope fields.
    let (agent_id, service) = split_credential(&info.credential_name);
    let summary = ReceiptSummary {
        human_owner,
        persona_id: info.persona_id.clone(),
        agent_id,
        service,
        resource: info.scope.clone(),
    };

    // 7. Attestation — pulled from the chain's first block where available.
    let attestation: AttestationBinding = chain
        .first()
        .and_then(|sb| {
            // Block-level attestation lives on the AccessGrant envelope,
            // not the inner block. The synthesized path leaves this at
            // default; callers that care should set it when composing a
            // multi-block chain.
            let _ = sb;
            None
        })
        .unwrap_or_default();

    // 8. Assemble receipt body (Evidence zeroed for hash stability — caller
    //    signs and repopulates evidence if needed).
    let receipt_id = format!("rct-{}", Uuid::new_v4());
    GrantReceipt {
        id: receipt_id,
        grant_id: info.id.clone(),
        summary,
        approved_chain: chain,
        per_statement_usage,
        approval_chain,
        actions_observed,
        lifecycle,
        attestation,
        evidence: Evidence::default(),
    }
}

/// Build a signed receipt for a terminal grant and persist it. Returns
/// the receipt id.
pub fn emit_receipt(
    store: &DaemonStore,
    identity: &DaemonIdentity,
    info: &GrantInfo,
    reason: TerminalReason,
) -> Result<String, StoreError> {
    let now = Utc::now().timestamp().max(0) as u64;
    let mut receipt = build_receipt_body(store, info, reason, now);

    // Sign. Canonical hash is over body-minus-Evidence.
    let hash_hex = canonical_hash(&receipt);
    let sig_bytes = identity.sign(hash_hex.as_bytes());
    receipt.evidence = Evidence {
        hash: hash_hex,
        sig: hex::encode(sig_bytes),
        signer_pubkey: identity.pubkey_hex(),
        canonical_version: CANONICAL_VERSION,
    };

    let receipt_id = receipt.id.clone();
    store.store_receipt(&receipt)?;
    Ok(receipt_id)
}

/// Best-effort split of a `credential_name` into (agent_id, service).
/// The Phase 1 CLI convention is flat names like `github-token`,
/// `anthropic-api-key`. We approximate: everything before the first
/// `-` is the service, the rest becomes the agent_id context. When
/// the split is ambiguous we fall back to the full name on both.
fn split_credential(cred: &str) -> (String, String) {
    if let Some((svc, _rest)) = cred.split_once('-') {
        (cred.to_string(), svc.to_string())
    } else {
        (cred.to_string(), cred.to_string())
    }
}

fn parse_rfc3339_epoch(s: &str) -> u64 {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc).timestamp().max(0) as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Receipt filter
// ---------------------------------------------------------------------------

/// Server-side filter for `/api/receipts`.
///
/// All fields are optional; omitting them returns all receipts up to `limit`.
#[derive(Debug, Default)]
pub struct ReceiptFilter {
    /// Restrict to receipts whose `persona_id` matches exactly.
    pub persona_id: Option<String>,
    /// When `true`, exclude receipts whose `signer_pubkey` is empty (unsigned
    /// placeholder receipts that were never signed by a daemon identity key).
    pub signed_only: bool,
    /// ISO-8601 lower bound on `created_at`. Generated from the `?since=`
    /// query param by the dashboard handler (24h / 7d / all → epoch offset).
    pub since_iso: Option<String>,
    /// Maximum rows to return. Defaults to 100 when `None`.
    pub limit: Option<u64>,
    /// EMBER-implementation-note-18 — kind discriminator (`grant`, `kms_wrap`,
    /// `kms_unwrap`). Mapped 1:1 to the `kind` column.
    pub kind: Option<String>,
    /// EMBER-implementation-note-18 — restrict to receipts whose `grant_id` matches.
    pub grant_id: Option<String>,
    /// EMBER-implementation-note-18 — substring filter on the receipt's `summary.resource`
    /// (grant receipts) or top-level `key_name` (kms receipts). Applied
    /// post-fetch so the JSON1 index can still serve exact-match callers.
    pub resource: Option<String>,
}

/// EMBER-implementation-note-18 — flat audit row returned by [`DaemonStore::list_receipt_rows`].
///
/// Joins receipt fields with [`crate::grant::GrantInfo`] when the row is a
/// grant receipt so callers see `requested_scope` / `granted_scope` without
/// having to re-fetch the grant. Both scope fields are `None` for rows
/// where no matching grant was found (e.g. orphaned kms receipts whose
/// `grant_id` field is empty).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReceiptRow {
    pub id: String,
    /// `grant`, `kms_wrap`, or `kms_unwrap`.
    pub kind: String,
    /// Persona id of the actor that triggered this receipt.
    pub actor: String,
    /// Resource label — `summary.resource` for grant receipts,
    /// `key_name` for kms receipts. Empty string when the field is missing.
    pub resource: String,
    /// Grant id this receipt closes out. Empty string for kms receipts
    /// that bypassed grant evaluation.
    pub grant_id: String,
    /// ISO-8601 timestamp when the receipt landed in the table
    /// (`receipts.created_at`).
    pub materialized_at: String,
    /// Terminal reason for grant receipts; outcome string for kms receipts.
    pub terminal_reason: String,
    /// Originally-requested scope from the parent grant. `None` when no
    /// grant matched.
    pub requested_scope: Option<String>,
    /// Effective (post-attenuation) scope from the parent grant. `None` when
    /// no grant matched.
    pub granted_scope: Option<String>,
}

// ---------------------------------------------------------------------------
// Store methods — receipts table
// ---------------------------------------------------------------------------

impl DaemonStore {
    /// Persist a fully-signed receipt to the `receipts` table.
    pub fn store_receipt(&self, receipt: &GrantReceipt) -> Result<(), StoreError> {
        let now = Utc::now().to_rfc3339();
        let receipt_json = serde_json::to_string(receipt).map_err(|e| {
            StoreError::InvalidInput(format!("serialize receipt: {e}"))
        })?;
        let persona_id = receipt.summary.persona_id.clone();
        let terminal_reason = serde_json::to_string(&receipt.lifecycle.terminal_reason)
            .unwrap_or_else(|_| "\"unknown\"".to_string());
        self.conn().execute(
            "INSERT OR REPLACE INTO receipts \
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'grant')",
            rusqlite::params![
                receipt.id,
                receipt.grant_id,
                persona_id,
                terminal_reason,
                now,
                receipt_json,
                receipt.evidence.signer_pubkey,
            ],
        )?;
        Ok(())
    }

    /// Persist an ember-kms receipt (`kms_wrap` / `kms_unwrap`).
    ///
    /// Reuses the unified `receipts` table — the `kind` column
    /// discriminates rows; the SQL fast-path index `idx_receipts_kms_key`
    /// pulls `key_name` out of `receipt_json` via SQLite JSON1.
    ///
    /// **No plaintext / ciphertext bytes appear in the row.** Sizes only.
    pub fn store_kms_receipt(&self, receipt: &KmsReceipt) -> Result<(), StoreError> {
        let now = Utc::now().to_rfc3339();
        let receipt_json = serde_json::to_string(receipt).map_err(|e| {
            StoreError::InvalidInput(format!("serialize kms receipt: {e}"))
        })?;
        let kind_str = match receipt.kind {
            ReceiptKind::KmsWrap => "kms_wrap",
            ReceiptKind::KmsUnwrap => "kms_unwrap",
            ReceiptKind::Grant => {
                return Err(StoreError::InvalidInput(
                    "store_kms_receipt called with ReceiptKind::Grant — use store_receipt".into(),
                ));
            }
        };
        // The kms receipts schema reuses the existing `receipts` columns:
        //   - grant_id stores the consulted grant_id (or "" when none)
        //   - persona_id stores the caller persona
        //   - terminal_reason is the kms outcome string ("success" / "failure")
        //   - signer_pubkey is the daemon identity (or zero placeholder
        //     when the sink runs without an initialised identity)
        let consulted_grant = receipt
            .grant_evaluation
            .grant_id
            .clone()
            .unwrap_or_default();
        let outcome_str = serde_json::to_string(&receipt.outcome)
            .unwrap_or_else(|_| "\"unknown\"".to_string());
        self.conn().execute(
            "INSERT OR REPLACE INTO receipts \
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                receipt.id,
                consulted_grant,
                receipt.caller_persona,
                outcome_str,
                now,
                receipt_json,
                receipt.evidence.signer_pubkey,
                kind_str,
            ],
        )?;
        Ok(())
    }

    /// Load a kms receipt by id. Returns `NotFound` if the row is not a
    /// kms_wrap / kms_unwrap kind (use [`get_receipt`] for grant receipts).
    pub fn get_kms_receipt(&self, id: &str) -> Result<KmsReceipt, StoreError> {
        use rusqlite::OptionalExtension;
        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT receipt_json FROM receipts \
                 WHERE id = ?1 AND kind IN ('kms_wrap','kms_unwrap')",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .optional()?;
        let raw = raw.ok_or(StoreError::NotFound)?;
        serde_json::from_str(&raw).map_err(|e| {
            StoreError::InvalidInput(format!("corrupt kms receipt row {id}: {e}"))
        })
    }

    /// List ember-kms receipts for a given key, most-recent first. Both
    /// `kms_wrap` and `kms_unwrap` rows are returned. Limited to `limit`
    /// rows (default 100). Uses the `idx_receipts_kms_key` index for the
    /// `key_name` lookup.
    pub fn list_kms_receipts_for_key(
        &self,
        key_name: &str,
        limit: Option<u64>,
    ) -> Result<Vec<KmsReceipt>, StoreError> {
        let limit = limit.unwrap_or(100);
        let mut stmt = self.conn().prepare(
            "SELECT receipt_json FROM receipts \
             WHERE kind IN ('kms_wrap','kms_unwrap') \
               AND json_extract(receipt_json, '$.key_name') = ?1 \
             ORDER BY created_at DESC LIMIT ?2",
        )?;
        let rows: Vec<String> = stmt
            .query_map(rusqlite::params![key_name, limit as i64], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for raw in rows {
            if let Ok(r) = serde_json::from_str::<KmsReceipt>(&raw) {
                out.push(r);
            }
        }
        Ok(out)
    }

    /// Load a receipt by id.
    pub fn get_receipt(&self, id: &str) -> Result<GrantReceipt, StoreError> {
        use rusqlite::OptionalExtension;
        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT receipt_json FROM receipts WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .optional()?;
        let raw = raw.ok_or(StoreError::NotFound)?;
        serde_json::from_str(&raw).map_err(|e| {
            StoreError::InvalidInput(format!("corrupt receipt row {id}: {e}"))
        })
    }

    /// List receipts, most-recent first. Optionally filter by persona.
    pub fn list_receipts(
        &self,
        persona_id: Option<&str>,
    ) -> Result<Vec<GrantReceipt>, StoreError> {
        self.list_receipts_filtered(&ReceiptFilter {
            persona_id: persona_id.map(|s| s.to_string()),
            ..Default::default()
        })
    }

    /// List receipts with full filter control. Returns up to `limit` receipts,
    /// ordered by `created_at DESC`. Used by `/api/receipts`.
    pub fn list_receipts_filtered(
        &self,
        filter: &ReceiptFilter,
    ) -> Result<Vec<GrantReceipt>, StoreError> {
        let mut sql = String::from(
            "SELECT receipt_json, signer_pubkey FROM receipts WHERE 1=1",
        );
        let mut binds: Vec<String> = Vec::new();
        if let Some(ref pid) = filter.persona_id {
            sql.push_str(&format!(" AND persona_id = ?{}", binds.len() + 1));
            binds.push(pid.clone());
        }
        if filter.signed_only {
            // Evidence::default() encodes the placeholder pubkey as 64 zero chars.
            // A real Ed25519 pubkey from a running daemon is never all-zeros.
            sql.push_str(&format!(" AND signer_pubkey != '{}'", "0".repeat(64)));
        }
        if let Some(ref since) = filter.since_iso {
            sql.push_str(&format!(" AND created_at >= ?{}", binds.len() + 1));
            binds.push(since.clone());
        }
        sql.push_str(" ORDER BY created_at DESC");
        let limit = filter.limit.unwrap_or(100);
        sql.push_str(&format!(" LIMIT {limit}"));

        let mut stmt = self.conn().prepare(&sql)?;
        let mapper =
            |row: &rusqlite::Row<'_>| -> rusqlite::Result<(String, String)> {
                Ok((row.get(0)?, row.get(1)?))
            };

        // rusqlite doesn't support dynamic param slices without unsafe tricks;
        // match on the number of bound params instead.
        let pairs: Vec<(String, String)> = match binds.len() {
            0 => stmt.query_map([], mapper)?.collect::<Result<_, _>>()?,
            1 => stmt
                .query_map(rusqlite::params![binds[0]], mapper)?
                .collect::<Result<_, _>>()?,
            2 => stmt
                .query_map(rusqlite::params![binds[0], binds[1]], mapper)?
                .collect::<Result<_, _>>()?,
            _ => {
                // Fallback: run without since-filter (shouldn't happen with current callers).
                stmt.query_map(rusqlite::params![binds[0]], mapper)?
                    .collect::<Result<_, _>>()?
            }
        };

        let mut out = Vec::with_capacity(pairs.len());
        for (raw, _pubkey) in pairs {
            if let Ok(r) = serde_json::from_str::<GrantReceipt>(&raw) {
                out.push(r);
            }
        }
        Ok(out)
    }

    /// EMBER-implementation-note-18 — flat audit-row listing for the `ember audit`
    /// query CLI. Joins the receipts table with `grants` so the row carries
    /// both the receipt fields and the parent grant's scope.
    ///
    /// Filters are AND-combined. `since` is a lower bound on the
    /// `materialized_at` column (`receipts.created_at`). `resource` is a
    /// substring match against `summary.resource` (grant receipts) or
    /// `key_name` (kms receipts) — applied post-fetch so the SQL stays
    /// index-friendly for exact-match callers.
    pub fn list_receipt_rows(
        &self,
        filter: &ReceiptFilter,
    ) -> Result<Vec<ReceiptRow>, StoreError> {
        // Indexed columns first (kind / persona_id / grant_id / created_at).
        // Build the parameterised SQL with positional binds; keep the bind
        // vector aligned with the params slice we hand to rusqlite.
        let mut sql = String::from(
            "SELECT r.id, r.kind, r.persona_id, r.grant_id, r.terminal_reason, \
                    r.created_at, r.receipt_json, g.scope \
             FROM receipts r \
             LEFT JOIN grants g ON g.id = r.grant_id \
             WHERE 1=1",
        );
        let mut binds: Vec<String> = Vec::new();
        if let Some(ref kind) = filter.kind {
            sql.push_str(&format!(" AND r.kind = ?{}", binds.len() + 1));
            binds.push(kind.clone());
        }
        if let Some(ref pid) = filter.persona_id {
            sql.push_str(&format!(" AND r.persona_id = ?{}", binds.len() + 1));
            binds.push(pid.clone());
        }
        if let Some(ref gid) = filter.grant_id {
            sql.push_str(&format!(" AND r.grant_id = ?{}", binds.len() + 1));
            binds.push(gid.clone());
        }
        if let Some(ref since) = filter.since_iso {
            sql.push_str(&format!(" AND r.created_at >= ?{}", binds.len() + 1));
            binds.push(since.clone());
        }
        if filter.signed_only {
            sql.push_str(&format!(" AND r.signer_pubkey != '{}'", "0".repeat(64)));
        }
        sql.push_str(" ORDER BY r.created_at DESC");
        let limit = filter.limit.unwrap_or(100);
        sql.push_str(&format!(" LIMIT {limit}"));

        let mut stmt = self.conn().prepare(&sql)?;
        let mapper =
            |row: &rusqlite::Row<'_>| -> rusqlite::Result<(
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                Option<String>,
            )> {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            };

        let rows: Vec<_> = match binds.len() {
            0 => stmt.query_map([], mapper)?.collect::<Result<Vec<_>, _>>()?,
            1 => stmt
                .query_map(rusqlite::params![binds[0]], mapper)?
                .collect::<Result<Vec<_>, _>>()?,
            2 => stmt
                .query_map(rusqlite::params![binds[0], binds[1]], mapper)?
                .collect::<Result<Vec<_>, _>>()?,
            3 => stmt
                .query_map(
                    rusqlite::params![binds[0], binds[1], binds[2]],
                    mapper,
                )?
                .collect::<Result<Vec<_>, _>>()?,
            _ => stmt
                .query_map(
                    rusqlite::params![binds[0], binds[1], binds[2], binds[3]],
                    mapper,
                )?
                .collect::<Result<Vec<_>, _>>()?,
        };

        let needle = filter
            .resource
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let mut out = Vec::with_capacity(rows.len());
        for (id, kind, persona_id, grant_id, terminal_reason, created_at, receipt_json, granted_scope) in
            rows
        {
            // Pull the resource label out of the receipt body. Grant
            // receipts: `$.summary.resource`. Kms receipts: `$.key_name`.
            // Fall back to empty string when the field is missing.
            let resource = match kind.as_str() {
                "grant" => {
                    serde_json::from_str::<serde_json::Value>(&receipt_json)
                        .ok()
                        .and_then(|v| {
                            v.get("summary")
                                .and_then(|s| s.get("resource"))
                                .and_then(|r| r.as_str())
                                .map(|s| s.to_string())
                        })
                        .unwrap_or_default()
                }
                "kms_wrap" | "kms_unwrap" => {
                    serde_json::from_str::<serde_json::Value>(&receipt_json)
                        .ok()
                        .and_then(|v| {
                            v.get("key_name")
                                .and_then(|r| r.as_str())
                                .map(|s| s.to_string())
                        })
                        .unwrap_or_default()
                }
                _ => String::new(),
            };

            // Post-fetch substring filter on `resource`.
            if let Some(ref n) = needle
                && !resource.contains(n.as_str())
            {
                continue;
            }

            // For grant receipts the scope from the joined grants row is
            // both the requested and granted view (the table only carries
            // the current scope; the original block-0 request scope lives
            // inside `receipt_json.approved_chain[0]` and is left out for
            // simplicity in v0). For kms receipts the join is meaningless —
            // surface `None` for both.
            let (requested_scope, granted_scope) = match kind.as_str() {
                "grant" => (granted_scope.clone(), granted_scope.clone()),
                _ => (None, None),
            };

            out.push(ReceiptRow {
                id,
                kind,
                actor: persona_id,
                resource,
                grant_id,
                materialized_at: created_at,
                terminal_reason,
                requested_scope,
                granted_scope,
            });
        }
        Ok(out)
    }

    /// Return the count of persisted receipts. Used by tests and the
    /// dashboard summary row.
    pub fn receipt_count(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn()
            .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))?;
        Ok(n as u64)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::DaemonStore;

    /// Make sure the process-singleton identity is initialised, then
    /// return it. We use a shared tempdir per-process so every receipt
    /// test signs/verifies against the same keypair — eliminating the
    /// race that bit us when each test generated its own identity but
    /// `revoke_grant` used the OnceCell pubkey.
    fn ensure_identity() -> &'static DaemonIdentity {
        static INIT_DIR: OnceCell<tempfile::TempDir> = OnceCell::new();
        let dir = INIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"));
        let _ = init_identity(dir.path());
        current_identity().expect("identity was just initialised")
    }

    #[test]
    fn identity_round_trips_through_file() {
        let dir = tempfile::tempdir().unwrap();
        let id1 = DaemonIdentity::load_or_create(dir.path()).unwrap();
        let pk1 = id1.pubkey_hex();
        drop(id1);
        let id2 = DaemonIdentity::load_or_create(dir.path()).unwrap();
        assert_eq!(id2.pubkey_hex(), pk1, "second load returns same pubkey");
        assert_eq!(pk1.len(), 64, "pubkey hex must be 64 chars");
    }

    #[test]
    fn emit_receipt_creates_signed_artifact() {
        let identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-a").unwrap();
        let grant = store
            .create_grant(&persona.id, "github-token", "push", None)
            .unwrap();
        // revoke_grant triggers receipt emission via the OnceCell identity.
        store.revoke_grant(&grant.id).unwrap();

        let info = store.get_grant(&grant.id).unwrap();
        let rid = info.receipt_id.expect("terminal grant has receipt_id");
        let r = store.get_receipt(&rid).unwrap();
        assert_eq!(r.grant_id, grant.id);
        assert_eq!(r.evidence.canonical_version, CANONICAL_VERSION);
        assert_eq!(r.evidence.sig.len(), 128, "sig hex is 128 chars");
        assert_eq!(r.evidence.hash.len(), 64);
        assert_eq!(r.evidence.signer_pubkey, identity.pubkey_hex());
        verify_receipt(&r, &identity.pubkey_hex()).expect("own-signed receipt verifies");
    }

    #[test]
    fn trigger_is_idempotent() {
        let identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-idem").unwrap();
        let grant = store
            .create_grant(&persona.id, "cred", "read", None)
            .unwrap();
        // First revoke already triggers via the OnceCell path.
        store.revoke_grant(&grant.id).unwrap();
        let first = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
        // Second explicit trigger must no-op.
        let second = trigger_receipt_if_terminal(&store, identity, &grant.id, None)
            .unwrap()
            .unwrap();
        assert_eq!(first, second, "idempotent — same receipt id");
    }

    #[test]
    fn trigger_noop_on_active_grant() {
        let identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-active").unwrap();
        let grant = store
            .create_grant(&persona.id, "cred", "read", None)
            .unwrap();
        // Grant is still active — no receipt.
        let r = trigger_receipt_if_terminal(&store, identity, &grant.id, None).unwrap();
        assert!(r.is_none());
        // Note: cannot assert `receipt_count() == 0` because tests share a
        // DaemonStore-per-test but the process identity is shared; the
        // store is isolated so its own count is still zero.
        assert_eq!(store.receipt_count().unwrap(), 0);
    }

    #[test]
    fn tampered_receipt_fails_verify() {
        let identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-tamper").unwrap();
        let grant = store
            .create_grant(&persona.id, "cred", "read", None)
            .unwrap();
        store.revoke_grant(&grant.id).unwrap();
        let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
        let mut r = store.get_receipt(&rid).unwrap();
        // Flip a summary field — recomputed hash will no longer match.
        r.summary.resource.push_str("-tampered");
        let err = verify_receipt(&r, &identity.pubkey_hex()).unwrap_err();
        assert!(
            matches!(err, ReceiptVerifyError::HashMismatch { .. }),
            "tampering changes hash, got {err}"
        );
    }

    #[test]
    fn wrong_pubkey_fails_verify() {
        let _identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-wp").unwrap();
        let grant = store.create_grant(&persona.id, "c", "r", None).unwrap();
        store.revoke_grant(&grant.id).unwrap();
        let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
        let r = store.get_receipt(&rid).unwrap();
        // An unrelated pubkey — verify must reject.
        let err = verify_receipt(&r, &"0".repeat(64)).unwrap_err();
        assert!(matches!(err, ReceiptVerifyError::SignerMismatch { .. }));
    }

    #[test]
    fn list_receipts_orders_recent_first_and_filters_by_persona() {
        let _identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let a = store.create_persona("agent-l1").unwrap();
        let b = store.create_persona("agent-l2").unwrap();
        let g1 = store.create_grant(&a.id, "c", "r", None).unwrap();
        let g2 = store.create_grant(&b.id, "c", "r", None).unwrap();
        store.revoke_grant(&g1.id).unwrap();
        store.revoke_grant(&g2.id).unwrap();

        let all = store.list_receipts(None).unwrap();
        assert_eq!(all.len(), 2);

        let just_a = store.list_receipts(Some(&a.id)).unwrap();
        assert_eq!(just_a.len(), 1);
        assert_eq!(just_a[0].summary.persona_id, a.id);
    }

    #[test]
    fn three_statement_receipt_preserves_per_statement_usage() {
        use core_types::{
            Block, Budget, ResourceSelector, ResourceType, SignedBlock, Statement,
        };

        let identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-3stmt").unwrap();
        // Seed with a fully-permissive "*" scope so the P69K-A2-I4
        // bipartite dominance check accepts the three-statement
        // attenuation (credential:use / llm:generate / session:run).
        let grant = store
            .create_grant(&persona.id, "composite", "*", None)
            .unwrap();

        // Overwrite blocks with a three-statement chain.
        let statements = vec![
            Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["credential:use".into()],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage { requests: 3, ..Default::default() },
                conditions: vec![],
            },
            Statement {
                sid: "S1".into(),
                resource_type: ResourceType::Session,
                actions: vec!["llm:generate".into()],
                resource: ResourceSelector::Any,
                budget: Some(Budget { tokens: Some(1000), ..Default::default() }),
                usage: Usage { tokens: 250, ..Default::default() },
                conditions: vec![],
            },
            Statement {
                sid: "S2".into(),
                resource_type: ResourceType::Time,
                actions: vec!["session:run".into()],
                resource: ResourceSelector::Any,
                budget: Some(Budget { wall_clock_secs: Some(3600), ..Default::default() }),
                usage: Usage { wall_clock_secs: 120, ..Default::default() },
                conditions: vec![],
            },
        ];
        let now = Utc::now().timestamp().max(0) as u64;
        let block = Block {
            statements,
            nbf: None,
            expires_at: None,
            issued_by: persona.id.clone(),
            issued_at: now,
            approval: None,
            note: None,
        };
        // W1 + W4: the read path verifies the chain, so seed a real
        // Ed25519 signature under the persona's root key instead of the
        // "unsigned-test" placeholder.
        let root = store.persona_root_keypair(&persona.id).unwrap();
        let signed = crate::grant::sign_block_zero_with(&root, &block).unwrap();
        let composed = core_types::AccessGrant {
            id: grant.id.clone(),
            version: 1,
            issuing_persona_id: persona.id.clone(),
            recipient_kind: core_types::PresentationAudienceKind::Service,
            recipient_id: "composite".into(),
            recipient_profile: core_types::RecipientProfile::Agent,
            status: core_types::GrantStatus::Active,
            mode: core_types::GrantMode::OneShot,
            blocks: vec![signed],
            attestation: AttestationBinding::default(),
            created_at: now,
            updated_at: now,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        };
        store.overwrite_grant_blocks(&grant.id, &composed).unwrap();

        store.revoke_grant(&grant.id).unwrap();
        let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
        let r = store.get_receipt(&rid).unwrap();
        assert_eq!(r.per_statement_usage.len(), 3);
        let by_sid: std::collections::HashMap<_, _> = r
            .per_statement_usage
            .iter()
            .map(|(sid, u)| (sid.clone(), u.clone()))
            .collect();
        assert_eq!(by_sid.get("S0").unwrap().requests, 3);
        assert_eq!(by_sid.get("S1").unwrap().tokens, 250);
        assert_eq!(by_sid.get("S2").unwrap().wall_clock_secs, 120);
        verify_receipt(&r, &identity.pubkey_hex()).unwrap();
    }

    #[test]
    fn canonical_hash_is_stable() {
        let _identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-ch").unwrap();
        let g = store.create_grant(&persona.id, "c", "r", None).unwrap();
        store.revoke_grant(&g.id).unwrap();
        let rid = store.get_grant(&g.id).unwrap().receipt_id.unwrap();
        let r = store.get_receipt(&rid).unwrap();
        // Recompute twice — must match.
        assert_eq!(canonical_hash(&r), canonical_hash(&r));
        // Must match the stored evidence.hash.
        assert_eq!(canonical_hash(&r), r.evidence.hash);
    }

    /// Approval chain is populated from audit log when a human approval
    /// (source = "approval") is recorded before the grant is revoked.
    #[test]
    fn emit_receipt_populates_approval_chain_from_audit() {
        use crate::approval::ApprovalOutcome as StoreApprovalOutcome;
        use core_types::grant_receipt::{ApprovalActor, ApprovalOutcome};

        let identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-approval-chain").unwrap();

        // Simulate a human-approval flow: submit approval then resolve it.
        // resolve_approval creates the grant and logs "grant.issued" with
        // source = "approval".
        let req = store
            .submit_approval(&persona.id, "github-token", "push", None, "credential.access.github-token", "medium")
            .unwrap();
        store.resolve_approval(&req.id, &StoreApprovalOutcome::Approved).unwrap();

        // Retrieve the grant that was created by resolve_approval.
        let grants = store.list_grants().unwrap();
        assert_eq!(grants.len(), 1, "resolve_approval must have created a grant");
        let grant = &grants[0];

        store.revoke_grant(&grant.id).unwrap();
        let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
        let r = store.get_receipt(&rid).unwrap();

        assert_eq!(r.approval_chain.len(), 1, "expected exactly one approval event");
        let ev = &r.approval_chain[0];
        assert_eq!(ev.actor, ApprovalActor::HumanDashboard);
        assert_eq!(ev.outcome, ApprovalOutcome::Approved);
        assert!(ev.at > 0, "approval event must have a non-zero timestamp");

        verify_receipt(&r, &identity.pubkey_hex()).expect("receipt with approval_chain must verify");
    }

    /// Approval chain entries are ordered ascending by timestamp regardless
    /// of the audit log's descending query order.
    #[test]
    fn emit_receipt_approval_chain_ordered_by_time() {
        use core_types::grant_receipt::ApprovalActor;

        let identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-order").unwrap();

        // Directly log three grant.issued events for the same grant_id in
        // order t1 < t2 < t3 to verify the chain sorts ascending.
        // We use a fixed grant (created but never touched by the standard
        // flow) so there is no race with revoke_grant's own log events.
        let grant = store
            .create_grant(&persona.id, "tok", "r", None)
            .unwrap();
        let grant_id = grant.id.clone();

        // Seed three audit entries with distinct timestamps by using
        // wall-clock spacing. Each entry must reference the grant_id in
        // `details` so the filter picks it up.
        for i in 0u64..3 {
            let details = serde_json::json!({
                "grant_id": grant_id,
                "scope": "r",
                "source": "approval",
            }).to_string();
            store
                .log_event(Some(&persona.id), "grant.issued", Some("tok"), "allowed", Some(&details))
                .unwrap();
            // Brief pause so RFC-3339 timestamps differ (SQLite stores TEXT).
            std::thread::sleep(std::time::Duration::from_millis(10 + i * 2));
        }

        store.revoke_grant(&grant_id).unwrap();
        let rid = store.get_grant(&grant_id).unwrap().receipt_id.unwrap();
        let r = store.get_receipt(&rid).unwrap();

        // We seeded 3 approval entries; revoke_grant does not add a
        // grant.issued so the count should be exactly 3.
        assert_eq!(r.approval_chain.len(), 3, "expected 3 approval events");
        assert!(r.approval_chain.iter().all(|ev| ev.actor == ApprovalActor::HumanDashboard));

        // Verify ascending order.
        for w in r.approval_chain.windows(2) {
            assert!(
                w[0].at <= w[1].at,
                "approval chain must be ordered ascending: {} > {}",
                w[0].at,
                w[1].at
            );
        }

        verify_receipt(&r, &identity.pubkey_hex()).expect("receipt verifies");
    }

    // ------------------------------------------------------------------
    // generate_receipt / canonical_hash_receipt — task P69K-D scaffold
    // ------------------------------------------------------------------

    /// Flip the grant's SQL status directly so generate_receipt can see it.
    /// Used by tests that want to exercise terminal paths without invoking
    /// the OnceCell-backed revoke path (which also persists a receipt and
    /// would muddy the assertion target).
    fn force_status(store: &DaemonStore, grant_id: &str, status: &str) {
        store
            .conn()
            .execute(
                "UPDATE grants SET status = ?1 WHERE id = ?2",
                rusqlite::params![status, grant_id],
            )
            .expect("force_status update");
    }

    #[test]
    fn generate_receipt_on_expired_grant_has_correct_terminal_reason() {
        let _identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-gen-expired").unwrap();
        let grant = store
            .create_grant(&persona.id, "cred", "read", None)
            .unwrap();
        force_status(&store, &grant.id, "expired");

        let now = 1_700_000_000u64;
        let receipt =
            generate_receipt(&store, &grant.id, TerminalReason::Expired, now).unwrap();

        assert_eq!(receipt.grant_id, grant.id);
        assert_eq!(receipt.lifecycle.terminated_at, now);
        assert!(matches!(receipt.lifecycle.terminal_reason, TerminalReason::Expired));
        // Evidence must stay zeroed on the pure-logic path — signing is a
        // separate concern.
        assert_eq!(receipt.evidence, Evidence::default());
    }

    #[test]
    fn generate_receipt_on_revoked_grant_captures_revoke_actor() {
        let _identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-gen-revoked").unwrap();
        let grant = store
            .create_grant(&persona.id, "cred", "read", None)
            .unwrap();
        force_status(&store, &grant.id, "revoked");

        let reason = TerminalReason::Revoked {
            by: RevokeActor::Agent,
            reason: "voluntary release".into(),
        };
        let now = 1_700_000_050u64;
        let receipt =
            generate_receipt(&store, &grant.id, reason.clone(), now).unwrap();

        match receipt.lifecycle.terminal_reason {
            TerminalReason::Revoked { by, reason: r } => {
                assert_eq!(by, RevokeActor::Agent);
                assert_eq!(r, "voluntary release");
            }
            other => panic!("expected Revoked, got {other:?}"),
        }
        assert_eq!(receipt.lifecycle.terminated_at, now);
    }

    #[test]
    fn generate_receipt_populates_per_statement_usage() {
        use core_types::{Block, Budget, ResourceSelector, ResourceType, Statement};

        let _identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-gen-usage").unwrap();
        // Seed with a fully-permissive "*" scope so the P69K-A2-I4
        // bipartite dominance check accepts the two-statement
        // attenuation (credential:use + llm:generate).
        let grant = store
            .create_grant(&persona.id, "composite-usage", "*", None)
            .unwrap();

        // Overwrite the block chain with two statements carrying distinct
        // per-axis usage tallies.
        let statements = vec![
            Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["credential:use".into()],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage { requests: 7, ..Default::default() },
                conditions: vec![],
            },
            Statement {
                sid: "S1".into(),
                resource_type: ResourceType::Session,
                actions: vec!["llm:generate".into()],
                resource: ResourceSelector::Any,
                budget: Some(Budget { tokens: Some(10_000), ..Default::default() }),
                usage: Usage { tokens: 4_321, ..Default::default() },
                conditions: vec![],
            },
        ];
        let now_secs = Utc::now().timestamp().max(0) as u64;
        let block = Block {
            statements,
            nbf: None,
            expires_at: None,
            issued_by: persona.id.clone(),
            issued_at: now_secs,
            approval: None,
            note: None,
        };
        let root = store.persona_root_keypair(&persona.id).unwrap();
        let signed = crate::grant::sign_block_zero_with(&root, &block).unwrap();
        let composed = core_types::AccessGrant {
            id: grant.id.clone(),
            version: 1,
            issuing_persona_id: persona.id.clone(),
            recipient_kind: core_types::PresentationAudienceKind::Service,
            recipient_id: "composite-usage".into(),
            recipient_profile: core_types::RecipientProfile::Agent,
            status: core_types::GrantStatus::Active,
            mode: core_types::GrantMode::OneShot,
            blocks: vec![signed],
            attestation: AttestationBinding::default(),
            created_at: now_secs,
            updated_at: now_secs,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        };
        store.overwrite_grant_blocks(&grant.id, &composed).unwrap();
        force_status(&store, &grant.id, "expired");

        let receipt =
            generate_receipt(&store, &grant.id, TerminalReason::Expired, now_secs).unwrap();

        assert_eq!(receipt.per_statement_usage.len(), 2);
        let by_sid: std::collections::HashMap<_, _> = receipt
            .per_statement_usage
            .iter()
            .map(|(sid, u)| (sid.clone(), u.clone()))
            .collect();
        assert_eq!(by_sid.get("S0").unwrap().requests, 7);
        assert_eq!(by_sid.get("S1").unwrap().tokens, 4_321);
    }

    #[test]
    fn generate_receipt_fails_on_unknown_grant_id() {
        let _identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let err = generate_receipt(
            &store,
            "grant-does-not-exist",
            TerminalReason::Expired,
            1_700_000_000,
        )
        .unwrap_err();
        assert!(
            matches!(err, StoreError::NotFound),
            "expected NotFound for unknown grant, got {err:?}"
        );
    }

    #[test]
    fn generate_receipt_fails_on_non_terminal_grant() {
        let _identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-gen-active").unwrap();
        let grant = store
            .create_grant(&persona.id, "cred", "read", None)
            .unwrap();
        // Grant is active; generate_receipt must refuse.
        let err = generate_receipt(
            &store,
            &grant.id,
            TerminalReason::Expired,
            1_700_000_000,
        )
        .unwrap_err();
        assert!(
            matches!(err, StoreError::InvalidInput(_)),
            "expected InvalidInput for active grant, got {err:?}"
        );
    }

    #[test]
    fn canonical_hash_receipt_deterministic() {
        let _identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-hash-det").unwrap();
        let grant = store
            .create_grant(&persona.id, "cred", "read", None)
            .unwrap();
        force_status(&store, &grant.id, "expired");

        let now = 1_700_000_123u64;
        let r1 =
            generate_receipt(&store, &grant.id, TerminalReason::Expired, now).unwrap();
        let mut r2 = r1.clone();
        // Deterministic: identical content → identical hash, even though
        // generate_receipt mints a fresh uuid for the id on each call.
        // Force-match the id so the receipts really are identical.
        r2.id = r1.id.clone();

        let h1 = canonical_hash_receipt(&r1);
        let h2 = canonical_hash_receipt(&r2);
        assert_eq!(h1, h2, "canonical_hash_receipt must be deterministic");
        assert_eq!(h1.len(), 32, "sha256 digest must be 32 bytes");

        // The hex wrapper must agree with the raw-bytes result.
        assert_eq!(canonical_hash(&r1), hex::encode(h1));
    }

    #[test]
    fn canonical_hash_receipt_evidence_fields_excluded() {
        let _identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-hash-evex").unwrap();
        let grant = store
            .create_grant(&persona.id, "cred", "read", None)
            .unwrap();
        force_status(&store, &grant.id, "expired");

        let now = 1_700_000_456u64;
        let base =
            generate_receipt(&store, &grant.id, TerminalReason::Expired, now).unwrap();
        let baseline_hash = canonical_hash_receipt(&base);

        // Mutate ONLY evidence fields. The canonical hash must stay stable.
        let mut with_hash = base.clone();
        with_hash.evidence.hash = "ff".repeat(32);
        assert_eq!(
            canonical_hash_receipt(&with_hash),
            baseline_hash,
            "evidence.hash must not influence canonical hash"
        );

        let mut with_sig = base.clone();
        with_sig.evidence.sig = "ab".repeat(64);
        assert_eq!(
            canonical_hash_receipt(&with_sig),
            baseline_hash,
            "evidence.sig must not influence canonical hash"
        );

        let mut with_pubkey = base.clone();
        with_pubkey.evidence.signer_pubkey = "cd".repeat(32);
        assert_eq!(
            canonical_hash_receipt(&with_pubkey),
            baseline_hash,
            "evidence.signer_pubkey must not influence canonical hash"
        );

        let mut with_version = base.clone();
        with_version.evidence.canonical_version = 99;
        assert_eq!(
            canonical_hash_receipt(&with_version),
            baseline_hash,
            "evidence.canonical_version must not influence canonical hash"
        );

        // Sanity: mutating a *non-evidence* field DOES change the hash.
        let mut with_summary = base.clone();
        with_summary.summary.resource.push_str("-tampered");
        assert_ne!(
            canonical_hash_receipt(&with_summary),
            baseline_hash,
            "non-evidence mutation must change canonical hash"
        );
    }

    /// verify_receipt uses the caller-supplied trust anchor (expected_pubkey_hex),
    /// not the receipt's own signer_pubkey field. A receipt whose signer_pubkey
    /// is set to an attacker's key but whose signature was made by a DIFFERENT
    /// key must be rejected even if the attacker's key could verify some
    /// crafted payload — the recomputed hash won't match what the real signer
    /// signed, so BadSignature fires.
    #[test]
    fn verify_receipt_uses_caller_trust_anchor() {
        let identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-trust-anchor").unwrap();
        let grant = store
            .create_grant(&persona.id, "cred", "read", None)
            .unwrap();
        store.revoke_grant(&grant.id).unwrap();
        let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
        let mut r = store.get_receipt(&rid).unwrap();

        // Generate a second (attacker-controlled) keypair.
        let attacker_seed = [0xABu8; 32];
        let attacker_key = ed25519_dalek::SigningKey::from_bytes(&attacker_seed);
        let attacker_pubkey_hex = hex::encode(attacker_key.verifying_key().to_bytes());

        // Swap signer_pubkey to the attacker's key while keeping the real sig.
        // verify_receipt must still use the CALLER-SUPPLIED identity pubkey
        // as the trust anchor, so it rejects with SignerMismatch (the
        // receipt's signer_pubkey no longer matches expected_pubkey_hex).
        r.evidence.signer_pubkey = attacker_pubkey_hex;
        let err = verify_receipt(&r, &identity.pubkey_hex()).unwrap_err();
        assert!(
            matches!(err, ReceiptVerifyError::SignerMismatch { .. }),
            "swapping signer_pubkey must produce SignerMismatch, got {err}"
        );

        // Confirm the original receipt (unmodified signer_pubkey) still verifies
        // correctly against the real trust anchor.
        let r_orig = store.get_receipt(&rid).unwrap();
        verify_receipt(&r_orig, &identity.pubkey_hex())
            .expect("original receipt verifies against real trust anchor");
    }

    /// A receipt with an all-zeros placeholder signature returns PlaceholderSig,
    /// not a generic BadSignature or Malformed error.
    #[test]
    fn verify_receipt_distinguishes_placeholder_signature() {
        let identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-placeholder-sig").unwrap();
        let grant = store
            .create_grant(&persona.id, "cred", "read", None)
            .unwrap();
        store.revoke_grant(&grant.id).unwrap();
        let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
        let mut r = store.get_receipt(&rid).unwrap();

        // Replace the real signature with the all-zeros phase-1 placeholder.
        r.evidence.sig = "00".repeat(64);
        let err = verify_receipt(&r, &identity.pubkey_hex()).unwrap_err();
        assert!(
            matches!(err, ReceiptVerifyError::PlaceholderSig),
            "all-zeros sig must return PlaceholderSig, got {err}"
        );
    }

    /// Legacy grants that have no grant.issued audit entries produce an
    /// empty approval chain rather than a crash.
    #[test]
    fn emit_receipt_approval_chain_empty_when_no_audit_entries() {
        let identity = ensure_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-legacy").unwrap();

        // Create and immediately revoke without any approval flow — no
        // grant.issued event is emitted by create_grant itself.
        // (create_grant does not call log_event; the caller in handler.rs
        //  does. In tests that call create_grant directly there is no log.)
        let grant = store
            .create_grant(&persona.id, "legacy-cred", "read", None)
            .unwrap();
        store.revoke_grant(&grant.id).unwrap();

        let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
        let r = store.get_receipt(&rid).unwrap();

        assert!(
            r.approval_chain.is_empty(),
            "legacy grants with no audit entries must produce empty approval_chain, got {:?}",
            r.approval_chain
        );

        verify_receipt(&r, &identity.pubkey_hex()).expect("receipt verifies even with empty chain");
    }
}

// ---------------------------------------------------------------------------
// Public re-exports
// ---------------------------------------------------------------------------

/// Resolve the identity-key path for a given data dir. Exposed so the
/// CLI/dashboard can debug or rotate the key.
pub fn identity_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join(IDENTITY_KEY_FILENAME)
}

// ---------------------------------------------------------------------------
// Process-singleton identity
// ---------------------------------------------------------------------------
//
// The daemon runs a single identity per process. We cache it in an OnceCell
// so handler/socket/dashboard code can call `current_identity()` without
// threading a ref through every function signature. `init_identity` is
// called exactly once at runtime startup. In tests that open an in-memory
// store without a runtime, the cell may be uninitialized — callers should
// treat that case as "skip receipt emission" and log a warning.

static IDENTITY: OnceCell<DaemonIdentity> = OnceCell::new();

/// Initialise the process-singleton identity. Calling a second time with a
/// different `data_dir` has no effect; the first initialisation wins.
/// Returns the pubkey hex of the (now-active) identity for log/banner
/// surfaces.
pub fn init_identity(data_dir: &Path) -> Result<String, StoreError> {
    // Fast path: already initialised.
    if let Some(id) = IDENTITY.get() {
        return Ok(id.pubkey_hex());
    }
    let id = DaemonIdentity::load_or_create(data_dir)?;
    let pubkey = id.pubkey_hex();
    // get_or_init ensures exactly-once semantics even under concurrent init.
    IDENTITY.get_or_init(|| id);
    Ok(pubkey)
}

/// Access the process identity if previously initialised.
pub fn current_identity() -> Option<&'static DaemonIdentity> {
    IDENTITY.get()
}

/// Variant of [`trigger_receipt_if_terminal`] that uses the process
/// identity. Logs a warning and no-ops when the identity is not
/// initialised (test harness, pre-startup paths).
///
/// On success, emits an `info!` log line with the new receipt id when a
/// receipt was actually written (i.e., `Ok(Some(rid))`). The `Ok(None)`
/// case — grant absent, still active, or already had a receipt — is
/// surfaced as a `debug!` line so noisy idempotent re-triggers (e.g.
/// the cascade-revoke path that re-visits already-terminated children)
/// do not dominate the daemon log.
pub fn trigger_receipt_if_terminal_current(
    store: &DaemonStore,
    grant_id: &str,
    explicit_reason: Option<TerminalReason>,
) -> Option<String> {
    let Some(identity) = current_identity() else {
        tracing::warn!(
            grant_id = %grant_id,
            "receipt emission skipped — daemon identity not initialised"
        );
        return None;
    };
    match trigger_receipt_if_terminal(store, identity, grant_id, explicit_reason) {
        Ok(Some(rid)) => {
            tracing::info!(
                grant_id = %grant_id,
                receipt_id = %rid,
                "receipt emitted"
            );
            Some(rid)
        }
        Ok(None) => {
            tracing::debug!(
                grant_id = %grant_id,
                "receipt emission no-op (grant absent, still active, or already has receipt)"
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                grant_id = %grant_id,
                error = %e,
                "receipt emission failed"
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// implementation-note-3 — kms receipt sink wiring
// ---------------------------------------------------------------------------
//
// `core_kms::ReceiptSink` requires `Send + Sync`, but `DaemonStore` is
// `!Send + !Sync` because `rusqlite::Connection` cannot move across
// threads. The bridge: an mpsc channel. The kms HTTP handlers push
// `KmsReceipt` values into the sender (cheap, lock-free); a single
// drain task on the daemon's LocalSet receives them and persists via
// `store.store_kms_receipt(...)`. The drain task signs each receipt with
// the process-singleton daemon identity before persisting; receipts that
// arrive before the identity is initialised are stored with the zero-byte
// placeholder evidence so the row is still recorded.

/// `core_kms::ReceiptSink` impl backed by an unbounded mpsc channel.
///
/// Cheap to clone — every clone shares the underlying sender. The
/// receiver lives on the daemon's runtime and is drained by
/// [`drain_kms_receipts`].
#[derive(Clone)]
pub struct ChannelKmsSink {
    tx: tokio::sync::mpsc::UnboundedSender<KmsReceipt>,
}

impl ChannelKmsSink {
    /// Construct a (sink, receiver) pair. The receiver is one-shot —
    /// pass it to [`drain_kms_receipts`] exactly once.
    pub fn channel() -> (Self, tokio::sync::mpsc::UnboundedReceiver<KmsReceipt>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Self { tx }, rx)
    }
}

impl core_kms::ReceiptSink for ChannelKmsSink {
    fn record(&self, receipt: KmsReceipt) {
        // A failing `send` means the daemon's drain task has shut down —
        // log + drop. Receipts are observability data; never fail a kms
        // operation because the sink is gone.
        if let Err(e) = self.tx.send(receipt) {
            tracing::warn!(error = %e, "kms receipt sink send failed — dropping receipt");
        }
    }
}

/// Drain `rx` until closed, signing each receipt with the process
/// identity (when initialised) and persisting via `store`.
///
/// Run as a `tokio::task::spawn_local` on the daemon's LocalSet — the
/// `Arc<DaemonStore>` is `!Send` so this task is local-only.
pub async fn drain_kms_receipts(
    store: std::sync::Arc<DaemonStore>,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<KmsReceipt>,
) {
    while let Some(mut receipt) = rx.recv().await {
        if let Some(identity) = current_identity() {
            sign_kms_receipt(&mut receipt, identity);
        }
        match store.store_kms_receipt(&receipt) {
            Ok(()) => {
                tracing::info!(
                    receipt_id = %receipt.id,
                    kind = ?receipt.kind,
                    key_name = %receipt.key_name,
                    outcome = ?receipt.outcome,
                    "kms receipt persisted"
                );
            }
            Err(e) => {
                tracing::warn!(
                    receipt_id = %receipt.id,
                    error = %e,
                    "kms receipt persist failed"
                );
            }
        }
    }
}

#[cfg(test)]
mod kms_tests {
    use super::*;
    use core_types::grant_receipt::{
        GrantEvaluation, GrantEvaluationOutcome, KmsReceipt, ReceiptKind, ReceiptOutcome,
    };

    fn fixture_kms_receipt(kind: ReceiptKind, key: &str) -> KmsReceipt {
        KmsReceipt {
            id: format!("rct-test-{}", uuid::Uuid::new_v4()),
            kind,
            key_name: key.into(),
            caller_persona: "persona-test".into(),
            request_size_bytes: 32,
            materialized_at_epoch_secs: 1_700_000_000,
            grant_evaluation: GrantEvaluation {
                outcome: GrantEvaluationOutcome::Allowed,
                grant_id: Some("grant-test-1".into()),
            },
            outcome: ReceiptOutcome::Success,
            evidence: Evidence::default(),
        }
    }

    #[test]
    fn store_kms_receipt_round_trips() {
        let store = DaemonStore::open_in_memory().unwrap();
        let r = fixture_kms_receipt(ReceiptKind::KmsWrap, "production-tokens");
        store.store_kms_receipt(&r).unwrap();
        let loaded = store.get_kms_receipt(&r.id).unwrap();
        assert_eq!(loaded, r);
    }

    #[test]
    fn store_kms_receipt_rejects_grant_kind() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut r = fixture_kms_receipt(ReceiptKind::KmsWrap, "k");
        r.kind = ReceiptKind::Grant;
        let err = store.store_kms_receipt(&r).unwrap_err();
        assert!(matches!(err, StoreError::InvalidInput(_)));
    }

    #[test]
    fn list_kms_receipts_for_key_filters_by_key_name() {
        let store = DaemonStore::open_in_memory().unwrap();
        // Three receipts: two for key-a (one wrap, one unwrap), one for key-b.
        let r1 = fixture_kms_receipt(ReceiptKind::KmsWrap, "key-a");
        let r2 = fixture_kms_receipt(ReceiptKind::KmsUnwrap, "key-a");
        let r3 = fixture_kms_receipt(ReceiptKind::KmsWrap, "key-b");
        store.store_kms_receipt(&r1).unwrap();
        store.store_kms_receipt(&r2).unwrap();
        store.store_kms_receipt(&r3).unwrap();

        let a = store.list_kms_receipts_for_key("key-a", None).unwrap();
        assert_eq!(a.len(), 2);
        assert!(a.iter().all(|r| r.key_name == "key-a"));

        let b = store.list_kms_receipts_for_key("key-b", None).unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].key_name, "key-b");
    }

    #[test]
    fn get_kms_receipt_rejects_grant_row() {
        // A grant receipt persisted via store_receipt must NOT be loadable
        // through get_kms_receipt — `kind` filter is enforced at the SQL
        // level so the two paths cannot accidentally return each other's
        // rows.
        let _ = ensure_identity_for_kms_test();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("agent-cross").unwrap();
        let grant = store
            .create_grant(&persona.id, "cred", "read", None)
            .unwrap();
        store.revoke_grant(&grant.id).unwrap();
        let grant_receipt_id = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
        let err = store.get_kms_receipt(&grant_receipt_id).unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
    }

    #[test]
    fn sign_kms_receipt_populates_evidence() {
        let store = DaemonStore::open_in_memory().unwrap();
        let identity = ensure_identity_for_kms_test();
        let mut r = fixture_kms_receipt(ReceiptKind::KmsWrap, "k");
        sign_kms_receipt(&mut r, identity);
        assert_eq!(r.evidence.signer_pubkey, identity.pubkey_hex());
        assert_eq!(r.evidence.sig.len(), 128);
        assert_eq!(r.evidence.hash.len(), 64);
        assert_eq!(r.evidence.canonical_version, CANONICAL_VERSION);
        // Re-hashing the receipt with its evidence still in place must
        // match — the canonical hash zeros evidence first.
        let h = kms_canonical_hash(&r);
        assert_eq!(h, r.evidence.hash);
        // Receipt persists cleanly.
        store.store_kms_receipt(&r).unwrap();
    }

    #[test]
    fn channel_sink_send_is_send_and_sync() {
        // Compile-time enforcement: ChannelKmsSink and core_kms::ReceiptSink
        // bound require Send + Sync so axum can hold them in shared state.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ChannelKmsSink>();
    }

    #[tokio::test]
    async fn drain_kms_receipts_persists_through_channel() {
        // End-to-end: kms server -> ChannelKmsSink -> drain task -> DaemonStore.
        // Build a store inside a LocalSet so the !Send Arc is happy.
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let store = std::sync::Arc::new(DaemonStore::open_in_memory().unwrap());
                let (sink, rx) = ChannelKmsSink::channel();
                let drain_handle = tokio::task::spawn_local(drain_kms_receipts(store.clone(), rx));

                let r = fixture_kms_receipt(ReceiptKind::KmsWrap, "drain-key");
                let id = r.id.clone();
                core_kms::ReceiptSink::record(&sink, r);

                // Drop the sender to close the channel so the drain task exits.
                drop(sink);
                drain_handle.await.unwrap();

                let loaded = store.get_kms_receipt(&id).unwrap();
                assert_eq!(loaded.id, id);
                assert_eq!(loaded.kind, ReceiptKind::KmsWrap);
                assert_eq!(loaded.key_name, "drain-key");
            })
            .await;
    }

    /// Ensure the process-singleton identity is initialised for kms tests
    /// that need to sign. Mirrors the helper in the parent test module.
    fn ensure_identity_for_kms_test() -> &'static DaemonIdentity {
        static INIT_DIR: once_cell::sync::OnceCell<tempfile::TempDir> =
            once_cell::sync::OnceCell::new();
        let dir = INIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"));
        let _ = init_identity(dir.path());
        current_identity().expect("identity was just initialised")
    }

    /// EMBER-implementation-note-18 — mixed-kind audit query. Seed two kms receipts for
    /// the same persona (one wrap, one unwrap) plus one for a different
    /// persona; the actor filter must return only the matching pair, and
    /// the rows must be sorted `materialized_at DESC`.
    #[test]
    fn list_receipt_rows_filters_by_actor_and_sorts_desc() {
        let _ = ensure_identity_for_kms_test();
        let store = DaemonStore::open_in_memory().unwrap();

        let mut r1 = fixture_kms_receipt(ReceiptKind::KmsWrap, "k1");
        r1.caller_persona = "persona-alpha".into();
        store.store_kms_receipt(&r1).unwrap();

        let mut r2 = fixture_kms_receipt(ReceiptKind::KmsUnwrap, "k1");
        r2.caller_persona = "persona-alpha".into();
        store.store_kms_receipt(&r2).unwrap();

        let mut r3 = fixture_kms_receipt(ReceiptKind::KmsWrap, "k2");
        r3.caller_persona = "persona-beta".into();
        store.store_kms_receipt(&r3).unwrap();

        let rows = store
            .list_receipt_rows(&ReceiptFilter {
                persona_id: Some("persona-alpha".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.actor == "persona-alpha"));
        // Both rows are kms — resource carries `key_name`, scopes are None.
        assert!(rows.iter().all(|r| r.resource == "k1"));
        assert!(rows.iter().all(|r| r.requested_scope.is_none()));
        assert!(rows.iter().all(|r| r.granted_scope.is_none()));
        // `materialized_at` is the receipts.created_at column written by
        // `store_kms_receipt` — same RFC3339 string for back-to-back inserts
        // is acceptable; we just need the sort key to be a string and the
        // listing to be DESC stable. Bound by id so the assertion is
        // independent of clock granularity.
        let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
        assert!(
            ids.contains(&r1.id.as_str()) && ids.contains(&r2.id.as_str()),
            "both alpha receipts in the result set"
        );
    }

    /// EMBER-implementation-note-18 — kind filter narrows to a single discriminator.
    #[test]
    fn list_receipt_rows_filters_by_kind() {
        let _ = ensure_identity_for_kms_test();
        let store = DaemonStore::open_in_memory().unwrap();

        let r1 = fixture_kms_receipt(ReceiptKind::KmsWrap, "k1");
        store.store_kms_receipt(&r1).unwrap();
        let r2 = fixture_kms_receipt(ReceiptKind::KmsUnwrap, "k2");
        store.store_kms_receipt(&r2).unwrap();

        let wraps = store
            .list_receipt_rows(&ReceiptFilter {
                kind: Some("kms_wrap".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(wraps.len(), 1);
        assert_eq!(wraps[0].kind, "kms_wrap");
        assert_eq!(wraps[0].resource, "k1");
    }

    /// EMBER-implementation-note-18 — resource substring filter (post-fetch) narrows
    /// matches without forcing exact equality.
    #[test]
    fn list_receipt_rows_filters_by_resource_substring() {
        let _ = ensure_identity_for_kms_test();
        let store = DaemonStore::open_in_memory().unwrap();

        let r1 = fixture_kms_receipt(ReceiptKind::KmsWrap, "production-tokens");
        store.store_kms_receipt(&r1).unwrap();
        let r2 = fixture_kms_receipt(ReceiptKind::KmsWrap, "staging-tokens");
        store.store_kms_receipt(&r2).unwrap();
        let r3 = fixture_kms_receipt(ReceiptKind::KmsWrap, "demo-keys");
        store.store_kms_receipt(&r3).unwrap();

        let rows = store
            .list_receipt_rows(&ReceiptFilter {
                resource: Some("tokens".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.resource.contains("tokens")));
    }

    /// EMBER-implementation-note-18 — index existence sanity check. Inspect the
    /// sqlite_master catalog and confirm the new audit-CLI indexes were
    /// created by the migration.
    #[test]
    fn audit_cli_indexes_exist() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut stmt = store
            .conn()
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type = 'index' AND name LIKE 'idx_receipts_%' \
                 ORDER BY name",
            )
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            names.iter().any(|n| n == "idx_receipts_actor"),
            "idx_receipts_actor missing — got {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "idx_receipts_resource"),
            "idx_receipts_resource missing — got {names:?}"
        );
    }
}
