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
    BudgetAxis, Evidence, GrantReceipt, Lifecycle, ReceiptSummary, RevokeActor,
    TerminalReason,
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
    let mut cloned = receipt.clone();
    cloned.evidence = Evidence::default();
    let bytes = canonical_body_bytes(&cloned);
    hex::encode(Sha256::digest(&bytes))
}

/// Verify an Ed25519 signature against a pubkey (both hex) over the
/// canonical hash of the receipt body.
///
/// Returns `Ok(())` iff:
///   - `receipt.evidence.signer_pubkey` decodes to a valid 32-byte pubkey
///     matching `expected_pubkey_hex`;
///   - recomputed canonical hash matches `receipt.evidence.hash`;
///   - Ed25519 verify passes over the hash bytes.
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
    let recomputed = canonical_hash(receipt);
    if !recomputed.eq_ignore_ascii_case(&receipt.evidence.hash) {
        return Err(ReceiptVerifyError::HashMismatch {
            got: receipt.evidence.hash.clone(),
            recomputed,
        });
    }
    let pubkey_bytes = hex::decode(&receipt.evidence.signer_pubkey)
        .map_err(|e| ReceiptVerifyError::Malformed(format!("pubkey hex: {e}")))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ReceiptVerifyError::Malformed("pubkey length".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|e| ReceiptVerifyError::Malformed(format!("pubkey parse: {e}")))?;
    let sig_bytes = hex::decode(&receipt.evidence.sig)
        .map_err(|e| ReceiptVerifyError::Malformed(format!("sig hex: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ReceiptVerifyError::Malformed("sig length".into()))?;
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

/// Build a signed receipt for a terminal grant and persist it. Returns
/// the receipt id.
pub fn emit_receipt(
    store: &DaemonStore,
    identity: &DaemonIdentity,
    info: &GrantInfo,
    reason: TerminalReason,
) -> Result<String, StoreError> {
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
    let actions_observed: Vec<ReceiptAuditEntry> = store
        .query_audit(&AuditFilter { limit: Some(500), ..Default::default() })
        .unwrap_or_default()
        .into_iter()
        .filter(|e| {
            let details = e.details.as_deref().unwrap_or("");
            details.contains(&info.id) || e.credential.as_deref() == Some(&info.credential_name)
        })
        .map(|e| ReceiptAuditEntry {
            at: parse_rfc3339_epoch(&e.timestamp),
            event: e.action.clone(),
            action: Some(e.action),
            resource: e.credential,
            outcome: e.outcome,
        })
        .collect();

    // 4. Human owner + approval chain (best-effort; Phase 1 persona record
    //    has no email, so we fall back to the persona display name).
    let human_owner = store
        .get_persona(&info.persona_id)
        .ok()
        .map(|p| p.name)
        .unwrap_or_else(|| info.persona_id.clone());

    let approval_chain: Vec<ApprovalEvent> = chain
        .iter()
        .filter_map(|sb| {
            sb.block.approval.as_ref().map(|_| ApprovalEvent {
                at: sb.block.issued_at,
                actor: ApprovalActor::HumanDashboard,
                outcome: ApprovalOutcome::Approved,
                reason: None,
            })
        })
        .collect();

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
    let terminated_at = Utc::now().timestamp().max(0) as u64;
    let lifecycle = Lifecycle {
        issued_at,
        last_used_at,
        terminated_at,
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

    // 8. Assemble receipt body (Evidence zeroed for hash stability).
    let receipt_id = format!("rct-{}", Uuid::new_v4());
    let mut receipt = GrantReceipt {
        id: receipt_id.clone(),
        grant_id: info.id.clone(),
        summary,
        approved_chain: chain,
        per_statement_usage,
        approval_chain,
        actions_observed,
        lifecycle,
        attestation,
        evidence: Evidence::default(),
    };

    // 9. Sign. Canonical hash is over body-minus-Evidence.
    let hash_hex = canonical_hash(&receipt);
    let sig_bytes = identity.sign(hash_hex.as_bytes());
    receipt.evidence = Evidence {
        hash: hash_hex,
        sig: hex::encode(sig_bytes),
        signer_pubkey: identity.pubkey_hex(),
        canonical_version: CANONICAL_VERSION,
    };

    // 10. Persist.
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
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
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
        let (sql, params_vec): (&str, Vec<&dyn rusqlite::ToSql>) = match persona_id {
            Some(_p) => (
                "SELECT receipt_json FROM receipts WHERE persona_id = ?1 \
                 ORDER BY created_at DESC",
                vec![&persona_id],
            ),
            None => (
                "SELECT receipt_json FROM receipts ORDER BY created_at DESC",
                Vec::new(),
            ),
        };
        // Rebuild params because `persona_id` in the outer `vec!` takes &Option<&str>.
        let mut stmt = self.conn().prepare(sql)?;
        let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<String> { row.get(0) };
        let rows: Vec<String> = match persona_id {
            Some(p) => stmt
                .query_map(rusqlite::params![p], mapper)?
                .collect::<Result<Vec<_>, _>>()?,
            None => stmt
                .query_map([], mapper)?
                .collect::<Result<Vec<_>, _>>()?,
        };
        let _ = params_vec; // silence unused — path chosen above
        let mut out = Vec::with_capacity(rows.len());
        for raw in rows {
            if let Ok(r) = serde_json::from_str::<GrantReceipt>(&raw) {
                out.push(r);
            }
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
        let grant = store
            .create_grant(&persona.id, "composite", "llm:generate", None)
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
pub fn trigger_receipt_if_terminal_current(
    store: &DaemonStore,
    grant_id: &str,
    explicit_reason: Option<TerminalReason>,
) -> Option<String> {
    let Some(identity) = current_identity() else {
        tracing::debug!(
            grant_id = %grant_id,
            "receipt emission skipped — daemon identity not initialised"
        );
        return None;
    };
    match trigger_receipt_if_terminal(store, identity, grant_id, explicit_reason) {
        Ok(rid) => rid,
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
