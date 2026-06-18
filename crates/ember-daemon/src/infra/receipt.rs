//! Grant Receipt emission — Stream D (ADR 072 §Evidence).
//!
//! Every terminal grant state (expired, revoked, abandoned, exhausted_by_budget,
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
//! `<data_dir>/daemon_persona.key` (mode 0600). The file holds 32 bytes
//! of raw Ed25519 secret key material. Published via
//! `GET /daemon/identity.json` as hex so external verifiers can compare
//! against their trust anchor.

// Receipt v2 issuance helper for cohort-A
// `session.claude_code` Receipts. Lives in the `receipt/` sibling
// directory; this `pub mod` declaration wires it under the existing
// `receipt` module path so callers see `ember_daemon::receipt::issue`.
// The v1 Grant Receipt code below remains untouched.
pub mod issue;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use core_event_types::ActionRef;
use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
use core_events::receipt::{
    RECEIPT_KIND_SERVICE_INSTALLED_V1, RECEIPT_KIND_SERVICE_UNINSTALLED_V1, ServiceInstalledBody,
    ServiceUninstalledBody,
};
use core_grant_types::grant_receipt::{
    ApprovalActor, ApprovalEvent, ApprovalOutcome, AuditEntry as ReceiptAuditEntry, BrokerReceipt,
    BudgetAxis, Evidence, GrantReceipt, KmsReceipt, Lifecycle, ReceiptKind, ReceiptOutcome,
    ReceiptSummary, RevokeActor, TerminalReason, VaultReceipt,
};
use core_grant_types::{AttestationBinding, StatementId, Usage};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use once_cell::sync::OnceCell;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::infra::audit::AuditFilter;
use crate::infra::claim_journal::close_grant_scope_best_effort;
use crate::infra::identity_substrate::daemon_signing_attribution;
use crate::infra::receipt::issue::{
    TerminationMeta, issue_session_receipt_from_closed_scope, stamp_signer_attribution,
};
// TODO: GrantInfo retained because emit_receipt, build_receipt_body,
// derive_reason, and generate_receipt all depend on GrantInfo fields (credential_name,
// created_at, expires_at as Strings, budget, parent_grant_id, status, persona_id).
// Migrate these functions to walk AccessGrant.blocks[].statements[] natively once
// the scalar-projection columns are removed from the SQLite schema.
use crate::infra::store::{DaemonStore, StoreError};
use crate::trust::grant::{GrantInfo, derive_wall_clock_secs};

/// Canonical-encoding prefix. Bump version AND
/// `Evidence::canonical_version` together if the encoding ever changes.
const CANONICAL_PREFIX: &str = "type=grant-receipt-v1\n";

/// Current canonical-encoding version. Mirrored into Evidence.
pub const CANONICAL_VERSION: u8 = 1;

/// Filename (under `data_dir`) where the daemon's long-lived identity key
/// is persisted. 32 bytes raw Ed25519 secret.
const IDENTITY_KEY_FILENAME: &str = "daemon_persona.key";

/// World-readable (mode 0644) pubkey sidecar published next to
/// `daemon_persona.key`. Lets cross-uid CLI callers (e.g. `ember
/// receipt tree` from a non-daemon uid under ADR 131's separate-uid
/// posture) read just the Ed25519 pubkey as the trust anchor for
/// offline-verify without needing read access to the 0600 private
/// key file. Cross-uid pubkey-sidecar read path, Option A.
const IDENTITY_PUBKEY_SIDECAR_FILENAME: &str = "daemon_persona.pub";

// ---------------------------------------------------------------------------
// Identity key
// ---------------------------------------------------------------------------

/// The daemon's long-lived identity key — the **Daemon Persona** signing key
/// per ADR 116.
///
/// Loaded on first access and cached. First-run generates a fresh
/// Ed25519 keypair and writes the 32-byte secret to
/// `<data_dir>/daemon_persona.key` with mode 0600. Subsequent loads
/// read the same file. This key signs every Grant Receipt; it is the
/// Daemon Persona signing key and is NOT used for any protocol message
/// outside of receipt Evidence.
///
/// # Zeroization (M1 security hardening — ZeroizeOnDrop_DaemonPersona)
///
/// `DaemonPersona` derives `ZeroizeOnDrop`. `SigningKey` (ed25519-dalek 2.x)
/// also implements `Zeroize`, so the secret scalar is cleared on drop.
/// `verifying_key` is public material and is skipped.
///
/// **OnceCell caveat:** the process-singleton `IDENTITY: OnceCell<DaemonPersona>`
/// (below) holds the key for the lifetime of the process and therefore `Drop`
/// is never called on the `DaemonPersona` stored inside it. Zeroization on
/// drop is still correct discipline for any non-singleton `DaemonPersona`
/// values (e.g. the temporary created in `load_or_create` before it is
/// moved into the cell, test instances). Future key-rotation/reload work
/// that replaces the cell value will benefit from this automatically.
#[derive(ZeroizeOnDrop)]
pub struct DaemonPersona {
    signing_key: SigningKey,
    #[zeroize(skip)]
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for DaemonPersona {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose signing_key material in Debug output.
        f.debug_struct("DaemonPersona")
            .field("pubkey_hex", &self.pubkey_hex())
            .finish_non_exhaustive()
    }
}

impl DaemonPersona {
    /// Load from `<data_dir>/daemon_persona.key`, generating on first run.
    pub fn load_or_create(data_dir: &Path) -> Result<Self, StoreError> {
        fs::create_dir_all(data_dir).map_err(|e| {
            StoreError::InvalidInput(format!("create data_dir for identity key: {e}"))
        })?;
        let path = data_dir.join(IDENTITY_KEY_FILENAME);
        if path.exists() {
            // M2 mode-check: refuse to load a key file that is wider than 0600.
            // daemon_persona_key_mode_refuse_world_readable — we do NOT auto-fix
            // the permissions so the operator can investigate how the file ended
            // up with insecure mode (backup restore, operator copy, crash, etc.).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = fs::metadata(&path).map_err(|e| {
                    StoreError::InvalidInput(format!(
                        "stat daemon identity key at {}: {e}",
                        path.display()
                    ))
                })?;
                let mode = meta.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(StoreError::KeyInsecureMode {
                        path: path.display().to_string(),
                        mode,
                    });
                }
            }

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
            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(&bytes);
            let signing_key = SigningKey::from_bytes(&seed);
            let verifying_key = signing_key.verifying_key();
            // Publish (or refresh) the 0644 pubkey sidecar so cross-uid
            // callers can resolve the trust anchor without 0600 read.
            // Anchor: receipt_tree_pubkey_cross_uid_safe
            write_pubkey_sidecar(data_dir, &verifying_key)?;
            Ok(Self {
                signing_key,
                verifying_key,
            })
        } else {
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut *seed).map_err(|e| {
                StoreError::InvalidInput(format!("OS RNG failure generating identity: {e}"))
            })?;
            write_identity_file(&path, &seed)?;
            let signing_key = SigningKey::from_bytes(&seed);
            let verifying_key = signing_key.verifying_key();
            // Publish the 0644 pubkey sidecar on first create — see
            // `IDENTITY_PUBKEY_SIDECAR_FILENAME` doc for rationale.
            // Anchor: receipt_tree_pubkey_cross_uid_safe
            write_pubkey_sidecar(data_dir, &verifying_key)?;
            Ok(Self {
                signing_key,
                verifying_key,
            })
        }
    }

    /// Ed25519 public key (32 bytes, hex-encoded, 64 chars).
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// The daemon identity-root fingerprint: `blake3(pubkey_hex)` as hex. This is
    /// the canonical string that binds an operator co-signature / presence intent
    /// to THIS daemon identity (refuses replay across daemon identities). Single
    /// source of truth shared by the audit-repair co-sign path
    /// (`audit::DaemonFingerprintMismatch`) and the presence-intent nonce
    /// (`presence/request_nonce` → `canonical_presence_intent_bytes`, ADR 200 §3).
    pub fn identity_root_fingerprint(&self) -> String {
        blake3::hash(self.pubkey_hex().as_bytes())
            .to_hex()
            .to_string()
    }

    /// Sign an arbitrary byte payload. Returns a `Zeroizing` wrapper so the
    /// 64-byte signature temp is scrubbed when the caller drops it.
    pub fn sign(&self, payload: &[u8]) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(self.signing_key.sign(payload).to_bytes())
    }

    /// Return the Ed25519 signing key seed (32 bytes) as a `Zeroizing` wrapper.
    ///
    /// Used by snapshot emission to derive the HKDF-SHA256 snapshot-encryption
    /// key (`HKDF-SHA256(seed, "emberlink/v1/ember-seal/snapshot-key")`) per
    /// ADR 115 §The primitive and the `core_crypto` HKDF registry. The
    /// EmberSeal X25519 recipient scalar derives from the same seed under a
    /// *distinct* info string so the two lanes are cryptographically
    /// independent (security review H2).
    /// The seed is NOT the private key scalar — it is the 32-byte input from
    /// which both the scalar and the nonce prefix are derived. The ed25519-dalek
    /// `to_bytes()` method returns these 32 bytes.
    ///
    /// The `Zeroizing` wrapper ensures the stack copy is scrubbed when the
    /// caller's binding goes out of scope.
    ///
    /// Treat the output as secret. Never log or expose outside the daemon.
    pub fn seed_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    #[cfg(test)]
    pub(crate) fn from_seed_for_test(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Ed25519 verifying key (raw 32 bytes) for external verifiers.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

/// Path to the world-readable pubkey sidecar that mirrors
/// `daemon_persona.key`'s public half. See
/// [`IDENTITY_PUBKEY_SIDECAR_FILENAME`] for rationale.
///
/// Anchor: receipt_tree_pubkey_cross_uid_safe
pub fn identity_pubkey_sidecar_path(data_dir: &Path) -> PathBuf {
    data_dir.join(IDENTITY_PUBKEY_SIDECAR_FILENAME)
}

/// Read the daemon's Ed25519 pubkey as hex from the world-readable
/// `daemon_persona.pub` sidecar. Cross-uid CLI callers (`ember
/// receipt tree` invoked by a non-daemon uid under ADR 131) use this
/// to resolve the offline-verify trust anchor without needing 0600
/// read access to the private key file.
///
/// Returns `Ok(<64-char hex>)` on success. Surfaces `StoreError` when
/// the sidecar is missing or unreadable so callers can fall back to
/// the legacy `DaemonPersona::load_or_create` path (used pre-sidecar
/// or in environments where the daemon has not yet started).
///
/// Anchor: receipt_tree_pubkey_cross_uid_safe
pub fn read_pubkey_sidecar_hex(data_dir: &Path) -> Result<String, StoreError> {
    let path = identity_pubkey_sidecar_path(data_dir);
    let raw = fs::read_to_string(&path).map_err(|e| {
        StoreError::InvalidInput(format!(
            "read daemon pubkey sidecar at {}: {e}",
            path.display()
        ))
    })?;
    let trimmed = raw.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(StoreError::InvalidInput(format!(
            "daemon pubkey sidecar at {} is not a 64-char hex string (got {} chars)",
            path.display(),
            trimmed.len()
        )));
    }
    Ok(trimmed.to_string())
}

/// Write the daemon's Ed25519 pubkey as hex into the world-readable
/// `daemon_persona.pub` sidecar at mode 0644. Idempotent — called
/// from both branches of `DaemonPersona::load_or_create` so a
/// running daemon's sidecar is always in sync with the key file.
fn write_pubkey_sidecar(data_dir: &Path, verifying_key: &VerifyingKey) -> Result<(), StoreError> {
    let path = identity_pubkey_sidecar_path(data_dir);
    let pubkey_hex = hex::encode(verifying_key.to_bytes());
    fs::write(&path, &pubkey_hex).map_err(|e| {
        StoreError::InvalidInput(format!(
            "write daemon pubkey sidecar to {}: {e}",
            path.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)
            .map_err(|e| StoreError::InvalidInput(format!("stat pubkey sidecar: {e}")))?
            .permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms)
            .map_err(|e| StoreError::InvalidInput(format!("chmod 0644 pubkey sidecar: {e}")))?;
    }
    Ok(())
}

/// Write the 32-byte secret to `path` with permissions 0600.
fn write_identity_file(path: &Path, secret: &[u8; 32]) -> Result<(), StoreError> {
    fs::write(path, secret).map_err(|e| {
        StoreError::InvalidInput(format!(
            "write daemon identity key to {}: {e}",
            path.display()
        ))
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
// kms receipt canonical-encoding + signing helpers
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
pub fn sign_kms_receipt(receipt: &mut KmsReceipt, identity: &DaemonPersona) {
    let hash_hex = kms_canonical_hash(receipt);
    let sig_bytes = identity.sign(hash_hex.as_bytes());
    receipt.evidence = Evidence {
        hash: hash_hex,
        sig: hex::encode(*sig_bytes),
        signer_pubkey: identity.pubkey_hex(),
        canonical_version: CANONICAL_VERSION,
    };
}

// ---------------------------------------------------------------------------
// broker receipt canonical-encoding + signing helpers
// ---------------------------------------------------------------------------

/// Canonical-encoding prefix for broker receipts. Distinct from
/// [`CANONICAL_PREFIX`] and [`KMS_CANONICAL_PREFIX`] so a broker receipt
/// can never be replayed against a grant-receipt or kms-receipt verifier
/// (cross-protocol signature reuse prevention).
const BROKER_CANONICAL_PREFIX: &str = "type=broker-receipt-v1\n";

/// Serialise a [`BrokerReceipt`] to canonical bytes (v1) — zero evidence,
/// JSON, prefixed.
fn broker_canonical_body_bytes(receipt_with_zero_evidence: &BrokerReceipt) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(BROKER_CANONICAL_PREFIX.as_bytes());
    let body = serde_json::to_vec(receipt_with_zero_evidence)
        .expect("BrokerReceipt with default Evidence always serializes");
    out.extend_from_slice(&body);
    out
}

/// Compute the canonical hash (sha256 hex) of a broker receipt body. Zeroes
/// evidence first so the result is independent of the caller's evidence field.
pub fn broker_canonical_hash(receipt: &BrokerReceipt) -> String {
    let mut cloned = receipt.clone();
    cloned.evidence = Evidence::default();
    let bytes = broker_canonical_body_bytes(&cloned);
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}

/// Sign a broker receipt in place using the daemon identity. Populates
/// `evidence.{hash, sig, signer_pubkey, canonical_version}`.
pub fn sign_broker_receipt(receipt: &mut BrokerReceipt, identity: &DaemonPersona) {
    let hash_hex = broker_canonical_hash(receipt);
    let sig_bytes = identity.sign(hash_hex.as_bytes());
    receipt.evidence = Evidence {
        hash: hash_hex,
        sig: hex::encode(*sig_bytes),
        signer_pubkey: identity.pubkey_hex(),
        canonical_version: CANONICAL_VERSION,
    };
}

// ---------------------------------------------------------------------------
// v2 broker envelope builders — Phase A substrate for the broker
// receipt v2 migration. Per ADR 118 §Envelope + ADR 133 §receipt-kind
// catalog ("broker.materialization", "broker.revocation").
//
// Returned envelopes are unsigned: callers wrap a Signer (e.g.
// `session::lifecycle::DaemonPersonaSigner`) and call
// `core_events::receipt::sign::sign_receipt_v2` to populate `receipt_id`
// + `signature`. Call-site migration is Phase B.
// ---------------------------------------------------------------------------

/// v2 kind discriminator — broker materialization. Per ADR 133.
///
/// Retained for back-compat reads of legacy `broker.materialization` receipt
/// rows and as the reserved kind for a future PROVIDER-signed materialization
/// receipt (ADR 205 §B.7). There is intentionally **no
/// `build_broker_materialization_envelope`**: per ADR 205 §B.6 a materialization
/// is an AUDIT event, not a Receipt — the daemon is the sole witness of the mint
/// and a daemon self-signature earns no root-verifiability, so the record lives
/// only in the hash-chained audit log (`emit_materialization_audit_event` →
/// `log_event`, broker `handler/materialization.rs`). Do not reintroduce a
/// daemon-signed materialization envelope.
pub const RECEIPT_KIND_BROKER_MATERIALIZATION: &str = "broker.materialization";
/// v2 kind discriminator — broker revocation. Per ADR 133.
pub const RECEIPT_KIND_BROKER_REVOCATION: &str = "broker.revocation";
/// v2 kind discriminator — ssh-agent-over-bridge session SSH-signing lease
/// grant (the authority decision, ADR 211/207 Slice 3). The `session.` prefix
/// routes it through [`DaemonStore::store_session_receipt_v2`]. This Receipt is
/// emitted ONCE at lease grant; each individual sign is an audit-log row, not a
/// receipt (`receipt_vs_audit_log`).
pub const RECEIPT_KIND_SSH_LEASE_GRANT: &str = "session.ssh_lease_grant";

/// Build an unsigned v2 [`ReceiptEnvelope`] for a broker revocation event.
/// `summary` is optional so the envelope can still be emitted when the
/// materialization is unknown to the daemon (matches v1's `Option`
/// posture in [`crate::broker::handler::emit_revocation_receipt`]).
///
/// `mock_broker` (dev/prod parity, mock-broker explicit / ADR 157 §Component 2):
/// `true` iff the registered broker for the provider revoking the
/// credential is a `MockBroker` instance. Stamped onto every
/// `broker.revocation` Receipt body for the same audit-signal reason as
/// the materialization envelope.
pub fn build_broker_revocation_envelope(
    materialization_id: &str,
    summary: Option<&crate::broker::handler::MaterializationSummary>,
    daemon_root_id: &str,
    mock_broker: bool,
) -> ReceiptEnvelope {
    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let provider = summary
        .map(|s| s.provider.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let reason = summary.map(|s| s.reason.clone()).unwrap_or_default();
    let body = serde_json::json!({
        "provider": provider,
        "materialization_id": materialization_id,
        "revoked_at_epoch_secs": now_epoch,
        "contract_id": summary.and_then(|s| s.contract_id.as_deref()),
        "action_ref": summary.and_then(|s| s.action_ref.clone()),
        "workspace_ref": summary.and_then(|s| s.workspace_ref.as_deref()),
        "subject_ref": summary.and_then(|s| s.subject_ref.as_deref()),
        "coordination_ref": summary.and_then(|s| s.coordination_ref.as_deref()),
        "caller_ref": summary.and_then(|s| s.caller_ref.as_deref()),
        "authority_ref": summary.and_then(|s| s.authority_ref.as_deref()),
        "reason": reason,
        // dev/prod parity, mock-broker explicit / ADR 157 §Component 2.
        "mock_broker": mock_broker,
    });
    ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_BROKER_REVOCATION.to_string(),
        receipt_id: String::new(),
        daemon_root_id: daemon_root_id.to_string(),
        traceparent: None,
        termination_authority: TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body,
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    }
}

/// Build an unsigned v2 [`ReceiptEnvelope`] for an ssh-agent-over-bridge SSH-
/// signing **lease grant** (ssh-agent-over-bridge Slice 3 — the authority
/// decision, ADR 211/207). The caller signs it with
/// [`core_events::receipt::sign::sign_receipt_v2`] and persists it via
/// [`DaemonStore::store_session_receipt_v2`].
///
/// The body records the time-box (lease bounds TIME, per the resolved design)
/// and the loaded key fingerprint (the key bounds TARGET); the repo is NOT in
/// the SSH handshake, so target attribution correlates from the egress log, not
/// this Receipt.
#[allow(clippy::too_many_arguments)]
pub fn build_ssh_lease_grant_envelope(
    session_id: &str,
    persona_id: &str,
    grant_id: &str,
    scope: &str,
    key_fingerprint_sha256: &str,
    granted_at_epoch_secs: u64,
    expires_at_epoch_secs: u64,
    daemon_root_id: &str,
) -> ReceiptEnvelope {
    let body = serde_json::json!({
        "session_id": session_id,
        "persona_id": persona_id,
        "grant_id": grant_id,
        "scope": scope,
        "key_fingerprint_sha256": key_fingerprint_sha256,
        "granted_at_epoch_secs": granted_at_epoch_secs,
        "expires_at_epoch_secs": expires_at_epoch_secs,
    });
    ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_SSH_LEASE_GRANT.to_string(),
        receipt_id: String::new(),
        daemon_root_id: daemon_root_id.to_string(),
        traceparent: None,
        termination_authority: TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body,
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    }
}

/// Verify an Ed25519 signature against a pubkey (both hex) over the
/// canonical hash of a broker receipt body.
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
pub fn verify_broker_receipt(
    receipt: &BrokerReceipt,
    expected_pubkey_hex: &str,
) -> Result<(), ReceiptVerifyError> {
    if receipt.evidence.canonical_version != CANONICAL_VERSION {
        return Err(ReceiptVerifyError::WrongVersion {
            got: receipt.evidence.canonical_version,
        });
    }
    let sig_bytes = hex::decode(&receipt.evidence.sig)
        .map_err(|e| ReceiptVerifyError::Malformed(format!("sig hex: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ReceiptVerifyError::Malformed("sig length".into()))?;
    if sig_arr == [0u8; 64] {
        return Err(ReceiptVerifyError::PlaceholderSig);
    }
    let recomputed = broker_canonical_hash(receipt);
    if !recomputed.eq_ignore_ascii_case(&receipt.evidence.hash) {
        return Err(ReceiptVerifyError::HashMismatch {
            got: receipt.evidence.hash.clone(),
            recomputed,
        });
    }
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

// ---------------------------------------------------------------------------
// vault receipt canonical-encoding + signing helpers
// ---------------------------------------------------------------------------

/// Canonical-encoding prefix for vault receipts. Distinct from
/// [`CANONICAL_PREFIX`], [`KMS_CANONICAL_PREFIX`], and
/// [`BROKER_CANONICAL_PREFIX`] so a vault receipt can never be replayed
/// against a grant-receipt, kms-receipt, or broker-receipt verifier
/// (cross-protocol signature reuse prevention).
pub const VAULT_CANONICAL_PREFIX: &str = "type=vault-receipt-v1\n";

/// Serialise a [`VaultReceipt`] to canonical bytes (v1) — zero evidence,
/// JSON, prefixed.
pub fn vault_canonical_body_bytes(receipt_with_zero_evidence: &VaultReceipt) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(VAULT_CANONICAL_PREFIX.as_bytes());
    let body = serde_json::to_vec(receipt_with_zero_evidence)
        .expect("VaultReceipt with default Evidence always serializes");
    out.extend_from_slice(&body);
    out
}

/// Compute the canonical hash (sha256 hex) of a vault receipt body. Zeroes
/// evidence first so the result is independent of the caller's evidence field.
pub fn vault_canonical_hash(receipt: &VaultReceipt) -> String {
    let mut cloned = receipt.clone();
    cloned.evidence = Evidence::default();
    let bytes = vault_canonical_body_bytes(&cloned);
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}

/// Sign a vault receipt in place using the daemon identity. Populates
/// `evidence.{hash, sig, signer_pubkey, canonical_version}`.
pub fn sign_vault_receipt(receipt: &mut VaultReceipt, identity: &DaemonPersona) {
    let hash_hex = vault_canonical_hash(receipt);
    let sig_bytes = identity.sign(hash_hex.as_bytes());
    receipt.evidence = Evidence {
        hash: hash_hex,
        sig: hex::encode(*sig_bytes),
        signer_pubkey: identity.pubkey_hex(),
        canonical_version: CANONICAL_VERSION,
    };
}

/// Kind string for the local, signed receipt emitted when a vault entry's
/// per-entry biometric gate approves a read.
pub const VAULT_BIOMETRIC_RECEIPT_KIND: &str = "vault_biometric_retrieval";

/// Canonical-encoding prefix for biometric vault-read receipts.
pub const VAULT_BIOMETRIC_CANONICAL_PREFIX: &str = "type=vault-biometric-receipt-v1\n";

/// Signed audit artifact for reads of entries whose [`PresencePolicy`] is
/// `PerAccessFresh` (formerly `requires_biometric=1` per
/// presence-policy unification).
///
/// This deliberately lives in the daemon receipt layer instead of widening the
/// legacy `core_grant_types::VaultReceipt` wire type. The original
/// `vault_retrieval` receipt remains backward-compatible; this companion
/// receipt records the fresh proof's verified authenticator.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultBiometricReceipt {
    pub id: String,
    pub kind: String,
    pub key_name: String,
    pub caller_persona: String,
    pub materialized_at_epoch_secs: u64,
    pub read_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    pub outcome: ReceiptOutcome,
    /// Operator-identity `device_id` for the enrolled presence Device whose
    /// public key verified the nonce-bound `_presence_proof`.
    pub presence_authenticator_id: String,
    /// SHA-256 of the enrolled presence Device public key. This is enough for
    /// offline disambiguation without duplicating the public key in every row.
    pub presence_public_key_hash: String,
    pub evidence: Evidence,
}

pub fn vault_biometric_canonical_body_bytes(
    receipt_with_zero_evidence: &VaultBiometricReceipt,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(384);
    out.extend_from_slice(VAULT_BIOMETRIC_CANONICAL_PREFIX.as_bytes());
    let body = serde_json::to_vec(receipt_with_zero_evidence)
        .expect("VaultBiometricReceipt with default Evidence always serializes");
    out.extend_from_slice(&body);
    out
}

pub fn vault_biometric_canonical_hash(receipt: &VaultBiometricReceipt) -> String {
    let mut cloned = receipt.clone();
    cloned.evidence = Evidence::default();
    let bytes = vault_biometric_canonical_body_bytes(&cloned);
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}

pub fn sign_vault_biometric_receipt(receipt: &mut VaultBiometricReceipt, identity: &DaemonPersona) {
    let hash_hex = vault_biometric_canonical_hash(receipt);
    let sig_bytes = identity.sign(hash_hex.as_bytes());
    receipt.evidence = Evidence {
        hash: hash_hex,
        sig: hex::encode(*sig_bytes),
        signer_pubkey: identity.pubkey_hex(),
        canonical_version: CANONICAL_VERSION,
    };
}

pub fn persist_vault_biometric_receipt(
    store: &DaemonStore,
    key_name: &str,
    caller_persona: &str,
    read_path: &str,
    grant_id: Option<&str>,
    presence_authenticator_id: &str,
    presence_public_key_hash: &str,
) -> Result<(), StoreError> {
    let materialized_at_epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut receipt = VaultBiometricReceipt {
        id: format!("rct-vault-bio-{}", Uuid::new_v4()),
        kind: VAULT_BIOMETRIC_RECEIPT_KIND.to_string(),
        key_name: key_name.to_string(),
        caller_persona: caller_persona.to_string(),
        materialized_at_epoch_secs,
        read_path: read_path.to_string(),
        grant_id: grant_id.map(str::to_string),
        outcome: ReceiptOutcome::Success,
        presence_authenticator_id: presence_authenticator_id.to_string(),
        presence_public_key_hash: presence_public_key_hash.to_string(),
        evidence: Evidence::default(),
    };
    if let Some(identity) = current_identity() {
        sign_vault_biometric_receipt(&mut receipt, identity);
    }
    store.store_vault_biometric_receipt(&receipt)
}

/// Verify an Ed25519 signature against a pubkey (hex) over the canonical
/// hash of a vault receipt body.
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
pub fn verify_vault_receipt(
    receipt: &VaultReceipt,
    expected_pubkey_hex: &str,
) -> Result<(), ReceiptVerifyError> {
    if receipt.evidence.canonical_version != CANONICAL_VERSION {
        return Err(ReceiptVerifyError::WrongVersion {
            got: receipt.evidence.canonical_version,
        });
    }
    let sig_bytes = hex::decode(&receipt.evidence.sig)
        .map_err(|e| ReceiptVerifyError::Malformed(format!("sig hex: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ReceiptVerifyError::Malformed("sig length".into()))?;
    if sig_arr == [0u8; 64] {
        return Err(ReceiptVerifyError::PlaceholderSig);
    }
    let recomputed = vault_canonical_hash(receipt);
    if !recomputed.eq_ignore_ascii_case(&receipt.evidence.hash) {
        return Err(ReceiptVerifyError::HashMismatch {
            got: receipt.evidence.hash.clone(),
            recomputed,
        });
    }
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
    if !receipt
        .evidence
        .signer_pubkey
        .eq_ignore_ascii_case(expected_pubkey_hex)
    {
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
// append-only receipts journal
// ---------------------------------------------------------------------------

/// Errors specific to the `receipts.log` journal append path.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The journal file's mode bits drifted from `0o600`. Refuse to write
    /// so an attacker who's already widened the file can't observe newly-
    /// written receipts in cleartext. Operator must reinstall to restore.
    #[error("receipts.log permissions drifted (mode {mode:#o}); refusing to write")]
    InsecureMode { mode: u32 },
    /// Underlying filesystem I/O failure (open, write, stat).
    #[error("receipts.log I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization of the receipt body failed.
    #[error("receipts.log serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Append a single receipt line to the append-only `receipts.log` journal
/// at `<data_dir>/receipts.log`. Format is one JCS-canonical JSON object
/// per line terminated by `\n`; the file is opened `O_APPEND | O_CREAT`
/// with mode `0o600` so the daemon's uid owns it and group/other have no
/// access. Pre-write the function checks the file's mode bits and refuses
/// to write if any group or world permission is set — defense-in-depth
/// against later chmod drift between install time and runtime.
///
/// Used by the daemon's per-receipt hot path (operator-initiated revoke
/// receipts, KMS receipts, broker receipts) and by the periodic
/// `daemon.receipt_root` envelope writer (subtask follow-up). The journal
/// is the redundant store that lets the verifier (subtask C) detect SQLite
/// tampering by cross-checking the SQL chain against the file's contents.
///
/// # target_state_anchor
///
/// `fn append_receipts_journal`
///
/// # FSYNC CONTRACT (fsync_contract_ADR155_C8_P3)
///
/// ADR 155 §Component 8 Prerequisites P3: **fail-atomic audit emission**.
/// If the pre-exec `broker.execution_domain` Receipt cannot be persisted,
/// `broker_exec` MUST fail before the construct runs and before any
/// credential is minted. The structural defense against "we minted a token
/// but lost the audit record."
///
/// On `Ok(())` return, the receipt is durable: power-loss after this
/// function returns cannot lose it. Both file contents AND inode metadata
/// (size, mtime) are flushed via `sync_all()` — the conservative audit-
/// chain posture. `sync_data` (fdatasync) would suffice for content
/// recovery of an append-only journal but does not guarantee size-metadata
/// durability; for a security-product audit chain the stronger promise is
/// worth the extra IO.
///
/// On `Err` return, the caller MUST treat the failure as "audit not
/// persisted" and abort any credentialed call that depended on the
/// receipt's existence. Specifically: the broker_exec critical path
/// awaits this function synchronously (no `tokio::spawn`), `?`-propagates
/// the IoError, and aborts the credential mint on any non-`Ok` outcome.
pub fn append_receipts_journal<T: serde::Serialize>(
    data_dir: &Path,
    receipt: &T,
) -> Result<(), JournalError> {
    use std::fs::OpenOptions;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = data_dir.join("receipts.log");

    // Pre-write mode check (defense-in-depth). Only applied on existing
    // files; the create path below opens with mode 0o600.
    #[cfg(unix)]
    if path.exists() {
        let meta = std::fs::metadata(&path)?;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{mode:#o}"),
                "receipts.log has group/other permissions — refusing to write"
            );
            return Err(JournalError::InsecureMode { mode });
        }
    }

    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    opts.mode(0o600);

    let mut file = opts.open(&path)?;

    // JCS-style canonicalization is hard in the general case; serde_json
    // with serde's default Serializer is deterministic for BTreeMap +
    // primitive types per current crate semantics. The verifier (subtask
    // C) reads each line back via serde_json::from_str and reconstructs
    // the Merkle leaf from the parsed Value, so any small key-order drift
    // between writer and reader gets normalized at parse time.
    let line = serde_json::to_string(receipt)?;
    writeln!(file, "{}", line)?;
    // ADR 155 §Component 8 Prerequisites P3 (FSYNC CONTRACT): sync_all
    // not sync_data — guarantee size-metadata durability alongside content.
    // See doc-comment "FSYNC CONTRACT" above (fsync_contract_ADR155_C8_P3).
    file.sync_all()?;
    Ok(())
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
        "revoked" | "abandoned" | "expired" | "exhausted_by_budget" | "parent_cascade_revoked"
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
    identity: &DaemonPersona,
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
    let reason = explicit_reason.unwrap_or_else(|| derive_reason(store, &info));
    let receipt_id = emit_receipt(store, identity, &info, reason)?;
    store.set_grant_receipt_id(grant_id, &receipt_id)?;
    Ok(Some(receipt_id))
}

/// Derive a terminal reason from grant status alone.
///
/// For `exhausted_by_budget`, the axis is read from the `budget.exhausted`
/// audit row instead of guessed from which
/// axes the grant's budget configures. The audit row carries the
/// authoritative axis that actually tripped the cap.
fn derive_reason(store: &DaemonStore, info: &GrantInfo) -> TerminalReason {
    match info.status.as_str() {
        "revoked" => TerminalReason::Revoked {
            by: RevokeActor::Operator,
            reason: String::new(),
        },
        "abandoned" => TerminalReason::Abandoned {
            reason: String::new(),
        },
        "expired" => TerminalReason::Expired,
        "exhausted_by_budget" => {
            let sid = info
                .budget
                .as_ref()
                .map(|_| StatementId::from("S0"))
                .unwrap_or_else(|| "S0".to_string());
            let axis = exhausted_axis_from_audit(store, info).unwrap_or(BudgetAxis::Requests);
            TerminalReason::ExhaustedByBudget {
                statement_sid: sid,
                axis,
            }
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

/// Read the exhaustion axis from the `budget.exhausted` audit row for this
/// grant.
///
/// `budget.exhausted` rows are emitted by the proxy meter when a Statement
/// usage tally crosses a budget cap. The row's `details` column carries the
/// canonical `axis=<axis> used=... limit=...` payload set by
/// `emit_threshold_crossings`; its `credential` column is the recipient
/// credential name. We filter on (action, credential) and parse the axis
/// token out of the most recent matching row.
///
/// Returns `None` when no `budget.exhausted` audit row exists for the grant
/// (e.g. wall-clock exhaustion drives `grant.exhausted` directly from the
/// sweeper without an intervening `budget.exhausted` row — in that path the
/// caller passes `explicit_reason` so `derive_reason` is bypassed). Callers
/// fall back to a stable default rather than a guess-ladder.
fn exhausted_axis_from_audit(store: &DaemonStore, info: &GrantInfo) -> Option<BudgetAxis> {
    let rows = store
        .query_audit(&AuditFilter {
            action: Some("budget.exhausted".to_string()),
            limit: Some(50),
            ..Default::default()
        })
        .ok()?;
    rows.into_iter()
        .filter(|e| e.credential.as_deref() == Some(info.credential_name.as_str()))
        .find_map(|e| parse_axis_from_details(e.details.as_deref().unwrap_or("")))
}

/// Parse the `axis=<axis>` token out of a `budget.exhausted` audit row's
/// details payload. The payload format is `axis=<axis> used=... limit=...`
/// (see `emit_threshold_crossings` in `infra/proxy.rs`); axis values are the
/// snake_case variants the proxy meter writes today (`tokens`, `cents`),
/// extended here to cover `requests` and `wall_clock_secs` so future emitters
/// can reuse the same payload shape without a parser change.
fn parse_axis_from_details(details: &str) -> Option<BudgetAxis> {
    let axis_token = details
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("axis="))?;
    match axis_token {
        "tokens" => Some(BudgetAxis::Tokens),
        "cents" => Some(BudgetAxis::Cents),
        "requests" => Some(BudgetAxis::Requests),
        "wall_clock_secs" | "wall_clock" => Some(BudgetAxis::WallClockSecs),
        _ => None,
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
    Ok(build_receipt_body(
        store,
        &info,
        terminal_reason,
        now_epoch_secs,
    ))
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
    // 1. Pull the canonical composite chain + envelope-level attestation.
    //    AUDIT Decision 2 #4 (attestation passthrough): the
    //    AccessGrant envelope carries the live attestation posture
    //    (sandbox / spiffe / tee status). Capture it here alongside the
    //    chain so step 7 can pass it through into the signed receipt
    //    instead of zeroing it out.
    let (chain, grant_attestation) = match store.get_access_grant(&info.id) {
        Ok(g) => (g.blocks, g.attestation),
        Err(_) => (Vec::new(), AttestationBinding::default()),
    };

    // 2. Per-statement usage tallies from the block-0 statements.
    // Derive wall_clock_secs at receipt-build
    // time so signed receipts record actual time used rather than the stored 0.
    let created_at_secs = parse_rfc3339_epoch(&info.created_at);
    let expires_at_secs = info
        .expires_at
        .as_deref()
        .map(parse_rfc3339_epoch)
        .filter(|&v| v != 0);
    let per_statement_usage: Vec<(StatementId, Usage)> = chain
        .first()
        .map(|sb| {
            sb.block
                .statements
                .iter()
                .map(|s| {
                    let mut u = s.usage.clone();
                    // Only derive wall_clock_secs when the stored usage
                    // value is 0 (i.e. unset / default-zeroed). When the
                    // caller has supplied a non-zero usage tally, that's
                    // the canonical "actual time used" — preserve it
                    // even if a budget cap is also set. Pre-2026-05-08:
                    // condition was `budget_cap.is_some() || u.wall_clock_secs == 0`,
                    // which clobbered legitimate usage values whenever a
                    // budget was configured (the test
                    // `three_statement_receipt_preserves_per_statement_usage`
                    // catches this — it sets usage.wall_clock_secs = 120
                    // alongside budget.wall_clock_secs = Some(3600), and
                    // the override replaced 120 with elapsed-since-create
                    // ≈ 0). Per AUDIT D5: per-statement usage is the
                    // source of truth; derivation is the fallback.
                    let budget_cap = s.budget.as_ref().and_then(|b| b.wall_clock_secs);
                    if u.wall_clock_secs == 0 {
                        u.wall_clock_secs = derive_wall_clock_secs(
                            now_epoch_secs,
                            created_at_secs,
                            expires_at_secs,
                            budget_cap,
                        );
                    }
                    (s.sid.clone(), u)
                })
                .collect()
        })
        .unwrap_or_default();

    // 3. Scoped audit excerpt. We pull a broad slice of the store's audit
    //    log and filter client-side for entries whose `details` JSON
    //    references this grant_id. Keeps the receipt self-contained and
    //    avoids a schema for grant-id→event mapping.
    let raw_audit: Vec<crate::infra::audit::AuditEntry> = store
        .query_audit(&AuditFilter {
            limit: Some(500),
            ..Default::default()
        })
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
            let details: serde_json::Value = serde_json::from_str(details_str).unwrap_or_default();
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
                "approval_narrowed" => (
                    ApprovalActor::HumanDashboard,
                    ApprovalOutcome::ApprovedWithNarrowing,
                ),
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
    // Per AUDIT Decision 2 #5 (last-used per statement):
    // last_used_at reflects the most recent moment ANY statement was
    // touched. Aggregate Usage.last_updated was a stand-in that swallowed
    // per-statement granularity in the audit trail. Source of truth is the
    // per_statement_usage vector computed above.
    // statement.last_used_at — aggregated as max across per-Statement Usage
    let last_used_at = per_statement_usage
        .iter()
        .map(|(_, u)| u.last_updated)
        .filter(|t| *t != 0)
        .max();
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

    // 7. Attestation — passes through from the live grant. Per AUDIT
    //    Decision 2 #4 (attestation passthrough): the previous
    //    `chain.first().and_then(|_| None).unwrap_or_default()` was a
    //    dead-code default that erased sandbox/spiffe/tee status from the
    //    grant before signing. Source of truth is the AccessGrant
    //    envelope, captured at step 1.
    // fn pass_attestation — receipt attestation passes through from grant struct (no zero-default)
    let attestation: AttestationBinding = grant_attestation;

    // 8. Assemble receipt body (Evidence zeroed for hash stability — caller
    //    signs and repopulates evidence if needed).
    //
    //    ADR 157 §Component 5 — stamp `dev_mode_active` from the
    //    process-global flag set during daemon startup
    //    (`binary_manifest::set_dev_mode_active`). `false` for prod
    //    daemons running with release-only trust; `true` when the
    //    operator supplied any additional root via `EMBER_TRUST_ROOTS`.
    //    The field has `#[serde(skip_serializing_if = "std::ops::Not::not")]`
    //    so the JSON for prod-mode receipts is byte-identical to
    //    pre-ADR-157 receipts (preserves canonical hash stability for
    //    operators not using trust-root extension).
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
        dev_mode_active: crate::binary_manifest::dev_mode_active(),
        evidence: Evidence::default(),
    }
}

/// Build a signed receipt for a terminal grant and persist it. Returns
/// the receipt id.
pub fn emit_receipt(
    store: &DaemonStore,
    identity: &DaemonPersona,
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
        sig: hex::encode(*sig_bytes),
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
    /// `ember audit` — kind discriminator (`grant`, `kms_wrap`,
    /// `kms_unwrap`). Mapped 1:1 to the `kind` column.
    pub kind: Option<String>,
    /// `ember audit` — restrict to receipts whose `grant_id` matches.
    pub grant_id: Option<String>,
    /// `ember audit` — substring filter on the receipt's `summary.resource`
    /// (grant receipts) or top-level `key_name` (kms receipts). Applied
    /// post-fetch so the JSON1 index can still serve exact-match callers.
    pub resource: Option<String>,
}

/// `ember audit` — flat audit row returned by [`DaemonStore::list_receipt_rows`].
///
/// Joins receipt fields with [`crate::trust::grant::GrantInfo`] when the row is a
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
    /// Canonical structured action identity when the receipt body carries it.
    pub action_ref: Option<ActionRef>,
    /// Authority-minted execution-contract identifier when the receipt body
    /// carries it.
    pub contract_id: Option<String>,
    /// Logical workspace handle when the receipt body carries it.
    pub workspace_ref: Option<String>,
    /// Requesting caller/session/persona identity in authority space when the
    /// receipt body carries it.
    pub caller_ref: Option<String>,
    /// Grant or approval binding used for the action when the receipt body
    /// carries it.
    pub authority_ref: Option<String>,
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
    /// Whether the stored receipt artifact carries a real signature.
    pub signed: bool,
    /// Delegation template or other session-lane human label when the receipt
    /// body carries one.
    pub delegation_template: Option<String>,
    /// Total claims represented by a segmented session/composite receipt.
    pub claim_count_total: Option<u64>,
    /// Whether the inline `claim_events[]` are only a bounded tail.
    pub claim_events_truncated: bool,
    /// Number of segment digests carried by the receipt body.
    pub claim_segment_count: Option<u64>,
    /// Full-scope Merkle root over the segment digests when present.
    pub claim_history_merkle_root: Option<String>,
}

// ---------------------------------------------------------------------------
// Store methods — receipts table
// ---------------------------------------------------------------------------

impl DaemonStore {
    /// Persist a fully-signed receipt to the `receipts` table.
    pub fn store_receipt(&self, receipt: &GrantReceipt) -> Result<(), StoreError> {
        let now = Utc::now().to_rfc3339();
        let receipt_json = serde_json::to_string(receipt)
            .map_err(|e| StoreError::InvalidInput(format!("serialize receipt: {e}")))?;
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
        let receipt_json = serde_json::to_string(receipt)
            .map_err(|e| StoreError::InvalidInput(format!("serialize kms receipt: {e}")))?;
        let kind_str = match receipt.kind {
            ReceiptKind::KmsWrap => "kms_wrap",
            ReceiptKind::KmsUnwrap => "kms_unwrap",
            // Non-kms variants must never reach this sink — they have
            // their own (planned) typed-Receipt persistence paths for
            // vault-retrieval and broker-typed receipts. Reject explicitly
            // so a mis-routed call surfaces immediately rather than landing
            // a non-kms row in the kms-shaped storage path.
            ReceiptKind::Grant
            | ReceiptKind::VaultRetrieval
            | ReceiptKind::BrokerMaterialization
            | ReceiptKind::BrokerRevocation
            | ReceiptKind::PeerEnroll
            | ReceiptKind::PeerInstall
            | ReceiptKind::PeerRevoke => {
                return Err(StoreError::InvalidInput(format!(
                    "store_kms_receipt called with non-kms ReceiptKind::{:?} — \
                     use the typed sink for this kind",
                    receipt.kind
                )));
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
        let outcome_str =
            serde_json::to_string(&receipt.outcome).unwrap_or_else(|_| "\"unknown\"".to_string());
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

    /// Persist a broker receipt (`broker_materialization` / `broker_revocation`).
    ///
    /// Reuses the unified `receipts` table. The `kind` column discriminates
    /// rows. **No plaintext credential bytes appear in the row** — only
    /// opaque labels and timing metadata.
    pub fn store_broker_receipt(&self, receipt: &BrokerReceipt) -> Result<(), StoreError> {
        let now = Utc::now().to_rfc3339();
        let receipt_json = serde_json::to_string(receipt)
            .map_err(|e| StoreError::InvalidInput(format!("serialize broker receipt: {e}")))?;
        let kind_str = match receipt.kind {
            ReceiptKind::BrokerMaterialization => "broker_materialization",
            ReceiptKind::BrokerRevocation => "broker_revocation",
            other => {
                return Err(StoreError::InvalidInput(format!(
                    "store_broker_receipt called with non-broker ReceiptKind::{other:?} — \
                     use the typed sink for this kind"
                )));
            }
        };
        // Reuse existing columns:
        //   - grant_id is empty (broker receipts are not tied to a grant)
        //   - persona_id stores the caller persona
        //   - terminal_reason stores the provider name (opaque label)
        //   - signer_pubkey is the daemon identity (or zero placeholder)
        self.conn().execute(
            "INSERT OR REPLACE INTO receipts \
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, '', ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                receipt.id,
                receipt.caller_persona,
                receipt.provider,
                now,
                receipt_json,
                receipt.evidence.signer_pubkey,
                kind_str,
            ],
        )?;
        Ok(())
    }

    /// Persist a v2 broker [`ReceiptEnvelope`] (kinds `broker.materialization`
    /// or `broker.revocation`). Companion to [`Self::store_broker_receipt`]
    /// (v1). Rejects envelopes whose `kind` does not start with `"broker."`.
    ///
    /// Reuses the unified `receipts` table. The v2 row is distinguishable from
    /// v1 by the dotted-kind discriminator (`broker.materialization` vs the
    /// underscore-form `broker_materialization` used by v1) — both shapes
    /// coexist for the dual-emit transition (Phase A) until Phase B retires
    /// the v1 path.
    ///
    /// Verification: the envelope is the canonical signing artifact. The row's
    /// `signer_pubkey` column is left empty for v2 — callers verify via
    /// [`core_events::receipt::sign::verify_receipt_v2`] using a
    /// caller-supplied pubkey (typically `current_identity().pubkey_hex()`).
    pub fn store_broker_receipt_v2(&self, envelope: &ReceiptEnvelope) -> Result<(), StoreError> {
        if !envelope.kind.starts_with("broker.") {
            return Err(StoreError::InvalidInput(format!(
                "store_broker_receipt_v2 called with non-broker kind '{}' — \
                 expected 'broker.materialization' or 'broker.revocation'",
                envelope.kind
            )));
        }
        if envelope.receipt_id.is_empty() {
            return Err(StoreError::InvalidInput(
                "store_broker_receipt_v2 called with empty receipt_id — \
                 caller must invoke sign_receipt_v2 before persistence"
                    .to_string(),
            ));
        }
        let envelope_json = serde_json::to_string(envelope).map_err(|e| {
            StoreError::InvalidInput(format!("serialize broker receipt envelope: {e}"))
        })?;
        let now = Utc::now().to_rfc3339();
        let caller_persona = envelope
            .body
            .get("caller_persona")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let provider = envelope
            .body
            .get("provider")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        // Reuse existing columns:
        //   - grant_id is empty (broker receipts are not tied to a grant)
        //   - persona_id stores the caller persona (extracted from body)
        //   - terminal_reason stores the provider name
        //   - signer_pubkey is empty for v2 — the envelope's signature is the
        //     canonical artifact and the pubkey is per-daemon, looked up at
        //     verification time via current_identity().
        self.conn().execute(
            "INSERT OR REPLACE INTO receipts \
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, '', ?2, ?3, ?4, ?5, '', ?6)",
            rusqlite::params![
                envelope.receipt_id,
                caller_persona,
                provider,
                now,
                envelope_json,
                envelope.kind,
            ],
        )?;
        Ok(())
    }

    /// Persist a v2 session [`ReceiptEnvelope`] (for example
    /// `session.claude_code` or `session.composite_grant`).
    ///
    /// Reuses the unified `receipts` table:
    /// - `grant_id` is supplied by the caller for session kinds that close a
    ///   specific grant lifecycle
    /// - `persona_id` is supplied explicitly so callers do not need to rely on
    ///   ad hoc body parsing to recover the actor principal
    /// - `terminal_reason` is copied from `body.termination_reason` when
    ///   present so flat receipt listings can filter by terminal state without
    ///   reparsing the full envelope JSON
    pub fn store_session_receipt_v2(
        &self,
        envelope: &ReceiptEnvelope,
        grant_id: &str,
        persona_id: &str,
    ) -> Result<(), StoreError> {
        if !envelope.kind.starts_with("session.") {
            return Err(StoreError::InvalidInput(format!(
                "store_session_receipt_v2 called with non-session kind '{}' — expected 'session.*'",
                envelope.kind
            )));
        }
        if envelope.receipt_id.is_empty() {
            return Err(StoreError::InvalidInput(
                "store_session_receipt_v2 called with empty receipt_id — caller must invoke sign_receipt_v2 before persistence"
                    .to_string(),
            ));
        }
        let envelope_json = serde_json::to_string(envelope).map_err(|e| {
            StoreError::InvalidInput(format!("serialize session receipt envelope: {e}"))
        })?;
        let now = Utc::now().to_rfc3339();
        let terminal_reason = envelope
            .body
            .get("termination_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        self.conn().execute(
            "INSERT OR REPLACE INTO receipts \
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, '', ?7)",
            rusqlite::params![
                envelope.receipt_id,
                grant_id,
                persona_id,
                terminal_reason,
                now,
                envelope_json,
                envelope.kind,
            ],
        )?;
        Ok(())
    }

    /// Persist a v2 atomic [`ReceiptEnvelope`] for non-session, non-broker
    /// kinds that are still grant-scoped (for example `payment.*`).
    ///
    /// Reuses the unified `receipts` table. `terminal_reason` is caller-
    /// supplied because generic atomic bodies do not share a single stable
    /// field name for their summary state.
    pub fn store_atomic_receipt_v2(
        &self,
        envelope: &ReceiptEnvelope,
        grant_id: &str,
        persona_id: &str,
        terminal_reason: &str,
    ) -> Result<(), StoreError> {
        let allowed_non_dotted = matches!(
            envelope.kind.as_str(),
            core_events::receipt::RECEIPT_KIND_HEADLESS_ENROLLMENT
                | core_events::receipt::RECEIPT_KIND_HEADLESS_REVOCATION
        );
        if (!envelope.kind.contains('.') && !allowed_non_dotted)
            || envelope.kind.starts_with("session.")
        {
            return Err(StoreError::InvalidInput(format!(
                "store_atomic_receipt_v2 called with non-atomic kind '{}' — expected dotted non-session kind",
                envelope.kind
            )));
        }
        if envelope.receipt_id.is_empty() {
            return Err(StoreError::InvalidInput(
                "store_atomic_receipt_v2 called with empty receipt_id — caller must invoke sign_receipt_v2 before persistence"
                    .to_string(),
            ));
        }
        let envelope_json = serde_json::to_string(envelope).map_err(|e| {
            StoreError::InvalidInput(format!("serialize atomic receipt envelope: {e}"))
        })?;
        let now = Utc::now().to_rfc3339();
        self.conn().execute(
            "INSERT OR REPLACE INTO receipts \
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, '', ?7)",
            rusqlite::params![
                envelope.receipt_id,
                grant_id,
                persona_id,
                terminal_reason,
                now,
                envelope_json,
                envelope.kind,
            ],
        )?;
        Ok(())
    }

    /// Persist a v2 service lifecycle [`ReceiptEnvelope`] and project its
    /// catalog state into `service_registrations`.
    ///
    /// Supported kinds:
    /// - `service.installed.v1`
    /// - `service.uninstalled.v1`
    ///
    /// Reuses the unified `receipts` table:
    /// - `grant_id` is empty (service lifecycle receipts are not grant-bound)
    /// - `persona_id` stores the acting installer/uninstaller persona
    /// - `terminal_reason` stores the `plugin_address` so flat listings can
    ///   group by service without reparsing the envelope body
    ///
    /// The `service_registrations` row is updated in the same savepoint as
    /// receipt persistence so the catalog substrate does not drift from the
    /// lifecycle receipt ledger.
    pub fn store_service_receipt_v2(&self, envelope: &ReceiptEnvelope) -> Result<(), StoreError> {
        if envelope.receipt_id.is_empty() {
            return Err(StoreError::InvalidInput(
                "store_service_receipt_v2 called with empty receipt_id — caller must invoke sign_receipt_v2 before persistence"
                    .to_string(),
            ));
        }

        enum ServiceReceiptProjection {
            Installed(ServiceInstalledBody),
            Uninstalled(ServiceUninstalledBody),
        }

        let projection = match envelope.kind.as_str() {
            RECEIPT_KIND_SERVICE_INSTALLED_V1 => {
                serde_json::from_value::<ServiceInstalledBody>(envelope.body.clone())
                    .map(ServiceReceiptProjection::Installed)
                    .map_err(|e| {
                        StoreError::InvalidInput(format!(
                            "deserialize service.installed.v1 envelope body: {e}"
                        ))
                    })?
            }
            RECEIPT_KIND_SERVICE_UNINSTALLED_V1 => {
                serde_json::from_value::<ServiceUninstalledBody>(envelope.body.clone())
                    .map(ServiceReceiptProjection::Uninstalled)
                    .map_err(|e| {
                        StoreError::InvalidInput(format!(
                            "deserialize service.uninstalled.v1 envelope body: {e}"
                        ))
                    })?
            }
            other => {
                return Err(StoreError::InvalidInput(format!(
                    "store_service_receipt_v2 called with non-service kind '{other}' — expected '{RECEIPT_KIND_SERVICE_INSTALLED_V1}' or '{RECEIPT_KIND_SERVICE_UNINSTALLED_V1}'"
                )));
            }
        };

        let envelope_json = serde_json::to_string(envelope).map_err(|e| {
            StoreError::InvalidInput(format!("serialize service receipt envelope: {e}"))
        })?;
        let now = Utc::now().to_rfc3339();

        self.conn().execute_batch("SAVEPOINT service_receipt_v2")?;
        let result = (|| -> Result<(), StoreError> {
            match &projection {
                ServiceReceiptProjection::Installed(body) => {
                    self.conn().execute(
                        "INSERT OR REPLACE INTO receipts \
                         (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
                         VALUES (?1, '', ?2, ?3, ?4, ?5, '', ?6)",
                        rusqlite::params![
                            envelope.receipt_id,
                            body.installed_by_persona_id,
                            body.plugin_address,
                            now,
                            envelope_json,
                            envelope.kind,
                        ],
                    )?;
                    self.conn().execute(
                        "INSERT OR REPLACE INTO service_registrations \
                         (plugin_address, plugin_version, publisher_id, installed_at, installed_by, state, service_label, install_receipt_hash) \
                         VALUES (?1, ?2, ?3, ?4, ?5, 'installed', ?6, ?7)",
                        rusqlite::params![
                            body.plugin_address,
                            body.plugin_version,
                            body.publisher_id,
                            now,
                            body.installed_by_persona_id,
                            body.service_label,
                            envelope.receipt_id,
                        ],
                    )?;
                }
                ServiceReceiptProjection::Uninstalled(body) => {
                    self.conn().execute(
                        "INSERT OR REPLACE INTO receipts \
                         (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
                         VALUES (?1, '', ?2, ?3, ?4, ?5, '', ?6)",
                        rusqlite::params![
                            envelope.receipt_id,
                            body.uninstalled_by_persona_id,
                            body.plugin_address,
                            now,
                            envelope_json,
                            envelope.kind,
                        ],
                    )?;
                    let updated = self.conn().execute(
                        "UPDATE service_registrations \
                         SET state = 'uninstalled' \
                         WHERE plugin_address = ?1 AND plugin_version = ?2",
                        rusqlite::params![body.plugin_address, body.plugin_version],
                    )?;
                    if updated == 0 {
                        return Err(StoreError::NotFound);
                    }
                }
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                self.conn()
                    .execute_batch("RELEASE SAVEPOINT service_receipt_v2")?;
                Ok(())
            }
            Err(err) => {
                let _ = self.conn().execute_batch(
                    "ROLLBACK TO SAVEPOINT service_receipt_v2; RELEASE SAVEPOINT service_receipt_v2;",
                );
                Err(err)
            }
        }
    }

    /// Load the raw `receipt_json` column for a persisted v2 envelope row.
    /// Returns the serialized [`ReceiptEnvelope`] JSON for callers (tests,
    /// verifiers, dashboard) that need to round-trip the persisted envelope
    /// through `verify_receipt_v2` or render generic v2 detail views.
    ///
    /// Filters on dotted `kind` values so legacy underscore-form v1 rows are
    /// excluded while allowing any real v2 family (`broker.*`, `session.*`,
    /// `spawn.witness`, future dotted kinds) to be fetched by receipt id.
    pub fn get_receipt_v2_envelope_json(&self, id: &str) -> Result<String, StoreError> {
        use rusqlite::OptionalExtension;
        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT receipt_json FROM receipts \
                 WHERE id = ?1 AND kind LIKE '%.%'",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .optional()?;
        raw.ok_or(StoreError::NotFound)
    }

    /// Persist a v2 `spawn.witness`
    /// [`ReceiptEnvelope`] from the spawn path
    /// (`crate::trust::grant::delegate_grant_full_sql`). Companion to
    /// [`Self::store_broker_receipt_v2`]; rejects envelopes whose `kind` is
    /// not exactly `"spawn.witness"`.
    ///
    /// Reuses the unified `receipts` table:
    /// - `id` ← `envelope.receipt_id` (blake3 over the canonical envelope,
    ///   recomputed by `sign_receipt_v2` before persistence).
    /// - `grant_id` ← the parent grant authorizing the spawn (extracted from
    ///   `body.spawn_grant_id`); this lets the tree CLI's
    ///   `list_spawn_witnesses_for_grants` index witnesses by the parent
    ///   grant edge.
    /// - `persona_id` ← `body.spawned_persona_id` (the child) so per-persona
    ///   listings surface the witness alongside the child's other artifacts.
    /// - `terminal_reason` ← `body.parent_persona_id` so the parent persona
    ///   is retrievable in a flat row scan without re-parsing JSON.
    /// - `signer_pubkey` is empty (per v2 convention — the envelope's
    ///   signature is the canonical artifact; the daemon pubkey is looked
    ///   up at verification time via the trust anchor on disk).
    pub fn store_spawn_witness_receipt(
        &self,
        envelope: &ReceiptEnvelope,
    ) -> Result<(), StoreError> {
        if envelope.kind != core_events::receipt::RECEIPT_KIND_SPAWN_WITNESS {
            return Err(StoreError::InvalidInput(format!(
                "store_spawn_witness_receipt called with kind '{}' — \
                 expected '{}'",
                envelope.kind,
                core_events::receipt::RECEIPT_KIND_SPAWN_WITNESS,
            )));
        }
        if envelope.receipt_id.is_empty() {
            return Err(StoreError::InvalidInput(
                "store_spawn_witness_receipt called with empty receipt_id — \
                 caller must invoke sign_receipt_v2 before persistence"
                    .to_string(),
            ));
        }
        let envelope_json = serde_json::to_string(envelope).map_err(|e| {
            StoreError::InvalidInput(format!("serialize spawn.witness envelope: {e}"))
        })?;
        let now = Utc::now().to_rfc3339();
        let spawned_persona = envelope
            .body
            .get("spawned_persona_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let parent_persona = envelope
            .body
            .get("parent_persona_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let spawn_grant_id = envelope
            .body
            .get("spawn_grant_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        self.conn().execute(
            "INSERT OR REPLACE INTO receipts \
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, '', ?7)",
            rusqlite::params![
                envelope.receipt_id,
                spawn_grant_id,
                spawned_persona,
                parent_persona,
                now,
                envelope_json,
                envelope.kind,
            ],
        )?;
        Ok(())
    }

    /// Persist a
    /// signed v2 `identity.rotation_witness` [`ReceiptEnvelope`] from
    /// the daemon-side emission path (`crate::infra::vault::emit_identity_rotation_witness`).
    /// Companion to [`Self::store_spawn_witness_receipt`]; rejects
    /// envelopes whose `kind` is not exactly `"identity.rotation_witness"`.
    ///
    /// Reuses the unified `receipts` table:
    /// - `id` ← `envelope.receipt_id` (blake3 over the canonical envelope,
    ///   recomputed by `sign_receipt_v2` before persistence).
    /// - `grant_id` is empty (rotation witnesses are not tied to a grant).
    /// - `persona_id` ← `body.prev_epoch_root_id` so per-persona listings
    ///   surface the witness alongside the retired identity's other
    ///   artifacts (and the next-epoch root id is recoverable from the
    ///   envelope JSON for the post-rotation continuation).
    /// - `terminal_reason` ← `body.next_epoch_root_id` so the rotation
    ///   target is retrievable in a flat row scan without re-parsing
    ///   JSON.
    /// - `signer_pubkey` is empty (per v2 convention — the envelope's
    ///   signature is the canonical artifact; the daemon pubkey is
    ///   looked up at verification time via the trust anchor on disk).
    pub fn store_identity_rotation_witness_receipt(
        &self,
        envelope: &ReceiptEnvelope,
    ) -> Result<(), StoreError> {
        if envelope.kind != core_events::receipt::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS {
            return Err(StoreError::InvalidInput(format!(
                "store_identity_rotation_witness_receipt called with kind '{}' — \
                 expected '{}'",
                envelope.kind,
                core_events::receipt::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS,
            )));
        }
        if envelope.receipt_id.is_empty() {
            return Err(StoreError::InvalidInput(
                "store_identity_rotation_witness_receipt called with empty receipt_id — \
                 caller must invoke sign_receipt_v2 before persistence"
                    .to_string(),
            ));
        }
        let envelope_json = serde_json::to_string(envelope).map_err(|e| {
            StoreError::InvalidInput(format!("serialize identity.rotation_witness envelope: {e}"))
        })?;
        let now = Utc::now().to_rfc3339();
        let prev_epoch_root_id = envelope
            .body
            .get("prev_epoch_root_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let next_epoch_root_id = envelope
            .body
            .get("next_epoch_root_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        self.conn().execute(
            "INSERT OR REPLACE INTO receipts \
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, '', ?2, ?3, ?4, ?5, '', ?6)",
            rusqlite::params![
                envelope.receipt_id,
                prev_epoch_root_id,
                next_epoch_root_id,
                now,
                envelope_json,
                envelope.kind,
            ],
        )?;
        Ok(())
    }

    /// Load every persisted
    /// `spawn.witness` envelope whose `grant_id` (== `body.spawn_grant_id`)
    /// matches one of the supplied parent grant ids. Used by the tree CLI
    /// (`emberlink-cli::receipt::tree::build_tree`) to assemble the
    /// `spawn_witnesses` array from the store instead of synthesising it
    /// per-edge at export time.
    ///
    /// Returns parsed `(ReceiptEnvelope, parent_persona_id)` pairs ordered
    /// by `created_at ASC` (oldest first — matches the BFS order the tree
    /// already produces for grant nodes). `parent_persona_id` is sourced
    /// from the row's `terminal_reason` column (where `store_spawn_witness_receipt`
    /// recorded it) so verifiers can resolve the parent persona's pubkey
    /// without re-parsing the envelope body twice.
    pub fn list_spawn_witnesses_for_grants(
        &self,
        grant_ids: &[String],
    ) -> Result<Vec<(ReceiptEnvelope, String)>, StoreError> {
        if grant_ids.is_empty() {
            return Ok(Vec::new());
        }
        // SQLite has a SQLITE_MAX_VARIABLE_NUMBER ceiling (default 999) on
        // positional binds. A grant tree with >999 nodes is well beyond
        // demo-scale; we still defend by chunking. For typical demo sizes
        // (≤100s of grants) this is a single pass.
        const CHUNK: usize = 512;
        let mut out: Vec<(ReceiptEnvelope, String)> = Vec::new();
        for chunk in grant_ids.chunks(CHUNK) {
            let placeholders = (1..=chunk.len())
                .map(|i| format!("?{i}"))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT receipt_json, terminal_reason FROM receipts \
                 WHERE kind = '{}' AND grant_id IN ({}) \
                 ORDER BY created_at ASC",
                core_events::receipt::RECEIPT_KIND_SPAWN_WITNESS,
                placeholders,
            );
            let mut stmt = self.conn().prepare(&sql)?;
            let params: Vec<&dyn rusqlite::ToSql> =
                chunk.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
            let rows: Vec<(String, String)> = stmt
                .query_map(params.as_slice(), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<_, _>>()?;
            for (raw, parent_persona) in rows {
                let env: ReceiptEnvelope = serde_json::from_str(&raw).map_err(|e| {
                    StoreError::InvalidInput(format!("corrupt spawn.witness row: {e}"))
                })?;
                out.push((env, parent_persona));
            }
        }
        Ok(out)
    }

    /// List v2 [`ReceiptEnvelope`]
    /// rows from the `receipts` table whose `grant_id` is in `grant_ids`.
    ///
    /// V2 rows are identified by a dotted `kind` discriminator
    /// (e.g. `broker.materialization`, `broker.revocation`, `spawn.witness`).
    /// `spawn.witness` envelopes are excluded here — the tree CLI
    /// surfaces them through `list_spawn_witnesses_for_grants` which also
    /// carries the dual-signature metadata required for offline verify.
    ///
    /// Returns `(receipt_id, kind, grant_id, ReceiptEnvelope)` tuples ordered
    /// by `created_at ASC`.
    pub fn list_receipts_v2_envelopes(
        &self,
        grant_ids: &[String],
    ) -> Result<Vec<(String, String, String, ReceiptEnvelope)>, StoreError> {
        if grant_ids.is_empty() {
            return Ok(Vec::new());
        }
        const CHUNK: usize = 512;
        let mut out: Vec<(String, String, String, ReceiptEnvelope)> = Vec::new();
        for chunk in grant_ids.chunks(CHUNK) {
            let placeholders = (1..=chunk.len())
                .map(|i| format!("?{i}"))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT id, kind, grant_id, receipt_json FROM receipts \
                 WHERE kind LIKE '%.%' \
                   AND kind != '{}' \
                   AND grant_id IN ({}) \
                 ORDER BY created_at ASC",
                core_events::receipt::RECEIPT_KIND_SPAWN_WITNESS,
                placeholders,
            );
            let mut stmt = self.conn().prepare(&sql)?;
            let params: Vec<&dyn rusqlite::ToSql> =
                chunk.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
            let rows: Vec<(String, String, String, String)> = stmt
                .query_map(params.as_slice(), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?
                .collect::<Result<_, _>>()?;
            for (id, kind, grant_id, raw) in rows {
                let env: ReceiptEnvelope = serde_json::from_str(&raw).map_err(|e| {
                    StoreError::InvalidInput(format!("corrupt v2 envelope row {id}: {e}"))
                })?;
                out.push((id, kind, grant_id, env));
            }
        }
        Ok(out)
    }

    /// Load a broker receipt by id. Returns `NotFound` if the row is not a
    /// broker_materialization / broker_revocation kind.
    pub fn get_broker_receipt(&self, id: &str) -> Result<BrokerReceipt, StoreError> {
        use rusqlite::OptionalExtension;
        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT receipt_json FROM receipts \
                 WHERE id = ?1 AND kind IN ('broker_materialization','broker_revocation')",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .optional()?;
        let raw = raw.ok_or(StoreError::NotFound)?;
        serde_json::from_str(&raw)
            .map_err(|e| StoreError::InvalidInput(format!("corrupt broker receipt row {id}: {e}")))
    }

    /// Persist a vault retrieval receipt (`vault_retrieval`).
    ///
    /// Reuses the unified `receipts` table. The `kind` column discriminates
    /// rows. **No plaintext credential bytes appear in the row** — only the
    /// opaque key name and timing metadata.
    pub fn store_vault_receipt(&self, receipt: &VaultReceipt) -> Result<(), StoreError> {
        let now = Utc::now().to_rfc3339();
        let receipt_json = serde_json::to_string(receipt)
            .map_err(|e| StoreError::InvalidInput(format!("serialize vault receipt: {e}")))?;
        match receipt.kind {
            ReceiptKind::VaultRetrieval => {}
            other => {
                return Err(StoreError::InvalidInput(format!(
                    "store_vault_receipt called with non-vault ReceiptKind::{other:?} — \
                     use the typed sink for this kind"
                )));
            }
        }
        // Reuse existing columns:
        //   - grant_id is empty (vault receipts are not tied to a grant)
        //   - persona_id stores the caller persona
        //   - terminal_reason stores the outcome string
        //   - signer_pubkey is the daemon identity (or zero placeholder)
        let outcome_str =
            serde_json::to_string(&receipt.outcome).unwrap_or_else(|_| "\"unknown\"".to_string());
        self.conn().execute(
            "INSERT OR REPLACE INTO receipts \
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, '', ?2, ?3, ?4, ?5, ?6, 'vault_retrieval')",
            rusqlite::params![
                receipt.id,
                receipt.caller_persona,
                outcome_str,
                now,
                receipt_json,
                receipt.evidence.signer_pubkey,
            ],
        )?;
        Ok(())
    }

    /// Persist a signed biometric vault-read receipt.
    pub fn store_vault_biometric_receipt(
        &self,
        receipt: &VaultBiometricReceipt,
    ) -> Result<(), StoreError> {
        if receipt.kind != VAULT_BIOMETRIC_RECEIPT_KIND {
            return Err(StoreError::InvalidInput(format!(
                "store_vault_biometric_receipt called with kind {:?}",
                receipt.kind
            )));
        }
        let now = Utc::now().to_rfc3339();
        let receipt_json = serde_json::to_string(receipt).map_err(|e| {
            StoreError::InvalidInput(format!("serialize vault biometric receipt: {e}"))
        })?;
        let outcome_str =
            serde_json::to_string(&receipt.outcome).unwrap_or_else(|_| "\"unknown\"".to_string());
        self.conn().execute(
            "INSERT OR REPLACE INTO receipts \
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                receipt.id,
                receipt.grant_id.as_deref().unwrap_or(""),
                receipt.caller_persona,
                outcome_str,
                now,
                receipt_json,
                receipt.evidence.signer_pubkey,
                VAULT_BIOMETRIC_RECEIPT_KIND,
            ],
        )?;
        Ok(())
    }

    /// Load a biometric vault-read receipt by id.
    pub fn get_vault_biometric_receipt(
        &self,
        id: &str,
    ) -> Result<VaultBiometricReceipt, StoreError> {
        use rusqlite::OptionalExtension;
        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT receipt_json FROM receipts \
                 WHERE id = ?1 AND kind = ?2",
                rusqlite::params![id, VAULT_BIOMETRIC_RECEIPT_KIND],
                |row| row.get(0),
            )
            .optional()?;
        let raw = raw.ok_or(StoreError::NotFound)?;
        serde_json::from_str(&raw).map_err(|e| {
            StoreError::InvalidInput(format!("corrupt vault biometric receipt row {id}: {e}"))
        })
    }

    /// Load a vault receipt by id. Returns `NotFound` if the row is not a
    /// vault_retrieval kind.
    pub fn get_vault_receipt(&self, id: &str) -> Result<VaultReceipt, StoreError> {
        use rusqlite::OptionalExtension;
        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT receipt_json FROM receipts \
                 WHERE id = ?1 AND kind = 'vault_retrieval'",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .optional()?;
        let raw = raw.ok_or(StoreError::NotFound)?;
        serde_json::from_str(&raw)
            .map_err(|e| StoreError::InvalidInput(format!("corrupt vault receipt row {id}: {e}")))
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
        serde_json::from_str(&raw)
            .map_err(|e| StoreError::InvalidInput(format!("corrupt kms receipt row {id}: {e}")))
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
        serde_json::from_str(&raw)
            .map_err(|e| StoreError::InvalidInput(format!("corrupt receipt row {id}: {e}")))
    }

    /// List receipts, most-recent first. Optionally filter by persona.
    pub fn list_receipts(&self, persona_id: Option<&str>) -> Result<Vec<GrantReceipt>, StoreError> {
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
        let mut sql = String::from("SELECT receipt_json, signer_pubkey FROM receipts WHERE 1=1");
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
        let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<(String, String)> {
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

    /// Flat audit-row listing for the `ember audit`
    /// query CLI. Joins the receipts table with `grants` so the row carries
    /// both the receipt fields and the parent grant's scope.
    ///
    /// Filters are AND-combined. `since` is a lower bound on the
    /// `materialized_at` column (`receipts.created_at`). `resource` is a
    /// substring match against `summary.resource` (grant receipts) or
    /// `key_name` (kms receipts) — applied post-fetch so the SQL stays
    /// index-friendly for exact-match callers.
    pub fn list_receipt_rows(&self, filter: &ReceiptFilter) -> Result<Vec<ReceiptRow>, StoreError> {
        // Indexed columns first (kind / persona_id / grant_id / created_at).
        // Build the parameterised SQL with positional binds; keep the bind
        // vector aligned with the params slice we hand to rusqlite.
        let mut sql = String::from(
            "SELECT r.id, r.kind, r.persona_id, r.grant_id, r.terminal_reason, \
                    r.created_at, r.receipt_json, r.signer_pubkey, g.scope \
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
        sql.push_str(" ORDER BY r.created_at DESC");
        let limit = filter.limit.unwrap_or(100);
        sql.push_str(&format!(" LIMIT {limit}"));

        let mut stmt = self.conn().prepare(&sql)?;
        type ReceiptRowTuple = (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
        );
        let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<ReceiptRowTuple> {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
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
                .query_map(rusqlite::params![binds[0], binds[1], binds[2]], mapper)?
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
        for (
            id,
            kind,
            persona_id,
            grant_id,
            terminal_reason,
            created_at,
            receipt_json,
            signer_pubkey,
            granted_scope,
        ) in rows
        {
            let receipt_value = serde_json::from_str::<serde_json::Value>(&receipt_json).ok();
            // Pull the resource label out of the receipt body. Grant
            // receipts: `$.summary.resource`. Kms receipts: `$.key_name`.
            // Fall back to empty string when the field is missing.
            let resource = match kind.as_str() {
                "grant" => receipt_value
                    .as_ref()
                    .and_then(|v| {
                        v.get("summary")
                            .and_then(|s| s.get("resource"))
                            .and_then(|r| r.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_default(),
                "kms_wrap" | "kms_unwrap" => receipt_value
                    .as_ref()
                    .and_then(|v| {
                        v.get("key_name")
                            .and_then(|r| r.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_default(),
                "broker_materialization" | "broker_revocation" => {
                    // resource label for broker rows is the provider name,
                    // extracted from `$.provider` in the receipt JSON.
                    receipt_value
                        .as_ref()
                        .and_then(|v| {
                            v.get("provider")
                                .and_then(|r| r.as_str())
                                .map(|s| s.to_string())
                        })
                        .unwrap_or_default()
                }
                "vault_retrieval" | "vault_biometric_retrieval" => {
                    // resource label for vault rows is the key name,
                    // extracted from `$.key_name` in the receipt JSON.
                    receipt_value
                        .as_ref()
                        .and_then(|v| {
                            v.get("key_name")
                                .and_then(|r| r.as_str())
                                .map(|s| s.to_string())
                        })
                        .unwrap_or_default()
                }
                kind if kind.starts_with("session.") => {
                    let workflow = receipt_value
                        .as_ref()
                        .and_then(|v| v.get("body"))
                        .and_then(|body| body.get("delegation_template"))
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    let last_tool = receipt_value
                        .as_ref()
                        .and_then(|v| v.get("body"))
                        .and_then(|body| body.get("claim_events"))
                        .and_then(|claims| claims.as_array())
                        .and_then(|claims| claims.last())
                        .and_then(|claim| claim.get("tool"))
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    workflow.or(last_tool).unwrap_or_else(|| kind.to_string())
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
            // both the requested and granted view. For broker receipts,
            // extract scope strings from the receipt JSON itself. For kms
            // receipts the join is meaningless — surface `None` for both.
            let (requested_scope, granted_scope) = match kind.as_str() {
                "grant" => (granted_scope.clone(), granted_scope.clone()),
                "broker_materialization" | "broker_revocation" => {
                    let req = receipt_value
                        .as_ref()
                        .and_then(|v| v.get("requested_scope"))
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_string());
                    let grnt = receipt_value
                        .as_ref()
                        .and_then(|v| v.get("granted_scope"))
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_string());
                    (req, grnt)
                }
                _ => (None, None),
            };

            let signed = if kind.starts_with("session.") || kind.contains('.') {
                receipt_value
                    .as_ref()
                    .and_then(|v| v.get("signature"))
                    .and_then(|v| v.as_str())
                    .map(|sig| !sig.is_empty())
                    .unwrap_or(false)
            } else {
                signer_pubkey != "0".repeat(64) && !signer_pubkey.is_empty()
            };
            if filter.signed_only && !signed {
                continue;
            }

            let delegation_template = receipt_value
                .as_ref()
                .and_then(|v| v.get("body"))
                .and_then(|body| body.get("delegation_template"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let claim_count_total = receipt_value
                .as_ref()
                .and_then(|v| v.get("body"))
                .and_then(|body| body.get("claim_count_total"))
                .and_then(|v| v.as_u64());
            let claim_events_truncated = receipt_value
                .as_ref()
                .and_then(|v| v.get("body"))
                .and_then(|body| body.get("claim_events_truncated"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let claim_segment_count = receipt_value
                .as_ref()
                .and_then(|v| v.get("body"))
                .and_then(|body| body.get("claim_segment_summaries"))
                .and_then(|v| v.as_array())
                .map(|v| v.len() as u64);
            let claim_history_merkle_root = receipt_value
                .as_ref()
                .and_then(|v| v.get("body"))
                .and_then(|body| body.get("claim_history_merkle_root"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let action_ref = receipt_value
                .as_ref()
                .and_then(|v| {
                    v.get("action_ref").cloned().or_else(|| {
                        v.get("body")
                            .and_then(|body| body.get("action_ref"))
                            .cloned()
                    })
                })
                .and_then(|value| serde_json::from_value::<ActionRef>(value).ok());
            let contract_id = receipt_value.as_ref().and_then(|v| {
                v.get("contract_id")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
                    .or_else(|| {
                        v.get("body")
                            .and_then(|body| body.get("contract_id"))
                            .and_then(|value| value.as_str())
                            .map(str::to_string)
                    })
            });
            let workspace_ref = receipt_value.as_ref().and_then(|v| {
                v.get("workspace_ref")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
                    .or_else(|| {
                        v.get("body")
                            .and_then(|body| body.get("workspace_ref"))
                            .and_then(|value| value.as_str())
                            .map(str::to_string)
                    })
            });
            let caller_ref = receipt_value.as_ref().and_then(|v| {
                v.get("caller_ref")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
                    .or_else(|| {
                        v.get("body")
                            .and_then(|body| body.get("caller_ref"))
                            .and_then(|value| value.as_str())
                            .map(str::to_string)
                    })
            });
            let authority_ref = receipt_value.as_ref().and_then(|v| {
                v.get("authority_ref")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
                    .or_else(|| {
                        v.get("body")
                            .and_then(|body| body.get("authority_ref"))
                            .and_then(|value| value.as_str())
                            .map(str::to_string)
                    })
            });

            out.push(ReceiptRow {
                id,
                kind,
                actor: persona_id,
                resource,
                action_ref,
                contract_id,
                workspace_ref,
                caller_ref,
                authority_ref,
                grant_id,
                materialized_at: created_at,
                terminal_reason,
                requested_scope,
                granted_scope,
                signed,
                delegation_template,
                claim_count_total,
                claim_events_truncated,
                claim_segment_count,
                claim_history_merkle_root,
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
mod tests;

#[cfg(test)]
mod broker_v2_tests;

#[cfg(test)]
mod v2_envelope_listing_tests;

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
//
// ZeroizeOnDrop note: `DaemonPersona` derives `ZeroizeOnDrop`, but the value
// stored in this `OnceCell` is never dropped during normal process execution —
// `OnceCell` holds its content for the entire lifetime of the static. This
// means the signing key is NOT zeroized on process exit via this path.
// That is accepted steady-state: process exit releases all memory anyway, and
// OS-level guard pages protect against cross-process reads. The derive still
// provides correct-by-default discipline for any future rotation/reload path
// that replaces this cell (which must be a new allocation, not an in-place
// mutation), and it clears temporary `DaemonPersona` values created in tests
// or intermediate load paths.

static IDENTITY: OnceCell<DaemonPersona> = OnceCell::new();

/// Initialise the process-singleton identity. Calling a second time with a
/// different `data_dir` has no effect; the first initialisation wins.
/// Returns the pubkey hex of the (now-active) identity for log/banner
/// surfaces.
pub fn init_identity(data_dir: &Path) -> Result<String, StoreError> {
    // Fast path: already initialised.
    if let Some(id) = IDENTITY.get() {
        return Ok(id.pubkey_hex());
    }
    let id = DaemonPersona::load_or_create(data_dir)?;
    let pubkey = id.pubkey_hex();
    // get_or_init ensures exactly-once semantics even under concurrent init.
    IDENTITY.get_or_init(|| id);
    Ok(pubkey)
}

/// Access the process identity if previously initialised.
pub fn current_identity() -> Option<&'static DaemonPersona> {
    IDENTITY.get()
}

fn emit_atomic_receipt_v2_current<T: serde::Serialize>(
    store: &DaemonStore,
    kind: &str,
    grant_id: &str,
    persona_id: &str,
    terminal_reason: &str,
    body: &T,
) -> Option<String> {
    let Some(identity) = current_identity() else {
        tracing::warn!(
            grant_id = %grant_id,
            kind = %kind,
            "atomic receipt emission skipped — daemon identity not initialised"
        );
        return None;
    };

    let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
    let mut body_value = match serde_json::to_value(body) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(grant_id = %grant_id, kind = %kind, %error, "atomic receipt body serialize failed");
            return None;
        }
    };
    let attribution = daemon_signing_attribution(&identity.pubkey_hex());
    stamp_signer_attribution(&mut body_value, &attribution);
    let mut envelope = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: kind.to_string(),
        receipt_id: String::new(),
        daemon_root_id: identity.pubkey_hex(),
        traceparent: None,
        termination_authority: TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body: body_value,
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    if let Err(error) = core_events::receipt::sign::sign_receipt_v2(&mut envelope, &signer) {
        tracing::warn!(grant_id = %grant_id, kind = %kind, %error, "atomic receipt sign failed");
        return None;
    }
    if let Err(error) =
        store.store_atomic_receipt_v2(&envelope, grant_id, persona_id, terminal_reason)
    {
        tracing::warn!(grant_id = %grant_id, kind = %kind, %error, "atomic receipt persistence failed");
        return None;
    }
    Some(envelope.receipt_id)
}

pub fn emit_payment_evaluated_receipt_current(
    store: &DaemonStore,
    grant_id: &str,
    persona_id: &str,
    body: &core_events::receipt::PaymentEvaluatedBody,
) -> Option<String> {
    let terminal_reason = match body.state {
        core_events::receipt::PaymentEvaluatedState::Allowed => "allowed",
        core_events::receipt::PaymentEvaluatedState::Denied => "denied",
        core_events::receipt::PaymentEvaluatedState::EscalationRequired => "escalation_required",
        core_events::receipt::PaymentEvaluatedState::Reserved => "reserved",
    };
    emit_atomic_receipt_v2_current(
        store,
        core_events::receipt::RECEIPT_KIND_PAYMENT_EVALUATED,
        grant_id,
        persona_id,
        terminal_reason,
        body,
    )
}

pub fn emit_payment_settled_receipt_current(
    store: &DaemonStore,
    grant_id: &str,
    persona_id: &str,
    body: &core_events::receipt::PaymentSettledBody,
) -> Option<String> {
    let terminal_reason = match body.state {
        core_events::receipt::PaymentSettledState::Committed => "committed",
        core_events::receipt::PaymentSettledState::Voided => "voided",
        core_events::receipt::PaymentSettledState::Expired => "expired",
    };
    emit_atomic_receipt_v2_current(
        store,
        core_events::receipt::RECEIPT_KIND_PAYMENT_SETTLED,
        grant_id,
        persona_id,
        terminal_reason,
        body,
    )
}

pub fn emit_proxy_call_receipt_current(
    store: &DaemonStore,
    grant_id: &str,
    persona_id: &str,
    body: &core_events::receipt::ProxyCallBody,
) -> Option<String> {
    let terminal_reason = if body.outcome.trim().is_empty() {
        "complete"
    } else {
        body.outcome.as_str()
    };
    emit_atomic_receipt_v2_current(
        store,
        core_events::receipt::RECEIPT_KIND_PROXY_CALL,
        grant_id,
        persona_id,
        terminal_reason,
        body,
    )
}

pub fn emit_headless_enrollment_receipt_current(
    store: &DaemonStore,
    body: &core_events::receipt::HeadlessEnrollmentBody,
) -> Option<String> {
    emit_atomic_receipt_v2_current(
        store,
        core_events::receipt::RECEIPT_KIND_HEADLESS_ENROLLMENT,
        "",
        &body.persona,
        "enrolled",
        body,
    )
}

pub fn emit_headless_revocation_receipt_current(
    store: &DaemonStore,
    body: &core_events::receipt::HeadlessRevocationBody,
) -> Option<String> {
    emit_atomic_receipt_v2_current(
        store,
        core_events::receipt::RECEIPT_KIND_HEADLESS_REVOCATION,
        "",
        &body.persona,
        &body.reason,
        body,
    )
}

fn map_grant_terminal_reason_to_session_reason(
    reason: &TerminalReason,
) -> Option<core_events::receipt::TerminationReason> {
    match reason {
        TerminalReason::Expired => Some(core_events::receipt::TerminationReason::TtlExpired),
        TerminalReason::Revoked {
            by: RevokeActor::Operator,
            ..
        } => Some(core_events::receipt::TerminationReason::ExplicitRevoke),
        TerminalReason::Abandoned { .. } => {
            Some(core_events::receipt::TerminationReason::ExplicitRevoke)
        }
        TerminalReason::ExhaustedByBudget { .. } => {
            Some(core_events::receipt::TerminationReason::ExhaustedByBudget)
        }
        TerminalReason::ParentCascadeRevoked { .. } => {
            Some(core_events::receipt::TerminationReason::ParentCascadeRevoked)
        }
        TerminalReason::Revoked { .. } => None,
    }
}

fn emit_composite_grant_receipt_v2_current(
    store: &DaemonStore,
    grant_id: &str,
    persona_id: &str,
    reason: core_events::receipt::TerminationReason,
) {
    let Some(identity) = current_identity() else {
        tracing::warn!(
            grant_id = %grant_id,
            "session.composite_grant v2 emission skipped — daemon identity not initialised"
        );
        return;
    };

    let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
    let synthetic_session_id = format!("grant:{grant_id}");
    let termination = Some(TerminationMeta {
        reason,
        last_heartbeat_at: None,
        pid_alive_at_check: None,
    });
    let Some(scope_summary) = close_grant_scope_best_effort(
        store,
        grant_id,
        "infra::receipt::emit_composite_grant_receipt_v2_current",
    ) else {
        tracing::debug!(
            grant_id = %grant_id,
            "session.composite_grant v2 emission skipped — no claim-journal scope for grant"
        );
        return;
    };
    let envelope_result = issue_session_receipt_from_closed_scope(
        core_events::receipt::RECEIPT_KIND_COMPOSITE_GRANT,
        &synthetic_session_id,
        &scope_summary,
        None,
        TerminationAuthority::DaemonPersona,
        &identity.pubkey_hex(),
        termination,
        &signer,
    );

    match envelope_result {
        Ok(envelope) => {
            if let Err(e) = store.store_session_receipt_v2(&envelope, grant_id, persona_id) {
                tracing::warn!(
                    grant_id = %grant_id,
                    error = %e,
                    "session.composite_grant v2 persistence failed"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                grant_id = %grant_id,
                error = %e,
                "session.composite_grant v2 emission failed"
            );
        }
    }
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
    let session_reason = explicit_reason
        .as_ref()
        .and_then(map_grant_terminal_reason_to_session_reason);
    let Some(identity) = current_identity() else {
        tracing::warn!(
            grant_id = %grant_id,
            "receipt emission skipped — daemon identity not initialised"
        );
        return None;
    };
    match trigger_receipt_if_terminal(store, identity, grant_id, explicit_reason) {
        Ok(Some(rid)) => {
            if let Some(reason) = session_reason
                && let Ok(info) = store.get_grant(grant_id)
            {
                emit_composite_grant_receipt_v2_current(store, grant_id, &info.persona_id, reason);
            }
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
// kms receipt sink wiring
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
mod kms_tests;
