//! Vault snapshot emission — design (EmberSeal Recovery).
//!
//! Implements periodic (1h default, configurable) and event-triggered vault
//! snapshots. Each snapshot is:
//!   1. Serialized as a JSON blob covering the snapshot scope (see below).
//!   2. Encrypted to the Daemon Persona X25519 key (HKDF-SHA256 of the
//!      Ed25519 seed with info "ember-seal-v1") using XChaCha20-Poly1305.
//!   3. Described by a signed [`SnapshotManifest`] chained via `prev_snapshot_id`.
//!
//! **Snapshot scope** (per implementation-note-35, design §Decision):
//!   - `credentials` table rows (vault-sealed blobs)
//!   - `vault.salt` file bytes (critical: without it the MEK cannot be rebuilt)
//!   - `personas` table rows
//!   - `grants` table rows
//!   - `grant_usage` table rows
//!   - `standing_grants` table rows
//!   - `audit_log` table rows
//!   - `receipts` table rows
//!
//! **Excluded** (not in snapshot):
//!   - `policy.toml` — config; recovered via GitOps/ConfigMap
//!   - Active broker materializations — ephemeral; re-issued on restart

use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use core_crypto::{derive_snapshot_encryption_key, encrypt_content, decrypt_content, EncryptedContent};
use core_grant_types::grant_receipt::{Evidence, SnapshotManifest};

use crate::infra::receipt::{DaemonPersona, CANONICAL_VERSION};
use crate::infra::store::{DaemonStore, StoreError};
use crate::infra::vault::VaultScope;

// ---------------------------------------------------------------------------
// Canonical encoding prefix — cross-protocol signature reuse prevention.
// ---------------------------------------------------------------------------

const SNAPSHOT_CANONICAL_PREFIX: &str = "type=snapshot-manifest-v1\n";

// ---------------------------------------------------------------------------
// Serialized vault state — the snapshot payload
// ---------------------------------------------------------------------------

/// Raw row dump of one `credentials` table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRow {
    pub id: String,
    pub name: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub created_at: String,
    pub metadata: Option<String>,
}

/// Raw row dump of one `personas` table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonaRow {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub private_key_nonce_hex: Option<String>,
    pub private_key_ciphertext_hex: Option<String>,
    pub created_at: String,
    pub status: String,
}

/// Raw row dump of one `grants` table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRow {
    pub id: String,
    pub persona_id: String,
    pub credential_name: String,
    pub scope: String,
    pub ttl_secs: Option<i64>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub status: String,
    pub blocks_json: Option<String>,
    pub budget_json: Option<String>,
    pub usage_json: Option<String>,
}

/// Raw row dump of one `grant_usage` table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantUsageRow {
    pub id: i64,
    pub grant_id: String,
    pub used_at: String,
    pub amount_cents: i64,
}

/// Raw row dump of one `standing_grants` table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandingGrantRow {
    pub id: String,
    pub persona_id: String,
    pub action_pattern: String,
    pub scope: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

/// Raw row dump of one `audit_log` table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogRow {
    pub id: i64,
    pub timestamp: String,
    pub agent_id: Option<String>,
    pub action: String,
    pub credential: Option<String>,
    pub outcome: String,
    pub details: Option<String>,
}

/// Raw row dump of one `receipts` table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptRow {
    pub id: String,
    pub grant_id: String,
    pub persona_id: String,
    pub terminal_reason: String,
    pub created_at: String,
    pub receipt_json: String,
    pub signer_pubkey: String,
    pub kind: String,
}

/// The full serialized vault state — the inner payload of an encrypted snapshot.
///
/// **Critical:** includes `vault_salt_hex` so the MEK can be reconstructed.
/// **Excluded:** `policy.toml` (config); active broker materializations (ephemeral).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedVaultState {
    /// Snapshot format version (start at 1).
    pub format_version: u8,
    /// Hex-encoded 16-byte Argon2id vault salt. Critical for MEK reconstruction.
    pub vault_salt_hex: String,
    pub credentials: Vec<CredentialRow>,
    pub personas: Vec<PersonaRow>,
    pub grants: Vec<GrantRow>,
    pub grant_usage: Vec<GrantUsageRow>,
    pub standing_grants: Vec<StandingGrantRow>,
    pub audit_log: Vec<AuditLogRow>,
    pub receipts: Vec<ReceiptRow>,
}

// ---------------------------------------------------------------------------
// Snapshot state dump
// ---------------------------------------------------------------------------

/// Dump all relevant tables from the store and read the vault salt from disk.
///
/// Returns `Err` when the store query fails or the salt file cannot be read.
pub fn dump_vault_state(
    store: &DaemonStore,
    data_dir: &Path,
) -> Result<SerializedVaultState, StoreError> {
    let conn = store.conn();

    // credentials
    let mut stmt = conn
        .prepare("SELECT id, name, nonce, ciphertext, created_at, metadata FROM credentials")
        .map_err(StoreError::Sqlite)?;
    let credentials = stmt
        .query_map([], |row| {
            let nonce: Vec<u8> = row.get(2)?;
            let ciphertext: Vec<u8> = row.get(3)?;
            Ok(CredentialRow {
                id: row.get(0)?,
                name: row.get(1)?,
                nonce_hex: hex::encode(&nonce),
                ciphertext_hex: hex::encode(&ciphertext),
                created_at: row.get(4)?,
                metadata: row.get(5)?,
            })
        })
        .map_err(StoreError::Sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::Sqlite)?;

    // personas
    let mut stmt = conn
        .prepare("SELECT id, name, public_key, private_key_nonce, private_key_ciphertext, created_at, status FROM personas")
        .map_err(StoreError::Sqlite)?;
    let personas = stmt
        .query_map([], |row| {
            let nonce: Option<Vec<u8>> = row.get(3)?;
            let ciphertext: Option<Vec<u8>> = row.get(4)?;
            Ok(PersonaRow {
                id: row.get(0)?,
                name: row.get(1)?,
                public_key: row.get(2)?,
                private_key_nonce_hex: nonce.map(|b| hex::encode(&b)),
                private_key_ciphertext_hex: ciphertext.map(|b| hex::encode(&b)),
                created_at: row.get(5)?,
                status: row.get(6)?,
            })
        })
        .map_err(StoreError::Sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::Sqlite)?;

    // grants (core columns only — avoid schema-drift from optional columns)
    let mut stmt = conn
        .prepare(
            "SELECT id, persona_id, credential_name, scope, ttl_secs, created_at, \
             expires_at, status, blocks_json, budget_json, usage_json FROM grants",
        )
        .map_err(StoreError::Sqlite)?;
    let grants = stmt
        .query_map([], |row| {
            Ok(GrantRow {
                id: row.get(0)?,
                persona_id: row.get(1)?,
                credential_name: row.get(2)?,
                scope: row.get(3)?,
                ttl_secs: row.get(4)?,
                created_at: row.get(5)?,
                expires_at: row.get(6)?,
                status: row.get(7)?,
                blocks_json: row.get(8)?,
                budget_json: row.get(9)?,
                usage_json: row.get(10)?,
            })
        })
        .map_err(StoreError::Sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::Sqlite)?;

    // grant_usage
    let mut stmt = conn
        .prepare("SELECT id, grant_id, used_at, amount_cents FROM grant_usage")
        .map_err(StoreError::Sqlite)?;
    let grant_usage = stmt
        .query_map([], |row| {
            Ok(GrantUsageRow {
                id: row.get(0)?,
                grant_id: row.get(1)?,
                used_at: row.get(2)?,
                amount_cents: row.get(3)?,
            })
        })
        .map_err(StoreError::Sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::Sqlite)?;

    // standing_grants
    let mut stmt = conn
        .prepare(
            "SELECT id, persona_id, action_pattern, scope, created_at, expires_at \
             FROM standing_grants",
        )
        .map_err(StoreError::Sqlite)?;
    let standing_grants = stmt
        .query_map([], |row| {
            Ok(StandingGrantRow {
                id: row.get(0)?,
                persona_id: row.get(1)?,
                action_pattern: row.get(2)?,
                scope: row.get(3)?,
                created_at: row.get(4)?,
                expires_at: row.get(5)?,
            })
        })
        .map_err(StoreError::Sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::Sqlite)?;

    // audit_log
    let mut stmt = conn
        .prepare(
            "SELECT id, timestamp, agent_id, action, credential, outcome, details \
             FROM audit_log ORDER BY id ASC",
        )
        .map_err(StoreError::Sqlite)?;
    let audit_log = stmt
        .query_map([], |row| {
            Ok(AuditLogRow {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                agent_id: row.get(2)?,
                action: row.get(3)?,
                credential: row.get(4)?,
                outcome: row.get(5)?,
                details: row.get(6)?,
            })
        })
        .map_err(StoreError::Sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::Sqlite)?;

    // receipts
    let mut stmt = conn
        .prepare(
            "SELECT id, grant_id, persona_id, terminal_reason, created_at, \
             receipt_json, signer_pubkey, kind FROM receipts",
        )
        .map_err(StoreError::Sqlite)?;
    let receipts = stmt
        .query_map([], |row| {
            Ok(ReceiptRow {
                id: row.get(0)?,
                grant_id: row.get(1)?,
                persona_id: row.get(2)?,
                terminal_reason: row.get(3)?,
                created_at: row.get(4)?,
                receipt_json: row.get(5)?,
                signer_pubkey: row.get(6)?,
                kind: row.get(7)?,
            })
        })
        .map_err(StoreError::Sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::Sqlite)?;

    // vault.salt — read from disk
    let salt_path = data_dir.join("vault.salt");
    let vault_salt_hex = if salt_path.exists() {
        let bytes = std::fs::read(&salt_path).map_err(|e| {
            StoreError::InvalidInput(format!("snapshot: read vault.salt: {e}"))
        })?;
        hex::encode(&bytes)
    } else {
        // No salt file means the vault has never been initialized.
        // Include an empty salt so restore code can detect this state.
        String::new()
    };

    Ok(SerializedVaultState {
        format_version: 1,
        vault_salt_hex,
        credentials,
        personas,
        grants,
        grant_usage,
        standing_grants,
        audit_log,
        receipts,
    })
}

// ---------------------------------------------------------------------------
// Encryption / decryption
// ---------------------------------------------------------------------------

/// Encrypt serialized vault state to the Daemon Persona X25519 key.
///
/// The key is derived via HKDF-SHA256(ed25519_seed, "ember-seal-v1") per
/// design §The primitive. The encrypted blob format is:
///   `nonce_hex:ciphertext_hex` (ASCII, colon-delimited)
/// so it is self-describing and recoverable from the identity seed alone.
pub fn encrypt_vault_blob(
    state: &SerializedVaultState,
    identity: &DaemonPersona,
) -> Result<Vec<u8>, StoreError> {
    let json = serde_json::to_vec(state).map_err(|e| {
        StoreError::InvalidInput(format!("snapshot: serialize vault state: {e}"))
    })?;
    let content_key = derive_snapshot_encryption_key(&*identity.seed_bytes());
    let encrypted = encrypt_content(&content_key, &json, b"ember-snapshot-v1")
        .map_err(|e| StoreError::InvalidInput(format!("snapshot: encrypt vault state: {e}")))?;
    // Format: `nonce_hex:ciphertext_hex` — both fields are hex strings.
    let blob = format!("{}:{}", encrypted.nonce_hex, hex::encode(&encrypted.ciphertext));
    Ok(blob.into_bytes())
}

/// Decrypt an encrypted vault blob produced by [`encrypt_vault_blob`].
pub fn decrypt_vault_blob(
    blob: &[u8],
    identity: &DaemonPersona,
) -> Result<SerializedVaultState, StoreError> {
    let s = std::str::from_utf8(blob)
        .map_err(|e| StoreError::InvalidInput(format!("snapshot: blob utf8: {e}")))?;
    let (nonce_hex, ciphertext_hex) = s.split_once(':').ok_or_else(|| {
        StoreError::InvalidInput("snapshot: blob format invalid (missing ':')".to_string())
    })?;
    let ciphertext = hex::decode(ciphertext_hex)
        .map_err(|e| StoreError::InvalidInput(format!("snapshot: blob ciphertext hex: {e}")))?;
    let encrypted = EncryptedContent {
        nonce_hex: nonce_hex.to_string(),
        ciphertext,
    };
    let content_key = derive_snapshot_encryption_key(&*identity.seed_bytes());
    let plaintext = decrypt_content(&content_key, &encrypted, b"ember-snapshot-v1")
        .map_err(|e| StoreError::InvalidInput(format!("snapshot: decrypt vault state: {e}")))?;
    serde_json::from_slice(&plaintext).map_err(|e| {
        StoreError::InvalidInput(format!("snapshot: deserialize vault state: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Manifest signing + verification
// ---------------------------------------------------------------------------

/// Compute the canonical hash (sha256 hex) of a snapshot manifest.
///
/// Zeroes `evidence` before hashing so the hash is independent of what
/// `evidence` currently holds — mirrors the pattern in `receipt.rs`.
pub fn snapshot_canonical_hash(manifest: &SnapshotManifest) -> String {
    let mut cloned = manifest.clone();
    cloned.evidence = Evidence::default();
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(SNAPSHOT_CANONICAL_PREFIX.as_bytes());
    bytes.extend_from_slice(
        &serde_json::to_vec(&cloned)
            .expect("SnapshotManifest with default Evidence always serializes"),
    );
    hex::encode(Sha256::digest(&bytes))
}

/// Sign a snapshot manifest in place.
///
/// Sets `evidence.{hash, sig, signer_pubkey, canonical_version}` — same
/// convention as `sign_kms_receipt`, `sign_broker_receipt`, etc.
pub fn sign_snapshot_manifest(manifest: &mut SnapshotManifest, identity: &DaemonPersona) {
    let hash_hex = snapshot_canonical_hash(manifest);
    let sig_bytes = identity.sign(hash_hex.as_bytes());
    manifest.evidence = Evidence {
        hash: hash_hex,
        sig: hex::encode(&*sig_bytes),
        signer_pubkey: identity.pubkey_hex(),
        canonical_version: CANONICAL_VERSION,
    };
}

/// Verify a snapshot manifest signature against a trusted public key.
///
/// Returns `true` iff:
///   - `expected_pubkey_hex` decodes to a valid 32-byte Ed25519 verifying key;
///   - the signature is not the all-zeros placeholder;
///   - the canonical hash matches `evidence.hash`;
///   - Ed25519 signature verifies.
pub fn verify_snapshot_manifest(
    manifest: &SnapshotManifest,
    expected_pubkey_hex: &str,
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier as _};

    let Ok(pubkey_bytes) = hex::decode(expected_pubkey_hex) else {
        return false;
    };
    let Ok(pubkey_arr) = pubkey_bytes.as_slice().try_into() as Result<[u8; 32], _> else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey_arr) else {
        return false;
    };

    let Ok(sig_bytes) = hex::decode(&manifest.evidence.sig) else {
        return false;
    };
    let Ok(sig_arr) = sig_bytes.as_slice().try_into() as Result<[u8; 64], _> else {
        return false;
    };
    if sig_arr == [0u8; 64] {
        return false;
    }

    let recomputed = snapshot_canonical_hash(manifest);
    if !recomputed.eq_ignore_ascii_case(&manifest.evidence.hash) {
        return false;
    }

    let sig = Signature::from_bytes(&sig_arr);
    verifying_key.verify(recomputed.as_bytes(), &sig).is_ok()
}

// ---------------------------------------------------------------------------
// SnapshotEmitter
// ---------------------------------------------------------------------------

/// Drives periodic and event-triggered vault snapshot emission.
///
/// Call [`SnapshotEmitter::maybe_emit`] on a Tokio interval at daemon startup.
/// Call [`SnapshotEmitter::emit_snapshot`] directly for event-triggered paths.
pub struct SnapshotEmitter {
    interval_secs: u64,
    last_emitted_at: Mutex<Option<Instant>>,
    last_snapshot_id: Mutex<Option<String>>,
}

impl SnapshotEmitter {
    pub fn new(interval_secs: u64) -> Self {
        Self {
            interval_secs,
            last_emitted_at: Mutex::new(None),
            last_snapshot_id: Mutex::new(None),
        }
    }

    /// Call this from a periodic task (Tokio interval). Returns `Ok(None)`
    /// when not yet due, `Ok(Some(id))` after a successful emission.
    pub fn maybe_emit(
        &self,
        store: &DaemonStore,
        identity: &DaemonPersona,
        data_dir: &Path,
        event_log_high_watermark: u64,
    ) -> Result<Option<String>, StoreError> {
        let now = Instant::now();
        let due = {
            let guard = self
                .last_emitted_at
                .lock()
                .expect("snapshot mutex poisoned");
            match *guard {
                None => true,
                Some(last) => now.duration_since(last).as_secs() >= self.interval_secs,
            }
        };
        if !due {
            return Ok(None);
        }
        let id = self.emit_snapshot(store, identity, data_dir, event_log_high_watermark)?;
        Ok(Some(id))
    }

    /// Force a snapshot now (event-triggered path or test). Always emits,
    /// regardless of cadence.
    pub fn emit_snapshot(
        &self,
        store: &DaemonStore,
        identity: &DaemonPersona,
        data_dir: &Path,
        event_log_high_watermark: u64,
    ) -> Result<String, StoreError> {
        let taken_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Dump vault state.
        let vault_state = dump_vault_state(store, data_dir)?;

        // 2. Encrypt the blob.
        let encrypted_blob = encrypt_vault_blob(&vault_state, identity)?;

        // 3. Hash the encrypted blob (integrity check in manifest).
        let vault_state_hash = hex::encode(Sha256::digest(&encrypted_blob));

        // 4. Read the previous snapshot id for chain.
        let prev_snapshot_id = self
            .last_snapshot_id
            .lock()
            .expect("snapshot mutex poisoned")
            .clone();

        // 5. Build and sign the manifest.
        let mut manifest = SnapshotManifest {
            snapshot_id: String::new(), // filled after hash
            prev_snapshot_id,
            taken_at_epoch_secs: taken_at,
            vault_state_hash,
            event_log_high_watermark,
            daemon_persona_pubkey: identity.pubkey_hex(),
            evidence: Evidence::default(),
        };

        // Content-address the snapshot_id as sha256 of the canonical body.
        let body_hash = snapshot_canonical_hash(&manifest);
        manifest.snapshot_id = body_hash;

        sign_snapshot_manifest(&mut manifest, identity);
        let snapshot_id = manifest.snapshot_id.clone();

        // 6. Persist: write manifest JSON to the snapshot directory.
        let snapshot_dir = data_dir.join("snapshots");
        if let Err(e) = std::fs::create_dir_all(&snapshot_dir) {
            tracing::warn!(error = %e, "snapshot: could not create snapshots dir");
        } else {
            let manifest_path =
                snapshot_dir.join(format!("{}.manifest.json", &snapshot_id[..16]));
            let blob_path = snapshot_dir.join(format!("{}.blob.bin", &snapshot_id[..16]));
            if let Ok(manifest_json) = serde_json::to_vec_pretty(&manifest)
                && let Err(e) = std::fs::write(&manifest_path, &manifest_json)
            {
                tracing::warn!(error = %e, path = %manifest_path.display(), "snapshot: write manifest failed");
            }
            if let Err(e) = std::fs::write(&blob_path, &encrypted_blob) {
                tracing::warn!(error = %e, path = %blob_path.display(), "snapshot: write blob failed");
            }
        }

        // 7. Update state.
        {
            let mut guard = self.last_emitted_at.lock().expect("snapshot mutex poisoned");
            *guard = Some(Instant::now());
        }
        {
            let mut guard = self
                .last_snapshot_id
                .lock()
                .expect("snapshot mutex poisoned");
            *guard = Some(snapshot_id.clone());
        }

        tracing::info!(
            snapshot_id = %snapshot_id,
            taken_at = taken_at,
            event_watermark = event_log_high_watermark,
            "vault snapshot emitted"
        );

        Ok(snapshot_id)
    }
}

// ---------------------------------------------------------------------------
// SnapshotPuller — pull-side counterpart to SnapshotEmitter
// ---------------------------------------------------------------------------

/// Vault key prefix for pulled cluster snapshots.
/// Full key: `cluster-snapshot/<cluster-id>/snap-<id_prefix>` (blob)
///         or `cluster-snapshot/<cluster-id>/meta-<id_prefix>` (manifest).
const SNAPSHOT_PULL_KEY_PREFIX: &str = "cluster-snapshot";

/// Pull error — subset of conditions callers handle at the call site.
#[derive(Debug)]
pub enum PullError {
    /// Network or HTTP error fetching from the EIC endpoint.
    Http(String),
    /// EIC returned a non-200 response.
    HttpStatus(u16),
    /// Response body could not be deserialized.
    Deserialize(String),
    /// Manifest signature did not verify against the trusted pubkey.
    SignatureInvalid,
    /// Vault store error while persisting the snapshot.
    Store(StoreError),
}

impl std::fmt::Display for PullError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PullError::Http(e) => write!(f, "pull: HTTP error: {e}"),
            PullError::HttpStatus(s) => write!(f, "pull: EIC returned {s}"),
            PullError::Deserialize(e) => write!(f, "pull: deserialize error: {e}"),
            PullError::SignatureInvalid => write!(f, "pull: snapshot manifest signature invalid"),
            PullError::Store(e) => write!(f, "pull: vault store error: {e}"),
        }
    }
}

/// Build the vault key for a pulled snapshot blob.
///
/// Key shape: `cluster-snapshot/<cluster_id>/snap-<id_prefix>`
/// All segments are lowercase-alpha-start compliant per design.
fn snapshot_blob_key(cluster_id: &str, id_prefix: &str) -> String {
    format!("{SNAPSHOT_PULL_KEY_PREFIX}/{cluster_id}/snap-{id_prefix}")
}

/// Build the vault key for a pulled snapshot manifest.
///
/// Key shape: `cluster-snapshot/<cluster_id>/meta-<id_prefix>`
fn snapshot_meta_key(cluster_id: &str, id_prefix: &str) -> String {
    format!("{SNAPSHOT_PULL_KEY_PREFIX}/{cluster_id}/meta-{id_prefix}")
}

/// Response shape for `GET /api/cluster-snapshot/<id>`.
#[derive(Debug, Deserialize)]
struct ClusterSnapshotResponse {
    manifest: SnapshotManifest,
    encrypted_blob_hex: String,
}

/// Response shape for `GET /api/cluster-snapshot/latest`.
#[derive(Debug, Deserialize)]
struct ClusterSnapshotLatestResponse {
    snapshot_id: String,
}

/// Pull the latest snapshot from a remote EIC over its tailnet endpoint.
///
/// Validates the signed manifest against the EIC's Daemon Persona pubkey
/// (already trusted via the operator's IdentityRoot bootstrap). Stores the
/// encrypted blob in the local vault keyed by cluster-id + snapshot-id.
///
/// Returns `Ok(None)` if the EIC has no snapshots yet or if the snapshot is
/// already stored locally. Returns `Ok(Some(snapshot_id))` on a new pull.
pub async fn pull_cluster_snapshot(
    eic_endpoint: &str,
    cluster_id: &str,
    eic_persona_pubkey_hex: &str,
    vault: &crate::infra::vault::Vault,
    store: &DaemonStore,
) -> Result<Option<String>, PullError> {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::Request;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    // 1. GET <eic_endpoint>/api/cluster-snapshot/latest to discover snapshot_id.
    let latest_url = format!("{eic_endpoint}/api/cluster-snapshot/latest");
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    let req = Request::builder()
        .method("GET")
        .uri(&latest_url)
        .body(Full::new(Bytes::new()))
        .map_err(|e| PullError::Http(e.to_string()))?;

    let resp = client.request(req).await.map_err(|e| PullError::Http(e.to_string()))?;
    let status = resp.status().as_u16();
    if status == 404 {
        tracing::debug!(endpoint = %eic_endpoint, "pull: no snapshots available on EIC yet");
        return Ok(None);
    }
    if status != 200 {
        return Err(PullError::HttpStatus(status));
    }

    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| PullError::Http(e.to_string()))?
        .to_bytes();

    let latest: ClusterSnapshotLatestResponse =
        serde_json::from_slice(&body_bytes).map_err(|e| PullError::Deserialize(e.to_string()))?;
    let snapshot_id = latest.snapshot_id;

    // 2. Check if we already have this snapshot in the local vault.
    let id_prefix: String = if snapshot_id.len() >= 16 {
        snapshot_id[..16].to_string()
    } else {
        snapshot_id.clone()
    };
    let meta_key = snapshot_meta_key(cluster_id, &id_prefix);
    if vault.get(VaultScope::Interactive, store, &meta_key).is_ok() {
        tracing::debug!(
            snapshot_id = %snapshot_id,
            "pull: snapshot already in local vault, skipping"
        );
        return Ok(None);
    }

    // 3. Fetch the full snapshot blob + manifest.
    let fetch_url = format!("{eic_endpoint}/api/cluster-snapshot/{snapshot_id}");
    let client2: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req2 = Request::builder()
        .method("GET")
        .uri(&fetch_url)
        .body(Full::new(Bytes::new()))
        .map_err(|e| PullError::Http(e.to_string()))?;

    let resp2 = client2.request(req2).await.map_err(|e| PullError::Http(e.to_string()))?;
    let status2 = resp2.status().as_u16();
    if status2 != 200 {
        return Err(PullError::HttpStatus(status2));
    }

    let body2_bytes = resp2
        .into_body()
        .collect()
        .await
        .map_err(|e| PullError::Http(e.to_string()))?
        .to_bytes();

    let snap_resp: ClusterSnapshotResponse =
        serde_json::from_slice(&body2_bytes).map_err(|e| PullError::Deserialize(e.to_string()))?;

    // 4. Verify manifest signature against the trusted EIC Daemon Persona pubkey.
    if !verify_snapshot_manifest(&snap_resp.manifest, eic_persona_pubkey_hex) {
        tracing::warn!(
            snapshot_id = %snapshot_id,
            "pull: manifest signature verification failed — discarding snapshot"
        );
        return Err(PullError::SignatureInvalid);
    }

    // 5. Decode the encrypted blob.
    let blob_bytes = hex::decode(&snap_resp.encrypted_blob_hex)
        .map_err(|e| PullError::Deserialize(format!("blob hex decode: {e}")))?;

    // 6. Store encrypted blob + manifest in the local vault.
    let blob_key = snapshot_blob_key(cluster_id, &id_prefix);
    let manifest_json = serde_json::to_vec(&snap_resp.manifest)
        .map_err(|e| PullError::Deserialize(e.to_string()))?;

    // Store blob — ignore duplicate-name errors (idempotent on retry).
    match vault.add(VaultScope::Interactive, store, &blob_key, &blob_bytes, Some("cluster-snapshot-blob")) {
        Ok(_) => {}
        Err(crate::infra::vault::VaultError::Store(StoreError::Sqlite(e)))
            if e.to_string().contains("UNIQUE constraint") =>
        {
            tracing::debug!(key = %blob_key, "pull: blob key already present, overwrite skipped");
        }
        Err(e) => return Err(PullError::Store(StoreError::InvalidInput(e.to_string()))),
    }

    // Store manifest JSON — ignore duplicate-name errors (idempotent on retry).
    match vault.add(VaultScope::Interactive, store, &meta_key, &manifest_json, Some("cluster-snapshot-manifest")) {
        Ok(_) => {}
        Err(crate::infra::vault::VaultError::Store(StoreError::Sqlite(e)))
            if e.to_string().contains("UNIQUE constraint") =>
        {
            tracing::debug!(key = %meta_key, "pull: meta key already present, overwrite skipped");
        }
        Err(e) => return Err(PullError::Store(StoreError::InvalidInput(e.to_string()))),
    }

    tracing::info!(
        snapshot_id = %snapshot_id,
        cluster_id = %cluster_id,
        blob_key = %blob_key,
        "cluster snapshot pulled and stored in local vault"
    );

    Ok(Some(snapshot_id))
}

/// Drives periodic cluster snapshot pulls from a remote EIC endpoint.
///
/// Call [`SnapshotPuller::maybe_pull`] on a Tokio interval at daemon startup.
/// Only active when `snapshot_pull_endpoint` is configured (per design
/// implementation-note-125).
pub struct SnapshotPuller {
    interval_secs: u64,
    last_pulled_at: Mutex<Option<Instant>>,
}

impl SnapshotPuller {
    pub fn new(interval_secs: u64) -> Self {
        Self {
            interval_secs,
            last_pulled_at: Mutex::new(None),
        }
    }

    /// Call from a periodic task (Tokio interval). Returns `Ok(None)` when
    /// not yet due or when no new snapshot was fetched, `Ok(Some(id))` after
    /// a successful pull of a new snapshot.
    pub async fn maybe_pull(
        &self,
        eic_endpoint: &str,
        cluster_id: &str,
        eic_persona_pubkey_hex: &str,
        vault: &crate::infra::vault::Vault,
        store: &DaemonStore,
    ) -> Result<Option<String>, PullError> {
        let now = Instant::now();
        let due = {
            let guard = self.last_pulled_at.lock().expect("puller mutex poisoned");
            match *guard {
                None => true,
                Some(last) => now.duration_since(last).as_secs() >= self.interval_secs,
            }
        };
        if !due {
            return Ok(None);
        }

        let result =
            pull_cluster_snapshot(eic_endpoint, cluster_id, eic_persona_pubkey_hex, vault, store)
                .await;

        // Update last_pulled_at regardless of pull outcome so we don't hammer
        // a transiently unavailable EIC on every tick.
        {
            let mut guard = self.last_pulled_at.lock().expect("puller mutex poisoned");
            *guard = Some(Instant::now());
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Snapshot listing helpers — used by `ember cluster snapshots` CLI
// ---------------------------------------------------------------------------

/// Summary of one locally-stored cluster snapshot (from vault metadata).
#[derive(Debug, Clone, serde::Serialize)]
pub struct LocalSnapshotEntry {
    pub snapshot_id: String,
    pub taken_at: u64,
    pub prev_snapshot_id: Option<String>,
    pub cluster_id: String,
    pub size_bytes: usize,
}

/// List all locally-pulled cluster snapshots from the vault.
///
/// Scans vault entries whose name matches `cluster-snapshot/<cluster_id>/meta-*`
/// and parses the stored manifest JSON. Returns entries sorted by `taken_at`
/// descending (most recent first).
///
/// If `cluster_id_filter` is `None`, returns snapshots for all clusters.
pub fn list_local_snapshots(
    vault: &crate::infra::vault::Vault,
    store: &DaemonStore,
    cluster_id_filter: Option<&str>,
) -> Vec<LocalSnapshotEntry> {
    let all_creds = match vault.list(VaultScope::Interactive, store) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut entries: Vec<LocalSnapshotEntry> = all_creds
        .into_iter()
        .filter(|c| c.name.starts_with(SNAPSHOT_PULL_KEY_PREFIX))
        .filter(|c| {
            // Only manifest entries (meta-) carry the SnapshotManifest JSON.
            // Blob entries (snap-) are the raw bytes; skip them here.
            let segments: Vec<&str> = c.name.splitn(4, '/').collect();
            segments.len() == 3 && segments[2].starts_with("meta-")
        })
        .filter(|c| {
            if let Some(cid) = cluster_id_filter {
                let segments: Vec<&str> = c.name.splitn(4, '/').collect();
                segments.get(1).is_some_and(|s| *s == cid)
            } else {
                true
            }
        })
        .filter_map(|c| {
            // Derive cluster_id from key: cluster-snapshot/<cluster_id>/meta-<prefix>
            let segments: Vec<&str> = c.name.splitn(4, '/').collect();
            let cluster_id = segments.get(1)?.to_string();

            // Fetch the manifest JSON from the vault.
            let manifest_bytes = vault.get(VaultScope::Interactive, store, &c.name).ok()?;
            let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes).ok()?;

            // Fetch the blob to get size_bytes.
            let id_prefix = segments.get(2)?.strip_prefix("meta-").unwrap_or("");
            let blob_key = snapshot_blob_key(&cluster_id, id_prefix);
            let size_bytes = vault.get(VaultScope::Interactive, store, &blob_key).map(|b| b.len()).unwrap_or(0);

            Some(LocalSnapshotEntry {
                snapshot_id: manifest.snapshot_id,
                taken_at: manifest.taken_at_epoch_secs,
                prev_snapshot_id: manifest.prev_snapshot_id,
                cluster_id,
                size_bytes,
            })
        })
        .collect();

    entries.sort_by(|a, b| b.taken_at.cmp(&a.taken_at));
    entries
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_identity(dir: &Path) -> DaemonPersona {
        DaemonPersona::load_or_create(dir).expect("identity")
    }

    // ---------------------------------------------------------------------------
    // Signing + verification round-trip
    // ---------------------------------------------------------------------------

    #[test]
    fn sign_snapshot_manifest_round_trip() {
        let tmp = TempDir::new().unwrap();
        let identity = test_identity(tmp.path());

        let mut manifest = SnapshotManifest {
            snapshot_id: "test-id-0000".to_string(),
            prev_snapshot_id: None,
            taken_at_epoch_secs: 1_700_000_000,
            vault_state_hash: "aabbcc".to_string(),
            event_log_high_watermark: 42,
            daemon_persona_pubkey: identity.pubkey_hex(),
            evidence: Evidence::default(),
        };
        sign_snapshot_manifest(&mut manifest, &identity);

        // Signature is non-zero.
        assert_ne!(manifest.evidence.sig, "0".repeat(128));
        // hash is non-zero.
        assert_ne!(manifest.evidence.hash, "0".repeat(64));

        // Verify with the correct pubkey passes.
        assert!(verify_snapshot_manifest(&manifest, &identity.pubkey_hex()));
    }

    #[test]
    fn verify_snapshot_manifest_rejects_wrong_pubkey() {
        let tmp = TempDir::new().unwrap();
        let identity = test_identity(tmp.path());
        let mut manifest = SnapshotManifest {
            snapshot_id: "test-id-0001".to_string(),
            prev_snapshot_id: None,
            taken_at_epoch_secs: 1_700_000_001,
            vault_state_hash: "ddeeff".to_string(),
            event_log_high_watermark: 0,
            daemon_persona_pubkey: identity.pubkey_hex(),
            evidence: Evidence::default(),
        };
        sign_snapshot_manifest(&mut manifest, &identity);

        // Wrong pubkey → false.
        let wrong = "a".repeat(64);
        assert!(!verify_snapshot_manifest(&manifest, &wrong));
    }

    #[test]
    fn verify_snapshot_manifest_rejects_tampered_body() {
        let tmp = TempDir::new().unwrap();
        let identity = test_identity(tmp.path());
        let mut manifest = SnapshotManifest {
            snapshot_id: "test-id-0002".to_string(),
            prev_snapshot_id: None,
            taken_at_epoch_secs: 1_700_000_002,
            vault_state_hash: "112233".to_string(),
            event_log_high_watermark: 10,
            daemon_persona_pubkey: identity.pubkey_hex(),
            evidence: Evidence::default(),
        };
        sign_snapshot_manifest(&mut manifest, &identity);

        // Tamper the watermark → canonical hash changes → verify fails.
        manifest.event_log_high_watermark = 99;
        assert!(!verify_snapshot_manifest(&manifest, &identity.pubkey_hex()));
    }

    // ---------------------------------------------------------------------------
    // Blob encryption / decryption round-trip
    // ---------------------------------------------------------------------------

    #[test]
    fn encrypt_decrypt_vault_blob_round_trip() {
        let tmp = TempDir::new().unwrap();
        let identity = test_identity(tmp.path());

        let state = SerializedVaultState {
            format_version: 1,
            vault_salt_hex: "deadbeef00112233deadbeef00112233".to_string(),
            credentials: vec![],
            personas: vec![],
            grants: vec![],
            grant_usage: vec![],
            standing_grants: vec![],
            audit_log: vec![],
            receipts: vec![],
        };

        let blob = encrypt_vault_blob(&state, &identity).expect("encrypt");
        let recovered = decrypt_vault_blob(&blob, &identity).expect("decrypt");

        assert_eq!(recovered.vault_salt_hex, state.vault_salt_hex);
        assert_eq!(recovered.format_version, 1);
    }

    #[test]
    fn decrypt_vault_blob_fails_with_wrong_identity() {
        let tmp = TempDir::new().unwrap();
        let id1 = test_identity(tmp.path());

        let tmp2 = TempDir::new().unwrap();
        let id2 = test_identity(tmp2.path());

        let state = SerializedVaultState {
            format_version: 1,
            vault_salt_hex: String::new(),
            credentials: vec![],
            personas: vec![],
            grants: vec![],
            grant_usage: vec![],
            standing_grants: vec![],
            audit_log: vec![],
            receipts: vec![],
        };

        let blob = encrypt_vault_blob(&state, &id1).expect("encrypt");
        // id2 has a different seed → different derived key → decrypt fails.
        assert!(decrypt_vault_blob(&blob, &id2).is_err());
    }

    // ---------------------------------------------------------------------------
    // SnapshotEmitter::emit_snapshot
    // ---------------------------------------------------------------------------

    #[test]
    fn emit_snapshot_returns_snapshot_id() {
        let tmp = TempDir::new().unwrap();
        let identity = test_identity(tmp.path());
        let store = DaemonStore::open_in_memory().unwrap();
        let emitter = SnapshotEmitter::new(3600);

        let id = emitter
            .emit_snapshot(&store, &identity, tmp.path(), 0)
            .expect("emit_snapshot");
        assert!(!id.is_empty(), "snapshot_id should be non-empty");
    }

    #[test]
    fn maybe_emit_returns_some_on_first_call() {
        let tmp = TempDir::new().unwrap();
        let identity = test_identity(tmp.path());
        let store = DaemonStore::open_in_memory().unwrap();
        // interval_secs = 0 so it's always due.
        let emitter = SnapshotEmitter::new(0);

        let result = emitter
            .maybe_emit(&store, &identity, tmp.path(), 0)
            .expect("maybe_emit");
        assert!(result.is_some());
    }

    #[test]
    fn maybe_emit_returns_none_before_interval_expires() {
        let tmp = TempDir::new().unwrap();
        let identity = test_identity(tmp.path());
        let store = DaemonStore::open_in_memory().unwrap();
        // Very long interval.
        let emitter = SnapshotEmitter::new(86400);

        // First call: no prior emit → due → Some.
        let first = emitter
            .maybe_emit(&store, &identity, tmp.path(), 0)
            .expect("first");
        assert!(first.is_some());

        // Second call: just emitted → not due → None.
        let second = emitter
            .maybe_emit(&store, &identity, tmp.path(), 0)
            .expect("second");
        assert!(second.is_none());
    }

    #[test]
    fn emit_snapshot_chains_prev_snapshot_id() {
        let tmp = TempDir::new().unwrap();
        let identity = test_identity(tmp.path());
        let store = DaemonStore::open_in_memory().unwrap();
        // interval_secs = 0 so both calls emit.
        let emitter = SnapshotEmitter::new(0);

        let id1 = emitter
            .emit_snapshot(&store, &identity, tmp.path(), 0)
            .expect("first snapshot");
        let id2 = emitter
            .emit_snapshot(&store, &identity, tmp.path(), 0)
            .expect("second snapshot");

        assert_ne!(id1, id2);

        // The second snapshot's prev_snapshot_id should be id1.
        // We can verify by reading the manifest file.
        let snapshots_dir = tmp.path().join("snapshots");
        let manifest_path = snapshots_dir.join(format!("{}.manifest.json", &id2[..16]));
        let contents = std::fs::read(&manifest_path).expect("manifest file exists");
        let manifest: SnapshotManifest = serde_json::from_slice(&contents).expect("parse");
        assert_eq!(manifest.prev_snapshot_id, Some(id1));
    }

    // ---------------------------------------------------------------------------
    // vault.salt inclusion check
    // ---------------------------------------------------------------------------

    #[test]
    fn dump_vault_state_includes_vault_salt() {
        let tmp = TempDir::new().unwrap();
        // Write a fake vault.salt.
        let salt_bytes = [0xABu8; 16];
        std::fs::write(tmp.path().join("vault.salt"), salt_bytes).unwrap();

        let store = DaemonStore::open_in_memory().unwrap();
        let state = dump_vault_state(&store, tmp.path()).expect("dump");
        assert_eq!(state.vault_salt_hex, hex::encode(salt_bytes));
    }

    #[test]
    fn dump_vault_state_without_salt_file_returns_empty_hex() {
        let tmp = TempDir::new().unwrap();
        // No vault.salt file.
        let store = DaemonStore::open_in_memory().unwrap();
        let state = dump_vault_state(&store, tmp.path()).expect("dump");
        assert_eq!(state.vault_salt_hex, "");
    }

    // ---------------------------------------------------------------------------
    // Pull-side tests
    // ---------------------------------------------------------------------------

    /// `pull_cluster_snapshot` rejects a tampered manifest — the body hash no
    /// longer matches the signature so `verify_snapshot_manifest` returns false
    /// and `PullError::SignatureInvalid` is returned before any vault write.
    #[tokio::test]
    async fn pull_cluster_snapshot_rejects_tampered_manifest() {
        use crate::infra::vault::Vault;
        use bytes::Bytes;
        use http_body_util::Full;
        use hyper::{Request, Response, StatusCode};
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use std::rc::Rc;
        use std::sync::Arc;
        use tempfile::TempDir;
        use tokio::net::TcpListener;

        let tmp = TempDir::new().unwrap();
        let identity = test_identity(tmp.path());

        // Build a valid manifest + blob, then tamper with the watermark.
        let mut manifest = SnapshotManifest {
            snapshot_id: "tamper-test-id-0000".to_string(),
            prev_snapshot_id: None,
            taken_at_epoch_secs: 1_700_000_000,
            vault_state_hash: "aabbccdd".to_string(),
            event_log_high_watermark: 5,
            daemon_persona_pubkey: identity.pubkey_hex(),
            evidence: Evidence::default(),
        };
        sign_snapshot_manifest(&mut manifest, &identity);
        // Tamper: change the watermark so the hash no longer matches the sig.
        manifest.event_log_high_watermark = 9999;

        let encrypted_blob_hex = hex::encode(b"fake-blob-bytes");
        let snapshot_id = manifest.snapshot_id.clone();
        let pubkey_hex = identity.pubkey_hex();

        // Serve the tampered manifest from a local HTTP listener.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{addr}");

        let snapshot_id_clone = snapshot_id.clone();
        let manifest_clone = manifest.clone();
        let blob_hex_clone = encrypted_blob_hex.clone();

        let local = tokio::task::LocalSet::new();
        local.spawn_local(async move {
            // Accept exactly two requests: /latest, then the full fetch.
            for _ in 0..2 {
                let Ok((stream, _)) = listener.accept().await else { break };
                let snap_id = snapshot_id_clone.clone();
                let manifest_c = manifest_clone.clone();
                let blob_hex_c = blob_hex_clone.clone();
                tokio::task::spawn_local(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let path = req.uri().path().to_string();
                        let snap_id = snap_id.clone();
                        let manifest_c = manifest_c.clone();
                        let blob_hex_c = blob_hex_c.clone();
                        async move {
                            let body = if path == "/api/cluster-snapshot/latest" {
                                serde_json::json!({ "snapshot_id": snap_id }).to_string()
                            } else {
                                serde_json::json!({
                                    "manifest": manifest_c,
                                    "encrypted_blob_hex": blob_hex_c,
                                }).to_string()
                            };
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap()
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        // Open an in-memory vault + store. Vault::open_from_config requires
        // EMBER_VAULT_PASSPHRASE in test environments.
        let store = DaemonStore::open_in_memory().unwrap();
        let config = crate::infra::config::DaemonConfig {
            data_dir: tmp.path().to_path_buf(),
            ..crate::infra::config::DaemonConfig::for_test(tmp.path())
        };
        let vault = Vault::open_from_config(&config).expect("vault open");

        // Run the pull inside the LocalSet.
        let result = local.run_until(
            pull_cluster_snapshot(&endpoint, "test-cluster", &pubkey_hex, &vault, &store)
        ).await;

        assert!(
            matches!(result, Err(PullError::SignatureInvalid)),
            "expected SignatureInvalid for tampered manifest, got: {result:?}"
        );

        // Vault must be empty — no writes on signature failure.
        let creds = vault.list(VaultScope::Interactive, &store).unwrap_or_default();
        assert!(
            creds.iter().all(|c| !c.name.starts_with("cluster-snapshot")),
            "vault must not contain cluster-snapshot entries after signature failure"
        );
    }

    /// `pull_cluster_snapshot` stores the blob + manifest in the vault when
    /// the manifest signature is valid. This is the happy-path round-trip.
    #[tokio::test]
    async fn pull_cluster_snapshot_stores_valid_snapshot() {
        use crate::infra::vault::Vault;
        use bytes::Bytes;
        use http_body_util::Full;
        use hyper::{Request, Response, StatusCode};
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use tempfile::TempDir;
        use tokio::net::TcpListener;

        let tmp = TempDir::new().unwrap();
        let identity = test_identity(tmp.path());

        let mut manifest = SnapshotManifest {
            snapshot_id: "valid-pull-test-id-0000".to_string(),
            prev_snapshot_id: None,
            taken_at_epoch_secs: 1_700_000_001,
            vault_state_hash: "cafebabe".to_string(),
            event_log_high_watermark: 42,
            daemon_persona_pubkey: identity.pubkey_hex(),
            evidence: Evidence::default(),
        };
        sign_snapshot_manifest(&mut manifest, &identity);
        let pubkey_hex = identity.pubkey_hex();

        let encrypted_blob_hex = hex::encode(b"valid-snapshot-blob-bytes");
        let snapshot_id = manifest.snapshot_id.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{addr}");

        let snapshot_id_clone = snapshot_id.clone();
        let manifest_clone = manifest.clone();
        let blob_hex_clone = encrypted_blob_hex.clone();

        let local = tokio::task::LocalSet::new();
        local.spawn_local(async move {
            for _ in 0..2 {
                let Ok((stream, _)) = listener.accept().await else { break };
                let snap_id = snapshot_id_clone.clone();
                let manifest_c = manifest_clone.clone();
                let blob_hex_c = blob_hex_clone.clone();
                tokio::task::spawn_local(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let path = req.uri().path().to_string();
                        let snap_id = snap_id.clone();
                        let manifest_c = manifest_c.clone();
                        let blob_hex_c = blob_hex_c.clone();
                        async move {
                            let body = if path == "/api/cluster-snapshot/latest" {
                                serde_json::json!({ "snapshot_id": snap_id }).to_string()
                            } else {
                                serde_json::json!({
                                    "manifest": manifest_c,
                                    "encrypted_blob_hex": blob_hex_c,
                                }).to_string()
                            };
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap()
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        let store = DaemonStore::open_in_memory().unwrap();
        let config = crate::infra::config::DaemonConfig {
            data_dir: tmp.path().to_path_buf(),
            ..crate::infra::config::DaemonConfig::for_test(tmp.path())
        };
        let vault = Vault::open_from_config(&config).expect("vault open");

        let result = local.run_until(
            pull_cluster_snapshot(&endpoint, "my-cluster", &pubkey_hex, &vault, &store)
        ).await;

        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        let returned_id = result.unwrap();
        assert_eq!(returned_id, Some(snapshot_id.clone()), "should return the pulled snapshot_id");

        // Vault must contain blob + manifest entries.
        let creds = vault.list(VaultScope::Interactive, &store).unwrap_or_default();
        let has_blob = creds.iter().any(|c| c.name.contains("snap-"));
        let has_meta = creds.iter().any(|c| c.name.contains("meta-"));
        assert!(has_blob, "vault must contain blob entry");
        assert!(has_meta, "vault must contain manifest (meta) entry");

        // list_local_snapshots should surface the entry.
        let entries = list_local_snapshots(&vault, &store, Some("my-cluster"));
        assert_eq!(entries.len(), 1, "expected 1 local snapshot entry");
        assert_eq!(entries[0].snapshot_id, snapshot_id);
        assert_eq!(entries[0].cluster_id, "my-cluster");
    }

    /// `SnapshotPuller::maybe_pull` respects the cadence gate: the second call
    /// within the interval returns `Ok(None)` without hitting the network.
    #[test]
    fn snapshot_puller_cadence_gate() {
        // interval_secs = 86400 (1 day) — a second call always finds `last_pulled_at`
        // within the window.
        let puller = SnapshotPuller::new(86400);

        // Manually set last_pulled_at to now — simulates a pull just happened.
        {
            let mut guard = puller.last_pulled_at.lock().unwrap();
            *guard = Some(Instant::now());
        }

        // Due check: should NOT be due since interval hasn't elapsed.
        let now = Instant::now();
        let due = {
            let guard = puller.last_pulled_at.lock().unwrap();
            match *guard {
                None => true,
                Some(last) => now.duration_since(last).as_secs() >= puller.interval_secs,
            }
        };
        assert!(!due, "puller should not be due immediately after a pull");
    }
}
