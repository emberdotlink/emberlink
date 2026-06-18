use std::collections::{HashMap, HashSet};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use chrono::{DateTime, Duration, Timelike, Utc};
use core_broker::{RailAdapter, RailAttemptAccepted, RailOutcomeReport, RailSettlementState};
use core_crypto::grant_chain::{
    self, PubkeyNextKeyPair, RootKeyPair, root_pubkey_bytes_from_ed25519_hex, verify_chain,
};
use core_event_types::{PresentationAudienceKind, RailTrustContract};
use core_events::receipt::{
    PaymentEvaluatedBody, PaymentEvaluatedState, PaymentSettledBody, PaymentSettledState,
    RECEIPT_KIND_PAYMENT_EVALUATED, RECEIPT_KIND_PAYMENT_SETTLED,
};
use core_grant_types::{
    AccessGrant, AttestationBinding, Block, Budget, Condition, GrantMode, GrantStatus,
    RecipientProfile, SignedBlock, Statement, Usage,
};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::infra::receipt::{
    emit_payment_evaluated_receipt_current, emit_payment_settled_receipt_current,
};
use crate::infra::store::{DaemonStore, StoreError};
use crate::trust::grant_projection::{parse_epoch, row_to_grant};
use crate::trust::lease::LeaseKey;
use core_grants::chain::{
    access_grant_envelope, build_single_statement_block, scope_to_actions_and_selector,
};
use core_grants::scope::{
    check_budget_attenuation, check_expiry_attenuation, check_statement_attenuation,
};
use zeroize::Zeroizing;

pub(crate) use crate::trust::grant_projection::{derive_wall_clock_secs, grant_info_to_core};

// Final phase cleanup pass completed (ADR 114 phase C-FINAL)
// Internal grant.rs sites walk AccessGrant.blocks[] (ADR 114 phase C-2)
// Legacy entry points delegate through DaemonGrantStore (ADR 114 phase C-1)
// --- Phase B: DaemonGrantStore adapter (ADR 114 §2.3) ---
// TODO: GrantInfo struct is retained as a daemon-internal DB projection
// because receipt.rs, dashboard.rs, tailnet.rs, and handler.rs all depend on fields not present
// in core_grants::Grant (credential_name, scope string, created_at string, budget, paused, etc.).
// Full deletion requires a separate phase that migrates those callers to walk AccessGrant.blocks[]
// natively and removes the scalar-projection columns from the SQLite schema.

const GRANT_PERSONA_SECRET_AAD_PREFIX: &[u8] = b"emberlink/adr211/v1/grant-persona-secret";

/// AAD prefix for the H3-fix `pubkey_next_secret` seal. Distinct from the
/// `grant-persona-secret` prefix so a sealed persona-root blob cannot be
/// substituted for a sealed chain-tail blob (each one decrypts cleanly
/// only against its own AAD).
const GRANT_CHAIN_SECRET_AAD_PREFIX: &[u8] = b"emberlink/c1-h1-h3/v1/grant-chain-secret";

#[derive(Debug, Serialize, Deserialize)]
struct GrantPersonaSecretPlaintext {
    schema_version: u8,
    grant_id: String,
    persona_id: String,
    public_hex: String,
    secret_hex: String,
}

fn grant_persona_secret_aad(grant_id: &str, persona_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        GRANT_PERSONA_SECRET_AAD_PREFIX.len() + 4 + grant_id.len() + 4 + persona_id.len(),
    );
    aad.extend_from_slice(GRANT_PERSONA_SECRET_AAD_PREFIX);
    aad.extend_from_slice(&(grant_id.len() as u32).to_le_bytes());
    aad.extend_from_slice(grant_id.as_bytes());
    aad.extend_from_slice(&(persona_id.len() as u32).to_le_bytes());
    aad.extend_from_slice(persona_id.as_bytes());
    aad
}

fn seal_grant_persona_secret(
    lease_key: &LeaseKey,
    grant_id: &str,
    persona_id: &str,
    material: crate::infra::persona::PersonaRootKeyMaterial,
) -> Result<Vec<u8>, StoreError> {
    let cipher = XChaCha20Poly1305::new_from_slice(lease_key.as_bytes())
        .map_err(|e| StoreError::InvalidInput(format!("grant persona seal cipher init: {e}")))?;
    let mut nonce_bytes = [0u8; 24];
    getrandom::fill(&mut nonce_bytes).expect("OS entropy failure on grant persona secret nonce");
    let aad = grant_persona_secret_aad(grant_id, persona_id);
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&GrantPersonaSecretPlaintext {
            schema_version: 1,
            grant_id: grant_id.to_string(),
            persona_id: persona_id.to_string(),
            public_hex: material.public_hex,
            secret_hex: material.secret_hex,
        })
        .map_err(|e| StoreError::InvalidInput(format!("grant persona secret serialize: {e}")))?,
    );
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|e| StoreError::InvalidInput(format!("grant persona secret seal: {e}")))?;
    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn open_grant_persona_secret(
    lease_key: &LeaseKey,
    grant_id: &str,
    persona_id: &str,
    blob: &[u8],
) -> Result<RootKeyPair, StoreError> {
    if blob.len() < 24 + 16 {
        return Err(StoreError::InvalidInput(format!(
            "grant {grant_id} persona-root blob is too short ({} bytes)",
            blob.len()
        )));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(lease_key.as_bytes())
        .map_err(|e| StoreError::InvalidInput(format!("grant persona open cipher init: {e}")))?;
    let aad = grant_persona_secret_aad(grant_id, persona_id);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&blob[..24]),
                Payload {
                    msg: &blob[24..],
                    aad: &aad,
                },
            )
            .map_err(|e| StoreError::InvalidInput(format!("grant persona secret open: {e}")))?,
    );
    let decoded: GrantPersonaSecretPlaintext = serde_json::from_slice(&plaintext).map_err(|e| {
        StoreError::InvalidInput(format!("grant persona secret plaintext malformed: {e}"))
    })?;
    if decoded.schema_version != 1
        || decoded.grant_id != grant_id
        || decoded.persona_id != persona_id
    {
        return Err(StoreError::InvalidInput(format!(
            "grant persona secret binding mismatch for grant {grant_id} persona {persona_id}"
        )));
    }
    RootKeyPair::from_hex(decoded.public_hex, decoded.secret_hex).map_err(|e| {
        StoreError::InvalidInput(format!(
            "grant {grant_id} lease-wrapped persona root key invalid: {e}"
        ))
    })
}

/// H3 fix — plaintext shape of a sealed `pubkey_next_secret` blob.
///
/// `tail_block_index` is the 0-indexed position of the block whose
/// `pubkey_next` this secret pairs with. We authenticate it inside the
/// AAD-bound plaintext so a misalignment between the SQL column and the
/// sealed bytes fails closed at open time.
#[derive(Debug, Serialize, Deserialize)]
struct GrantChainSecretPlaintext {
    schema_version: u8,
    grant_id: String,
    tail_block_index: u32,
    public_hex: String,
    secret_hex: String,
}

fn grant_chain_secret_aad(grant_id: &str, tail_block_index: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(GRANT_CHAIN_SECRET_AAD_PREFIX.len() + 4 + grant_id.len() + 4);
    aad.extend_from_slice(GRANT_CHAIN_SECRET_AAD_PREFIX);
    aad.extend_from_slice(&(grant_id.len() as u32).to_le_bytes());
    aad.extend_from_slice(grant_id.as_bytes());
    aad.extend_from_slice(&tail_block_index.to_le_bytes());
    aad
}

fn seal_grant_chain_secret(
    lease_key: &LeaseKey,
    grant_id: &str,
    tail_block_index: u32,
    pubkey_next: &PubkeyNextKeyPair,
) -> Result<Vec<u8>, StoreError> {
    let cipher = XChaCha20Poly1305::new_from_slice(lease_key.as_bytes())
        .map_err(|e| StoreError::InvalidInput(format!("grant chain seal cipher init: {e}")))?;
    let mut nonce_bytes = [0u8; 24];
    getrandom::fill(&mut nonce_bytes).expect("OS entropy failure on grant chain secret nonce");
    let aad = grant_chain_secret_aad(grant_id, tail_block_index);
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&GrantChainSecretPlaintext {
            schema_version: 1,
            grant_id: grant_id.to_string(),
            tail_block_index,
            public_hex: pubkey_next.public_hex.clone(),
            secret_hex: pubkey_next.secret_hex.clone(),
        })
        .map_err(|e| StoreError::InvalidInput(format!("grant chain secret serialize: {e}")))?,
    );
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|e| StoreError::InvalidInput(format!("grant chain secret seal: {e}")))?;
    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn open_grant_chain_secret(
    lease_key: &LeaseKey,
    grant_id: &str,
    tail_block_index: u32,
    blob: &[u8],
) -> Result<PubkeyNextKeyPair, StoreError> {
    if blob.len() < 24 + 16 {
        return Err(StoreError::InvalidInput(format!(
            "grant {grant_id} chain-secret blob is too short ({} bytes)",
            blob.len()
        )));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(lease_key.as_bytes())
        .map_err(|e| StoreError::InvalidInput(format!("grant chain open cipher init: {e}")))?;
    let aad = grant_chain_secret_aad(grant_id, tail_block_index);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&blob[..24]),
                Payload {
                    msg: &blob[24..],
                    aad: &aad,
                },
            )
            .map_err(|e| StoreError::InvalidInput(format!("grant chain secret open: {e}")))?,
    );
    let decoded: GrantChainSecretPlaintext = serde_json::from_slice(&plaintext).map_err(|e| {
        StoreError::InvalidInput(format!("grant chain secret plaintext malformed: {e}"))
    })?;
    if decoded.schema_version != 1
        || decoded.grant_id != grant_id
        || decoded.tail_block_index != tail_block_index
    {
        return Err(StoreError::InvalidInput(format!(
            "grant chain secret binding mismatch for grant {grant_id} tail {tail_block_index}"
        )));
    }
    PubkeyNextKeyPair::from_hex(decoded.public_hex, decoded.secret_hex).map_err(|e| {
        StoreError::InvalidInput(format!(
            "grant {grant_id} lease-wrapped chain secret invalid: {e}"
        ))
    })
}

impl From<core_grants::GrantError> for StoreError {
    fn from(e: core_grants::GrantError) -> Self {
        match e {
            core_grants::GrantError::InvalidState => {
                StoreError::InvalidInput("grant state machine: invalid state for operation".into())
            }
            core_grants::GrantError::ScopeViolation => StoreError::DelegationViolation {
                reason: "narrowed scope is not a subset of the grant scope".into(),
            },
            core_grants::GrantError::BudgetExhausted => {
                StoreError::InvalidInput("grant budget exhausted".into())
            }
            core_grants::GrantError::NotAuthorized => StoreError::Unauthorized,
        }
    }
}

/// Adapter trait for grant persistence (ADR 114 §2.3).
///
/// `DaemonGrantStore` implements this trait over the SQLite store.
/// Pure-in-memory or relay-side implementations can provide an
/// alternative backend without depending on `ember-daemon`.
pub trait GrantStore {
    fn load(&self, id: uuid::Uuid) -> Result<core_grants::Grant, StoreError>;
    fn save(&self, grant: &core_grants::Grant) -> Result<(), StoreError>;
    fn list_active(&self, persona_id: &str) -> Result<Vec<core_grants::Grant>, StoreError>;
}

/// Daemon-side adapter that implements `GrantStore` over `DaemonStore`.
///
/// Transition methods on this type follow the ADR 114 §2.3 delegation
/// pattern: `load → core_grants::<fn> → save`. The adapter enforces no
/// transition logic of its own — `core-grants` is the single source of
/// truth for the state machine.
pub struct DaemonGrantStore<'a> {
    inner: &'a DaemonStore,
}

impl<'a> DaemonGrantStore<'a> {
    pub fn new(inner: &'a DaemonStore) -> Self {
        Self { inner }
    }

    /// Parse a daemon grant ID ("grant-{uuid}" format) into a `uuid::Uuid`.
    fn parse_grant_id(id: &str) -> Result<uuid::Uuid, StoreError> {
        let raw = id.strip_prefix("grant-").unwrap_or(id);
        uuid::Uuid::parse_str(raw)
            .map_err(|e| StoreError::InvalidInput(format!("invalid grant id '{id}': {e}")))
    }

    /// Load a `core_grants::Grant` by its daemon-format string ID ("grant-{uuid}").
    ///
    /// Thin convenience bridge for migrated handler.rs sites.
    /// Returns the state-machine type so callers can
    /// use `grant.state` / `grant.issuer` / `grant.expires_at` directly
    /// without going through the `GrantInfo` projection.
    pub fn load_grant(&self, id: &str) -> Result<core_grants::Grant, StoreError> {
        let uuid = Self::parse_grant_id(id)?;
        GrantStore::load(self, uuid)
    }

    /// Revoke a grant, delegating the state-machine check to `core_grants::revoke`.
    ///
    /// The by-principal is set to the grant's issuer (preserving existing
    /// behavior where operator-initiated revoke acts as the issuer). The actual
    /// SQL mutation and receipt emission are handled by `DaemonStore::revoke_grant`.
    pub fn revoke_grant(&self, id: &str) -> Result<(), StoreError> {
        let uuid = Self::parse_grant_id(id)?;
        let grant = GrantStore::load(self, uuid)?;
        let by = grant.issuer.clone();
        // core_grants::revoke validates the state transition.
        // Idempotent: revoking a Revoked grant returns Ok.
        let _ = core_grants::revoke(grant, &by)?;
        // Delegate SQL + receipt emission to the existing store method.
        self.inner.revoke_grant_sql(id)
    }

    /// Mark a grant explicitly abandoned through the recovery plane.
    ///
    /// `core_grants` has no separate abandoned state yet, so this validates
    /// through the daemon projection and then writes the ADR 195 terminal state
    /// that downstream grant receipts understand.
    pub fn abandon_grant(&self, id: &str, reason: &str) -> Result<(), StoreError> {
        self.inner.abandon_grant_sql(id, reason)
    }

    /// Pause a grant, delegating the state-machine check to `core_grants::pause`.
    ///
    /// Idempotent: already-paused grants return `Ok(())` without re-pausing.
    pub fn pause_grant(&self, id: &str) -> Result<(), StoreError> {
        let uuid = Self::parse_grant_id(id)?;
        let grant = GrantStore::load(self, uuid)?;
        // Already paused — idempotent; skip core_grants::pause which would
        // return InvalidState for a non-Active grant.
        if grant.state == core_grants::GrantState::Paused {
            return Ok(());
        }
        let by = grant.issuer.clone();
        let _ = core_grants::pause(grant, &by)?;
        self.inner.pause_grant_sql(id)
    }

    /// Resume a paused grant, delegating the state-machine check to `core_grants::resume`.
    ///
    /// Idempotent: already-active grants return `Ok(())` without error.
    pub fn resume_grant(&self, id: &str) -> Result<(), StoreError> {
        let uuid = Self::parse_grant_id(id)?;
        let grant = GrantStore::load(self, uuid)?;
        // Already active — idempotent; skip core_grants::resume which would
        // return InvalidState for a non-Paused grant.
        if grant.state == core_grants::GrantState::Active {
            return Ok(());
        }
        let by = grant.issuer.clone();
        let _ = core_grants::resume(grant, &by)?;
        self.inner.resume_grant_sql(id)
    }

    /// Extend a grant's budget and/or TTL.
    ///
    /// Uses `core_grants::extend` to validate the state-machine precondition
    /// (grant must be Active), then delegates the SQL + chain re-signing to
    /// `DaemonStore::extend_grant`.
    pub fn extend_grant(
        &self,
        id: &str,
        tokens_delta: Option<u64>,
        cents_delta: Option<u64>,
        ttl_extension_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        let uuid = Self::parse_grant_id(id)?;
        let grant = GrantStore::load(self, uuid)?;
        // Validate that the state machine allows extension (Active only).
        let ttl = chrono::Duration::seconds(ttl_extension_secs.unwrap_or(0) as i64);
        let _ = core_grants::extend(grant, ttl)?;
        self.inner
            .extend_grant_sql(id, tokens_delta, cents_delta, ttl_extension_secs)
    }

    /// Delegate a grant (narrow scope only, no child budget).
    pub fn delegate_grant(
        &self,
        parent_grant_id: &str,
        child_persona_id: &str,
        narrowed_scope: &str,
        ttl_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        self.delegate_grant_full(
            parent_grant_id,
            child_persona_id,
            narrowed_scope,
            ttl_secs,
            None,
        )
    }

    /// Delegate a grant with optional child budget.
    ///
    /// Uses `core_grants` to validate that the parent grant is `Active`
    /// (state-machine precondition), then delegates SQL + chain construction
    /// to `DaemonStore::delegate_grant_full`. Delegation-depth enforcement
    /// and scope-attenuation remain in the existing store method (which uses
    /// the daemon's `max_delegation_depth` field — a remaining-budget
    /// counter, not the `core_grants::delegation_depth` monotonic counter).
    /// Phase C will unify these representations.
    pub fn delegate_grant_full(
        &self,
        parent_grant_id: &str,
        child_persona_id: &str,
        narrowed_scope: &str,
        ttl_secs: Option<u64>,
        child_budget: Option<core_grant_types::Budget>,
    ) -> Result<GrantInfo, StoreError> {
        let uuid = Self::parse_grant_id(parent_grant_id)?;
        let grant = GrantStore::load(self, uuid)?;
        // Validate that the parent is Active — delegates to the state machine.
        if grant.state != core_grants::GrantState::Active {
            return Err(StoreError::InvalidInput("parent grant not active".into()));
        }
        self.inner.delegate_grant_full_sql(
            parent_grant_id,
            child_persona_id,
            narrowed_scope,
            ttl_secs,
            child_budget,
        )
    }

    /// Per-Statement revocation list passthrough — no state-machine check
    /// (this is per-Statement sid management, not a grant-level transition).
    pub fn revoke_grant_statement(&self, grant_id: &str, sid: &str) -> Result<(), StoreError> {
        self.inner.revoke_grant_statement_sql(grant_id, sid)
    }
}

impl GrantStore for DaemonGrantStore<'_> {
    fn load(&self, id: uuid::Uuid) -> Result<core_grants::Grant, StoreError> {
        // Grant IDs are stored as "grant-{uuid}" in the daemon's SQLite schema.
        let store_id = format!("grant-{id}");
        let info = self.inner.get_grant(&store_id)?;
        Ok(grant_info_to_core(&info))
    }

    fn save(&self, grant: &core_grants::Grant) -> Result<(), StoreError> {
        // Phase B: save propagates only the state transition (status column).
        // Full round-trip (blocks_json, expires_at, etc.) is Phase C work.
        let status = match grant.state {
            core_grants::GrantState::Active => "active",
            core_grants::GrantState::Paused => "paused",
            core_grants::GrantState::Revoked => "revoked",
        };
        // Reconstruct the daemon's "grant-{uuid}" ID from the core UUID.
        let store_id = format!("grant-{}", grant.id);
        let n = self.inner.conn().execute(
            "UPDATE grants SET status = ?1 WHERE id = ?2",
            rusqlite::params![status, store_id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn list_active(&self, persona_id: &str) -> Result<Vec<core_grants::Grant>, StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        let sql = format!(
            "SELECT {GRANT_COLUMNS} FROM grants \
             WHERE persona_id = ?1 AND status = 'active' \
             AND (expires_at IS NULL OR expires_at > ?2)"
        );
        let mut stmt = self.inner.conn().prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params![persona_id, now], row_to_grant)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(grant_info_to_core(&row?));
        }
        Ok(out)
    }
}

/// Daemon-local grant record.
///
/// TODO: this struct is retained as a daemon-internal SQLite
/// row projection. receipt.rs (emit_receipt, build_receipt_body, derive_reason),
/// dashboard.rs (grant_to_json, grant_to_json_with_store, build_receipt_json),
/// tailnet.rs (lease_credential), and handler.rs (use_credential credential_name
/// resolution) all depend on fields not available in core_grants::Grant:
/// credential_name, scope (String), created_at, expires_at (String), budget,
/// usage, paused, is_standing, allowed_targets, etc.
///
/// Per ADR 073 the canonical representation is the composite
/// [`core_grant_types::AccessGrant`] chain in `access_grant`. The scalar fields
/// on `GrantInfo` (scope, budget, usage, etc.) are **projections** over the
/// first-statement in the chain. Full deletion requires migrating all callers
/// above to walk `access_grant.blocks[].statements[]` natively.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantInfo {
    pub id: String,
    pub persona_id: String,
    pub credential_name: String,
    pub scope: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub status: String,
    pub max_uses_per_hour: Option<u64>,
    pub allowed_hours_start: Option<u32>,
    pub allowed_hours_end: Option<u32>,
    pub allowed_targets: Option<String>,
    pub parent_grant_id: Option<String>,
    pub max_delegation_depth: Option<u32>,
    pub spending_limit_cents: Option<u64>,
    /// Aggregate authority budget — projection from `access_grant`'s
    /// first statement. Per-Statement budgets live inside `access_grant`.
    pub budget: Option<Budget>,
    /// Aggregate running tally — sum across all statements.
    #[serde(default)]
    pub usage: Usage,
    /// Operator-set advisory pause flag (69K.7). Advisory only — does not
    /// gate proxy traffic; emits a `budget.warning` with `paused: true` for
    /// well-behaved agents to self-moderate.
    pub paused: bool,
    /// Populated when the grant reached a terminal state and the Warden
    /// emitted a `GrantReceipt`.
    pub receipt_id: Option<String>,
    /// P69L.3 — standing parent grant flag. When set, the orchestrator
    /// (or any delegation caller) can mint child grants from this parent
    /// without re-prompting the operator, subject to
    /// `max_children_per_day`.
    #[serde(default)]
    pub is_standing: bool,
    /// P69L.3 — rolling 24h delegation ceiling. Only consulted when the
    /// parent is standing. `None` on a non-standing parent.
    pub max_children_per_day: Option<u64>,
    /// P69L.3 — canonical scope narrowing applied by the orchestrator on
    /// each auto-delegation. Stored as an opaque string so callers can
    /// encode whatever shape the cycle needs (often a short DSL fragment
    /// like `"github:push:acme/agent-<run-id>"`). Not enforced by the
    /// daemon — advisory.
    pub auto_delegate_scope_template: Option<String>,
}

const GRANT_COLUMNS: &str = "id, persona_id, credential_name, scope, created_at, expires_at, status, max_uses_per_hour, allowed_hours_start, allowed_hours_end, allowed_targets, parent_grant_id, max_delegation_depth, spending_limit_cents, budget_json, usage_json, paused, receipt_id, blocks_json, is_standing, max_children_per_day, auto_delegate_scope_template";

// --- `blocks_json` write-path size caps (P69K-A2 L3 / F-04) ---
//
// Every production path that writes `blocks_json` (create, overwrite,
// delegate, extend, increment_statement_usage) must run the caller's
// chain through [`validate_blocks_json_caps`] before executing the SQL
// write. External callers (socket overwrite, delegation append) are
// about to start feeding caller-supplied chains directly; without caps a
// malicious or buggy caller could write a monster payload, an unbounded
// block array, or a pathological single statement.
//
// The numbers are comfortably above realistic use:
//   - typical grant: 1 block, 1-3 statements, <2 KiB JSON;
//   - `ember sandbox run` 3-Statement envelope: 1 block, 3 statements,
//     ~1 KiB JSON;
//   - deepest anticipated delegation chain: 3-5 blocks.
// The caps are defence-in-depth, not ergonomic limits.

/// Maximum number of [`SignedBlock`]s allowed in a composite grant chain.
///
/// Bounds delegation chain length; each additional block costs one
/// Ed25519 signature verify on the read path. The daemon's
/// `max_delegation_depth` field bounds depth at the *policy* layer;
/// this constant is the crypto/storage-level floor that applies even
/// when policy depth is unset.
pub const MAX_BLOCKS: usize = 32;

/// Back-compat alias for [`MAX_BLOCKS`]. Retained so external callers
/// referencing the old name keep compiling until the next cycle's
/// cleanup pass.
pub const MAX_BLOCKS_PER_GRANT: usize = MAX_BLOCKS;

/// Maximum number of [`Statement`]s allowed per [`Block`].
///
/// Bounds per-block `authorize` cost (linear walk across statements)
/// and the size of the authority matrix a single block can express.
/// Every realistic envelope we've seen uses at most 3-5 statements
/// (credential + session + time is the shape `ember sandbox run` emits);
/// 16 gives ~3x headroom.
pub const MAX_STATEMENTS_PER_BLOCK: usize = 16;

/// Maximum size (in bytes) of the serialized `blocks_json` payload.
///
/// Defence against pathological payloads — a caller supplying a block
/// with a multi-megabyte resource string, giant condition list, or
/// oversized note would otherwise be able to bloat the grants table
/// unbounded. 64 KiB is ~30x the largest realistic chain we've
/// measured; any row exceeding this is almost certainly malicious or a
/// bug upstream.
pub const MAX_BLOCKS_JSON_BYTES: usize = 64 * 1024;

/// Maximum lifetime (in seconds) for a grant's TTL. Per adversarial-review
/// 2026-05-19 HIGH-7: without a cap, an approver could mint an effectively-
/// permanent grant (e.g. `ttl_secs: 31_536_000` for one year, or the
/// `Always.expires_at` path with a year-2099 date). That violates ADR 072's
/// "bounded" invariant for the Grant Warden category.
///
/// 30 days matches the longest reasonable dogfooding / standing-grant
/// window the operator would mint by hand. Standing grants (the `Always`
/// outcome) are subject to the same cap — the implicit assumption that
/// `Always` means "permanent" is itself the bug. Mirrors the pattern in
/// `crates/ember-daemon/src/infra/tailnet.rs::MAX_LEASE_TTL_SECS`.
///
/// Internal callers (test harness, recovery flow) still observe this cap;
/// adjust the constant if a legitimate use case emerges, but do not gate
/// it behind a flag — the cap is the architectural intent.
pub const MAX_GRANT_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Validate an [`AccessGrant`]'s block chain + its serialized JSON
/// length against the size caps. Called on every production path that
/// writes `blocks_json` so a cap violation is caught before the SQL
/// UPDATE/INSERT executes.
///
/// Returns `StoreError::InvalidInput` with a message naming the
/// specific cap that was exceeded — callers surface the message to
/// operators verbatim, so it should be specific but not leak any
/// other grant's state.
pub(crate) fn validate_blocks_json_caps(
    grant: &AccessGrant,
    serialized: &str,
) -> Result<(), StoreError> {
    if grant.blocks.len() > MAX_BLOCKS {
        return Err(StoreError::InvalidInput(format!(
            "blocks_json write rejected: chain has {} blocks; cap is {MAX_BLOCKS}",
            grant.blocks.len()
        )));
    }
    for (idx, sb) in grant.blocks.iter().enumerate() {
        let n = sb.block.statements.len();
        if n > MAX_STATEMENTS_PER_BLOCK {
            return Err(StoreError::InvalidInput(format!(
                "blocks_json write rejected: block {idx} has {n} statements; \
                 cap is {MAX_STATEMENTS_PER_BLOCK}"
            )));
        }
    }
    if serialized.len() > MAX_BLOCKS_JSON_BYTES {
        return Err(StoreError::InvalidInput(format!(
            "blocks_json write rejected: payload is {} bytes; cap is {MAX_BLOCKS_JSON_BYTES}",
            serialized.len()
        )));
    }
    Ok(())
}

/// Synthetic single-block `AccessGrant` view around an already-signed
/// `SignedBlock`, suitable as input to `check_statement_attenuation`.
///
/// Only fields read by the attenuation predicate (the block's
/// statements) need to be faithful — the rest is stable filler so
/// the predicate has a coherent envelope to walk.
///
/// H3 write-time use: feed the parent's tail block in as the parent,
/// the about-to-be-appended child block in as the child, run
/// `check_statement_attenuation`. The use-time verifier
/// (`trust/use_time_verify.rs::first_attenuation_violation`) does
/// the same thing per hop on the way back out.
fn synthetic_grant_from_block(
    sb: &SignedBlock,
    grant_id: &str,
    issuing_persona_id: &str,
) -> AccessGrant {
    AccessGrant {
        id: grant_id.to_string(),
        version: 1,
        issuing_persona_id: issuing_persona_id.to_string(),
        recipient_kind: PresentationAudienceKind::Service,
        recipient_id: String::new(),
        recipient_profile: RecipientProfile::Agent,
        status: GrantStatus::Active,
        mode: GrantMode::OneShot,
        blocks: vec![sb.clone()],
        attestation: AttestationBinding::default(),
        created_at: sb.block.issued_at,
        updated_at: sb.block.issued_at,
        revoked_at: None,
        revoked_reason: None,
        last_used_at: None,
        label: None,
    }
}

/// Synthetic single-block `AccessGrant` view around an UNSIGNED `Block`
/// (the one about to be appended at delegation write time). Wraps the
/// block in a placeholder `SignedBlock` shell — the attenuation
/// predicate reads only the block's statements, never the signature.
fn synthetic_grant_from_unsigned_block(
    block: &Block,
    grant_id: &str,
    issuing_persona_id: &str,
) -> AccessGrant {
    let stub_signed = SignedBlock {
        block: block.clone(),
        pubkey_next: String::new(),
        signature: String::new(),
    };
    synthetic_grant_from_block(&stub_signed, grant_id, issuing_persona_id)
}

/// Build a single-statement block payload from daemon scalar fields.
///
/// Returns the unsigned [`Block`] — signing is a separate step that
/// requires the issuing persona's root keypair. Used when a grant row has
/// no `blocks_json` (legacy) so every in-memory `GrantInfo` can be turned
/// into a canonical composite chain to reason about.
/// Sign a single block with the given root keypair. Daemon-layer wrapper that
/// maps [`core_grants::chain::ChainBuildError`] onto `StoreError::InvalidInput`
/// so daemon callers don't have to juggle two error enums.
///
/// Logic lives in `core_grants::chain::sign_block_zero_with`.
pub(crate) fn sign_block_zero_with(
    root: &RootKeyPair,
    block: &Block,
) -> Result<SignedBlock, StoreError> {
    core_grants::chain::sign_block_zero_with(root, block)
        .map_err(|e| StoreError::InvalidInput(e.to_string()))
}

/// Serialize an `AccessGrant`'s block chain to JSON for storage in
/// `blocks_json`. Only the blocks are persisted — envelope metadata
/// (id, persona, recipient, status, timestamps) already live in the
/// daemon's flat row columns and round-trip via those.
pub(crate) fn access_grant_blocks_to_json(g: &AccessGrant) -> Result<String, StoreError> {
    serde_json::to_string(&g.blocks).map_err(|e| {
        StoreError::InvalidInput(format!("failed to serialize AccessGrant blocks: {e}"))
    })
}

/// Build a signed `AccessGrant` envelope wrapping a caller-supplied
/// `Vec<Statement>`.
///
/// Daemon-layer wrapper that maps [`core_grants::chain::ChainBuildError`] onto
/// `StoreError::InvalidInput`. Logic lives in
/// `core_grants::chain::access_grant_from_statements`.
pub fn access_grant_from_statements(
    id: &str,
    persona_id: &str,
    recipient_id: &str,
    statements: Vec<Statement>,
    created_at: u64,
    expires_at: Option<u64>,
    root: &RootKeyPair,
) -> Result<AccessGrant, StoreError> {
    core_grants::chain::access_grant_from_statements(
        id,
        persona_id,
        recipient_id,
        statements,
        created_at,
        expires_at,
        root,
    )
    .map_err(|e| StoreError::InvalidInput(e.to_string()))
}

/// Build a signed `AccessGrant` envelope, looking up the persona's root
/// keypair internally from `store`.
///
/// This is the preferred form for new callers — the `root` parameter is
/// derived from the store rather than threaded in from the outside.
/// Existing callers of [`access_grant_from_statements`] continue to
/// compile unchanged; migrate them to this form incrementally.
///
/// Returns the same value as calling `access_grant_from_statements` with
/// the result of `store.persona_root_keypair(persona_id)`.
pub fn access_grant_from_statements_for_persona(
    store: &DaemonStore,
    id: &str,
    persona_id: &str,
    recipient_id: &str,
    statements: Vec<Statement>,
    created_at: u64,
    expires_at: Option<u64>,
) -> Result<AccessGrant, StoreError> {
    let real_grant_row = match store.get_grant(id) {
        Ok(_) => true,
        Err(StoreError::NotFound) => false,
        Err(e) => return Err(e),
    };
    let root = if real_grant_row {
        store
            .leases()
            .with_lease_key(id, Utc::now(), |lease_key| {
                store.lease_wrapped_persona_root_keypair(id, persona_id, lease_key)
            })
            .ok_or_else(|| {
                StoreError::InvalidInput(format!(
                    "grant {id} has no live leased authority; synthetic grant signing \
                     refused for existing row"
                ))
            })??
    } else {
        // Compatibility for synthetic, non-persisted test grants. Real grant
        // rows must use the PR-A lease-wrapped persona-root blob above.
        store.persona_root_keypair(persona_id)?
    };
    access_grant_from_statements(
        id,
        persona_id,
        recipient_id,
        statements,
        created_at,
        expires_at,
        &root,
    )
}

impl DaemonStore {
    /// Build a `DaemonGrantStore` adapter wrapping this store.
    /// Phase C-1: public transition entry points delegate through this.
    pub fn grant_store(&self) -> DaemonGrantStore<'_> {
        DaemonGrantStore::new(self)
    }

    fn sign_block_zero_with_live_lease(
        &self,
        grant_id: &str,
        persona_id: &str,
        block: &Block,
        now: DateTime<Utc>,
        purpose: &str,
    ) -> Result<SignedBlock, StoreError> {
        self.leases()
            .with_lease_key(grant_id, now, |lease_key| {
                let root =
                    self.lease_wrapped_persona_root_keypair(grant_id, persona_id, lease_key)?;
                sign_block_zero_with(&root, block)
            })
            .ok_or_else(|| {
                StoreError::InvalidInput(format!(
                    "grant {grant_id} has no live leased authority; \
                     block-0 signing refused for {purpose}; persona is inert for this grant"
                ))
            })?
    }

    /// H3 fix — sign block 0 under the lease AND persist the resulting
    /// tail `pubkey_next_secret` (sealed under the same lease key). The
    /// secret is required for any future delegation hop off this grant —
    /// without it the chain cannot be extended via `sign_appended_block`,
    /// so a later `delegate_grant_full` would fail closed.
    ///
    /// The tail block index after signing block 0 is `0` (the block-0
    /// pubkey_next will sign block 1 when delegated).
    fn sign_block_zero_with_live_lease_persisting_chain_secret(
        &self,
        grant_id: &str,
        persona_id: &str,
        block: &Block,
        now: DateTime<Utc>,
        purpose: &str,
    ) -> Result<SignedBlock, StoreError> {
        let output =
            self.leases()
                .with_lease_key(
                    grant_id,
                    now,
                    |lease_key| -> Result<
                        (core_crypto::grant_chain::SignedBlockOutput, Vec<u8>),
                        StoreError,
                    > {
                        let root = self
                            .lease_wrapped_persona_root_keypair(grant_id, persona_id, lease_key)?;
                        let out =
                            core_grants::chain::sign_block_zero_with_returning_output(&root, block)
                                .map_err(|e| StoreError::InvalidInput(e.to_string()))?;
                        let chain_blob = seal_grant_chain_secret(
                            lease_key,
                            grant_id,
                            0,
                            &out.pubkey_next_secret,
                        )?;
                        Ok((out, chain_blob))
                    },
                )
                .ok_or_else(|| {
                    StoreError::InvalidInput(format!(
                        "grant {grant_id} has no live leased authority; \
                     block-0 signing refused for {purpose}; persona is inert for this grant"
                    ))
                })??;
        let (out, chain_blob) = output;
        self.write_grant_chain_secret(grant_id, 0, &chain_blob)?;
        Ok(out.signed)
    }

    /// H3 fix — append a new block N≥1 to an existing grant's chain,
    /// signed by the parent's tail `pubkey_next` (read from the
    /// `grant_chain_secrets` row sealed under the PARENT's live lease).
    /// Persists the newly-minted tail secret under the CHILD grant id
    /// (sealed under the child's just-minted lease) so the child chain
    /// can itself be extended later.
    ///
    /// Returns the appended `SignedBlock`. The caller assembles the full
    /// child chain as `parent.blocks ++ [appended]`.
    // Lease-handoff signing plumbing — structurally many params (parent/child grant + chain context).
    #[allow(clippy::too_many_arguments)]
    fn sign_appended_block_with_lease_handoff(
        &self,
        parent_grant_id: &str,
        parent_persona_id: &str,
        parent_tail_block_index: u32,
        child_grant_id: &str,
        child_block: &Block,
        now: DateTime<Utc>,
        purpose: &str,
    ) -> Result<SignedBlock, StoreError> {
        // 1. Open the parent's tail pubkey_next_secret under the parent's
        //    live lease. The parent grant's lease MUST be live; the
        //    delegate path already gates on this above, but we double-check
        //    here so this helper is safe to call directly.
        let parent_secret = self
            .leases()
            .with_lease_key(
                parent_grant_id,
                now,
                |lease_key| -> Result<PubkeyNextKeyPair, StoreError> {
                    let (stored_index, blob) =
                    self.read_grant_chain_secret(parent_grant_id)?.ok_or_else(|| {
                        StoreError::InvalidInput(format!(
                            "parent grant {parent_grant_id} has no persisted chain-tail secret; \
                             delegation refused — chain cannot be extended"
                        ))
                    })?;
                    if stored_index != parent_tail_block_index {
                        return Err(StoreError::InvalidInput(format!(
                            "parent grant {parent_grant_id} chain-tail index mismatch \
                         (stored {stored_index}, expected {parent_tail_block_index})"
                        )));
                    }
                    open_grant_chain_secret(lease_key, parent_grant_id, stored_index, &blob)
                },
            )
            .ok_or_else(|| {
                StoreError::InvalidInput(format!(
                    "parent grant {parent_grant_id} has no live leased authority; \
                     {purpose} refused — persona inert for parent"
                ))
            })??;

        // Suppress unused-field lint on persona_id — it is a structural
        // hint for the caller (which persona owns the parent chain) but
        // not used by sign_appended_block (the chain-tail key is what
        // signs, not the persona root).
        let _ = parent_persona_id;

        // 2. Sign the appended block.
        let out = core_grants::chain::sign_appended_block_with(&parent_secret, child_block)
            .map_err(|e| StoreError::InvalidInput(format!("appended-block signing failed: {e}")))?;

        // 3. Persist the child's new tail secret, sealed under the CHILD
        //    grant's live lease. tail_block_index = parent_tail_block_index + 1.
        let new_tail_index = parent_tail_block_index
            .checked_add(1)
            .ok_or_else(|| StoreError::InvalidInput("grant chain index overflow".into()))?;
        let chain_blob = self
            .leases()
            .with_lease_key(child_grant_id, now, |lease_key| {
                seal_grant_chain_secret(
                    lease_key,
                    child_grant_id,
                    new_tail_index,
                    &out.pubkey_next_secret,
                )
            })
            .ok_or_else(|| {
                StoreError::InvalidInput(format!(
                    "child grant {child_grant_id} has no live leased authority; \
                     {purpose} refused — chain-tail secret cannot be sealed"
                ))
            })??;
        self.write_grant_chain_secret(child_grant_id, new_tail_index, &chain_blob)?;
        Ok(out.signed)
    }

    fn seal_persona_root_for_grant_lease(
        &self,
        grant_id: &str,
        persona_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let blob = self
            .leases()
            .with_lease_key(grant_id, now, |lease_key| {
                let material = self.persona_root_key_material(persona_id)?;
                seal_grant_persona_secret(lease_key, grant_id, persona_id, material)
            })
            .ok_or_else(|| {
                StoreError::InvalidInput(format!(
                    "grant {grant_id} has no live leased authority; refusing to \
                     persist grant-scoped persona root for persona {persona_id}"
                ))
            })??;
        self.write_grant_persona_secret(grant_id, &blob)
    }

    /// ADR 211 §2 — mint a grant's live lease, seal its persona root under that
    /// lease, and sign block-0 through the lease. This is the canonical
    /// authority-to-act establishment shared by every grant-creation path
    /// (`create_grant_with_budget_inner`, `delegate_grant_full`); exposed
    /// `pub(crate)` so the runtime-persona mirror path
    /// (`infra::persona::mirror_composite_parent_grant_to_runtime_persona`) can
    /// be lease-symmetric instead of signing block-0 with the raw root and
    /// minting no lease (which left the proxy's `has_live_lease` gate failing —
    /// `no_live_lease` 403 on every model-auth request for template/`--delegated`
    /// sessions). The recovered root is identical to the raw root, so the
    /// block-0 signature is unchanged; the lease only gates access. Fail-closed:
    /// on any seal/sign error the just-minted lease is dropped so a failed
    /// creation never leaves a dangling lease.
    // Lease-mint + block-zero signing plumbing — structurally many params (grant/persona/scope/block context).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn mint_lease_and_lease_sign_block_zero(
        &self,
        grant_id: &str,
        persona_id: &str,
        scope: &str,
        expires_at: Option<DateTime<Utc>>,
        block: &Block,
        now: DateTime<Utc>,
        purpose: &str,
    ) -> Result<SignedBlock, StoreError> {
        self.leases()
            .mint(grant_id, persona_id, scope, expires_at, now);
        if let Err(err) = self.seal_persona_root_for_grant_lease(grant_id, persona_id, now) {
            self.leases().drop_lease(grant_id);
            return Err(err);
        }
        // H3 fix — use the persisting variant so this apex grant's tail
        // `pubkey_next_secret` is sealed under the grant's lease and
        // persisted. Without persistence a later delegation off this
        // grant would have no key to sign the appended block.
        match self.sign_block_zero_with_live_lease_persisting_chain_secret(
            grant_id, persona_id, block, now, purpose,
        ) {
            Ok(signed) => Ok(signed),
            Err(err) => {
                self.leases().drop_lease(grant_id);
                Err(err)
            }
        }
    }

    fn lease_wrapped_persona_root_keypair(
        &self,
        grant_id: &str,
        persona_id: &str,
        lease_key: &LeaseKey,
    ) -> Result<RootKeyPair, StoreError> {
        let blob = self.read_grant_persona_secret(grant_id)?.ok_or_else(|| {
            StoreError::InvalidInput(format!(
                "grant {grant_id} has no lease-wrapped persona root; \
                 block-0 signing refused for persona {persona_id}"
            ))
        })?;
        open_grant_persona_secret(lease_key, grant_id, persona_id, &blob)
    }

    /// Create a single-statement grant with no budget attached.
    ///
    /// Thin wrapper over [`DaemonStore::create_grant_with_budget`] that
    /// passes `None` for the budget. Kept with the original signature so
    /// the ~70 existing callers (handler, approval, proxy smoke tests,
    /// dashboard tests, …) keep compiling; new callers that need to
    /// encode a budget into block-zero's statement should use
    /// `create_grant_with_budget` directly.
    pub fn create_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        self.create_grant_with_budget(persona_id, credential_name, scope, ttl_secs, None)
    }

    /// Create a single-statement grant whose block-zero statement
    /// carries the supplied [`Budget`] (P69K-BUDGET-WRITE).
    ///
    /// Before this change, `create_grant` always called
    /// `build_single_statement_block(..., budget: None, ...)`, which
    /// meant the composite read path
    /// (`get_access_grant → AccessGrant.blocks[0].statements[0].budget`)
    /// saw `None` even when the operator had set a budget via
    /// `ember grant budget` / `ember sandbox run --budget-tokens`. The
    /// dashboard then rendered `(none)` or yellow for the displayed
    /// budget — the "Beat 2 credibility gap" the demo script called out.
    ///
    /// The flat `budget_json` column on `grants` is **not** written from
    /// this path. `row_to_grant` already prefers `blocks_json`'s
    /// first-statement budget when present, and writing the flat column
    /// too would create two sources of truth that can drift. The column
    /// remains populated by the legacy paths (`delegate_grant_full`,
    /// `extend_grant`) as a redundant mirror slated for removal with
    /// `P69K-G` (live usage outside the chain).
    pub fn create_grant_with_budget(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
        budget: Option<Budget>,
    ) -> Result<GrantInfo, StoreError> {
        self.create_grant_with_budget_inner(
            persona_id,
            credential_name,
            scope,
            ttl_secs,
            budget,
            true,
        )
    }

    /// Like [`create_grant_with_budget`] but suppresses the `grant.minted`
    /// audit event.  Used by the composite-approval path so that
    /// `mint_composite_chain_for_grant` can emit a single `grant.minted`
    /// event AFTER the composite shape is finalised (REVIEW2-F8).
    pub(crate) fn create_grant_with_budget_suppress_minted_event(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
        budget: Option<Budget>,
    ) -> Result<GrantInfo, StoreError> {
        self.create_grant_with_budget_inner(
            persona_id,
            credential_name,
            scope,
            ttl_secs,
            budget,
            false,
        )
    }

    fn create_grant_with_budget_inner(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
        budget: Option<Budget>,
        emit_minted_event: bool,
    ) -> Result<GrantInfo, StoreError> {
        // grant_ttl_capped_at_max — Per adversarial-review 2026-05-19 HIGH-7.
        // Refuse a TTL that exceeds [`MAX_GRANT_TTL_SECS`] before any
        // persona/key work or event emission. Maintains ADR 072's "bounded"
        // invariant: even a malicious approver (or compromised dashboard)
        // cannot mint an effectively-permanent grant.
        if let Some(secs) = ttl_secs
            && secs > MAX_GRANT_TTL_SECS
        {
            return Err(StoreError::InvalidInput(format!(
                "ttl_secs ({secs}) exceeds MAX_GRANT_TTL_SECS ({MAX_GRANT_TTL_SECS}); \
                 grants are bounded per ADR 072 — mint a shorter-lived grant or \
                 schedule re-issuance"
            )));
        }

        // Verify persona exists and is active.
        let persona_status: Option<String> = self
            .conn()
            .query_row(
                "SELECT status FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
                |row| row.get(0),
            )
            .optional()?;

        match persona_status.as_deref() {
            None => return Err(StoreError::NotFound),
            Some("active") => {}
            Some(other) => {
                return Err(StoreError::InvalidInput(format!(
                    "persona is not active: {other}"
                )));
            }
        }

        let id = format!("grant-{}", Uuid::new_v4());
        let now: DateTime<Utc> = Utc::now();
        let created_at = now.to_rfc3339();
        let created_at_epoch = now.timestamp().max(0) as u64;

        let lease_expires_at = ttl_secs.map(|secs| now + Duration::seconds(secs as i64));
        let expires_at: Option<String> = lease_expires_at.as_ref().map(DateTime::<Utc>::to_rfc3339);
        let expires_at_epoch = ttl_secs.map(|s| created_at_epoch.saturating_add(s));

        // Build the canonical composite chain (single-statement) up front
        // and persist its blocks_json alongside the flat columns. Callers
        // reading this grant hydrate from blocks_json and see the Statement.
        //
        // Block 0 is signed under the issuing persona's root Ed25519 key
        // via `core_crypto::grant_chain::sign_block_zero` per ADR 074
        // revision. Daemon-issued grants no longer carry the
        // `"unsigned-phase1"` placeholder.
        //
        // The caller's `budget` (if any) is threaded into the
        // first-statement's `budget` field — this is the authoritative
        // source of truth for budget on composite-read paths.
        //
        // ADR 211 §2 — block-0 signing is authority-to-act. Mint the
        // grant-scoped lease before signing and borrow through
        // `LeaseRegistry::with_lease_key`; if the lease is already inert
        // (for example ttl_secs=0), signing fails closed and no row is
        // inserted.
        self.leases()
            .mint(&id, persona_id, scope, lease_expires_at, now);
        if let Err(err) = self.seal_persona_root_for_grant_lease(&id, persona_id, now) {
            self.leases().drop_lease(&id);
            return Err(err);
        }
        let build_result: Result<(Option<Budget>, String), StoreError> = (|| {
            let effective_budget = budget.clone().filter(|b| !b.is_none_set());
            let block = build_single_statement_block(
                persona_id,
                credential_name,
                scope,
                created_at_epoch,
                expires_at_epoch,
                effective_budget.clone(),
                Usage::default(),
            );
            // H3 fix — use the new sign-and-persist helper so the tail
            // pubkey_next_secret is sealed under the grant's lease and
            // persisted. This is what enables later append-chain
            // delegation off this grant; pre-fix the secret was dropped on
            // the floor and the only path to delegate was minting a fresh
            // single-block chain linked by `parent_grant_id` (the H3 bug).
            let signed = self.sign_block_zero_with_live_lease_persisting_chain_secret(
                &id,
                persona_id,
                &block,
                now,
                "grant creation",
            )?;
            let access_grant = access_grant_envelope(
                &id,
                persona_id,
                credential_name,
                "active",
                signed,
                created_at_epoch,
            );
            let blocks_json = access_grant_blocks_to_json(&access_grant)?;
            validate_blocks_json_caps(&access_grant, &blocks_json)?;
            Ok((effective_budget, blocks_json))
        })();
        let (effective_budget, blocks_json) = match build_result {
            Ok(result) => result,
            Err(err) => {
                self.leases().drop_lease(&id);
                return Err(err);
            }
        };

        if let Err(err) = self.conn().execute(
            "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status, blocks_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8)",
            rusqlite::params![
                id,
                persona_id,
                credential_name,
                scope,
                ttl_secs.map(|s| s as i64),
                created_at,
                expires_at,
                blocks_json,
            ],
        ) {
            self.leases().drop_lease(&id);
            return Err(err.into());
        }

        // REVIEW2-F8: for composite grants this event is suppressed here and
        // re-emitted by `mint_composite_chain_for_grant` after the multi-
        // statement shape is finalised so the audit log shows the accurate
        // statement_count.
        if emit_minted_event {
            let _ = self.log_event(
                Some(persona_id),
                "grant.minted",
                Some(credential_name),
                "minted",
                Some(
                    &serde_json::json!({
                        "grant_id": id,
                        "statement_count": 1,
                        "ttl_secs": ttl_secs,
                        "creation_mode": "single",
                    })
                    .to_string(),
                ),
            );
        }
        Ok(GrantInfo {
            id,
            persona_id: persona_id.to_string(),
            credential_name: credential_name.to_string(),
            scope: scope.to_string(),
            created_at,
            expires_at,
            status: "active".to_string(),
            max_uses_per_hour: None,
            allowed_hours_start: None,
            allowed_hours_end: None,
            allowed_targets: None,
            parent_grant_id: None,
            max_delegation_depth: None,
            spending_limit_cents: None,
            budget: effective_budget,
            usage: Usage::default(),
            paused: false,
            receipt_id: None,
            is_standing: false,
            max_children_per_day: None,
            auto_delegate_scope_template: None,
        })
    }

    /// Mark an existing grant as a standing parent (P69L.3).
    ///
    /// Standing parents let the orchestrator mint short-lived child grants
    /// without re-prompting the operator, subject to
    /// `max_children_per_day`. The operator approves the parent once (with
    /// a broad scope template and a daily ceiling), and each cycle calls
    /// `delegate_grant_full(parent_id, …)` to mint a cycle-specific child.
    ///
    /// Requires that the grant allow delegation — callers must have
    /// already set `max_delegation_depth` (via the standard UPDATE path)
    /// before marking the grant standing, or `delegate_grant_full` will
    /// later reject every child with "parent does not allow delegation".
    ///
    /// `max_children_per_day` must be > 0. Passing 0 is treated as a
    /// misconfiguration (would disable delegation entirely) and rejected.
    pub fn mark_grant_standing(
        &self,
        grant_id: &str,
        max_children_per_day: u64,
        scope_template: Option<&str>,
    ) -> Result<(), StoreError> {
        if max_children_per_day == 0 {
            return Err(StoreError::InvalidInput(
                "max_children_per_day must be > 0".into(),
            ));
        }
        let n = self.conn().execute(
            "UPDATE grants SET is_standing = 1, max_children_per_day = ?1, \
                               auto_delegate_scope_template = ?2 \
             WHERE id = ?3",
            rusqlite::params![max_children_per_day as i64, scope_template, grant_id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub fn list_grants(&self) -> Result<Vec<GrantInfo>, StoreError> {
        let sql = format!("SELECT {GRANT_COLUMNS} FROM grants");
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt.query_map([], row_to_grant)?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?);
        }
        Ok(grants)
    }

    pub fn list_active_grants(&self) -> Result<Vec<GrantInfo>, StoreError> {
        // `paused` is a reversible state; the operator
        // who pauses a grant must still be able to find and resume it
        // without flipping the "show terminated" toggle (which is for
        // *terminal* states: revoked / expired / exhausted_by_budget).
        // Both `active` and `paused` belong on the operator-facing list.
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "SELECT {GRANT_COLUMNS} FROM grants \
             WHERE status IN ('active', 'paused') \
             AND (expires_at IS NULL OR expires_at > ?1)"
        );
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params![now], row_to_grant)?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?);
        }
        Ok(grants)
    }

    /// True iff `grant_id` names a still-active grant — `status IN ('active',
    /// 'paused')` and not past its own `expires_at` (the same liveness definition
    /// as [`Self::list_active_grants`], for a single id).
    ///
    /// Used by the ADR 211 Phase 4 lease rehydration path: a lease must not be
    /// resurrected from a persisted SE-wrapped blob once its grant is revoked /
    /// expired / exhausted (a *status flip* — the grant row persists) or absent. A
    /// SQLite error is treated as "not active" (fail-closed): a lease whose
    /// liveness we cannot confirm stays inert.
    pub(crate) fn grant_is_active(&self, grant_id: &str, now: DateTime<Utc>) -> bool {
        let now_s = now.to_rfc3339();
        match self
            .conn()
            .query_row(
                "SELECT 1 FROM grants \
                 WHERE id = ?1 AND status IN ('active', 'paused') \
                 AND (expires_at IS NULL OR expires_at > ?2)",
                rusqlite::params![grant_id, now_s],
                |_| Ok(()),
            )
            .optional()
        {
            Ok(Some(())) => true,
            Ok(None) => false,
            Err(e) => {
                tracing::error!(
                    grant_id = %grant_id,
                    error = %e,
                    "ADR 211 Phase 4: grant_is_active query failed; treating grant as \
                     inactive (fail-closed)"
                );
                false
            }
        }
    }

    pub fn get_grant(&self, id: &str) -> Result<GrantInfo, StoreError> {
        let sql = format!("SELECT {GRANT_COLUMNS} FROM grants WHERE id = ?1");
        self.conn()
            .query_row(&sql, rusqlite::params![id], row_to_grant)
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    /// Return the canonical composite `AccessGrant` chain for a grant.
    ///
    /// Prefers the stored `blocks_json` (written by `create_grant` and
    /// `delegate_grant_full`); falls back to synthesizing a single-
    /// statement chain from the scalar columns for legacy rows.
    ///
    /// Callers needing per-Statement metering (Stream C) or receipts
    /// (Stream D) read through this method rather than `get_grant` so
    /// they see the authoritative Statement shape directly.
    ///
    /// Before returning, `verify_chain` is called on the grant's block
    /// chain. Grants with the pre-migration `"unsigned-phase1"` placeholder
    /// are logged and passed through until W1's daemon Ed25519 wiring
    /// eliminates them. Any other chain error rejects the grant.
    pub fn get_access_grant(&self, id: &str) -> Result<AccessGrant, StoreError> {
        let info = self.get_grant(id)?;
        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT blocks_json FROM grants WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if let Some(s) = raw
            && let Ok(blocks) = serde_json::from_str::<Vec<SignedBlock>>(&s)
            && !blocks.is_empty()
        {
            // Envelope-chain consistency guard (adversarial review M1):
            //
            // - Apex grant (no `parent_grant_id`): block 0 must declare itself
            //   issued by the row's persona. A mismatch means a corrupt write,
            //   a migration bug, or an attacker-crafted blocks_json.
            // - Delegated grant (H3 fix, post-rewire): block 0's `issued_by`
            //   is the CHAIN-ROOT persona (the apex many hops up), not the
            //   row's persona. The integrity invariant is that the TAIL
            //   block's `issued_by` must equal the row's persona — that is
            //   the persona who actually received the appended authority.
            //   `issuing_persona_id` is then taken from block 0 so chain
            //   verification looks up the right root key.
            //
            // On mismatch, fall back to the synthesized single-statement
            // projection so callers still see a coherent grant (same shape
            // as legacy rows).
            let is_delegated = info.parent_grant_id.is_some();
            let consistency_ok = if is_delegated {
                blocks.last().map(|b| b.block.issued_by.as_str()) == Some(info.persona_id.as_str())
            } else {
                blocks[0].block.issued_by == info.persona_id
            };
            if !consistency_ok {
                tracing::warn!(
                    grant_id = %info.id,
                    row_persona = %info.persona_id,
                    chain_block_zero_issued_by = %blocks[0].block.issued_by,
                    chain_tail_issued_by = %blocks.last().map(|b| b.block.issued_by.as_str()).unwrap_or(""),
                    is_delegated,
                    "blocks_json chain consistency mismatch with grant row persona; \
                     rejecting hydrated chain, falling back to projection"
                );
                let projected = self.project_access_grant(&info)?;
                return self.verify_and_return(projected);
            }
            let issuing_persona_id = blocks[0].block.issued_by.clone();
            let created_at_epoch = parse_epoch(Some(&info.created_at)).unwrap_or(0);
            let grant = AccessGrant {
                id: info.id.clone(),
                version: 1,
                issuing_persona_id,
                recipient_kind: PresentationAudienceKind::Service,
                recipient_id: info.credential_name.clone(),
                recipient_profile: RecipientProfile::Agent,
                status: GrantStatus::parse(&info.status).unwrap_or(GrantStatus::Active),
                mode: GrantMode::OneShot,
                blocks,
                attestation: AttestationBinding::default(),
                created_at: created_at_epoch,
                updated_at: created_at_epoch,
                revoked_at: None,
                revoked_reason: None,
                last_used_at: None,
                label: None,
            };
            return self.verify_and_return(grant);
        }
        let projected = self.project_access_grant(&info)?;
        self.verify_and_return(projected)
    }

    /// Verify a hydrated grant's chain before returning it from the read
    /// path (W4 / adversarial M-2). Persona-missing edge case (orphan
    /// grant or deleted persona) passes through with a log; all other
    /// chain errors reject with `InvalidInput`. `core-crypto` rejects the
    /// legacy `unsigned-phase1` placeholder naturally — the daemon no
    /// longer carries a pass-through for it.
    fn verify_and_return(&self, grant: AccessGrant) -> Result<AccessGrant, StoreError> {
        match self.get_persona_root_pubkey_bytes(&grant.issuing_persona_id) {
            None => {
                // F-07: only pass through when the grant is an unsigned
                // phase-1 placeholder (single block, unsigned-phase1
                // signature). Multi-block or real-signature orphans are
                // rejected — they had a persona at mint time and the
                // missing row is suspicious.
                let is_phase1 = grant.blocks.len() == 1
                    && grant.blocks[0].signature == grant_chain::UNSIGNED_PHASE1_PLACEHOLDER;
                if is_phase1 {
                    tracing::warn!(
                        grant_id = %grant.id,
                        persona_id = %grant.issuing_persona_id,
                        "persona root pubkey not found — unsigned phase-1 grant; \
                         skipping chain verification"
                    );
                    Ok(grant)
                } else {
                    Err(StoreError::InvalidInput(format!(
                        "grant chain verification failed: persona '{}' not found \
                         and grant is not a phase-1 placeholder",
                        grant.issuing_persona_id
                    )))
                }
            }
            Some(root_pubkey) => verify_chain(&grant.blocks, &root_pubkey)
                .map(|()| grant)
                .map_err(|e| {
                    StoreError::InvalidInput(format!("grant chain verification failed: {e}"))
                }),
        }
    }

    /// Look up the Ed25519 root public key for a persona as raw 32 bytes
    /// (for `verify_chain`). Returns `None` if the persona row is missing
    /// or its `public_key` column cannot be decoded.
    fn get_persona_root_pubkey_bytes(&self, persona_id: &str) -> Option<[u8; 32]> {
        let public_key: Option<String> = self
            .conn()
            .query_row(
                "SELECT public_key FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten();
        let public_key = public_key?;
        root_pubkey_bytes_from_ed25519_hex(&public_key).ok()
    }

    /// Project a [`GrantInfo`] (flat daemon-row view) into a canonical
    /// composite [`AccessGrant`] chain. Used as the fallback when a grant
    /// row has no `blocks_json` (pre-ADR-073 legacy row) or when the
    /// stored chain was rejected by the envelope-consistency guard.
    ///
    /// Block 0 is signed through the grant's live leased-authority blob. A
    /// legacy row without `grant_persona_secrets` fails closed instead of
    /// reopening the persona's standing secret.
    pub fn project_access_grant(&self, info: &GrantInfo) -> Result<AccessGrant, StoreError> {
        let created_at_epoch = parse_epoch(Some(&info.created_at)).unwrap_or(0);
        let expires_at_epoch = info
            .expires_at
            .as_deref()
            .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
            .map(|dt| dt.with_timezone(&Utc).timestamp().max(0) as u64);
        let block = build_single_statement_block(
            &info.persona_id,
            &info.credential_name,
            &info.scope,
            created_at_epoch,
            expires_at_epoch,
            info.budget.clone(),
            info.usage.clone(),
        );
        let signed = self.sign_block_zero_with_live_lease(
            &info.id,
            &info.persona_id,
            &block,
            Utc::now(),
            "grant projection",
        )?;
        Ok(access_grant_envelope(
            &info.id,
            &info.persona_id,
            &info.credential_name,
            &info.status,
            signed,
            created_at_epoch,
        ))
    }

    /// Overwrite a grant's `blocks_json` with the caller-supplied composite
    /// chain. Used by multi-statement minting flows (e.g. `ember sandbox
    /// run`'s 3-statement envelope) to replace the single-statement shim
    /// `create_grant` wrote with the canonical multi-Statement shape.
    pub fn overwrite_grant_blocks(&self, id: &str, grant: &AccessGrant) -> Result<(), StoreError> {
        self.overwrite_grant_blocks_inner(id, grant, None)
    }

    /// REVIEW2-F4: overwrite a grant's `blocks_json`, running the
    /// bipartite-dominance check against an explicit `parent_bound`
    /// rather than the row's currently-stored chain.
    ///
    /// Used by [`mint_composite_chain_for_grant`](crate::approval) so the
    /// dominance gate is rooted in the operator-approved statement set
    /// (the union bound) instead of the scope-`*` projection that
    /// `create_grant` wrote upstream — without this, the dominance check
    /// is trivially true because `*` dominates everything, hollowing out
    /// the composite-grant security claim.
    ///
    /// `parent_bound` must:
    /// - have block-0 `issued_by` matching the row's persona_id (else
    ///   the same envelope guard `overwrite_grant_blocks` enforces fires);
    /// - carry statements that bound the new `grant`'s authority (every
    ///   statement in `grant` must be dominated by at least one statement
    ///   in `parent_bound`).
    ///
    /// All other guards (envelope consistency, size caps, full-chain
    /// crypto verify) run identically to the loaded-parent path.
    pub fn overwrite_grant_blocks_with_parent_bound(
        &self,
        id: &str,
        grant: &AccessGrant,
        parent_bound: &AccessGrant,
    ) -> Result<(), StoreError> {
        self.overwrite_grant_blocks_inner(id, grant, Some(parent_bound))
    }

    /// Shared implementation for `overwrite_grant_blocks` and
    /// `overwrite_grant_blocks_with_parent_bound`. When `parent_override`
    /// is `Some`, the bipartite-dominance check uses it directly; when
    /// `None`, the parent is hydrated from the row's stored chain via
    /// [`Self::load_parent_access_grant_for_overwrite`].
    fn overwrite_grant_blocks_inner(
        &self,
        id: &str,
        grant: &AccessGrant,
        parent_override: Option<&AccessGrant>,
    ) -> Result<(), StoreError> {
        // Adversarial review L2: caller must pass matching id / grant.id.
        // Only one caller today (CLI sandbox run) does it correctly; guard
        // so a future caller can't accidentally cross-write a grant's
        // blocks under another grant's row id.
        if grant.id != id {
            return Err(StoreError::InvalidInput(format!(
                "overwrite_grant_blocks: id={id} but grant.id={} — mismatch",
                grant.id
            )));
        }

        // --- F-04 / P69K-A2 L3: size caps before any SQL write ---
        //
        // Block count + per-block statement count + serialized JSON
        // size are validated together via `validate_blocks_json_caps`
        // so the same rejection shape fires on every write path.
        let blocks_json = access_grant_blocks_to_json(grant)?;
        validate_blocks_json_caps(grant, &blocks_json)?;

        // Envelope consistency: block-0 issued_by must match the row's
        // persona_id. Look up the row's persona_id from SQL once.
        let row_persona_id: Option<String> = self
            .conn()
            .query_row(
                "SELECT persona_id FROM grants WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .optional()?;
        let row_persona_id = row_persona_id.ok_or(StoreError::NotFound)?;

        if let Some(first) = grant.blocks.first()
            && first.block.issued_by != row_persona_id
        {
            return Err(StoreError::InvalidInput(format!(
                "overwrite_grant_blocks: block-0 issued_by={} does not match \
                 row persona_id={row_persona_id}",
                first.block.issued_by
            )));
        }

        // --- P69K-A2 I4: bipartite dominance (ADR 073 §Attenuation) ---
        //
        // Re-verifying the client-supplied chain's signature only proves
        // the client held the right keys to sign the new blocks. It does
        // NOT prove the new statements are attenuations of the previously
        // stored statements. A malicious (or buggy) client could overwrite
        // with a chain that expands authority — widening actions, escaping
        // a budget cap, replacing a glob with a broader resource. Enforce
        // bipartite dominance: every statement in the NEW chain must have
        // AT LEAST ONE statement in the OLD chain that subsumes it on
        // actions, resource, and budget-with-usage.
        //
        // Check runs BEFORE the (expensive) crypto verify so the cheap
        // violation fails fast — but AFTER envelope checks so we know the
        // row exists and block-0 is self-consistent.
        //
        // REVIEW2-F4: When `parent_override` is `Some`, the dominance gate
        // is rooted in the caller-supplied bound (e.g. the operator-approved
        // statement set for composite minting) rather than the scope-`*`
        // projection that `create_grant` wrote upstream. Same envelope guard
        // applies to the override: its block-0 issued_by must match the row.
        let loaded_parent;
        let parent: &AccessGrant = match parent_override {
            Some(p) => {
                if let Some(first) = p.blocks.first()
                    && first.block.issued_by != row_persona_id
                {
                    return Err(StoreError::InvalidInput(format!(
                        "overwrite_grant_blocks: parent_bound block-0 issued_by={} \
                         does not match row persona_id={row_persona_id}",
                        first.block.issued_by
                    )));
                }
                p
            }
            None => {
                loaded_parent = self.load_parent_access_grant_for_overwrite(id, &row_persona_id)?;
                &loaded_parent
            }
        };
        check_statement_attenuation(parent, grant).map_err(|e| {
            StoreError::InvalidInput(format!("attenuation violation: {}", e.reason))
        })?;

        // Full chain verify (crypto — most expensive, last).
        match self.get_persona_root_pubkey_bytes(&row_persona_id) {
            None => {
                return Err(StoreError::InvalidInput(format!(
                    "cannot verify chain: persona root pubkey missing for {row_persona_id}"
                )));
            }
            Some(root_pubkey) => {
                verify_chain(&grant.blocks, &root_pubkey).map_err(|e| {
                    StoreError::InvalidInput(format!("grant chain verification failed: {e}"))
                })?;
            }
        }

        self.conn().execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, id],
        )?;
        Ok(())
    }

    /// Hydrate the currently-stored chain for `id` so the bipartite
    /// dominance check in [`overwrite_grant_blocks`] has a parent to
    /// compare against.
    ///
    /// Prefers `blocks_json` when present (and shape-consistent with the
    /// row's persona), falls back to the synthesized single-statement
    /// projection for legacy rows that pre-date `blocks_json`. This
    /// mirrors the hydration strategy used by [`Self::get_access_grant`]
    /// and [`Self::increment_statement_usage`] so a parent loaded here
    /// matches what every other read path sees.
    ///
    /// Unlike `get_access_grant`, we do NOT run `verify_chain` on the
    /// parent here — the parent was already verified at the point it was
    /// written (every write path now runs `verify_chain` before UPDATE),
    /// so re-verifying on every overwrite doubles the Ed25519 work for
    /// no new signal. If the stored `blocks_json` somehow deserializes
    /// but block-0 disagrees with the row's `persona_id`, we fall back
    /// to the projection (same failsafe as the read path).
    fn load_parent_access_grant_for_overwrite(
        &self,
        id: &str,
        row_persona_id: &str,
    ) -> Result<AccessGrant, StoreError> {
        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT blocks_json FROM grants WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        if let Some(s) = raw
            && let Ok(blocks) = serde_json::from_str::<Vec<SignedBlock>>(&s)
            && !blocks.is_empty()
            && blocks[0].block.issued_by == row_persona_id
        {
            let info = self.get_grant(id)?;
            let created_at_epoch = parse_epoch(Some(&info.created_at)).unwrap_or(0);
            return Ok(AccessGrant {
                id: info.id,
                version: 1,
                issuing_persona_id: info.persona_id,
                recipient_kind: PresentationAudienceKind::Service,
                recipient_id: info.credential_name,
                recipient_profile: RecipientProfile::Agent,
                status: GrantStatus::parse(&info.status).unwrap_or(GrantStatus::Active),
                mode: GrantMode::OneShot,
                blocks,
                attestation: AttestationBinding::default(),
                created_at: created_at_epoch,
                updated_at: created_at_epoch,
                revoked_at: None,
                revoked_reason: None,
                last_used_at: None,
                label: None,
            });
        }

        // Fall back to the projected single-statement chain for legacy
        // rows or rows whose blocks_json tripped the block-0 guard.
        let info = self.get_grant(id)?;
        self.project_access_grant(&info)
    }

    pub fn evaluate_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
    ) -> Result<GrantInfo, StoreError> {
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "SELECT {GRANT_COLUMNS} FROM grants \
             WHERE persona_id = ?1 AND credential_name = ?2 \
             AND status = 'active' AND (expires_at IS NULL OR expires_at > ?3) \
             LIMIT 1"
        );
        let grant = self
            .conn()
            .query_row(
                &sql,
                rusqlite::params![persona_id, credential_name, now],
                row_to_grant,
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;

        // Check time window
        if let (Some(start), Some(end)) = (grant.allowed_hours_start, grant.allowed_hours_end) {
            let current_hour = Utc::now().hour();
            let in_window = if start <= end {
                current_hour >= start && current_hour < end
            } else {
                current_hour >= start || current_hour < end
            };
            if !in_window {
                return Err(StoreError::InvalidInput(format!(
                    "outside allowed hours ({start}:00-{end}:00 UTC)"
                )));
            }
        }

        Ok(grant)
    }

    /// Record a usage of a grant. Returns error if rate limit exceeded.
    pub fn record_grant_usage(&self, grant_id: &str) -> Result<(), StoreError> {
        let max_uses: Option<i64> = self
            .conn()
            .query_row(
                "SELECT max_uses_per_hour FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        if let Some(max) = max_uses {
            let one_hour_ago = (Utc::now() - Duration::hours(1)).to_rfc3339();
            let count: i64 = self.conn().query_row(
                "SELECT COUNT(*) FROM grant_usage WHERE grant_id = ?1 AND used_at > ?2",
                rusqlite::params![grant_id, one_hour_ago],
                |row| row.get(0),
            )?;
            if count >= max {
                return Err(StoreError::InvalidInput(format!(
                    "rate limit exceeded: {count}/{max} uses per hour"
                )));
            }
        }

        let now = Utc::now().to_rfc3339();
        self.conn().execute(
            "INSERT INTO grant_usage (grant_id, used_at) VALUES (?1, ?2)",
            rusqlite::params![grant_id, now],
        )?;
        Ok(())
    }

    /// Create a delegated grant with narrowed scope (TTL + scope only).
    ///
    pub fn delegate_grant(
        &self,
        parent_grant_id: &str,
        child_persona_id: &str,
        narrowed_scope: &str,
        ttl_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        self.grant_store().delegate_grant(
            parent_grant_id,
            child_persona_id,
            narrowed_scope,
            ttl_secs,
        )
    }

    pub fn delegate_grant_full(
        &self,
        parent_grant_id: &str,
        child_persona_id: &str,
        narrowed_scope: &str,
        ttl_secs: Option<u64>,
        child_budget: Option<Budget>,
    ) -> Result<GrantInfo, StoreError> {
        self.grant_store().delegate_grant_full(
            parent_grant_id,
            child_persona_id,
            narrowed_scope,
            ttl_secs,
            child_budget,
        )
    }

    /// Create a delegated grant with narrowed scope + optional child budget.
    ///
    /// Enforces offline attenuation per ADR 072 § Offline attenuation:
    /// - child scope must be a subset of parent scope;
    /// - child budget must fit inside parent's remaining allowance
    ///   (parent.budget − parent.usage) on every axis the parent bounds;
    /// - child expires_at must be no later than the parent's (and must be
    ///   present if the parent has one).
    ///
    /// A failure on any axis returns `StoreError::DelegationViolation` with
    /// a reason that names the violating dimension only.
    pub(crate) fn delegate_grant_full_sql(
        &self,
        parent_grant_id: &str,
        child_persona_id: &str,
        narrowed_scope: &str,
        ttl_secs: Option<u64>,
        child_budget: Option<Budget>,
    ) -> Result<GrantInfo, StoreError> {
        // grant_ttl_capped_at_max — D18: delegated child grants must obey
        // the same hard TTL ceiling as directly-created grants. Parent
        // expiry attenuation is not enough because an unbounded parent
        // (`expires_at = None`) permits any bounded child expiry.
        if let Some(secs) = ttl_secs
            && secs > MAX_GRANT_TTL_SECS
        {
            return Err(StoreError::InvalidInput(format!(
                "ttl_secs ({secs}) exceeds MAX_GRANT_TTL_SECS ({MAX_GRANT_TTL_SECS}); \
                 grants are bounded per ADR 072 — mint a shorter-lived grant or \
                 schedule re-issuance"
            )));
        }

        // F-06: route through get_access_grant which calls verify_and_return
        // → verify_chain. Column-tampered parents (scope, budget_json,
        // expires_at mutated without touching blocks_json) are rejected here
        // before any attenuation logic runs. `max_delegation_depth` is still
        // read from the flat row — SQL-tampering depth cannot expand scope
        // or budget, so severity is lower. Tracked as P69K-F06-depth.
        let parent_chain = self.get_access_grant(parent_grant_id)?;
        // Depth check still uses flat row (see P69K-F06-depth).
        let parent_flat = self.get_grant(parent_grant_id)?;
        let now = Utc::now();
        if self
            .leases()
            .with_lease_key(parent_grant_id, now, |lease_key| {
                debug_assert_eq!(lease_key.as_bytes().len(), 32);
            })
            .is_none()
        {
            return Err(StoreError::InvalidInput(
                "parent grant has no live leased authority; delegation requires \
                 a live grant-scoped lease"
                    .into(),
            ));
        }
        let max_depth = parent_flat
            .max_delegation_depth
            .ok_or_else(|| StoreError::InvalidInput("parent does not allow delegation".into()))?;
        if max_depth == 0 {
            return Err(StoreError::InvalidInput("delegation depth exceeded".into()));
        }

        // P69L.3 — standing-parent daily delegation ceiling. Only applies
        // when the parent is marked standing; classical one-shot parents
        // skip this gate entirely. The 24h window is measured backwards
        // from `now` against the child row's `created_at` so the limit is
        // a rolling trailing window, not a midnight-aligned bucket.
        if parent_flat.is_standing
            && let Some(limit) = parent_flat.max_children_per_day
        {
            let one_day_ago = (now - Duration::hours(24)).to_rfc3339();
            let count: i64 = self.conn().query_row(
                "SELECT COUNT(*) FROM grants \
                 WHERE parent_grant_id = ?1 AND created_at > ?2",
                rusqlite::params![parent_grant_id, one_day_ago],
                |row| row.get(0),
            )?;
            if (count as u64) >= limit {
                return Err(StoreError::InvalidInput(format!(
                    "standing-parent delegation ceiling reached: {count}/{limit} children \
                     minted in the trailing 24h window"
                )));
            }
        }

        // --- Offline attenuation (ADR 072 § Offline attenuation) ---
        // Scope, budget, expiry all derived from the VERIFIED chain now.
        //
        // H3 fix — for a multi-block (delegated) parent, the narrowest
        // currently-effective authority lives in the chain's TAIL block,
        // not block 0 (which holds the original apex authority). Pre-fix
        // this site assumed `blocks.first()` which silently widened
        // attenuation to the apex on every multi-hop delegation. Post-fix
        // we read the tail; for a single-block apex parent `first ==
        // last` and behaviour is unchanged.
        let parent_tail_stmt_owner = parent_chain
            .blocks
            .last()
            .ok_or_else(|| StoreError::InvalidInput("parent chain empty".into()))?;
        let parent_stmt = parent_tail_stmt_owner
            .block
            .statements
            .first()
            .ok_or_else(|| StoreError::InvalidInput("parent chain tail block empty".into()))?;
        let parent_scope_str = parent_flat.scope.clone();

        // P69K-F06 scope-consistency guard: the flat `scope` column is a
        // projection of the chain's tail-Statement (actions + resource
        // selector — the currently-effective narrowing). A direct
        // `UPDATE grants SET scope = ...` diverges from the signed
        // chain — reject, mirroring the M1 issued_by consistency check
        // in `get_access_grant`. Without this, an attacker with raw SQL
        // access could expand scope for delegation purposes without
        // touching blocks_json (which would break chain verification).
        // F-06's budget-column tamper is already caught by reading
        // budget from `parent_stmt`; this closes the same hole for
        // scope.
        let (flat_actions, flat_selector) =
            scope_to_actions_and_selector(&parent_scope_str, &parent_flat.credential_name);
        if flat_actions != parent_stmt.actions || flat_selector != parent_stmt.resource {
            return Err(StoreError::InvalidInput(
                "parent grant scope diverges from signed chain — \
                 rejecting delegation of tampered parent"
                    .into(),
            ));
        }

        // H3 fix — supersedes the legacy `enforce_subset(narrowed_scope,
        // &parent_scope_str)` string-predicate gate. Per-Statement
        // attenuation is checked structurally inside `build_result`
        // below via `check_statement_attenuation` (the same predicate
        // the use-time verifier walks per hop), which covers the
        // actions, selector, conditions, delegation, and budget axes
        // — none of which a raw scope-string compare reliably catches.
        // The remaining per-axis checks (expiry, parent-budget
        // headroom) stay; they are not redundant with the per-Statement
        // attenuation walk.
        let _ = parent_scope_str; // retained for diagnostic context only
        let _ = narrowed_scope;

        // Compute child expiry epoch seconds (if provided) and parent's
        // from the TAIL block (most-recent narrowing).
        let child_expiry_epoch: Option<u64> =
            ttl_secs.map(|s| (now.timestamp() as i128 + s as i128).max(0) as u64);
        let parent_expiry_epoch: Option<u64> = parent_tail_stmt_owner.block.expires_at;

        check_expiry_attenuation(parent_expiry_epoch, child_expiry_epoch)?;
        check_budget_attenuation(&parent_stmt.budget, &parent_stmt.usage, &child_budget)?;
        // Preserve legacy parent binding for the INSERT below (credential_name
        // comes from the flat row via the existing parent_flat).
        let parent = parent_flat;

        let id = format!("grant-{}", Uuid::new_v4());
        let created_at = now.to_rfc3339();
        let created_at_epoch = now.timestamp().max(0) as u64;
        let child_lease_expires_at = ttl_secs.map(|s| now + Duration::seconds(s as i64));
        let expires_at = child_lease_expires_at
            .as_ref()
            .map(DateTime::<Utc>::to_rfc3339);
        let expires_at_epoch = ttl_secs.map(|s| created_at_epoch.saturating_add(s));
        let effective_child_budget = child_budget.clone().filter(|b| !b.is_none_set());
        let budget_json: Option<String> = effective_child_budget
            .as_ref()
            .map(|b| serde_json::to_string(b).expect("Budget serializes"));

        // Build composite chain for the delegated grant (H3 fix):
        //
        // Post-fix delegation produces a REAL append-chain — the child's
        // appended block is signed by the parent's tail `pubkey_next`
        // (read from the persisted, lease-sealed `grant_chain_secrets`
        // row) so the full chain `parent.blocks ++ [child_appended]`
        // verifies end-to-end against the chain ROOT persona's key. The
        // mutable `parent_grant_id` SQL column stays for query/analytics
        // only — it is no longer the cryptographic link.
        //
        // Per-Statement attenuation is enforced at WRITE time here via
        // `check_statement_attenuation` (the same predicate the use-time
        // verifier walks per hop). This supersedes the pre-fix
        // `enforce_subset` string predicate, which compared raw scope
        // strings and missed conditions / delegation / budget axes.
        //
        // ADR 211 §2 — the child chain's appended-block signing is
        // guarded by the child grant's own lease (the parent lease only
        // authorizes the delegation decision above; it does not bound
        // the newly minted authority-to-act).
        self.leases().mint(
            &id,
            child_persona_id,
            narrowed_scope,
            child_lease_expires_at,
            now,
        );
        if let Err(err) = self.seal_persona_root_for_grant_lease(&id, child_persona_id, now) {
            self.leases().drop_lease(&id);
            return Err(err);
        }
        let parent_tail_block_index: u32 = (parent_chain.blocks.len().saturating_sub(1)) as u32;
        let build_result: Result<String, StoreError> = (|| {
            let child_block = build_single_statement_block(
                child_persona_id,
                &parent.credential_name,
                narrowed_scope,
                created_at_epoch,
                expires_at_epoch,
                effective_child_budget.clone(),
                Usage::default(),
            );

            // H1/H3 write-time per-Statement attenuation: the appended
            // block must attenuate the parent's tail block. Use the same
            // predicate the use-time verifier walks per hop, applied
            // between the parent chain's tail block and the about-to-be-
            // appended child block.
            let parent_tail_signed = parent_chain
                .blocks
                .last()
                .cloned()
                .ok_or_else(|| StoreError::InvalidInput("parent chain empty".into()))?;
            let parent_tail_synth = synthetic_grant_from_block(
                &parent_tail_signed,
                parent_grant_id,
                &parent_chain.issuing_persona_id,
            );
            let child_unsigned_synth =
                synthetic_grant_from_unsigned_block(&child_block, &id, child_persona_id);
            check_statement_attenuation(&parent_tail_synth, &child_unsigned_synth).map_err(
                |violation| StoreError::DelegationViolation {
                    reason: violation.reason,
                },
            )?;

            // Sign the appended block off the parent's persisted tail
            // pubkey_next; persist the child's new tail secret under the
            // child grant's just-minted lease.
            let child_appended = self.sign_appended_block_with_lease_handoff(
                parent_grant_id,
                &parent.persona_id,
                parent_tail_block_index,
                &id,
                &child_block,
                now,
                "delegated grant creation",
            )?;

            // Assemble the full child chain = parent.blocks ++ [appended].
            // The envelope's `issuing_persona_id` is the chain-root persona
            // (block 0's `issued_by`) so verify_chain looks up the right
            // root key on the use-time path.
            let mut child_blocks = parent_chain.blocks.clone();
            child_blocks.push(child_appended);
            let chain_root_persona = child_blocks[0].block.issued_by.clone();
            let child_access_grant = AccessGrant {
                id: id.clone(),
                version: 1,
                issuing_persona_id: chain_root_persona,
                recipient_kind: PresentationAudienceKind::Service,
                recipient_id: parent.credential_name.clone(),
                recipient_profile: RecipientProfile::Agent,
                status: GrantStatus::Active,
                mode: GrantMode::OneShot,
                blocks: child_blocks,
                attestation: AttestationBinding::default(),
                created_at: created_at_epoch,
                updated_at: created_at_epoch,
                revoked_at: None,
                revoked_reason: None,
                last_used_at: None,
                label: None,
            };
            let blocks_json = access_grant_blocks_to_json(&child_access_grant)?;
            validate_blocks_json_caps(&child_access_grant, &blocks_json)?;
            Ok(blocks_json)
        })();
        let blocks_json = match build_result {
            Ok(blocks_json) => blocks_json,
            Err(err) => {
                self.leases().drop_lease(&id);
                return Err(err);
            }
        };

        if let Err(err) = self.conn().execute(
            "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status, parent_grant_id, max_delegation_depth, budget_json, blocks_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, ?9, ?10, ?11)",
            rusqlite::params![
                id,
                child_persona_id,
                parent.credential_name,
                narrowed_scope,
                ttl_secs.map(|s| s as i64),
                created_at,
                expires_at,
                parent_grant_id,
                max_depth.saturating_sub(1) as i64,
                budget_json,
                blocks_json,
            ],
        ) {
            self.leases().drop_lease(&id);
            return Err(err.into());
        }

        let _ = self.log_event(
            Some(child_persona_id),
            "grant.minted",
            Some(&parent.credential_name),
            "minted",
            Some(
                &serde_json::json!({
                    "grant_id": id,
                    "statement_count": 1,
                    "ttl_secs": ttl_secs,
                    "creation_mode": "delegate",
                    "parent_grant_id": parent_grant_id,
                })
                .to_string(),
            ),
        );

        // Emit + persist a
        // `spawn.witness` Receipt v2 envelope for this parent→child grant
        // edge. The witness binds the spawned (child) persona to the
        // parent's authorization via two independent signatures (CRIT-7
        // mitigation per ADR 118 / core-receipts):
        //
        //   1. The parent persona signs JCS(body \ parent_signature). The
        //      parent's signing key is decrypted out of the vault via
        //      `persona_signer`; without this signature an emberd
        //      impersonator could forge `spawned_persona_id` without the
        //      parent's corroborating authorization.
        //   2. The daemon persona signs the outer envelope (receipt_id +
        //      body), matching `broker.materialization` / `exec.completion`.
        //
        // Best-effort: any failure here (parent persona key not loadable,
        // daemon identity uninitialised in tests, signing or persistence
        // I/O error) logs a warning and continues — the child grant has
        // already minted and a receipt-emission failure must not break
        // delegation. Demo-seam fallback in `tree.rs` was removed in the
        // same patch; downstream verifiers that find no witness for an
        // edge will treat it as an audit gap, not silently fabricate one.
        if let Some(identity) = crate::infra::receipt::current_identity() {
            match self.persona_signer(&parent.persona_id) {
                Ok(parent_signer) => {
                    let daemon_signer =
                        crate::session::lifecycle::DaemonPersonaSigner::new(identity);
                    // container_id is the SCION container slot when the
                    // parent persona is bound to one (workload personas
                    // minted via `create_agent_persona_enrolling`).
                    // Legacy parents created via `create_persona` have no
                    // container binding; pass an empty string so the body
                    // shape stays stable and verifiers can distinguish
                    // SCION-bound from legacy edges via the field.
                    let container_id = self
                        .get_persona(&parent.persona_id)
                        .ok()
                        .and_then(|p| p.container_id)
                        .unwrap_or_default();
                    // Read the Bridge CA fingerprint cached on `DaemonStore`
                    // (wired in by `runtime.rs` after `load_or_mint_bridge_ca`
                    // succeeds at startup). In-memory test stores that never
                    // wired a Bridge CA return `None`; we pass `[0u8; 32]` in
                    // that case — Slice D treats the zero checkpoint as
                    // "fingerprint not asserted" and falls back to legacy
                    // verification (bridge_ca_fingerprint_in_spawn_receipt).
                    let ca_fingerprint = self.bridge_ca_fingerprint().unwrap_or([0u8; 32]);
                    match crate::spawn::scion::emit_spawn_witness_receipt(
                        child_persona_id,
                        &parent.persona_id,
                        &container_id,
                        parent_grant_id,
                        ca_fingerprint,
                        &parent_signer,
                        &daemon_signer,
                    ) {
                        Ok(envelope) => {
                            if let Err(e) = self.store_spawn_witness_receipt(&envelope) {
                                tracing::warn!(
                                    error = %e,
                                    parent_grant_id = %parent_grant_id,
                                    child_grant_id = %id,
                                    receipt_id = %envelope.receipt_id,
                                    "spawn.witness: failed to persist envelope; \
                                     parent→child edge will lack an audit witness"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                parent_grant_id = %parent_grant_id,
                                child_grant_id = %id,
                                "spawn.witness: sign failed; receipt not persisted"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        parent_grant_id = %parent_grant_id,
                        parent_persona_id = %parent.persona_id,
                        child_grant_id = %id,
                        "spawn.witness: parent persona signer unavailable; \
                         receipt not emitted (edge will lack audit witness)"
                    );
                }
            }
        } else {
            tracing::debug!(
                parent_grant_id = %parent_grant_id,
                child_grant_id = %id,
                "spawn.witness: daemon identity not initialised — \
                 skipping receipt emission (test harness / pre-startup path)"
            );
        }

        Ok(GrantInfo {
            id,
            persona_id: child_persona_id.to_string(),
            credential_name: parent.credential_name,
            scope: narrowed_scope.to_string(),
            created_at,
            expires_at,
            status: "active".to_string(),
            max_uses_per_hour: None,
            allowed_hours_start: None,
            allowed_hours_end: None,
            allowed_targets: None,
            parent_grant_id: Some(parent_grant_id.to_string()),
            max_delegation_depth: Some(max_depth.saturating_sub(1)),
            spending_limit_cents: None,
            budget: effective_child_budget,
            usage: Usage::default(),
            paused: false,
            receipt_id: None,
            is_standing: false,
            max_children_per_day: None,
            auto_delegate_scope_template: None,
        })
    }

    /// Read the per-Statement
    /// revocation list for a grant. Returns the deserialized vector of
    /// revoked sids ("S0", "S1", ...). Missing or NULL column is treated
    /// as empty (legacy rows that predate the migration). Malformed JSON
    /// is logged and treated as empty so a corrupt row doesn't take down
    /// the whole grant.
    ///
    /// Reads the per-grant column only — no ancestry walk. Most callers
    /// want [`Self::get_revoked_sids`] which unions this row's sids with
    /// every ancestor persona's grant revocations so revoking an
    /// orchestrator persona cascades to its spawned workers.
    pub(crate) fn get_revoked_sids_for_grant(
        &self,
        grant_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT revoked_sids_json FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        let Some(s) = raw else {
            return Ok(Vec::new());
        };
        match serde_json::from_str::<Vec<String>>(&s) {
            Ok(v) => Ok(v),
            Err(e) => {
                tracing::warn!(
                    grant_id = %grant_id,
                    error = %e,
                    "revoked_sids_json malformed; treating as empty"
                );
                Ok(Vec::new())
            }
        }
    }

    // fn get_revoked_sids walks parent_persona_id ancestry
    /// Return the per-Statement
    /// revocation set for a grant **unioned with every ancestor persona's
    /// grant revocations**. Revoking an orchestrator persona's grant now
    /// cascades to all child / grandchild personas spawned under that
    /// orchestrator: their statement sids appear revoked from the proxy's
    /// perspective even though the per-grant `revoked_sids_json` on the
    /// child row is unchanged.
    ///
    /// Walk shape:
    ///   1. Read the grant row to find its owning `persona_id`.
    ///   2. Walk `personas.parent_grant_id → grants.persona_id` up to
    ///      [`crate::infra::persona::MAX_PARENT_PERSONA_CHAIN_HOPS`]
    ///      ancestors (bounded; cycle-safe via seen-set).
    ///   3. For each ancestor persona, union the revoked sids from EVERY
    ///      grant that persona owns.
    ///   4. Union in the original grant's own revoked sids.
    ///
    /// Signature is preserved (single `grant_id`) — this is an additive
    /// enhancement, not a breaking change. All existing call sites pick
    /// up cascade semantics transparently.
    pub fn get_revoked_sids(&self, grant_id: &str) -> Result<Vec<String>, StoreError> {
        // Always include the grant's own revocations.
        let own = self.get_revoked_sids_for_grant(grant_id)?;
        let mut acc: std::collections::BTreeSet<String> = own.into_iter().collect();

        // Resolve the grant's owning persona. If the grant row is missing
        // the own-read above returns Vec::new() and the persona lookup
        // here also misses — treat as "no ancestors to union" and return
        // the empty set.
        let persona_id: Option<String> = self
            .conn()
            .query_row(
                "SELECT persona_id FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(persona_id) = persona_id else {
            return Ok(acc.into_iter().collect());
        };

        // Walk the ancestry. `parent_persona_chain` returns [self, parent,
        // grandparent, ...] — we union over the WHOLE chain (including
        // self) so revocations on sibling grants owned by the same
        // persona also propagate to this grant's view.
        let chain = self
            .parent_persona_chain(&persona_id)
            .unwrap_or_else(|_| vec![persona_id.clone()]);

        for ancestor in &chain {
            // For each ancestor persona, find every grant they own and
            // union that grant's revoked sids into the accumulator.
            let mut stmt = self
                .conn()
                .prepare("SELECT id FROM grants WHERE persona_id = ?1")?;
            let grant_ids: Vec<String> = stmt
                .query_map(rusqlite::params![ancestor], |row| row.get::<_, String>(0))?
                .filter_map(Result::ok)
                .collect();
            drop(stmt);

            for gid in grant_ids {
                let sids = self.get_revoked_sids_for_grant(&gid)?;
                for sid in sids {
                    acc.insert(sid);
                }
            }
        }

        Ok(acc.into_iter().collect())
    }

    pub fn revoke_grant_statement(&self, grant_id: &str, sid: &str) -> Result<(), StoreError> {
        self.grant_store().revoke_grant_statement(grant_id, sid)
    }

    /// Append `sid` to the per-Statement
    /// revocation list for a grant. Idempotent: appending an already-revoked
    /// sid is a no-op. Emits a `grant.statement_revoked` audit event with
    /// the grant_id and statement sid.
    pub(crate) fn revoke_grant_statement_sql(
        &self,
        grant_id: &str,
        sid: &str,
    ) -> Result<(), StoreError> {
        // Verify the grant exists and capture persona_id for the audit row.
        let grant = self.get_grant(grant_id)?;
        let mut sids = self.get_revoked_sids(grant_id)?;
        if sids.iter().any(|s| s == sid) {
            // Already revoked — idempotent. Still log so operators see the
            // duplicate signal in the audit feed.
            let _ = self.log_event(
                Some(&grant.persona_id),
                "grant.statement_revoked",
                Some(&grant.credential_name),
                "duplicate",
                Some(
                    &serde_json::json!({
                        "grant_id": grant_id,
                        "statement_sid": sid,
                    })
                    .to_string(),
                ),
            );
            return Ok(());
        }
        sids.push(sid.to_string());
        let json = serde_json::to_string(&sids)
            .map_err(|e| StoreError::InvalidInput(format!("revoked_sids serialize: {e}")))?;
        let n = self.conn().execute(
            "UPDATE grants SET revoked_sids_json = ?1 WHERE id = ?2",
            rusqlite::params![json, grant_id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        let _ = self.log_event(
            Some(&grant.persona_id),
            "grant.statement_revoked",
            Some(&grant.credential_name),
            "revoked",
            Some(
                &serde_json::json!({
                    "grant_id": grant_id,
                    "statement_sid": sid,
                })
                .to_string(),
            ),
        );
        Ok(())
    }

    pub fn revoke_grant(&self, id: &str) -> Result<(), StoreError> {
        self.grant_store().revoke_grant(id)
    }

    pub fn abandon_grant(&self, id: &str, reason: &str) -> Result<(), StoreError> {
        self.grant_store().abandon_grant(id, reason)
    }

    pub(crate) fn revoke_grant_sql(&self, id: &str) -> Result<(), StoreError> {
        // Audit-chain hardening: wrap the revoke +
        // audit chain emission + grant-receipt emission in a single
        // BEGIN IMMEDIATE transaction so partial failure can't leave a
        // revoked grant without its audit / receipt trail (or vice versa).
        // Cascade-revoke of children runs OUTSIDE this transaction —
        // recursive calls would otherwise nest BEGIN IMMEDIATE.
        let conn = self.conn();
        conn.execute("BEGIN IMMEDIATE", [])?;

        let txn_result: Result<(), StoreError> = (|| {
            let n = conn.execute(
                "UPDATE grants SET status = 'revoked' WHERE id = ?1",
                rusqlite::params![id],
            )?;
            if n == 0 {
                return Err(StoreError::NotFound);
            }

            // F-S5-005: emit a chained grant.revoked audit event for the
            // operator-initiated revocation. The in-tx variant skips the
            // outer transaction management since we're already inside one.
            crate::infra::audit::append_audit_event_with_chain_in_tx(
                conn,
                None,
                "grant.revoked",
                None,
                "ok",
                Some(
                    &serde_json::json!({
                        "grant_id": id,
                        "revoke_actor": "operator",
                    })
                    .to_string(),
                ),
            )?;

            // Emit Grant Receipt for the operator-initiated revocation.
            if crate::infra::receipt::trigger_receipt_if_terminal_current(
                self,
                id,
                Some(core_grant_types::grant_receipt::TerminalReason::Revoked {
                    by: core_grant_types::grant_receipt::RevokeActor::Operator,
                    reason: String::new(),
                }),
            )
            .is_none()
            {
                tracing::warn!(
                    grant_id = %id,
                    terminal_reason = "revoked",
                    "receipt did not emit for revoked grant — see prior log line"
                );
            }
            Ok(())
        })();

        match txn_result {
            Ok(()) => {
                conn.execute("COMMIT", [])?;
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                return Err(e);
            }
        }

        // ADR 211 §1 — revocation ends authority-to-act: drop the grant's lease
        // (zeroizing its key). Children are dropped in the cascade below.
        self.leases().drop_lease(id);

        // Cascade to child delegated grants — outside the transaction so
        // recursive cascade calls can each open their own BEGIN IMMEDIATE
        // via the same revoke_grant_sql path.
        self.cascade_revoke_children(id, id)?;
        Ok(())
    }

    pub(crate) fn abandon_grant_sql(&self, id: &str, reason: &str) -> Result<(), StoreError> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(StoreError::InvalidInput(
                "abandon_grant requires a non-empty reason".into(),
            ));
        }

        let conn = self.conn();
        conn.execute("BEGIN IMMEDIATE", [])?;

        let txn_result: Result<(), StoreError> = (|| {
            let stored_status: Option<String> = conn
                .query_row(
                    "SELECT status FROM grants WHERE id = ?1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(stored_status) = stored_status else {
                return Err(StoreError::NotFound);
            };
            if matches!(
                stored_status.as_str(),
                "revoked"
                    | "abandoned"
                    | "expired"
                    | "exhausted_by_budget"
                    | "expired_by_budget"
                    | "parent_cascade_revoked"
            ) {
                return Err(StoreError::InvalidInput(format!(
                    "grant {id} is already terminal ({stored_status})"
                )));
            }

            conn.execute(
                "UPDATE grants SET status = 'abandoned' WHERE id = ?1",
                rusqlite::params![id],
            )?;

            crate::infra::audit::append_audit_event_with_chain_in_tx(
                conn,
                None,
                "grant.abandoned",
                None,
                "ok",
                Some(
                    &serde_json::json!({
                        "grant_id": id,
                        "reason": reason,
                    })
                    .to_string(),
                ),
            )?;

            if crate::infra::receipt::trigger_receipt_if_terminal_current(
                self,
                id,
                Some(core_grant_types::grant_receipt::TerminalReason::Abandoned {
                    reason: reason.to_string(),
                }),
            )
            .is_none()
            {
                tracing::warn!(
                    grant_id = %id,
                    terminal_reason = "abandoned",
                    "receipt did not emit for abandoned grant — see prior log line"
                );
            }
            Ok(())
        })();

        match txn_result {
            Ok(()) => {
                conn.execute("COMMIT", [])?;
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                return Err(e);
            }
        }

        self.leases().drop_lease(id);
        self.cascade_revoke_children(id, id)?;
        Ok(())
    }

    fn cascade_revoke_children(
        &self,
        parent_id: &str,
        root_revoked_id: &str,
    ) -> Result<(), StoreError> {
        let mut stmt = self
            .conn()
            .prepare("SELECT id FROM grants WHERE parent_grant_id = ?1 AND status = 'active'")?;
        let children: Vec<String> = stmt
            .query_map(rusqlite::params![parent_id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        for child_id in children {
            self.conn().execute(
                "UPDATE grants SET status = 'revoked' WHERE id = ?1",
                rusqlite::params![child_id],
            )?;
            // ADR 211 §1 — drop the cascade-revoked child's lease.
            self.leases().drop_lease(&child_id);
            // Emit a receipt for the cascade-revoked child. The receipt's
            // TerminalReason distinguishes cascade from direct revoke even
            // though both share the same `revoked` SQL status today.
            if crate::infra::receipt::trigger_receipt_if_terminal_current(
                self,
                &child_id,
                Some(
                    core_grant_types::grant_receipt::TerminalReason::ParentCascadeRevoked {
                        parent_grant_id: root_revoked_id.to_string(),
                    },
                ),
            )
            .is_none()
            {
                tracing::warn!(
                    grant_id = %child_id,
                    parent_grant_id = %root_revoked_id,
                    terminal_reason = "parent_cascade_revoked",
                    "receipt did not emit for cascade-revoked child — see prior log line"
                );
            }
            self.cascade_revoke_children(&child_id, root_revoked_id)?;
        }
        Ok(())
    }

    /// Mark grants whose expires_at has passed as 'expired'.
    ///
    /// For each grant that transitions to expired, emits a signed Grant
    /// Receipt (Stream D) via the process-singleton identity.
    pub fn expire_stale_grants(&self) -> Result<usize, StoreError> {
        let now = Utc::now().to_rfc3339();
        // Collect ids of grants about to expire so we can emit receipts
        // after the status flip (emit reads the terminal status).
        let mut stmt = self.conn().prepare(
            "SELECT id FROM grants \
             WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?1",
        )?;
        let expiring: Vec<String> = stmt
            .query_map(rusqlite::params![now], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        let count = self.conn().execute(
            "UPDATE grants SET status = 'expired' \
             WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?1",
            rusqlite::params![now],
        )?;
        for gid in &expiring {
            // ADR 211 §1 — TTL expiry ends authority-to-act: drop the lease.
            self.leases().drop_lease(gid);
            if crate::infra::receipt::trigger_receipt_if_terminal_current(
                self,
                gid,
                Some(core_grant_types::grant_receipt::TerminalReason::Expired),
            )
            .is_none()
            {
                tracing::warn!(
                    grant_id = %gid,
                    terminal_reason = "expired",
                    "receipt did not emit for TTL-expired grant — see prior log line"
                );
            }
        }
        Ok(count)
    }

    /// Wall-clock budget sweep (P69K-A2). Walks every active grant's
    /// composite chain and flips to `exhausted_by_budget` when any
    /// Statement with `budget.wall_clock_secs` set has been in force for
    /// at least that many seconds (measured from the grant's `created_at`).
    ///
    /// Return value is `(exhausted_count, warned_count)`. Warning events
    /// are emitted to the audit log at `action="budget.warning"` when a
    /// grant crosses the 80% threshold on wall-clock, matching the
    /// TTL-expiry pattern. A grant is only warned once per crossing — the
    /// `warned_wall_clock` column tracks this.
    pub fn expire_grants_by_wall_clock(&self) -> Result<(usize, usize), StoreError> {
        let now_secs = Utc::now().timestamp().max(0) as u64;
        let active = self.list_active_grants()?;
        let mut exhausted = 0usize;
        let mut warned = 0usize;

        for info in active {
            let Ok(ag) = self.get_access_grant(&info.id) else {
                continue;
            };
            let created = ag.created_at;
            if created == 0 || now_secs <= created {
                continue;
            }
            let elapsed = now_secs - created;

            // Find the minimum wall_clock_secs across Statements that set
            // it. First-match exhaustion on any statement terminates the
            // grant (we're allow-only, and a wall-clock-bounded statement
            // that has nothing left cannot contribute).
            let mut min_wall_clock: Option<u64> = None;
            for (_i, stmt) in ag.statements() {
                if let Some(b) = &stmt.budget
                    && let Some(wc) = b.wall_clock_secs
                {
                    min_wall_clock = Some(match min_wall_clock {
                        Some(m) => m.min(wc),
                        None => wc,
                    });
                }
            }
            let Some(limit) = min_wall_clock else {
                continue;
            };

            if elapsed >= limit {
                self.conn().execute(
                    "UPDATE grants SET status = 'exhausted_by_budget' WHERE id = ?1",
                    rusqlite::params![ag.id],
                )?;
                // ADR 211 §1 — budget exhaustion ends authority-to-act: drop the lease.
                self.leases().drop_lease(&ag.id);
                let _ = self.log_event(
                    Some(&ag.issuing_persona_id),
                    "grant.exhausted",
                    Some(&ag.recipient_id),
                    "exhausted_by_budget",
                    Some(&format!("wall_clock elapsed={elapsed} limit={limit}")),
                );
                // Emit a signed Grant Receipt for the terminal state.
                if crate::infra::receipt::trigger_receipt_if_terminal_current(
                    self,
                    &ag.id,
                    Some(
                        core_grant_types::grant_receipt::TerminalReason::ExhaustedByBudget {
                            statement_sid: "S0".into(),
                            axis: core_grant_types::grant_receipt::BudgetAxis::WallClockSecs,
                        },
                    ),
                )
                .is_none()
                {
                    tracing::warn!(
                        grant_id = %ag.id,
                        terminal_reason = "exhausted_by_budget",
                        "receipt did not emit for budget-exhausted grant — see prior log line"
                    );
                }
                exhausted += 1;
                continue;
            }

            // 80% threshold warning — same as TTL. Emit a single warn per
            // crossing. Check-and-set via the `warned_wall_clock_at` column
            // if schema supports it; otherwise fall back to per-tick
            // tracing without de-dup.
            let warn_at = (limit as f64 * 0.8) as u64;
            if elapsed >= warn_at {
                let _ = self.log_event(
                    Some(&ag.issuing_persona_id),
                    "budget.warning",
                    Some(&ag.recipient_id),
                    "wall_clock_80pct",
                    Some(&format!("elapsed={elapsed} limit={limit}")),
                );
                warned += 1;
            }
        }

        Ok((exhausted, warned))
    }

    /// Per-grant version of the
    /// background sweeps (`expire_stale_grants` + `expire_grants_by_wall_clock`)
    /// run synchronously on observation. `get_grant` already projects an
    /// `effective_status` from `expires_at` vs `now`, so callers can
    /// observe a grant as terminal up to 60 seconds before the periodic
    /// sweep flips the DB row + emits the signed receipt. That window
    /// races every receipt-aware downstream check (live receipts panel,
    /// receipt verify, dashboard SSE). Calling this once at the head of
    /// each `grant_status` / observer path closes the window — the
    /// observer flips its own DB row + emits the receipt before reading.
    ///
    /// Returns `true` when a transition (and therefore a receipt) was
    /// emitted in this call. A non-existent grant is `Ok(false)` (callers
    /// resolve the not-found path via the subsequent `get_grant`).
    /// Receipt-emit failures are logged via `tracing::warn` but do not
    /// fail the call — observability beats blocking the read.
    pub fn expire_grant_if_terminal_now(&self, grant_id: &str) -> Result<bool, StoreError> {
        // Cheap row-level fetch to decide whether anything's worth doing.
        let row: Option<(String, Option<String>)> = self
            .conn()
            .query_row(
                "SELECT status, expires_at FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((status, expires_at)) = row else {
            return Ok(false);
        };
        if status != "active" {
            return Ok(false);
        }

        let now = Utc::now();
        let now_secs = now.timestamp().max(0) as u64;

        // TTL-based expiry — mirrors `expire_stale_grants` for one row.
        if let Some(exp_str) = expires_at.as_deref()
            && let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp_str)
            && exp_dt.with_timezone(&Utc) <= now
        {
            self.conn().execute(
                "UPDATE grants SET status = 'expired' WHERE id = ?1 AND status = 'active'",
                rusqlite::params![grant_id],
            )?;
            // ADR 211 §1 — synchronous TTL expiry ends authority-to-act: drop the lease.
            self.leases().drop_lease(grant_id);
            if crate::infra::receipt::trigger_receipt_if_terminal_current(
                self,
                grant_id,
                Some(core_grant_types::grant_receipt::TerminalReason::Expired),
            )
            .is_none()
            {
                tracing::warn!(
                    grant_id = %grant_id,
                    terminal_reason = "expired",
                    "receipt did not emit for synchronous TTL-expired grant"
                );
            }
            return Ok(true);
        }

        // Wall-clock-budget exhaustion — mirrors the per-grant arm of
        // `expire_grants_by_wall_clock` for one row. Re-using the chain
        // walk lets a future axis (token / cents wall-clock) pick up the
        // same observation hook without further touch points.
        let Ok(ag) = self.get_access_grant(grant_id) else {
            return Ok(false);
        };
        let created = ag.created_at;
        if created == 0 || now_secs <= created {
            return Ok(false);
        }
        let elapsed = now_secs - created;
        let mut min_wall_clock: Option<u64> = None;
        for (_i, stmt) in ag.statements() {
            if let Some(b) = &stmt.budget
                && let Some(wc) = b.wall_clock_secs
            {
                min_wall_clock = Some(match min_wall_clock {
                    Some(m) => m.min(wc),
                    None => wc,
                });
            }
        }
        if let Some(limit) = min_wall_clock
            && elapsed >= limit
        {
            self.conn().execute(
                "UPDATE grants SET status = 'exhausted_by_budget' \
                 WHERE id = ?1 AND status = 'active'",
                rusqlite::params![grant_id],
            )?;
            // ADR 211 §1 — synchronous budget exhaustion ends authority-to-act: drop the lease.
            self.leases().drop_lease(grant_id);
            if crate::infra::receipt::trigger_receipt_if_terminal_current(
                self,
                grant_id,
                Some(
                    core_grant_types::grant_receipt::TerminalReason::ExhaustedByBudget {
                        statement_sid: "S0".into(),
                        axis: core_grant_types::grant_receipt::BudgetAxis::WallClockSecs,
                    },
                ),
            )
            .is_none()
            {
                tracing::warn!(
                    grant_id = %grant_id,
                    terminal_reason = "exhausted_by_budget",
                    "receipt did not emit for synchronous wall-clock-exhausted grant"
                );
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// List grants of any status — used for the receipt viewer and terminated-grant rows.
    pub fn list_all_grants(&self) -> Result<Vec<GrantInfo>, StoreError> {
        let sql = format!("SELECT {GRANT_COLUMNS} FROM grants ORDER BY created_at DESC");
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt.query_map([], row_to_grant)?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?);
        }
        Ok(grants)
    }

    /// Set the `paused` flag on a grant (advisory signal to the agent).
    pub fn set_grant_paused(&self, id: &str, paused: bool) -> Result<(), StoreError> {
        let n = self.conn().execute(
            "UPDATE grants SET paused = ?1 WHERE id = ?2 AND status = 'active'",
            rusqlite::params![paused as i64, id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub fn pause_grant(&self, id: &str) -> Result<(), StoreError> {
        self.grant_store().pause_grant(id)
    }

    /// Hard-pause a grant: sets `status = 'paused'` so the proxy's
    /// `evaluate_grant` (which filters `status = 'active'`) rejects all
    /// further requests under this grant. Also sets the `paused` flag for
    /// dashboard rendering consistency.
    ///
    /// Returns `StoreError::NotFound` when the id does not exist.
    /// Returns `StoreError::InvalidInput` when the grant is not in a
    /// state that can be paused (e.g. already revoked, expired, or
    /// exhausted). Idempotent for already-paused grants.
    pub(crate) fn pause_grant_sql(&self, id: &str) -> Result<(), StoreError> {
        // First verify the grant exists and is in a pause-able state.
        let grant = self.get_grant(id)?;
        match grant.status.as_str() {
            "paused" => {
                // Idempotent — already paused.
                return Ok(());
            }
            "active" => {}
            other => {
                return Err(StoreError::InvalidInput(format!(
                    "cannot pause grant with status '{other}'"
                )));
            }
        }
        let n = self.conn().execute(
            "UPDATE grants SET status = 'paused', paused = 1 WHERE id = ?1",
            rusqlite::params![id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub fn resume_grant(&self, id: &str) -> Result<(), StoreError> {
        self.grant_store().resume_grant(id)
    }

    /// Resume a paused grant: flips `status` back to `'active'` and clears
    /// the `paused` flag. No-ops if the grant is already active. Returns
    /// `StoreError::InvalidInput` for non-paused terminal statuses.
    pub(crate) fn resume_grant_sql(&self, id: &str) -> Result<(), StoreError> {
        let grant = self.get_grant(id)?;
        match grant.status.as_str() {
            "active" => {
                // Idempotent — already active.
                return Ok(());
            }
            "paused" => {}
            other => {
                return Err(StoreError::InvalidInput(format!(
                    "cannot resume grant with status '{other}'"
                )));
            }
        }
        let n = self.conn().execute(
            "UPDATE grants SET status = 'active', paused = 0 WHERE id = ?1",
            rusqlite::params![id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Extend a grant's budget and/or TTL.
    ///
    pub fn extend_grant(
        &self,
        id: &str,
        tokens_delta: Option<u64>,
        cents_delta: Option<u64>,
        ttl_extension_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        self.grant_store()
            .extend_grant(id, tokens_delta, cents_delta, ttl_extension_secs)
    }

    /// - `tokens_delta`: additional tokens to add to `budget_tokens` (and reset `tokens_used` floor
    ///   so the new budget is `old_budget + tokens_delta`).
    /// - `cents_delta`: additional cents to add to `budget_cents`.
    /// - `ttl_extension_secs`: seconds to add to `expires_at` (from now if currently unbounded).
    pub(crate) fn extend_grant_sql(
        &self,
        id: &str,
        tokens_delta: Option<u64>,
        cents_delta: Option<u64>,
        ttl_extension_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        // P69K-H1 (adversarial follow-up on #526): wrap the
        // read-compute-write sequence in a `BEGIN IMMEDIATE` transaction so
        // that a concurrent `increment_statement_usage` (or revoke) cannot
        // interleave between our read of `blocks_json` and our UPDATE,
        // rewinding its usage write. Pattern mirrors
        // `increment_statement_usage` — manual begin/commit + RAII rollback
        // guard so any `?`-propagated error path rolls back cleanly.
        self.conn().execute_batch("BEGIN IMMEDIATE")?;
        struct TxGuard<'c> {
            conn: &'c rusqlite::Connection,
            committed: bool,
        }
        impl Drop for TxGuard<'_> {
            fn drop(&mut self) {
                if !self.committed {
                    let _ = self.conn.execute_batch("ROLLBACK");
                }
            }
        }
        let mut tx_guard = TxGuard {
            conn: self.conn(),
            committed: false,
        };

        let grant = self.get_grant(id)?;
        if grant.status != "active" {
            return Err(StoreError::InvalidInput(format!(
                "cannot extend grant with status '{}'",
                grant.status
            )));
        }

        let now: DateTime<Utc> = Utc::now();

        // Compute new expires_at
        let new_expires_at: Option<String> = if let Some(ext) = ttl_extension_secs {
            let base = if let Some(ref exp) = grant.expires_at {
                DateTime::parse_from_rfc3339(exp)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or(now)
            } else {
                now
            };
            let new_exp = base + Duration::seconds(ext as i64);
            Some(new_exp.to_rfc3339())
        } else {
            grant.expires_at.clone()
        };

        // Compute new budget values per ADR 072 (Budget struct, not flat columns)
        let existing_budget = grant.budget.clone().unwrap_or_default();
        let new_budget = Budget {
            tokens: match (existing_budget.tokens, tokens_delta) {
                (Some(e), Some(d)) => Some(e + d),
                (None, Some(d)) => Some(d),
                (e, None) => e,
            },
            cents: match (existing_budget.cents, cents_delta) {
                (Some(e), Some(d)) => Some(e + d),
                (None, Some(d)) => Some(d),
                (e, None) => e,
            },
            ..existing_budget
        };
        let new_budget_opt: Option<Budget> = if new_budget.is_none_set() {
            None
        } else {
            Some(new_budget)
        };
        let new_budget_json: Option<String> = new_budget_opt
            .as_ref()
            .map(|b| serde_json::to_string(b).expect("Budget serializes"));

        // Update the composite chain's first-statement budget to track the
        // envelope-level budget so dashboard/receipt projections stay in
        // sync. Per ADR 073 this is a transitional mapping — once per-
        // Statement metering lands (Stream C) extend_grant will target a
        // specific Statement by sid.
        //
        // Mutating block 0's payload invalidates its signature — we MUST
        // re-sign block 0 under the issuing persona's root key so the
        // chain remains verifiable end-to-end. The transitional signer still
        // opens the persona root key, but the authority-to-act gate is the
        // grant-scoped lease: an active SQL grant with no live lease is inert
        // and cannot reach the signing material. This is not an append; it
        // replaces the only block (the single-block chain is being re-issued
        // with a bumped budget/expiry). ADR 074 revision documents this as
        // the transitional shape until per-Statement metering lets us express
        // the extension as an appended block.
        let mut new_chain = self.get_access_grant(id)?;

        // F-01 (adversarial finding): re-signing block 0 mints a fresh
        // pubkey_next, which orphans the signature on every subsequent
        // block (those are signed by the PREVIOUS pubkey_next's secret,
        // which the daemon does not persist). On a multi-block chain
        // that would silently brick the grant on next read. Guard: only
        // permit extend_grant on a single-block chain today. Future
        // P69K-C append-block path will express extension as a NEW
        // appended block instead of mutating block 0.
        if new_chain.blocks.len() > 1 {
            return Err(StoreError::InvalidInput(
                "extend_grant not supported on multi-block chains yet — \
                 mutating block 0 would orphan subsequent blocks' signatures. \
                 Append-block path (P69K-C3) required."
                    .into(),
            ));
        }

        if let Some(first_block) = new_chain.blocks.first_mut()
            && let Some(first_stmt) = first_block.block.statements.first_mut()
        {
            first_stmt.budget = new_budget_opt.clone();
        }
        if let Some(first_block) = new_chain.blocks.first_mut() {
            // Keep envelope expiry in sync with the row's new expires_at so
            // verify-side expiry checks (if any are wired later) match the
            // stored row.
            let new_expires_epoch = new_expires_at
                .as_deref()
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .map(|dt| dt.with_timezone(&Utc).timestamp().max(0) as u64);
            first_block.block.expires_at = new_expires_epoch;
            // H3 fix — re-signing block 0 rotates pubkey_next, so the
            // persisted tail `pubkey_next_secret` must rotate with it.
            // The persisting variant writes the new (lease-sealed) secret
            // back to `grant_chain_secrets` keyed on this grant, keeping
            // any later delegation off this grant verifiable.
            let resigned = self.sign_block_zero_with_live_lease_persisting_chain_secret(
                id,
                &grant.persona_id,
                &first_block.block,
                now,
                "grant extension",
            )?;
            *first_block = resigned;
        }
        let new_blocks_json = access_grant_blocks_to_json(&new_chain)?;
        validate_blocks_json_caps(&new_chain, &new_blocks_json)?;

        // P69K-H1: re-check status inside the transaction. A revoke that
        // committed between our first `get_grant` and here must win — we
        // refuse to overwrite the blocks_json of a grant that is no longer
        // active. Without this, a concurrent `revoke_grant` followed by an
        // `extend_grant` could silently resurrect the grant's budget/TTL
        // view while leaving status='revoked' (or vice versa — rewind a
        // revoked-status to active-budget).
        let current_status: String = self.conn().query_row(
            "SELECT status FROM grants WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        )?;
        if current_status != "active" {
            // TxGuard rolls back on early return.
            return Err(StoreError::InvalidInput(format!(
                "cannot extend grant with status '{current_status}'"
            )));
        }

        self.conn().execute(
            "UPDATE grants SET budget_json = ?1, expires_at = ?2, blocks_json = ?3 WHERE id = ?4",
            rusqlite::params![new_budget_json, new_expires_at, new_blocks_json, id],
        )?;

        self.conn().execute_batch("COMMIT")?;
        tx_guard.committed = true;

        self.get_grant(id)
    }

    /// Set a receipt_id on a terminated grant.
    pub fn set_grant_receipt_id(&self, grant_id: &str, receipt_id: &str) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE grants SET receipt_id = ?1 WHERE id = ?2",
            rusqlite::params![receipt_id, grant_id],
        )?;
        Ok(())
    }

    /// Get counts of grants by status.
    pub fn grant_summary(&self) -> Result<GrantSummary, StoreError> {
        let active: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM grants WHERE status = 'active'",
            [],
            |row| row.get(0),
        )?;
        let expired: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM grants WHERE status = 'expired'",
            [],
            |row| row.get(0),
        )?;
        let revoked: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM grants WHERE status = 'revoked'",
            [],
            |row| row.get(0),
        )?;
        Ok(GrantSummary {
            active: active as u64,
            expired: expired as u64,
            revoked: revoked as u64,
        })
    }

    /// Atomically increment a specific Statement's usage by `delta` and
    /// return the post-increment `Usage` for that Statement. Used by the
    /// proxy's post-flight meter (Stream C) when an LLM response body has
    /// been parsed for tokens/cents.
    ///
    /// Atomicity is provided by the daemon's single-connection SQLite
    /// (`DaemonStore::conn()` returns the one connection bound to the
    /// LocalSet runtime), plus an immediate transaction bracketing the
    /// read-modify-write on `blocks_json`. No other caller can interleave
    /// a write to this row mid-RMW.
    ///
    /// Returns `StoreError::NotFound` if the grant or the named
    /// `statement_sid` doesn't exist. Returns the prior + new `Usage` tuple
    /// so the caller can compute threshold crossings (80%/95%) without a
    /// second read.
    pub fn increment_statement_usage(
        &self,
        grant_id: &str,
        statement_sid: &str,
        delta: Usage,
    ) -> Result<StatementUsageDelta, StoreError> {
        // Bracket the RMW in a transaction — prevents interleave with the
        // expiry sweep and any future concurrent writer. unchecked_transaction
        // issues BEGIN and provides RAII rollback-on-drop; .commit() closes
        // it on success.
        let tx = self.conn().unchecked_transaction()?;

        // Read current blocks_json. Fall back to the synthesized single-
        // statement chain if the row was created before blocks_json
        // existed (legacy grants; their sid is always "S0").

        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT blocks_json FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        let mut grant: AccessGrant = match raw {
            Some(s) => match serde_json::from_str::<Vec<SignedBlock>>(&s) {
                Ok(blocks) if !blocks.is_empty() => {
                    // Rebuild envelope from the row's scalar fields.
                    let info = self.get_grant(grant_id)?;
                    let created_at_epoch = parse_epoch(Some(&info.created_at)).unwrap_or(0);
                    AccessGrant {
                        id: info.id,
                        version: 1,
                        issuing_persona_id: info.persona_id,
                        recipient_kind: PresentationAudienceKind::Service,
                        recipient_id: info.credential_name,
                        recipient_profile: RecipientProfile::Agent,
                        status: GrantStatus::parse(&info.status).unwrap_or(GrantStatus::Active),
                        mode: GrantMode::OneShot,
                        blocks,
                        attestation: AttestationBinding::default(),
                        created_at: created_at_epoch,
                        updated_at: created_at_epoch,
                        revoked_at: None,
                        revoked_reason: None,
                        last_used_at: None,
                        label: None,
                    }
                }
                _ => {
                    let info = self.get_grant(grant_id)?;
                    self.project_access_grant(&info)?
                }
            },
            None => {
                let info = self.get_grant(grant_id)?;
                self.project_access_grant(&info)?
            }
        };

        // Find the statement by sid and mutate its usage.
        let mut prior: Option<Usage> = None;
        let mut updated: Option<Usage> = None;
        let mut found = false;
        let mut mutated_block_idx: Option<usize> = None;
        let now = Utc::now();
        let now_secs = now.timestamp().max(0) as u64;
        'outer: for (bi, sb) in grant.blocks.iter_mut().enumerate() {
            for stmt in sb.block.statements.iter_mut() {
                if stmt.sid == statement_sid {
                    let before = stmt.usage.clone();
                    stmt.usage.tokens = stmt.usage.tokens.saturating_add(delta.tokens);
                    // Accumulate micro-cents
                    // (sub-cent precision) and DERIVE the integer `cents`
                    // display value from it. Adding `delta.cents` directly
                    // would lose every sub-cent call to integer truncation,
                    // and the budget cap (in micro-cents) would never trip.
                    //
                    // Two backward-compat lifts so legacy callers keep
                    // working through the schema transition:
                    //   1. Stored stmt: pre-fix grants may carry non-zero
                    //      `cents` and zero `cents_micro` from prior runs;
                    //      lift the legacy display value into micro-cents
                    //      on first touch so existing accumulation isn't
                    //      silently dropped.
                    //   2. Delta: callers that haven't been migrated to
                    //      micro-cent precision (legacy meter paths,
                    //      tests, manual increments) pass `Usage { cents:
                    //      N, .. }` with `cents_micro = 0`. Treat that as
                    //      "N whole cents at micro-cent precision" so the
                    //      assertion `s.usage.cents == N` after increment
                    //      still holds.
                    if stmt.usage.cents_micro == 0 && stmt.usage.cents > 0 {
                        stmt.usage.cents_micro = stmt.usage.cents.saturating_mul(1_000_000);
                    }
                    let delta_cents_micro = if delta.cents_micro > 0 {
                        delta.cents_micro
                    } else {
                        delta.cents.saturating_mul(1_000_000)
                    };
                    stmt.usage.cents_micro =
                        stmt.usage.cents_micro.saturating_add(delta_cents_micro);
                    stmt.usage.cents = stmt.usage.cents_micro / 1_000_000;
                    stmt.usage.requests = stmt.usage.requests.saturating_add(delta.requests);
                    stmt.usage.workload_hours = stmt
                        .usage
                        .workload_hours
                        .saturating_add(delta.workload_hours);
                    stmt.usage.wall_clock_secs = stmt
                        .usage
                        .wall_clock_secs
                        .saturating_add(delta.wall_clock_secs);
                    stmt.usage.last_updated = now_secs;
                    prior = Some(before);
                    updated = Some(stmt.usage.clone());
                    found = true;
                    mutated_block_idx = Some(bi);
                    break 'outer;
                }
            }
        }
        if !found {
            return Err(StoreError::NotFound);
        }

        // F-01 (adversarial finding): re-signing block 0 rotates
        // pubkey_next, which orphans blocks 1..N (their signers used the
        // PREVIOUS pubkey_next's secret, which the daemon does not
        // persist). On a multi-block chain that silently bricks the
        // grant on next read. Guard: refuse metering on multi-block
        // chains until live-usage-outside-chain (or pubkey_next_secret
        // persistence) lands. Documented architectural follow-up.
        if grant.blocks.len() > 1 {
            return Err(StoreError::InvalidInput(
                "increment_statement_usage not supported on multi-block chains yet — \
                 re-signing block 0 would orphan subsequent blocks. \
                 Live-usage-outside-chain (P69K-G) required."
                    .into(),
            ));
        }

        // Re-sign block 0 under issuing persona's root key — mutating the
        // statement payload invalidates the chain signature otherwise, and
        // the read path (verify_and_return) rejects unverifiable chains. Per
        // ADR 211, the active SQL row alone is not authority-to-act: usage
        // metering must hold the grant-scoped lease while reopening the
        // signing material.
        if mutated_block_idx == Some(0) {
            // H3 fix — re-signing block 0 rotates pubkey_next, so the
            // persisted tail `pubkey_next_secret` must rotate too. The
            // persisting variant writes the new (lease-sealed) secret
            // back so any later delegation off this grant stays
            // verifiable.
            let new_signed = self.sign_block_zero_with_live_lease_persisting_chain_secret(
                grant_id,
                &grant.issuing_persona_id,
                &grant.blocks[0].block,
                now,
                "statement usage metering",
            )?;
            grant.blocks[0] = new_signed;
        }

        // Persist the mutated blocks chain.
        let blocks_json = access_grant_blocks_to_json(&grant)?;
        validate_blocks_json_caps(&grant, &blocks_json)?;
        self.conn().execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, grant_id],
        )?;
        tx.commit()?;

        Ok(StatementUsageDelta {
            prior: prior.unwrap_or_default(),
            current: updated.unwrap_or_default(),
        })
    }

    /// If a grant's composite chain has no remaining applicable-budget
    /// capacity — specifically: every Statement that carries a `budget`
    /// has at least one axis exhausted — flip status to
    /// `exhausted_by_budget` and log an audit event. No-op otherwise.
    ///
    /// Semantics choice (documented here so Stream D receipts and the
    /// dashboard agree): a grant is "budget-terminal" when **every
    /// budget-bearing Statement** is exhausted on at least one axis.
    /// Statements with `budget = None` are ignored — they are TTL-only
    /// and do not contribute to budget termination. A grant with zero
    /// budget-bearing statements never flips via this path.
    ///
    /// This is the conservative choice: a 3-statement grant
    /// (credential, session, time) flips only once both the session
    /// budget AND the time budget are spent. A single-budget-Statement
    /// grant flips as soon as that one axis exhausts.
    pub fn mark_grant_exhausted_by_budget_if_terminal(
        &self,
        grant_id: &str,
    ) -> Result<bool, StoreError> {
        let grant = self.get_access_grant(grant_id)?;
        if !matches!(grant.status, GrantStatus::Active) {
            return Ok(false);
        }

        let mut any_budget_bearing = false;
        let mut all_exhausted = true;
        for (_i, stmt) in grant.statements() {
            if stmt.budget.is_none() {
                continue;
            }
            any_budget_bearing = true;
            if stmt.has_budget_remaining() {
                all_exhausted = false;
                break;
            }
        }
        if !any_budget_bearing || !all_exhausted {
            return Ok(false);
        }

        let n = self.conn().execute(
            "UPDATE grants SET status = 'exhausted_by_budget' \
             WHERE id = ?1 AND status = 'active'",
            rusqlite::params![grant_id],
        )?;
        if n == 0 {
            return Ok(false);
        }
        let info = self.get_grant(grant_id).ok();
        let (persona, credential) = info
            .map(|i| (Some(i.persona_id), Some(i.credential_name)))
            .unwrap_or((None, None));
        let _ = self.log_event(
            persona.as_deref(),
            "grant.exhausted",
            credential.as_deref(),
            "exhausted_by_budget",
            Some("all_budget_bearing_statements_exhausted"),
        );
        Ok(true)
    }

    /// Record a spending event. Returns error if daily limit exceeded.
    pub fn record_grant_spending(
        &self,
        grant_id: &str,
        amount_cents: u64,
    ) -> Result<(), StoreError> {
        let limit: Option<i64> = self
            .conn()
            .query_row(
                "SELECT spending_limit_cents FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        if let Some(max) = limit {
            let today = Utc::now()
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
                .to_rfc3339();
            let spent: i64 = self.conn().query_row(
                "SELECT COALESCE(SUM(amount_cents), 0) FROM grant_usage WHERE grant_id = ?1 AND used_at > ?2",
                rusqlite::params![grant_id, today],
                |row| row.get(0),
            )?;
            if spent + amount_cents as i64 > max {
                return Err(StoreError::InvalidInput(format!(
                    "spending limit exceeded: ${:.2} + ${:.2} > ${:.2}/day",
                    spent as f64 / 100.0,
                    amount_cents as f64 / 100.0,
                    max as f64 / 100.0
                )));
            }
        }

        let now = Utc::now().to_rfc3339();
        self.conn().execute(
            "INSERT INTO grant_usage (grant_id, used_at, amount_cents) VALUES (?1, ?2, ?3)",
            rusqlite::params![grant_id, now, amount_cents as i64],
        )?;
        Ok(())
    }

    // ===========================================================================
    // ADR191_PAYMENT_BUILD_AHEAD — payment reserve/settle lane (rail adapter +
    // payment.evaluated/.settled receipts). This is BUILD-AHEAD substrate for
    // ADR 191 (ResourceType::Payment via broker_exec rail). It is intentionally
    // NOT wired to a live daemon RPC yet (the PreToolUse hook that
    // formerly entered it was retired in chore/retire-cohort-a2-pretooluse-hook).
    // DO NOT delete these as "no callers / dead code" — they are exercised by the
    // tests below and are the seed of the ADR 191 implementation. See ADR 191.
    // ===========================================================================

    /// ADR191_PAYMENT_BUILD_AHEAD: crate-visible seed entry for the payment
    /// reserve/settle lane. Resolves the grant (by `grant_id` when supplied,
    /// otherwise by active-grant-for-persona), parses a [`PaymentAttempt`] from
    /// `params`, and dispatches into [`Self::evaluate_payment_tool_call`],
    /// emitting the `tool_call_attempt` audit row. This is the seam a future
    /// ADR 191 broker_exec entry will call; it is NOT yet wired to a daemon RPC.
    pub(crate) fn reserve_payment_tool_call(
        &self,
        persona: &str,
        tool_name: &str,
        params: &serde_json::Value,
        session_id: Option<&str>,
        grant_id: Option<&str>,
    ) -> Result<ToolCallDecision, StoreError> {
        let now = Utc::now().to_rfc3339();
        let grant: Option<GrantInfo> = if let Some(gid) = grant_id {
            self.get_grant(gid).ok().filter(|grant| {
                grant.status == "active"
                    && grant
                        .expires_at
                        .as_deref()
                        .is_none_or(|expires_at| expires_at > now.as_str())
            })
        } else {
            let sql = format!(
                "SELECT {GRANT_COLUMNS} FROM grants \
                 WHERE persona_id IN (SELECT id FROM personas WHERE name = ?1) \
                 AND status = 'active' \
                 AND (expires_at IS NULL OR expires_at > ?2) \
                 LIMIT 1"
            );
            self.conn()
                .query_row(&sql, rusqlite::params![persona, now], row_to_grant)
                .optional()?
        };

        let evaluated = match (&grant, self.payment_attempt_from_params(params)) {
            (Some(g), Some(attempt)) => {
                self.evaluate_payment_tool_call(g, tool_name, params, attempt)?
            }
            (Some(_), None) => {
                return Err(StoreError::InvalidInput(
                    "reserve_payment_tool_call requires a payment attempt (attempt_id/vendor/amount_cents) in params".to_string(),
                ));
            }
            (None, _) => EvaluatedToolCall {
                decision: ToolCallDecision {
                    permit: false,
                    reason: Some(format!("no active grant for persona '{persona}'")),
                    grant_id: None,
                    emitted_event_id: String::new(),
                    await_approval_request_id: None,
                },
                audit_outcome: "denied".to_string(),
                audit_details: serde_json::json!({
                    "tool_name": tool_name,
                    "params": params,
                    "session_id": session_id,
                    "persona": persona,
                    "grant_id_hint": grant_id,
                }),
            },
        };

        let agent_id = grant
            .as_ref()
            .map(|g| g.persona_id.as_str())
            .or(Some(persona));
        let event_id = self
            .log_event(
                agent_id,
                "tool_call_attempt",
                Some(tool_name),
                &evaluated.audit_outcome,
                Some(&evaluated.audit_details.to_string()),
            )
            .unwrap_or(0);

        Ok(ToolCallDecision {
            emitted_event_id: event_id.to_string(),
            ..evaluated.decision
        })
    }

    pub(crate) fn payment_attempt_from_params(
        &self,
        params: &serde_json::Value,
    ) -> Option<PaymentAttempt> {
        let attempt_id = params.get("attempt_id")?.as_str()?.to_string();
        let vendor = params
            .get("vendor")
            .or_else(|| params.get("merchant"))?
            .as_str()?
            .to_string();
        let amount_cents = params.get("amount_cents")?.as_u64()?;
        let shadow = params
            .get("shadow")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        Some(PaymentAttempt {
            attempt_id,
            vendor,
            amount_cents,
            shadow,
        })
    }

    fn payment_attempt_scope(attempt_id: &str) -> String {
        format!("payment_attempt:{attempt_id}")
    }

    fn latest_payment_decision_only_approval(
        &self,
        persona_id: &str,
        action: &str,
        attempt_id: &str,
    ) -> Result<Option<crate::trust::approval::ApprovalRequestInfo>, StoreError> {
        let approval_id: Option<String> = self
            .conn()
            .query_row(
                "SELECT id FROM approval_requests \
                 WHERE persona_id = ?1 AND action = ?2 AND scope = ?3 \
                   AND resolution_kind = 'decision_only' \
                 ORDER BY created_at DESC LIMIT 1",
                rusqlite::params![persona_id, action, Self::payment_attempt_scope(attempt_id)],
                |row| row.get(0),
            )
            .optional()?;
        approval_id.map(|id| self.get_approval(&id)).transpose()
    }

    fn collect_payment_receipt_ledger(
        &self,
        grant_id: &str,
        attempt_id: &str,
    ) -> Result<PaymentReceiptLedger, StoreError> {
        let mut ledger = PaymentReceiptLedger::default();
        let envelopes = self.list_receipts_v2_envelopes(&[grant_id.to_string()])?;
        let mut open_reservations: HashMap<String, PaymentReservation> = HashMap::new();
        let now = Utc::now();

        for (_, kind, _, envelope) in envelopes {
            match kind.as_str() {
                RECEIPT_KIND_PAYMENT_EVALUATED => {
                    let Ok(body) =
                        serde_json::from_value::<PaymentEvaluatedBody>(envelope.body.clone())
                    else {
                        continue;
                    };
                    if body.attempt_id == attempt_id {
                        ledger.attempt_evaluated_states.push(body.state);
                    }
                    if body.state == PaymentEvaluatedState::Reserved
                        && let Some(reserved_until) =
                            body.reserved_until.as_deref().and_then(parse_rfc3339_utc)
                    {
                        open_reservations.insert(
                            body.attempt_id.clone(),
                            PaymentReservation {
                                attempt_id: body.attempt_id,
                                statement_sid: body.statement_sid,
                                vendor: body.vendor,
                                amount_cents: body.amount_cents,
                                reserved_until,
                            },
                        );
                    }
                }
                RECEIPT_KIND_PAYMENT_SETTLED => {
                    let Ok(body) =
                        serde_json::from_value::<PaymentSettledBody>(envelope.body.clone())
                    else {
                        continue;
                    };
                    if body.attempt_id == attempt_id {
                        ledger.attempt_settled_states.push(body.state);
                    }
                    open_reservations.remove(&body.attempt_id);
                }
                _ => {}
            }
        }

        for reservation in open_reservations.into_values() {
            if reservation.reserved_until <= now {
                ledger.expired_reservations.push(reservation);
            } else {
                *ledger
                    .reserved_by_statement
                    .entry(reservation.statement_sid.clone())
                    .or_default() += reservation.amount_cents;
            }
        }

        Ok(ledger)
    }

    pub(crate) fn payment_reserved_cents_by_statement(
        &self,
        grant_id: &str,
    ) -> Result<HashMap<String, u64>, StoreError> {
        Ok(self
            .collect_payment_receipt_ledger(grant_id, "")?
            .reserved_by_statement)
    }

    fn latest_reserved_payment_receipt(
        &self,
        grant_id: &str,
        attempt_id: &str,
    ) -> Result<PaymentEvaluatedBody, StoreError> {
        self.list_receipts_v2_envelopes(&[grant_id.to_string()])?
            .into_iter()
            .filter_map(|(_, kind, _, envelope)| {
                if kind != RECEIPT_KIND_PAYMENT_EVALUATED {
                    return None;
                }
                serde_json::from_value::<PaymentEvaluatedBody>(envelope.body)
                    .ok()
                    .filter(|body| {
                        body.attempt_id == attempt_id
                            && body.state == PaymentEvaluatedState::Reserved
                    })
            })
            .next_back()
            .ok_or_else(|| {
                StoreError::InvalidInput(format!(
                    "attempt_id '{attempt_id}' has no reserved payment receipt"
                ))
            })
    }

    pub async fn settle_payment_attempt_with_rail<R: RailAdapter>(
        &self,
        grant_id: &str,
        payment_attempt_id: &str,
        accepted: &RailAttemptAccepted,
        outcome: &RailOutcomeReport,
        rail: &R,
    ) -> Result<Option<String>, StoreError> {
        let grant = self.get_grant(grant_id)?;
        let ledger = self.collect_payment_receipt_ledger(grant_id, payment_attempt_id)?;
        if !ledger.attempt_settled_states.is_empty() {
            return Err(StoreError::InvalidInput(format!(
                "attempt_id '{payment_attempt_id}' is already settled"
            )));
        }
        let reserved = self.latest_reserved_payment_receipt(grant_id, payment_attempt_id)?;

        if matches!(outcome.state, RailSettlementState::Committed) {
            match accepted.trust_contract {
                RailTrustContract::SideChannelReconciliation => {
                    let accepted_key = accepted.idempotency_key.as_deref().ok_or_else(|| {
                        StoreError::InvalidInput(
                            "side_channel_reconciliation settlement missing accepted idempotency_key"
                                .to_string(),
                        )
                    })?;
                    if let Some(outcome_key) = outcome.idempotency_key.as_deref()
                        && outcome_key != accepted_key
                    {
                        return Err(StoreError::InvalidInput(format!(
                            "rail outcome idempotency_key '{outcome_key}' did not match accepted key '{accepted_key}'"
                        )));
                    }
                    let landed = rail
                        .verify_attempt_landed(accepted_key)
                        .await
                        .map_err(|e| {
                            StoreError::InvalidInput(format!("rail verification failed: {e}"))
                        })?;
                    if !landed {
                        return Err(StoreError::InvalidInput(format!(
                            "rail verification could not confirm committed outcome for attempt_id '{payment_attempt_id}'"
                        )));
                    }
                }
                RailTrustContract::EphemeralSign => {
                    if outcome.committed_claim.is_none() {
                        return Err(StoreError::InvalidInput(
                            "ephemeral_sign settlement missing committed_claim".to_string(),
                        ));
                    }
                }
            }

            self.increment_statement_usage(
                grant_id,
                &reserved.statement_sid,
                Usage {
                    cents: reserved.amount_cents,
                    cents_micro: reserved.amount_cents.saturating_mul(1_000_000),
                    ..Usage::default()
                },
            )?;
            let _ = self.mark_grant_exhausted_by_budget_if_terminal(grant_id)?;
        }

        let state = match outcome.state {
            RailSettlementState::Committed => PaymentSettledState::Committed,
            RailSettlementState::Voided => PaymentSettledState::Voided,
            RailSettlementState::Expired => PaymentSettledState::Expired,
        };
        let reason = match (accepted.trust_contract, outcome.state) {
            (RailTrustContract::SideChannelReconciliation, RailSettlementState::Committed) => {
                Some("verified_via_side_channel_reconciliation".to_string())
            }
            (_, RailSettlementState::Committed) => Some("rail_committed".to_string()),
            (_, RailSettlementState::Voided) => Some("rail_voided".to_string()),
            (_, RailSettlementState::Expired) => Some("rail_expired".to_string()),
        };
        Ok(emit_payment_settled_receipt_current(
            self,
            grant_id,
            &grant.persona_id,
            &PaymentSettledBody {
                state,
                attempt_id: payment_attempt_id.to_string(),
                statement_sid: reserved.statement_sid,
                vendor: reserved.vendor,
                final_amount_cents: Some(reserved.amount_cents),
                rail_reference: outcome.rail_reference.clone(),
                reason,
            },
        ))
    }

    fn sweep_expired_payment_reservations(
        &self,
        grant_id: &str,
        persona_id: &str,
        ledger: &PaymentReceiptLedger,
    ) {
        for reservation in &ledger.expired_reservations {
            let _ = emit_payment_settled_receipt_current(
                self,
                grant_id,
                persona_id,
                &PaymentSettledBody {
                    state: PaymentSettledState::Expired,
                    attempt_id: reservation.attempt_id.clone(),
                    statement_sid: reservation.statement_sid.clone(),
                    vendor: reservation.vendor.clone(),
                    final_amount_cents: Some(reservation.amount_cents),
                    rail_reference: None,
                    reason: Some("reservation_ttl_expired".to_string()),
                },
            );
        }
    }

    fn payment_statement_gate(
        &self,
        stmt: &Statement,
        attempt: &PaymentAttempt,
        params: &serde_json::Value,
        reserved_cents: u64,
    ) -> PaymentStatementGate {
        let mut threshold: Option<(String, String)> = None;

        for (idx, condition) in stmt.conditions.iter().enumerate() {
            match condition {
                Condition::MerchantAllowlist { merchants } => {
                    if !merchants.iter().any(|merchant| merchant == &attempt.vendor) {
                        return PaymentStatementGate::Deny {
                            reason: format!("vendor '{}' not allowlisted", attempt.vendor),
                            condition_path: Some(format!("conditions[{idx}].merchant_allowlist")),
                        };
                    }
                }
                Condition::TimeWindow {
                    start_secs_of_day,
                    end_secs_of_day,
                } => {
                    let now = Utc::now().num_seconds_from_midnight();
                    let in_window = if start_secs_of_day <= end_secs_of_day {
                        now >= *start_secs_of_day && now < *end_secs_of_day
                    } else {
                        now >= *start_secs_of_day || now < *end_secs_of_day
                    };
                    if !in_window {
                        return PaymentStatementGate::Deny {
                            reason: "attempt is outside the allowed time window".to_string(),
                            condition_path: Some(format!("conditions[{idx}].time_window")),
                        };
                    }
                }
                Condition::Range { field, min, max } => {
                    let Some(value) = json_field_as_i64(params, field) else {
                        continue;
                    };
                    if field == "amount_cents" {
                        if let Some(minimum) = min
                            && value < *minimum
                        {
                            return PaymentStatementGate::Deny {
                                reason: format!(
                                    "amount {} is below the minimum allowed amount {}",
                                    value, minimum
                                ),
                                condition_path: Some(format!("conditions[{idx}].range({field})")),
                            };
                        }
                        if let Some(maximum) = max
                            && value > *maximum
                        {
                            threshold = Some((
                                format!("conditions[{idx}].range({field})"),
                                format!("amount {} exceeds approval threshold {}", value, maximum),
                            ));
                        }
                    } else if min.is_some_and(|minimum| value < minimum)
                        || max.is_some_and(|maximum| value > maximum)
                    {
                        return PaymentStatementGate::Deny {
                            reason: format!("field '{field}' is outside the allowed range"),
                            condition_path: Some(format!("conditions[{idx}].range({field})")),
                        };
                    }
                }
                Condition::OneOf { field, values } => {
                    let Some(value) = json_field_as_str(params, field) else {
                        continue;
                    };
                    if !values.iter().any(|candidate| candidate == value) {
                        return PaymentStatementGate::Deny {
                            reason: format!("field '{field}' is not in the allowlist"),
                            condition_path: Some(format!("conditions[{idx}].one_of({field})")),
                        };
                    }
                }
                Condition::NotOneOf { field, values } => {
                    let Some(value) = json_field_as_str(params, field) else {
                        continue;
                    };
                    if values.iter().any(|candidate| candidate == value) {
                        return PaymentStatementGate::Deny {
                            reason: format!("field '{field}' is explicitly denied"),
                            condition_path: Some(format!("conditions[{idx}].not_one_of({field})")),
                        };
                    }
                }
                _ => {}
            }
        }

        if let Some((condition_path, reason)) = threshold {
            return PaymentStatementGate::RequireApproval {
                reason,
                condition_path: Some(condition_path),
            };
        }

        if let Some(cap_cents) = stmt.budget.as_ref().and_then(|budget| budget.cents) {
            let cap_micro = cap_cents.saturating_mul(1_000_000);
            let used_micro = if stmt.usage.cents_micro > 0 {
                stmt.usage.cents_micro
            } else {
                stmt.usage.cents.saturating_mul(1_000_000)
            };
            let reserved_micro = reserved_cents.saturating_mul(1_000_000);
            let requested_micro = attempt.amount_cents.saturating_mul(1_000_000);
            let unavailable_micro = used_micro.saturating_add(reserved_micro);
            let remaining_micro = cap_micro.saturating_sub(unavailable_micro);
            if requested_micro > remaining_micro {
                return PaymentStatementGate::Deny {
                    reason: format!(
                        "amount {} exceeds effective remaining capacity {}",
                        attempt.amount_cents,
                        remaining_micro / 1_000_000
                    ),
                    condition_path: None,
                };
            }
        }

        PaymentStatementGate::Allow
    }

    pub(crate) fn evaluate_payment_tool_call(
        &self,
        grant: &GrantInfo,
        tool_name: &str,
        params: &serde_json::Value,
        attempt: PaymentAttempt,
    ) -> Result<EvaluatedToolCall, StoreError> {
        let initial_ledger = self.collect_payment_receipt_ledger(&grant.id, &attempt.attempt_id)?;
        if !initial_ledger.expired_reservations.is_empty() {
            self.sweep_expired_payment_reservations(&grant.id, &grant.persona_id, &initial_ledger);
        }
        let ledger = self.collect_payment_receipt_ledger(&grant.id, &attempt.attempt_id)?;
        if !ledger.attempt_settled_states.is_empty()
            || ledger.attempt_evaluated_states.iter().any(|state| {
                matches!(
                    state,
                    PaymentEvaluatedState::Allowed | PaymentEvaluatedState::Reserved
                )
            })
        {
            let decision = ToolCallDecision {
                permit: false,
                reason: Some(format!(
                    "attempt_id '{}' was already authorized or settled",
                    attempt.attempt_id
                )),
                grant_id: Some(grant.id.clone()),
                emitted_event_id: String::new(),
                await_approval_request_id: None,
            };
            return Ok(EvaluatedToolCall {
                audit_outcome: "denied".to_string(),
                audit_details: serde_json::json!({
                    "grant_id": grant.id.clone(),
                    "payment": {
                        "attempt_id": attempt.attempt_id,
                        "vendor": attempt.vendor,
                        "amount_cents": attempt.amount_cents,
                        "state": "denied",
                        "reason": decision.reason.clone(),
                    }
                }),
                decision,
            });
        }

        let access_grant = self.get_access_grant(&grant.id)?;
        let mut first_deny: Option<(String, Option<String>)> = None;
        let mut approval_candidate: Option<(String, Option<String>, String)> = None;

        for (_, stmt) in access_grant.statements() {
            if stmt.resource_type != core_grant_types::ResourceType::Payment {
                continue;
            }
            let action_ok = stmt
                .actions
                .iter()
                .any(|action| action == tool_name || action == "*");
            if !action_ok || !stmt.resource.covers(&attempt.vendor) {
                continue;
            }
            let reserved_cents = ledger
                .reserved_by_statement
                .get(stmt.sid.as_str())
                .copied()
                .unwrap_or(0);
            match self.payment_statement_gate(stmt, &attempt, params, reserved_cents) {
                PaymentStatementGate::Allow => {
                    let state = if attempt.shadow {
                        PaymentEvaluatedState::Allowed
                    } else {
                        PaymentEvaluatedState::Reserved
                    };
                    let reserved_until = (!attempt.shadow).then(|| {
                        (Utc::now() + Duration::seconds(PAYMENT_RESERVATION_TTL_SECS)).to_rfc3339()
                    });
                    let receipt_body = PaymentEvaluatedBody {
                        state,
                        attempt_id: attempt.attempt_id.clone(),
                        statement_sid: stmt.sid.clone(),
                        amount_cents: attempt.amount_cents,
                        vendor: attempt.vendor.clone(),
                        condition_path: None,
                        approval_request_id: None,
                        reserved_until: reserved_until.clone(),
                        reason: None,
                    };
                    let receipt_id = emit_payment_evaluated_receipt_current(
                        self,
                        &grant.id,
                        &grant.persona_id,
                        &receipt_body,
                    );
                    let decision = ToolCallDecision {
                        permit: true,
                        reason: None,
                        grant_id: Some(grant.id.clone()),
                        emitted_event_id: String::new(),
                        await_approval_request_id: None,
                    };
                    return Ok(EvaluatedToolCall {
                        audit_outcome: match state {
                            PaymentEvaluatedState::Allowed => "allowed".to_string(),
                            PaymentEvaluatedState::Reserved => "reserved".to_string(),
                            _ => "allowed".to_string(),
                        },
                        audit_details: serde_json::json!({
                            "grant_id": grant.id.clone(),
                            "payment": {
                                "attempt_id": attempt.attempt_id,
                                "vendor": attempt.vendor,
                                "amount_cents": attempt.amount_cents,
                                "state": if attempt.shadow { "allowed" } else { "reserved" },
                                "statement_sid": stmt.sid.clone(),
                                "receipt_id": receipt_id,
                                "reserved_until": reserved_until,
                            }
                        }),
                        decision,
                    });
                }
                PaymentStatementGate::RequireApproval {
                    reason,
                    condition_path,
                } => {
                    approval_candidate = Some((stmt.sid.clone(), condition_path, reason));
                }
                PaymentStatementGate::Deny {
                    reason,
                    condition_path,
                } => {
                    if first_deny.is_none() {
                        first_deny = Some((reason, condition_path));
                    }
                }
            }
        }

        if let Some((statement_sid, condition_path, threshold_reason)) = approval_candidate {
            let approval = self.latest_payment_decision_only_approval(
                &grant.persona_id,
                tool_name,
                &attempt.attempt_id,
            )?;
            match approval {
                Some(info) if info.status == "approved" => {
                    let state = if attempt.shadow {
                        PaymentEvaluatedState::Allowed
                    } else {
                        PaymentEvaluatedState::Reserved
                    };
                    let reserved_until = (!attempt.shadow).then(|| {
                        (Utc::now() + Duration::seconds(PAYMENT_RESERVATION_TTL_SECS)).to_rfc3339()
                    });
                    let receipt_body = PaymentEvaluatedBody {
                        state,
                        attempt_id: attempt.attempt_id.clone(),
                        statement_sid,
                        amount_cents: attempt.amount_cents,
                        vendor: attempt.vendor.clone(),
                        condition_path: condition_path.clone(),
                        approval_request_id: Some(info.id.clone()),
                        reserved_until: reserved_until.clone(),
                        reason: Some("approval_granted".to_string()),
                    };
                    let receipt_id = emit_payment_evaluated_receipt_current(
                        self,
                        &grant.id,
                        &grant.persona_id,
                        &receipt_body,
                    );
                    let decision = ToolCallDecision {
                        permit: true,
                        reason: None,
                        grant_id: Some(grant.id.clone()),
                        emitted_event_id: String::new(),
                        await_approval_request_id: None,
                    };
                    return Ok(EvaluatedToolCall {
                        audit_outcome: match state {
                            PaymentEvaluatedState::Allowed => "allowed".to_string(),
                            PaymentEvaluatedState::Reserved => "reserved".to_string(),
                            _ => "allowed".to_string(),
                        },
                        audit_details: serde_json::json!({
                            "grant_id": grant.id.clone(),
                            "payment": {
                                "attempt_id": attempt.attempt_id,
                                "vendor": attempt.vendor,
                                "amount_cents": attempt.amount_cents,
                                "state": if attempt.shadow { "allowed" } else { "reserved" },
                                "statement_sid": receipt_body.statement_sid.clone(),
                                "receipt_id": receipt_id,
                                "approval_request_id": info.id,
                                "reserved_until": reserved_until,
                            }
                        }),
                        decision,
                    });
                }
                Some(info) if info.status == "pending" => {
                    let receipt_body = PaymentEvaluatedBody {
                        state: PaymentEvaluatedState::EscalationRequired,
                        attempt_id: attempt.attempt_id.clone(),
                        statement_sid,
                        amount_cents: attempt.amount_cents,
                        vendor: attempt.vendor.clone(),
                        condition_path: condition_path.clone(),
                        approval_request_id: Some(info.id.clone()),
                        reserved_until: None,
                        reason: Some(threshold_reason.clone()),
                    };
                    let receipt_id = emit_payment_evaluated_receipt_current(
                        self,
                        &grant.id,
                        &grant.persona_id,
                        &receipt_body,
                    );
                    let decision = ToolCallDecision {
                        permit: false,
                        reason: Some(threshold_reason),
                        grant_id: Some(grant.id.clone()),
                        emitted_event_id: String::new(),
                        await_approval_request_id: Some(info.id.clone()),
                    };
                    return Ok(EvaluatedToolCall {
                        audit_outcome: "escalation_required".to_string(),
                        audit_details: serde_json::json!({
                            "grant_id": grant.id.clone(),
                            "payment": {
                                "attempt_id": attempt.attempt_id,
                                "vendor": attempt.vendor,
                                "amount_cents": attempt.amount_cents,
                                "state": "escalation_required",
                                "statement_sid": receipt_body.statement_sid.clone(),
                                "receipt_id": receipt_id,
                                "approval_request_id": info.id,
                            }
                        }),
                        decision,
                    });
                }
                Some(info) => {
                    let reason = info
                        .reason
                        .unwrap_or_else(|| format!("approval_{}", info.status));
                    let receipt_body = PaymentEvaluatedBody {
                        state: PaymentEvaluatedState::Denied,
                        attempt_id: attempt.attempt_id.clone(),
                        statement_sid,
                        amount_cents: attempt.amount_cents,
                        vendor: attempt.vendor.clone(),
                        condition_path: condition_path.clone(),
                        approval_request_id: Some(info.id.clone()),
                        reserved_until: None,
                        reason: Some(reason.clone()),
                    };
                    let receipt_id = emit_payment_evaluated_receipt_current(
                        self,
                        &grant.id,
                        &grant.persona_id,
                        &receipt_body,
                    );
                    let decision = ToolCallDecision {
                        permit: false,
                        reason: Some(reason.clone()),
                        grant_id: Some(grant.id.clone()),
                        emitted_event_id: String::new(),
                        await_approval_request_id: None,
                    };
                    return Ok(EvaluatedToolCall {
                        audit_outcome: "denied".to_string(),
                        audit_details: serde_json::json!({
                            "grant_id": grant.id.clone(),
                            "payment": {
                                "attempt_id": attempt.attempt_id,
                                "vendor": attempt.vendor,
                                "amount_cents": attempt.amount_cents,
                                "state": "denied",
                                "statement_sid": receipt_body.statement_sid.clone(),
                                "receipt_id": receipt_id,
                                "approval_request_id": info.id,
                                "reason": reason,
                            }
                        }),
                        decision,
                    });
                }
                None => {
                    let approval = self.submit_decision_only_approval(
                        &grant.persona_id,
                        &attempt.vendor,
                        &Self::payment_attempt_scope(&attempt.attempt_id),
                        tool_name,
                        "high",
                        Some(tool_name.to_string()),
                        Some(attempt.vendor.clone()),
                        None,
                        Some("payment".to_string()),
                    )?;
                    let receipt_body = PaymentEvaluatedBody {
                        state: PaymentEvaluatedState::EscalationRequired,
                        attempt_id: attempt.attempt_id.clone(),
                        statement_sid,
                        amount_cents: attempt.amount_cents,
                        vendor: attempt.vendor.clone(),
                        condition_path: condition_path.clone(),
                        approval_request_id: Some(approval.id.clone()),
                        reserved_until: None,
                        reason: Some(threshold_reason.clone()),
                    };
                    let receipt_id = emit_payment_evaluated_receipt_current(
                        self,
                        &grant.id,
                        &grant.persona_id,
                        &receipt_body,
                    );
                    let decision = ToolCallDecision {
                        permit: false,
                        reason: Some(threshold_reason),
                        grant_id: Some(grant.id.clone()),
                        emitted_event_id: String::new(),
                        await_approval_request_id: Some(approval.id.clone()),
                    };
                    return Ok(EvaluatedToolCall {
                        audit_outcome: "escalation_required".to_string(),
                        audit_details: serde_json::json!({
                            "grant_id": grant.id.clone(),
                            "payment": {
                                "attempt_id": attempt.attempt_id,
                                "vendor": attempt.vendor,
                                "amount_cents": attempt.amount_cents,
                                "state": "escalation_required",
                                "statement_sid": receipt_body.statement_sid.clone(),
                                "receipt_id": receipt_id,
                                "approval_request_id": approval.id,
                            }
                        }),
                        decision,
                    });
                }
            }
        }

        let (reason, condition_path) = first_deny.unwrap_or_else(|| {
            (
                "no applicable payment statement matched the attempt".to_string(),
                None,
            )
        });
        let receipt_body = PaymentEvaluatedBody {
            state: PaymentEvaluatedState::Denied,
            attempt_id: attempt.attempt_id.clone(),
            statement_sid: "unmatched".to_string(),
            amount_cents: attempt.amount_cents,
            vendor: attempt.vendor.clone(),
            condition_path: condition_path.clone(),
            approval_request_id: None,
            reserved_until: None,
            reason: Some(reason.clone()),
        };
        let receipt_id = emit_payment_evaluated_receipt_current(
            self,
            &grant.id,
            &grant.persona_id,
            &receipt_body,
        );
        let decision = ToolCallDecision {
            permit: false,
            reason: Some(reason.clone()),
            grant_id: Some(grant.id.clone()),
            emitted_event_id: String::new(),
            await_approval_request_id: None,
        };
        Ok(EvaluatedToolCall {
            audit_outcome: "denied".to_string(),
            audit_details: serde_json::json!({
                "grant_id": grant.id.clone(),
                "payment": {
                    "attempt_id": attempt.attempt_id,
                    "vendor": attempt.vendor,
                    "amount_cents": attempt.amount_cents,
                    "state": "denied",
                    "receipt_id": receipt_id,
                    "reason": reason,
                    "condition_path": condition_path,
                }
            }),
            decision,
        })
    }
}

// ---------------------------------------------------------------------------
// ADR 205 §A.3 / §A.4 — store-backed use-time verification seams (BKR-4b-4)
// ---------------------------------------------------------------------------
//
// The composition lives in `crate::trust::use_time_verify`
// (`verify_grant_for_use`); it is deliberately store-agnostic and
// unit-testable. These are the production `DaemonStore`-backed implementations
// of its two seams plus the boundary-agnostic walk helper both use-time
// boundaries (proxy `resolve_grant` + construct mint) invoke.

/// Hard ceiling on the §A.4 ancestry walk — defence against a corrupt
/// `parent_grant_id` graph. A real delegation chain is ~3–4 hops
/// (apex→durable→runtime→sub-agent); the `seen` cycle-guard is the primary
/// protection, this bounds a pathological acyclic chain.
const MAX_ANCESTRY_WALK: usize = 256;

impl crate::trust::use_time_verify::PersonaRootAuthority for DaemonStore {
    fn authorized_root_pubkey(&self, persona_id: &str) -> Option<[u8; 32]> {
        // TRANSITIONAL (ADR 205 §A.5 / §9 — the honest dev0 limit). Verifier #1
        // should resolve the persona's root key *iff it is authorized by the
        // apex presence-rooted device-set* (ADR 200 Model-C). That device-set
        // anchoring is ADR 206's to build (MUS slice 4); until it lands this
        // returns the persona's daemon-STORED root key, which is
        // daemon-FORGEABLE — the accepted dev0 limit, not a new hole. When the
        // persona key is vouched into the device-set, this body swaps to
        // `is_active_persona_key_under_root` over that set; the trait boundary
        // and every caller are unchanged. A missing / undecodable persona row
        // yields `None`, failing the composition closed.
        self.get_persona_root_pubkey_bytes(persona_id)
    }
}

impl crate::trust::use_time_verify::GrantAncestry for DaemonStore {
    fn ancestor_ids(&self, grant_id: &str) -> Vec<String> {
        // Walk the `parent_grant_id` column UP, nearest-parent first — the
        // mirror of `cascade_revoke_children` (which walks it DOWN). The `seen`
        // set breaks any cycle a corrupt graph might contain; `MAX_ANCESTRY_WALK`
        // bounds a pathological acyclic chain.
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        seen.insert(grant_id.to_string());
        let mut current = grant_id.to_string();
        while out.len() < MAX_ANCESTRY_WALK {
            let parent: Option<String> = self
                .conn()
                .query_row(
                    "SELECT parent_grant_id FROM grants WHERE id = ?1",
                    rusqlite::params![current],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .ok()
                .flatten()
                .flatten();
            match parent {
                Some(p) if !p.is_empty() && seen.insert(p.clone()) => {
                    out.push(p.clone());
                    current = p;
                }
                _ => break,
            }
        }
        out
    }

    fn status_of(&self, ids: &[String]) -> Vec<AccessGrant> {
        ids.iter()
            .filter_map(|id| {
                // `get_grant` returns the EFFECTIVE status (time-derived expiry
                // folded in via `GrantStatus::derive`) cheaply, without the
                // chain-verify that `get_access_grant` would run on an ancestor
                // we only need a status for. An unparseable status string fails
                // CLOSED: we omit the record so `first_revoked_ancestor` treats
                // the ancestor as `Absent` (blocking).
                let info = self.get_grant(id).ok()?;
                let status = GrantStatus::parse(&info.status)?;
                // The daemon encodes revocation as `status = Revoked` with no
                // separate `revoked_at` column; synthesize a checkpoint so the
                // walk reports `AncestorRevocation::Revoked` (vs the generic
                // `NonActive`) for a revoked ancestor. Both block; this is
                // purely a more faithful reason for the audit line.
                let revoked_at = (status == GrantStatus::Revoked).then_some(0u64);
                Some(bare_status_grant(&info.id, status, revoked_at))
            })
            .collect()
    }
}

/// Minimal status-bearing [`AccessGrant`] for the §A.4 ancestry walk.
/// [`core_grants::first_revoked_ancestor`] reads only `id`, `status`, and
/// `revoked_at`; the remaining fields are inert placeholders.
fn bare_status_grant(id: &str, status: GrantStatus, revoked_at: Option<u64>) -> AccessGrant {
    AccessGrant {
        id: id.to_string(),
        version: 1,
        issuing_persona_id: String::new(),
        recipient_kind: PresentationAudienceKind::Service,
        recipient_id: String::new(),
        recipient_profile: RecipientProfile::Agent,
        status,
        mode: GrantMode::OneShot,
        blocks: Vec::new(),
        attestation: AttestationBinding::default(),
        created_at: 0,
        updated_at: 0,
        revoked_at,
        revoked_reason: None,
        last_used_at: None,
        label: None,
    }
}

/// One row of the ADR 205 §A.2 **derived chain-edges projection**. The
/// canonical authority artifact is the embedded `SignedBlock` chain
/// (`blocks_json`); this is the normalized, analytics/visualization-friendly
/// view *derived* from it — never the source of truth. Regenerable at any time
/// from the embedded grants, so it carries no independent trust (exactly like
/// the ADR 187 §10 claim-journal/rollup derived from receipts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEdge {
    pub grant_id: String,
    pub parent_grant_id: Option<String>,
    pub persona_id: String,
    /// Distance to the apex = length of the `parent_grant_id` ancestry walk.
    /// 0 for an apex (root) grant.
    pub depth: usize,
    /// Compact summary of the embedded chain's leaf-block authority — the
    /// distinct action strings (`provider:object:verb`) the grant carries.
    /// Derived from the signed chain; falls back to the flat scope projection
    /// when the chain is unreadable (fail-soft: a projection row is observability,
    /// not an authority decision).
    pub statement_summary: String,
    /// Effective grant status (`GrantStatus::derive` folds in time-expiry).
    pub status: String,
}

impl DaemonStore {
    /// ADR 205 §A.2 ancestry metadata — the ordered `parent_grant_id` lineage
    /// of `grant_id`, nearest-parent first, apex last. Empty for an apex grant.
    /// Derived from the recorded `parent_grant_id` edges (the canonical ancestry
    /// key), so it never diverges from the embedded chain. Public inherent
    /// accessor over the [`GrantAncestry`](crate::trust::use_time_verify::GrantAncestry)
    /// walk the §A.4 revocation check already uses.
    pub fn ancestor_grant_ids(&self, grant_id: &str) -> Vec<String> {
        <Self as crate::trust::use_time_verify::GrantAncestry>::ancestor_ids(self, grant_id)
    }

    /// Materialize the ADR 205 §A.2 chain-edges projection over every grant in
    /// the store. Derived end-to-end from the canonical embed (the
    /// `parent_grant_id` ancestry + each grant's signed statements), so it is
    /// regenerable and carries no independent trust. Analytics / observability /
    /// forest-visualization run on this, never by parsing signed blobs at the
    /// call site.
    pub fn grant_chain_edges(&self) -> Result<Vec<ChainEdge>, StoreError> {
        let ids: Vec<String> = {
            let mut stmt = self
                .conn()
                .prepare("SELECT id FROM grants ORDER BY created_at")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut edges = Vec::with_capacity(ids.len());
        for id in ids {
            let info = match self.get_grant(&id) {
                Ok(info) => info,
                Err(_) => continue,
            };
            // Statement summary from the signed chain; fall back to the flat
            // scope projection when the chain cannot be read (fail-soft).
            let statement_summary = match self.get_access_grant(&id) {
                Ok(chain) => {
                    let mut actions: Vec<String> = chain
                        .statements()
                        .flat_map(|(_, stmt)| stmt.actions.iter().cloned())
                        .collect();
                    actions.sort();
                    actions.dedup();
                    if actions.is_empty() {
                        info.scope.clone()
                    } else {
                        actions.join(",")
                    }
                }
                Err(_) => info.scope.clone(),
            };
            edges.push(ChainEdge {
                grant_id: id.clone(),
                parent_grant_id: info.parent_grant_id.clone(),
                persona_id: info.persona_id.clone(),
                depth: self.ancestor_grant_ids(&id).len(),
                statement_summary,
                status: info.status.clone(),
            });
        }
        Ok(edges)
    }

    /// ADR 205 §A.4 online revocation walk — store-backed and
    /// **boundary-agnostic**. Resolves `grant_id`'s `parent_grant_id` ancestry
    /// and returns the first ancestor that blocks use (revoked / non-active /
    /// absent), or `None` when every ancestor is live (and for an apex grant
    /// with no ancestry). Both use-time boundaries call this so the
    /// parent-revocation cascade is enforced identically: the proxy
    /// (`infra::proxy::resolve_grant`) and the construct mint
    /// (`trust::use_time_verify::verify_grant_for_use`).
    ///
    /// COMPLEMENTARY to the eager write-side `cascade_revoke_children`
    /// (ADR 076 D2): that walks DOWN at revoke time; this walks UP at use time
    /// and catches what a crashed / raced cascade — or a presented embed-chain
    /// the daemon's column never cascaded — would miss. It is intentionally
    /// orthogonal to per-statement-SID revocation (`get_revoked_sids`): a grant
    /// can be revoked at any ancestry depth without touching its statements, so
    /// both checks stack at a boundary.
    pub(crate) fn first_revoked_grant_ancestor(
        &self,
        grant_id: &str,
    ) -> Option<core_grants::RevokedAncestor> {
        use crate::trust::use_time_verify::GrantAncestry;
        let ancestor_ids = self.ancestor_ids(grant_id);
        if ancestor_ids.is_empty() {
            return None;
        }
        let status = self.status_of(&ancestor_ids);
        core_grants::first_revoked_ancestor(&ancestor_ids, &status)
    }
}

const PAYMENT_RESERVATION_TTL_SECS: i64 = 60;

#[derive(Debug, Clone)]
pub(crate) struct PaymentAttempt {
    attempt_id: String,
    vendor: String,
    amount_cents: u64,
    shadow: bool,
}

#[derive(Debug, Clone)]
struct PaymentReservation {
    attempt_id: String,
    statement_sid: String,
    vendor: String,
    amount_cents: u64,
    reserved_until: DateTime<Utc>,
}

#[derive(Debug, Default)]
struct PaymentReceiptLedger {
    reserved_by_statement: HashMap<String, u64>,
    expired_reservations: Vec<PaymentReservation>,
    attempt_evaluated_states: Vec<PaymentEvaluatedState>,
    attempt_settled_states: Vec<PaymentSettledState>,
}

#[derive(Debug)]
pub(crate) struct EvaluatedToolCall {
    decision: ToolCallDecision,
    audit_outcome: String,
    audit_details: serde_json::Value,
}

enum PaymentStatementGate {
    Allow,
    RequireApproval {
        reason: String,
        condition_path: Option<String>,
    },
    Deny {
        reason: String,
        condition_path: Option<String>,
    },
}

fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc))
}

fn json_field_as_i64(params: &serde_json::Value, field: &str) -> Option<i64> {
    params.get(field)?.as_i64()
}

fn json_field_as_str<'a>(params: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    params.get(field)?.as_str()
}

/// ADR191_PAYMENT_BUILD_AHEAD: decision returned by the payment reserve lane
/// ([`DaemonStore::reserve_payment_tool_call`] →
/// [`DaemonStore::evaluate_payment_tool_call`]).
///
/// `permit` is the allow/deny verdict, `reason` carries the deny/escalation
/// rationale, and `grant_id` + `emitted_event_id` correlate the decision back
/// to the resolved grant + audit row. `await_approval_request_id` is set when
/// an over-threshold payment escalates to a decision-only approval.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ToolCallDecision {
    pub permit: bool,
    pub reason: Option<String>,
    pub grant_id: Option<String>,
    pub emitted_event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub await_approval_request_id: Option<String>,
}

pub struct GrantSummary {
    pub active: u64,
    pub expired: u64,
    pub revoked: u64,
}

/// Before/after usage snapshot returned by
/// [`DaemonStore::increment_statement_usage`]. Callers use `prior` and
/// `current` together to detect threshold crossings (80% / 95%) without a
/// second read.
#[derive(Debug, Clone)]
pub struct StatementUsageDelta {
    pub prior: Usage,
    pub current: Usage,
}

#[cfg(test)]
mod tests;
