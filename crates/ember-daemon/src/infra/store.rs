use std::cell::RefCell;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::Connection;

use crate::infra::vault::Vault;

/// Shared live-vault attachment used by the daemon runtime.
///
/// Multiple `DaemonStore` instances can point at the same slot so an explicit
/// lock clears the live vault for the socket, proxy, dashboard, and helper
/// lanes in one place instead of dropping only the store that happened to be
/// registered with the presence gate.
#[derive(Clone, Default)]
pub struct LiveVaultSlot(Rc<RefCell<Option<Rc<Vault>>>>);

impl LiveVaultSlot {
    pub fn set(&self, vault: Rc<Vault>) {
        *self.0.borrow_mut() = Some(vault);
    }

    pub fn get(&self) -> Option<Rc<Vault>> {
        self.0.borrow().clone()
    }

    pub fn clear(&self) {
        *self.0.borrow_mut() = None;
    }
}

/// Shared lease-KEK slot — mirrors [`LiveVaultSlot`] for the symmetric
/// lease-wrapping key (ADR 216 F1). All `DaemonStore` clones that share
/// the same slot see writes immediately (proxy stores, session stores).
///
/// ADR216-F4: the inner Option wraps the key in an `Rc<LeaseWrapKey>` so
/// `get()` is a cheap ref-count bump rather than a full key clone. Prior
/// to F4 the slot held a bare `LeaseWrapKey` whose `Clone` impl staged
/// the 32 raw key bytes in a `[u8; 32]` stack local on every access —
/// that staging copy was never wiped, leaving recoverable unzeroized
/// KEK copies on the stack of every `lease_kek()`-touching path. The
/// `Rc` handle removes the copy entirely: all consumers share one
/// mlocked allocation.
#[derive(Clone, Default)]
pub struct SharedLeaseKek(Rc<RefCell<Option<Rc<crate::trust::lease::LeaseWrapKey>>>>);

impl SharedLeaseKek {
    pub fn set(&self, key: Rc<crate::trust::lease::LeaseWrapKey>) {
        *self.0.borrow_mut() = Some(key);
    }

    /// Cheap ref-count bump — never copies the 32 raw key bytes (ADR216-F4).
    pub fn get(&self) -> Option<Rc<crate::trust::lease::LeaseWrapKey>> {
        self.0.borrow().clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("not found")]
    NotFound,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Attenuation failure in `delegate_grant` — child grant expands
    /// authority along some axis. `reason` names only the violating
    /// dimension so the error isn't an oracle for parent state.
    #[error("delegation violation: {reason}")]
    DelegationViolation { reason: String },
    /// Vault encrypt/decrypt failure — wraps the underlying
    /// `VaultError::Crypto` message without leaking key material.
    /// Emitted by persona-secret paths when the attached `Vault`
    /// cannot seal or open the stored ciphertext (e.g. wrong master
    /// key, corrupted nonce, Argon2id mismatch).
    #[error("vault error: {0}")]
    Vault(String),
    /// The approval request has already been resolved (approved, denied, etc.)
    /// and cannot be resolved again. Returned by `resolve_approval` when a
    /// concurrent caller already committed the status transition.
    #[error("approval already resolved")]
    AlreadyResolved,
    /// SHA-256 of `composite_statements_json` does not match the hash stored
    /// at submit time. Indicates the statement list was mutated in the DB
    /// between submit and approve — the grant is NOT minted.
    #[error("composite statements integrity violation: stored hash does not match")]
    CompositeStatementsTampered,
    /// Caller does not own the requested resource.
    #[error("unauthorized")]
    Unauthorized,
    /// daemon_persona_key_mode_refuse_world_readable — the identity key file
    /// has permissions that allow group or world read/write access.
    /// The daemon refuses to load it to prevent signing-key disclosure.
    /// Operator must `chmod 0600` the file after investigating why it is wider.
    #[error(
        "identity key at {path} has insecure mode {mode:#06o} (expected 0600 — chmod 0600 to fix)"
    )]
    KeyInsecureMode { path: String, mode: u32 },
    /// `quarantine_serve_mode_audit_writes_refused` — the daemon is in
    /// quarantine (audit-chain tamper detected at startup or mid-serve)
    /// and the audit-log writers refuse to record this event. Returned
    /// by `log_event`, `append_audit_event_with_chain`, and
    /// `append_audit_event_with_chain_in_tx`. Closes the chain-write
    /// entry points so the dispatcher quarantine gate's invariant holds
    /// across ALL audit writers (dashboard, proxy, session_watcher,
    /// startup runtime) — not just the JSON-RPC dispatch path. The
    /// `action` field names the suppressed event so the operator log
    /// can identify which writer was refused. Per ADR 174 v2 §1 +
    /// adversarial review CRIT-1/CRIT-2.
    #[error("daemon quarantined; audit-log write for action `{action}` refused")]
    Quarantined { action: String },
}

impl From<core_grants::scope::DelegationViolation> for StoreError {
    fn from(v: core_grants::scope::DelegationViolation) -> Self {
        StoreError::DelegationViolation { reason: v.reason }
    }
}

pub struct DaemonStore {
    conn: Connection,
    /// Optional handle to the daemon `Vault` used to seal/open persona
    /// root-key material at rest (F-05 / security review cycle 28 W6).
    ///
    /// Wired in by `runtime.rs` after the vault is unlocked but before the
    /// socket listener starts. Absent for in-memory test stores built via
    /// `open_in_memory()` — tests that need persona signing attach a vault
    /// via `set_vault` before exercising grant creation.
    ///
    /// Interior mutability is required because production callers pre-wrap
    /// `DaemonStore` in `Rc` before the vault exists (see `runtime.rs` —
    /// store opens first, then vault), so we cannot thread a mutable
    /// reference through that chain. The `RefCell` is only touched on
    /// the single-threaded LocalSet, so runtime borrow panics cannot race.
    vault_slot: RefCell<LiveVaultSlot>,
    /// In-memory rate-limit set for the
    /// `sops_unwrap_dek` RPC. Each grant_id is consumed exactly once per
    /// daemon-process lifetime. The set is intentionally non-persistent —
    /// daemon restart clears it (acceptable: a restart-then-replay attack
    /// requires the operator to also resurrect a still-active grant on the
    /// SAME id, which is not a realistic threat in v0).
    ///
    /// Single-threaded LocalSet semantics: same as `vault`. No cross-thread
    /// races possible.
    consumed_dek_grants: RefCell<HashSet<String>>,
    /// Cached
    /// copy of the daemon's Bridge CA fingerprint (blake3-256 of the SPKI
    /// bytes). Wired in by `runtime.rs` after `load_or_mint_bridge_ca`
    /// succeeds but before the socket listener starts. Read by the
    /// `spawn.witness` emission path in `trust::grant` to embed the
    /// fingerprint in every parent→child receipt. `None` for in-memory
    /// test stores that never wired a Bridge CA — `emit_spawn_witness_receipt`
    /// is called with `[0u8; 32]` in that case (Slice D treats the zero
    /// checkpoint as "fingerprint not asserted"). Interior mutability for
    /// the same reason as `vault` (store constructed before runtime opens
    /// the CA).
    bridge_ca_fingerprint: RefCell<Option<[u8; 32]>>,
    /// ADR 211 §1 / Phase 4 — the leased-authority registry: per-grant,
    /// TTL-bounded authority-to-act keys the daemon holds only for a grant's life
    /// (minted at issuance, dropped on revoke/expiry). This in-memory map is now a
    /// **hot cache**; each lease key is also SE-wrapped under the daemon's headless
    /// lease-KEK and persisted in `lease_blobs`, so a lease **survives a daemon
    /// restart** (AC-6) yet is non-exfiltratable. Reached through
    /// [`DaemonStore::leases`] (a [`crate::trust::lease::BoundLeaseRegistry`])
    /// which drives the persist / delete / rehydrate. Single `LocalSet` thread, so
    /// its interior `RefCell` cannot race.
    leases: crate::trust::lease::LeaseRegistry,
    /// ADR 216 S3 / F1 — the daemon's symmetric lease-wrapping key, installed
    /// after the double-envelope unlock. `None` until unlocked — in that state
    /// the lease registry runs **in-memory only** (no persistence). Shared via
    /// [`SharedLeaseKek`] so proxy stores see the key immediately when the main
    /// store receives it (mirrors [`LiveVaultSlot`] for the vault MEK).
    lease_kek: RefCell<SharedLeaseKek>,
    /// cordon_phase1_receipt_mint_retrofitted — data directory for the
    /// daemon, used to locate `receipts.log` when minting the Phase 1
    /// cordon bridge receipt + the `audit.chain_repair_finalize` receipt
    /// emitted by `audit.repair_chain`. `None` on in-memory stores (the
    /// receipt mint is then a logged no-op). Set at construction from the
    /// daemon.db path's parent for production callers.
    data_dir: Option<PathBuf>,
    /// ADR 213 AC-7 — trust-graph revision counter, auto-bumped by
    /// `rusqlite::Connection::update_hook` on any INSERT/UPDATE/DELETE
    /// to `publisher_trust_delegations`. Read via `TrustStore::trust_graph_revision()`.
    trust_graph_rev: Arc<AtomicU64>,
    /// ADR 216 — daemon wrap key for double-envelope SE custody. Loaded at
    /// startup from `daemon_keys` table; generated on first boot. The DWK
    /// is the inner envelope of the SE custody model: raw key material is
    /// wrapped under this key before the CLI SE-wraps the blob as the outer
    /// envelope. `None` on in-memory test stores that skip SE provisioning.
    dwk: RefCell<Option<std::rc::Rc<crate::infra::daemon_wrap_key::DaemonWrapKey>>>,
    /// ADR 216 S4 — live Bridge CA, loaded after BOTH vault MEK and lease-KEK
    /// are unlocked via the double-envelope RPC. `None` until both envelopes
    /// are peeled. Sandbox spawn fails closed when this is `None`. The CA is
    /// `Arc` (not `Rc`) because `load_or_mint_bridge_ca` returns `Arc<BridgeCa>`.
    bridge_ca: RefCell<Option<std::sync::Arc<crate::trust::bridge_ca::BridgeCa>>>,
    /// V030-EMBER-DEVICE-REVOKE F4.1 — serialization gate for identity-store
    /// mutations.
    ///
    /// Each identity-mutating RPC handler opens its own
    /// `core_state::EventStore` from disk (see
    /// `crate::infra::identity_substrate::open_identity_store`), then runs its
    /// pre-flight guards against the per-instance in-memory `MaterializedState`
    /// loaded BEFORE any concurrent commit. Without serialization, two
    /// concurrent revoke-COMMITs against the two remaining devices in a 2-device
    /// authority set could each independently pass the last-presence-device
    /// guard (each sees `2 - 1 == 1` remaining), and both could land — bricking
    /// the authority set despite the structural guard (adversarial finding
    /// F4.1 / F1.1 on PR #5898).
    ///
    /// `tokio::sync::Mutex` (not `RefCell`): the lock MUST survive across
    /// `.await` points so a future async-handler refactor cannot reopen the
    /// race. Acquisition is `&Rc<…>` so the `MutexGuard` lifetime is decoupled
    /// from the `&DaemonStore` borrow — callers `Rc::clone(&store.identity_mutation_lock())`
    /// before `.lock().await` to keep the store available for the underlying op.
    ///
    /// Locked by: `handle_identity_device_revoke` (COMMIT branch). Future
    /// identity-mutating handlers (`enroll`, `enroll_backup`, `recovery.enroll`)
    /// SHOULD lock through here too so their pre-flight guards are likewise
    /// race-free; that wider rollout is filed as a follow-up rather than
    /// bundled into this surgical fix.
    identity_mutation_lock: Rc<tokio::sync::Mutex<()>>,
}

impl DaemonStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        // cordon_phase1_recreate_table_landed — pre-cordon backup. If we
        // detect a pre-v2 schema on a populated DB, copy the file out of
        // the way before opening rusqlite (which would otherwise hold an
        // exclusive write lock during the BEGIN IMMEDIATE recreate). The
        // backup is the rollback substrate (locked decision #22 / R5).
        //
        // Best-effort: a backup failure does NOT abort startup — the
        // recreate is atomic in the SQLite transaction, so loss of the
        // backup file just means rollback would need to re-derive from
        // event-log evidence. We log a WARN so the operator knows.
        let backup_attempted = match Self::pre_cordon_backup_if_needed(path) {
            Ok(Some(dest)) => {
                tracing::warn!(
                    backup = %dest.display(),
                    "cordon_phase1_recreate_table_landed: pre-cordon DB backup written before migration"
                );
                true
            }
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "cordon_phase1_recreate_table_landed: pre-cordon backup attempt failed; \
                     continuing with migration (recreate is atomic in BEGIN IMMEDIATE)"
                );
                false
            }
        };

        let conn = Connection::open(path)?;
        let trust_graph_rev = Arc::new(AtomicU64::new(0));
        let rev_hook = trust_graph_rev.clone();
        conn.update_hook(Some(
            move |_action: rusqlite::hooks::Action, _db: &str, table: &str, _rowid: i64| {
                if table == "publisher_trust_delegations" {
                    rev_hook.fetch_add(1, Ordering::Release);
                }
            },
        ))?;
        // cordon_phase1_receipt_mint_retrofitted — derive data_dir from
        // the daemon.db path so the cordon path can locate receipts.log
        // (Phase 1 bridge receipt) without threading another parameter
        // through migrate().
        let data_dir = path.parent().map(|p| p.to_path_buf());
        let store = Self {
            conn,
            vault_slot: RefCell::new(LiveVaultSlot::default()),
            consumed_dek_grants: RefCell::new(HashSet::new()),
            leases: crate::trust::lease::LeaseRegistry::new(),
            lease_kek: RefCell::new(SharedLeaseKek::default()),
            bridge_ca_fingerprint: RefCell::new(None),
            data_dir,
            trust_graph_rev,
            dwk: RefCell::new(None),
            bridge_ca: RefCell::new(None),
            identity_mutation_lock: Rc::new(tokio::sync::Mutex::new(())),
        };
        let migrate_result = store.migrate();
        if migrate_result.is_err() && backup_attempted {
            tracing::error!(
                "cordon_phase1_recreate_table_landed: migrate() failed; the pre-cordon backup \
                 is the rollback substrate"
            );
        }
        migrate_result?;
        Ok(store)
    }

    /// cordon_phase1_recreate_table_landed — copy the daemon DB to a
    /// timestamped sibling file before opening rusqlite, if and only if
    /// the file exists and is a pre-v2 schema with rows that would be
    /// affected by the cordon. Returns Ok(Some(backup_path)) on a real
    /// copy, Ok(None) when no backup is needed.
    fn pre_cordon_backup_if_needed(
        path: &Path,
    ) -> Result<Option<std::path::PathBuf>, std::io::Error> {
        // No existing file? Fresh install, nothing to back up.
        if !path.exists() {
            return Ok(None);
        }
        // Probe the DB without rusqlite (lightweight): open a read-only
        // connection, check for segment_id column. If it already exists,
        // the cordon won't run, so no backup is needed.
        let probe = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY);
        let pre_v2 = match probe {
            Ok(conn) => {
                let mut stmt = match conn.prepare("PRAGMA table_info(audit_log)") {
                    Ok(s) => s,
                    Err(_) => return Ok(None),
                };
                let mut rows = match stmt.query([]) {
                    Ok(r) => r,
                    Err(_) => return Ok(None),
                };
                let mut has_segment_id = false;
                while let Ok(Some(row)) = rows.next() {
                    let name: String = match row.get(1) {
                        Ok(n) => n,
                        Err(_) => continue,
                    };
                    if name == "segment_id" {
                        has_segment_id = true;
                        break;
                    }
                }
                drop(rows);
                drop(stmt);
                !has_segment_id
            }
            Err(_) => return Ok(None),
        };
        if !pre_v2 {
            return Ok(None);
        }

        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let mut dest = path.to_path_buf();
        let stem = dest
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| "daemon.db".to_string());
        let dest_name = format!("{stem}.pre-cordon-{ts}");
        dest.set_file_name(dest_name);
        std::fs::copy(path, &dest)?;
        Ok(Some(dest))
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let trust_graph_rev = Arc::new(AtomicU64::new(0));
        let rev_hook = trust_graph_rev.clone();
        conn.update_hook(Some(
            move |_action: rusqlite::hooks::Action, _db: &str, table: &str, _rowid: i64| {
                if table == "publisher_trust_delegations" {
                    rev_hook.fetch_add(1, Ordering::Release);
                }
            },
        ))?;
        let store = Self {
            conn,
            vault_slot: RefCell::new(LiveVaultSlot::default()),
            consumed_dek_grants: RefCell::new(HashSet::new()),
            leases: crate::trust::lease::LeaseRegistry::new(),
            lease_kek: RefCell::new(SharedLeaseKek::default()),
            bridge_ca_fingerprint: RefCell::new(None),
            // In-memory stores have no on-disk receipts.log; the cordon
            // path logs a warning and skips the receipt mint when this
            // is None. Tests that need to assert on the mint use the
            // file-backed `open(&path)` constructor.
            data_dir: None,
            trust_graph_rev,
            dwk: RefCell::new(None),
            bridge_ca: RefCell::new(None),
            identity_mutation_lock: Rc::new(tokio::sync::Mutex::new(())),
        };
        store.migrate()?;
        // V0 schema: every persona secret is vault-sealed, so an
        // in-memory store always needs a vault for the persona write
        // path. Attach a deterministic test vault by default — tests
        // that want to assert "no vault" behavior can call
        // `open_in_memory_without_vault` instead.
        #[cfg(test)]
        {
            use crate::infra::vault::Vault;
            store.set_vault(Rc::new(Vault::new([0xABu8; 32])));
        }
        Ok(store)
    }

    /// Test-only helper that builds an in-memory store with no vault
    /// attached. Used to assert the "vault required" error path on
    /// persona creation.
    #[cfg(test)]
    pub fn open_in_memory_without_vault() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let trust_graph_rev = Arc::new(AtomicU64::new(0));
        let rev_hook = trust_graph_rev.clone();
        conn.update_hook(Some(
            move |_action: rusqlite::hooks::Action, _db: &str, table: &str, _rowid: i64| {
                if table == "publisher_trust_delegations" {
                    rev_hook.fetch_add(1, Ordering::Release);
                }
            },
        ))?;
        let store = Self {
            conn,
            vault_slot: RefCell::new(LiveVaultSlot::default()),
            consumed_dek_grants: RefCell::new(HashSet::new()),
            leases: crate::trust::lease::LeaseRegistry::new(),
            lease_kek: RefCell::new(SharedLeaseKek::default()),
            bridge_ca_fingerprint: RefCell::new(None),
            data_dir: None,
            trust_graph_rev,
            dwk: RefCell::new(None),
            bridge_ca: RefCell::new(None),
            identity_mutation_lock: Rc::new(tokio::sync::Mutex::new(())),
        };
        store.migrate()?;
        Ok(store)
    }

    /// cordon_phase1_receipt_mint_retrofitted — return the configured
    /// data_dir, if any. Used by the cordon migration to locate
    /// `receipts.log` and by `audit.repair_chain` to emit its
    /// `audit.chain_repair_finalize` receipt. `None` on in-memory stores.
    pub(crate) fn data_dir(&self) -> Option<&Path> {
        self.data_dir.as_deref()
    }

    /// V030-EMBER-DEVICE-REVOKE F4.1 — accessor for the identity-store
    /// mutation lock. Callers `Rc::clone()` this and `.lock().await` to
    /// serialize identity-store mutations across concurrent RPC handlers
    /// (each of which opens its own `EventStore` from disk and would
    /// otherwise race on the pre-flight last-presence-device guard).
    /// See the field doc on `identity_mutation_lock` for the full rationale.
    pub(crate) fn identity_mutation_lock(&self) -> &Rc<tokio::sync::Mutex<()>> {
        &self.identity_mutation_lock
    }

    /// Claim a `grant_id` slot for a
    /// `sops_unwrap_dek` RPC call. Returns `true` on first claim,
    /// `false` if the grant has already been consumed for an unwrap.
    ///
    /// Callers should claim the slot ONLY after the unwrap succeeds
    /// (so a vault-lookup or decrypt failure leaves the grant usable
    /// for a retry). The membership pre-check is exposed via
    /// [`DaemonStore::is_dek_grant_consumed`].
    ///
    /// This is the rate-limit primitive: one successful unwrap per
    /// grant_id per daemon-process lifetime.
    pub fn try_consume_dek_grant(&self, grant_id: &str) -> bool {
        let mut set = self.consumed_dek_grants.borrow_mut();
        set.insert(grant_id.to_string())
    }

    /// Has this `grant_id` already been consumed for a successful
    /// `sops_unwrap_dek` call? Used by the dispatcher to reject
    /// duplicate calls before doing any vault / decrypt work.
    pub fn is_dek_grant_consumed(&self, grant_id: &str) -> bool {
        self.consumed_dek_grants.borrow().contains(grant_id)
    }

    /// ADR 200 §3 / AC-3 — issue a single-use presence nonce bound to
    /// `(op_id, daemon_fingerprint, method)`. The operator signs the canonical
    /// intent bytes that include this nonce on their presence Device; the
    /// verifier later consumes it via [`Self::consume_presence_nonce`]. PIV has
    /// no FIDO sign-counter, so this nonce is the sole freshness anchor.
    ///
    /// Reaps expired rows on each mint so the table cannot grow unbounded.
    pub fn mint_presence_nonce(
        &self,
        op_id: &str,
        daemon_fingerprint: &str,
        method: &str,
        params_digest: &str,
        peer_uid: Option<u32>,
        ttl_seconds: i64,
    ) -> Result<(String, i64), StoreError> {
        let now = presence_nonce_now();
        let expires_at = now + ttl_seconds;
        let nonce = core_crypto::generate_random_identifier("pnonce");
        self.conn().execute(
            "DELETE FROM presence_challenges WHERE expires_at < ?1",
            rusqlite::params![now],
        )?;
        self.conn().execute(
            "INSERT INTO presence_challenges \
                (nonce, op_id, daemon_fingerprint, method, params_digest, peer_uid, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                nonce,
                op_id,
                daemon_fingerprint,
                method,
                params_digest,
                peer_uid,
                now,
                expires_at
            ],
        )?;
        Ok((nonce, expires_at))
    }

    /// ADR 200 §3 / AC-3 — atomically consume a presence nonce, tombstoning
    /// `(op_id, nonce)` so a captured signature cannot be replayed. Mirrors
    /// `webauthn_challenges` consume: DELETE first (a failed verify must not
    /// leave a replayable row), then validate the bound fields from the deleted
    /// row. Returns `Ok(())` only if the nonce existed, was unexpired, and was
    /// bound to exactly this `(op_id, daemon_fingerprint, method, params_digest)`.
    ///
    /// `params_digest` is the caller's RE-derivation over the RECEIVED op params
    /// (`presence_gate::presence_params_digest`); a mismatch against the digest
    /// the operator committed at mint means the daemon substituted the op body
    /// after the tap (approval-laundering Finding 1) → fail closed.
    pub fn consume_presence_nonce(
        &self,
        nonce: &str,
        op_id: &str,
        daemon_fingerprint: &str,
        method: &str,
        params_digest: &str,
    ) -> Result<(), StoreError> {
        let row: Option<(String, String, String, String, i64)> = self
            .conn()
            .query_row(
                "SELECT op_id, daemon_fingerprint, method, params_digest, expires_at \
                 FROM presence_challenges WHERE nonce = ?1",
                rusqlite::params![nonce],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .ok();
        // Always delete — a failed verify must not leave a replayable row.
        self.conn().execute(
            "DELETE FROM presence_challenges WHERE nonce = ?1",
            rusqlite::params![nonce],
        )?;
        let (got_op, got_fp, got_method, got_digest, expires_at) =
            row.ok_or_else(|| StoreError::Unauthorized)?;
        if expires_at < presence_nonce_now() {
            return Err(StoreError::Unauthorized);
        }
        if got_op != op_id
            || got_fp != daemon_fingerprint
            || got_method != method
            || got_digest != params_digest
        {
            return Err(StoreError::Unauthorized);
        }
        Ok(())
    }

    /// Attach a `Vault` handle to this store's shared live-vault slot so
    /// persona-secret and credential paths can encrypt/decrypt under the vault
    /// master key.
    ///
    /// Runtime use is explicit rather than automatic at daemon boot:
    /// `register_session` / `vault_unlock` repopulate the slot after operator
    /// authorization, while tests and narrow bootstrap helpers may preattach a
    /// vault intentionally.
    ///
    /// Idempotent — replacing an already-attached vault is allowed; tests
    /// swap vaults to assert "wrong key cannot decrypt" invariants.
    pub fn set_vault(&self, vault: Rc<Vault>) {
        self.vault_slot.borrow().set(vault);
    }

    /// Return a clone of the currently attached vault, if any. Persona-secret
    /// write/read paths require an attached vault after the V0 schema collapse
    /// — fresh DBs have no plaintext column. Callers handle the `None` case
    /// by returning a vault-not-attached error.
    pub(crate) fn vault(&self) -> Option<Rc<Vault>> {
        self.vault_slot.borrow().get()
    }

    /// Return the shared live-vault slot this store currently uses.
    pub fn vault_slot(&self) -> LiveVaultSlot {
        self.vault_slot.borrow().clone()
    }

    /// Replace this store's live-vault slot with an externally shared slot.
    ///
    /// Runtime helper lanes (dashboard, proxy, snapshot pull) use this to
    /// share the daemon's main live-vault attachment instead of carrying
    /// private `Rc<Vault>` owners that explicit lock cannot clear.
    pub fn replace_vault_slot(&self, slot: LiveVaultSlot) {
        *self.vault_slot.borrow_mut() = slot;
    }

    /// Attach the
    /// daemon's Bridge CA fingerprint after `load_or_mint_bridge_ca`
    /// succeeds in `runtime.rs`. Mirrors [`Self::set_vault`] — the store is
    /// constructed before the CA exists, so the runtime stitches them
    /// together post-hoc. Idempotent.
    pub fn set_bridge_ca_fingerprint(&self, fingerprint: [u8; 32]) {
        *self.bridge_ca_fingerprint.borrow_mut() = Some(fingerprint);
    }

    /// Return the cached Bridge CA fingerprint, if any. The
    /// `spawn.witness` emission path in `trust::grant` reads this to embed
    /// the fingerprint in every parent→child receipt. Returns `None` for
    /// in-memory test stores that never wired a Bridge CA; callers should
    /// fall back to `[0u8; 32]` (the "not asserted" checkpoint Slice D
    /// recognises).
    pub(crate) fn bridge_ca_fingerprint(&self) -> Option<[u8; 32]> {
        *self.bridge_ca_fingerprint.borrow()
    }

    /// ADR 216 S4 — attach the live Bridge CA after double-envelope unlock
    /// loads it via `load_or_mint_bridge_ca`. The CA is needed by sandbox
    /// spawn (mTLS cert minting) and must be available before any sandbox
    /// operations.
    pub fn set_bridge_ca(&self, ca: std::sync::Arc<crate::trust::bridge_ca::BridgeCa>) {
        *self.bridge_ca.borrow_mut() = Some(ca);
    }

    /// Return the live Bridge CA, if loaded. Sandbox spawn fails closed
    /// when this returns `None` (vault not yet unlocked via DE path).
    pub(crate) fn bridge_ca(&self) -> Option<std::sync::Arc<crate::trust::bridge_ca::BridgeCa>> {
        self.bridge_ca.borrow().clone()
    }

    /// ADR 216 — load or generate the DWK and cache it on this store.
    /// Called once at daemon startup (runtime.rs). In-memory test stores
    /// skip this; tests that need double-envelope behavior call
    /// `set_dwk_for_test`.
    pub fn provision_dwk(&self) -> Result<(), StoreError> {
        let dwk = crate::infra::daemon_wrap_key::DaemonWrapKey::load_or_generate(self)?;
        *self.dwk.borrow_mut() = Some(std::rc::Rc::new(dwk));
        Ok(())
    }

    /// Return the cached DWK, if provisioned.
    pub(crate) fn dwk(&self) -> Option<std::rc::Rc<crate::infra::daemon_wrap_key::DaemonWrapKey>> {
        self.dwk.borrow().clone()
    }

    /// Drop the attached `Rc<Vault>` so the
    /// final outstanding reference is released — the MEK is wiped via
    /// `ZeroizeOnDrop` once every clone of the `Rc` has dropped. Called
    /// from `trust::presence::lock()` (explicit user-initiated lock) so
    /// the daemon enters hard-lock semantics: the next vault op MUST
    /// re-derive the MEK from the keyring-stored passphrase.
    ///
    /// Idle auto-lock does NOT call this — but the asymmetry is
    /// observability-only. Both lock paths flip `SessionState::Locked`
    /// and clear the macOS SE session cache, so a Touch ID re-prompt is
    /// required either way. The retained `Rc<Vault>` after idle lock is
    /// diagnostic surface, not a "soft-lock" privilege carve-out; the
    /// recovery path for both is `vault_unlock`. See
    /// `presence_gate_soft_lock_distinction_landed`.
    pub fn drop_vault(&self) {
        self.vault_slot.borrow().clear();
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// ADR 211 §1 / Phase 4 — the leased-authority registry, **bound to this
    /// store's persistence**. Authority-to-act is held as per-grant, TTL-bounded
    /// leases (minted at issuance, dropped on revoke/expiry), never as a standing
    /// key. The Phase-2 signing/JIT-decrypt path reads leases through
    /// `with_lease_key` (fail-closed when inert).
    ///
    /// Returns a [`BoundLeaseRegistry`] that pairs the in-memory hot-cache
    /// registry with this store so `mint`/`drop_lease`/`with_lease_key`
    /// transparently SE-wrap-persist / delete / rehydrate the lease blob (ADR 211
    /// Phase 4 / AC-6: a lease survives a daemon restart, yet is
    /// non-exfiltratable). Every existing call site (`self.leases().mint(...)`,
    /// `store.leases().has_live_lease(...)`, …) keeps compiling unchanged — the
    /// wrapper forwards the same method surface.
    pub fn leases(&self) -> crate::trust::lease::BoundLeaseRegistry<'_> {
        crate::trust::lease::BoundLeaseRegistry::new(&self.leases, self)
    }

    /// ADR 216 S3 — the cached symmetric lease-KEK, if unlocked. `None` means
    /// the lease registry runs in-memory only (pre-unlock / test stores).
    ///
    /// ADR216-F4: returns `Rc<LeaseWrapKey>` so the accessor is a cheap
    /// ref-count bump — it never copies the 32 raw key bytes onto the
    /// stack. Callers that previously held `LeaseWrapKey` by value now
    /// hold an `Rc<LeaseWrapKey>` handle; `&*kek` borrows the inner
    /// `&LeaseWrapKey` for the wrap/unwrap entry points.
    pub(crate) fn lease_kek(&self) -> Option<Rc<crate::trust::lease::LeaseWrapKey>> {
        self.lease_kek.borrow().get()
    }

    /// Return the shared lease-KEK slot this store currently uses.
    pub fn lease_kek_slot(&self) -> SharedLeaseKek {
        self.lease_kek.borrow().clone()
    }

    /// Replace this store's lease-KEK slot with an externally shared slot.
    ///
    /// Mirrors [`Self::replace_vault_slot`] — proxy stores call this at
    /// construction time so `set_lease_kek` on the main store propagates
    /// to all proxies automatically.
    pub fn replace_lease_kek_slot(&self, slot: SharedLeaseKek) {
        *self.lease_kek.borrow_mut() = slot;
    }

    /// ADR 216 S3 — install the symmetric lease-KEK after a successful
    /// double-envelope unlock. Replaces `provision_lease_kek()`.
    ///
    /// ADR216-F4: takes the key by value and immediately wraps it in an
    /// `Rc<LeaseWrapKey>` so all subsequent accessors share one mlocked
    /// allocation.
    pub fn set_lease_kek(&self, key: crate::trust::lease::LeaseWrapKey) {
        self.lease_kek.borrow().set(Rc::new(key));
    }

    /// Test-only: inject a lease-KEK so tests exercise the
    /// wrap/persist/rehydrate path without hardware.
    #[cfg(test)]
    pub(crate) fn set_lease_kek_for_test(&self, key: crate::trust::lease::LeaseWrapKey) {
        self.lease_kek.borrow().set(Rc::new(key));
    }

    /// Test-only: read the persisted lease blob for `grant_id`, flattening the
    /// `Result` so AC-6 tests can assert presence/absence ergonomically. Panics
    /// on a SQLite error (a real failure should fail the test loudly).
    #[cfg(test)]
    pub(crate) fn read_lease_blob_for_test(
        &self,
        grant_id: &str,
    ) -> Option<crate::trust::lease::PersistedLease> {
        self.read_lease_blob(grant_id).expect("read_lease_blob")
    }

    /// ADR 211 Phase 4 — write (UPSERT) a SE-wrapped lease blob at rest, keyed by
    /// `grant_id`. The blob is `se_wrap(lease_kek, lease_key)` — non-exfiltratable
    /// and the ONLY representation of the key at rest. Raw key bytes are never
    /// persisted. Overwrites any prior row for the grant (re-mint / re-issue).
    pub(crate) fn write_lease_blob(
        &self,
        rec: &crate::trust::lease::PersistedLease,
    ) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO lease_blobs (grant_id, wrapped_blob) \
                 VALUES (?1, ?2) \
                 ON CONFLICT(grant_id) DO UPDATE SET wrapped_blob = excluded.wrapped_blob",
                rusqlite::params![rec.grant_id, rec.wrapped_blob],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// ADR 211 Phase 4 — read a single persisted lease blob by `grant_id`, or
    /// `None` if absent (e.g. revoked, expired-and-dropped, or never minted).
    pub(crate) fn read_lease_blob(
        &self,
        grant_id: &str,
    ) -> Result<Option<crate::trust::lease::PersistedLease>, StoreError> {
        use rusqlite::OptionalExtension as _;
        self.conn
            .query_row(
                "SELECT grant_id, wrapped_blob FROM lease_blobs WHERE grant_id = ?1",
                rusqlite::params![grant_id],
                Self::map_lease_blob_row,
            )
            .optional()
            .map_err(StoreError::Sqlite)
    }

    /// ADR 211 Phase 4 — load every persisted lease blob (daemon-startup
    /// rehydration). The caller rehydrates / drops per row.
    pub(crate) fn list_lease_blobs(
        &self,
    ) -> Result<Vec<crate::trust::lease::PersistedLease>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT grant_id, wrapped_blob FROM lease_blobs ORDER BY grant_id")
            .map_err(StoreError::Sqlite)?;
        let rows = stmt
            .query_map([], Self::map_lease_blob_row)
            .map_err(StoreError::Sqlite)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(StoreError::Sqlite)?);
        }
        Ok(out)
    }

    /// ADR 211 Phase 4 — delete the persisted lease blob for `grant_id` (revoke /
    /// terminal expiry / exhaustion). Idempotent.
    pub(crate) fn delete_lease_blob(&self, grant_id: &str) -> Result<(), StoreError> {
        self.conn
            .execute(
                "DELETE FROM lease_blobs WHERE grant_id = ?1",
                rusqlite::params![grant_id],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// ADR 211 PR-A — persist the persona authority-to-act material re-sealed
    /// under this grant's live lease key. The blob is opaque to the store:
    /// `grant.rs` authenticates grant/persona binding inside the sealed payload.
    pub(crate) fn write_grant_persona_secret(
        &self,
        grant_id: &str,
        wrapped_blob: &[u8],
    ) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO grant_persona_secrets (grant_id, wrapped_blob) \
                 VALUES (?1, ?2) \
                 ON CONFLICT(grant_id) DO UPDATE SET wrapped_blob = excluded.wrapped_blob",
                rusqlite::params![grant_id, wrapped_blob],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// ADR 211 PR-A — read the grant-scoped persona-root blob. Absence means
    /// the persona is inert for this grant; callers must fail closed.
    pub(crate) fn read_grant_persona_secret(
        &self,
        grant_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        use rusqlite::OptionalExtension as _;
        self.conn
            .query_row(
                "SELECT wrapped_blob FROM grant_persona_secrets WHERE grant_id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::Sqlite)
    }

    /// ADR 211 PR-A — delete the grant-scoped persona-root blob when the grant
    /// lease is revoked, expired, or exhausted. Idempotent.
    pub(crate) fn delete_grant_persona_secret(&self, grant_id: &str) -> Result<(), StoreError> {
        self.conn
            .execute(
                "DELETE FROM grant_persona_secrets WHERE grant_id = ?1",
                rusqlite::params![grant_id],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// H3 fix — persist the tail `pubkey_next_secret` of a grant's signed
    /// chain, sealed under the grant's live lease. Required so a later
    /// delegation hop can call `sign_appended_block` and produce an
    /// append-chain that verifies end-to-end against the apex root
    /// (Biscuit-style attenuation), instead of the pre-fix shape where each
    /// delegated grant was a fresh single-block chain linked to the parent
    /// only by a mutable `parent_grant_id` SQL column.
    ///
    /// The blob is opaque to the store: `grant.rs` authenticates
    /// `(grant_id, tail_block_index)` binding inside the sealed payload.
    pub(crate) fn write_grant_chain_secret(
        &self,
        grant_id: &str,
        tail_block_index: u32,
        wrapped_blob: &[u8],
    ) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO grant_chain_secrets (grant_id, tail_block_index, wrapped_blob) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(grant_id) DO UPDATE SET \
                   tail_block_index = excluded.tail_block_index, \
                   wrapped_blob = excluded.wrapped_blob",
                rusqlite::params![grant_id, tail_block_index, wrapped_blob],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// H3 fix — read the grant-scoped tail `pubkey_next_secret` blob and the
    /// tail block index it was sealed for. Absence means delegation from
    /// this grant is impossible (the chain cannot be extended); callers
    /// must fail closed.
    pub(crate) fn read_grant_chain_secret(
        &self,
        grant_id: &str,
    ) -> Result<Option<(u32, Vec<u8>)>, StoreError> {
        use rusqlite::OptionalExtension as _;
        self.conn
            .query_row(
                "SELECT tail_block_index, wrapped_blob FROM grant_chain_secrets WHERE grant_id = ?1",
                rusqlite::params![grant_id],
                |row| Ok((row.get::<_, i64>(0)? as u32, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(StoreError::Sqlite)
    }

    /// H3 fix — delete the grant-scoped tail `pubkey_next_secret` blob.
    /// Idempotent; called when the grant's lease is revoked/expired so the
    /// chain can no longer be extended.
    ///
    /// Wiring into `revoke_grant_sql` is a follow-up; today the row is
    /// reaped alongside the grant row in the bulk-grant reaper. The
    /// `#[allow(dead_code)]` reflects "method exists, not yet wired" —
    /// not "method unused forever."
    #[allow(dead_code)]
    pub(crate) fn delete_grant_chain_secret(&self, grant_id: &str) -> Result<(), StoreError> {
        self.conn
            .execute(
                "DELETE FROM grant_chain_secrets WHERE grant_id = ?1",
                rusqlite::params![grant_id],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn read_grant_persona_secret_for_test(&self, grant_id: &str) -> Option<Vec<u8>> {
        self.read_grant_persona_secret(grant_id)
            .expect("read_grant_persona_secret")
    }

    /// Map a `lease_blobs` row (`grant_id`, `wrapped_blob`) to a
    /// [`crate::trust::lease::PersistedLease`]. There are **no plaintext metadata
    /// columns**: all lease metadata (scope / persona / expiry / minted-at) is
    /// sealed and authenticated inside `wrapped_blob` and re-derived on rehydrate
    /// (defect-2 fix), so this map is a pure column read with nothing to validate.
    fn map_lease_blob_row(
        row: &rusqlite::Row<'_>,
    ) -> rusqlite::Result<crate::trust::lease::PersistedLease> {
        Ok(crate::trust::lease::PersistedLease {
            grant_id: row.get(0)?,
            wrapped_blob: row.get(1)?,
        })
    }

    /// ADR 211 Phase 4 / AC-6 — rehydrate live persisted leases into the
    /// in-memory hot cache at daemon startup. Requires the lease-KEK to be
    /// installed first (via double-envelope unlock); no-op if it is not.
    pub fn rehydrate_persisted_leases(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError> {
        let Some(kek) = self.lease_kek() else {
            tracing::warn!(
                "ADR 211 Phase 4: rehydrate_persisted_leases called before the lease-KEK \
                 was provisioned; skipping (leases will be in-memory only this run)"
            );
            return Ok(());
        };
        let persisted = self.list_lease_blobs()?;
        for rec in persisted {
            // A lease only exists for an active grant. Drop the blob if its grant
            // is revoked / expired / exhausted (status flip; the row persists) or
            // absent — never resurrect authority-to-act for a dead grant.
            if !self.grant_is_active(&rec.grant_id, now) {
                let _ = self.delete_lease_blob(&rec.grant_id);
                let _ = self.delete_grant_persona_secret(&rec.grant_id);
                continue;
            }
            match self.leases.rehydrate(&rec, now, &kek) {
                Ok(true) => {}
                Ok(false) => {
                    // Expired per the authenticated TTL inside the blob: drop it.
                    let _ = self.delete_lease_blob(&rec.grant_id);
                    let _ = self.delete_grant_persona_secret(&rec.grant_id);
                }
                Err(e) => {
                    tracing::error!(
                        grant_id = %rec.grant_id,
                        error = %e,
                        "ADR 211 Phase 4: failed to rehydrate a persisted lease blob \
                         (skipping this grant; its authority-to-act stays inert until re-minted)"
                    );
                }
            }
        }
        Ok(())
    }

    /// mek_fingerprint_column_verified — read the plaintext
    /// blake3(MEK) fingerprint from vault_meta. Returns `None` if not
    /// yet written (first-run pre-MEK-provision or pre-slice-B-bis).
    pub fn read_mek_fingerprint(&self) -> Result<Option<String>, StoreError> {
        use rusqlite::OptionalExtension as _;
        let row: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT mek_fingerprint FROM vault_meta WHERE id = 1",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(StoreError::Sqlite)?;
        Ok(row.flatten())
    }

    /// mek_fingerprint_column_verified — write the plaintext
    /// blake3(MEK) fingerprint to vault_meta. UPSERT semantics.
    ///
    /// ADR 198 D3 — the fingerprint is DEMOTED to a fast advisory
    /// pre-flight. A mismatch used to be a fault (error). It is no longer:
    /// rotation legitimately changes the MEK, so a string-compare cannot
    /// be the key-correctness authority (it is also spoofable by anyone
    /// who can write `vault_meta`). The AEAD canary unwrap
    /// (`Vault::verify_canary`) is now the cryptographic authority. A
    /// mismatch here is logged at `warn!` and the new fingerprint is
    /// written through — the canary check on the fail-loud startup path
    /// is what actually stops a wrong-MEK open.
    pub fn write_mek_fingerprint(&self, fingerprint_hex: &str) -> Result<(), StoreError> {
        let existing = self.read_mek_fingerprint()?;
        if let Some(prev) = &existing
            && prev != fingerprint_hex
        {
            tracing::warn!(
                recorded = %prev,
                attempted = %fingerprint_hex,
                "vault: MEK fingerprint advisory pre-flight mismatch (ADR 198 D3 — \
                 demoted to advisory; the AEAD canary is the key-correctness authority). \
                 Writing the new fingerprint through; a genuine wrong-MEK open is caught \
                 by Vault::verify_canary on the fail-loud startup path."
            );
        }
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO vault_meta (id, mek_fingerprint, provisioned_at) \
                 VALUES (1, ?1, ?2) \
                 ON CONFLICT(id) DO UPDATE SET \
                   mek_fingerprint = excluded.mek_fingerprint, \
                   provisioned_at = excluded.provisioned_at",
                rusqlite::params![fingerprint_hex, now],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// ADR 198 D3 — read the KDF salt from `vault_meta` if a row with a
    /// non-NULL `salt` column exists. Returns `None` when the column is
    /// NULL (pre-migration vault), which signals the open/derive path to
    /// fall back to the `vault.salt` file sidecar. This is the only
    /// transitional tolerance the committed code carries.
    pub fn read_vault_salt(&self) -> Result<Option<Vec<u8>>, StoreError> {
        use rusqlite::OptionalExtension as _;
        let row: Option<Option<Vec<u8>>> = self
            .conn
            .query_row("SELECT salt FROM vault_meta WHERE id = 1", [], |row| {
                row.get::<_, Option<Vec<u8>>>(0)
            })
            .optional()
            .map_err(StoreError::Sqlite)?;
        Ok(row.flatten())
    }

    /// ADR 198 D3 — read the Argon2 params TOML from `vault_meta` if
    /// present. `None` → fall back to the `vault.params` file sidecar.
    pub fn read_vault_argon2_params(&self) -> Result<Option<String>, StoreError> {
        use rusqlite::OptionalExtension as _;
        let row: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT argon2_params FROM vault_meta WHERE id = 1",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(StoreError::Sqlite)?;
        Ok(row.flatten())
    }

    /// ADR 198 D3 — read the AEAD-sealed canary `(canary, canary_nonce)`
    /// from `vault_meta`. Returns `None` when either column is NULL
    /// (pre-migration vault, or a vault provisioned before the canary
    /// landed) so the caller can skip the canary check rather than fail.
    #[allow(clippy::type_complexity)]
    pub fn read_vault_canary(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>, StoreError> {
        use rusqlite::OptionalExtension as _;
        let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> = self
            .conn
            .query_row(
                "SELECT canary, canary_nonce FROM vault_meta WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(StoreError::Sqlite)?;
        Ok(row.and_then(|(c, n)| match (c, n) {
            (Some(c), Some(n)) => Some((c, n)),
            _ => None,
        }))
    }

    /// ADR 198 D3 — provision the `vault_meta` envelope columns at first
    /// run: the KDF `salt`, the Argon2 `params` TOML, and the AEAD-sealed
    /// `(canary, canary_nonce)`. UPSERTs the single `id = 1` row,
    /// preserving any existing `mek_fingerprint`. `key_epoch` keeps its
    /// schema default of 0. Idempotent in the sense of "writes whatever
    /// the caller hands it" — the caller decides when to provision (first
    /// run, where the salt is generated).
    pub fn write_vault_envelope_meta(
        &self,
        salt: &[u8],
        argon2_params: &str,
        canary: &[u8],
        canary_nonce: &[u8],
    ) -> Result<(), StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO vault_meta (id, salt, argon2_params, canary, canary_nonce, provisioned_at) \
                 VALUES (1, ?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(id) DO UPDATE SET \
                   salt = excluded.salt, \
                   argon2_params = excluded.argon2_params, \
                   canary = excluded.canary, \
                   canary_nonce = excluded.canary_nonce, \
                   provisioned_at = COALESCE(vault_meta.provisioned_at, excluded.provisioned_at)",
                rusqlite::params![salt, argon2_params, canary, canary_nonce, now],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// ADR 198 D1/D3 — read the monotonic `vault_meta.key_epoch` (the
    /// rotation legibility/audit counter, surfaced by `vault_status` and
    /// the rotation plan). Returns `0` when no `vault_meta` row exists yet
    /// (the column is `NOT NULL DEFAULT 0`, so a present row always yields
    /// a concrete value).
    pub fn read_key_epoch(&self) -> Result<i64, StoreError> {
        use rusqlite::OptionalExtension as _;
        let epoch: Option<i64> = self
            .conn
            .query_row("SELECT key_epoch FROM vault_meta WHERE id = 1", [], |row| {
                row.get::<_, i64>(0)
            })
            .optional()
            .map_err(StoreError::Sqlite)?;
        Ok(epoch.unwrap_or(0))
    }

    /// ADR 198 D3 amendment — read the relocated Headless-MEK wrap from
    /// `vault_meta` (`(headless_mek_nonce, headless_mek_wrapped)`). The
    /// Headless MEK is AEAD-wrapped under the Interactive MEK; relocating
    /// it off the `vault.headless-mek.wrapped` file sidecar into the DB is
    /// what lets `rotate_headless` (and the Interactive-MEK rekey that
    /// re-wraps it) commit atomically with the per-row DEK rewraps in one
    /// SQLite transaction. Returns `None` (→ file-sidecar fallback) when
    /// either column is NULL (pre-migration vault).
    #[allow(clippy::type_complexity)]
    pub fn read_headless_mek_wrap(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>, StoreError> {
        use rusqlite::OptionalExtension as _;
        let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> = self
            .conn
            .query_row(
                "SELECT headless_mek_nonce, headless_mek_wrapped FROM vault_meta WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(StoreError::Sqlite)?;
        Ok(row.and_then(|(n, w)| match (n, w) {
            (Some(n), Some(w)) => Some((n, w)),
            _ => None,
        }))
    }

    /// ADR 198 D3 amendment — UPSERT the relocated Headless-MEK wrap into
    /// `vault_meta`. Used at first-run provisioning. (Rotation re-writes
    /// these columns inline inside the single rotation transaction, not via
    /// this method, so the wrap commits atomically with the DEK rewraps.)
    pub fn write_headless_mek_wrap(&self, nonce: &[u8], wrapped: &[u8]) -> Result<(), StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO vault_meta (id, headless_mek_nonce, headless_mek_wrapped, provisioned_at) \
                 VALUES (1, ?1, ?2, ?3) \
                 ON CONFLICT(id) DO UPDATE SET \
                   headless_mek_nonce = excluded.headless_mek_nonce, \
                   headless_mek_wrapped = excluded.headless_mek_wrapped, \
                   provisioned_at = COALESCE(vault_meta.provisioned_at, excluded.provisioned_at)",
                rusqlite::params![nonce, wrapped, now],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// ADR 206 §4 clean-break — NULL the headless-MEK wrap
    /// (`headless_mek_nonce`/`headless_mek_wrapped`) and the key-correctness
    /// canary (`canary`/`canary_nonce`) on the single `vault_meta` row.
    ///
    /// Called at `vault.se_provision` BEFORE installing the §4 scope KEK: once
    /// the interactive vault key is re-sourced from the presence-unwrapped KEK_s,
    /// a headless blob wrapped under the PRIOR (Argon2id/keychain) MEK can no
    /// longer be unwrapped, and a canary sealed under that prior MEK would
    /// false-alarm across the clean break. NULLing both forces the next vault
    /// open to hit first-run headless generation under KEK_s; the canary is then
    /// re-sealed under KEK_s by the caller. UPDATE-only: a fresh vault with no
    /// `vault_meta` row is a harmless no-op (nothing to clear).
    ///
    /// Deliberately does NOT silently regenerate-on-mismatch elsewhere — a
    /// passphrase-lane wrong-key must STAY a loud error; this is the one
    /// sanctioned, operator-initiated clean break.
    pub fn clear_headless_and_canary_meta(&self) -> Result<(), StoreError> {
        self.conn
            .execute(
                "UPDATE vault_meta SET \
                   headless_mek_nonce = NULL, \
                   headless_mek_wrapped = NULL, \
                   canary = NULL, \
                   canary_nonce = NULL \
                 WHERE id = 1",
                [],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// ADR 206 §4 clean-break — UPSERT ONLY the AEAD-sealed canary columns
    /// (`canary`/`canary_nonce`), leaving every other `vault_meta` column
    /// untouched. Used after the §4 scope KEK is installed to re-seal the
    /// key-correctness canary under KEK_s, so the fail-loud `verify_canary`
    /// check is live on the presence-as-decryption lane (the §4 install path
    /// does not write `salt`/`argon2_params`, so the broader
    /// `write_vault_envelope_meta` cannot be reused here).
    pub fn write_vault_canary(&self, canary: &[u8], canary_nonce: &[u8]) -> Result<(), StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO vault_meta (id, canary, canary_nonce, provisioned_at) \
                 VALUES (1, ?1, ?2, ?3) \
                 ON CONFLICT(id) DO UPDATE SET \
                   canary = excluded.canary, \
                   canary_nonce = excluded.canary_nonce, \
                   provisioned_at = COALESCE(vault_meta.provisioned_at, excluded.provisioned_at)",
                rusqlite::params![canary, canary_nonce, now],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// Read the SE-wrapped interactive key blob from `vault_meta`.
    /// Returns `None` on first boot (column NULL or row absent).
    pub fn read_se_wrapped_interactive_key(&self) -> Result<Option<Vec<u8>>, StoreError> {
        use rusqlite::OptionalExtension as _;
        Ok(self
            .conn
            .query_row(
                "SELECT se_wrapped_interactive_key FROM vault_meta WHERE id = 1",
                [],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map_err(StoreError::Sqlite)?
            .flatten())
    }

    /// UPSERT the SE-wrapped interactive key blob into `vault_meta`.
    /// Called once at first-boot provisioning.
    pub fn write_se_wrapped_interactive_key(&self, blob: &[u8]) -> Result<(), StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO vault_meta (id, se_wrapped_interactive_key, provisioned_at) \
                 VALUES (1, ?1, ?2) \
                 ON CONFLICT(id) DO UPDATE SET \
                   se_wrapped_interactive_key = excluded.se_wrapped_interactive_key, \
                   provisioned_at = COALESCE(vault_meta.provisioned_at, excluded.provisioned_at)",
                rusqlite::params![blob, now],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    // ── ADR 216 — DWK persistence ──────────────────────────────────────

    pub fn read_daemon_wrap_key(&self) -> Result<Option<Vec<u8>>, StoreError> {
        use rusqlite::OptionalExtension as _;
        self.conn
            .query_row(
                "SELECT key_blob FROM daemon_keys WHERE key_name = 'dwk'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::Sqlite)
    }

    pub fn write_daemon_wrap_key(&self, key: &[u8]) -> Result<(), StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO daemon_keys (key_name, key_blob, created_at) \
                 VALUES ('dwk', ?1, ?2) \
                 ON CONFLICT(key_name) DO UPDATE SET \
                   key_blob = excluded.key_blob",
                rusqlite::params![key, now],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    pub fn read_double_envelope_outer(&self) -> Result<Option<Vec<u8>>, StoreError> {
        use rusqlite::OptionalExtension as _;
        self.conn
            .query_row(
                "SELECT double_envelope_outer FROM vault_meta WHERE id = 1",
                [],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map(Option::flatten)
            .map_err(StoreError::Sqlite)
    }

    pub fn write_double_envelope_outer(&self, blob: &[u8]) -> Result<(), StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO vault_meta (id, double_envelope_outer, provisioned_at) \
                 VALUES (1, ?1, ?2) \
                 ON CONFLICT(id) DO UPDATE SET \
                   double_envelope_outer = excluded.double_envelope_outer, \
                   provisioned_at = COALESCE(vault_meta.provisioned_at, excluded.provisioned_at)",
                rusqlite::params![blob, now],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    pub fn read_lease_kek_double_envelope_outer(&self) -> Result<Option<Vec<u8>>, StoreError> {
        use rusqlite::OptionalExtension as _;
        self.conn
            .query_row(
                "SELECT key_blob FROM daemon_keys WHERE key_name = 'lease_kek_de_outer'",
                [],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map(Option::flatten)
            .map_err(StoreError::Sqlite)
    }

    pub fn write_lease_kek_double_envelope_outer(&self, blob: &[u8]) -> Result<(), StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO daemon_keys (key_name, key_blob, created_at) \
                 VALUES ('lease_kek_de_outer', ?1, ?2) \
                 ON CONFLICT(key_name) DO UPDATE SET \
                   key_blob = excluded.key_blob",
                rusqlite::params![blob, now],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    // ── ADR 206 §4 — scope KEK wraps ────────────────────────────────────

    /// ADR 206 §4 — UPSERT the SE-ECIES-wrapped scope KEK for one enrolled
    /// presence Device. `wrapped_kek` is the opaque blob the operator-session CLI
    /// produced via `se_wrap(ecies_key, KEK_s)`; the daemon stores it verbatim and
    /// never holds the unwrapped KEK_s at rest. ADR 206 §4 "Never one global KEK":
    /// the row is keyed by `(scope_kind, scope_id, device_id)` so a scope's KEK_s
    /// is wrapped to each enrolled Device (Model C, 1-of-N) and one tap opens
    /// exactly one scope — not the whole AuthorityBearing lane.
    pub fn write_presence_scope_kek_wrap(
        &self,
        scope_kind: &str,
        scope_id: &str,
        device_id: &str,
        ecies_key_id: &str,
        wrapped_kek: &[u8],
    ) -> Result<(), StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO presence_scope_kek \
                   (scope_kind, scope_id, device_id, ecies_key_id, wrapped_kek, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(scope_kind, scope_id, device_id) DO UPDATE SET \
                   ecies_key_id = excluded.ecies_key_id, \
                   wrapped_kek = excluded.wrapped_kek, \
                   created_at = excluded.created_at",
                rusqlite::params![
                    scope_kind,
                    scope_id,
                    device_id,
                    ecies_key_id,
                    wrapped_kek,
                    now
                ],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// ADR 206 §4 — list a SCOPE's enrolled-Device wrapped scope-KEK blobs as
    /// `(device_id, ecies_key_id, wrapped_kek)` for `(scope_kind, scope_id)`. The
    /// unlock handoff offers these to the operator-session CLI, which picks a
    /// Device it can unwrap with (its SE key is present in that session's
    /// keychain) and performs the tap — opening exactly that one scope.
    #[allow(clippy::type_complexity)]
    pub fn list_presence_scope_kek_wraps(
        &self,
        scope_kind: &str,
        scope_id: &str,
    ) -> Result<Vec<(String, String, Vec<u8>)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT device_id, ecies_key_id, wrapped_kek FROM presence_scope_kek \
                 WHERE scope_kind = ?1 AND scope_id = ?2 \
                 ORDER BY device_id",
            )
            .map_err(StoreError::Sqlite)?;
        let rows = stmt
            .query_map(rusqlite::params![scope_kind, scope_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(StoreError::Sqlite)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(StoreError::Sqlite)?);
        }
        Ok(out)
    }

    /// ADR 206 §4 — drop a Device's wrapped scope-KEK row for one scope (on Device
    /// revoke/replace, so a retired Device's recipient can no longer unwrap that
    /// scope). Keyed by `(scope_kind, scope_id, device_id)`.
    pub fn delete_presence_scope_kek_wrap(
        &self,
        scope_kind: &str,
        scope_id: &str,
        device_id: &str,
    ) -> Result<(), StoreError> {
        self.conn
            .execute(
                "DELETE FROM presence_scope_kek \
                 WHERE scope_kind = ?1 AND scope_id = ?2 AND device_id = ?3",
                rusqlite::params![scope_kind, scope_id, device_id],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// ADR 198 D1 — read the relocated Bridge-CA module-key wrap from
    /// `vault_meta.bridge_ca_wrapped` (a serialized [`crate::infra::vault::SealedEnvelope`]
    /// blob, sealed under the Interactive MEK). Relocating it off the
    /// `bridge_ca.wrap` file sidecar into the DB lets an Interactive-MEK
    /// rotation re-wrap the bridge-CA module key atomically with everything
    /// else. Returns `None` (→ file-sidecar fallback) when NULL.
    pub fn read_bridge_ca_wrap(&self) -> Result<Option<Vec<u8>>, StoreError> {
        use rusqlite::OptionalExtension as _;
        let row: Option<Option<Vec<u8>>> = self
            .conn
            .query_row(
                "SELECT bridge_ca_wrapped FROM vault_meta WHERE id = 1",
                [],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map_err(StoreError::Sqlite)?;
        Ok(row.flatten())
    }

    /// ADR 198 D1 — UPSERT the relocated Bridge-CA module-key wrap into
    /// `vault_meta.bridge_ca_wrapped`. Used at bridge-CA load/mint time.
    /// (Rotation re-writes this column inline inside the rotation
    /// transaction.)
    pub fn write_bridge_ca_wrap(&self, wrapped: &[u8]) -> Result<(), StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO vault_meta (id, bridge_ca_wrapped, provisioned_at) \
                 VALUES (1, ?1, ?2) \
                 ON CONFLICT(id) DO UPDATE SET \
                   bridge_ca_wrapped = excluded.bridge_ca_wrapped, \
                   provisioned_at = COALESCE(vault_meta.provisioned_at, excluded.provisioned_at)",
                rusqlite::params![wrapped, now],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// ADR 206 §4 clean-break — NULL the bridge-CA module-key wrap
    /// (`vault_meta.bridge_ca_wrapped`) so the next `BridgeCa::load_or_mint`
    /// re-mints under the §4-routed custody (bridge-CA is `DaemonOperational`,
    /// so its module key moves from the old interactive MEK to the autonomous
    /// headless key). The caller also removes the `bridge_ca.wrap` and
    /// `bridge_ca.sealed` files so the re-mint does not try to unseal the old
    /// CA under a fresh module key. UPDATE-only; a fresh vault is a no-op.
    pub fn clear_bridge_ca_wrap(&self) -> Result<(), StoreError> {
        self.conn
            .execute(
                "UPDATE vault_meta SET bridge_ca_wrapped = NULL WHERE id = 1",
                [],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    // --- ADR 213 AC-7: publisher trust delegation CRUD (F8 hardened) ---

    pub fn install_publisher_trust(
        &self,
        delegation: &crate::trust_graph::PublisherTrustDelegation,
    ) -> Result<(), StoreError> {
        if delegation.id.is_empty() {
            return Err(StoreError::InvalidInput(
                "delegation id must not be empty".into(),
            ));
        }
        if delegation.publisher_did.is_empty() {
            return Err(StoreError::InvalidInput(
                "publisher_did must not be empty".into(),
            ));
        }
        if delegation.pubkey_bytes == [0u8; 32] {
            return Err(StoreError::InvalidInput(
                "pubkey_bytes must not be all-zero".into(),
            ));
        }
        if delegation.publisher_did == "did:emberlink" {
            return Err(StoreError::InvalidInput(
                "did:emberlink is the pinned first-party root; cannot be delegated to".into(),
            ));
        }
        if let Some(until) = delegation.valid_until
            && until < delegation.valid_from
        {
            return Err(StoreError::InvalidInput(format!(
                "inverted time window: valid_until ({until}) < valid_from ({})",
                delegation.valid_from
            )));
        }
        self.conn
            .execute(
                "INSERT INTO publisher_trust_delegations \
                 (id, publisher_did, pubkey_bytes, valid_from, valid_until, installed_at, revoked_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    delegation.id,
                    delegation.publisher_did,
                    delegation.pubkey_bytes.as_slice(),
                    delegation.valid_from,
                    delegation.valid_until,
                    delegation.installed_at,
                    delegation.revoked_at,
                ],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    pub fn revoke_publisher_trust(&self, id: &str, revoked_at: i64) -> Result<bool, StoreError> {
        let updated = self
            .conn
            .execute(
                "UPDATE publisher_trust_delegations SET revoked_at = ?1 \
                 WHERE id = ?2 AND revoked_at IS NULL",
                rusqlite::params![revoked_at, id],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(updated > 0)
    }

    pub fn list_publisher_trusts(
        &self,
    ) -> Result<Vec<crate::trust_graph::PublisherTrustDelegation>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, publisher_did, pubkey_bytes, valid_from, valid_until, \
                 installed_at, revoked_at FROM publisher_trust_delegations \
                 ORDER BY installed_at, id",
            )
            .map_err(StoreError::Sqlite)?;
        let rows = stmt
            .query_map([], |row| {
                let id: String = row.get(0)?;
                let pubkey_blob: Vec<u8> = row.get(2)?;
                Ok((
                    id,
                    row.get::<_, String>(1)?,
                    pubkey_blob,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            })
            .map_err(StoreError::Sqlite)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, publisher_did, pubkey_blob, valid_from, valid_until, installed_at, revoked_at) =
                row.map_err(StoreError::Sqlite)?;
            let pubkey_bytes: [u8; 32] = match pubkey_blob.try_into() {
                Ok(b) => b,
                Err(blob) => {
                    tracing::warn!(
                        delegation_id = %id,
                        blob_len = blob.len(),
                        "list_publisher_trusts: skipping row with malformed pubkey_bytes"
                    );
                    continue;
                }
            };
            out.push(crate::trust_graph::PublisherTrustDelegation {
                id,
                publisher_did,
                pubkey_bytes,
                valid_from,
                valid_until,
                installed_at,
                revoked_at,
            });
        }
        Ok(out)
    }

    pub fn list_active_publisher_trusts(
        &self,
    ) -> Result<Vec<crate::trust_graph::PublisherTrustDelegation>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, publisher_did, pubkey_bytes, valid_from, valid_until, \
                 installed_at, revoked_at FROM publisher_trust_delegations \
                 WHERE revoked_at IS NULL ORDER BY installed_at, id",
            )
            .map_err(StoreError::Sqlite)?;
        let rows = stmt
            .query_map([], |row| {
                let id: String = row.get(0)?;
                let pubkey_blob: Vec<u8> = row.get(2)?;
                Ok((
                    id,
                    row.get::<_, String>(1)?,
                    pubkey_blob,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            })
            .map_err(StoreError::Sqlite)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, publisher_did, pubkey_blob, valid_from, valid_until, installed_at, revoked_at) =
                row.map_err(StoreError::Sqlite)?;
            let pubkey_bytes: [u8; 32] = match pubkey_blob.try_into() {
                Ok(b) => b,
                Err(blob) => {
                    tracing::warn!(
                        delegation_id = %id,
                        blob_len = blob.len(),
                        "list_active_publisher_trusts: skipping row with malformed pubkey_bytes"
                    );
                    continue;
                }
            };
            out.push(crate::trust_graph::PublisherTrustDelegation {
                id,
                publisher_did,
                pubkey_bytes,
                valid_from,
                valid_until,
                installed_at,
                revoked_at,
            });
        }
        Ok(out)
    }

    #[cfg(test)]
    pub(crate) fn test_write_non_trust_table(&self) {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS _test_unrelated (v INTEGER); \
                 INSERT INTO _test_unrelated (v) VALUES (1);",
            )
            .unwrap();
    }

    /// mek_missing_with_state_refuses_start helper.
    ///
    /// Returns true when any state-bearing row exists in the store:
    /// personas, grants, receipts, credentials (vault). Used by the
    /// runtime.rs MEK-missing-with-state detector to refuse the silent
    /// re-provision path on startup. Sum-of-counts pattern keeps this
    /// to a single connection round-trip; row contents are not loaded.
    pub fn has_state_bearing_rows(&self) -> Result<bool, StoreError> {
        let total: i64 = self
            .conn
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM personas) +
                    (SELECT COUNT(*) FROM grants) +
                    (SELECT COUNT(*) FROM receipts) +
                    (SELECT COUNT(*) FROM credentials)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(StoreError::Sqlite)?;
        Ok(total > 0)
    }

    /// cordon_phase1_recreate_table_landed — promote pre-v2 `audit_log`
    /// (chain columns present but no `segment_id`) to v2 via recreate-table
    /// per ADR 174 v2 + autogrill 20260521-134520 R2/R5/R7. No-op on:
    ///
    /// - Fresh DBs (CREATE TABLE already used v2 shape so `segment_id`
    ///   column already exists).
    /// - Already-migrated DBs (`MAX(segment_id) > 0`).
    /// - Pre-v1 DBs without the genesis row (the cordon predicate's third
    ///   clause demands at least one chained row past the legacy block).
    ///
    /// On the operator's host (1 genesis + 290 NULL legacy + 3 buggy
    /// chained tail at ids 295/296/297), this:
    ///   1. CREATEs `audit_log_new` with the v2 shape (CHECK + partial
    ///      unique index).
    ///   2. INSERTs rows 1..=294 into segment_id=0 (genesis +
    ///      cordoned-legacy block), preserving id values.
    ///   3. INSERTs a `audit.chain_v1_segment_bridge_unattested` row at
    ///      `segment_id = 1, is_segment_genesis = 1` whose `prev_hash`
    ///      chains to the v1 genesis's `row_hash`.
    ///   4. DROPs the old `audit_log` (which destroys rows 295/296/297 by
    ///      exclusion from the INSERT SELECT — they were not carried over).
    ///   5. ALTER RENAMEs `audit_log_new` → `audit_log`.
    ///
    /// All five steps run inside a single `BEGIN IMMEDIATE` transaction
    /// per locked decision #20. Idempotent via the `MAX(segment_id) > 0`
    /// predicate: a second invocation post-migration no-ops.
    ///
    /// Cordon discrimination predicate (R2 / pass-2 finding #1, locked in
    /// SQL not prose):
    /// ```sql
    /// MAX(segment_id) = 0
    ///   AND COUNT(*) FROM audit_log WHERE row_hash IS NULL > 0
    ///   AND EXISTS (SELECT 1 FROM audit_log WHERE row_hash IS NOT NULL AND id > 1)
    /// ```
    ///
    /// On a fresh-install DB the second clause is false (no legacy NULL
    /// rows) so the predicate no-ops and the daemon writes happily into
    /// segment 0.
    fn cordon_migration_phase1_if_needed(&self) -> Result<(), StoreError> {
        // 1. If `audit_log` doesn't have the segment_id column yet, this is
        //    a pre-v2 DB. Detect via PRAGMA table_info. If the column is
        //    already present, we're either fresh (v2 from CREATE TABLE) or
        //    already-migrated. Either way, ensure the partial unique index
        //    exists (idempotent via IF NOT EXISTS) and return.
        let has_segment_id = self.audit_log_column_exists("segment_id")?;
        if has_segment_id {
            self.recreate_audit_log_indexes(&self.conn)?;
            // cordon_phase1_receipt_backfill_landed — Part 2/3 retrofit for
            // hosts that cordoned under pre-#4435 code: the bridge row is in
            // audit_log but the `_unattested` receipt was never minted (and
            // receipts.log may not exist). This already-migrated early-return
            // path is the ONLY boot path such a host takes, so the backfill
            // must live here — and it runs inside DaemonStore::open, before
            // any startup verify, so the verifier never trips on the gap.
            // No-op on fresh v2 DBs (no bridge row) and already-backfilled
            // hosts (receipt present).
            self.cordon_phase1_receipt_backfill_if_needed()?;
            return Ok(());
        }

        // 2. Cordon discrimination predicate (R2 / pass-2 finding #1).
        // First: any rows at all? Fresh DBs (no audit_log content) skip the
        // recreate; the CREATE TABLE batch handled them.
        let total_rows: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap_or(0);
        if total_rows == 0 {
            // Empty table — fall through to the v2-shape CREATE TABLE the
            // migrate() body already executed via the IF NOT EXISTS, BUT
            // since the table already exists at v1 shape with rows=0, we
            // still need to recreate it to pick up the new columns +
            // CHECK constraint. Handle this as a no-data recreate.
            return self.recreate_audit_log_no_data();
        }

        // Legacy null block + chained-rows-past-genesis predicate.
        let legacy_null_count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE row_hash IS NULL AND action != 'audit.chain_v1_genesis'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let chained_past_genesis: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE row_hash IS NOT NULL AND action != 'audit.chain_v1_genesis'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let cordon_predicate_fires = legacy_null_count > 0 && chained_past_genesis > 0;

        if cordon_predicate_fires {
            self.cordon_migration_phase1_destructive()?;
            tracing::warn!(
                legacy_rows = legacy_null_count,
                chained_rows_destroyed = chained_past_genesis,
                "cordon_phase1_recreate_table_landed: Phase 1 cordon migration fired \
                 (recreate-table; pre-cordon backup written; bridge row inserted at segment_id=1)"
            );
        } else {
            // Pre-v2 schema without a legacy block: recreate-table to add
            // segment_id + is_segment_genesis + CHECK, carry all rows over
            // into segment 0. Fresh chained writes will land in segment 0
            // (per Theme A — segment_id is the operational segment, not
            // strictly a migration concept).
            self.recreate_audit_log_carry_all_segment_zero()?;
            tracing::info!(
                rows_carried = total_rows,
                "cordon_phase1_recreate_table_landed: pre-v2 → v2 recreate-table no-cordon \
                 (no legacy NULL block present; all rows carried into segment_id=0)"
            );
        }
        Ok(())
    }

    /// cordon_phase1_receipt_backfill_landed — Part 2/3 retrofit. On an
    /// already-cordoned host, back-fill the Phase 1
    /// `audit.chain_v1_segment_bridge_unattested` Receipt v2 if it is
    /// missing from `receipts.log`. Pure receipt-file backfill: reads the
    /// in-DB bridge row and (re)mints the receipt; does NOT mutate
    /// `audit_log`. `append_receipts_journal` creates `receipts.log`
    /// (mode 0600) when absent — that satisfies Part 3.
    ///
    /// Idempotent and conservative:
    /// - no bridge row in `audit_log` (fresh v2 DB) → no-op;
    /// - bridge row's `row_hash` is NULL/empty (malformed) → no-op;
    /// - `data_dir` not configured (in-memory store) → no-op;
    /// - a matching `_unattested` receipt already present → no-op.
    ///
    /// The retrofit cannot recover the original `destroyed_row_ids` (those
    /// rows were excised by the cordon), so the back-filled body carries an
    /// empty list. The receipt still anchors the bridge row by its
    /// `bridge_segment_genesis.row_hash`, which is what the verifier binds.
    fn cordon_phase1_receipt_backfill_if_needed(&self) -> Result<(), StoreError> {
        let Some(bridge) = self.lookup_cordon_bridge_row()? else {
            return Ok(());
        };
        if bridge.row_hash.is_empty() || bridge.prev_hash.is_empty() {
            return Ok(());
        }
        let Some(data_dir) = self.data_dir.as_deref() else {
            return Ok(());
        };
        match cordon_unattested_receipt_present(data_dir, &bridge.row_hash) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            // Read failure (e.g. receipts.log perms drift, I/O error): we
            // can't tell whether the receipt is present, so SKIP rather than
            // risk a double-mint — and never block boot on a retrofit read.
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "cordon_phase1_receipt_backfill_landed: could not read receipts.log to \
                     decide backfill; skipping (boot continues). Investigate receipts.log."
                );
                return Ok(());
            }
        }
        // Best-effort: unlike the forward path (which mints inside the
        // cordon's BEGIN IMMEDIATE and rolls back the whole migration on
        // failure), the bridge row here ALREADY landed on a previous boot.
        // The host was bootable before this retrofit existed, so a transient
        // mint failure (e.g. receipts.log mode-drift refusal, I/O error) must
        // NOT brick boot. Log loudly and continue — the verifier's existing
        // IncompleteRepairReceipt → quarantine path is the backstop for the
        // still-missing receipt, and the next boot retries the backfill
        // (the presence check skips any partial/corrupt line).
        match mint_cordon_phase1_bridge_receipt(
            Some(data_dir),
            &bridge.prev_hash,
            &[],
            &bridge.timestamp,
            &bridge.row_hash,
        ) {
            Ok(()) => tracing::warn!(
                bridge_row_hash = %bridge.row_hash,
                "cordon_phase1_receipt_backfill_landed: back-filled missing Phase 1 bridge \
                 receipt for an already-cordoned host (Part 2/3 retrofit; receipts.log \
                 created if absent)"
            ),
            Err(e) => tracing::error!(
                error = %e,
                bridge_row_hash = %bridge.row_hash,
                "cordon_phase1_receipt_backfill_landed: receipt backfill FAILED (best-effort, \
                 boot continues). The audit chain stays half-anchored until the next boot \
                 retries or the verifier quarantines on IncompleteRepairReceipt — investigate \
                 receipts.log permissions/IO."
            ),
        }
        Ok(())
    }

    /// Look up the Phase 1 cordon bridge row in `audit_log`, if present.
    /// Returns `None` on fresh v2 DBs (never cordoned). Used by the
    /// receipt-backfill retrofit.
    fn lookup_cordon_bridge_row(&self) -> Result<Option<CordonBridgeRow>, StoreError> {
        use rusqlite::OptionalExtension as _;
        let row = self
            .conn
            .query_row(
                "SELECT timestamp, prev_hash, row_hash FROM audit_log \
                 WHERE action = 'audit.chain_v1_segment_bridge_unattested' \
                   AND segment_id = 1 AND is_segment_genesis = 1 \
                 ORDER BY id ASC LIMIT 1",
                [],
                |r| {
                    Ok(CordonBridgeRow {
                        timestamp: r.get::<_, String>(0)?,
                        prev_hash: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        row_hash: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    })
                },
            )
            .optional()
            .map_err(StoreError::Sqlite)?;
        Ok(row)
    }

    /// PRAGMA-based column existence probe.
    fn audit_log_column_exists(&self, column_name: &str) -> Result<bool, StoreError> {
        let mut stmt = self.conn.prepare("PRAGMA table_info(audit_log)")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            if name == column_name {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// ADR 206 §4 per-scope cutover — true when `presence_scope_kek` exists with
    /// the pre-per-scope shape (`device_id PRIMARY KEY`, no `scope_kind` column).
    /// Such a table holds discardable single-global wraps; `migrate()` drops it so
    /// the per-scope `(scope_kind, scope_id, device_id)` schema can be installed
    /// (clean break — re-provision regenerates the wraps per-scope). False for a
    /// missing table (fresh DB) or one already carrying `scope_kind`.
    fn presence_scope_kek_is_pre_per_scope(&self) -> Result<bool, StoreError> {
        use rusqlite::OptionalExtension as _;
        let exists: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='presence_scope_kek'",
                [],
                |_| Ok(true),
            )
            .optional()
            .map_err(StoreError::Sqlite)?
            .unwrap_or(false);
        if !exists {
            return Ok(false);
        }
        let mut stmt = self.conn.prepare("PRAGMA table_info(presence_scope_kek)")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            if name == "scope_kind" {
                return Ok(false); // already per-scope
            }
        }
        Ok(true) // table exists but has no scope_kind => old single-global shape
    }

    /// Recreate `audit_log` from a pre-v2 schema where no rows exist (or
    /// the row count is genuinely zero). The CREATE TABLE in the migrate
    /// batch's IF NOT EXISTS was a no-op because the table already
    /// exists with the old shape; we drop and re-create to pick up the
    /// new columns + CHECK constraint + partial unique index.
    fn recreate_audit_log_no_data(&self) -> Result<(), StoreError> {
        let conn = &self.conn;
        conn.execute("BEGIN IMMEDIATE", [])?;
        let result = (|| -> Result<(), StoreError> {
            self.create_audit_log_new_v2(conn)?;
            // No rows to carry; just swap.
            conn.execute("DROP TABLE audit_log", [])?;
            conn.execute("ALTER TABLE audit_log_new RENAME TO audit_log", [])?;
            self.recreate_audit_log_indexes(conn)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    /// Carry all rows over into `segment_id = 0` and recreate the table.
    /// Used when a pre-v2 DB has no legacy NULL block (so no cordon-
    /// bridge needed) — e.g. a DB that already had only chained rows
    /// under v1 chain semantics.
    fn recreate_audit_log_carry_all_segment_zero(&self) -> Result<(), StoreError> {
        let conn = &self.conn;
        conn.execute("BEGIN IMMEDIATE", [])?;
        let result = (|| -> Result<(), StoreError> {
            self.create_audit_log_new_v2(conn)?;
            conn.execute(
                "INSERT INTO audit_log_new \
                 (id, timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash, segment_id, is_segment_genesis) \
                 SELECT id, timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash, \
                        0 AS segment_id, \
                        CASE WHEN action = 'audit.chain_v1_genesis' THEN 1 ELSE 0 END AS is_segment_genesis \
                 FROM audit_log",
                [],
            )?;
            conn.execute("DROP TABLE audit_log", [])?;
            conn.execute("ALTER TABLE audit_log_new RENAME TO audit_log", [])?;
            self.recreate_audit_log_indexes(conn)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    /// cordon_phase1_recreate_table_landed — the destructive cordon
    /// migration that fires on a DB matching the operator's host shape
    /// (legacy NULL block + chained tail past the block). See
    /// `cordon_migration_phase1_if_needed` doc-comment for the full
    /// design rationale.
    ///
    /// cordon_phase1_receipt_mint_retrofitted — the deferred-receipt
    /// obligation per ADR 174 v2 §5 + ADR 176 §4 is honored inside the
    /// `BEGIN IMMEDIATE` transaction below. The bridge row INSERT and
    /// the `audit.chain_v1_segment_bridge_unattested` Receipt v2 append
    /// to `receipts.log` are atomic: if the file write fails, the
    /// SQLite transaction rolls back and neither lands. On in-memory
    /// stores (`data_dir == None`) or pre-identity-init paths, the
    /// receipt mint logs a warning and skips — production callers
    /// (`runtime.rs`) initialise the daemon identity BEFORE
    /// `DaemonStore::open` so the singleton is set when the cordon
    /// runs.
    fn cordon_migration_phase1_destructive(&self) -> Result<(), StoreError> {
        // Compute the first-non-null chained id past genesis BEFORE
        // opening the transaction (this is a read).
        let first_non_null_after_genesis: Option<i64> = self
            .conn
            .query_row(
                "SELECT MIN(id) FROM audit_log WHERE row_hash IS NOT NULL AND action != 'audit.chain_v1_genesis'",
                [],
                |row| row.get(0),
            )
            .ok()
            .flatten();

        // The cordon boundary: every id < first_non_null_after_genesis
        // is carried over (genesis + legacy NULL block). Every id >=
        // first_non_null_after_genesis is destroyed (the buggy chained
        // tail past the legacy block).
        let boundary_id = first_non_null_after_genesis.ok_or_else(|| {
            StoreError::InvalidInput(
                "cordon predicate fired but no non-NULL chained row past genesis exists".into(),
            )
        })?;

        // cordon_phase1_receipt_mint_retrofitted — pre-compute the list
        // of destroyed-row ids so the bridge receipt body can record
        // them. Pre-transaction read; ordering by id is informational
        // for forensics.
        let destroyed_row_ids: Vec<i64> = {
            let mut stmt = self
                .conn
                .prepare("SELECT id FROM audit_log WHERE id >= ?1 ORDER BY id ASC")?;
            stmt.query_map(rusqlite::params![boundary_id], |r| r.get::<_, i64>(0))?
                .collect::<Result<Vec<i64>, _>>()?
        };

        // Resolve the genesis row's row_hash — it's the bridge row's
        // prev_hash.
        let genesis_row_hash: String = self
            .conn
            .query_row(
                "SELECT row_hash FROM audit_log WHERE action = 'audit.chain_v1_genesis' AND id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::InvalidInput(
                "cordon predicate fired but the chain-v1 genesis row at id=1 is missing or has NULL row_hash".into()
            ))?;

        let conn = &self.conn;
        conn.execute("BEGIN IMMEDIATE", [])?;
        let data_dir = self.data_dir.clone();
        let result = (|| -> Result<(), StoreError> {
            // 1. CREATE audit_log_new with v2 schema.
            self.create_audit_log_new_v2(conn)?;

            // 2. INSERT cordoned-legacy rows (id < boundary_id) into
            //    segment_id = 0. Preserves id values via INSERT ... id
            //    column. The genesis row gets is_segment_genesis = 1; all
            //    other carryovers get 0.
            conn.execute(
                "INSERT INTO audit_log_new \
                 (id, timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash, segment_id, is_segment_genesis) \
                 SELECT id, timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash, \
                        0 AS segment_id, \
                        CASE WHEN action = 'audit.chain_v1_genesis' THEN 1 ELSE 0 END AS is_segment_genesis \
                 FROM audit_log \
                 WHERE id < ?1",
                rusqlite::params![boundary_id],
            )?;

            // 3. INSERT segment-1 bridge row.
            // Action: `audit.chain_v1_segment_bridge_unattested` (Phase 1).
            // Bridge row body is canonical-encoded with the same shape as
            // a chained audit row; row_hash = blake3(genesis_row_hash ||
            // canonical_body). Phase 2 will re-issue with `_attested` +
            // operator signature; both receipts persist.
            let bridge_timestamp = chrono::Utc::now().to_rfc3339();
            let bridge_action = "audit.chain_v1_segment_bridge_unattested";
            let bridge_outcome = "ok";
            let canonical = crate::infra::audit::canonical_audit_row_bytes_pub(
                &bridge_timestamp,
                None,
                bridge_action,
                None,
                bridge_outcome,
                None,
            );
            let mut hasher = blake3::Hasher::new();
            hasher.update(genesis_row_hash.as_bytes());
            hasher.update(&canonical);
            let bridge_row_hash = hasher.finalize().to_hex().to_string();

            conn.execute(
                "INSERT INTO audit_log_new \
                 (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash, segment_id, is_segment_genesis) \
                 VALUES (?1, NULL, ?2, NULL, ?3, NULL, ?4, ?5, 1, 1)",
                rusqlite::params![
                    bridge_timestamp,
                    bridge_action,
                    bridge_outcome,
                    genesis_row_hash,
                    bridge_row_hash,
                ],
            )?;

            // 4. DROP the old table (destroys rows past boundary_id by
            //    exclusion). 5. RENAME the new table into place.
            conn.execute("DROP TABLE audit_log", [])?;
            conn.execute("ALTER TABLE audit_log_new RENAME TO audit_log", [])?;
            self.recreate_audit_log_indexes(conn)?;

            // cordon_phase1_receipt_mint_retrofitted — mint the Phase 1
            // bridge receipt INSIDE the BEGIN IMMEDIATE block. If the
            // receipts.log append fails, propagate the error so SQLite
            // ROLLBACK fires and the bridge row is undone — neither
            // lands. The body carries the pre-migration BLAKE3 anchor
            // (the v1 genesis row_hash, since the operator's tail is
            // destroyed by exclusion) + the destroyed-row ids + the
            // bridge row's anchor data so a verifier can re-bind the
            // receipt to the in-DB row by anchors.
            //
            // Idempotency: the cordon path itself is idempotent via
            // `cordon_migration_phase1_if_needed`'s `segment_id`-column
            // probe — the cordon does not re-run on already-migrated
            // DBs, so the receipt is minted exactly once per host. A
            // crash AFTER the SQLite COMMIT but BEFORE the runtime's
            // post-cordon receipt-presence check (Phase 2 attestation
            // surface, pending the audit-chain migration CLI) would
            // leave a row without a receipt; this is the symmetric
            // `IncompleteRepairReceipt` surface and is currently
            // out-of-band recovered.
            mint_cordon_phase1_bridge_receipt(
                data_dir.as_deref(),
                &genesis_row_hash,
                &destroyed_row_ids,
                &bridge_timestamp,
                &bridge_row_hash,
            )?;

            Ok(())
        })();
        match result {
            Ok(()) => {
                conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    /// audit_chain_v2_schema_landed — build the v2 `audit_log_new` table
    /// (same shape as the migrate-batch CREATE TABLE on fresh DBs). Used
    /// by all recreate paths so the schema definition lives in one place.
    fn create_audit_log_new_v2(&self, conn: &rusqlite::Connection) -> Result<(), StoreError> {
        conn.execute(
            "CREATE TABLE audit_log_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent_id TEXT,
                action TEXT NOT NULL,
                credential TEXT,
                outcome TEXT NOT NULL,
                details TEXT,
                prev_hash TEXT,
                row_hash TEXT,
                segment_id INTEGER NOT NULL,
                is_segment_genesis INTEGER NOT NULL DEFAULT 0,
                CHECK (
                    (segment_id = 0)
                    OR (action = 'audit.chain_v1_genesis')
                    OR (row_hash IS NOT NULL AND prev_hash IS NOT NULL)
                )
            )",
            [],
        )?;
        Ok(())
    }

    /// audit_chain_v2_schema_landed — re-create the audit_log indexes
    /// after a recreate-table swap. The indexes don't carry over via
    /// ALTER TABLE RENAME (they're attached to the original table name);
    /// re-create them against the new table.
    fn recreate_audit_log_indexes(&self, conn: &rusqlite::Connection) -> Result<(), StoreError> {
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
            [],
        )?;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_segment_genesis \
             ON audit_log(segment_id) WHERE is_segment_genesis = 1",
            [],
        )?;
        Ok(())
    }

    fn migrate(&self) -> Result<(), StoreError> {
        // V0 schema — pre-launch, no users, no rollback. Every column the
        // daemon needs is in the base CREATE TABLE. Future migrations add
        // ALTER TABLE blocks below this batch.
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS personas (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                private_key_nonce BLOB,
                private_key_ciphertext BLOB,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                created_at TEXT NOT NULL,
                metadata TEXT,
                -- Presence-policy unification: the prior
                -- `requires_biometric INTEGER` column folded into the typed
                -- `presence_policy TEXT` axis aligned with ADR 206's
                -- AuthorityLane vocabulary. `lane_default` = defer to method
                -- lane; `per_access_fresh` = every access demands a fresh
                -- nonce-bound presence-Device signature (closes the cached
                -- unlock bypass PR #6088 originally fixed via the boolean).
                -- Anchor: `vault_presence_policy_unified_with_adr206`.
                presence_policy TEXT NOT NULL DEFAULT 'lane_default'
            );

            -- audit_chain_v2_schema_landed (ARCH-AUDIT-CHAIN-SEGMENT-SCHEMA-V2).
            -- v2 audit_log shape from CREATE TABLE on fresh DBs. The CHECK
            -- constraint encodes the chain invariant. segment_id is NOT NULL
            -- with NO DEFAULT (per R5 / pass-2 finding #4) so an older binary
            -- that does not name the column fails loudly instead of silently
            -- downgrade-corrupting topology. Pre-v2 DBs are migrated by
            -- cordon_migration_phase1 below.
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent_id TEXT,
                action TEXT NOT NULL,
                credential TEXT,
                outcome TEXT NOT NULL,
                details TEXT,
                prev_hash TEXT,
                row_hash TEXT,
                segment_id INTEGER NOT NULL,
                is_segment_genesis INTEGER NOT NULL DEFAULT 0,
                CHECK (
                    (segment_id = 0)
                    OR (action = 'audit.chain_v1_genesis')
                    OR (row_hash IS NOT NULL AND prev_hash IS NOT NULL)
                )
            );
            CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            -- audit_chain_v2_schema_landed (R6 / pass-2 finding #6):
            -- the partial unique index `idx_audit_segment_genesis` is NOT
            -- created here because pre-v2 audit_log tables do not yet have
            -- the `is_segment_genesis` column — the cordon migration below
            -- (which runs before any chained writes) creates the index via
            -- `recreate_audit_log_indexes` after the v2 schema lands.

            CREATE TABLE IF NOT EXISTS grants (
                id TEXT PRIMARY KEY,
                persona_id TEXT NOT NULL,
                credential_name TEXT NOT NULL,
                scope TEXT NOT NULL,
                ttl_secs INTEGER,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                max_uses_per_hour INTEGER,
                allowed_hours_start INTEGER,
                allowed_hours_end INTEGER,
                allowed_targets TEXT,
                parent_grant_id TEXT,
                max_delegation_depth INTEGER,
                spending_limit_cents INTEGER,
                blocks_json TEXT,
                budget_json TEXT,
                usage_json TEXT,
                paused INTEGER NOT NULL DEFAULT 0,
                receipt_id TEXT,
                is_standing INTEGER NOT NULL DEFAULT 0,
                max_children_per_day INTEGER,
                auto_delegate_scope_template TEXT,
                revoked_sids_json TEXT NOT NULL DEFAULT '[]',
                FOREIGN KEY (persona_id) REFERENCES personas(id)
            );

            CREATE TABLE IF NOT EXISTS grant_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                grant_id TEXT NOT NULL,
                used_at TEXT NOT NULL,
                amount_cents INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (grant_id) REFERENCES grants(id)
            );
            CREATE INDEX IF NOT EXISTS idx_grant_usage_grant ON grant_usage(grant_id);

            CREATE TABLE IF NOT EXISTS sandboxes (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                persona_id TEXT NOT NULL,
                container_id TEXT,
                image TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'created',
                created_at TEXT NOT NULL,
                stopped_at TEXT,
                workspace_path TEXT,
                FOREIGN KEY (persona_id) REFERENCES personas(id)
            );

            CREATE TABLE IF NOT EXISTS approval_requests (
                id TEXT PRIMARY KEY,
                persona_id TEXT NOT NULL,
                credential_name TEXT NOT NULL,
                scope TEXT NOT NULL,
                ttl_secs INTEGER,
                action TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                reason TEXT,
                resolved_at TEXT,
                resolver_note TEXT,
                created_at TEXT NOT NULL,
                composite_statements_json TEXT,
                result_grant_id TEXT,
                resolution_kind TEXT NOT NULL DEFAULT 'grant',
                -- META-AP-DAEMON-APPROVAL-FLOW-DROPS-DELEGATION-FIELDS-FIXED:
                -- grant-shaping fields preserved through the approval queue so
                -- the resolver can re-stamp them on the minted grant.
                max_delegation_depth INTEGER,
                max_uses_per_hour INTEGER,
                allowed_hours_start INTEGER,
                allowed_hours_end INTEGER,
                allowed_targets TEXT,
                budget_json TEXT,
                max_children_per_day INTEGER,
                auto_delegate_scope_template TEXT,
                FOREIGN KEY (persona_id) REFERENCES personas(id)
            );

            CREATE TABLE IF NOT EXISTS standing_grants (
                id TEXT PRIMARY KEY,
                persona_id TEXT NOT NULL,
                action_pattern TEXT NOT NULL,
                scope TEXT NOT NULL DEFAULT '*',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT,
                UNIQUE(persona_id, action_pattern)
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                persona_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                read_at TEXT
            );

            CREATE TABLE IF NOT EXISTS receipts (
                id TEXT PRIMARY KEY,
                grant_id TEXT NOT NULL,
                persona_id TEXT NOT NULL,
                terminal_reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                signer_pubkey TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'grant'
            );
            CREATE INDEX IF NOT EXISTS idx_receipts_grant ON receipts(grant_id);
            CREATE INDEX IF NOT EXISTS idx_receipts_persona ON receipts(persona_id);
            CREATE INDEX IF NOT EXISTS idx_receipts_created ON receipts(created_at);

            -- DEMO-MAY3-BIO-REAL: server-persisted WebAuthn credentials.
            -- Each row is a passkey enrolled by a persona via
            -- /settings/passkeys; the `passkey_json` column is the
            -- webauthn-rs `Passkey` type (serde JSON serialization)
            -- which carries the COSE pubkey, sign counter, AAGUID,
            -- transports, and extension flags needed to verify a
            -- subsequent assertion. Credential IDs are stored as
            -- base64url so they can flow round-trip through the JSON
            -- HTTP surface without hex/base64 conversions at every hop.
            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                credential_id TEXT PRIMARY KEY,
                persona_id TEXT NOT NULL,
                passkey_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_used_at INTEGER,
                binding_scope TEXT,
                binding_ref TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_persona
                ON webauthn_credentials(persona_id);

            -- Claim Journal working set for successful Claim accumulation.
            -- This is distinct from `audit_log` (immutable evidence) and
            -- from `receipts` (durable signed artifacts). The journal is a
            -- segmented working set for session/composite rollups.
            CREATE TABLE IF NOT EXISTS claim_journal_scopes (
                scope_kind TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                status TEXT NOT NULL,
                next_scope_seq INTEGER NOT NULL,
                open_segment_no INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                closed_at TEXT,
                PRIMARY KEY (scope_kind, scope_id)
            );
            CREATE INDEX IF NOT EXISTS idx_claim_journal_scopes_status
                ON claim_journal_scopes(status);

            CREATE TABLE IF NOT EXISTS claim_journal_segments (
                scope_kind TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                segment_no INTEGER NOT NULL,
                status TEXT NOT NULL,
                first_scope_seq INTEGER NOT NULL,
                last_scope_seq INTEGER NOT NULL,
                claim_count INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                PRIMARY KEY (scope_kind, scope_id, segment_no)
            );

            CREATE TABLE IF NOT EXISTS service_registrations (
                plugin_address TEXT NOT NULL,
                plugin_version TEXT NOT NULL,
                publisher_id TEXT NOT NULL,
                installed_at TEXT NOT NULL,
                installed_by TEXT NOT NULL,
                state TEXT NOT NULL,
                service_label TEXT,
                install_receipt_hash TEXT NOT NULL,
                PRIMARY KEY (plugin_address, plugin_version)
            );
            CREATE INDEX IF NOT EXISTS idx_service_registrations_state
                ON service_registrations(state);

            CREATE TABLE IF NOT EXISTS claim_journal_claims (
                scope_kind TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                scope_seq INTEGER NOT NULL,
                segment_no INTEGER NOT NULL,
                segment_seq INTEGER NOT NULL,
                source_key TEXT NOT NULL,
                audit_event_id INTEGER NOT NULL,
                ts TEXT NOT NULL,
                claim_kind TEXT NOT NULL,
                tool TEXT NOT NULL,
                action_plugin_address TEXT,
                action_key TEXT,
                action_version TEXT,
                runner_class TEXT,
                execution_domain TEXT,
                materialization_class TEXT,
                legacy_flat INTEGER NOT NULL DEFAULT 0,
                input_hash TEXT NOT NULL,
                input_redacted_json TEXT NOT NULL,
                resolved_json TEXT NOT NULL,
                persona_id TEXT,
                grant_id TEXT,
                device_id TEXT,
                delegation_id TEXT,
                materialization_id TEXT,
                credential_name TEXT,
                PRIMARY KEY (scope_kind, scope_id, scope_seq),
                UNIQUE (scope_kind, scope_id, source_key)
            );
            CREATE INDEX IF NOT EXISTS idx_claim_journal_claims_scope_segment
                ON claim_journal_claims(scope_kind, scope_id, segment_no, segment_seq);

            -- DEMO-MAY3-BIO-REAL: in-flight WebAuthn ceremony state.
            -- Registration ceremonies and authentication ceremonies
            -- both stash `state_json` here keyed by a freshly-minted
            -- challenge_id; the corresponding finish endpoint reads it
            -- back, calls webauthn_rs::finish_*, deletes the row, and
            -- (for register) inserts a row in webauthn_credentials.
            -- For auth, `approval_id` binds the challenge to the
            -- specific approval being gated — replaying an assertion
            -- against a different approval fails because the stored
            -- state is consumed at finish time.
            -- expires_at is unix epoch seconds; rows older than that
            -- are reaped on each begin/finish call.
            CREATE TABLE IF NOT EXISTS webauthn_challenges (
                challenge_id TEXT PRIMARY KEY,
                approval_id TEXT,
                persona_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                state_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_approval
                ON webauthn_challenges(approval_id);
            CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_persona
                ON webauthn_challenges(persona_id);

            -- presence_challenges (ADR 200 §3 / AC-3) — the single-use nonce
            -- table that anchors freshness for the dev0/PIV presence lane. PIV
            -- has no FIDO sign-counter, so the daemon-issued nonce is the SOLE
            -- freshness primitive: require_authority issues a nonce bound to
            -- (op_id, daemon fingerprint), and the verifier tombstones
            -- (op_id, nonce) as single-use — consumed atomically (DELETE then
            -- validate, mirroring webauthn_challenges) so a captured signature
            -- cannot be replayed. `consumed_at` marks a spent nonce; expired or
            -- absent rows fail closed. expires_at is unix epoch seconds.
            CREATE TABLE IF NOT EXISTS presence_challenges (
                nonce TEXT PRIMARY KEY,
                op_id TEXT NOT NULL,
                daemon_fingerprint TEXT NOT NULL,
                method TEXT NOT NULL,
                -- params_digest (ADR 206 §1.3 / approval-laundering Finding 1):
                -- binds the canonical digest of the op's authority-relevant
                -- params into the nonce row so the signed intent covers the
                -- OBJECT, not just the VERB. Recomputed over the received params
                -- at consume; a mismatch fails closed. DEFAULT '' so a legacy
                -- in-flight nonce (pre-column, sub-minute TTL) fails closed
                -- rather than admitting an unbound op.
                params_digest TEXT NOT NULL DEFAULT '',
                peer_uid INTEGER,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_presence_challenges_op
                ON presence_challenges(op_id);

            -- credential_bindings_table_schema — META-ARCH-DCC-1
            -- Daemon-controlled credential-target allowlist: binds a
            -- principal (persona) + working-tree (canonical absolute
            -- repo-root path) + remote-name to a specific remote URL.
            -- The broker consults this table to decide whether an
            -- outbound credential injection is authorized for the
            -- requested target. Composite primary key matches the
            -- lookup pattern (principal + tree + remote) so single-row
            -- gets are index hits without a secondary scan.
            CREATE TABLE IF NOT EXISTS credential_bindings (
                principal_id    TEXT NOT NULL,
                working_tree_id TEXT NOT NULL,
                remote_name     TEXT NOT NULL,
                remote_url      TEXT NOT NULL,
                created_at      INTEGER NOT NULL,
                PRIMARY KEY (principal_id, working_tree_id, remote_name)
            );
            CREATE INDEX IF NOT EXISTS idx_credential_bindings_principal
                ON credential_bindings(principal_id);",
        )?;

        // CLAIM-JOURNAL-MULTI-SCOPE-PROJECTION — pre-release schema reset.
        //
        // The first cut enforced `UNIQUE(audit_event_id)` on
        // `claim_journal_claims`, which prevents one successful authority use
        // from being projected into both session and grant scopes while
        // sharing a single immutable audit evidence row. The real idempotency
        // key is `(scope_kind, scope_id, source_key)`. Rebuild the table once
        // so multi-scope rollups can back-reference one audit row without
        // duplicating evidence.
        let rebuild_claim_journal_for_multi_scope = {
            let mut stmt = self
                .conn
                .prepare("PRAGMA index_list(claim_journal_claims)")?;
            let indexes: Vec<(String, i64)> = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let mut found_unique_audit_only = false;
            for (index_name, is_unique) in indexes {
                if is_unique == 0 {
                    continue;
                }
                let pragma = format!("PRAGMA index_info({index_name})");
                let mut info_stmt = self.conn.prepare(&pragma)?;
                let cols: Vec<String> = info_stmt
                    .query_map([], |row| row.get::<_, String>(2))?
                    .collect::<Result<Vec<_>, _>>()?;
                if cols == ["audit_event_id"] {
                    found_unique_audit_only = true;
                    break;
                }
            }
            found_unique_audit_only
        };
        if rebuild_claim_journal_for_multi_scope {
            self.conn.execute_batch(
                "BEGIN IMMEDIATE;
                 ALTER TABLE claim_journal_claims
                     RENAME TO claim_journal_claims_legacy_unique_audit;
                 CREATE TABLE claim_journal_claims (
                     scope_kind TEXT NOT NULL,
                     scope_id TEXT NOT NULL,
                     scope_seq INTEGER NOT NULL,
                     segment_no INTEGER NOT NULL,
                     segment_seq INTEGER NOT NULL,
                     source_key TEXT NOT NULL,
                     audit_event_id INTEGER NOT NULL,
                     ts TEXT NOT NULL,
                     claim_kind TEXT NOT NULL,
                     tool TEXT NOT NULL,
                     action_plugin_address TEXT,
                     action_key TEXT,
                     action_version TEXT,
                     runner_class TEXT,
                     execution_domain TEXT,
                     materialization_class TEXT,
                     legacy_flat INTEGER NOT NULL DEFAULT 0,
                     input_hash TEXT NOT NULL,
                     input_redacted_json TEXT NOT NULL,
                     resolved_json TEXT NOT NULL,
                     persona_id TEXT,
                     grant_id TEXT,
                     device_id TEXT,
                     delegation_id TEXT,
                     materialization_id TEXT,
                     credential_name TEXT,
                     PRIMARY KEY (scope_kind, scope_id, scope_seq),
                     UNIQUE (scope_kind, scope_id, source_key)
                 );
                 INSERT INTO claim_journal_claims
                     (scope_kind, scope_id, scope_seq, segment_no, segment_seq, source_key, audit_event_id, ts, claim_kind, tool, action_plugin_address, action_key, action_version, runner_class, execution_domain, materialization_class, legacy_flat, input_hash, input_redacted_json, resolved_json, persona_id, grant_id, device_id, delegation_id, materialization_id, credential_name)
                 SELECT scope_kind, scope_id, scope_seq, segment_no, segment_seq, source_key, audit_event_id, ts, claim_kind, tool, NULL, NULL, NULL, NULL, NULL, NULL, 0, input_hash, input_redacted_json, resolved_json, persona_id, NULL, device_id, delegation_id, materialization_id, credential_name
                   FROM claim_journal_claims_legacy_unique_audit;
                 DROP TABLE claim_journal_claims_legacy_unique_audit;
                 CREATE INDEX IF NOT EXISTS idx_claim_journal_claims_scope_segment
                     ON claim_journal_claims(scope_kind, scope_id, segment_no, segment_seq);
                 CREATE INDEX IF NOT EXISTS idx_claim_journal_claims_plugin_time
                     ON claim_journal_claims(action_plugin_address, ts);
                 CREATE INDEX IF NOT EXISTS idx_claim_journal_claims_action_full
                     ON claim_journal_claims(action_plugin_address, action_key, action_version);
                 COMMIT;",
            )?;
        }

        let _ = self.conn.execute(
            "ALTER TABLE claim_journal_claims ADD COLUMN action_plugin_address TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE claim_journal_claims ADD COLUMN action_key TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE claim_journal_claims ADD COLUMN action_version TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE claim_journal_claims ADD COLUMN runner_class TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE claim_journal_claims ADD COLUMN execution_domain TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE claim_journal_claims ADD COLUMN materialization_class TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE claim_journal_claims ADD COLUMN legacy_flat INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE claim_journal_claims ADD COLUMN grant_id TEXT",
            [],
        );
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_claim_journal_claims_plugin_time \
             ON claim_journal_claims(action_plugin_address, ts)",
            [],
        );
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_claim_journal_claims_action_full \
             ON claim_journal_claims(action_plugin_address, action_key, action_version)",
            [],
        );

        // ADR 206 §1.3 / approval-laundering Finding 1 — add `params_digest` to
        // legacy `presence_challenges` DBs. Idempotent: swallowed when the column
        // already exists (fresh DBs created it in the schema batch above).
        let _ = self.conn.execute(
            "ALTER TABLE presence_challenges ADD COLUMN params_digest TEXT NOT NULL DEFAULT ''",
            [],
        );

        // Backfill `kind` column on legacy DBs so
        // the kms_wrap / kms_unwrap rows can land alongside grant rows.
        // Errors swallowed when the column already exists.
        let _ = self.conn.execute(
            "ALTER TABLE receipts ADD COLUMN kind TEXT NOT NULL DEFAULT 'grant'",
            [],
        );

        // Per-key fast-path index for queries shaped
        // `WHERE kind IN ('kms_wrap','kms_unwrap') AND key_name = ?`. Uses
        // SQLite JSON1 (`json_extract`) over the existing `receipt_json`
        // column so we don't have to project key_name into its own
        // column.
        self.conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_receipts_kind ON receipts(kind);
             CREATE INDEX IF NOT EXISTS idx_receipts_kms_key
                 ON receipts(json_extract(receipt_json, '$.key_name'))
                 WHERE kind IN ('kms_wrap','kms_unwrap');",
        )?;

        // Per-actor and per-resource fast-path indexes
        // for the `ember audit` query CLI. The existing
        // `idx_receipts_persona` covers persona_id lookups; we keep the
        // `idx_receipts_actor` alias as a stable name the task spec can
        // reference. The `_resource` index uses JSON1 over
        // `receipt_json.summary.resource` so substring/glob filters can
        // hit an index when the operator pins an exact resource value.
        self.conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_receipts_actor ON receipts(persona_id);
             CREATE INDEX IF NOT EXISTS idx_receipts_resource
                 ON receipts(json_extract(receipt_json, '$.summary.resource'));",
        )?;

        // Composite-grant approval columns. Existing v0 DBs
        // (e.g. the qember.sh demo seed) predate the columns above, so
        // additively backfill them with idempotent ALTER TABLE calls.
        // Errors here are swallowed when the column already exists; any
        // other failure is propagated.
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN composite_statements_json TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN result_grant_id TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN resolution_kind TEXT NOT NULL DEFAULT 'grant'",
            [],
        );

        // REVIEW2-F2 — integrity binding column. SHA-256 hex of
        // `composite_statements_json` written atomically at submit time.
        // Nullable: pre-existing rows have no hash and are treated as
        // legacy (backward-compat). New composite approvals always carry it.
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN composite_statements_hash TEXT",
            [],
        );

        // REVIEW-F7 — sandbox name uniqueness. New DBs get UNIQUE via the
        // CREATE TABLE above; existing v0 demo DBs that predate the constraint
        // get it enforced here via a unique index. `CREATE UNIQUE INDEX IF NOT
        // EXISTS` is idempotent and also covers DBs whose schema was created
        // before the UNIQUE column modifier was added.
        self.conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_sandboxes_name ON sandboxes(name);",
        )?;

        // REVIEW-F9 — owner_persona_id tracks who created (and may exec) the
        // sandbox. NULL for rows predating this migration; those legacy rows
        // are treated as unowned and the check is skipped.
        let _ = self
            .conn
            .execute("ALTER TABLE sandboxes ADD COLUMN owner_persona_id TEXT", []);

        // ADR 207 §I2 — session_id binds the sandbox to the internal
        // `register_session` minted for its proxy LLM lane. Held so
        // `sandbox_stop` / `sandbox_delete` can `close_session` it (release the
        // vault-lock pin + revoke the host-mode enrollment + invalidate the
        // attachment). NULL for sandboxes with no brokered lane / legacy rows.
        let _ = self
            .conn
            .execute("ALTER TABLE sandboxes ADD COLUMN session_id TEXT", []);

        // Per-statement revocation list.
        // Stores a JSON array of revoked Statement sids ("S0", "S1", ...) so
        // the demo can revoke a single Statement without taking down the
        // whole grant. Default `'[]'` keeps the column non-null on legacy
        // rows. Errors swallowed when the column already exists.
        let _ = self.conn.execute(
            "ALTER TABLE grants ADD COLUMN revoked_sids_json TEXT NOT NULL DEFAULT '[]'",
            [],
        );

        // approval_notify_fields_persisted — ADR 113 Phase C-1 NOTIF-1 fields.
        // Persist tool_name / target_host / target_url / agent_framework on the
        // approval row so get_approval can return them for notification banner
        // titles. Additive; no backfill needed — existing rows stay NULL.
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN tool_name TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN target_host TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN target_url TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN agent_framework TEXT",
            [],
        );

        // Daemon-operator passkeys need an
        // explicit binding anchor that is not just persona_id. Backfill the
        // nullable columns on legacy DBs; fresh DBs already get them via the
        // CREATE TABLE above.
        let _ = self.conn.execute(
            "ALTER TABLE webauthn_credentials ADD COLUMN binding_scope TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE webauthn_credentials ADD COLUMN binding_ref TEXT",
            [],
        );

        // COMPOSITE-PR6-TESTS-DASHBOARD — skill_ref advisory pointer from
        // GrantProposal. Persisted so the dashboard approval card can surface
        // which Construct/skill originated the proposal. Nullable: pre-existing
        // rows stay NULL; only proposals submitted with GrantProposal.skill_ref
        // set will populate this column.
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN skill_ref TEXT",
            [],
        );

        // Grant-
        // shaping fields the auto-approve `create_grant` path writes onto the
        // freshly-minted grant row. Before this fix the approval-required
        // path silently dropped them. Persisted on the approval_requests row
        // so the resolver can re-stamp them onto the minted grant after the
        // operator clicks Approve and the two code paths produce grants of
        // identical shape. Additive ALTER; pre-existing rows stay NULL.
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN max_delegation_depth INTEGER",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN max_uses_per_hour INTEGER",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN allowed_hours_start INTEGER",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN allowed_hours_end INTEGER",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN allowed_targets TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN budget_json TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN max_children_per_day INTEGER",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN auto_delegate_scope_template TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN approval_binding_json TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN approval_binding_used_at TEXT",
            [],
        );

        // ADR 140 §9 + §6 — bind a
        // workload Persona to the container identity it was minted for so
        // the reconciler can refuse to spawn a second container into the
        // same enrollment slot if the daemon restarts mid-spawn (CRIT-4
        // in-flight key checkpointing). `enrolling` is a new persona
        // `status` value (legal lifecycle: `enrolling -> active`; the row
        // is created in `enrolling` before the attenuated child grant
        // mints, and flips to `active` only on successful two-phase
        // commit). The reconciler treats `enrolling` rows as poisoned —
        // a daemon restart that crashed between phase-1 row insertion
        // and phase-2 grant minting leaves the row in `enrolling`, and
        // the reconciler refuses to spawn into that slot. Nullable —
        // legacy personas predate the binding and retain NULL.
        let _ = self
            .conn
            .execute("ALTER TABLE personas ADD COLUMN container_id TEXT", []);
        let _ = self
            .conn
            .execute("ALTER TABLE personas ADD COLUMN parent_grant_id TEXT", []);

        // M1 of ADR 173, Bridge
        // Cert Refresh Protocol. Per-persona client-certificate state for
        // the (d) refresh-and-rotate path:
        //
        // - `client_cert_fingerprint TEXT NOT NULL DEFAULT ''` — blake3 of
        //   the persona's currently-pinned leaf certificate DER, hex-lower.
        //   Empty string means "no cert pinned" (legacy pre-(d) sessions
        //   that ride the (b) handshake-only validation).
        // - `client_cert_not_after INTEGER NOT NULL DEFAULT 0` — Unix
        //   timestamp of the pinned cert's `notAfter`. Zero means "no
        //   cert" / "expiry not relevant" (same legacy class).
        // - `client_cert_refresh_seq INTEGER NOT NULL DEFAULT 0` —
        //   monotone refresh counter emitted by `refresh_cert` RPC into
        //   the `bridge.cert_refreshed` Receipt body (ADR 118 Extension
        //   4/5). The `verify --strict` invariants depend on this value
        //   being durable across daemon restarts; without persistence
        //   M3's RPC handler cannot guarantee monotonicity. New persona
        //   rows start at 0; the first `refresh_cert` call observes 1
        //   via the atomic UPDATE ... RETURNING in
        //   `DaemonStore::increment_refresh_seq`.
        //
        // Defaults preserve back-compat for any persona row that predates
        // the (d) chain. New persona rows minted by the spawn-time cert
        // machinery (M3 onward) fill these in atomically with cert mint.
        //
        // Idempotency: errors swallowed on second run (column already
        // exists). Matches the additive-ALTER pattern above.
        let _ = self.conn.execute(
            "ALTER TABLE personas ADD COLUMN client_cert_fingerprint TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE personas ADD COLUMN client_cert_not_after INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE personas ADD COLUMN client_cert_refresh_seq INTEGER NOT NULL DEFAULT 0",
            [],
        );

        // ADR 136 §"In-container
        // extension" — per-socket Persona enrollment table. At spawn
        // time the daemon records `(agent_socket_path, persona_id,
        // grant_id, brief_content_hash)` so subsequent RPCs on that
        // socket resolve identity from the enrollment table rather
        // than trusting the wire-claimed `caller_persona_id` /
        // `caller_grant_id`. The socket path is the identity primitive
        // for per-agent UDS sockets at `/run/emberd/agent-<uuid>.sock`.
        //
        // `state` is `'active'` for enrollments that should resolve
        // RPCs and `'revoked'` for tombstoned slots (the row stays so
        // a subsequent enrollment with the same socket path can detect
        // reuse). The default `'active'` matches the spawn-time happy
        // path.
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS agent_socket_enrollments (
                socket_path TEXT PRIMARY KEY,
                persona_id TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                brief_content_hash TEXT NOT NULL,
                enrolled_at TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'active',
                cgroup_v2_id INTEGER,
                userns_inode INTEGER,
                mnt_ns_inode INTEGER,
                peer_uid INTEGER
            );",
        )?;

        // Step A — namespace-inode columns on
        // agent_socket_enrollments. Errors swallowed when columns already
        // exist (fresh DBs have them via the CREATE TABLE above; old DBs
        // need the ALTER).
        let _ = self.conn.execute(
            "ALTER TABLE agent_socket_enrollments ADD COLUMN cgroup_v2_id INTEGER",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE agent_socket_enrollments ADD COLUMN userns_inode INTEGER",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE agent_socket_enrollments ADD COLUMN mnt_ns_inode INTEGER",
            [],
        );

        // peer_uid
        // column on agent_socket_enrollments. Carries the kernel-attested
        // uid the per-agent UDS socket was bound to at spawn time so the
        // broker's `check_principal_against_persona` gate can compare the
        // live `PeerCredPrincipal.uid` against the enrollment row. The
        // in-process `PERSONA_UID_REGISTRY` thread-local was retired when
        // the persona registry collapsed into the enrollment table; the
        // enrollment table is now the sole source of truth.
        //
        // Nullable to preserve back-compat for legacy / pre-Step-B rows
        // that were recorded before the writer was migrated; the
        // `lookup_persona_uid_from_enrollments` helper maps `NULL` to
        // `Ok(None)` so callers preserve the legacy fail-open posture
        // for personas that pre-date the per-agent UDS enrollment
        // surface. Error swallowed when the column already exists.
        let _ = self.conn.execute(
            "ALTER TABLE agent_socket_enrollments ADD COLUMN peer_uid INTEGER",
            [],
        );

        // audit_chain_v2_schema_landed — pre-v2 DBs may exist without the
        // chain columns at all (the very oldest schema). Best-effort ADD
        // COLUMN to bring them up to v1 shape (prev_hash + row_hash); the
        // cordon migration below promotes v1 → v2 (adds segment_id +
        // is_segment_genesis + CHECK + partial unique index via recreate-
        // table). Errors swallowed when the columns already exist.
        let _ = self
            .conn
            .execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT", []);
        let _ = self
            .conn
            .execute("ALTER TABLE audit_log ADD COLUMN row_hash TEXT", []);

        // cordon_phase1_recreate_table_landed — promote a v1 DB (chain
        // columns but no segment_id)
        // to v2 via recreate-table. No-op on v2 DBs (the column already
        // exists) and on fresh DBs (CREATE TABLE already used v2 shape).
        self.cordon_migration_phase1_if_needed()?;

        // Idempotent genesis: insert only if no genesis row exists yet.
        // chain_v1_genesis acts as the chain anchor — subsequent
        // append_audit_event_with_chain calls hash the prior row's
        // row_hash into the new row, with this genesis providing the
        // initial non-NULL prev_hash for chain readers. The genesis is at
        // `segment_id = 0, is_segment_genesis = 1` (the segment-0
        // boundary marker).
        let has_genesis: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE action = 'audit.chain_v1_genesis'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if has_genesis == 0 {
            let genesis_hash = blake3::hash(b"audit.chain_v1_genesis").to_hex().to_string();
            let _ = self.conn.execute(
                "INSERT INTO audit_log \
                 (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash, segment_id, is_segment_genesis) \
                 VALUES (?1, NULL, 'audit.chain_v1_genesis', NULL, 'ok', NULL, NULL, ?2, 0, 1)",
                rusqlite::params![chrono::Utc::now().to_rfc3339(), genesis_hash],
            );
        }

        // mek_fingerprint_column_verified.
        //
        // `vault_meta` table carries plaintext-fingerprint columns that
        // survive the keychain-ACL problem: the daemon can ALWAYS read
        // vault_meta regardless of who signed the binary, so a plaintext
        // blake3(MEK) hex string in SQLite is the cross-platform stable
        // reference point for the slice A loud-fail check.
        //
        // Single-row table (id=1 checkpoint). Columns:
        //   mek_fingerprint  — blake3(MEK_bytes).hex() as TEXT
        //   provisioned_at   — ISO-8601 timestamp when fingerprint written
        //
        // Idempotent: CREATE IF NOT EXISTS. Slice F's diagnose CLI +
        // future runtime.rs verify path read this column; slice B-bis
        // wires the WRITE side at MEK-first-provision time.
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS vault_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                mek_fingerprint TEXT,
                provisioned_at TEXT
            )",
            [],
        )?;

        // ADR 198 D1 — MEK→DEK envelope columns on credential rows.
        // `wrapped_dek` is the per-row Data Encryption Key AEAD-wrapped
        // under the row's scope MEK; `dek_nonce` is the fresh 24-byte
        // XChaCha20 nonce for that wrap. Additive ALTERs (idempotent — a
        // second open finds the column present and the `let _ =` swallows
        // the duplicate-column error). New rows always populate both;
        // pre-migration rows carry NULL and read-path errors loud per D2.
        let _ = self
            .conn
            .execute("ALTER TABLE credentials ADD COLUMN wrapped_dek BLOB", []);
        let _ = self
            .conn
            .execute("ALTER TABLE credentials ADD COLUMN dek_nonce BLOB", []);
        // Per-row marker for credentials that
        // require a fresh presence-Device ceremony on every read. Existing rows
        // default to ordinary cached-unlock behavior. Retained as an idempotent
        // ALTER so old DBs that landed before
        // The presence-policy unification still passes through the
        // migration below cleanly even if they never carried the column.
        let _ = self.conn.execute(
            "ALTER TABLE credentials ADD COLUMN requires_biometric INTEGER NOT NULL DEFAULT 0",
            [],
        );

        // Presence-policy unification: add the typed
        // `presence_policy` column and backfill it from any existing
        // `requires_biometric=1` rows. After this migration the application
        // code reads/writes only `presence_policy`; the legacy
        // `requires_biometric` column is retained as dead data because
        // SQLite column drops require a table rebuild we have no compelling
        // reason to take. Anchor:
        // `vault_presence_policy_unified_with_adr206`.
        let _ = self.conn.execute(
            "ALTER TABLE credentials ADD COLUMN presence_policy TEXT NOT NULL DEFAULT 'lane_default'",
            [],
        );
        let _ = self.conn.execute(
            "UPDATE credentials \
             SET presence_policy = CASE requires_biometric \
                 WHEN 1 THEN 'per_access_fresh' \
                 ELSE 'lane_default' \
             END \
             WHERE presence_policy = 'lane_default'",
            [],
        );

        // ADR 198 Part B — MEK→DEK envelope columns on persona rows. The
        // persona Ed25519 secret was previously sealed DIRECTLY under the
        // Interactive MEK (`Vault::seal` → `private_key_nonce` +
        // `private_key_ciphertext`). Part B envelopes it: the secret is now
        // sealed under a per-persona DEK whose nonce is `private_key_nonce`
        // and whose wrap (under the Interactive MEK, persona-bound AAD) is
        // carried by `private_key_dek_nonce` + `private_key_wrapped_dek`.
        // Additive ALTERs (idempotent — `let _ =` swallows duplicate-column).
        // New rows populate all four; a pre-Part-B row carries NULL in the
        // two new columns and the read path errors loud per envelope-only.
        let _ = self.conn.execute(
            "ALTER TABLE personas ADD COLUMN private_key_dek_nonce BLOB",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE personas ADD COLUMN private_key_wrapped_dek BLOB",
            [],
        );

        // ADR 198 D3 — move the KDF salt/params + key epoch + key-
        // correctness canary into `vault_meta` so they are committed
        // atomically with the wrapped DEKs in a future rotation tx (the
        // CRITICAL atomicity substrate). `salt` and `argon2_params` fall
        // back to the `vault.salt` / `vault.params` file sidecars when
        // NULL (the only transitional tolerance — lets a pre-migration
        // vault still open). `key_epoch` is legibility/audit only.
        // `canary` + `canary_nonce` carry the AEAD-sealed known plaintext
        // verified on the fail-loud startup path.
        let _ = self
            .conn
            .execute("ALTER TABLE vault_meta ADD COLUMN salt BLOB", []);
        let _ = self
            .conn
            .execute("ALTER TABLE vault_meta ADD COLUMN argon2_params TEXT", []);
        let _ = self.conn.execute(
            "ALTER TABLE vault_meta ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = self
            .conn
            .execute("ALTER TABLE vault_meta ADD COLUMN canary BLOB", []);
        let _ = self
            .conn
            .execute("ALTER TABLE vault_meta ADD COLUMN canary_nonce BLOB", []);

        // ADR 198 D1/D3 amendment — relocate the two FILE-backed wraps that
        // are sealed under the Interactive MEK into `vault_meta` so they
        // commit atomically with the per-row DEK rewraps inside one rotation
        // transaction. Before this, the Headless-MEK wrap lived in
        // `vault.headless-mek.wrapped` and the Bridge-CA module key lived in
        // `bridge_ca.wrap` — a crash between the SQLite commit and a separate
        // file rewrite during rotation could leave the file under one MEK and
        // the DB under another (the same brick-window class the salt move
        // closed). Relocating both makes the rotation tx the single
        // linearization point for ALL Interactive-MEK-wrapped material.
        //   - `headless_mek_nonce` / `headless_mek_wrapped`: the 24-byte
        //     XChaCha20 nonce + ciphertext-with-tag of the 32-byte Headless
        //     MEK wrapped under the Interactive MEK (AAD `vault.headless-mek.v1`).
        //   - `bridge_ca_wrapped`: a serialized `SealedEnvelope` (the bridge-CA
        //     module wrapping key) — `SealedEnvelope::to_blob()` bytes.
        // NULL columns fall back to the legacy file sidecars (the only
        // transitional tolerance; the dev0 host's existing files are migrated
        // into the DB by the out-of-tree one-shot, ADR 198 D2).
        let _ = self.conn.execute(
            "ALTER TABLE vault_meta ADD COLUMN headless_mek_nonce BLOB",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE vault_meta ADD COLUMN headless_mek_wrapped BLOB",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE vault_meta ADD COLUMN bridge_ca_wrapped BLOB",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE vault_meta ADD COLUMN se_wrapped_interactive_key BLOB",
            [],
        );

        // ADR 216 — double-envelope outer blob. The at-rest form of each
        // SE-custodied key is SE_ECIES_encrypt(DWK_encrypt(raw_key)). This
        // column stores the fully double-wrapped outer blob for the vault
        // MEK. (Lease-KEK uses the same double-envelope primitive but stores
        // its outer blob in the lease persistence table, not here.)
        let _ = self.conn.execute(
            "ALTER TABLE vault_meta ADD COLUMN double_envelope_outer BLOB",
            [],
        );

        // ADR 216 — daemon wrap key (DWK). A random 256-bit symmetric key
        // generated once and stored in daemon.db. Its security comes from
        // file ownership (uid=450, mode 0600). The DWK never leaves the
        // daemon process; it is the inner envelope of the double-envelope
        // SE custody model.
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS daemon_keys (
                key_name TEXT PRIMARY KEY,
                key_blob BLOB NOT NULL,
                created_at TEXT NOT NULL
            )",
            [],
        )?;

        // ADR 206 §4 — presence-as-decryption scope-KEK wraps. ONE operator
        // authority scope KEK (KEK_s) is wrapped (SE-ECIES) to EACH enrolled
        // presence Device's recipient key (Model C — any enrolled Device can
        // perform the unlock unwrap gesture, ADR 200 §2). One row per
        // (scope, Device) — a scope's KEK_s wrapped to each enrolled Device:
        // the opaque `wrapped_kek` blob produced by the operator-session CLI's
        // `se_wrap` (the separate-uid daemon never does SE crypto — it only
        // stores/serves these blobs). `ecies_key_id` records which recipient key
        // the blob is wrapped to (the Device's `active_encryption_key.key_id`)
        // so the unlock handoff can tell the CLI which SE key label to unwrap
        // with. The daemon NEVER stores the unwrapped KEK_s at rest.
        //
        // ADR 206 §4 per-scope cutover (clean break): the table was
        // `device_id PRIMARY KEY` (one global KEK). Drop an old-shape table —
        // its single-global wraps are discardable; re-provision regenerates them
        // per-scope — so the CREATE below installs the per-scope schema. A fresh
        // or already-per-scope DB skips the drop (idempotent).
        if self.presence_scope_kek_is_pre_per_scope()? {
            self.conn
                .execute("DROP TABLE presence_scope_kek", [])
                .map_err(StoreError::Sqlite)?;
        }
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS presence_scope_kek (
                scope_kind TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                ecies_key_id TEXT NOT NULL,
                wrapped_kek BLOB NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (scope_kind, scope_id, device_id)
            )",
            [],
        )?;

        // ADR 211 Phase 4 / AC-6 — SE-wrapped, restart-surviving lease blobs.
        // One row per grant: the grant's [`crate::trust::lease::LeaseKey`] AND its
        // metadata (scope / persona / expiry / minted-at), sealed together into a
        // single AES-GCM-authenticated blob `se_wrap`ed under the daemon's
        // headless lease-KEK (`crate::trust::lease::LEASE_KEK_LABEL`). The blob is
        // the ONLY representation of the lease at rest — non-exfiltratable (only
        // the SE key unwraps it) and fully authenticated. Raw key bytes are never
        // stored, and there are deliberately **no plaintext metadata columns**:
        // the live `Lease` fields are re-derived from the authenticated blob on
        // rehydrate, so a DB-write attacker who cannot extract the SE key cannot
        // flip a lease's scope or extend its TTL (defect-2 fix). This persistence
        // does NOT reintroduce a standing exfiltratable key (see the lease.rs
        // module note): it relocates restart-survival into hardware.
        //
        // Clean break (no users, pre-launch): a fresh CREATE; there is no prior
        // shape to migrate — the in-memory registry was non-persistent before
        // this slice, so there are no legacy rows to reshape.
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS lease_blobs (
                grant_id TEXT PRIMARY KEY,
                wrapped_blob BLOB NOT NULL
            )",
            [],
        )?;

        // ADR 211 PR-A — persona authority-to-act material re-sealed under one
        // grant's lease key. One opaque blob per grant, deleted with the lease
        // on revoke/expiry/exhaustion. The sealed payload binds grant_id and
        // persona_id, so there are deliberately no plaintext metadata columns to
        // tamper. Missing row => fail-closed: no lease-wrapped persona root, no
        // block-0 signing.
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS grant_persona_secrets (
                grant_id TEXT PRIMARY KEY,
                wrapped_blob BLOB NOT NULL
            )",
            [],
        )?;

        // H3 fix (security/c1-h1-h3 — v0.3.0 pre-release) — grant_chain_secrets
        // holds the tail `pubkey_next_secret` of each grant's signed chain,
        // sealed under the grant's live lease. Required so delegation can
        // produce a real append-chain (block N+1 signed by block N's
        // pubkey_next), not a fresh single-block child linked only via the
        // mutable `parent_grant_id` SQL column.
        //
        // `tail_block_index` is the 0-indexed position of the block whose
        // pubkey_next this secret pairs with — i.e. the LAST block in the
        // chain (the one a future appended block would be signed by).
        // Missing row => fail-closed: chain cannot be extended (delegation
        // refused). The blob is opaque to the store; `grant.rs` authenticates
        // `(grant_id, tail_block_index)` binding inside the sealed payload.
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS grant_chain_secrets (
                grant_id TEXT PRIMARY KEY,
                tail_block_index INTEGER NOT NULL,
                wrapped_blob BLOB NOT NULL
            )",
            [],
        )?;

        // ADR 213 AC-7 / ADR 123 §2 — installed publisher trust delegations
        // for the WoT walk. Each row maps a third-party publisher DID to an
        // Ed25519 pubkey the daemon trusts for Construct signature verification.
        // Revocation is soft-delete (revoked_at) for auditability.
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS publisher_trust_delegations (
                id TEXT PRIMARY KEY,
                publisher_did TEXT NOT NULL,
                pubkey_bytes BLOB NOT NULL CHECK(length(pubkey_bytes) = 32),
                valid_from INTEGER NOT NULL,
                valid_until INTEGER,
                installed_at INTEGER NOT NULL,
                revoked_at INTEGER
            )",
            [],
        )?;

        // ADR 210 spine reconciliation (2026-06-17): retire the
        // `transient_scope_additions` parallel auth-decision lane shipped by
        // #6087. The functionality is
        // canonically expressible via the existing minted lane (narrow-TTL
        // single-use lease per ADR 211).
        // Idempotent on fresh DBs (table never existed) and on DBs that already
        // dropped it.
        self.conn
            .execute("DROP TABLE IF EXISTS transient_scope_additions", [])?;

        Ok(())
    }
}

/// cordon_phase1_receipt_backfill_landed — the in-DB Phase 1 bridge row,
/// projected for the receipt-backfill retrofit. `prev_hash` is the
/// pre-migration chain-tip (the v1 genesis row_hash); `row_hash` is the
/// bridge row's own hash (the receipt's `bridge_segment_genesis.row_hash`).
struct CordonBridgeRow {
    timestamp: String,
    prev_hash: String,
    row_hash: String,
}

/// cordon_phase1_receipt_backfill_landed — true when `receipts.log` already
/// holds the Phase 1 `_unattested` bridge receipt anchoring `bridge_row_hash`.
/// Reads the append-only journal file directly (the file side of the
/// two-store invariant — the SQLite `receipts` table is a separate store).
/// A missing journal returns `Ok(false)`. Corrupt lines are skipped so a
/// single bad line never blocks the backfill decision. Matching on the
/// bridge row's `row_hash` (not merely the kind) keeps the check precise
/// across hosts and any future multi-cordon case.
fn cordon_unattested_receipt_present(
    data_dir: &Path,
    bridge_row_hash: &str,
) -> Result<bool, StoreError> {
    use core_events::receipt::{
        AuditChainV1SegmentBridgeUnattestedBody,
        RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_UNATTESTED, ReceiptEnvelope,
    };
    let path = data_dir.join("receipts.log");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(StoreError::InvalidInput(format!(
                "cordon_phase1_receipt_backfill_landed: read receipts.log: {e}"
            )));
        }
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(env) = serde_json::from_str::<ReceiptEnvelope>(line) else {
            continue;
        };
        if env.kind != RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_UNATTESTED {
            continue;
        }
        let Ok(body) =
            serde_json::from_value::<AuditChainV1SegmentBridgeUnattestedBody>(env.body.clone())
        else {
            continue;
        };
        if body.bridge_segment_genesis.row_hash == bridge_row_hash {
            return Ok(true);
        }
    }
    Ok(false)
}

/// cordon_phase1_receipt_mint_retrofitted — mint and append the Phase 1
/// `audit.chain_v1_segment_bridge_unattested` Receipt v2 to
/// `<data_dir>/receipts.log` per ADR 174 v2 §5 + ADR 176 §4. Called from
/// inside the cordon migration's `BEGIN IMMEDIATE` block AFTER the
/// bridge row INSERT and BEFORE the SQLite COMMIT — a failure here
/// propagates upward and the outer transaction rolls back, so the
/// receipt mint and the audit_log INSERT are byte-for-byte atomic
/// across the boundary.
///
/// `data_dir == None`: in-memory store or pre-identity-init test path.
/// Logs a warning and returns Ok (the bridge row still lands; the
/// receipt obligation surfaces as `IncompleteRepairReceipt` on the
/// next verifier walk and is out-of-band recovered).
///
/// `current_identity() == None`: the daemon's signing key hasn't been
/// loaded yet. Same posture as above — log + skip.
///
/// Returns `StoreError::InvalidInput` on a real journal-write failure
/// (mode-drift refusal, I/O error). The caller's `BEGIN IMMEDIATE`
/// then rolls back.
fn mint_cordon_phase1_bridge_receipt(
    data_dir: Option<&Path>,
    pre_migration_chain_tip_hash: &str,
    destroyed_row_ids: &[i64],
    bridge_timestamp: &str,
    bridge_row_hash: &str,
) -> Result<(), StoreError> {
    use core_events::receipt::{
        AuditChainV1SegmentBridgeUnattestedBody, BridgeSegmentGenesis,
        RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_UNATTESTED, ReceiptEnvelope, ReceiptVersion,
        TerminationAuthority, sign_receipt_v2,
    };

    let Some(data_dir) = data_dir else {
        tracing::warn!(
            "cordon_phase1_receipt_mint_retrofitted: data_dir not configured (likely \
             in-memory store); skipping Phase 1 bridge receipt mint. The bridge row \
             still lands; recovery is via Phase 2 attestation or the symmetric \
             IncompleteRepairReceipt path."
        );
        return Ok(());
    };

    let Some(identity) = crate::infra::receipt::current_identity() else {
        tracing::warn!(
            "cordon_phase1_receipt_mint_retrofitted: daemon identity not yet \
             initialised at cordon time; skipping Phase 1 bridge receipt mint. \
             Production callers (runtime.rs) initialise identity BEFORE opening the \
             store so the singleton is set when the cordon fires."
        );
        return Ok(());
    };

    let pubkey_hex = identity.pubkey_hex();
    let fingerprint_hex = blake3::hash(pubkey_hex.as_bytes()).to_hex().to_string();

    let body = AuditChainV1SegmentBridgeUnattestedBody {
        pre_migration_chain_tip_hash: pre_migration_chain_tip_hash.to_string(),
        destroyed_row_ids: destroyed_row_ids.to_vec(),
        bridge_segment_genesis: BridgeSegmentGenesis {
            segment_id: 1,
            prev_hash: pre_migration_chain_tip_hash.to_string(),
            row_hash: bridge_row_hash.to_string(),
        },
        migration_timestamp: bridge_timestamp.to_string(),
        daemon_identity_root_fingerprint: fingerprint_hex,
    };

    let body_value = serde_json::to_value(&body).map_err(|e| {
        StoreError::InvalidInput(format!(
            "cordon_phase1_receipt_mint_retrofitted: serialize bridge body: {e}"
        ))
    })?;

    let mut envelope = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_UNATTESTED.to_string(),
        receipt_id: String::new(),
        daemon_root_id: pubkey_hex,
        traceparent: None,
        // Daemon-administrative receipt — daemon persona is the termination
        // authority. Mirrors the pattern from `emit_vault_read_receipt`.
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

    let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
    sign_receipt_v2(&mut envelope, &signer).map_err(|e| {
        StoreError::InvalidInput(format!(
            "cordon_phase1_receipt_mint_retrofitted: sign bridge receipt: {e}"
        ))
    })?;

    crate::infra::receipt::append_receipts_journal(data_dir, &envelope).map_err(|e| {
        StoreError::InvalidInput(format!(
            "cordon_phase1_receipt_mint_retrofitted: append bridge receipt to receipts.log: {e}"
        ))
    })?;

    tracing::info!(
        receipt_id = %envelope.receipt_id,
        destroyed_count = destroyed_row_ids.len(),
        "cordon_phase1_receipt_mint_retrofitted: Phase 1 bridge receipt minted and \
         appended to receipts.log (atomic with cordon BEGIN IMMEDIATE)"
    );

    Ok(())
}

/// ADR 136 §"In-container
/// extension" — projection of an `agent_socket_enrollments` row.
///
/// Returned by [`DaemonStore::lookup_agent_socket_enrollment`] when an
/// active enrollment exists for the queried socket path. Revoked rows
/// are NOT surfaced — the helper returns `Ok(None)` for them so
/// dispatch can refuse the RPC with `PrincipalNotEnrolled`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSocketEnrollment {
    pub socket_path: String,
    pub persona_id: String,
    pub grant_id: String,
    pub brief_content_hash: String,
    pub enrolled_at: String,
    pub state: String,
    /// Step A — cgroup v2 leaf inode for
    /// the worker container (Step B populates; Step C gates dispatch).
    /// NULL for legacy/host-resident enrollments.
    pub cgroup_v2_id: Option<i64>,
    /// Step A — user-namespace inode.
    pub userns_inode: Option<i64>,
    /// Step A — mount-namespace inode.
    pub mnt_ns_inode: Option<i64>,
}

impl DaemonStore {
    /// Record a fresh per-socket
    /// Persona enrollment.
    ///
    /// Called at agent-spawn time by the scion spawn pipeline once a
    /// per-agent UDS socket has been created at `/run/emberd/agent-
    /// <uuid>.sock`. The `(socket_path, persona_id, grant_id,
    /// brief_content_hash)` quadruple is the kernel-attested identity
    /// substrate for every subsequent RPC on that socket — the handler
    /// reads from this table rather than trusting wire-claimed
    /// `caller_persona_id` / `caller_grant_id` per ADR 136.
    ///
    /// The row is inserted with `state = 'active'`. Subsequent
    /// re-enrollment of the same `socket_path` replaces the prior row
    /// (`INSERT OR REPLACE`) so a tombstoned slot can be reclaimed
    /// after the original agent exits.
    #[allow(clippy::too_many_arguments)]
    pub fn record_agent_socket_enrollment(
        &self,
        socket_path: &str,
        persona_id: &str,
        grant_id: &str,
        brief_content_hash: &str,
        cgroup_v2_id: Option<i64>,
        userns_inode: Option<i64>,
        mnt_ns_inode: Option<i64>,
    ) -> Result<(), StoreError> {
        // The three Option<i64>
        // columns carry the kernel-observable binding tuple captured
        // at spawn-completion via
        // `crate::spawn::scion::capture_container_ns_inodes`. NULL is
        // tolerated on legacy / non-Linux call sites; the production
        // spawn path passes Some(_) on all three.
        let enrolled_at = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO agent_socket_enrollments \
                (socket_path, persona_id, grant_id, brief_content_hash, enrolled_at, state, \
                 cgroup_v2_id, userns_inode, mnt_ns_inode) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?7, ?8)",
            rusqlite::params![
                socket_path,
                persona_id,
                grant_id,
                brief_content_hash,
                enrolled_at,
                cgroup_v2_id,
                userns_inode,
                mnt_ns_inode,
            ],
        )?;
        Ok(())
    }

    /// Resolve the Persona
    /// bound to a per-agent UDS socket.
    ///
    /// Returns `Ok(Some(...))` only when an `active` enrollment row is
    /// present for the requested socket path. Revoked rows yield
    /// `Ok(None)` so the dispatch layer can map the miss to
    /// `HandlerError::PrincipalNotEnrolled`.
    pub fn lookup_agent_socket_enrollment(
        &self,
        socket_path: &str,
    ) -> Result<Option<AgentSocketEnrollment>, StoreError> {
        let result = self.conn.query_row(
            "SELECT socket_path, persona_id, grant_id, brief_content_hash, enrolled_at, state, \
                    cgroup_v2_id, userns_inode, mnt_ns_inode \
             FROM agent_socket_enrollments WHERE socket_path = ?1 AND state = 'active'",
            rusqlite::params![socket_path],
            |row| {
                Ok(AgentSocketEnrollment {
                    socket_path: row.get(0)?,
                    persona_id: row.get(1)?,
                    grant_id: row.get(2)?,
                    brief_content_hash: row.get(3)?,
                    enrolled_at: row.get(4)?,
                    state: row.get(5)?,
                    cgroup_v2_id: row.get(6)?,
                    userns_inode: row.get(7)?,
                    mnt_ns_inode: row.get(8)?,
                })
            },
        );
        match result {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StoreError::Sqlite(e)),
        }
    }

    /// Tombstone an enrollment.
    ///
    /// Flips the row's `state` column to `'revoked'`; the row itself
    /// stays so the slot is observable for post-mortem audit and so a
    /// future re-enrollment of the same `socket_path` (via
    /// [`Self::record_agent_socket_enrollment`]'s `INSERT OR REPLACE`)
    /// is a deliberate operator action rather than a silent overwrite.
    ///
    /// No-op when the row does not exist — the operator-facing surface
    /// (e.g. agent-exit cleanup) shouldn't have to pre-check.
    pub fn revoke_agent_socket_enrollment(&self, socket_path: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE agent_socket_enrollments SET state = 'revoked' WHERE socket_path = ?1",
            rusqlite::params![socket_path],
        )?;
        Ok(())
    }

    /// target_state_anchor: SCION-everywhere — host-mode session-open
    /// enrollment shim. Writes an `agent_socket_enrollments` row keyed
    /// on a synthetic socket path so a host-mode session's runtime
    /// persona passes `check_principal_enrollment_strict` (broker.resolve
    /// checkpoint `fail_closed_broker_resolve`) and
    /// `check_principal_against_persona` (uid-binding gate). The
    /// namespace tuple is intentionally NULL — the namespace gate
    /// `check_principal_namespace_inodes` no-ops on all-NULL bindings,
    /// which is the documented carve-out for non-container call sites.
    ///
    /// `peer_uid` is stamped in the same `INSERT` so the broker
    /// gates never observe a row whose binding is half-written; the
    /// existing two-step `seed_socket_enrollment_for_test` pattern
    /// only exists because production code (until now) had no host-
    /// mode writer and the test surface pre-dated this helper.
    ///
    /// Remove once every session opens inside a SCION container
    /// (ADR 140); the SCION path's `enroll_container_persona` writes
    /// the equivalent row with kernel-attested namespace inodes and
    /// is the long-term writer.
    pub fn record_host_mode_socket_enrollment(
        &self,
        socket_path: &str,
        persona_id: &str,
        grant_id: &str,
        peer_uid: Option<u32>,
    ) -> Result<(), StoreError> {
        let enrolled_at = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO agent_socket_enrollments \
                (socket_path, persona_id, grant_id, brief_content_hash, enrolled_at, state, \
                 cgroup_v2_id, userns_inode, mnt_ns_inode, peer_uid) \
             VALUES (?1, ?2, ?3, 'host-mode', ?4, 'active', NULL, NULL, NULL, ?5)",
            rusqlite::params![
                socket_path,
                persona_id,
                grant_id,
                enrolled_at,
                peer_uid.map(|uid| uid as i64),
            ],
        )?;
        Ok(())
    }
}

/// Look up a
/// persona's expected peer uid by consulting the
/// `agent_socket_enrollments` table.
///
/// Single source of truth for the `check_principal_against_persona`
/// gate: the per-agent UDS socket already populates this table at
/// enrollment time, so the broker can compare the live kernel-attested
/// `PeerCredPrincipal.uid` against the recorded `peer_uid`. The
/// per-process `PERSONA_UID_REGISTRY` thread-local was retired when the
/// persona registry collapsed into the enrollment table; see
/// `crates/ember-daemon/src/infra/handler.rs` for the tombstone.
///
/// Resolution order:
///
/// 1. No active enrollment row for `persona_id` → `Ok(None)`. Caller
///    decides whether to refuse or downgrade — preserving the legacy
///    fail-open posture from `check_principal_against_persona` so
///    legacy daemon-internal smoke callers continue to function.
/// 2. Active row exists but `peer_uid` is `NULL` (legacy row recorded
///    before the writer was migrated) → `Ok(None)`. Same fail-open
///    semantics as (1).
/// 3. Active row exists with a non-NULL `peer_uid` → `Ok(Some(uid))`.
///    Multi-row personas (re-enrollment after a tombstone, multiple
///    sockets for the same persona) resolve to the most-recently
///    enrolled active row — the `ORDER BY enrolled_at DESC LIMIT 1`
///    deterministic tie-break.
///
/// Returns `Err(StoreError::Sqlite)` only on a real SQLite error
/// (corrupt db, schema-mismatch, etc.); the no-row and NULL-uid cases
/// are mapped to `Ok(None)` so the caller can apply policy uniformly.
/// Unix epoch seconds — the time base for `presence_challenges` (ADR 200 §3
/// AC-3 nonce TTL). Matches `webauthn_challenges`' epoch-seconds convention.
fn presence_nonce_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn lookup_persona_uid_from_enrollments(
    store: &DaemonStore,
    persona_id: &str,
) -> Result<Option<u32>, StoreError> {
    let result = store.conn.query_row(
        "SELECT peer_uid \
         FROM agent_socket_enrollments \
         WHERE persona_id = ?1 AND state = 'active' \
         ORDER BY enrolled_at DESC \
         LIMIT 1",
        rusqlite::params![persona_id],
        |row| row.get::<_, Option<i64>>(0),
    );
    match result {
        Ok(Some(uid)) if uid >= 0 => Ok(Some(uid as u32)),
        // NULL peer_uid or negative checkpoint — caller falls back to
        // legacy fail-open posture.
        Ok(_) => Ok(None),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(StoreError::Sqlite(e)),
    }
}

impl DaemonStore {
    /// Query the receipts table with the full
    /// [`crate::infra::receipt::ReceiptFilter`] filter set (actor/kind/grant_id/
    /// since_iso/resource/limit). Returns flat [`crate::infra::receipt::ReceiptRow`]
    /// projections so callers get `materialized_at`, `terminal_reason`,
    /// `requested_scope`, and `granted_scope` without re-fetching the grant.
    ///
    /// Delegates to [`DaemonStore::list_receipt_rows`] (defined in
    /// `receipt.rs`). Exposed here so it is co-located with the other
    /// store entry points and discoverable from the `store.rs` index.
    pub fn query_receipts(
        &self,
        filter: &crate::infra::receipt::ReceiptFilter,
    ) -> Result<Vec<crate::infra::receipt::ReceiptRow>, StoreError> {
        self.list_receipt_rows(filter)
    }

    /// Validate an approval state transition.
    ///
    /// Delegates to `core_approval::states::transition` so the transition guard
    /// is the single source of truth in the `core-approval` crate. Errors are
    /// mapped to `StoreError` variants; `StoreError` is local so the
    /// foreign-trait rule is satisfied without a wrapper type.
    ///
    /// Phase C callers replace the embedded `if current_status != "pending"`
    /// string-comparison guard with this fn, which also covers the
    /// scope-narrowing invariant checked by `core_approval::TransitionError::ScopeNotNarrowing`.
    // Phase C wires this into resolve_approval_inner.
    #[allow(dead_code)]
    pub(crate) fn validate_approval_transition(
        state: core_grant_types::approval::ApprovalStatus,
        outcome: &core_approval::ApprovalOutcome,
    ) -> Result<core_grant_types::approval::ApprovalStatus, StoreError> {
        core_approval::states::transition(state, outcome).map_err(|e| match e {
            core_approval::TransitionError::AlreadyDecided => StoreError::AlreadyResolved,
            core_approval::TransitionError::ScopeNotNarrowing => StoreError::InvalidInput(
                "narrowed scope is not a syntactic subset of request scope".into(),
            ),
        })
    }
}

impl crate::signature_verifier::TrustStore for DaemonStore {
    fn list_active_publisher_trusts(
        &self,
    ) -> Result<
        Vec<crate::trust_graph::PublisherTrustDelegation>,
        crate::signature_verifier::TrustStoreError,
    > {
        self.list_active_publisher_trusts()
            .map_err(|e| crate::signature_verifier::TrustStoreError(e.to_string()))
    }

    fn trust_graph_revision(&self) -> u64 {
        self.trust_graph_rev.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_nonce_single_use_and_bound() {
        let store = DaemonStore::open_in_memory().unwrap();
        let (nonce, _exp) = store
            .mint_presence_nonce("op-1", "fp-x", "create_grant", "b3:d1", Some(501), 300)
            .unwrap();

        // Wrong binding fails (and consumes the nonce — DELETE-then-validate).
        let (n2, _) = store
            .mint_presence_nonce("op-2", "fp-x", "create_grant", "b3:d1", Some(501), 300)
            .unwrap();
        assert!(
            store
                .consume_presence_nonce(&n2, "op-WRONG", "fp-x", "create_grant", "b3:d1")
                .is_err()
        );
        // Even the correct binding now fails — the row was tombstoned on the
        // failed attempt (no replay window).
        assert!(
            store
                .consume_presence_nonce(&n2, "op-2", "fp-x", "create_grant", "b3:d1")
                .is_err()
        );

        // Correct binding succeeds exactly once.
        assert!(
            store
                .consume_presence_nonce(&nonce, "op-1", "fp-x", "create_grant", "b3:d1")
                .is_ok()
        );
        // Second consume of the same nonce fails (single-use, AC-3).
        assert!(
            store
                .consume_presence_nonce(&nonce, "op-1", "fp-x", "create_grant", "b3:d1")
                .is_err()
        );
    }

    #[test]
    fn presence_nonce_rejects_params_digest_mismatch() {
        // ADR 206 §1.3 / Finding 1: a nonce minted committing digest-A must NOT
        // consume when the daemon recomputes digest-B over substituted params.
        let store = DaemonStore::open_in_memory().unwrap();
        let (nonce, _) = store
            .mint_presence_nonce(
                "op-d",
                "fp-x",
                "create_grant",
                "b3:read-foo",
                Some(501),
                300,
            )
            .unwrap();
        // Substituted params → different recomputed digest → rejected.
        assert!(
            store
                .consume_presence_nonce(&nonce, "op-d", "fp-x", "create_grant", "b3:admin-all")
                .is_err()
        );
        // And the failed attempt tombstoned the row (no replay even with the
        // correct digest).
        let (nonce2, _) = store
            .mint_presence_nonce(
                "op-d2",
                "fp-x",
                "create_grant",
                "b3:read-foo",
                Some(501),
                300,
            )
            .unwrap();
        assert!(
            store
                .consume_presence_nonce(&nonce2, "op-d2", "fp-x", "create_grant", "b3:read-foo")
                .is_ok(),
            "matching digest must consume"
        );
    }

    #[test]
    fn presence_nonce_expired_is_rejected() {
        let store = DaemonStore::open_in_memory().unwrap();
        // TTL 0 → expires_at == now; the < now check fails it on consume.
        let (nonce, _) = store
            .mint_presence_nonce("op-e", "fp-x", "vault_add", "b3:d1", None, -1)
            .unwrap();
        assert!(
            store
                .consume_presence_nonce(&nonce, "op-e", "fp-x", "vault_add", "b3:d1")
                .is_err()
        );
    }

    #[test]
    fn open_in_memory_succeeds() {
        assert!(DaemonStore::open_in_memory().is_ok());
    }

    #[test]
    fn presence_scope_kek_wraps_round_trip_and_delete() {
        // ADR 206 §4: per-(scope, Device) wrapped scope-KEK storage. UPSERT, list
        // a scope across its Model-C device set, delete on Device retirement, and —
        // the F4 point — scopes are ISOLATED: a tap for one scope lists only its
        // own wraps, never another scope's ("Never one global KEK").
        let store = DaemonStore::open_in_memory().unwrap();
        let (sk, s1) = ("persona", "scope-1");
        let (ok, o2) = ("persona", "scope-2");
        assert!(
            store
                .list_presence_scope_kek_wraps(sk, s1)
                .unwrap()
                .is_empty()
        );

        store
            .write_presence_scope_kek_wrap(sk, s1, "device-a", "ecies-a", b"wrapped-a")
            .unwrap();
        store
            .write_presence_scope_kek_wrap(sk, s1, "device-b", "ecies-b", b"wrapped-b")
            .unwrap();
        // A DIFFERENT scope's wrap for the SAME device must not bleed into scope-1.
        store
            .write_presence_scope_kek_wrap(ok, o2, "device-a", "ecies-x", b"wrapped-x")
            .unwrap();

        let all = store.list_presence_scope_kek_wraps(sk, s1).unwrap();
        assert_eq!(
            all,
            vec![
                (
                    "device-a".to_string(),
                    "ecies-a".to_string(),
                    b"wrapped-a".to_vec()
                ),
                (
                    "device-b".to_string(),
                    "ecies-b".to_string(),
                    b"wrapped-b".to_vec()
                ),
            ],
            "list returns ONLY this scope's wraps (F4: never one global KEK)"
        );

        // UPSERT replaces the blob for an existing (scope, Device).
        store
            .write_presence_scope_kek_wrap(sk, s1, "device-a", "ecies-a2", b"wrapped-a2")
            .unwrap();
        let updated = store.list_presence_scope_kek_wraps(sk, s1).unwrap();
        assert_eq!(updated[0].1, "ecies-a2");
        assert_eq!(updated[0].2, b"wrapped-a2".to_vec());
        assert_eq!(updated.len(), 2, "UPSERT must not add a row");

        // Delete drops only the named (scope, Device) row — other scopes untouched.
        store
            .delete_presence_scope_kek_wrap(sk, s1, "device-a")
            .unwrap();
        let after = store.list_presence_scope_kek_wraps(sk, s1).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].0, "device-b");
        let other_after = store.list_presence_scope_kek_wraps(ok, o2).unwrap();
        assert_eq!(
            other_after.len(),
            1,
            "delete on scope-1 must not touch scope-2"
        );
        assert_eq!(other_after[0].0, "device-a");
    }

    #[test]
    fn presence_scope_kek_old_global_shape_is_clean_break_dropped_on_migrate() {
        // ADR 206 §4 per-scope cutover: a pre-per-scope DB (device_id PRIMARY KEY,
        // no scope_kind) must be detected and clean-break dropped+recreated on
        // migrate() so the per-scope schema installs. Old single-global wraps are
        // discardable (re-provision regenerates them per-scope).
        let store = DaemonStore::open_in_memory().unwrap();

        // Simulate a pre-per-scope DB shape with a stale single-global wrap.
        store
            .conn
            .execute("DROP TABLE presence_scope_kek", [])
            .unwrap();
        store
            .conn
            .execute(
                "CREATE TABLE presence_scope_kek (
                    device_id TEXT PRIMARY KEY,
                    ecies_key_id TEXT NOT NULL,
                    wrapped_kek BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )",
                [],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO presence_scope_kek (device_id, ecies_key_id, wrapped_kek, created_at) \
                 VALUES ('old-dev', 'old-ecies', x'00', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        assert!(
            store.presence_scope_kek_is_pre_per_scope().unwrap(),
            "pre-per-scope shape is detected"
        );

        // migrate() is idempotent; re-running it drops the old-shape table and
        // recreates the per-scope schema (discarding the stale global wrap).
        store.migrate().unwrap();
        assert!(
            !store.presence_scope_kek_is_pre_per_scope().unwrap(),
            "after migrate the table is per-scope"
        );
        assert!(
            store
                .list_presence_scope_kek_wraps("operator", "root-x")
                .unwrap()
                .is_empty(),
            "the stale single-global wrap was discarded (clean break)"
        );
        // Per-scope writes work on the migrated schema.
        store
            .write_presence_scope_kek_wrap("operator", "root-x", "dev", "ecies", b"w")
            .unwrap();
        assert_eq!(
            store
                .list_presence_scope_kek_wraps("operator", "root-x")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn clean_break_nulls_headless_and_canary_then_canary_reseals() {
        // ADR 206 §4 clean-break: at `vault.se_provision` the prior-MEK headless
        // wrap + canary are NULLed (so the next open regenerates headless under
        // KEK_s), then the canary is re-sealed under KEK_s.
        let store = DaemonStore::open_in_memory().unwrap();

        // Seed a prior-MEK headless wrap + canary (the pre-§4 state).
        store
            .write_vault_envelope_meta(b"salt-16-bytes!!!", "params", b"old-canary", b"old-nonce")
            .unwrap();
        store
            .write_headless_mek_wrap(b"h-nonce", b"h-wrapped")
            .unwrap();
        assert!(store.read_vault_canary().unwrap().is_some());
        assert!(store.read_headless_mek_wrap().unwrap().is_some());

        // Clean-break NULLs both the headless wrap and the canary.
        store.clear_headless_and_canary_meta().unwrap();
        assert!(
            store.read_headless_mek_wrap().unwrap().is_none(),
            "clean-break must NULL the prior-MEK headless wrap"
        );
        assert!(
            store.read_vault_canary().unwrap().is_none(),
            "clean-break must NULL the prior-MEK canary"
        );

        // Re-seal the canary under KEK_s (canary-only UPSERT) — the headless
        // wrap stays NULL so the next open regenerates it under KEK_s.
        store
            .write_vault_canary(b"kek-s-canary", b"kek-s-nonce")
            .unwrap();
        assert_eq!(
            store.read_vault_canary().unwrap(),
            Some((b"kek-s-canary".to_vec(), b"kek-s-nonce".to_vec()))
        );
        assert!(
            store.read_headless_mek_wrap().unwrap().is_none(),
            "canary re-seal must not resurrect the headless wrap"
        );
    }

    #[test]
    fn clean_break_on_fresh_vault_meta_is_noop() {
        // A fresh vault has no `vault_meta` row; the clean-break UPDATE must be a
        // harmless no-op (nothing to clear) rather than an error.
        let store = DaemonStore::open_in_memory().unwrap();
        store.clear_headless_and_canary_meta().unwrap();
        assert!(store.read_vault_canary().unwrap().is_none());
    }

    /// Bridge persona cert columns (M1) +
    /// refresh-seq column — verify the
    /// schema migration landed: the `personas` table has
    /// `client_cert_fingerprint` (TEXT NOT NULL DEFAULT ''),
    /// `client_cert_not_after` (INTEGER NOT NULL DEFAULT 0), and
    /// `client_cert_refresh_seq` (INTEGER NOT NULL DEFAULT 0).
    ///
    /// Also verifies idempotency by running `migrate()` a second time and
    /// re-querying — the second call must be a no-op (additive ALTER with
    /// swallowed errors).
    #[test]
    fn personas_table_has_client_cert_columns() {
        let store = DaemonStore::open_in_memory().unwrap();

        // The columns exist on a fresh open.
        let cols = collect_persona_columns(&store);
        let fp = cols
            .iter()
            .find(|c| c.name == "client_cert_fingerprint")
            .expect("client_cert_fingerprint column must exist");
        assert_eq!(fp.col_type, "TEXT");
        assert_eq!(fp.notnull, 1, "client_cert_fingerprint must be NOT NULL");
        assert_eq!(
            fp.default.as_deref(),
            Some("''"),
            "client_cert_fingerprint default must be empty string"
        );

        let not_after = cols
            .iter()
            .find(|c| c.name == "client_cert_not_after")
            .expect("client_cert_not_after column must exist");
        assert_eq!(not_after.col_type, "INTEGER");
        assert_eq!(
            not_after.notnull, 1,
            "client_cert_not_after must be NOT NULL"
        );
        assert_eq!(
            not_after.default.as_deref(),
            Some("0"),
            "client_cert_not_after default must be 0"
        );

        // Third M-series
        // column on the cert refresh chain. Default 0 so legacy rows
        // observe their first refresh as seq=1 via the atomic
        // `UPDATE ... RETURNING` in `DaemonStore::increment_refresh_seq`.
        let refresh_seq = cols
            .iter()
            .find(|c| c.name == "client_cert_refresh_seq")
            .expect("client_cert_refresh_seq column must exist");
        assert_eq!(refresh_seq.col_type, "INTEGER");
        assert_eq!(
            refresh_seq.notnull, 1,
            "client_cert_refresh_seq must be NOT NULL"
        );
        assert_eq!(
            refresh_seq.default.as_deref(),
            Some("0"),
            "client_cert_refresh_seq default must be 0"
        );

        // Re-running migrate() is a no-op — the ALTER calls swallow errors
        // when the column already exists.
        store.migrate().expect("idempotent migrate() must succeed");
        let cols_again = collect_persona_columns(&store);
        assert_eq!(
            cols.len(),
            cols_again.len(),
            "idempotent migrate must not change column count"
        );
    }

    #[derive(Debug)]
    struct PersonaColumn {
        name: String,
        col_type: String,
        notnull: i32,
        default: Option<String>,
    }

    fn collect_persona_columns(store: &DaemonStore) -> Vec<PersonaColumn> {
        collect_columns(store, "personas")
    }

    fn collect_webauthn_credential_columns(store: &DaemonStore) -> Vec<PersonaColumn> {
        collect_columns(store, "webauthn_credentials")
    }

    fn collect_claim_journal_claim_columns(store: &DaemonStore) -> Vec<PersonaColumn> {
        collect_columns(store, "claim_journal_claims")
    }

    fn collect_columns(store: &DaemonStore, table: &str) -> Vec<PersonaColumn> {
        let pragma = format!("PRAGMA table_info({table})");
        let mut stmt = store.conn().prepare(&pragma).unwrap();
        stmt.query_map([], |row| {
            Ok(PersonaColumn {
                name: row.get(1)?,
                col_type: row.get(2)?,
                notnull: row.get(3)?,
                default: row.get(4)?,
            })
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    }

    #[test]
    fn open_creates_tables() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut stmt = store
            .conn()
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap();
        let tables: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let expected = [
            // Per-socket Persona
            // enrollment table keyed by `socket_path`.
            "agent_socket_enrollments",
            "approval_requests",
            "audit_log",
            "claim_journal_claims",
            "claim_journal_scopes",
            "claim_journal_segments",
            "credential_bindings",
            "credentials",
            "grant_chain_secrets",
            "grant_usage",
            "grant_persona_secrets",
            "grants",
            "notifications",
            "personas",
            // ADR 213 AC-7 / ADR 123 §2: installed WoT trust delegations.
            "publisher_trust_delegations",
            "receipts",
            "sandboxes",
            "service_registrations",
            "standing_grants",
            // ADR 158 / SE-sealed vault:
            // single-row table holding the current MEK fingerprint + the
            // ISO-8601 timestamp it was provisioned at. Slice B-bis writes
            // it at first-provision; slice F's diagnose CLI reads it.
            "vault_meta",
            // Server-persisted WebAuthn state.
            "webauthn_credentials",
            "webauthn_challenges",
            // ADR 200 §3 (P23-S2, #5035): single-use presence-authority nonces.
            "presence_challenges",
            // ADR 206 §4 (slice 4): per-Device SE-ECIES-wrapped scope-KEK blobs.
            "presence_scope_kek",
            // ADR 211 Phase 4 / AC-6: SE-wrapped, restart-surviving lease blobs.
            "lease_blobs",
            // ADR 216: daemon wrap keys for double-envelope SE custody.
            "daemon_keys",
        ];
        assert_eq!(tables.len(), expected.len());
        for name in &expected {
            assert!(tables.contains(&name.to_string()), "missing table: {name}");
        }
    }

    #[test]
    fn publisher_trust_delegation_crud() {
        let store = DaemonStore::open_in_memory().unwrap();
        let pk_bytes: [u8; 32] = {
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() {
                *b = (i + 1) as u8;
            }
            s
        };
        let deleg = crate::trust_graph::PublisherTrustDelegation {
            id: "deleg-1".to_string(),
            publisher_did: "did:acme-tools".to_string(),
            pubkey_bytes: pk_bytes,
            valid_from: 0,
            valid_until: None,
            installed_at: 1735689600,
            revoked_at: None,
        };

        store.install_publisher_trust(&deleg).unwrap();

        let all = store.list_publisher_trusts().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].publisher_did, "did:acme-tools");
        assert_eq!(all[0].pubkey_bytes, pk_bytes);

        let active = store.list_active_publisher_trusts().unwrap();
        assert_eq!(active.len(), 1);

        let revoked = store.revoke_publisher_trust("deleg-1", 1735690000).unwrap();
        assert!(revoked);

        let active_after = store.list_active_publisher_trusts().unwrap();
        assert_eq!(active_after.len(), 0);

        let all_after = store.list_publisher_trusts().unwrap();
        assert_eq!(all_after.len(), 1);
        assert!(all_after[0].revoked_at.is_some());

        let double_revoke = store.revoke_publisher_trust("deleg-1", 1735691000).unwrap();
        assert!(
            !double_revoke,
            "already-revoked delegation must return false"
        );
    }

    #[test]
    fn trust_graph_revision_bumps_on_delegation_crud() {
        use crate::signature_verifier::TrustStore;

        let store = DaemonStore::open_in_memory().unwrap();
        let rev0 = store.trust_graph_revision();

        let deleg = crate::trust_graph::PublisherTrustDelegation {
            id: "rev-test".to_string(),
            publisher_did: "did:test".to_string(),
            pubkey_bytes: [1u8; 32],
            valid_from: 0,
            valid_until: None,
            installed_at: 1000,
            revoked_at: None,
        };
        store.install_publisher_trust(&deleg).unwrap();
        let rev1 = store.trust_graph_revision();
        assert_ne!(rev0, rev1, "INSERT must bump revision");

        store.revoke_publisher_trust("rev-test", 2000).unwrap();
        let rev2 = store.trust_graph_revision();
        assert_ne!(rev1, rev2, "UPDATE (revoke) must bump revision");
    }

    #[test]
    fn trust_graph_revision_unaffected_by_other_tables() {
        use crate::signature_verifier::TrustStore;

        let store = DaemonStore::open_in_memory().unwrap();
        let rev0 = store.trust_graph_revision();

        store.test_write_non_trust_table();
        let rev1 = store.trust_graph_revision();
        assert_eq!(
            rev0, rev1,
            "mutation to a different table must NOT bump trust_graph_revision"
        );
    }

    #[test]
    fn install_publisher_trust_rejects_empty_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let deleg = crate::trust_graph::PublisherTrustDelegation {
            id: "".into(),
            publisher_did: "did:test".into(),
            pubkey_bytes: [1u8; 32],
            valid_from: 0,
            valid_until: None,
            installed_at: 1000,
            revoked_at: None,
        };
        let err = store.install_publisher_trust(&deleg).unwrap_err();
        assert!(format!("{err}").contains("empty"), "got: {err}");
    }

    #[test]
    fn install_publisher_trust_rejects_all_zero_pubkey() {
        let store = DaemonStore::open_in_memory().unwrap();
        let deleg = crate::trust_graph::PublisherTrustDelegation {
            id: "zero-pk".into(),
            publisher_did: "did:test".into(),
            pubkey_bytes: [0u8; 32],
            valid_from: 0,
            valid_until: None,
            installed_at: 1000,
            revoked_at: None,
        };
        let err = store.install_publisher_trust(&deleg).unwrap_err();
        assert!(format!("{err}").contains("all-zero"), "got: {err}");
    }

    #[test]
    fn install_publisher_trust_rejects_emberlink_self_delegation() {
        let store = DaemonStore::open_in_memory().unwrap();
        let deleg = crate::trust_graph::PublisherTrustDelegation {
            id: "self-deleg".into(),
            publisher_did: "did:emberlink".into(),
            pubkey_bytes: [1u8; 32],
            valid_from: 0,
            valid_until: None,
            installed_at: 1000,
            revoked_at: None,
        };
        let err = store.install_publisher_trust(&deleg).unwrap_err();
        assert!(format!("{err}").contains("did:emberlink"), "got: {err}");
    }

    #[test]
    fn install_publisher_trust_rejects_inverted_time_window() {
        let store = DaemonStore::open_in_memory().unwrap();
        let deleg = crate::trust_graph::PublisherTrustDelegation {
            id: "inverted".into(),
            publisher_did: "did:test".into(),
            pubkey_bytes: [1u8; 32],
            valid_from: 2000,
            valid_until: Some(1000),
            installed_at: 1000,
            revoked_at: None,
        };
        let err = store.install_publisher_trust(&deleg).unwrap_err();
        assert!(format!("{err}").contains("inverted"), "got: {err}");
    }

    #[test]
    fn list_publisher_trusts_skips_malformed_pubkey_rows() {
        let store = DaemonStore::open_in_memory().unwrap();
        let good = crate::trust_graph::PublisherTrustDelegation {
            id: "good".into(),
            publisher_did: "did:good".into(),
            pubkey_bytes: [1u8; 32],
            valid_from: 0,
            valid_until: None,
            installed_at: 1000,
            revoked_at: None,
        };
        store.install_publisher_trust(&good).unwrap();
        // Bypass Rust + CHECK by recreating table without constraint,
        // simulating a pre-hardening DB with a corrupt row.
        store.conn.execute_batch(
            "CREATE TABLE _ptd_bak AS SELECT * FROM publisher_trust_delegations; \
             DROP TABLE publisher_trust_delegations; \
             CREATE TABLE publisher_trust_delegations ( \
                 id TEXT PRIMARY KEY, publisher_did TEXT NOT NULL, pubkey_bytes BLOB NOT NULL, \
                 valid_from INTEGER NOT NULL, valid_until INTEGER, installed_at INTEGER NOT NULL, revoked_at INTEGER); \
             INSERT INTO publisher_trust_delegations SELECT * FROM _ptd_bak; \
             DROP TABLE _ptd_bak; \
             INSERT INTO publisher_trust_delegations (id, publisher_did, pubkey_bytes, valid_from, installed_at) \
                 VALUES ('bad', 'did:bad', X'CAFE', 0, 2000);",
        ).unwrap();
        let all = store.list_publisher_trusts().unwrap();
        assert_eq!(all.len(), 1, "malformed row must be skipped");
        assert_eq!(all[0].id, "good");
        let active = store.list_active_publisher_trusts().unwrap();
        assert_eq!(
            active.len(),
            1,
            "malformed row must be skipped in active list"
        );
        assert_eq!(active[0].id, "good");
    }

    #[test]
    fn list_publisher_trusts_deterministic_order() {
        let store = DaemonStore::open_in_memory().unwrap();
        for name in ["c", "a", "b"] {
            store
                .conn
                .execute(
                    "INSERT INTO publisher_trust_delegations \
                 (id, publisher_did, pubkey_bytes, valid_from, installed_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![name, "did:test", [1u8; 32].as_slice(), 0i64, 1000i64],
                )
                .unwrap();
        }
        let all = store.list_publisher_trusts().unwrap();
        let ids: Vec<&str> = all.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(
            ids,
            ["a", "b", "c"],
            "same installed_at must tie-break on id"
        );
    }

    #[test]
    fn conn_returns_valid_connection() {
        let store = DaemonStore::open_in_memory().unwrap();
        let result: i64 = store
            .conn()
            .query_row("SELECT 1", [], |row| row.get(0))
            .unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn webauthn_credentials_table_has_daemon_operator_binding_scope_column() {
        let store = DaemonStore::open_in_memory().unwrap();
        let cols = collect_webauthn_credential_columns(&store);
        let names: Vec<&str> = cols.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"binding_scope"),
            "webauthn_credentials must carry binding_scope so operator attesters are not keyed only by persona_id"
        );
        assert!(
            names.contains(&"binding_ref"),
            "webauthn_credentials must carry binding_ref so daemon_operator attesters have an explicit anchor independent of persona_id"
        );
    }

    #[test]
    fn claim_journal_claims_table_has_segmented_rollup_columns() {
        let store = DaemonStore::open_in_memory().unwrap();
        let cols = collect_claim_journal_claim_columns(&store);
        let names: Vec<&str> = cols.iter().map(|c| c.name.as_str()).collect();
        for expected in [
            "scope_kind",
            "scope_id",
            "scope_seq",
            "segment_no",
            "segment_seq",
            "source_key",
            "audit_event_id",
            "claim_kind",
            "tool",
            "action_plugin_address",
            "action_key",
            "action_version",
            "runner_class",
            "execution_domain",
            "materialization_class",
            "legacy_flat",
            "input_hash",
            "input_redacted_json",
            "resolved_json",
            "grant_id",
        ] {
            assert!(
                names.contains(&expected),
                "claim_journal_claims missing required column: {expected}"
            );
        }
    }

    #[test]
    fn service_registrations_table_has_catalog_lifecycle_columns() {
        let store = DaemonStore::open_in_memory().unwrap();
        let cols = collect_columns(&store, "service_registrations");
        let names: Vec<&str> = cols.iter().map(|c| c.name.as_str()).collect();
        for expected in [
            "plugin_address",
            "plugin_version",
            "publisher_id",
            "installed_at",
            "installed_by",
            "state",
            "service_label",
            "install_receipt_hash",
        ] {
            assert!(
                names.contains(&expected),
                "service_registrations missing required column: {expected}"
            );
        }
    }

    #[test]
    fn open_migrates_legacy_claim_journal_rows_to_catalog_substrate_columns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE claim_journal_claims (
                scope_kind TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                scope_seq INTEGER NOT NULL,
                segment_no INTEGER NOT NULL,
                segment_seq INTEGER NOT NULL,
                source_key TEXT NOT NULL,
                audit_event_id INTEGER NOT NULL,
                ts TEXT NOT NULL,
                claim_kind TEXT NOT NULL,
                tool TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                input_redacted_json TEXT NOT NULL,
                resolved_json TEXT NOT NULL,
                persona_id TEXT,
                device_id TEXT,
                delegation_id TEXT,
                materialization_id TEXT,
                credential_name TEXT,
                PRIMARY KEY (scope_kind, scope_id, scope_seq),
                UNIQUE (scope_kind, scope_id, source_key),
                UNIQUE (audit_event_id)
            );
            INSERT INTO claim_journal_claims
                (scope_kind, scope_id, scope_seq, segment_no, segment_seq, source_key, audit_event_id, ts, claim_kind, tool, input_hash, input_redacted_json, resolved_json, persona_id, device_id, delegation_id, materialization_id, credential_name)
            VALUES
                ('session', 'legacy-session', 1, 0, 1, 'src-legacy', 17, '2026-05-22T12:00:00Z', 'credential_vended', 'Claude', 'h-legacy', '{\"cmd\":\"deploy\"}', '{\"allowed\":true}', 'persona-legacy', 'device-legacy', NULL, 'mid-legacy', 'anthropic');",
        )
        .unwrap();
        drop(conn);

        let store = DaemonStore::open(&path).unwrap();
        let cols = collect_claim_journal_claim_columns(&store);
        let names: Vec<&str> = cols.iter().map(|c| c.name.as_str()).collect();
        for expected in [
            "action_plugin_address",
            "action_key",
            "action_version",
            "runner_class",
            "execution_domain",
            "materialization_class",
            "grant_id",
        ] {
            assert!(
                names.contains(&expected),
                "migrated claim_journal_claims missing required column: {expected}"
            );
        }

        let row: (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = store
            .conn()
            .query_row(
                "SELECT tool, action_plugin_address, action_key, action_version, grant_id
                   FROM claim_journal_claims
                  WHERE scope_kind = 'session' AND scope_id = 'legacy-session' AND scope_seq = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row, ("Claude".to_string(), None, None, None, None,));
    }

    #[test]
    fn claim_journal_claims_table_allows_shared_audit_event_backpointers() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut stmt = store
            .conn()
            .prepare("PRAGMA index_list(claim_journal_claims)")
            .unwrap();
        let indexes: Vec<(String, i64)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        for (index_name, is_unique) in indexes {
            if is_unique == 0 {
                continue;
            }
            let pragma = format!("PRAGMA index_info({index_name})");
            let mut info_stmt = store.conn().prepare(&pragma).unwrap();
            let cols: Vec<String> = info_stmt
                .query_map([], |row| row.get::<_, String>(2))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_ne!(
                cols,
                vec!["audit_event_id".to_string()],
                "claim_journal_claims must not globally unique-lock audit_event_id"
            );
        }
    }

    #[test]
    fn shared_vault_slot_propagates_attach_and_drop_across_stores() {
        let primary = DaemonStore::open_in_memory_without_vault().unwrap();
        let secondary = DaemonStore::open_in_memory_without_vault().unwrap();

        let shared_slot = LiveVaultSlot::default();
        primary.replace_vault_slot(shared_slot.clone());
        secondary.replace_vault_slot(shared_slot);

        primary.set_vault(Rc::new(Vault::new([0x11u8; 32])));
        assert!(
            secondary.vault().is_some(),
            "secondary store must observe the shared live-vault attachment"
        );

        secondary.drop_vault();
        assert!(
            primary.vault().is_none(),
            "dropping one store's shared slot must clear the other store too"
        );
    }

    #[test]
    fn shared_lease_kek_propagates_across_stores() {
        let primary = DaemonStore::open_in_memory_without_vault().unwrap();
        let secondary = DaemonStore::open_in_memory_without_vault().unwrap();

        let shared_slot = primary.lease_kek_slot();
        secondary.replace_lease_kek_slot(shared_slot);

        assert!(
            secondary.lease_kek().is_none(),
            "lease-KEK must be None before unlock"
        );

        let kek = crate::trust::lease::LeaseWrapKey::from_raw([0xCCu8; 32]);
        primary.set_lease_kek(kek);

        assert!(
            secondary.lease_kek().is_some(),
            "secondary store must observe the shared lease-KEK after set on primary"
        );
    }

    #[test]
    fn open_file_creates_db() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        assert!(!path.exists());
        DaemonStore::open(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn open_file_is_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("idempotent.db");
        DaemonStore::open(&path).unwrap();
        assert!(DaemonStore::open(&path).is_ok());
    }

    #[test]
    fn log_event_and_query() {
        use crate::infra::audit::AuditFilter;

        let store = DaemonStore::open_in_memory().unwrap();
        store
            .log_event(
                Some("agent-x"),
                "test.action",
                Some("cred-y"),
                "allowed",
                Some("details"),
            )
            .unwrap();

        let entries = store.query_audit(&AuditFilter::default()).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.agent_id.as_deref(), Some("agent-x"));
        assert_eq!(e.action, "test.action");
        assert_eq!(e.credential.as_deref(), Some("cred-y"));
        assert_eq!(e.outcome, "allowed");
        assert_eq!(e.details.as_deref(), Some("details"));
    }

    #[test]
    fn audit_count_reflects_events() {
        let store = DaemonStore::open_in_memory().unwrap();
        let n = 5_u64;
        for i in 0..n {
            store
                .log_event(None, &format!("action-{i}"), None, "ok", None)
                .unwrap();
        }
        assert_eq!(store.audit_count().unwrap(), n);
    }

    #[test]
    fn detect_anomalies_empty_store() {
        let store = DaemonStore::open_in_memory().unwrap();
        let anomalies = store.detect_anomalies().unwrap();
        assert!(anomalies.is_empty());
    }

    #[test]
    fn list_personas_empty() {
        let store = DaemonStore::open_in_memory().unwrap();
        let personas = store.list_personas().unwrap();
        assert!(personas.is_empty());
    }

    #[test]
    fn list_active_grants_empty() {
        let store = DaemonStore::open_in_memory().unwrap();
        let grants = store.list_active_grants().unwrap();
        assert!(grants.is_empty());
    }

    // audit_chain_v2_schema_landed — v2 schema invariant tests.
    // The pre-v2 `recover_audit_chain_tail` tests were deleted per R4 /
    // pass-2 finding #3: the CHECK constraint structurally precludes the
    // half-write input that primitive was designed to clean up, so the
    // primitive is dead code and its tests now violate the CHECK
    // constraint at raw-INSERT time.

    /// audit_chain_v2_schema_landed — the CHECK constraint rejects a
    /// row with `segment_id > 0` that has NULL prev_hash/row_hash and
    /// is not the chain-v1 genesis checkpoint. This is the structural
    /// enforcement that makes the buggy-half-write input (the case
    /// `recover_audit_chain_tail` used to clean up) un-constructible.
    #[test]
    fn audit_log_check_constraint_rejects_unchained_segment_1() {
        let store = DaemonStore::open_in_memory().unwrap();
        let result = store.conn().execute(
            "INSERT INTO audit_log \
             (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash, segment_id, is_segment_genesis) \
             VALUES (?1, NULL, 'grant.create', NULL, 'ok', NULL, NULL, NULL, 1, 0)",
            rusqlite::params!["2026-05-21T00:00:00Z"],
        );
        let err = result.expect_err("CHECK constraint must reject segment_id=1 with NULL hashes");
        let msg = format!("{err}");
        assert!(
            msg.to_uppercase().contains("CHECK") || msg.to_uppercase().contains("CONSTRAINT"),
            "expected CHECK constraint failure, got: {msg}"
        );
    }

    /// audit_chain_v2_schema_landed (R6 / pass-2 finding #6) — the
    /// partial unique index rejects a second `is_segment_genesis = 1`
    /// row within the same segment_id. Composes with the cordon bridge
    /// + repair-tombstone invariant "each segment-genesis opens a NEW
    /// segment."
    #[test]
    fn audit_log_partial_unique_index_rejects_double_genesis() {
        let store = DaemonStore::open_in_memory().unwrap();
        // First segment-1 genesis insert succeeds.
        let h1 = blake3::hash(b"synthetic-bridge-1").to_hex().to_string();
        let genesis_hash = blake3::hash(b"audit.chain_v1_genesis").to_hex().to_string();
        store
            .conn()
            .execute(
                "INSERT INTO audit_log \
                 (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash, segment_id, is_segment_genesis) \
                 VALUES (?1, NULL, 'audit.chain_v1_segment_bridge_unattested', NULL, 'ok', NULL, ?2, ?3, 1, 1)",
                rusqlite::params!["2026-05-21T00:00:01Z", genesis_hash, h1],
            )
            .expect("first segment-1 genesis insert");

        // Second segment-1 genesis insert fails (partial unique index).
        let h2 = blake3::hash(b"synthetic-bridge-2").to_hex().to_string();
        let result = store.conn().execute(
            "INSERT INTO audit_log \
             (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash, segment_id, is_segment_genesis) \
             VALUES (?1, NULL, 'audit.chain_v1_segment_bridge_unattested', NULL, 'ok', NULL, ?2, ?3, 1, 1)",
            rusqlite::params!["2026-05-21T00:00:02Z", genesis_hash, h2],
        );
        let err = result.expect_err("partial unique index must reject second segment-1 genesis");
        let msg = format!("{err}");
        assert!(
            msg.to_uppercase().contains("UNIQUE") || msg.to_uppercase().contains("CONSTRAINT"),
            "expected UNIQUE constraint failure, got: {msg}"
        );
    }

    /// cordon_phase1_recreate_table_landed — synthesize a DB matching the
    /// operator's host shape (1 genesis + N legacy NULL rows + 3 chained
    /// rows past the legacy block). Run the cordon migration. Assert
    /// the legacy block is preserved in segment 0, a bridge row sits at
    /// segment 1, and the chained-tail rows past the legacy block were
    /// destroyed.
    ///
    /// Built against a fresh in-memory store BUT bypasses the migrate()
    /// auto-cordon by manipulating the table back to v1 shape, seeding
    /// the operator's row pattern, then calling
    /// cordon_migration_phase1_if_needed directly.
    #[test]
    fn cordon_migration_recreate_table_on_operators_db_shape() {
        // Use a temp file so the open() backup path exercises against
        // a real file (in-memory has no backup).
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("operator-shape.db");

        // Build the pre-v2 (v1) shape manually so the cordon predicate
        // fires. v1 had prev_hash + row_hash columns but NO segment_id.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT,
                    action TEXT NOT NULL,
                    credential TEXT,
                    outcome TEXT NOT NULL,
                    details TEXT,
                    prev_hash TEXT,
                    row_hash TEXT
                );",
            )
            .unwrap();
            // Genesis at id=1.
            let genesis_hash = blake3::hash(b"audit.chain_v1_genesis").to_hex().to_string();
            conn.execute(
                "INSERT INTO audit_log \
                 (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash) \
                 VALUES (?1, NULL, 'audit.chain_v1_genesis', NULL, 'ok', NULL, NULL, ?2)",
                rusqlite::params!["2026-05-01T00:00:00Z", genesis_hash],
            )
            .unwrap();
            // 5 legacy NULL-NULL rows.
            for i in 0..5 {
                conn.execute(
                    "INSERT INTO audit_log \
                     (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash) \
                     VALUES (?1, NULL, ?2, NULL, 'ok', NULL, NULL, NULL)",
                    rusqlite::params![
                        format!("2026-05-{:02}T00:00:00Z", 2 + i),
                        format!("legacy.event-{}", i),
                    ],
                )
                .unwrap();
            }
            // 3 buggy chained rows past the legacy block (operator's
            // 295/296/297 equivalent).
            for i in 0..3 {
                let fake_hash = blake3::hash(format!("synthetic-tail-{i}").as_bytes())
                    .to_hex()
                    .to_string();
                let prev_hash: Option<String> = if i == 0 {
                    None
                } else {
                    Some(fake_hash.clone())
                };
                conn.execute(
                    "INSERT INTO audit_log \
                     (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash) \
                     VALUES (?1, NULL, ?2, NULL, 'ok', NULL, ?3, ?4)",
                    rusqlite::params![
                        format!("2026-05-{:02}T00:00:00Z", 7 + i),
                        format!("buggy.tail-{}", i),
                        prev_hash,
                        fake_hash,
                    ],
                )
                .unwrap();
            }
        }

        // Open via DaemonStore::open — fires the cordon migration.
        let store = DaemonStore::open(&path).expect("open + cordon migration");

        // Post-migration assertions.
        let total: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap();
        // 1 genesis + 5 legacy + 1 bridge = 7. Buggy-tail rows were destroyed.
        assert_eq!(
            total, 7,
            "post-migration row count must be genesis + legacy + bridge ({total} != 7)"
        );

        let segment_0_count: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE segment_id = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            segment_0_count, 6,
            "segment 0 must carry genesis + 5 legacy"
        );

        let segment_1_count: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE segment_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(segment_1_count, 1, "segment 1 must hold the bridge row");

        let (bridge_action, is_genesis): (String, i64) = store
            .conn()
            .query_row(
                "SELECT action, is_segment_genesis FROM audit_log WHERE segment_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(bridge_action, "audit.chain_v1_segment_bridge_unattested");
        assert_eq!(is_genesis, 1);

        // Pre-cordon backup file was written.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("operator-shape.db.pre-cordon-")
            })
            .collect();
        assert_eq!(entries.len(), 1, "exactly one pre-cordon backup must exist");

        // Idempotency: opening again no-ops the migration.
        drop(store);
        let _reopen = DaemonStore::open(&path).expect("reopen post-migration");
    }

    /// cordon_phase1_receipt_mint_retrofitted — bridge row INSERT and
    /// `audit.chain_v1_segment_bridge_unattested` Receipt v2 append to
    /// `receipts.log` must be atomic across the cordon's BEGIN IMMEDIATE
    /// boundary. With the daemon identity initialised before the cordon
    /// fires, opening a operator-shape DB lands BOTH the bridge row AND a
    /// matching receipt; reopening is a no-op (idempotent — does not
    /// double-mint).
    #[test]
    fn cordon_phase1_mints_receipt_atomically_with_bridge_row() {
        // Set up an isolated data_dir for the daemon identity sidecar
        // so the OnceCell singleton is populated against a fresh key
        // (subsequent #[test] in the suite may have already loaded it).
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("operator.db");

        // Initialise the daemon identity in this data_dir BEFORE the
        // store is opened — mirrors runtime.rs's reordered boot.
        crate::infra::receipt::init_identity(dir.path())
            .expect("init daemon identity for cordon receipt mint test");

        // Build the pre-v2 (v1) operator-shape DB.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT,
                    action TEXT NOT NULL,
                    credential TEXT,
                    outcome TEXT NOT NULL,
                    details TEXT,
                    prev_hash TEXT,
                    row_hash TEXT
                );",
            )
            .unwrap();
            let genesis_hash = blake3::hash(b"audit.chain_v1_genesis").to_hex().to_string();
            conn.execute(
                "INSERT INTO audit_log \
                 (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash) \
                 VALUES (?1, NULL, 'audit.chain_v1_genesis', NULL, 'ok', NULL, NULL, ?2)",
                rusqlite::params!["2026-05-01T00:00:00Z", genesis_hash],
            )
            .unwrap();
            for i in 0..3 {
                conn.execute(
                    "INSERT INTO audit_log \
                     (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash) \
                     VALUES (?1, NULL, ?2, NULL, 'ok', NULL, NULL, NULL)",
                    rusqlite::params![
                        format!("2026-05-{:02}T00:00:00Z", 2 + i),
                        format!("legacy.event-{}", i),
                    ],
                )
                .unwrap();
            }
            // Buggy chained tail past the legacy block to trip the
            // cordon predicate.
            for i in 0..2 {
                let fake = blake3::hash(format!("tail-{i}").as_bytes())
                    .to_hex()
                    .to_string();
                let prev: Option<String> = if i == 0 { None } else { Some(fake.clone()) };
                conn.execute(
                    "INSERT INTO audit_log \
                     (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash) \
                     VALUES (?1, NULL, ?2, NULL, 'ok', NULL, ?3, ?4)",
                    rusqlite::params![
                        format!("2026-05-{:02}T00:00:00Z", 6 + i),
                        format!("buggy.tail-{i}"),
                        prev,
                        fake,
                    ],
                )
                .unwrap();
            }
        }

        // Open via DaemonStore::open — fires the cordon + mints receipt.
        let store = DaemonStore::open(&path).expect("open + cordon + receipt mint");

        // Bridge row landed.
        let (segment_1_count, bridge_action): (i64, String) = store
            .conn()
            .query_row(
                "SELECT COUNT(*), MAX(action) FROM audit_log WHERE segment_id = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    ))
                },
            )
            .unwrap();
        assert_eq!(segment_1_count, 1, "exactly one bridge row at segment_id=1");
        assert_eq!(bridge_action, "audit.chain_v1_segment_bridge_unattested");

        // Receipt landed in receipts.log with the right kind + body.
        let receipts_path = dir.path().join("receipts.log");
        assert!(
            receipts_path.exists(),
            "receipts.log must exist post-cordon"
        );
        let contents = std::fs::read_to_string(&receipts_path).unwrap();
        let bridge_receipt_lines: Vec<&str> = contents
            .lines()
            .filter(|line| line.contains("audit.chain_v1_segment_bridge_unattested"))
            .collect();
        assert_eq!(
            bridge_receipt_lines.len(),
            1,
            "exactly one Phase 1 bridge receipt in receipts.log"
        );
        // Parse and assert envelope shape.
        let envelope: serde_json::Value =
            serde_json::from_str(bridge_receipt_lines[0]).expect("parse bridge receipt envelope");
        assert_eq!(
            envelope["kind"].as_str().unwrap(),
            "audit.chain_v1_segment_bridge_unattested"
        );
        assert!(
            envelope["signature"].is_string(),
            "Phase 1 bridge receipt must be signed by the daemon persona"
        );
        let body = &envelope["body"];
        assert_eq!(
            body["bridge_segment_genesis"]["segment_id"]
                .as_u64()
                .unwrap(),
            1
        );
        let destroyed = body["destroyed_row_ids"]
            .as_array()
            .expect("destroyed_row_ids array");
        assert_eq!(
            destroyed.len(),
            2,
            "destroyed_row_ids must record the 2 buggy-tail rows excluded by the cordon"
        );

        // Idempotency: reopening the same path does NOT re-mint the
        // receipt (cordon migration is gated on segment_id-column
        // existence per `cordon_migration_phase1_if_needed`).
        drop(store);
        let _reopen = DaemonStore::open(&path).expect("reopen post-migration");
        let contents2 = std::fs::read_to_string(&receipts_path).unwrap();
        let bridge_receipt_lines2: Vec<&str> = contents2
            .lines()
            .filter(|line| line.contains("audit.chain_v1_segment_bridge_unattested"))
            .collect();
        assert_eq!(
            bridge_receipt_lines2.len(),
            1,
            "reopening must NOT double-mint the bridge receipt (idempotency)"
        );
    }

    /// cordon_phase1_receipt_backfill_landed — Part 2/3 retrofit. A host
    /// that cordoned under pre-#4435 code has a bridge row in `audit_log`
    /// but NO `_unattested` receipt in `receipts.log` (the file may not
    /// even exist). Reopening the store must detect the missing receipt
    /// and back-fill it from the bridge row's stored fields, creating
    /// `receipts.log` (mode 0600) if absent — and must do so on the
    /// already-cordoned early-return path (before any startup verify).
    #[test]
    fn cordon_backfill_remints_receipt_for_already_cordoned_host() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("operator.db");
        crate::infra::receipt::init_identity(dir.path())
            .expect("init daemon identity for cordon backfill test");

        // Build pre-v2 operator-shape DB (genesis + legacy block + buggy tail).
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT,
                    action TEXT NOT NULL,
                    credential TEXT,
                    outcome TEXT NOT NULL,
                    details TEXT,
                    prev_hash TEXT,
                    row_hash TEXT
                );",
            )
            .unwrap();
            let genesis_hash = blake3::hash(b"audit.chain_v1_genesis").to_hex().to_string();
            conn.execute(
                "INSERT INTO audit_log \
                 (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash) \
                 VALUES (?1, NULL, 'audit.chain_v1_genesis', NULL, 'ok', NULL, NULL, ?2)",
                rusqlite::params!["2026-05-01T00:00:00Z", genesis_hash],
            )
            .unwrap();
            for i in 0..3 {
                conn.execute(
                    "INSERT INTO audit_log \
                     (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash) \
                     VALUES (?1, NULL, ?2, NULL, 'ok', NULL, NULL, NULL)",
                    rusqlite::params![
                        format!("2026-05-{:02}T00:00:00Z", 2 + i),
                        format!("legacy.event-{}", i),
                    ],
                )
                .unwrap();
            }
            for i in 0..2 {
                let fake = blake3::hash(format!("tail-{i}").as_bytes())
                    .to_hex()
                    .to_string();
                let prev: Option<String> = if i == 0 { None } else { Some(fake.clone()) };
                conn.execute(
                    "INSERT INTO audit_log \
                     (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash) \
                     VALUES (?1, NULL, ?2, NULL, 'ok', NULL, ?3, ?4)",
                    rusqlite::params![
                        format!("2026-05-{:02}T00:00:00Z", 6 + i),
                        format!("buggy.tail-{i}"),
                        prev,
                        fake,
                    ],
                )
                .unwrap();
            }
        }

        // First open: forward cordon fires + mints the receipt.
        let store = DaemonStore::open(&path).expect("open + cordon");
        let receipts_path = dir.path().join("receipts.log");
        assert!(receipts_path.exists(), "forward mint creates receipts.log");
        // Capture the bridge row's row_hash so we can match the backfilled receipt.
        let bridge_row_hash: String = store
            .conn()
            .query_row(
                "SELECT row_hash FROM audit_log \
                 WHERE action = 'audit.chain_v1_segment_bridge_unattested' \
                   AND segment_id = 1 AND is_segment_genesis = 1",
                [],
                |row| {
                    row.get::<_, Option<String>>(0)
                        .map(|h| h.unwrap_or_default())
                },
            )
            .unwrap();
        assert!(!bridge_row_hash.is_empty(), "bridge row has a row_hash");

        // Simulate the operator's already-cordoned host: the bridge row is
        // in audit_log (segment_id column present) but receipts.log is
        // gone (cordoned under pre-#4435 code that never minted it).
        drop(store);
        std::fs::remove_file(&receipts_path).expect("delete receipts.log");
        assert!(!receipts_path.exists());

        // Reopen: the already-cordoned early-return path must back-fill.
        let _reopen = DaemonStore::open(&path).expect("reopen + backfill");
        assert!(
            receipts_path.exists(),
            "backfill must recreate receipts.log on the already-cordoned host"
        );
        // Part 3: file mode is 0600.
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&receipts_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "receipts.log must be 0600, got {mode:#o}");
        }
        let contents = std::fs::read_to_string(&receipts_path).unwrap();
        let lines: Vec<&str> = contents
            .lines()
            .filter(|l| l.contains("audit.chain_v1_segment_bridge_unattested"))
            .collect();
        assert_eq!(lines.len(), 1, "exactly one backfilled bridge receipt");
        let env: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(
            env["body"]["bridge_segment_genesis"]["row_hash"]
                .as_str()
                .unwrap(),
            bridge_row_hash,
            "backfilled receipt must anchor the in-DB bridge row by hash"
        );
        assert!(env["signature"].is_string(), "backfilled receipt is signed");

        // Idempotency: a third open does NOT double-mint.
        let _reopen2 = DaemonStore::open(&path).expect("third open");
        let contents2 = std::fs::read_to_string(&receipts_path).unwrap();
        let lines2 = contents2
            .lines()
            .filter(|l| l.contains("audit.chain_v1_segment_bridge_unattested"))
            .count();
        assert_eq!(lines2, 1, "backfill must be idempotent (no double-mint)");
    }

    /// cordon_phase1_recreate_table_landed — on a fresh DB the cordon
    /// predicate's "chained rows past legacy block" clause is false, so
    /// Phase 1 no-ops. The daemon writes happily into segment_id = 0.
    #[test]
    fn cordon_migration_noop_on_fresh_db() {
        let store = DaemonStore::open_in_memory().unwrap();
        // Only the genesis row exists.
        let total: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total, 1);
        let segment_id: i64 = store
            .conn()
            .query_row(
                "SELECT segment_id FROM audit_log WHERE action = 'audit.chain_v1_genesis'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(segment_id, 0);

        // Write a chained event — lands in segment 0.
        crate::infra::audit::append_audit_event_with_chain(
            &store,
            None,
            "grant.create",
            None,
            "ok",
            None,
        )
        .unwrap();
        let (sid, sg): (i64, i64) = store
            .conn()
            .query_row(
                "SELECT segment_id, is_segment_genesis FROM audit_log WHERE action = 'grant.create'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(sid, 0, "fresh-DB chained writes go into segment 0");
        assert_eq!(sg, 0, "chain extensions are NOT segment-genesis");
    }

    #[test]
    fn agent_socket_enrollment_namespace_inodes_round_trip_none() {
        let store = DaemonStore::open_in_memory().unwrap();
        store
            .record_agent_socket_enrollment(
                "/run/emberd/agent-test.sock",
                "persona-test",
                "grant-test",
                "hash-test",
                None,
                None,
                None,
            )
            .unwrap();
        let row = store
            .lookup_agent_socket_enrollment("/run/emberd/agent-test.sock")
            .unwrap()
            .expect("inserted enrollment must resolve");
        // Legacy / non-Linux call sites pass None on all three.
        assert_eq!(row.cgroup_v2_id, None);
        assert_eq!(row.userns_inode, None);
        assert_eq!(row.mnt_ns_inode, None);
    }

    #[test]
    fn agent_socket_enrollment_namespace_inodes_round_trip_some() {
        let store = DaemonStore::open_in_memory().unwrap();
        store
            .record_agent_socket_enrollment(
                "/run/emberd/agent-test-some.sock",
                "persona-test",
                "grant-test",
                "hash-test",
                Some(987654321),
                Some(4026531840),
                Some(4026531841),
            )
            .unwrap();
        let row = store
            .lookup_agent_socket_enrollment("/run/emberd/agent-test-some.sock")
            .unwrap()
            .expect("inserted enrollment must resolve");
        // The binding tuple round-
        // trips through SQLite intact.
        assert_eq!(row.cgroup_v2_id, Some(987654321));
        assert_eq!(row.userns_inode, Some(4026531840));
        assert_eq!(row.mnt_ns_inode, Some(4026531841));
    }

    // Unit
    // tests on `lookup_persona_uid_from_enrollments`. The helper is the
    // seam between the broker's `check_principal_against_persona` gate
    // and the per-agent UDS enrollment table; Step A only wires the
    // reader path, so tests seed `peer_uid` directly via SQL until Step
    // B migrates the writer signature.

    /// Helper-side test seam: stamp `peer_uid` onto an existing
    /// `agent_socket_enrollments` row by socket_path. Step B will
    /// thread `peer_uid` through `record_agent_socket_enrollment`;
    /// until then, tests use this to exercise the reader's new column
    /// without touching the writer signature.
    fn seed_peer_uid_for_test(store: &DaemonStore, socket_path: &str, peer_uid: u32) {
        store
            .conn()
            .execute(
                "UPDATE agent_socket_enrollments SET peer_uid = ?1 WHERE socket_path = ?2",
                rusqlite::params![peer_uid as i64, socket_path],
            )
            .expect("seed peer_uid for test");
    }

    /// Row-exists-with-peer-uid → `Ok(Some(uid))`. The happy path: an
    /// active enrollment with a populated `peer_uid` column resolves
    /// to that uid.
    #[test]
    fn lookup_persona_uid_from_enrollments_returns_some_when_row_present() {
        let store = DaemonStore::open_in_memory().unwrap();
        let socket_path = "/run/emberd/agent-uid-some.sock";
        let persona_id = "persona-uid-some";
        store
            .record_agent_socket_enrollment(
                socket_path,
                persona_id,
                "grant-uid-some",
                "hash-uid-some",
                None,
                None,
                None,
            )
            .unwrap();
        seed_peer_uid_for_test(&store, socket_path, 4242);

        let resolved =
            lookup_persona_uid_from_enrollments(&store, persona_id).expect("lookup must succeed");
        assert_eq!(
            resolved,
            Some(4242),
            "active enrollment with peer_uid must resolve to that uid"
        );
    }

    /// No-row → `Ok(None)`. A persona with no enrollment surface
    /// returns None; caller falls back to the legacy fail-open
    /// posture (no refusal).
    #[test]
    fn lookup_persona_uid_from_enrollments_returns_none_when_row_absent() {
        let store = DaemonStore::open_in_memory().unwrap();
        let resolved = lookup_persona_uid_from_enrollments(&store, "persona-with-no-enrollment")
            .expect("lookup must succeed");
        assert_eq!(
            resolved, None,
            "no enrollment row → None (legacy fail-open posture)"
        );
    }

    /// Row-exists-but-NULL-peer_uid → `Ok(None)`. Pre-Step-B legacy
    /// rows recorded before the writer was migrated carry NULL in
    /// the new column; the reader maps NULL to None so the caller's
    /// fail-open posture is preserved during the transition.
    #[test]
    fn lookup_persona_uid_from_enrollments_returns_none_when_peer_uid_null() {
        let store = DaemonStore::open_in_memory().unwrap();
        let persona_id = "persona-null-peer-uid";
        store
            .record_agent_socket_enrollment(
                "/run/emberd/agent-uid-null.sock",
                persona_id,
                "grant-uid-null",
                "hash-uid-null",
                None,
                None,
                None,
            )
            .unwrap();
        // `record_agent_socket_enrollment` does not yet populate
        // `peer_uid` (Step B). Row exists but column is NULL.

        let resolved =
            lookup_persona_uid_from_enrollments(&store, persona_id).expect("lookup must succeed");
        assert_eq!(
            resolved, None,
            "row with NULL peer_uid must resolve to None"
        );
    }

    /// Multi-row → returns the most-recent (`ORDER BY enrolled_at
    /// DESC LIMIT 1`). A persona that's been re-enrolled across
    /// multiple sockets resolves to the most-recent active row, so
    /// the latest binding wins.
    #[test]
    fn lookup_persona_uid_from_enrollments_returns_most_recent_when_multi_row() {
        let store = DaemonStore::open_in_memory().unwrap();
        let persona_id = "persona-multi-enrollment";

        // First enrollment — older.
        store
            .record_agent_socket_enrollment(
                "/run/emberd/agent-multi-1.sock",
                persona_id,
                "grant-multi-1",
                "hash-multi-1",
                None,
                None,
                None,
            )
            .unwrap();
        seed_peer_uid_for_test(&store, "/run/emberd/agent-multi-1.sock", 1001);
        // Pin the older row's enrolled_at to an earlier timestamp so
        // the DESC ordering is deterministic regardless of wall-clock
        // resolution.
        store
            .conn()
            .execute(
                "UPDATE agent_socket_enrollments SET enrolled_at = ?1 WHERE socket_path = ?2",
                rusqlite::params!["2026-01-01T00:00:00Z", "/run/emberd/agent-multi-1.sock"],
            )
            .expect("backdate older enrollment");

        // Second enrollment — newer.
        store
            .record_agent_socket_enrollment(
                "/run/emberd/agent-multi-2.sock",
                persona_id,
                "grant-multi-2",
                "hash-multi-2",
                None,
                None,
                None,
            )
            .unwrap();
        seed_peer_uid_for_test(&store, "/run/emberd/agent-multi-2.sock", 2002);
        store
            .conn()
            .execute(
                "UPDATE agent_socket_enrollments SET enrolled_at = ?1 WHERE socket_path = ?2",
                rusqlite::params!["2026-05-01T00:00:00Z", "/run/emberd/agent-multi-2.sock"],
            )
            .expect("forward-date newer enrollment");

        let resolved =
            lookup_persona_uid_from_enrollments(&store, persona_id).expect("lookup must succeed");
        assert_eq!(
            resolved,
            Some(2002),
            "multi-row persona must resolve to the most-recent enrolled_at"
        );
    }

    /// Revoked rows are filtered out — only `state = 'active'`
    /// enrollments resolve. A revoked row, even with a populated
    /// peer_uid, must not produce a binding.
    #[test]
    fn lookup_persona_uid_from_enrollments_skips_revoked_rows() {
        let store = DaemonStore::open_in_memory().unwrap();
        let persona_id = "persona-revoked-enrollment";
        let socket_path = "/run/emberd/agent-uid-revoked.sock";
        store
            .record_agent_socket_enrollment(
                socket_path,
                persona_id,
                "grant-uid-revoked",
                "hash-uid-revoked",
                None,
                None,
                None,
            )
            .unwrap();
        seed_peer_uid_for_test(&store, socket_path, 9999);
        store
            .revoke_agent_socket_enrollment(socket_path)
            .expect("revoke");

        let resolved =
            lookup_persona_uid_from_enrollments(&store, persona_id).expect("lookup must succeed");
        assert_eq!(
            resolved, None,
            "revoked enrollment must not produce a binding"
        );
    }

    // mek_missing_with_state_refuses_start helper tests.

    #[test]
    fn has_state_bearing_rows_returns_false_for_empty_store() {
        let store = DaemonStore::open_in_memory_without_vault().expect("open");
        let has = store.has_state_bearing_rows().expect("probe");
        assert!(!has, "fresh in-memory store must report empty");
    }

    // mek_fingerprint_column_verified tests.

    #[test]
    fn read_mek_fingerprint_returns_none_on_fresh_store() {
        let store = DaemonStore::open_in_memory_without_vault().expect("open");
        let fp = store.read_mek_fingerprint().expect("read");
        assert!(fp.is_none(), "fresh store must have no fingerprint");
    }

    #[test]
    fn read_double_envelope_outer_returns_none_for_null_legacy_row() {
        let store = DaemonStore::open_in_memory_without_vault().expect("open");
        store
            .conn
            .execute(
                "INSERT INTO vault_meta (id, mek_fingerprint, provisioned_at) \
                 VALUES (1, 'legacy-fingerprint', '2026-06-16T00:00:00Z')",
                [],
            )
            .expect("seed legacy vault_meta row");

        let outer = store.read_double_envelope_outer().expect("read");
        assert!(
            outer.is_none(),
            "NULL double-envelope outer blob means unprovisioned, not corrupt"
        );
    }

    #[test]
    fn double_envelope_outer_round_trips() {
        let store = DaemonStore::open_in_memory_without_vault().expect("open");
        let expected = b"double-envelope-outer".to_vec();

        store.write_double_envelope_outer(&expected).expect("write");

        let got = store.read_double_envelope_outer().expect("read");
        assert_eq!(got, Some(expected));
    }

    #[test]
    fn write_mek_fingerprint_round_trips() {
        let store = DaemonStore::open_in_memory_without_vault().expect("open");
        let expected = "feedfaceabba0000feedfaceabba0001feedfaceabba0002feedfaceabba0003";
        store.write_mek_fingerprint(expected).expect("write");
        let got = store.read_mek_fingerprint().expect("read");
        assert_eq!(got.as_deref(), Some(expected));
    }

    #[test]
    fn write_mek_fingerprint_same_value_is_idempotent() {
        let store = DaemonStore::open_in_memory_without_vault().expect("open");
        let value = "deadbeef".repeat(8);
        store.write_mek_fingerprint(&value).expect("first write");
        // Second write with the same value is idempotent (UPSERT updates provisioned_at).
        store.write_mek_fingerprint(&value).expect("second write");
        let got = store.read_mek_fingerprint().expect("read");
        assert_eq!(got.as_deref(), Some(value.as_str()));
    }

    #[test]
    fn write_mek_fingerprint_mismatch_is_advisory_write_through() {
        // ADR 198 D3 (shipped in P14-S6a, #4958): the `mek_fingerprint` is
        // demoted to an advisory pre-flight. A mismatch is logged at `warn!`
        // and the NEW value is written through — it is NOT a fault. The AEAD
        // canary (`Vault::verify_canary`), not this blake3 string-compare, is
        // the key-correctness authority. (Prior to the demotion this test
        // asserted an error; the assertion is updated to the shipped contract
        // — the demotion left this test stale/red on main.)
        let store = DaemonStore::open_in_memory_without_vault().expect("open");
        let first = "cafebabe".repeat(8);
        let second = "12345678".repeat(8);
        store.write_mek_fingerprint(&first).expect("first write");
        store
            .write_mek_fingerprint(&second)
            .expect("mismatched fingerprint write is advisory (write-through), not an error");
        // New fingerprint persisted (advisory pre-flight, not a fault gate).
        let got = store.read_mek_fingerprint().expect("read");
        assert_eq!(got.as_deref(), Some(second.as_str()));
    }

    #[test]
    fn has_state_bearing_rows_returns_true_when_credentials_exist() {
        let store = DaemonStore::open_in_memory_without_vault().expect("open");
        // Insert a single credential row — the lowest-level state proxy.
        store
            .conn
            .execute(
                "INSERT INTO credentials (id, name, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?, ?)",
                rusqlite::params![
                    "cred-test-1",
                    "test-cred",
                    b"nonce-bytes-24-chars-xyzab" as &[u8],
                    b"opaque-ciphertext" as &[u8],
                    "2026-05-20T00:00:00Z"
                ],
            )
            .expect("insert credential");
        let has = store.has_state_bearing_rows().expect("probe");
        assert!(has, "store with one credential row must report has_state");
    }
}
