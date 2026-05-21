use std::cell::RefCell;
use std::collections::HashSet;
use std::path::Path;
use std::rc::Rc;

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
    /// can identify which writer was refused. Per design v2 §1 +
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
    /// implementation-note-279 Phase 2: in-memory rate-limit set for the
    /// `sops_unwrap_dek` RPC. Each grant_id is consumed exactly once per
    /// daemon-process lifetime. The set is intentionally non-persistent —
    /// daemon restart clears it (acceptable: a restart-then-replay attack
    /// requires the operator to also resurrect a still-active grant on the
    /// SAME id, which is not a realistic threat in v0).
    ///
    /// Single-threaded LocalSet semantics: same as `vault`. No cross-thread
    /// races possible.
    consumed_dek_grants: RefCell<HashSet<String>>,
    /// implementation-note-71: cached
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
        let store = Self {
            conn,
            vault_slot: RefCell::new(LiveVaultSlot::default()),
            consumed_dek_grants: RefCell::new(HashSet::new()),
            bridge_ca_fingerprint: RefCell::new(None),
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
    fn pre_cordon_backup_if_needed(path: &Path) -> Result<Option<std::path::PathBuf>, std::io::Error> {
        // No existing file? Fresh install, nothing to back up.
        if !path.exists() {
            return Ok(None);
        }
        // Probe the DB without rusqlite (lightweight): open a read-only
        // connection, check for segment_id column. If it already exists,
        // the cordon won't run, so no backup is needed.
        let probe = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        );
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
        let store = Self {
            conn,
            vault_slot: RefCell::new(LiveVaultSlot::default()),
            consumed_dek_grants: RefCell::new(HashSet::new()),
            bridge_ca_fingerprint: RefCell::new(None),
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
        let store = Self {
            conn,
            vault_slot: RefCell::new(LiveVaultSlot::default()),
            consumed_dek_grants: RefCell::new(HashSet::new()),
            bridge_ca_fingerprint: RefCell::new(None),
        };
        store.migrate()?;
        Ok(store)
    }

    /// implementation-note-279 Phase 2: claim a `grant_id` slot for a
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

    /// implementation-note-71: attach the
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

    /// implementation-note-33 C2: drop the attached `Rc<Vault>` so the
    /// final outstanding reference is released — the MEK is wiped via
    /// `ZeroizeOnDrop` once every clone of the `Rc` has dropped. Called
    /// from `trust::presence::lock()` (explicit user-initiated lock) so
    /// the daemon enters hard-lock semantics: the next vault op MUST
    /// re-derive the MEK from the keyring-stored passphrase.
    ///
    /// Idle auto-lock does NOT call this — it retains soft-lock so
    /// background headless survives the idle window without forcing a
    /// re-prompt.
    pub fn drop_vault(&self) {
        self.vault_slot.borrow().clear();
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// mek_fingerprint_column_verified — read the plaintext
    /// blake3(MEK) fingerprint from vault_meta. Returns `None` if not
    /// yet written (first-run pre-MEK-provision or pre-slice-B-bis).
    /// Per implementation-note-341.
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
    /// blake3(MEK) fingerprint to vault_meta. UPSERT semantics: if a
    /// fingerprint is already present and differs from the supplied
    /// value, returns an error (mismatch — caller must surface to the
    /// startup-probe fail-loud path). Per
    /// implementation-note-341.
    pub fn write_mek_fingerprint(&self, fingerprint_hex: &str) -> Result<(), StoreError> {
        let existing = self.read_mek_fingerprint()?;
        if let Some(prev) = &existing
            && prev != fingerprint_hex {
                return Err(StoreError::InvalidInput(format!(
                    "MEK fingerprint mismatch: recorded={prev} attempted={fingerprint_hex}"
                )));
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

    /// mek_missing_with_state_refuses_start helper
    /// (implementation-note-327).
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
    /// per design v2 + design review 20260521-134520 R2/R5/R7. No-op on:
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

        let cordon_predicate_fires =
            legacy_null_count > 0 && chained_past_genesis > 0;

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
        let boundary_id = first_non_null_after_genesis
            .ok_or_else(|| StoreError::InvalidInput(
                "cordon predicate fired but no non-NULL chained row past genesis exists".into()
            ))?;

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
                metadata TEXT
            );

            -- audit_chain_v2_schema_landed (implementation-note-342).
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
                -- implementation-note-10:
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

            -- implementation-note-105: server-persisted WebAuthn credentials.
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
                last_used_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_persona
                ON webauthn_credentials(persona_id);

            -- implementation-note-105: in-flight WebAuthn ceremony state.
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

            -- credential_bindings_table_schema — implementation-note-343
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

        // implementation-note-60 — backfill `kind` column on legacy DBs so
        // the kms_wrap / kms_unwrap rows can land alongside grant rows.
        // Errors swallowed when the column already exists.
        let _ = self.conn.execute(
            "ALTER TABLE receipts ADD COLUMN kind TEXT NOT NULL DEFAULT 'grant'",
            [],
        );

        // implementation-note-60 — per-key fast-path index for queries shaped
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

        // EMBER-implementation-note-270 — per-actor and per-resource fast-path indexes
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

        // implementation-note-226 — composite-grant approval columns. Existing v0 DBs
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

        // implementation-note-268 — per-statement revocation list.
        // Stores a JSON array of revoked Statement sids ("S0", "S1", ...) so
        // the demo can revoke a single Statement without taking down the
        // whole grant. Default `'[]'` keeps the column non-null on legacy
        // rows. Errors swallowed when the column already exists.
        let _ = self.conn.execute(
            "ALTER TABLE grants ADD COLUMN revoked_sids_json TEXT NOT NULL DEFAULT '[]'",
            [],
        );

        // approval_notify_fields_persisted — design Phase C-1 NOTIF-1 fields.
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

        // COMPOSITE-prior change-TESTS-DASHBOARD — skill_ref advisory pointer from
        // GrantProposal. Persisted so the dashboard approval card can surface
        // which Construct/skill originated the proposal. Nullable: pre-existing
        // rows stay NULL; only proposals submitted with GrantProposal.skill_ref
        // set will populate this column.
        let _ = self.conn.execute(
            "ALTER TABLE approval_requests ADD COLUMN skill_ref TEXT",
            [],
        );

        // implementation-note-10 — grant-
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

        // implementation-note-64 (design §9 + §6) — bind a
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

        // implementation-note-344 (M1 of design, Bridge
        // Cert Refresh Protocol). Per-persona client-certificate state for
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
        //   the `bridge.cert_refreshed` Receipt body (design Extension
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

        // implementation-note-264 (design §"In-container
        // extension") — per-socket Persona enrollment table. At spawn
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

        // implementation-note-345 Step A — namespace-inode columns on
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

        // implementation-note-289 — peer_uid
        // column on agent_socket_enrollments. Carries the kernel-attested
        // uid the per-agent UDS socket was bound to at spawn time so the
        // broker's `check_principal_against_persona` gate can compare the
        // live `PeerCredPrincipal.uid` against the enrollment row. The
        // in-process `PERSONA_UID_REGISTRY` thread-local was retired in
        // implementation-note-151; the
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

        // cordon_phase1_recreate_table_landed (implementation-note-346-
        // CORDON-PHASE1) — promote a v1 DB (chain columns but no segment_id)
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

        // mek_fingerprint_column_verified
        // (implementation-note-341).
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

        Ok(())
    }
}

/// implementation-note-264 (design §"In-container
/// extension") — projection of an `agent_socket_enrollments` row.
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
    /// implementation-note-345 Step A — cgroup v2 leaf inode for
    /// the worker container (Step B populates; Step C gates dispatch).
    /// NULL for legacy/host-resident enrollments.
    pub cgroup_v2_id: Option<i64>,
    /// implementation-note-345 Step A — user-namespace inode.
    pub userns_inode: Option<i64>,
    /// implementation-note-345 Step A — mount-namespace inode.
    pub mnt_ns_inode: Option<i64>,
}

impl DaemonStore {
    /// implementation-note-264 — record a fresh per-socket
    /// Persona enrollment.
    ///
    /// Called at agent-spawn time by the scion spawn pipeline once a
    /// per-agent UDS socket has been created at `/run/emberd/agent-
    /// <uuid>.sock`. The `(socket_path, persona_id, grant_id,
    /// brief_content_hash)` quadruple is the kernel-attested identity
    /// substrate for every subsequent RPC on that socket — the handler
    /// reads from this table rather than trusting wire-claimed
    /// `caller_persona_id` / `caller_grant_id` per design.
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
        // implementation-note-347 — the three Option<i64>
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

    /// implementation-note-264 — resolve the Persona
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

    /// implementation-note-264 — tombstone an enrollment.
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
}

/// implementation-note-289 — look up a
/// persona's expected peer uid by consulting the
/// `agent_socket_enrollments` table.
///
/// Single source of truth for the `check_principal_against_persona`
/// gate: the per-agent UDS socket already populates this table at
/// enrollment time, so the broker can compare the live kernel-attested
/// `PeerCredPrincipal.uid` against the recorded `peer_uid`. The
/// per-process `PERSONA_UID_REGISTRY` thread-local was retired in
/// implementation-note-151; see
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
    /// EMBER-implementation-note-270 — query the receipts table with the full
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
    // implementation-note-348 wires this into resolve_approval_inner.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_succeeds() {
        assert!(DaemonStore::open_in_memory().is_ok());
    }

    /// implementation-note-344 (M1) +
    /// implementation-note-296 — verify the
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

        // implementation-note-296 — third M-series
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
        let mut stmt = store.conn().prepare("PRAGMA table_info(personas)").unwrap();
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
            // implementation-note-264: per-socket Persona
            // enrollment table keyed by `socket_path`.
            "agent_socket_enrollments",
            "approval_requests",
            "audit_log",
            "credential_bindings",
            "credentials",
            "grant_usage",
            "grants",
            "notifications",
            "personas",
            "receipts",
            "sandboxes",
            "standing_grants",
            // implementation-note-349-* (design / SE-sealed vault):
            // single-row table holding the current MEK fingerprint + the
            // ISO-8601 timestamp it was provisioned at. Slice B-bis writes
            // it at first-provision; slice F's diagnose CLI reads it.
            "vault_meta",
            // implementation-note-105: server-persisted WebAuthn state.
            "webauthn_credentials",
            "webauthn_challenges",
        ];
        assert_eq!(tables.len(), 15);
        for name in &expected {
            assert!(tables.contains(&name.to_string()), "missing table: {name}");
        }
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
                let prev_hash: Option<String> = if i == 0 { None } else { Some(fake_hash.clone()) };
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
        assert_eq!(segment_0_count, 6, "segment 0 must carry genesis + 5 legacy");

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
        assert_eq!(
            entries.len(),
            1,
            "exactly one pre-cordon backup must exist"
        );

        // Idempotency: opening again no-ops the migration.
        drop(store);
        let _reopen = DaemonStore::open(&path).expect("reopen post-migration");
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
        // implementation-note-347 — the binding tuple round-
        // trips through SQLite intact.
        assert_eq!(row.cgroup_v2_id, Some(987654321));
        assert_eq!(row.userns_inode, Some(4026531840));
        assert_eq!(row.mnt_ns_inode, Some(4026531841));
    }

    // implementation-note-289 — T1 unit
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

    // mek_missing_with_state_refuses_start helper tests
    // (implementation-note-327).

    #[test]
    fn has_state_bearing_rows_returns_false_for_empty_store() {
        let store = DaemonStore::open_in_memory_without_vault().expect("open");
        let has = store.has_state_bearing_rows().expect("probe");
        assert!(!has, "fresh in-memory store must report empty");
    }

    // mek_fingerprint_column_verified tests
    // (implementation-note-341).

    #[test]
    fn read_mek_fingerprint_returns_none_on_fresh_store() {
        let store = DaemonStore::open_in_memory_without_vault().expect("open");
        let fp = store.read_mek_fingerprint().expect("read");
        assert!(fp.is_none(), "fresh store must have no fingerprint");
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
    fn write_mek_fingerprint_mismatch_errors() {
        let store = DaemonStore::open_in_memory_without_vault().expect("open");
        let first = "cafebabe".repeat(8);
        let second = "12345678".repeat(8);
        store.write_mek_fingerprint(&first).expect("first write");
        let result = store.write_mek_fingerprint(&second);
        assert!(
            matches!(result, Err(StoreError::InvalidInput(_))),
            "mismatched fingerprint write must error; got: {result:?}"
        );
        // Original fingerprint preserved on disk.
        let got = store.read_mek_fingerprint().expect("read");
        assert_eq!(got.as_deref(), Some(first.as_str()));
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
