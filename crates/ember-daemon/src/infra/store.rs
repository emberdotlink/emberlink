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
}

impl From<core_grants::scope::DelegationViolation> for StoreError {
    fn from(v: core_grants::scope::DelegationViolation) -> Self {
        StoreError::DelegationViolation { reason: v.reason }
    }
}

/// implementation-note-292 —
/// outcome of [`DaemonStore::recover_audit_chain_tail`].
///
/// `NoOp` is the normal-path outcome — the tail row is well-formed (or
/// the audit_log is empty). `Truncated` means a half-written tail row
/// was detected and removed before the verifier ran; the carried fields
/// are surfaced via a structured `tracing::warn!` so operators see the
/// recovery in `audit show` / `daemon.log` rather than a silent fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditChainTailRecovery {
    /// The tail row is well-formed (or no row exists).
    NoOp,
    /// A half-write was detected and truncated. Carries the deleted
    /// row's SQLite `id` and `action` so the operator log can identify
    /// what was removed without dumping the full row.
    Truncated {
        /// The deleted row's `audit_log.id`.
        id: i64,
        /// The deleted row's `action` column (e.g. `"grant.create"`).
        action: String,
    },
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
    /// implementation-note-253 Phase 2: in-memory rate-limit set for the
    /// `sops_unwrap_dek` RPC. Each grant_id is consumed exactly once per
    /// daemon-process lifetime. The set is intentionally non-persistent —
    /// daemon restart clears it (acceptable: a restart-then-replay attack
    /// requires the operator to also resurrect a still-active grant on the
    /// SAME id, which is not a realistic threat in v0).
    ///
    /// Single-threaded LocalSet semantics: same as `vault`. No cross-thread
    /// races possible.
    consumed_dek_grants: RefCell<HashSet<String>>,
    /// implementation-note-60: cached
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
        let conn = Connection::open(path)?;
        let store = Self {
            conn,
            vault_slot: RefCell::new(LiveVaultSlot::default()),
            consumed_dek_grants: RefCell::new(HashSet::new()),
            bridge_ca_fingerprint: RefCell::new(None),
        };
        store.migrate()?;
        Ok(store)
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

    /// implementation-note-253 Phase 2: claim a `grant_id` slot for a
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

    /// implementation-note-60: attach the
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

    /// implementation-note-27 C2: drop the attached `Rc<Vault>` so the
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

    /// implementation-note-292 —
    /// recovery pre-pass for the audit-chain tail.
    ///
    /// Called from `runtime.rs::Daemon::start` BEFORE `run_audit_verify`.
    /// Detects the half-write signature on the most-recently-inserted
    /// `audit_log` row and truncates it so the verifier does not
    /// false-positive a tamper. The signature is:
    ///
    /// ```text
    /// prev_hash IS NULL
    ///   AND row_hash IS NOT NULL
    ///   AND action != 'audit.chain_v1_genesis'
    /// ```
    ///
    /// A row that matches this shape can only arise from a
    /// chain-write whose `prev_hash` lookup landed on a legacy
    /// `log_event` row (whose `row_hash` is NULL by design) and
    /// therefore stored `prev_hash = NULL`. The chain verifier walks
    /// past the legacy row (via the `row_hash IS NULL → continue`
    /// branch) and then expects the next chained row's `prev_hash` to
    /// equal the prior chain row's `row_hash` — but the stored value
    /// is `NULL`, so the verifier emits a false-positive
    /// `VerifyOutcome::Break`.
    ///
    /// This is NOT actual tampering. Mutating an existing row's
    /// `details` (the real tamper signature, asserted by
    /// `audit_verify_chain_detects_tampered_row`) leaves both
    /// `prev_hash` and `row_hash` non-NULL — only the `row_hash`
    /// diverges from the recomputed value. The NULL-`prev_hash`
    /// signature is structurally distinct and is the brief's
    /// "missing chain-link write on shutdown" failure mode.
    ///
    /// Recovery is conservative — strictly latest-row-only. A
    /// non-NULL but wrong `prev_hash` mid-chain (a real attacker
    /// rewrite) remains a tamper. A NULL-prev_hash row that is NOT
    /// the latest (i.e. there is at least one row inserted after it)
    /// also remains a tamper, because the daemon's writes have
    /// committed past that point and operator intervention is
    /// required to choose a recovery strategy.
    ///
    /// Returns:
    /// - `AuditChainTailRecovery::NoOp` if the tail row is
    ///   well-formed or no audit_log row exists.
    /// - `AuditChainTailRecovery::Truncated { id, action }` if a
    ///   half-write was detected and the row was deleted.
    ///
    /// Runs inside `BEGIN IMMEDIATE` so the read-decide-delete is
    /// atomic w.r.t. concurrent writers; in practice the recovery is
    /// called BEFORE the socket listener binds, so no concurrent
    /// writer exists, but the immediate-mode lock guards against a
    /// future caller invoking this from a hot path.
    pub fn recover_audit_chain_tail(&self) -> Result<AuditChainTailRecovery, StoreError> {
        let conn = &self.conn;
        conn.execute("BEGIN IMMEDIATE", [])?;
        let result = (|| -> Result<AuditChainTailRecovery, StoreError> {
            // Fetch (id, action, prev_hash, row_hash) of the latest row.
            // QueryReturnedNoRows → empty audit_log (pre-migrate path),
            // which is a NoOp.
            let row = conn.query_row(
                "SELECT id, action, prev_hash, row_hash \
                 FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            );
            let (id, action, prev_hash, row_hash) = match row {
                Ok(t) => t,
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    return Ok(AuditChainTailRecovery::NoOp);
                }
                Err(e) => return Err(StoreError::Sqlite(e)),
            };

            // The half-write signature: chained row (row_hash set)
            // whose prev_hash is NULL, and which is not the genesis
            // anchor (genesis legitimately has NULL prev_hash).
            let is_half_write =
                prev_hash.is_none() && row_hash.is_some() && action != "audit.chain_v1_genesis";

            if !is_half_write {
                return Ok(AuditChainTailRecovery::NoOp);
            }

            conn.execute("DELETE FROM audit_log WHERE id = ?1", rusqlite::params![id])?;
            Ok(AuditChainTailRecovery::Truncated { id, action })
        })();

        match result {
            Ok(outcome) => {
                conn.execute("COMMIT", [])?;
                Ok(outcome)
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
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

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent_id TEXT,
                action TEXT NOT NULL,
                credential TEXT,
                outcome TEXT NOT NULL,
                details TEXT,
                prev_hash TEXT,
                row_hash TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

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
                -- implementation-note-7:
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

            -- implementation-note-91: server-persisted WebAuthn credentials.
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

            -- implementation-note-91: in-flight WebAuthn ceremony state.
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

            -- credential_bindings_table_schema — implementation-note-307
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

        // implementation-note-49 — backfill `kind` column on legacy DBs so
        // the kms_wrap / kms_unwrap rows can land alongside grant rows.
        // Errors swallowed when the column already exists.
        let _ = self.conn.execute(
            "ALTER TABLE receipts ADD COLUMN kind TEXT NOT NULL DEFAULT 'grant'",
            [],
        );

        // implementation-note-49 — per-key fast-path index for queries shaped
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

        // EMBER-implementation-note-244 — per-actor and per-resource fast-path indexes
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

        // implementation-note-201 — composite-grant approval columns. Existing v0 DBs
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

        // implementation-note-242 — per-statement revocation list.
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

        // implementation-note-7 — grant-
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

        // implementation-note-53 (design §9 + §6) — bind a
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

        // implementation-note-308 (M1 of design, Bridge
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

        // implementation-note-238 (design §"In-container
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
                mnt_ns_inode INTEGER
            );",
        )?;

        // implementation-note-309 Step A — namespace-inode columns on
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

        // implementation-note-168 — tamper-evident chain columns on the
        // audit_log table + split-brain migration checkpoint. Pre-chain rows
        // carry NULL hashes; the genesis row marks the boundary between
        // pre-chain audit history and the new chained-from-here regime.
        // Errors swallowed when columns already exist (fresh DBs have them
        // via the CREATE TABLE above; old DBs need the ALTER).
        let _ = self
            .conn
            .execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT", []);
        let _ = self
            .conn
            .execute("ALTER TABLE audit_log ADD COLUMN row_hash TEXT", []);
        // Idempotent genesis: insert only if no genesis row exists yet.
        // chain_v1_genesis acts as the chain anchor — subsequent
        // append_audit_event_with_chain calls hash the prior row's
        // row_hash into the new row, with this genesis providing the
        // initial non-NULL prev_hash for chain readers.
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
                 (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash) \
                 VALUES (?1, NULL, 'audit.chain_v1_genesis', NULL, 'ok', NULL, NULL, ?2)",
                rusqlite::params![chrono::Utc::now().to_rfc3339(), genesis_hash],
            );
        }

        Ok(())
    }
}

/// implementation-note-238 (design §"In-container
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
    /// implementation-note-309 Step A — cgroup v2 leaf inode for
    /// the worker container (Step B populates; Step C gates dispatch).
    /// NULL for legacy/host-resident enrollments.
    pub cgroup_v2_id: Option<i64>,
    /// implementation-note-309 Step A — user-namespace inode.
    pub userns_inode: Option<i64>,
    /// implementation-note-309 Step A — mount-namespace inode.
    pub mnt_ns_inode: Option<i64>,
}

impl DaemonStore {
    /// implementation-note-238 — record a fresh per-socket
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
        // implementation-note-310 — the three Option<i64>
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

    /// implementation-note-238 — resolve the Persona
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

    /// implementation-note-238 — tombstone an enrollment.
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

impl DaemonStore {
    /// EMBER-implementation-note-244 — query the receipts table with the full
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
    // implementation-note-311 wires this into resolve_approval_inner.
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

    /// implementation-note-308 (M1) — verify the M1
    /// schema migration landed: the `personas` table has
    /// `client_cert_fingerprint` (TEXT NOT NULL DEFAULT '') and
    /// `client_cert_not_after` (INTEGER NOT NULL DEFAULT 0).
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
            // implementation-note-238: per-socket Persona
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
            // implementation-note-91: server-persisted WebAuthn state.
            "webauthn_credentials",
            "webauthn_challenges",
        ];
        assert_eq!(tables.len(), 14);
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

    // implementation-note-292 —
    // recovery pre-pass tests.

    /// On a fresh DB the migrate() call inserts the genesis anchor. The
    /// anchor legitimately carries `prev_hash = NULL` because it's the
    /// chain root — recovery MUST treat it as well-formed and not
    /// truncate it.
    #[test]
    fn recover_audit_chain_tail_noop_on_genesis_only() {
        let store = DaemonStore::open_in_memory().unwrap();
        let outcome = store.recover_audit_chain_tail().unwrap();
        assert_eq!(outcome, AuditChainTailRecovery::NoOp);
        let count: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "genesis row must remain after recovery");
    }

    /// A legacy `log_event` row tail carries (NULL, NULL) — it is NOT a
    /// half-write (the chain verifier skips it). Recovery must leave it
    /// alone so non-chained audit history is preserved.
    #[test]
    fn recover_audit_chain_tail_noop_on_legacy_log_event_tail() {
        let store = DaemonStore::open_in_memory().unwrap();
        store
            .log_event(Some("agent-x"), "legacy.action", None, "ok", None)
            .unwrap();
        let outcome = store.recover_audit_chain_tail().unwrap();
        assert_eq!(outcome, AuditChainTailRecovery::NoOp);
        // The legacy row stays.
        let action: String = store
            .conn()
            .query_row(
                "SELECT action FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(action, "legacy.action");
    }

    /// A well-formed chained tail row (prev_hash + row_hash both set)
    /// must not be truncated.
    #[test]
    fn recover_audit_chain_tail_noop_on_well_formed_chain_tail() {
        let store = DaemonStore::open_in_memory().unwrap();
        crate::infra::audit::append_audit_event_with_chain(
            &store,
            Some("agent-x"),
            "grant.create",
            None,
            "ok",
            None,
        )
        .unwrap();
        let outcome = store.recover_audit_chain_tail().unwrap();
        assert_eq!(outcome, AuditChainTailRecovery::NoOp);
        let action: String = store
            .conn()
            .query_row(
                "SELECT action FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(action, "grant.create");
    }

    /// The half-write signature: tail row has a `row_hash` (so the
    /// verifier will walk it) but a NULL `prev_hash` (the verifier
    /// expects it to match the prior chain row's row_hash). Recovery
    /// MUST truncate this row so the verifier does not false-positive.
    ///
    /// Reproduces the bootout-bootstrap repro by directly synthesizing
    /// the row state — equivalent to what
    /// `append_audit_event_with_chain` produced under the pre-fix bug
    /// when the prior row was a legacy `log_event` (NULL row_hash).
    #[test]
    fn recover_audit_chain_tail_truncates_half_written_tail() {
        let store = DaemonStore::open_in_memory().unwrap();
        // Synthesize the half-write: chained row with row_hash set but
        // prev_hash NULL. Bypass `append_audit_event_with_chain` so we
        // control the row shape exactly.
        let fake_hash = blake3::hash(b"synthetic-row").to_hex().to_string();
        let inserted = store
            .conn()
            .execute(
                "INSERT INTO audit_log \
                 (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash) \
                 VALUES (?1, NULL, 'grant.create', NULL, 'ok', NULL, NULL, ?2)",
                rusqlite::params!["2026-05-15T00:00:00Z", fake_hash],
            )
            .unwrap();
        assert_eq!(inserted, 1);
        let half_id: i64 = store.conn().last_insert_rowid();

        let outcome = store.recover_audit_chain_tail().unwrap();
        match outcome {
            AuditChainTailRecovery::Truncated { id, action } => {
                assert_eq!(id, half_id);
                assert_eq!(action, "grant.create");
            }
            other => panic!("expected Truncated, got {other:?}"),
        }

        // The half-written row is gone; the genesis row remains.
        let count: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let surviving_action: String = store
            .conn()
            .query_row(
                "SELECT action FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(surviving_action, "audit.chain_v1_genesis");
    }

    /// After recovery, the chain verifier MUST report Ok on a previously
    /// false-positive DB. End-to-end regression for the bootout repro.
    #[test]
    fn recover_then_verify_passes_on_bootout_repro() {
        use crate::infra::audit::{VerifyOutcome, run_audit_verify};

        let store = DaemonStore::open_in_memory().unwrap();
        // Genesis (from migrate) + legacy log_event row + half-written
        // chained tail row. Without recovery the verifier fails at the
        // tail with `prev_hash` mismatch.
        store
            .log_event(None, "vault.auto_unseal_from_keyring", None, "ok", None)
            .unwrap();
        let fake_hash = blake3::hash(b"synthetic-row").to_hex().to_string();
        store
            .conn()
            .execute(
                "INSERT INTO audit_log \
                 (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash) \
                 VALUES (?1, NULL, 'grant.create', NULL, 'ok', NULL, NULL, ?2)",
                rusqlite::params!["2026-05-15T00:00:00Z", fake_hash],
            )
            .unwrap();

        // Pre-recovery: the verifier sees the half-write and emits Break.
        match run_audit_verify(store.conn(), None).unwrap() {
            VerifyOutcome::Break { .. } => {}
            other => panic!("expected pre-recovery Break, got {other:?}"),
        }

        // Recovery truncates the tail.
        let outcome = store.recover_audit_chain_tail().unwrap();
        assert!(matches!(outcome, AuditChainTailRecovery::Truncated { .. }));

        // Post-recovery: verifier reports Ok.
        match run_audit_verify(store.conn(), None).unwrap() {
            VerifyOutcome::Ok { .. } => {}
            other => panic!("expected post-recovery Ok, got {other:?}"),
        }
    }

    /// Tamper on a mid-chain row (existing test
    /// `audit_verify_chain_detects_tampered_row` in audit.rs) flips a
    /// row's `details`, leaving `prev_hash` non-NULL but `row_hash`
    /// diverging. Recovery on the latest-only tail MUST NOT mask that
    /// case — the verifier still emits Break.
    #[test]
    fn recover_audit_chain_tail_preserves_mid_chain_tamper_detection() {
        use crate::infra::audit::{VerifyOutcome, append_audit_event_with_chain, run_audit_verify};
        let store = DaemonStore::open_in_memory().unwrap();
        let id1 = append_audit_event_with_chain(
            &store,
            Some("a-1"),
            "grant.create",
            None,
            "ok",
            Some("orig"),
        )
        .unwrap();
        append_audit_event_with_chain(&store, Some("a-2"), "grant.revoked", None, "ok", None)
            .unwrap();
        append_audit_event_with_chain(&store, None, "broker.materialization", None, "ok", None)
            .unwrap();

        // Real tamper — mutate row 1's `details` directly. prev_hash
        // and row_hash stay non-NULL; only the recomputed hash
        // diverges.
        store
            .conn()
            .execute(
                "UPDATE audit_log SET details = 'TAMPERED' WHERE id = ?1",
                rusqlite::params![id1],
            )
            .unwrap();

        // Recovery: NoOp — the latest row is well-formed.
        let outcome = store.recover_audit_chain_tail().unwrap();
        assert_eq!(outcome, AuditChainTailRecovery::NoOp);

        // Verifier: still Break.
        match run_audit_verify(store.conn(), None).unwrap() {
            VerifyOutcome::Break { at_row_id, .. } => assert_eq!(at_row_id, id1),
            other => panic!("expected Break, got {other:?}"),
        }
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
        // implementation-note-310 — the binding tuple round-
        // trips through SQLite intact.
        assert_eq!(row.cgroup_v2_id, Some(987654321));
        assert_eq!(row.userns_inode, Some(4026531840));
        assert_eq!(row.mnt_ns_inode, Some(4026531841));
    }
}
