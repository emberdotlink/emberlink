use std::cell::RefCell;
use std::collections::HashSet;
use std::path::Path;
use std::rc::Rc;

use rusqlite::Connection;

use crate::infra::vault::Vault;

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
    #[error("identity key at {path} has insecure mode {mode:#06o} (expected 0600 — chmod 0600 to fix)")]
    KeyInsecureMode { path: String, mode: u32 },
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
    vault: RefCell<Option<Rc<Vault>>>,
    /// implementation-note-102 Phase 2: in-memory rate-limit set for the
    /// `sops_unwrap_dek` RPC. Each grant_id is consumed exactly once per
    /// daemon-process lifetime. The set is intentionally non-persistent —
    /// daemon restart clears it (acceptable: a restart-then-replay attack
    /// requires the operator to also resurrect a still-active grant on the
    /// SAME id, which is not a realistic threat in v0).
    ///
    /// Single-threaded LocalSet semantics: same as `vault`. No cross-thread
    /// races possible.
    consumed_dek_grants: RefCell<HashSet<String>>,
}

impl DaemonStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        let store = Self {
            conn,
            vault: RefCell::new(None),
            consumed_dek_grants: RefCell::new(HashSet::new()),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn,
            vault: RefCell::new(None),
            consumed_dek_grants: RefCell::new(HashSet::new()),
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
            vault: RefCell::new(None),
            consumed_dek_grants: RefCell::new(HashSet::new()),
        };
        store.migrate()?;
        Ok(store)
    }

    /// implementation-note-102 Phase 2: claim a `grant_id` slot for a
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

    /// Attach a shared `Vault` handle after construction so persona-secret
    /// write/read paths can encrypt under the vault master key. Call once
    /// at startup after `Vault::open_from_config` succeeds and before the
    /// socket listener accepts traffic.
    ///
    /// Idempotent — replacing an already-attached vault is allowed; tests
    /// swap vaults to assert "wrong key cannot decrypt" invariants.
    pub fn set_vault(&self, vault: Rc<Vault>) {
        *self.vault.borrow_mut() = Some(vault);
    }

    /// Return a clone of the currently attached vault, if any. Persona-secret
    /// write/read paths require an attached vault after the V0 schema collapse
    /// — fresh DBs have no plaintext column. Callers handle the `None` case
    /// by returning a vault-not-attached error.
    pub(crate) fn vault(&self) -> Option<Rc<Vault>> {
        self.vault.borrow().clone()
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
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
                details TEXT
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

            -- implementation-note-38: server-persisted WebAuthn credentials.
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

            -- implementation-note-38: in-flight WebAuthn ceremony state.
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
                ON webauthn_challenges(persona_id);",
        )?;

        // implementation-note-16 — backfill `kind` column on legacy DBs so
        // the kms_wrap / kms_unwrap rows can land alongside grant rows.
        // Errors swallowed when the column already exists.
        let _ = self.conn.execute(
            "ALTER TABLE receipts ADD COLUMN kind TEXT NOT NULL DEFAULT 'grant'",
            [],
        );

        // implementation-note-16 — per-key fast-path index for queries shaped
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

        // EMBER-implementation-note-94 — per-actor and per-resource fast-path indexes
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

        // implementation-note-77 — composite-grant approval columns. Existing v0 DBs
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
        let _ = self.conn.execute(
            "ALTER TABLE sandboxes ADD COLUMN owner_persona_id TEXT",
            [],
        );

        // implementation-note-92 — per-statement revocation list.
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

        Ok(())
    }
}

impl DaemonStore {
    /// EMBER-implementation-note-94 — query the receipts table with the full
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
    // implementation-note-129 wires this into resolve_approval_inner.
    #[allow(dead_code)]
    pub(crate) fn validate_approval_transition(
        state: core_types::approval::ApprovalStatus,
        outcome: &core_approval::ApprovalOutcome,
    ) -> Result<core_types::approval::ApprovalStatus, StoreError> {
        core_approval::states::transition(state, outcome).map_err(|e| match e {
            core_approval::TransitionError::AlreadyDecided => StoreError::AlreadyResolved,
            core_approval::TransitionError::ScopeNotNarrowing => {
                StoreError::InvalidInput(
                    "narrowed scope is not a syntactic subset of request scope".into(),
                )
            }
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
            "approval_requests",
            "audit_log",
            "credentials",
            "grant_usage",
            "grants",
            "notifications",
            "personas",
            "receipts",
            "sandboxes",
            "standing_grants",
            // implementation-note-38: server-persisted WebAuthn state.
            "webauthn_credentials",
            "webauthn_challenges",
        ];
        assert_eq!(tables.len(), 12);
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
            .log_event(Some("agent-x"), "test.action", Some("cred-y"), "allowed", Some("details"))
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
}
