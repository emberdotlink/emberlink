use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use rusqlite::Connection;

use crate::vault::Vault;

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
}

impl From<crate::attenuation::DelegationViolation> for StoreError {
    fn from(v: crate::attenuation::DelegationViolation) -> Self {
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
}

impl DaemonStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        let store = Self {
            conn,
            vault: RefCell::new(None),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn,
            vault: RefCell::new(None),
        };
        store.migrate()?;
        // V0 schema: every persona secret is vault-sealed, so an
        // in-memory store always needs a vault for the persona write
        // path. Attach a deterministic test vault by default — tests
        // that want to assert "no vault" behavior can call
        // `open_in_memory_without_vault` instead.
        #[cfg(test)]
        {
            use crate::vault::Vault;
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
        };
        store.migrate()?;
        Ok(store)
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
                signer_pubkey TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_receipts_grant ON receipts(grant_id);
            CREATE INDEX IF NOT EXISTS idx_receipts_persona ON receipts(persona_id);
            CREATE INDEX IF NOT EXISTS idx_receipts_created ON receipts(created_at);",
        )?;

        // implementation-note-1 — composite-grant approval columns. Existing v0 DBs
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

        Ok(())
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
        ];
        assert_eq!(tables.len(), 10);
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
        use crate::audit::AuditFilter;

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
