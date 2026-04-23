use chrono::Utc;
use core_crypto::grant_chain::RootKeyPair;
use uuid::Uuid;

use crate::store::{DaemonStore, StoreError};

pub struct PersonaInfo {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub created_at: String,
    pub status: String,
}

impl DaemonStore {
    pub fn create_persona(&self, name: &str) -> Result<PersonaInfo, StoreError> {
        let id = format!("persona-{}", Uuid::new_v4());
        let kp = core_crypto::generate_local_key_pair("persona", &id);
        let created_at = Utc::now().to_rfc3339();

        self.conn().execute(
            "INSERT INTO personas (id, name, public_key, private_key, created_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, 'active')",
            rusqlite::params![id, name, kp.public_key, kp.private_key, created_at],
        )?;

        Ok(PersonaInfo {
            id,
            name: name.to_string(),
            public_key: kp.public_key.clone(),
            created_at,
            status: "active".to_string(),
        })
    }

    pub fn list_personas(&self) -> Result<Vec<PersonaInfo>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, name, public_key, created_at, status FROM personas ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PersonaInfo {
                id: row.get(0)?,
                name: row.get(1)?,
                public_key: row.get(2)?,
                created_at: row.get(3)?,
                status: row.get(4)?,
            })
        })?;
        let mut personas = Vec::new();
        for row in rows {
            personas.push(row?);
        }
        Ok(personas)
    }

    pub fn get_persona(&self, id: &str) -> Result<PersonaInfo, StoreError> {
        let result = self.conn().query_row(
            "SELECT id, name, public_key, created_at, status FROM personas WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(PersonaInfo {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    public_key: row.get(2)?,
                    created_at: row.get(3)?,
                    status: row.get(4)?,
                })
            },
        );
        match result {
            Ok(p) => Ok(p),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(StoreError::NotFound),
            Err(e) => Err(StoreError::Sqlite(e)),
        }
    }

    /// Return the persona's Ed25519 root keypair, formatted for
    /// `core_crypto::grant_chain::sign_block_zero`.
    ///
    /// Daemon-issued grants (per design revision) sign block 0 under the
    /// issuing persona's root Ed25519 key. The daemon stores both halves of
    /// that key in its own SQLite `personas` table — the same vault it
    /// already uses for credential material. Exposing this as a narrow
    /// lookup keeps the signing surface legible without adding a second
    /// vault or an unlocked in-memory keystore.
    ///
    /// Returns `StoreError::NotFound` if the persona does not exist and
    /// `StoreError::InvalidInput` if the stored key material cannot be
    /// parsed as Ed25519 (e.g. DB corruption or a future algorithm switch).
    pub fn persona_root_keypair(&self, persona_id: &str) -> Result<RootKeyPair, StoreError> {
        let row: Option<(String, String)> = self
            .conn()
            .query_row(
                "SELECT public_key, private_key FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        let (public_key, private_key) = row.ok_or(StoreError::NotFound)?;

        // Both halves are prefixed per `core_crypto::LocalKeyPair`
        // (`ed25519:<hex>` and `ed25519-secret:<hex>`). Strip the prefix
        // and hand raw hex to `RootKeyPair::from_hex`.
        let public_hex = public_key.strip_prefix("ed25519:").ok_or_else(|| {
            StoreError::InvalidInput(format!(
                "persona '{persona_id}' public key missing 'ed25519:' prefix"
            ))
        })?;
        let secret_hex = private_key
            .strip_prefix("ed25519-secret:")
            .ok_or_else(|| {
                StoreError::InvalidInput(format!(
                    "persona '{persona_id}' private key missing 'ed25519-secret:' prefix"
                ))
            })?;
        RootKeyPair::from_hex(public_hex, secret_hex).map_err(|e| {
            StoreError::InvalidInput(format!(
                "persona '{persona_id}' root key invalid: {e}"
            ))
        })
    }

    pub fn revoke_persona(&self, id: &str) -> Result<(), StoreError> {
        let count = self.conn().execute(
            "UPDATE personas SET status = 'revoked' WHERE id = ?1",
            rusqlite::params![id],
        )?;
        if count == 0 {
            return Err(StoreError::NotFound);
        }
        // Cascade: revoke all active grants for this persona
        self.conn().execute(
            "UPDATE grants SET status = 'revoked' WHERE persona_id = ?1 AND status = 'active'",
            rusqlite::params![id],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_persona_appears_in_list_as_active() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.create_persona("agent-alpha").unwrap();
        let list = store.list_personas().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "agent-alpha");
        assert_eq!(list[0].status, "active");
    }

    #[test]
    fn create_persona_get_by_id_matches() {
        let store = DaemonStore::open_in_memory().unwrap();
        let created = store.create_persona("agent-beta").unwrap();
        let fetched = store.get_persona(&created.id).unwrap();
        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.name, created.name);
        assert_eq!(fetched.public_key, created.public_key);
        assert_eq!(fetched.status, "active");
    }

    #[test]
    fn create_persona_duplicate_name_returns_error() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.create_persona("agent-gamma").unwrap();
        let result = store.create_persona("agent-gamma");
        assert!(result.is_err());
    }

    #[test]
    fn revoke_persona_changes_status() {
        let store = DaemonStore::open_in_memory().unwrap();
        let created = store.create_persona("agent-delta").unwrap();
        store.revoke_persona(&created.id).unwrap();
        let fetched = store.get_persona(&created.id).unwrap();
        assert_eq!(fetched.status, "revoked");
    }

    #[test]
    fn revoke_nonexistent_persona_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let result = store.revoke_persona("persona-does-not-exist");
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn persona_root_keypair_round_trips_signing() {
        use core_crypto::grant_chain::{sign_block_zero, verify_chain};
        use core_types::{Block, ResourceSelector, ResourceType, Statement, Usage};

        let store = DaemonStore::open_in_memory().unwrap();
        let created = store.create_persona("agent-sign").unwrap();

        let rk = store.persona_root_keypair(&created.id).unwrap();
        let block = Block {
            statements: vec![Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["read".into()],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage::default(),
                conditions: Vec::new(),
            }],
            nbf: None,
            expires_at: None,
            issued_by: created.id.clone(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let signed = sign_block_zero(&rk, &block).unwrap();
        let root_pubkey_bytes = hex::decode(&rk.public_hex).unwrap();
        verify_chain(std::slice::from_ref(&signed.signed), &root_pubkey_bytes).unwrap();
    }

    #[test]
    fn persona_root_keypair_unknown_persona_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let err = store.persona_root_keypair("persona-nope").unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
    }

    #[test]
    fn list_shows_both_active_and_revoked() {
        let store = DaemonStore::open_in_memory().unwrap();
        let p1 = store.create_persona("agent-epsilon").unwrap();
        store.create_persona("agent-zeta").unwrap();
        store.revoke_persona(&p1.id).unwrap();

        let list = store.list_personas().unwrap();
        assert_eq!(list.len(), 2);

        let statuses: Vec<&str> = list.iter().map(|p| p.status.as_str()).collect();
        assert!(statuses.contains(&"active"));
        assert!(statuses.contains(&"revoked"));
    }
}
