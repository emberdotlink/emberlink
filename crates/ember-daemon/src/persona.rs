use chrono::Utc;
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
