use chrono::{DateTime, Duration, Utc};
use rusqlite::OptionalExtension;
use uuid::Uuid;

use crate::store::{DaemonStore, StoreError};

pub struct GrantInfo {
    pub id: String,
    pub persona_id: String,
    pub credential_name: String,
    pub scope: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub status: String,
}

impl DaemonStore {
    pub fn create_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
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
                )))
            }
        }

        let id = format!("grant-{}", Uuid::new_v4());
        let now: DateTime<Utc> = Utc::now();
        let created_at = now.to_rfc3339();

        let expires_at: Option<String> = ttl_secs.map(|secs| {
            let expiry = now + Duration::seconds(secs as i64);
            expiry.to_rfc3339()
        });

        self.conn().execute(
            "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
            rusqlite::params![
                id,
                persona_id,
                credential_name,
                scope,
                ttl_secs.map(|s| s as i64),
                created_at,
                expires_at,
            ],
        )?;

        Ok(GrantInfo {
            id,
            persona_id: persona_id.to_string(),
            credential_name: credential_name.to_string(),
            scope: scope.to_string(),
            created_at,
            expires_at,
            status: "active".to_string(),
        })
    }

    pub fn list_grants(&self) -> Result<Vec<GrantInfo>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, persona_id, credential_name, scope, created_at, expires_at, status FROM grants",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(GrantInfo {
                id: row.get(0)?,
                persona_id: row.get(1)?,
                credential_name: row.get(2)?,
                scope: row.get(3)?,
                created_at: row.get(4)?,
                expires_at: row.get(5)?,
                status: row.get(6)?,
            })
        })?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?);
        }
        Ok(grants)
    }

    pub fn list_active_grants(&self) -> Result<Vec<GrantInfo>, StoreError> {
        let now = Utc::now().to_rfc3339();
        let mut stmt = self.conn().prepare(
            "SELECT id, persona_id, credential_name, scope, created_at, expires_at, status
             FROM grants
             WHERE status = 'active'
               AND (expires_at IS NULL OR expires_at > ?1)",
        )?;
        let rows = stmt.query_map(rusqlite::params![now], |row| {
            Ok(GrantInfo {
                id: row.get(0)?,
                persona_id: row.get(1)?,
                credential_name: row.get(2)?,
                scope: row.get(3)?,
                created_at: row.get(4)?,
                expires_at: row.get(5)?,
                status: row.get(6)?,
            })
        })?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?);
        }
        Ok(grants)
    }

    pub fn get_grant(&self, id: &str) -> Result<GrantInfo, StoreError> {
        self.conn()
            .query_row(
                "SELECT id, persona_id, credential_name, scope, created_at, expires_at, status
                 FROM grants WHERE id = ?1",
                rusqlite::params![id],
                |row| {
                    Ok(GrantInfo {
                        id: row.get(0)?,
                        persona_id: row.get(1)?,
                        credential_name: row.get(2)?,
                        scope: row.get(3)?,
                        created_at: row.get(4)?,
                        expires_at: row.get(5)?,
                        status: row.get(6)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    pub fn evaluate_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
    ) -> Result<GrantInfo, StoreError> {
        let now = Utc::now().to_rfc3339();
        self.conn()
            .query_row(
                "SELECT id, persona_id, credential_name, scope, created_at, expires_at, status
                 FROM grants
                 WHERE persona_id = ?1
                   AND credential_name = ?2
                   AND status = 'active'
                   AND (expires_at IS NULL OR expires_at > ?3)
                 LIMIT 1",
                rusqlite::params![persona_id, credential_name, now],
                |row| {
                    Ok(GrantInfo {
                        id: row.get(0)?,
                        persona_id: row.get(1)?,
                        credential_name: row.get(2)?,
                        scope: row.get(3)?,
                        created_at: row.get(4)?,
                        expires_at: row.get(5)?,
                        status: row.get(6)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    pub fn revoke_grant(&self, id: &str) -> Result<(), StoreError> {
        let n = self.conn().execute(
            "UPDATE grants SET status = 'revoked' WHERE id = ?1",
            rusqlite::params![id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration as StdDuration;

    use super::*;
    use crate::store::DaemonStore;

    fn setup() -> DaemonStore {
        DaemonStore::open_in_memory().expect("in-memory store")
    }

    #[test]
    fn create_grant_list_shows_active() {
        let store = setup();
        let persona = store.create_persona("agent-alpha").unwrap();
        let grant = store
            .create_grant(&persona.id, "api-key", "read", None)
            .unwrap();
        assert_eq!(grant.status, "active");
        assert!(grant.expires_at.is_none());

        let grants = store.list_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].id, grant.id);
        assert_eq!(grants[0].status, "active");
    }

    #[test]
    fn create_grant_with_ttl_expires_at_set() {
        let store = setup();
        let persona = store.create_persona("agent-beta").unwrap();
        let grant = store
            .create_grant(&persona.id, "api-key", "write", Some(3600))
            .unwrap();
        assert!(grant.expires_at.is_some());

        // Parse and verify it's in the future.
        let expires: DateTime<Utc> =
            DateTime::parse_from_rfc3339(grant.expires_at.as_ref().unwrap())
                .unwrap()
                .into();
        assert!(expires > Utc::now());
    }

    #[test]
    fn evaluate_grant_returns_active_grant() {
        let store = setup();
        let persona = store.create_persona("agent-gamma").unwrap();
        store
            .create_grant(&persona.id, "secret", "read", None)
            .unwrap();

        let found = store.evaluate_grant(&persona.id, "secret").unwrap();
        assert_eq!(found.persona_id, persona.id);
        assert_eq!(found.credential_name, "secret");
        assert_eq!(found.status, "active");
    }

    #[test]
    fn evaluate_grant_after_ttl_expires_returns_not_found() {
        let store = setup();
        let persona = store.create_persona("agent-delta").unwrap();

        // Insert a grant with expires_at in the past directly.
        let id = format!("grant-{}", Uuid::new_v4());
        let now = Utc::now();
        let past = now - Duration::seconds(10);
        store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
                rusqlite::params![
                    id,
                    persona.id,
                    "expired-key",
                    "read",
                    1_i64,
                    now.to_rfc3339(),
                    past.to_rfc3339(),
                ],
            )
            .unwrap();

        let result = store.evaluate_grant(&persona.id, "expired-key");
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn revoke_grant_evaluate_returns_not_found() {
        let store = setup();
        let persona = store.create_persona("agent-epsilon").unwrap();
        let grant = store
            .create_grant(&persona.id, "token", "full", None)
            .unwrap();

        store.revoke_grant(&grant.id).unwrap();

        let result = store.evaluate_grant(&persona.id, "token");
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn create_grant_nonexistent_persona_returns_error() {
        let store = setup();
        let result = store.create_grant("persona-does-not-exist", "key", "read", None);
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn create_grant_revoked_persona_returns_error() {
        let store = setup();
        let persona = store.create_persona("agent-zeta").unwrap();
        store.revoke_persona(&persona.id).unwrap();

        let result = store.create_grant(&persona.id, "key", "read", None);
        assert!(matches!(result, Err(StoreError::InvalidInput(_))));
    }

    #[test]
    fn list_active_grants_excludes_expired_and_revoked() {
        let store = setup();
        let persona = store.create_persona("agent-eta").unwrap();

        // Active grant (no TTL).
        let active = store
            .create_grant(&persona.id, "active-key", "read", None)
            .unwrap();

        // Revoked grant.
        let revoked = store
            .create_grant(&persona.id, "revoked-key", "read", None)
            .unwrap();
        store.revoke_grant(&revoked.id).unwrap();

        // Expired grant: insert directly with past expires_at.
        let exp_id = format!("grant-{}", Uuid::new_v4());
        let now = Utc::now();
        let past = now - Duration::seconds(10);
        store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
                rusqlite::params![
                    exp_id,
                    persona.id,
                    "expired-key2",
                    "read",
                    1_i64,
                    now.to_rfc3339(),
                    past.to_rfc3339(),
                ],
            )
            .unwrap();

        let active_grants = store.list_active_grants().unwrap();
        assert_eq!(active_grants.len(), 1);
        assert_eq!(active_grants[0].id, active.id);
    }

    // Keep the import used only in the sleep-based variant (unused without it).
    #[allow(dead_code)]
    fn _uses_thread_sleep() {
        let _ = thread::sleep(StdDuration::from_millis(0));
    }
}
