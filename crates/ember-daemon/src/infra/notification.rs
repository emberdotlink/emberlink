use uuid::Uuid;

use crate::infra::store::{DaemonStore, StoreError};

impl DaemonStore {
    pub fn push_notification(
        &self,
        persona_id: &str,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<(), StoreError> {
        let id = format!("notif-{}", Uuid::new_v4());
        self.conn().execute(
            "INSERT INTO notifications (id, persona_id, event_type, payload) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                id,
                persona_id,
                event_type,
                serde_json::to_string(payload).unwrap_or_default(),
            ],
        ).map_err(StoreError::Sqlite)?;
        Ok(())
    }

    pub fn poll_notifications(
        &self,
        persona_id: &str,
    ) -> Result<Vec<serde_json::Value>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, event_type, payload, created_at FROM notifications WHERE persona_id = ?1 AND read_at IS NULL ORDER BY created_at",
        ).map_err(StoreError::Sqlite)?;
        let rows = stmt
            .query_map(rusqlite::params![persona_id], |row| {
                let id: String = row.get(0)?;
                let event_type: String = row.get(1)?;
                let payload: String = row.get(2)?;
                let created_at: String = row.get(3)?;
                Ok((id, event_type, payload, created_at))
            })
            .map_err(StoreError::Sqlite)?;

        let mut results = Vec::new();
        for row in rows {
            let (id, event_type, payload, created_at) = row.map_err(StoreError::Sqlite)?;
            results.push(serde_json::json!({
                "id": id,
                "event_type": event_type,
                "payload": serde_json::from_str::<serde_json::Value>(&payload).unwrap_or_default(),
                "created_at": created_at,
            }));
        }

        self.conn().execute(
            "UPDATE notifications SET read_at = datetime('now') WHERE persona_id = ?1 AND read_at IS NULL",
            rusqlite::params![persona_id],
        ).map_err(StoreError::Sqlite)?;

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use crate::infra::store::DaemonStore;
    use serde_json::json;

    #[test]
    fn push_and_poll_returns_notification() {
        let store = DaemonStore::open_in_memory().unwrap();
        store
            .push_notification(
                "persona-1",
                "grant.revoked",
                &json!({"grant_id": "grant-abc"}),
            )
            .unwrap();

        let notifs = store.poll_notifications("persona-1").unwrap();
        assert_eq!(notifs.len(), 1);
        assert_eq!(notifs[0]["event_type"], json!("grant.revoked"));
        assert_eq!(notifs[0]["payload"]["grant_id"], json!("grant-abc"));
    }

    #[test]
    fn poll_marks_as_read() {
        let store = DaemonStore::open_in_memory().unwrap();
        store
            .push_notification(
                "persona-2",
                "grant.revoked",
                &json!({"grant_id": "grant-xyz"}),
            )
            .unwrap();

        let first = store.poll_notifications("persona-2").unwrap();
        assert_eq!(first.len(), 1);

        // Second poll returns empty (already marked read).
        let second = store.poll_notifications("persona-2").unwrap();
        assert_eq!(second.len(), 0);
    }

    #[test]
    fn poll_only_returns_own_persona_notifications() {
        let store = DaemonStore::open_in_memory().unwrap();
        store
            .push_notification("persona-a", "grant.revoked", &json!({}))
            .unwrap();
        store
            .push_notification("persona-b", "grant.revoked", &json!({}))
            .unwrap();

        let notifs = store.poll_notifications("persona-a").unwrap();
        assert_eq!(notifs.len(), 1);

        let notifs_b = store.poll_notifications("persona-b").unwrap();
        assert_eq!(notifs_b.len(), 1);
    }
}
