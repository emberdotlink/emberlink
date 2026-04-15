use chrono::Utc;
use uuid::Uuid;

use crate::store::{DaemonStore, StoreError};

pub struct SandboxInfo {
    pub id: String,
    pub name: String,
    pub persona_id: String,
    pub container_id: Option<String>,
    pub image: String,
    pub status: String,
    pub created_at: String,
}

impl DaemonStore {
    pub fn create_sandbox(&self, name: &str, image: &str) -> Result<SandboxInfo, StoreError> {
        let persona = self.create_persona(name)?;
        let id = format!("sandbox-{}", Uuid::new_v4());
        let created_at = Utc::now().to_rfc3339();

        self.conn().execute(
            "INSERT INTO sandboxes (id, name, persona_id, container_id, image, status, created_at)
             VALUES (?1, ?2, ?3, NULL, ?4, 'created', ?5)",
            rusqlite::params![id, name, persona.id, image, created_at],
        )?;

        Ok(SandboxInfo {
            id,
            name: name.to_string(),
            persona_id: persona.id,
            container_id: None,
            image: image.to_string(),
            status: "created".to_string(),
            created_at,
        })
    }

    pub fn start_container(&self, sandbox_id: &str) -> Result<String, StoreError> {
        let (name, image) = self.conn().query_row(
            "SELECT name, image FROM sandboxes WHERE id = ?1",
            rusqlite::params![sandbox_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
            other => StoreError::Sqlite(other),
        })?;

        let output = std::process::Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &name,
                "--network=none",
                "--cap-drop=ALL",
                "--read-only",
                "--tmpfs",
                "/tmp",
                &image,
                "sleep",
                "infinity",
            ])
            .output()
            .map_err(|e| StoreError::InvalidInput(format!("docker not available: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            self.conn().execute(
                "UPDATE sandboxes SET status = 'error' WHERE id = ?1",
                rusqlite::params![sandbox_id],
            )?;
            return Err(StoreError::InvalidInput(format!("docker run failed: {stderr}")));
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

        self.conn().execute(
            "UPDATE sandboxes SET container_id = ?1, status = 'running' WHERE id = ?2",
            rusqlite::params![container_id, sandbox_id],
        )?;

        Ok(container_id)
    }

    pub fn list_sandboxes(&self) -> Result<Vec<SandboxInfo>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, name, persona_id, container_id, image, status, created_at
             FROM sandboxes ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SandboxInfo {
                id: row.get(0)?,
                name: row.get(1)?,
                persona_id: row.get(2)?,
                container_id: row.get(3)?,
                image: row.get(4)?,
                status: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?;
        let mut sandboxes = Vec::new();
        for row in rows {
            sandboxes.push(row?);
        }
        Ok(sandboxes)
    }

    pub fn stop_sandbox(&self, id: &str) -> Result<(), StoreError> {
        let (persona_id, container_id): (String, Option<String>) = self.conn().query_row(
            "SELECT persona_id, container_id FROM sandboxes WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
            other => StoreError::Sqlite(other),
        })?;

        if let Some(ref cid) = container_id {
            let _ = std::process::Command::new("docker")
                .args(["stop", cid])
                .output();
            let _ = std::process::Command::new("docker")
                .args(["rm", cid])
                .output();
        }

        let _ = self.revoke_persona(&persona_id);

        let stopped_at = Utc::now().to_rfc3339();
        self.conn().execute(
            "UPDATE sandboxes SET status = 'stopped', stopped_at = ?1 WHERE id = ?2",
            rusqlite::params![stopped_at, id],
        )?;

        Ok(())
    }

    pub fn exec_sandbox(&self, id: &str, command: &[&str]) -> Result<String, StoreError> {
        let (container_id, status): (Option<String>, String) = self.conn().query_row(
            "SELECT container_id, status FROM sandboxes WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
            other => StoreError::Sqlite(other),
        })?;

        if status != "running" {
            return Err(StoreError::InvalidInput(format!(
                "sandbox is not running (status: {status})"
            )));
        }

        let cid = container_id.ok_or_else(|| {
            StoreError::InvalidInput("sandbox has no container".to_string())
        })?;

        let mut args = vec!["exec", &cid];
        args.extend_from_slice(command);

        let output = std::process::Command::new("docker")
            .args(&args)
            .output()
            .map_err(|e| StoreError::InvalidInput(format!("docker not available: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(StoreError::InvalidInput(format!("docker exec failed: {stderr}")));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

#[cfg(test)]
fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_sandbox_appears_in_list() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.create_sandbox("test-box", "alpine:latest").unwrap();
        let list = store.list_sandboxes().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "test-box");
        assert_eq!(list[0].image, "alpine:latest");
        assert!(list[0].container_id.is_none());
    }

    #[test]
    fn create_sandbox_auto_creates_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store.create_sandbox("persona-box", "ubuntu:22.04").unwrap();
        let persona = store.get_persona(&sandbox.persona_id).unwrap();
        assert_eq!(persona.name, "persona-box");
        assert_eq!(persona.status, "active");
    }

    #[test]
    fn stop_sandbox_without_container_changes_status_and_revokes_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store.create_sandbox("no-container-box", "alpine:latest").unwrap();
        store.stop_sandbox(&sandbox.id).unwrap();

        let list = store.list_sandboxes().unwrap();
        assert_eq!(list[0].status, "stopped");

        let persona = store.get_persona(&sandbox.persona_id).unwrap();
        assert_eq!(persona.status, "revoked");
    }

    #[test]
    fn create_duplicate_sandbox_name_returns_error() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.create_sandbox("dup-box", "alpine:latest").unwrap();
        let result = store.create_sandbox("dup-box", "alpine:latest");
        assert!(result.is_err());
    }

    #[test]
    fn start_container_docker_available() {
        if !docker_available() {
            return;
        }
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store
            .create_sandbox("start-test-box", "alpine:latest")
            .unwrap();
        let container_id = store.start_container(&sandbox.id).unwrap();
        assert!(!container_id.is_empty());

        let list = store.list_sandboxes().unwrap();
        assert_eq!(list[0].container_id.as_deref(), Some(container_id.as_str()));
        assert_eq!(list[0].status, "running");

        // Clean up
        store.stop_sandbox(&sandbox.id).unwrap();
    }

    #[test]
    fn exec_in_running_container_docker_available() {
        if !docker_available() {
            return;
        }
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store
            .create_sandbox("exec-test-box", "alpine:latest")
            .unwrap();
        store.start_container(&sandbox.id).unwrap();

        let output = store.exec_sandbox(&sandbox.id, &["echo", "hello"]).unwrap();
        assert!(output.contains("hello"));

        // Clean up
        store.stop_sandbox(&sandbox.id).unwrap();
    }
}
