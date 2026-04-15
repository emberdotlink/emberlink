use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use rand::RngCore;
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::store::{DaemonStore, StoreError};

#[derive(Debug)]
pub enum VaultError {
    Store(StoreError),
    Crypto(String),
    NotFound,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Store(e) => write!(f, "store error: {e}"),
            VaultError::Crypto(s) => write!(f, "crypto error: {s}"),
            VaultError::NotFound => write!(f, "credential not found"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        VaultError::Store(e)
    }
}

pub struct CredentialInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub metadata: Option<String>,
}

pub struct Vault {
    vault_key: [u8; 32],
}

impl Vault {
    pub fn new(vault_key: [u8; 32]) -> Self {
        Vault { vault_key }
    }

    pub fn add(
        &self,
        store: &DaemonStore,
        name: &str,
        value: &[u8],
        metadata: Option<&str>,
    ) -> Result<CredentialInfo, VaultError> {
        let cipher = XChaCha20Poly1305::new_from_slice(&self.vault_key).unwrap();
        let mut nonce_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, value)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        let id = format!("cred-{}", Uuid::new_v4());
        let created_at = chrono::Utc::now().to_rfc3339();

        store
            .conn()
            .execute(
                "INSERT INTO credentials (id, name, nonce, ciphertext, created_at, metadata) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, name, nonce_bytes.as_slice(), ciphertext, created_at, metadata],
            )
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        Ok(CredentialInfo {
            id,
            name: name.to_string(),
            created_at,
            metadata: metadata.map(str::to_string),
        })
    }

    pub fn list(&self, store: &DaemonStore) -> Result<Vec<CredentialInfo>, VaultError> {
        let mut stmt = store
            .conn()
            .prepare("SELECT id, name, created_at, metadata FROM credentials ORDER BY created_at")
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(CredentialInfo {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_at: row.get(2)?,
                    metadata: row.get(3)?,
                })
            })
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?);
        }
        Ok(result)
    }

    pub fn get(&self, store: &DaemonStore, name: &str) -> Result<Vec<u8>, VaultError> {
        let result: Option<(Vec<u8>, Vec<u8>)> = store
            .conn()
            .query_row(
                "SELECT nonce, ciphertext FROM credentials WHERE name = ?1",
                params![name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        let (nonce_bytes, ciphertext) = result.ok_or(VaultError::NotFound)?;

        let cipher = XChaCha20Poly1305::new_from_slice(&self.vault_key).unwrap();
        let nonce = XNonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        Ok(plaintext)
    }

    pub fn remove(&self, store: &DaemonStore, name: &str) -> Result<(), VaultError> {
        let rows_affected = store
            .conn()
            .execute("DELETE FROM credentials WHERE name = ?1", params![name])
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        if rows_affected == 0 {
            return Err(VaultError::NotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::DaemonStore;

    fn test_key() -> [u8; 32] {
        [42u8; 32]
    }

    fn other_key() -> [u8; 32] {
        [99u8; 32]
    }

    #[test]
    fn add_list_get_roundtrip() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        let info = vault
            .add(&store, "my-api-key", b"supersecret", None)
            .unwrap();
        assert_eq!(info.name, "my-api-key");
        assert!(info.id.starts_with("cred-"));

        let list = vault.list(&store).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "my-api-key");

        let value = vault.get(&store, "my-api-key").unwrap();
        assert_eq!(value, b"supersecret");
    }

    #[test]
    fn duplicate_name_returns_error() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        vault.add(&store, "token", b"value1", None).unwrap();
        let result = vault.add(&store, "token", b"value2", None);
        assert!(result.is_err());
    }

    #[test]
    fn get_nonexistent_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        let result = vault.get(&store, "does-not-exist");
        assert!(matches!(result, Err(VaultError::NotFound)));
    }

    #[test]
    fn remove_then_get_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        vault.add(&store, "ephemeral", b"data", None).unwrap();
        vault.remove(&store, "ephemeral").unwrap();

        let result = vault.get(&store, "ephemeral");
        assert!(matches!(result, Err(VaultError::NotFound)));
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        vault.add(&store, "secret", b"confidential", None).unwrap();

        let wrong_vault = Vault::new(other_key());
        let result = wrong_vault.get(&store, "secret");
        assert!(matches!(result, Err(VaultError::Crypto(_))));
    }

    #[test]
    fn list_does_not_include_values() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        vault
            .add(&store, "key1", b"secret1", Some("tag=prod"))
            .unwrap();
        vault.add(&store, "key2", b"secret2", None).unwrap();

        let list = vault.list(&store).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].metadata.as_deref(), Some("tag=prod"));
        assert_eq!(list[1].metadata, None);
    }
}
