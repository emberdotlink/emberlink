use chrono::Utc;
use core_crypto::grant_chain::RootKeyPair;
use uuid::Uuid;

use crate::store::{DaemonStore, StoreError};
use crate::vault::Vault;

/// Encrypt a persona's Ed25519 secret string via the attached vault and
/// return `(nonce_blob, ciphertext_blob)` for SQLite storage.
///
/// Plaintext is the prefixed form (`ed25519-secret:<hex>`) — we encrypt
/// the string as-is so the read path can strip the prefix and hand the
/// hex straight to `RootKeyPair::from_hex`.
fn seal_persona_secret(
    vault: &Vault,
    persona_id: &str,
    secret: &str,
) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
    vault
        .seal(secret.as_bytes())
        .map_err(|e| StoreError::Vault(format!("encrypt persona '{persona_id}' secret: {e}")))
}

fn open_persona_secret(
    vault: &Vault,
    persona_id: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<String, StoreError> {
    let plaintext = vault
        .open(nonce, ciphertext)
        .map_err(|e| StoreError::Vault(format!("decrypt persona '{persona_id}' secret: {e}")))?;
    String::from_utf8(plaintext).map_err(|_| {
        StoreError::Vault(format!(
            "decrypted persona '{persona_id}' secret is not valid UTF-8"
        ))
    })
}

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

        // V0 schema: every persona row's secret is vault-sealed at rest.
        // The plaintext `private_key` column is gone — callers without an
        // attached vault (bare `DaemonStore::open_in_memory()` in tests)
        // must attach one via `set_vault` before creating a persona.
        let vault = self.vault().ok_or_else(|| {
            StoreError::InvalidInput(
                "create_persona requires an attached vault (V0 schema)".to_string(),
            )
        })?;
        let (nonce, ciphertext) = seal_persona_secret(&vault, &id, &kp.private_key)?;
        self.conn().execute(
            "INSERT INTO personas \
                (id, name, public_key, private_key_nonce, \
                 private_key_ciphertext, created_at, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active')",
            rusqlite::params![id, name, kp.public_key, nonce, ciphertext, created_at],
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
    /// issuing persona's root Ed25519 key. The daemon stores the secret
    /// vault-sealed (nonce + ciphertext) in the `personas` table — the
    /// same vault it uses for credential material.
    ///
    /// Returns `StoreError::NotFound` if the persona does not exist and
    /// `StoreError::InvalidInput` if the stored key material cannot be
    /// parsed as Ed25519 (e.g. DB corruption or a future algorithm switch).
    pub fn persona_root_keypair(&self, persona_id: &str) -> Result<RootKeyPair, StoreError> {
        type PersonaKeyRow = (String, Option<Vec<u8>>, Option<Vec<u8>>);
        let row: Option<PersonaKeyRow> = self
            .conn()
            .query_row(
                "SELECT public_key, private_key_nonce, \
                        private_key_ciphertext \
                 FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        let (public_key, nonce, ciphertext) = row.ok_or(StoreError::NotFound)?;

        let (n, ct) = match (nonce, ciphertext) {
            (Some(n), Some(ct)) => (n, ct),
            _ => {
                return Err(StoreError::InvalidInput(format!(
                    "persona '{persona_id}' has no vault-sealed private key"
                )));
            }
        };
        let vault = self.vault().ok_or_else(|| {
            StoreError::Vault(format!(
                "persona '{persona_id}' secret is vault-sealed but no vault is attached"
            ))
        })?;
        let secret_plain = open_persona_secret(&vault, persona_id, &n, &ct)?;

        // Both halves are prefixed per `core_crypto::LocalKeyPair`
        // (`ed25519:<hex>` and `ed25519-secret:<hex>`). Strip the prefix
        // and hand raw hex to `RootKeyPair::from_hex`.
        let public_hex = public_key.strip_prefix("ed25519:").ok_or_else(|| {
            StoreError::InvalidInput(format!(
                "persona '{persona_id}' public key missing 'ed25519:' prefix"
            ))
        })?;
        let secret_hex = secret_plain
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
    use std::rc::Rc;

    /// V0 schema: every test that creates a persona needs an attached vault
    /// since the plaintext `private_key` column is gone. Returns a store with
    /// a deterministic vault key so tests can assert crypto invariants.
    fn store_with_vault() -> (DaemonStore, Rc<Vault>) {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Rc::new(Vault::new([42u8; 32]));
        store.set_vault(Rc::clone(&vault));
        (store, vault)
    }

    #[test]
    fn create_persona_appears_in_list_as_active() {
        let (store, _vault) = store_with_vault();
        store.create_persona("agent-alpha").unwrap();
        let list = store.list_personas().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "agent-alpha");
        assert_eq!(list[0].status, "active");
    }

    #[test]
    fn create_persona_get_by_id_matches() {
        let (store, _vault) = store_with_vault();
        let created = store.create_persona("agent-beta").unwrap();
        let fetched = store.get_persona(&created.id).unwrap();
        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.name, created.name);
        assert_eq!(fetched.public_key, created.public_key);
        assert_eq!(fetched.status, "active");
    }

    #[test]
    fn create_persona_duplicate_name_returns_error() {
        let (store, _vault) = store_with_vault();
        store.create_persona("agent-gamma").unwrap();
        let result = store.create_persona("agent-gamma");
        assert!(result.is_err());
    }

    #[test]
    fn revoke_persona_changes_status() {
        let (store, _vault) = store_with_vault();
        let created = store.create_persona("agent-delta").unwrap();
        store.revoke_persona(&created.id).unwrap();
        let fetched = store.get_persona(&created.id).unwrap();
        assert_eq!(fetched.status, "revoked");
    }

    #[test]
    fn revoke_nonexistent_persona_returns_not_found() {
        let (store, _vault) = store_with_vault();
        let result = store.revoke_persona("persona-does-not-exist");
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn persona_root_keypair_round_trips_signing() {
        use core_crypto::grant_chain::{sign_block_zero, verify_chain};
        use core_types::{Block, ResourceSelector, ResourceType, Statement, Usage};

        let (store, _vault) = store_with_vault();
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
        let root_pubkey_bytes = hex::decode(rk.public_hex()).unwrap();
        verify_chain(std::slice::from_ref(&signed.signed), &root_pubkey_bytes).unwrap();
    }

    #[test]
    fn persona_root_keypair_unknown_persona_returns_not_found() {
        let (store, _vault) = store_with_vault();
        let err = store.persona_root_keypair("persona-nope").unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
    }

    #[test]
    fn list_shows_both_active_and_revoked() {
        let (store, _vault) = store_with_vault();
        let p1 = store.create_persona("agent-epsilon").unwrap();
        store.create_persona("agent-zeta").unwrap();
        store.revoke_persona(&p1.id).unwrap();

        let list = store.list_personas().unwrap();
        assert_eq!(list.len(), 2);

        let statuses: Vec<&str> = list.iter().map(|p| p.status.as_str()).collect();
        assert!(statuses.contains(&"active"));
        assert!(statuses.contains(&"revoked"));
    }

    // ------------------------------------------------------------------
    // F-05: persona private-key-at-rest encryption.
    // ------------------------------------------------------------------

    #[test]
    fn create_persona_stores_encrypted_private_key() {
        let (store, _vault) = store_with_vault();
        let created = store.create_persona("agent-sealed").unwrap();

        // Inspect SQLite directly — nonce + ciphertext must be populated.
        let (nonce_len, ct_len): (Option<i64>, Option<i64>) = store
            .conn()
            .query_row(
                "SELECT length(private_key_nonce), length(private_key_ciphertext) \
                 FROM personas WHERE id = ?1",
                rusqlite::params![created.id],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                    ))
                },
            )
            .unwrap();

        assert_eq!(nonce_len, Some(24), "XChaCha20 nonce is 24 bytes");
        assert!(
            ct_len.unwrap_or(0) > 16,
            "ciphertext + tag must be non-trivial"
        );

        // Roundtrip: the key we fetch back signs under the same public key.
        let rk = store.persona_root_keypair(&created.id).unwrap();
        assert_eq!(format!("ed25519:{}", rk.public_hex()), created.public_key);
    }

    #[test]
    fn create_persona_without_vault_is_rejected() {
        // V0: bare in-memory store has no vault. create_persona must fail
        // rather than silently write plaintext (which has no column anymore).
        let store = DaemonStore::open_in_memory_without_vault().unwrap();
        match store.create_persona("agent-no-vault") {
            Err(StoreError::InvalidInput(_)) => {}
            Err(other) => panic!("expected InvalidInput, got {other:?}"),
            Ok(_) => panic!("expected vault-required error"),
        }
    }

    #[test]
    fn wrong_vault_key_cannot_decrypt_sealed_persona() {
        // Encrypt under one key, try to read back under another — must fail
        // the AEAD check rather than silently returning garbage.
        let (store, _correct) = store_with_vault();
        let created = store.create_persona("agent-tamper").unwrap();

        let wrong = Rc::new(Vault::new([99u8; 32]));
        store.set_vault(wrong);
        let err = store.persona_root_keypair(&created.id).unwrap_err();
        assert!(matches!(err, StoreError::Vault(_)), "got {err:?}");
    }
}
