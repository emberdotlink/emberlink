//! Headless-scope subset management for design.
//!
//! This module keeps the local-vault headless lane honest:
//! - the headless scope is an explicit subset, not a hidden alias of the
//!   interactive scope
//! - stale headless ciphertext is pruned when enrollment disappears
//! - future `headless_enroll` wiring gets one adapter instead of open-coded
//!   copy/remove loops spread across handler and runtime paths

use std::collections::{BTreeSet, HashMap};

use rusqlite::params;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::infra::store::{DaemonStore, StoreError};
use crate::infra::vault::{
    Vault, VaultError, VaultScope, logical_name_from_storage, storage_name_for_scope,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("vault: {0}")]
    Vault(#[from] VaultError),
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct StagedCredential {
    name: String,
    value: Vec<u8>,
    metadata: Option<String>,
}

pub fn list_scope_keys(store: &DaemonStore, scope: VaultScope) -> Result<Vec<String>, Error> {
    let mut stmt = store
        .conn()
        .prepare("SELECT name FROM credentials ORDER BY created_at")
        .map_err(StoreError::Sqlite)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(StoreError::Sqlite)?;

    let mut keys = Vec::new();
    for row in rows {
        let stored_name = row.map_err(StoreError::Sqlite)?;
        let Some(logical_name) = logical_name_from_storage(scope, &stored_name) else {
            continue;
        };
        keys.push(logical_name);
    }
    Ok(keys)
}

pub fn list_headless_keys(store: &DaemonStore) -> Result<Vec<String>, Error> {
    list_scope_keys(store, VaultScope::Headless)
}

pub fn clear_headless_scope(store: &DaemonStore) -> Result<usize, Error> {
    let keys = list_headless_keys(store)?;
    let mut deleted = 0usize;
    for key in keys {
        let stored_name = storage_name_for_scope(VaultScope::Headless, &key);
        deleted += store
            .conn()
            .execute(
                "DELETE FROM credentials WHERE name = ?1",
                params![stored_name],
            )
            .map_err(StoreError::Sqlite)? as usize;
    }
    Ok(deleted)
}

pub fn replace_headless_subset(
    interactive_vault: &Vault,
    headless_vault: &Vault,
    store: &DaemonStore,
    keys: &[String],
) -> Result<(), Error> {
    let desired: BTreeSet<String> = keys.iter().cloned().collect();
    let interactive_metadata: HashMap<String, Option<String>> = interactive_vault
        .list(VaultScope::Interactive, store)?
        .into_iter()
        .map(|info| (info.name, info.metadata))
        .collect();

    let mut staged = Vec::with_capacity(desired.len());
    for key in &desired {
        staged.push(StagedCredential {
            name: key.clone(),
            value: interactive_vault.get(VaultScope::Interactive, store, key)?,
            metadata: interactive_metadata.get(key).cloned().unwrap_or(None),
        });
    }

    for key in list_headless_keys(store)? {
        if !desired.contains(&key) {
            headless_vault.remove(VaultScope::Headless, store, &key)?;
        }
    }

    for cred in &staged {
        headless_vault.replace(
            VaultScope::Headless,
            store,
            &cred.name,
            &cred.value,
            cred.metadata.as_deref(),
        )?;
    }

    staged.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn replace_headless_subset_copies_requested_keys_and_prunes_stale_rows() {
        let store = DaemonStore::open_in_memory_without_vault().expect("store");
        let interactive = Vault::new(key(0x11));
        let headless = Vault::new(key(0x22));

        interactive
            .add(
                VaultScope::Interactive,
                &store,
                "svc/keep-a",
                b"interactive-a",
                Some("meta-a"),
            )
            .unwrap();
        interactive
            .add(
                VaultScope::Interactive,
                &store,
                "svc/keep-b",
                b"interactive-b",
                None,
            )
            .unwrap();
        interactive
            .add(
                VaultScope::Interactive,
                &store,
                "svc/drop-c",
                b"interactive-c",
                Some("meta-c"),
            )
            .unwrap();

        headless
            .add(
                VaultScope::Headless,
                &store,
                "svc/stale",
                b"stale",
                Some("stale-meta"),
            )
            .unwrap();

        replace_headless_subset(
            &interactive,
            &headless,
            &store,
            &["svc/keep-a".to_string(), "svc/keep-b".to_string()],
        )
        .unwrap();

        assert_eq!(
            headless
                .get(VaultScope::Headless, &store, "svc/keep-a")
                .unwrap(),
            b"interactive-a"
        );
        assert_eq!(
            headless
                .get(VaultScope::Headless, &store, "svc/keep-b")
                .unwrap(),
            b"interactive-b"
        );
        assert!(matches!(
            headless.get(VaultScope::Headless, &store, "svc/drop-c"),
            Err(VaultError::NotFound)
        ));
        assert!(matches!(
            headless.get(VaultScope::Headless, &store, "svc/stale"),
            Err(VaultError::NotFound)
        ));

        let headless_info = headless.list(VaultScope::Headless, &store).unwrap();
        let keep_a = headless_info
            .iter()
            .find(|info| info.name == "svc/keep-a")
            .unwrap();
        assert_eq!(keep_a.metadata.as_deref(), Some("meta-a"));
    }

    #[test]
    fn clear_headless_scope_removes_only_headless_rows() {
        let store = DaemonStore::open_in_memory_without_vault().expect("store");
        let interactive = Vault::new(key(0x31));
        let headless = Vault::new(key(0x32));

        interactive
            .add(
                VaultScope::Interactive,
                &store,
                "svc/shared-name",
                b"interactive",
                None,
            )
            .unwrap();
        headless
            .add(
                VaultScope::Headless,
                &store,
                "svc/shared-name",
                b"headless",
                None,
            )
            .unwrap();
        headless
            .add(
                VaultScope::Headless,
                &store,
                "svc/only-headless",
                b"headless-2",
                None,
            )
            .unwrap();

        let deleted = clear_headless_scope(&store).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(
            interactive
                .get(VaultScope::Interactive, &store, "svc/shared-name")
                .unwrap(),
            b"interactive"
        );
        assert!(list_headless_keys(&store).unwrap().is_empty());
    }
}
