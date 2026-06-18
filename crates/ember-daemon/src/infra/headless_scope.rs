//! Headless-scope subset management for ADR 139.
//!
//! This module keeps the local-vault headless lane honest:
//! - the headless scope is an explicit subset, not a hidden alias of the
//!   interactive scope
//! - stale headless ciphertext is pruned when enrollment disappears
//! - future `headless_enroll` wiring gets one adapter instead of open-coded
//!   copy/remove loops spread across handler and runtime paths

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use rusqlite::params;
use serde::{Deserialize, Serialize};
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
    #[error("material: {0}")]
    Material(String),
}

const ENV_MATERIAL_PREFIX: &str = "headless/material/env/";
const FILE_MATERIAL_PREFIX: &str = "headless/material/file/";

#[derive(Zeroize, ZeroizeOnDrop)]
struct StagedCredential {
    name: String,
    value: Vec<u8>,
    metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FileSnapshot {
    kind: String,
    entries: Vec<FileSnapshotEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FileSnapshotEntry {
    relative_path: String,
    data_base64: String,
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
            .map_err(StoreError::Sqlite)?;
    }
    Ok(deleted)
}

pub fn replace_headless_subset(
    interactive_vault: &Vault,
    headless_vault: &Vault,
    store: &DaemonStore,
    authority_keys: &[String],
    vault_paths: &[String],
    env_passthrough: &[String],
    file_env: &[String],
) -> Result<(), Error> {
    let mut desired: BTreeSet<String> = authority_keys.iter().cloned().collect();
    desired.extend(vault_paths.iter().cloned());
    desired.extend(env_passthrough.iter().map(|name| env_material_key(name)));
    desired.extend(file_env.iter().map(|name| file_material_key(name)));
    let interactive_metadata: HashMap<String, Option<String>> = interactive_vault
        .list(VaultScope::Interactive, store)?
        .into_iter()
        .map(|info| (info.name, info.metadata))
        .collect();

    let mut staged = Vec::with_capacity(desired.len());
    for key in authority_keys.iter().chain(vault_paths.iter()) {
        staged.push(StagedCredential {
            name: key.clone(),
            value: interactive_vault
                .get(VaultScope::Interactive, store, key)?
                .to_vec(),
            metadata: interactive_metadata.get(key).cloned().unwrap_or(None),
        });
    }
    for name in env_passthrough {
        let value = std::env::var(name)
            .map_err(|err| Error::Material(format!("read env {name}: {err}")))?;
        staged.push(StagedCredential {
            name: env_material_key(name),
            value: value.into_bytes(),
            metadata: Some(format!("headless-env:{name}")),
        });
    }
    for name in file_env {
        let path = std::env::var(name)
            .map_err(|err| Error::Material(format!("read file env {name}: {err}")))?;
        let snapshot = snapshot_file_env(Path::new(&path))
            .map_err(|err| Error::Material(format!("snapshot {name}={path}: {err}")))?;
        staged.push(StagedCredential {
            name: file_material_key(name),
            value: serde_json::to_vec(&snapshot)
                .map_err(|err| Error::Material(format!("serialize file env {name}: {err}")))?,
            metadata: Some(format!("headless-file-env:{name}")),
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

pub fn env_material_key(name: &str) -> String {
    format!("{ENV_MATERIAL_PREFIX}name-{}", hex::encode(name.as_bytes()))
}

pub fn file_material_key(name: &str) -> String {
    format!(
        "{FILE_MATERIAL_PREFIX}name-{}",
        hex::encode(name.as_bytes())
    )
}

fn snapshot_file_env(path: &Path) -> Result<FileSnapshot, String> {
    let metadata = fs::metadata(path).map_err(|err| format!("stat {}: {err}", path.display()))?;
    if metadata.is_file() {
        let bytes = fs::read(path).map_err(|err| format!("read {}: {err}", path.display()))?;
        return Ok(FileSnapshot {
            kind: "file".to_string(),
            entries: vec![FileSnapshotEntry {
                relative_path: String::new(),
                data_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            }],
        });
    }
    if metadata.is_dir() {
        let mut entries = Vec::new();
        snapshot_directory(path, path, &mut entries)?;
        entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        return Ok(FileSnapshot {
            kind: "directory".to_string(),
            entries,
        });
    }
    Err(format!(
        "{} is neither a regular file nor a directory",
        path.display()
    ))
}

fn snapshot_directory(
    root: &Path,
    current: &Path,
    entries: &mut Vec<FileSnapshotEntry>,
) -> Result<(), String> {
    let read_dir =
        fs::read_dir(current).map_err(|err| format!("read_dir {}: {err}", current.display()))?;
    let mut children: Vec<PathBuf> = read_dir
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("walk {}: {err}", current.display()))?;
    children.sort();
    for child in children {
        let metadata =
            fs::metadata(&child).map_err(|err| format!("stat {}: {err}", child.display()))?;
        if metadata.is_dir() {
            snapshot_directory(root, &child, entries)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(format!(
                "unsupported non-file entry in directory snapshot: {}",
                child.display()
            ));
        }
        let bytes = fs::read(&child).map_err(|err| format!("read {}: {err}", child.display()))?;
        let relative = child
            .strip_prefix(root)
            .map_err(|err| format!("strip prefix {}: {err}", child.display()))?;
        entries.push(FileSnapshotEntry {
            relative_path: relative.to_string_lossy().to_string(),
            data_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        });
    }
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
            &[],
            &[],
            &[],
        )
        .unwrap();

        assert_eq!(
            headless
                .get(VaultScope::Headless, &store, "svc/keep-a")
                .unwrap()
                .as_slice(),
            b"interactive-a"
        );
        assert_eq!(
            headless
                .get(VaultScope::Headless, &store, "svc/keep-b")
                .unwrap()
                .as_slice(),
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
    fn replace_headless_subset_captures_env_and_file_material() {
        let store = DaemonStore::open_in_memory_without_vault().expect("store");
        let interactive = Vault::new(key(0x41));
        let headless = Vault::new(key(0x42));
        let tmp = tempfile::tempdir().unwrap();
        let kubeconfig = tmp.path().join("config");
        fs::write(&kubeconfig, b"clusters: []").unwrap();
        let docker_dir = tmp.path().join("docker");
        fs::create_dir_all(&docker_dir).unwrap();
        fs::write(docker_dir.join("config.json"), br#"{"auths":{}}"#).unwrap();

        // SAFETY: test-scoped environment mutation in a single-threaded unit test.
        unsafe {
            std::env::set_var("KUBECONFIG", &kubeconfig);
            std::env::set_var("DOCKER_CONFIG", &docker_dir);
        }

        replace_headless_subset(
            &interactive,
            &headless,
            &store,
            &[],
            &[],
            &["KUBECONFIG".to_string()],
            &["DOCKER_CONFIG".to_string()],
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(
                headless
                    .get(
                        VaultScope::Headless,
                        &store,
                        &env_material_key("KUBECONFIG")
                    )
                    .unwrap()
                    .to_vec()
            )
            .unwrap(),
            kubeconfig.display().to_string()
        );
        let file_snapshot = headless
            .get(
                VaultScope::Headless,
                &store,
                &file_material_key("DOCKER_CONFIG"),
            )
            .unwrap();
        let parsed: FileSnapshot = serde_json::from_slice(&file_snapshot).unwrap();
        assert_eq!(parsed.kind, "directory");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].relative_path, "config.json");
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
                .unwrap()
                .as_slice(),
            b"interactive"
        );
        assert!(list_headless_keys(&store).unwrap().is_empty());
    }
}
