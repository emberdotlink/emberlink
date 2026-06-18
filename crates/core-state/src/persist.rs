use std::collections::{BTreeMap, BTreeSet, HashMap};

use core_crypto::{
    EncryptedContent, LocalKeyPair, PublicKey, Signature, decrypt_content, encrypt_content,
};
use core_event_types::{
    ChunkReference, EventRefRelation, EventSubject, EventType, FileManifest, KeyRole,
    ManifestDeviceAccess, PresentationArtifact, PresentationTemplate, SignerBinding, SubjectKind,
    VaultNamespace, VaultOwnerKind,
};
use core_events::{EventEnvelope, EventRef};
use core_storage::{EncryptedBlock, PresentationArtifactEnvelope};
use core_types::{
    CanonicalEncode, SchemaVersion, Validate, ValidationError, bytes_to_hex, hex_to_bytes,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use zeroize::Zeroizing;

const COLUMN_ENC_TAG: &str = "ENC1:";

/// Encrypt a plaintext column value using the master key.
/// Output format: `ENC1:{nonce_hex}:{ciphertext_hex}`
pub(crate) fn encrypt_column(
    master_key: &str,
    plaintext: &str,
    aad: &[u8],
) -> Result<String, ValidationError> {
    let enc = encrypt_content(master_key, plaintext.as_bytes(), aad)?;
    Ok(format!(
        "{}{}:{}",
        COLUMN_ENC_TAG,
        enc.nonce_hex,
        bytes_to_hex(&enc.ciphertext)
    ))
}

/// Decrypt a column value encrypted with [`encrypt_column`].
///
/// If the stored value does not start with `ENC1:` it is returned as-is,
/// allowing existing plaintext rows to be read without a migration step.
///
/// Returns a `Zeroizing<String>` so the decrypted secret zeroizes on drop
/// (N6-deeper, see PR #5861). Callers should keep the value in the
/// `Zeroizing` wrapper end-to-end and use `.as_str()` at point of use.
pub(crate) fn decrypt_column(
    master_key: &str,
    stored: &str,
    aad: &[u8],
) -> Result<Zeroizing<String>, ValidationError> {
    let Some(rest) = stored.strip_prefix(COLUMN_ENC_TAG) else {
        // Plaintext fallback: row was written before encryption was enabled.
        // Wrap so the caller path is uniform even when the row hasn't been
        // upgraded to ENC1 yet — the secret bytes still want to zeroize.
        return Ok(Zeroizing::new(stored.to_string()));
    };
    let (nonce_hex, ciphertext_hex) = rest.split_once(':').ok_or_else(|| {
        ValidationError::new("malformed encrypted column value: missing ':' separator".to_string())
    })?;
    let ciphertext = hex_to_bytes(ciphertext_hex).map_err(|e| {
        ValidationError::new(format!("encrypted column ciphertext hex decode: {e}"))
    })?;
    let plaintext_bytes = decrypt_content(
        master_key,
        &EncryptedContent {
            nonce_hex: nonce_hex.to_string(),
            ciphertext,
        },
        aad,
    )?;
    String::from_utf8(plaintext_bytes)
        .map(Zeroizing::new)
        .map_err(|e| ValidationError::new(format!("decrypted column is not valid UTF-8: {e}")))
}

use crate::{
    DeviceStatus, LocalBlockRecord, LocalPresentationArtifactRecord, MaterializedState,
    PersonaStatus, ReceivedDisclosureSourceKind, ReceivedPresentationArtifactRecord,
    RecoveryRequestStatus, RootStatus,
};

pub(crate) fn persist_event(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<(), ValidationError> {
    tx.execute(
        "INSERT INTO events (
            event_id,
            schema_version,
            event_type,
            subject_kind,
            subject_id,
            signer_kind,
            signer_id,
            signer_role,
            signer_key_id,
            signer_public_key,
            payload,
            retention_class
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            &event.event_id,
            event.schema_version.to_string(),
            event.event_type.as_str(),
            event.subject.kind.as_str(),
            &event.subject.subject_id,
            event.signer_binding.signer.kind.as_str(),
            &event.signer_binding.signer.subject_id,
            event.signer_binding.role.as_str(),
            &event.signer_binding.key_id,
            &event.signer.0,
            &event.payload,
            event.event_type.retention_class().as_str(),
        ],
    )
    .map_err(|err| ValidationError::new(format!("insert event row: {err}")))?;

    for reference in &event.refs {
        tx.execute(
            "INSERT INTO event_refs (event_id, relation, target_event_id, seq) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                &event.event_id,
                reference.relation.as_str(),
                &reference.target_event_id,
                // `seq` is part of the canonical signing pre-image — persist it so a
                // reloaded chain still verifies (ADR 200 AC-1). Dropping it (the
                // pre-fix behavior) silently broke `verify_chain` after restart.
                // SQLite has no u64; store as i64 (per-root seq never approaches i64::MAX).
                reference.seq as i64,
            ],
        )
        .map_err(|err| ValidationError::new(format!("insert event ref row: {err}")))?;
    }

    tx.execute(
        "INSERT INTO event_signatures (event_id, signer, signature) VALUES (?1, ?2, ?3)",
        params![&event.event_id, &event.signer.0, &event.signature.0],
    )
    .map_err(|err| ValidationError::new(format!("insert event signature row: {err}")))?;

    Ok(())
}

pub(crate) fn write_file_manifest(
    tx: &Transaction<'_>,
    manifest: &FileManifest,
) -> Result<(), ValidationError> {
    tx.execute(
        "INSERT INTO storage_manifests_current (
            manifest_id,
            encrypted_root_chunk_id,
            chunk_count
         ) VALUES (?1, ?2, ?3)
         ON CONFLICT(manifest_id) DO UPDATE SET
            encrypted_root_chunk_id = excluded.encrypted_root_chunk_id,
            chunk_count = excluded.chunk_count",
        params![
            &manifest.id,
            &manifest.encrypted_root_chunk_id,
            manifest.chunks.len() as u32,
        ],
    )
    .map_err(|err| ValidationError::new(format!("write storage manifest: {err}")))?;

    tx.execute(
        "DELETE FROM storage_manifest_device_access_current WHERE manifest_id = ?1",
        params![&manifest.id],
    )
    .map_err(|err| ValidationError::new(format!("clear manifest device access: {err}")))?;
    tx.execute(
        "DELETE FROM storage_manifest_chunks_current WHERE manifest_id = ?1",
        params![&manifest.id],
    )
    .map_err(|err| ValidationError::new(format!("clear manifest chunks: {err}")))?;

    for access in &manifest.authorized_devices {
        tx.execute(
            "INSERT INTO storage_manifest_device_access_current (
                manifest_id,
                device_id,
                wrapped_manifest_key_hex
             ) VALUES (?1, ?2, ?3)",
            params![
                &manifest.id,
                &access.device_id,
                &access.wrapped_manifest_key_hex
            ],
        )
        .map_err(|err| ValidationError::new(format!("write manifest device access: {err}")))?;
    }

    let mut chunks = manifest.chunks.clone();
    chunks.sort_by(|left, right| {
        left.ordinal
            .cmp(&right.ordinal)
            .then_with(|| left.chunk_id.cmp(&right.chunk_id))
    });
    for chunk in &chunks {
        tx.execute(
            "INSERT INTO storage_manifest_chunks_current (
                manifest_id,
                ordinal,
                chunk_id,
                ciphertext_bytes
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                &chunk.manifest_id,
                chunk.ordinal,
                &chunk.chunk_id,
                // rusqlite 0.39 removed u64 ToSql; SQLite integers are signed i64.
                chunk.ciphertext_bytes as i64
            ],
        )
        .map_err(|err| ValidationError::new(format!("write manifest chunk row: {err}")))?;
    }

    Ok(())
}

pub(crate) fn write_local_file_manifest(
    tx: &Transaction<'_>,
    manifest: &FileManifest,
) -> Result<(), ValidationError> {
    tx.execute(
        "INSERT INTO local_manifests (
            manifest_id,
            encrypted_root_chunk_id,
            chunk_count
         ) VALUES (?1, ?2, ?3)
         ON CONFLICT(manifest_id) DO UPDATE SET
            encrypted_root_chunk_id = excluded.encrypted_root_chunk_id,
            chunk_count = excluded.chunk_count",
        params![
            &manifest.id,
            &manifest.encrypted_root_chunk_id,
            manifest.chunks.len() as u32,
        ],
    )
    .map_err(|err| ValidationError::new(format!("write local manifest: {err}")))?;

    tx.execute(
        "DELETE FROM local_manifest_device_access WHERE manifest_id = ?1",
        params![&manifest.id],
    )
    .map_err(|err| ValidationError::new(format!("clear local manifest device access: {err}")))?;
    tx.execute(
        "DELETE FROM local_manifest_chunks WHERE manifest_id = ?1",
        params![&manifest.id],
    )
    .map_err(|err| ValidationError::new(format!("clear local manifest chunks: {err}")))?;

    for access in &manifest.authorized_devices {
        tx.execute(
            "INSERT INTO local_manifest_device_access (
                manifest_id,
                device_id,
                wrapped_manifest_key_hex
             ) VALUES (?1, ?2, ?3)",
            params![
                &manifest.id,
                &access.device_id,
                &access.wrapped_manifest_key_hex
            ],
        )
        .map_err(|err| ValidationError::new(format!("write local manifest access: {err}")))?;
    }

    let mut chunks = manifest.chunks.clone();
    chunks.sort_by(|left, right| {
        left.ordinal
            .cmp(&right.ordinal)
            .then_with(|| left.chunk_id.cmp(&right.chunk_id))
    });
    for chunk in &chunks {
        tx.execute(
            "INSERT INTO local_manifest_chunks (
                manifest_id,
                ordinal,
                chunk_id,
                ciphertext_bytes
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                &chunk.manifest_id,
                chunk.ordinal,
                &chunk.chunk_id,
                // rusqlite 0.39 removed u64 ToSql; SQLite integers are signed i64.
                chunk.ciphertext_bytes as i64
            ],
        )
        .map_err(|err| ValidationError::new(format!("write local manifest chunk row: {err}")))?;
    }

    Ok(())
}

pub(crate) fn delete_local_file_manifest(
    tx: &Transaction<'_>,
    manifest_id: &str,
) -> Result<(), ValidationError> {
    tx.execute(
        "DELETE FROM local_manifest_device_access WHERE manifest_id = ?1",
        params![manifest_id],
    )
    .map_err(|err| ValidationError::new(format!("delete local manifest device access: {err}")))?;
    tx.execute(
        "DELETE FROM local_manifest_chunks WHERE manifest_id = ?1",
        params![manifest_id],
    )
    .map_err(|err| ValidationError::new(format!("delete local manifest chunks: {err}")))?;
    tx.execute(
        "DELETE FROM local_manifests WHERE manifest_id = ?1",
        params![manifest_id],
    )
    .map_err(|err| ValidationError::new(format!("delete local manifest: {err}")))?;
    Ok(())
}

#[allow(dead_code)] // needed once sync materializes remote manifests
pub(crate) fn load_file_manifest(
    conn: &Connection,
    manifest_id: &str,
) -> Result<Option<FileManifest>, ValidationError> {
    let manifest_row: Option<String> = conn
        .query_row(
            "SELECT encrypted_root_chunk_id
             FROM storage_manifests_current
             WHERE manifest_id = ?1",
            params![manifest_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| ValidationError::new(format!("load storage manifest: {err}")))?;

    let Some(encrypted_root_chunk_id) = manifest_row else {
        return Ok(None);
    };

    let mut chunk_stmt = conn
        .prepare(
            "SELECT chunk_id, ordinal, ciphertext_bytes
             FROM storage_manifest_chunks_current
             WHERE manifest_id = ?1
             ORDER BY ordinal ASC, chunk_id ASC",
        )
        .map_err(|err| ValidationError::new(format!("prepare manifest chunk lookup: {err}")))?;
    let chunk_rows = chunk_stmt
        .query_map(params![manifest_id], |row| {
            Ok(ChunkReference {
                manifest_id: manifest_id.to_string(),
                chunk_id: row.get(0)?,
                ordinal: row.get(1)?,
                // rusqlite 0.39 removed u64 FromSql; read as i64 and cast.
                ciphertext_bytes: row.get::<_, i64>(2)? as u64,
            })
        })
        .map_err(|err| ValidationError::new(format!("query manifest chunk rows: {err}")))?;

    let mut chunks = Vec::new();
    for row in chunk_rows {
        chunks.push(
            row.map_err(|err| ValidationError::new(format!("read manifest chunk row: {err}")))?,
        );
    }

    let mut stmt = conn
        .prepare(
            "SELECT device_id, wrapped_manifest_key_hex
             FROM storage_manifest_device_access_current
             WHERE manifest_id = ?1
             ORDER BY device_id ASC",
        )
        .map_err(|err| ValidationError::new(format!("prepare manifest access lookup: {err}")))?;
    let rows = stmt
        .query_map(params![manifest_id], |row| {
            Ok(ManifestDeviceAccess {
                device_id: row.get(0)?,
                wrapped_manifest_key_hex: row.get(1)?,
            })
        })
        .map_err(|err| ValidationError::new(format!("query manifest access rows: {err}")))?;

    let mut authorized_devices = Vec::new();
    for row in rows {
        authorized_devices.push(
            row.map_err(|err| ValidationError::new(format!("read manifest access row: {err}")))?,
        );
    }

    Ok(Some(FileManifest {
        id: manifest_id.to_string(),
        encrypted_root_chunk_id,
        chunks,
        authorized_devices,
    }))
}

pub(crate) fn load_local_file_manifest(
    conn: &Connection,
    manifest_id: &str,
) -> Result<Option<FileManifest>, ValidationError> {
    let manifest_row: Option<String> = conn
        .query_row(
            "SELECT encrypted_root_chunk_id
             FROM local_manifests
             WHERE manifest_id = ?1",
            params![manifest_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| ValidationError::new(format!("load local manifest: {err}")))?;

    let Some(encrypted_root_chunk_id) = manifest_row else {
        return Ok(None);
    };

    let mut chunk_stmt = conn
        .prepare(
            "SELECT chunk_id, ordinal, ciphertext_bytes
             FROM local_manifest_chunks
             WHERE manifest_id = ?1
             ORDER BY ordinal ASC, chunk_id ASC",
        )
        .map_err(|err| {
            ValidationError::new(format!("prepare local manifest chunk lookup: {err}"))
        })?;
    let chunk_rows = chunk_stmt
        .query_map(params![manifest_id], |row| {
            Ok(ChunkReference {
                manifest_id: manifest_id.to_string(),
                chunk_id: row.get(0)?,
                ordinal: row.get(1)?,
                // rusqlite 0.39 removed u64 FromSql; read as i64 and cast.
                ciphertext_bytes: row.get::<_, i64>(2)? as u64,
            })
        })
        .map_err(|err| ValidationError::new(format!("query local manifest chunk rows: {err}")))?;

    let mut chunks = Vec::new();
    for row in chunk_rows {
        chunks.push(row.map_err(|err| {
            ValidationError::new(format!("read local manifest chunk row: {err}"))
        })?);
    }

    let mut stmt = conn
        .prepare(
            "SELECT device_id, wrapped_manifest_key_hex
             FROM local_manifest_device_access
             WHERE manifest_id = ?1
             ORDER BY device_id ASC",
        )
        .map_err(|err| {
            ValidationError::new(format!("prepare local manifest access lookup: {err}"))
        })?;
    let rows = stmt
        .query_map(params![manifest_id], |row| {
            Ok(ManifestDeviceAccess {
                device_id: row.get(0)?,
                wrapped_manifest_key_hex: row.get(1)?,
            })
        })
        .map_err(|err| ValidationError::new(format!("query local manifest access rows: {err}")))?;

    let mut authorized_devices = Vec::new();
    for row in rows {
        authorized_devices.push(row.map_err(|err| {
            ValidationError::new(format!("read local manifest access row: {err}"))
        })?);
    }

    Ok(Some(FileManifest {
        id: manifest_id.to_string(),
        encrypted_root_chunk_id,
        chunks,
        authorized_devices,
    }))
}

#[allow(dead_code)] // needed once sync materializes remote manifests
pub(crate) fn load_all_file_manifests(
    conn: &Connection,
) -> Result<BTreeMap<String, FileManifest>, ValidationError> {
    let mut stmt = conn
        .prepare("SELECT manifest_id FROM storage_manifests_current ORDER BY manifest_id ASC")
        .map_err(|err| ValidationError::new(format!("prepare manifest id query: {err}")))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|err| ValidationError::new(format!("query manifest ids: {err}")))?;

    let mut manifests = BTreeMap::new();
    for row in rows {
        let manifest_id =
            row.map_err(|err| ValidationError::new(format!("read manifest id row: {err}")))?;
        if let Some(manifest) = load_file_manifest(conn, &manifest_id)? {
            manifests.insert(manifest.id.clone(), manifest);
        }
    }
    Ok(manifests)
}

pub(crate) fn load_all_local_file_manifests(
    conn: &Connection,
) -> Result<BTreeMap<String, FileManifest>, ValidationError> {
    let mut stmt = conn
        .prepare("SELECT manifest_id FROM local_manifests ORDER BY manifest_id ASC")
        .map_err(|err| ValidationError::new(format!("prepare local manifest id query: {err}")))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|err| ValidationError::new(format!("query local manifest ids: {err}")))?;

    let mut manifests = BTreeMap::new();
    for row in rows {
        let manifest_id =
            row.map_err(|err| ValidationError::new(format!("read local manifest id row: {err}")))?;
        if let Some(manifest) = load_local_file_manifest(conn, &manifest_id)? {
            manifests.insert(manifest.id.clone(), manifest);
        }
    }
    Ok(manifests)
}

pub(crate) fn write_all_file_manifests(
    tx: &Transaction<'_>,
    manifests: &BTreeMap<String, FileManifest>,
) -> Result<(), ValidationError> {
    // Upsert each manifest (per-manifest delete of children + reinsert)
    for manifest in manifests.values() {
        write_file_manifest(tx, manifest)?;
    }

    // Remove stale manifests no longer in the active set
    if manifests.is_empty() {
        tx.execute("DELETE FROM storage_manifest_device_access_current", [])
            .map_err(|err| ValidationError::new(format!("clear device access: {err}")))?;
        tx.execute("DELETE FROM storage_manifest_chunks_current", [])
            .map_err(|err| ValidationError::new(format!("clear chunks: {err}")))?;
        tx.execute("DELETE FROM storage_manifests_current", [])
            .map_err(|err| ValidationError::new(format!("clear manifests: {err}")))?;
    } else {
        let placeholders: Vec<String> = (1..=manifests.len()).map(|i| format!("?{i}")).collect();
        let ids: Vec<&str> = manifests.keys().map(|k| k.as_str()).collect();
        let sql = format!(
            "DELETE FROM storage_manifests_current WHERE manifest_id NOT IN ({})",
            placeholders.join(", ")
        );
        tx.execute(&sql, rusqlite::params_from_iter(&ids))
            .map_err(|err| ValidationError::new(format!("prune stale manifests: {err}")))?;
        let sql = format!(
            "DELETE FROM storage_manifest_chunks_current WHERE manifest_id NOT IN ({})",
            placeholders.join(", ")
        );
        tx.execute(&sql, rusqlite::params_from_iter(&ids))
            .map_err(|err| ValidationError::new(format!("prune stale manifest chunks: {err}")))?;
        let sql = format!(
            "DELETE FROM storage_manifest_device_access_current WHERE manifest_id NOT IN ({})",
            placeholders.join(", ")
        );
        tx.execute(&sql, rusqlite::params_from_iter(&ids))
            .map_err(|err| ValidationError::new(format!("prune stale manifest access: {err}")))?;
    }

    Ok(())
}

pub(crate) fn write_local_block(
    tx: &Transaction<'_>,
    block: &LocalBlockRecord,
) -> Result<(), ValidationError> {
    tx.execute(
        "INSERT INTO local_blocks (chunk_id, ciphertext_bytes, nonce_hex, ciphertext)
         VALUES (?1, ?2, NULL, NULL)
         ON CONFLICT(chunk_id) DO UPDATE SET
            ciphertext_bytes = excluded.ciphertext_bytes",
        // rusqlite 0.39 removed u64 ToSql; SQLite integers are signed i64.
        params![&block.chunk_id, block.ciphertext_bytes as i64],
    )
    .map_err(|err| ValidationError::new(format!("write local block: {err}")))?;
    Ok(())
}

pub(crate) fn write_encrypted_local_block(
    tx: &Transaction<'_>,
    block: &EncryptedBlock,
) -> Result<(), ValidationError> {
    tx.execute(
        "INSERT INTO local_blocks (chunk_id, ciphertext_bytes, nonce_hex, ciphertext)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(chunk_id) DO UPDATE SET
            ciphertext_bytes = excluded.ciphertext_bytes,
            nonce_hex = excluded.nonce_hex,
            ciphertext = excluded.ciphertext",
        params![
            &block.chunk.chunk_id,
            // rusqlite 0.39 removed u64 ToSql; SQLite integers are signed i64.
            block.chunk.ciphertext_bytes as i64,
            &block.encrypted.nonce_hex,
            &block.encrypted.ciphertext
        ],
    )
    .map_err(|err| ValidationError::new(format!("write encrypted local block: {err}")))?;
    Ok(())
}

pub(crate) fn load_local_block_ids(conn: &Connection) -> Result<BTreeSet<String>, ValidationError> {
    let mut stmt = conn
        .prepare("SELECT chunk_id FROM local_blocks ORDER BY chunk_id ASC")
        .map_err(|err| ValidationError::new(format!("prepare local block lookup: {err}")))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|err| ValidationError::new(format!("query local block rows: {err}")))?;

    let mut block_ids = BTreeSet::new();
    for row in rows {
        block_ids.insert(
            row.map_err(|err| ValidationError::new(format!("read local block row: {err}")))?,
        );
    }
    Ok(block_ids)
}

pub(crate) fn delete_local_block(
    tx: &Transaction<'_>,
    chunk_id: &str,
) -> Result<(), ValidationError> {
    tx.execute(
        "DELETE FROM local_blocks WHERE chunk_id = ?1",
        params![chunk_id],
    )
    .map_err(|err| ValidationError::new(format!("delete local block row: {err}")))?;
    Ok(())
}

pub(crate) fn load_local_encrypted_content(
    conn: &Connection,
    chunk_id: &str,
) -> Result<Option<EncryptedContent>, ValidationError> {
    conn.query_row(
        "SELECT nonce_hex, ciphertext
         FROM local_blocks
         WHERE chunk_id = ?1 AND nonce_hex IS NOT NULL AND ciphertext IS NOT NULL",
        params![chunk_id],
        |row| {
            Ok(EncryptedContent {
                nonce_hex: row.get(0)?,
                ciphertext: row.get(1)?,
            })
        },
    )
    .optional()
    .map_err(|err| ValidationError::new(format!("load encrypted local block: {err}")))
}

pub(crate) fn write_local_vault_catalog_head(
    tx: &Transaction<'_>,
    namespace: &VaultNamespace,
    manifest: &FileManifest,
    content_key: &str,
    master_key: Option<&str>,
) -> Result<(), ValidationError> {
    let stored_key = if let Some(mk) = master_key {
        let aad = format!(
            "vault-catalog-key:{}:{}",
            namespace.owner_kind.as_str(),
            &namespace.owner_id
        );
        encrypt_column(mk, content_key, aad.as_bytes())?
    } else {
        content_key.to_string()
    };
    tx.execute(
        "INSERT INTO local_vault_catalogs (
            owner_kind,
            owner_id,
            manifest_id,
            manifest_payload,
            content_key
         )
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(owner_kind, owner_id) DO UPDATE SET
            manifest_id = excluded.manifest_id,
            manifest_payload = excluded.manifest_payload,
            content_key = excluded.content_key",
        params![
            namespace.owner_kind.as_str(),
            &namespace.owner_id,
            &manifest.id,
            manifest.canonical_encode(),
            stored_key
        ],
    )
    .map_err(|err| ValidationError::new(format!("write local vault catalog head: {err}")))?;
    tx.execute(
        "INSERT OR IGNORE INTO local_vault_catalog_manifest_history (
            owner_kind,
            owner_id,
            manifest_id
         )
         VALUES (?1, ?2, ?3)",
        params![
            namespace.owner_kind.as_str(),
            &namespace.owner_id,
            &manifest.id
        ],
    )
    .map_err(|err| {
        ValidationError::new(format!("write local vault catalog manifest history: {err}"))
    })?;
    Ok(())
}

pub(crate) fn validate_encrypted_manifest_blocks(
    manifest: &FileManifest,
    blocks: &[EncryptedBlock],
) -> Result<(), ValidationError> {
    manifest.validate()?;
    if blocks.len() != manifest.chunks.len() {
        return Err(ValidationError::new(
            "encrypted manifest blocks must match manifest chunk count",
        ));
    }
    let blocks_by_chunk = blocks
        .iter()
        .map(|block| (block.chunk.chunk_id.as_str(), block))
        .collect::<BTreeMap<_, _>>();
    for chunk in &manifest.chunks {
        let block = blocks_by_chunk
            .get(chunk.chunk_id.as_str())
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "encrypted manifest is missing block for chunk: {}",
                    chunk.chunk_id
                ))
            })?;
        if block.chunk != *chunk {
            return Err(ValidationError::new(format!(
                "encrypted manifest block metadata does not match chunk: {}",
                chunk.chunk_id
            )));
        }
    }
    Ok(())
}

/// Load the head of a local vault catalog along with its content key.
///
/// The content key is returned in a `Zeroizing<String>` (N6-deeper, see
/// PR #5861) so it zeroizes on drop. Callers should keep the value in the
/// wrapper end-to-end and only `.as_str()` at point of use.
pub(crate) fn load_local_vault_catalog_head(
    conn: &Connection,
    namespace: &VaultNamespace,
    master_key: Option<&str>,
) -> Result<Option<(FileManifest, Zeroizing<String>)>, ValidationError> {
    let row = conn
        .query_row(
            "SELECT manifest_payload, content_key
         FROM local_vault_catalogs
         WHERE owner_kind = ?1 AND owner_id = ?2",
            params![namespace.owner_kind.as_str(), &namespace.owner_id],
            |row| {
                let manifest_payload = row.get::<_, Vec<u8>>(0)?;
                let content_key = row.get::<_, String>(1)?;
                Ok((manifest_payload, content_key))
            },
        )
        .optional()
        .map_err(|err| ValidationError::new(format!("load local vault catalog head: {err}")))?;

    let Some((manifest_payload, stored_key)) = row else {
        return Ok(None);
    };

    let content_key: Zeroizing<String> = if let Some(mk) = master_key {
        let aad = format!(
            "vault-catalog-key:{}:{}",
            namespace.owner_kind.as_str(),
            &namespace.owner_id
        );
        decrypt_column(mk, &stored_key, aad.as_bytes())?
    } else {
        // Plaintext fallback: vault was never sealed at rest, but the value is
        // still a content key and should zeroize on drop.
        Zeroizing::new(stored_key)
    };

    let manifest = FileManifest::decode_canonical(&manifest_payload)?;
    Ok(Some((manifest, content_key)))
}

pub(crate) fn load_local_vault_catalog_manifest_ids(
    conn: &Connection,
    namespace: &VaultNamespace,
) -> Result<BTreeSet<String>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT manifest_id
             FROM local_vault_catalog_manifest_history
             WHERE owner_kind = ?1 AND owner_id = ?2
             ORDER BY manifest_id ASC",
        )
        .map_err(|err| {
            ValidationError::new(format!(
                "prepare local vault catalog manifest history query: {err}"
            ))
        })?;
    let mut rows = stmt
        .query(params![namespace.owner_kind.as_str(), &namespace.owner_id])
        .map_err(|err| {
            ValidationError::new(format!("query local vault catalog manifest history: {err}"))
        })?;
    let mut manifest_ids = BTreeSet::new();
    while let Some(row) = rows.next().map_err(|err| {
        ValidationError::new(format!(
            "iterate local vault catalog manifest history: {err}"
        ))
    })? {
        manifest_ids.insert(row.get::<_, String>(0).map_err(|err| {
            ValidationError::new(format!("read local vault catalog manifest id: {err}"))
        })?);
    }
    Ok(manifest_ids)
}

pub(crate) fn load_local_vault_namespaces(
    conn: &Connection,
) -> Result<Vec<VaultNamespace>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT owner_kind, owner_id
             FROM local_vault_catalogs
             ORDER BY owner_kind ASC, owner_id ASC",
        )
        .map_err(|err| {
            ValidationError::new(format!("prepare local vault namespace query: {err}"))
        })?;
    let mut rows = stmt
        .query([])
        .map_err(|err| ValidationError::new(format!("query local vault namespaces: {err}")))?;
    let mut namespaces = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| ValidationError::new(format!("iterate local vault namespaces: {err}")))?
    {
        let owner_kind = row
            .get::<_, String>(0)
            .map_err(|err| ValidationError::new(format!("read local vault owner kind: {err}")))?;
        let owner_id = row
            .get::<_, String>(1)
            .map_err(|err| ValidationError::new(format!("read local vault owner id: {err}")))?;
        let owner_kind = VaultOwnerKind::parse(&owner_kind).ok_or_else(|| {
            ValidationError::new(format!("invalid local vault owner kind: {owner_kind}"))
        })?;
        namespaces.push(VaultNamespace {
            owner_kind,
            owner_id,
        });
    }
    Ok(namespaces)
}

pub(crate) fn delete_local_vault_catalog_manifest_history(
    tx: &Transaction<'_>,
    namespace: &VaultNamespace,
    manifest_id: &str,
) -> Result<(), ValidationError> {
    tx.execute(
        "DELETE FROM local_vault_catalog_manifest_history
         WHERE owner_kind = ?1 AND owner_id = ?2 AND manifest_id = ?3",
        params![
            namespace.owner_kind.as_str(),
            &namespace.owner_id,
            manifest_id
        ],
    )
    .map_err(|err| {
        ValidationError::new(format!(
            "delete local vault catalog manifest history row: {err}"
        ))
    })?;
    Ok(())
}

pub(crate) fn write_local_presentation_template(
    tx: &Transaction<'_>,
    template: &PresentationTemplate,
) -> Result<(), ValidationError> {
    tx.execute(
        "INSERT INTO local_presentation_templates (template_id, template_payload)
         VALUES (?1, ?2)
         ON CONFLICT(template_id) DO UPDATE SET
            template_payload = excluded.template_payload",
        params![&template.id, template.canonical_encode()],
    )
    .map_err(|err| ValidationError::new(format!("write local presentation template: {err}")))?;
    Ok(())
}

pub(crate) fn load_local_presentation_template(
    conn: &Connection,
    template_id: &str,
) -> Result<Option<PresentationTemplate>, ValidationError> {
    conn.query_row(
        "SELECT template_payload
         FROM local_presentation_templates
         WHERE template_id = ?1",
        params![template_id],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(|err| ValidationError::new(format!("load local presentation template: {err}")))?
    .map(|payload| PresentationTemplate::decode_canonical(&payload))
    .transpose()
}

pub(crate) fn load_local_presentation_templates(
    conn: &Connection,
) -> Result<Vec<PresentationTemplate>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT template_payload
             FROM local_presentation_templates
             ORDER BY template_id ASC",
        )
        .map_err(|err| {
            ValidationError::new(format!("prepare local presentation template query: {err}"))
        })?;
    let mut rows = stmt.query([]).map_err(|err| {
        ValidationError::new(format!("query local presentation templates: {err}"))
    })?;
    let mut templates = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| ValidationError::new(format!("iterate presentation templates: {err}")))?
    {
        let payload = row
            .get::<_, Vec<u8>>(0)
            .map_err(|err| ValidationError::new(format!("read presentation template: {err}")))?;
        templates.push(PresentationTemplate::decode_canonical(&payload)?);
    }
    Ok(templates)
}

pub(crate) fn write_local_manifest_key(
    tx: &Transaction<'_>,
    manifest_id: &str,
    content_key: &str,
    master_key: Option<&str>,
) -> Result<(), ValidationError> {
    let stored_key = if let Some(mk) = master_key {
        encrypt_column(
            mk,
            content_key,
            format!("manifest-key:{manifest_id}").as_bytes(),
        )?
    } else {
        content_key.to_string()
    };
    tx.execute(
        "INSERT INTO local_manifest_keys (manifest_id, content_key)
         VALUES (?1, ?2)
         ON CONFLICT(manifest_id) DO UPDATE SET
            content_key = excluded.content_key",
        params![manifest_id, stored_key],
    )
    .map_err(|err| ValidationError::new(format!("write local manifest key: {err}")))?;
    Ok(())
}

pub(crate) fn write_local_device_encryption_key(
    tx: &Transaction<'_>,
    device_id: &str,
    key_pair: &LocalKeyPair,
    master_key: Option<&str>,
) -> Result<(), ValidationError> {
    let stored_private_key = if let Some(mk) = master_key {
        encrypt_column(
            mk,
            &key_pair.private_key,
            format!("device-enc-key:{device_id}").as_bytes(),
        )?
    } else {
        key_pair.private_key.clone()
    };
    tx.execute(
        "INSERT INTO local_device_encryption_keys (
            device_id,
            key_id,
            algorithm,
            public_key,
            private_key
         )
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(device_id) DO UPDATE SET
            key_id = excluded.key_id,
            algorithm = excluded.algorithm,
            public_key = excluded.public_key,
            private_key = excluded.private_key",
        params![
            device_id,
            &key_pair.key_id,
            key_pair.algorithm.as_str(),
            &key_pair.public_key,
            stored_private_key
        ],
    )
    .map_err(|err| ValidationError::new(format!("write local device encryption key: {err}")))?;
    Ok(())
}

pub(crate) fn load_local_device_encryption_key(
    conn: &Connection,
    device_id: &str,
    master_key: Option<&str>,
) -> Result<Option<LocalKeyPair>, ValidationError> {
    let row = conn
        .query_row(
            "SELECT key_id, algorithm, public_key, private_key
         FROM local_device_encryption_keys
         WHERE device_id = ?1",
            params![device_id],
            |row| {
                let algorithm = row.get::<_, String>(1)?;
                let algorithm =
                    core_principals::KeyAlgorithm::parse(&algorithm).ok_or_else(|| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("unknown key algorithm: {algorithm}"),
                            )),
                        )
                    })?;
                Ok(LocalKeyPair {
                    key_id: row.get(0)?,
                    algorithm,
                    public_key: row.get(2)?,
                    private_key: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|err| ValidationError::new(format!("load local device encryption key: {err}")))?;

    match (row, master_key) {
        (Some(mut kp), Some(mk)) => {
            // decrypt_column returns Zeroizing<String>; LocalKeyPair is
            // ZeroizeOnDrop so the cloned target also zeroizes on drop.
            // The transient Zeroizing wrapper zeroizes when it falls out of
            // scope at the end of the expression.
            let decrypted = decrypt_column(
                mk,
                &kp.private_key,
                format!("device-enc-key:{device_id}").as_bytes(),
            )?;
            kp.private_key = (*decrypted).clone();
            Ok(Some(kp))
        }
        (row, _) => Ok(row),
    }
}

pub(crate) fn delete_local_manifest_key(
    tx: &Transaction<'_>,
    manifest_id: &str,
) -> Result<(), ValidationError> {
    tx.execute(
        "DELETE FROM local_manifest_keys WHERE manifest_id = ?1",
        params![manifest_id],
    )
    .map_err(|err| ValidationError::new(format!("delete local manifest key: {err}")))?;
    Ok(())
}

/// Load the content key for a local manifest.
///
/// Returns `Zeroizing<String>` so the content key zeroizes on drop
/// (N6-deeper, see PR #5861).
pub(crate) fn load_local_manifest_key(
    conn: &Connection,
    manifest_id: &str,
    master_key: Option<&str>,
) -> Result<Option<Zeroizing<String>>, ValidationError> {
    let stored = conn
        .query_row(
            "SELECT content_key
         FROM local_manifest_keys
         WHERE manifest_id = ?1",
            params![manifest_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|err| ValidationError::new(format!("load local manifest key: {err}")))?;

    match (stored, master_key) {
        (Some(s), Some(mk)) => Ok(Some(decrypt_column(
            mk,
            &s,
            format!("manifest-key:{manifest_id}").as_bytes(),
        )?)),
        // Plaintext fallback: row predates encryption. Still a secret — wrap
        // so the residue hygiene is the same as the encrypted path.
        (Some(s), None) => Ok(Some(Zeroizing::new(s))),
        (None, _) => Ok(None),
    }
}

pub(crate) fn write_local_presentation_artifact(
    tx: &Transaction<'_>,
    record: &LocalPresentationArtifactRecord,
) -> Result<(), ValidationError> {
    tx.execute(
        "INSERT INTO local_presentation_artifacts (
            artifact_id,
            artifact_payload,
            owner_kind,
            owner_id,
            template_id,
            grant_id
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(artifact_id) DO UPDATE SET
            artifact_payload = excluded.artifact_payload,
            owner_kind = excluded.owner_kind,
            owner_id = excluded.owner_id,
            template_id = excluded.template_id,
            grant_id = excluded.grant_id",
        params![
            &record.artifact.id,
            record.artifact.canonical_encode(),
            record.namespace.owner_kind.as_str(),
            &record.namespace.owner_id,
            &record.template_id,
            &record.grant_id
        ],
    )
    .map_err(|err| ValidationError::new(format!("write local presentation artifact: {err}")))?;
    Ok(())
}

pub(crate) fn load_local_presentation_artifact(
    conn: &Connection,
    artifact_id: &str,
) -> Result<Option<LocalPresentationArtifactRecord>, ValidationError> {
    conn.query_row(
        "SELECT artifact_payload, owner_kind, owner_id, template_id, grant_id
         FROM local_presentation_artifacts
         WHERE artifact_id = ?1",
        params![artifact_id],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        },
    )
    .optional()
    .map_err(|err| ValidationError::new(format!("load local presentation artifact: {err}")))?
    .map(|(payload, owner_kind, owner_id, template_id, grant_id)| {
        let owner_kind = VaultOwnerKind::parse(&owner_kind).ok_or_else(|| {
            ValidationError::new(format!(
                "unknown local presentation artifact owner kind: {owner_kind}"
            ))
        })?;
        Ok(LocalPresentationArtifactRecord {
            artifact: PresentationArtifact::decode_canonical(&payload)?,
            namespace: VaultNamespace {
                owner_kind,
                owner_id,
            },
            template_id,
            grant_id,
        })
    })
    .transpose()
}

pub(crate) fn load_local_presentation_artifacts(
    conn: &Connection,
) -> Result<Vec<LocalPresentationArtifactRecord>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT artifact_payload, owner_kind, owner_id, template_id, grant_id
             FROM local_presentation_artifacts
             ORDER BY artifact_id ASC",
        )
        .map_err(|err| {
            ValidationError::new(format!("prepare local presentation artifact query: {err}"))
        })?;
    let mut rows = stmt.query([]).map_err(|err| {
        ValidationError::new(format!("query local presentation artifacts: {err}"))
    })?;
    let mut artifacts = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| ValidationError::new(format!("iterate presentation artifacts: {err}")))?
    {
        let payload = row
            .get::<_, Vec<u8>>(0)
            .map_err(|err| ValidationError::new(format!("read presentation artifact: {err}")))?;
        let owner_kind = row.get::<_, String>(1).map_err(|err| {
            ValidationError::new(format!("read presentation artifact owner kind: {err}"))
        })?;
        let owner_id = row.get::<_, String>(2).map_err(|err| {
            ValidationError::new(format!("read presentation artifact owner id: {err}"))
        })?;
        let template_id = row.get::<_, String>(3).map_err(|err| {
            ValidationError::new(format!("read presentation artifact template id: {err}"))
        })?;
        let grant_id = row.get::<_, Option<String>>(4).map_err(|err| {
            ValidationError::new(format!("read presentation artifact grant id: {err}"))
        })?;
        let owner_kind = VaultOwnerKind::parse(&owner_kind).ok_or_else(|| {
            ValidationError::new(format!(
                "unknown local presentation artifact owner kind: {owner_kind}"
            ))
        })?;
        artifacts.push(LocalPresentationArtifactRecord {
            artifact: PresentationArtifact::decode_canonical(&payload)?,
            namespace: VaultNamespace {
                owner_kind,
                owner_id,
            },
            template_id,
            grant_id,
        });
    }
    Ok(artifacts)
}

pub(crate) fn load_artifact_ids_by_grant(
    conn: &Connection,
    grant_id: &str,
) -> Result<Vec<String>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT artifact_id FROM local_presentation_artifacts
             WHERE grant_id = ?1
             ORDER BY artifact_id ASC",
        )
        .map_err(|err| ValidationError::new(format!("prepare artifact-by-grant query: {err}")))?;
    let mut rows = stmt
        .query(params![grant_id])
        .map_err(|err| ValidationError::new(format!("query artifacts by grant: {err}")))?;
    let mut ids = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| ValidationError::new(format!("iterate artifacts by grant: {err}")))?
    {
        ids.push(
            row.get::<_, String>(0)
                .map_err(|err| ValidationError::new(format!("read artifact id: {err}")))?,
        );
    }
    Ok(ids)
}

pub(crate) fn write_local_received_presentation_artifact(
    tx: &Transaction<'_>,
    record: &ReceivedPresentationArtifactRecord,
) -> Result<(), ValidationError> {
    tx.execute(
        "INSERT INTO local_received_presentation_artifacts (
            artifact_id,
            artifact_payload,
            payload_bytes,
            first_received_at,
            last_received_at,
            first_source_kind,
            first_source_ref,
            last_source_kind,
            last_source_ref,
            receipt_count,
            issuer_persona_id,
            issuer_key_id,
            issuer_public_key,
            issuer_signature_hex
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
         ON CONFLICT(artifact_id) DO UPDATE SET
            artifact_payload = excluded.artifact_payload,
            payload_bytes = excluded.payload_bytes,
            first_received_at = excluded.first_received_at,
            last_received_at = excluded.last_received_at,
            first_source_kind = excluded.first_source_kind,
            first_source_ref = excluded.first_source_ref,
            last_source_kind = excluded.last_source_kind,
            last_source_ref = excluded.last_source_ref,
            receipt_count = excluded.receipt_count,
            issuer_persona_id = excluded.issuer_persona_id,
            issuer_key_id = excluded.issuer_key_id,
            issuer_public_key = excluded.issuer_public_key,
            issuer_signature_hex = excluded.issuer_signature_hex",
        params![
            &record.envelope.artifact.id,
            record.envelope.artifact.canonical_encode(),
            &record.envelope.payload_bytes,
            record.first_received_at as i64,
            record.last_received_at as i64,
            record.first_source_kind.as_str(),
            &record.first_source_ref,
            record.last_source_kind.as_str(),
            &record.last_source_ref,
            record.receipt_count as i64,
            &record.envelope.issuer_persona_id,
            &record.envelope.issuer_key_id,
            &record.envelope.issuer_public_key,
            &record.envelope.issuer_signature_hex,
        ],
    )
    .map_err(|err| {
        ValidationError::new(format!("write local received presentation artifact: {err}"))
    })?;
    Ok(())
}

pub(crate) fn load_local_received_presentation_artifact(
    conn: &Connection,
    artifact_id: &str,
) -> Result<Option<ReceivedPresentationArtifactRecord>, ValidationError> {
    let raw = conn
        .query_row(
            "SELECT
            artifact_payload,
            payload_bytes,
            first_received_at,
            last_received_at,
            first_source_kind,
            first_source_ref,
            last_source_kind,
            last_source_ref,
            receipt_count,
            issuer_persona_id,
            issuer_key_id,
            issuer_public_key,
            issuer_signature_hex
         FROM local_received_presentation_artifacts
         WHERE artifact_id = ?1",
            params![artifact_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)? as u64,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                ))
            },
        )
        .optional()
        .map_err(|err| {
            ValidationError::new(format!("load local received presentation artifact: {err}"))
        })?;
    let Some((
        artifact_payload,
        payload_bytes,
        first_received_at,
        last_received_at,
        first_source_kind,
        first_source_ref,
        last_source_kind,
        last_source_ref,
        receipt_count,
        issuer_persona_id,
        issuer_key_id,
        issuer_public_key,
        issuer_signature_hex,
    )) = raw
    else {
        return Ok(None);
    };
    Ok(Some(ReceivedPresentationArtifactRecord {
        envelope: PresentationArtifactEnvelope {
            artifact: PresentationArtifact::decode_canonical(&artifact_payload)?,
            payload_bytes,
            issuer_persona_id,
            issuer_key_id,
            issuer_public_key,
            issuer_signature_hex,
        },
        first_received_at,
        last_received_at,
        first_source_kind: ReceivedDisclosureSourceKind::from_str(&first_source_kind)?,
        first_source_ref,
        last_source_kind: ReceivedDisclosureSourceKind::from_str(&last_source_kind)?,
        last_source_ref,
        receipt_count,
    }))
}

pub(crate) fn load_local_received_presentation_artifacts(
    conn: &Connection,
) -> Result<Vec<ReceivedPresentationArtifactRecord>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT
                artifact_payload,
                payload_bytes,
                first_received_at,
                last_received_at,
                first_source_kind,
                first_source_ref,
                last_source_kind,
                last_source_ref,
                receipt_count,
                issuer_persona_id,
                issuer_key_id,
                issuer_public_key,
                issuer_signature_hex
             FROM local_received_presentation_artifacts
             ORDER BY last_received_at DESC, artifact_id ASC",
        )
        .map_err(|err| {
            ValidationError::new(format!(
                "prepare local received presentation artifact query: {err}"
            ))
        })?;
    let mut rows = stmt.query([]).map_err(|err| {
        ValidationError::new(format!(
            "query local received presentation artifacts: {err}"
        ))
    })?;
    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(|err| {
        ValidationError::new(format!("iterate received presentation artifacts: {err}"))
    })? {
        let artifact_payload = row.get::<_, Vec<u8>>(0).map_err(|err| {
            ValidationError::new(format!(
                "read received presentation artifact payload: {err}"
            ))
        })?;
        let first_source_kind = row.get::<_, String>(4).map_err(|err| {
            ValidationError::new(format!(
                "read received presentation artifact first_source_kind: {err}"
            ))
        })?;
        let last_source_kind = row.get::<_, String>(6).map_err(|err| {
            ValidationError::new(format!(
                "read received presentation artifact last_source_kind: {err}"
            ))
        })?;
        let issuer_persona_id = row.get::<_, String>(9).map_err(|err| {
            ValidationError::new(format!(
                "read received presentation artifact issuer_persona_id: {err}"
            ))
        })?;
        let issuer_key_id = row.get::<_, String>(10).map_err(|err| {
            ValidationError::new(format!(
                "read received presentation artifact issuer_key_id: {err}"
            ))
        })?;
        let issuer_public_key = row.get::<_, String>(11).map_err(|err| {
            ValidationError::new(format!(
                "read received presentation artifact issuer_public_key: {err}"
            ))
        })?;
        let issuer_signature_hex = row.get::<_, String>(12).map_err(|err| {
            ValidationError::new(format!(
                "read received presentation artifact issuer_signature_hex: {err}"
            ))
        })?;
        records.push(ReceivedPresentationArtifactRecord {
            envelope: PresentationArtifactEnvelope {
                artifact: PresentationArtifact::decode_canonical(&artifact_payload)?,
                payload_bytes: row.get(1).map_err(|err| {
                    ValidationError::new(format!(
                        "read received presentation artifact bytes: {err}"
                    ))
                })?,
                issuer_persona_id,
                issuer_key_id,
                issuer_public_key,
                issuer_signature_hex,
            },
            first_received_at: row.get::<_, i64>(2).map_err(|err| {
                ValidationError::new(format!(
                    "read received presentation artifact first_received_at: {err}"
                ))
            })? as u64,
            last_received_at: row.get::<_, i64>(3).map_err(|err| {
                ValidationError::new(format!(
                    "read received presentation artifact last_received_at: {err}"
                ))
            })? as u64,
            first_source_kind: ReceivedDisclosureSourceKind::from_str(&first_source_kind)?,
            first_source_ref: row.get(5).map_err(|err| {
                ValidationError::new(format!(
                    "read received presentation artifact first_source_ref: {err}"
                ))
            })?,
            last_source_kind: ReceivedDisclosureSourceKind::from_str(&last_source_kind)?,
            last_source_ref: row.get(7).map_err(|err| {
                ValidationError::new(format!(
                    "read received presentation artifact last_source_ref: {err}"
                ))
            })?,
            receipt_count: row.get::<_, i64>(8).map_err(|err| {
                ValidationError::new(format!(
                    "read received presentation artifact receipt_count: {err}"
                ))
            })? as u64,
        });
    }
    Ok(records)
}

pub(crate) fn load_events(conn: &Connection) -> Result<Vec<EventEnvelope>, ValidationError> {
    struct RawEventRow {
        schema_version: String,
        event_id: String,
        event_type: String,
        subject_kind: String,
        subject_id: String,
        signer_kind: String,
        signer_id: String,
        signer_role: String,
        signer_key_id: String,
        signer_public_key: String,
        payload: Vec<u8>,
        signature: String,
    }

    let mut stmt = conn
        .prepare(
            "SELECT
                e.schema_version,
                e.event_id,
                e.event_type,
                e.subject_kind,
                e.subject_id,
                e.signer_kind,
                e.signer_id,
                e.signer_role,
                e.signer_key_id,
                e.signer_public_key,
                e.payload,
                s.signature
             FROM events e
             JOIN event_signatures s ON s.event_id = e.event_id
             ORDER BY e.sequence ASC",
        )
        .map_err(|err| ValidationError::new(format!("prepare event load query: {err}")))?;

    let mut rows = stmt
        .query([])
        .map_err(|err| ValidationError::new(format!("run event load query: {err}")))?;

    let mut raw_rows = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| ValidationError::new(format!("iterate event rows: {err}")))?
    {
        raw_rows.push(RawEventRow {
            schema_version: row
                .get(0)
                .map_err(|err| ValidationError::new(format!("read schema version: {err}")))?,
            event_id: row
                .get(1)
                .map_err(|err| ValidationError::new(format!("read event id: {err}")))?,
            event_type: row
                .get(2)
                .map_err(|err| ValidationError::new(format!("read event type: {err}")))?,
            subject_kind: row
                .get(3)
                .map_err(|err| ValidationError::new(format!("read subject kind: {err}")))?,
            subject_id: row
                .get(4)
                .map_err(|err| ValidationError::new(format!("read subject id: {err}")))?,
            signer_kind: row
                .get(5)
                .map_err(|err| ValidationError::new(format!("read signer kind: {err}")))?,
            signer_id: row
                .get(6)
                .map_err(|err| ValidationError::new(format!("read signer id: {err}")))?,
            signer_role: row
                .get(7)
                .map_err(|err| ValidationError::new(format!("read signer role: {err}")))?,
            signer_key_id: row
                .get(8)
                .map_err(|err| ValidationError::new(format!("read signer key id: {err}")))?,
            signer_public_key: row
                .get(9)
                .map_err(|err| ValidationError::new(format!("read signer public key: {err}")))?,
            payload: row
                .get(10)
                .map_err(|err| ValidationError::new(format!("read payload: {err}")))?,
            signature: row
                .get(11)
                .map_err(|err| ValidationError::new(format!("read signature: {err}")))?,
        });
    }
    drop(rows);
    drop(stmt);

    // Bulk-load all event refs in one query (avoids N+1 per-event queries)
    let all_refs = load_all_event_refs(conn)?;

    let mut events = Vec::with_capacity(raw_rows.len());
    for raw in raw_rows {
        let refs = all_refs.get(&raw.event_id).cloned().unwrap_or_default();
        let event = EventEnvelope::from_stored_parts(
            SchemaVersion::parse(&raw.schema_version)
                .ok_or_else(|| ValidationError::new("unsupported schema version in sqlite"))?,
            raw.event_id,
            EventType::parse(&raw.event_type)
                .ok_or_else(|| ValidationError::new("unsupported event type in sqlite"))?,
            EventSubject::new(
                SubjectKind::parse(&raw.subject_kind)
                    .ok_or_else(|| ValidationError::new("unsupported subject kind in sqlite"))?,
                raw.subject_id,
            ),
            SignerBinding {
                signer: EventSubject::new(
                    SubjectKind::parse(&raw.signer_kind)
                        .ok_or_else(|| ValidationError::new("unsupported signer kind in sqlite"))?,
                    raw.signer_id,
                ),
                key_id: raw.signer_key_id,
                role: KeyRole::parse(&raw.signer_role)
                    .ok_or_else(|| ValidationError::new("unsupported signer role in sqlite"))?,
            },
            PublicKey(raw.signer_public_key),
            raw.payload,
            refs,
            Signature(raw.signature),
        )?;
        events.push(event);
    }

    Ok(events)
}

/// Load all event refs in a single query, grouped by event_id.
fn load_all_event_refs(
    conn: &Connection,
) -> Result<HashMap<String, Vec<EventRef>>, ValidationError> {
    let mut stmt = conn
        .prepare(
            // Order by `seq` within each event so a reloaded multi-ref event
            // reconstructs its refs in the chain order they were signed in (the
            // signing pre-image iterates refs by Vec position). Single-`Previous`-ref
            // events (all current event types) are unaffected; this hardens the
            // reload path for any future multi-ref event. A fully order-faithful
            // reload would persist an explicit insertion ordinal — noted follow-up.
            "SELECT event_id, relation, target_event_id, seq
             FROM event_refs
             ORDER BY event_id, seq, relation, target_event_id",
        )
        .map_err(|err| ValidationError::new(format!("prepare all event refs query: {err}")))?;

    let mut rows = stmt
        .query([])
        .map_err(|err| ValidationError::new(format!("run all event refs query: {err}")))?;

    let mut refs_by_event: HashMap<String, Vec<EventRef>> = HashMap::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| ValidationError::new(format!("iterate all event refs rows: {err}")))?
    {
        let event_id: String = row
            .get(0)
            .map_err(|err| ValidationError::new(format!("read event ref event_id: {err}")))?;
        let relation: String = row
            .get(1)
            .map_err(|err| ValidationError::new(format!("read event ref relation: {err}")))?;
        let target_event_id: String = row
            .get(2)
            .map_err(|err| ValidationError::new(format!("read event ref target: {err}")))?;
        let seq: i64 = row
            .get(3)
            .map_err(|err| ValidationError::new(format!("read event ref seq: {err}")))?;
        refs_by_event.entry(event_id).or_default().push(EventRef {
            relation: EventRefRelation::parse(&relation)
                .ok_or_else(|| ValidationError::new("unsupported event ref relation in sqlite"))?,
            target_event_id,
            seq: seq as u64,
        });
    }

    Ok(refs_by_event)
}

pub(crate) fn write_materialized_tables(
    tx: &Transaction<'_>,
    materialized: &MaterializedState,
) -> Result<(), ValidationError> {
    // --- Upsert roots ---
    for root in materialized.roots_current.values() {
        tx.execute(
            "INSERT INTO roots_current (root_id, display_name, active_key_id, active_public_key, status)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(root_id) DO UPDATE SET
                display_name = excluded.display_name,
                active_key_id = excluded.active_key_id,
                active_public_key = excluded.active_public_key,
                status = excluded.status",
            params![
                &root.root_id,
                &root.display_name,
                &root.active_key.key_id,
                &root.active_key.public_key,
                root_status_name(&root.status),
            ],
        )
        .map_err(|err| ValidationError::io_error(format!("upsert roots_current: {err}")))?;
    }
    prune_stale_rows(
        tx,
        "roots_current",
        "root_id",
        materialized.roots_current.keys(),
    )?;

    // --- Upsert devices ---
    for device in materialized.devices_current.values() {
        tx.execute(
            "INSERT INTO devices_current (device_id, root_id, label, active_key_id, active_public_key, active_encryption_key_id, active_encryption_public_key, status, replacement_device_id, custody_class, attestation_statement, attestation_tier, presence_factor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(device_id) DO UPDATE SET
                root_id = excluded.root_id, label = excluded.label,
                active_key_id = excluded.active_key_id, active_public_key = excluded.active_public_key,
                active_encryption_key_id = excluded.active_encryption_key_id, active_encryption_public_key = excluded.active_encryption_public_key,
                status = excluded.status, replacement_device_id = excluded.replacement_device_id,
                custody_class = excluded.custody_class, attestation_statement = excluded.attestation_statement,
                attestation_tier = excluded.attestation_tier, presence_factor = excluded.presence_factor",
            params![
                &device.device_id,
                &device.root_id,
                &device.label,
                &device.active_key.key_id,
                &device.active_key.public_key,
                &device.active_encryption_key.key_id,
                &device.active_encryption_key.public_key,
                device_status_name(&device.status),
                &device.replacement_device_id,
                device.custody_class.as_str(),
                &device.attestation_statement,
                device.attestation_tier.as_str(),
                device.presence_factor.as_str(),
            ],
        )
        .map_err(|err| ValidationError::io_error(format!("upsert devices_current: {err}")))?;
    }
    prune_stale_rows(
        tx,
        "devices_current",
        "device_id",
        materialized.devices_current.keys(),
    )?;

    // --- Upsert personas ---
    for persona in materialized.personas_current.values() {
        tx.execute(
            "INSERT INTO personas_current (persona_id, root_id, label, disclosure_profile, survival_mode, active_key_id, active_public_key, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(persona_id) DO UPDATE SET
                root_id = excluded.root_id, label = excluded.label,
                disclosure_profile = excluded.disclosure_profile, survival_mode = excluded.survival_mode,
                active_key_id = excluded.active_key_id, active_public_key = excluded.active_public_key,
                status = excluded.status",
            params![
                &persona.persona_id,
                &persona.root_id,
                &persona.label,
                &persona.disclosure_profile,
                persona.survival_mode.as_str(),
                &persona.active_key.key_id,
                &persona.active_key.public_key,
                persona_status_name(&persona.status),
            ],
        )
        .map_err(|err| ValidationError::io_error(format!("upsert personas_current: {err}")))?;
    }
    prune_stale_rows(
        tx,
        "personas_current",
        "persona_id",
        materialized.personas_current.keys(),
    )?;

    // --- Upsert trust edges ---
    for attestation in materialized.trust_edges_current.values() {
        tx.execute(
            "INSERT INTO trust_edges_current (attestation_id, attester, subject, domain, score, recipient_bound)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(attestation_id) DO UPDATE SET
                attester = excluded.attester, subject = excluded.subject,
                domain = excluded.domain, score = excluded.score,
                recipient_bound = excluded.recipient_bound",
            params![
                &attestation.id,
                &attestation.attester,
                &attestation.subject,
                &attestation.domain,
                attestation.score,
                &attestation.recipient_bound,
            ],
        )
        .map_err(|err| ValidationError::io_error(format!("upsert trust_edges_current: {err}")))?;
    }
    prune_stale_rows(
        tx,
        "trust_edges_current",
        "attestation_id",
        materialized.trust_edges_current.keys(),
    )?;

    // --- Upsert derived trust ---
    for statement in materialized.derived_trust_current.values() {
        tx.execute(
            "INSERT INTO derived_trust_current (statement_id, subject, domain, normalized_score)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(statement_id) DO UPDATE SET
                subject = excluded.subject, domain = excluded.domain,
                normalized_score = excluded.normalized_score",
            params![
                &statement.id,
                &statement.subject,
                &statement.domain,
                statement.normalized_score,
            ],
        )
        .map_err(|err| ValidationError::io_error(format!("upsert derived_trust_current: {err}")))?;
    }
    prune_stale_rows(
        tx,
        "derived_trust_current",
        "statement_id",
        materialized.derived_trust_current.keys(),
    )?;

    // --- Upsert recovery policies ---
    for policy in materialized.recovery_policies_current.values() {
        tx.execute(
            "INSERT INTO recovery_policies_current (root_id, guardian_threshold, cooldown_seconds)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(root_id) DO UPDATE SET
                guardian_threshold = excluded.guardian_threshold,
                cooldown_seconds = excluded.cooldown_seconds",
            params![
                &policy.root_id,
                policy.guardian_threshold,
                policy.cooldown_seconds
            ],
        )
        .map_err(|err| {
            ValidationError::io_error(format!("upsert recovery_policies_current: {err}"))
        })?;
    }
    prune_stale_rows(
        tx,
        "recovery_policies_current",
        "root_id",
        materialized.recovery_policies_current.keys(),
    )?;

    // --- Upsert recovery requests ---
    for request in materialized.recovery_requests_current.values() {
        tx.execute(
            "INSERT INTO recovery_requests_current (request_id, root_id, target_device_id, status, approval_count, executed_scope, cooldown_until, contest_reason, rejection_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(request_id) DO UPDATE SET
                root_id = excluded.root_id, target_device_id = excluded.target_device_id,
                status = excluded.status, approval_count = excluded.approval_count,
                executed_scope = excluded.executed_scope, cooldown_until = excluded.cooldown_until,
                contest_reason = excluded.contest_reason, rejection_reason = excluded.rejection_reason",
            params![
                &request.request_id,
                &request.root_id,
                &request.target_device_id,
                recovery_request_status_name(&request.status),
                request.approvals.len() as i64,
                request
                    .executed_scope
                    .map(|scope| scope.as_str().to_string()),
                request.cooldown_until.map(|v| v as i64),
                &request.contest_reason,
                &request.rejection_reason,
            ],
        )
        .map_err(|err| ValidationError::io_error(format!("upsert recovery_requests_current: {err}")))?;
    }
    prune_stale_rows(
        tx,
        "recovery_requests_current",
        "request_id",
        materialized.recovery_requests_current.keys(),
    )?;

    // --- Upsert storage relationships ---
    for relationship in materialized.storage_relationships_current.values() {
        tx.execute(
            "INSERT INTO storage_relationships_current (relationship_id, local_peer_id, remote_peer_id, approved)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(relationship_id) DO UPDATE SET
                local_peer_id = excluded.local_peer_id, remote_peer_id = excluded.remote_peer_id,
                approved = excluded.approved",
            params![
                &relationship.id,
                &relationship.local_peer_id,
                &relationship.remote_peer_id,
                if relationship.approved { 1_i64 } else { 0_i64 },
            ],
        )
        .map_err(|err| ValidationError::io_error(format!("upsert storage_relationships_current: {err}")))?;
    }
    prune_stale_rows(
        tx,
        "storage_relationships_current",
        "relationship_id",
        materialized.storage_relationships_current.keys(),
    )?;

    // --- Upsert storage balances ---
    for balance in materialized.storage_balances_current.values() {
        tx.execute(
            "INSERT INTO storage_balances_current (relationship_id, stored_bytes_delta)
             VALUES (?1, ?2)
             ON CONFLICT(relationship_id) DO UPDATE SET
                stored_bytes_delta = excluded.stored_bytes_delta",
            params![&balance.relationship_id, balance.stored_bytes_delta],
        )
        .map_err(|err| {
            ValidationError::io_error(format!("upsert storage_balances_current: {err}"))
        })?;
    }
    prune_stale_rows(
        tx,
        "storage_balances_current",
        "relationship_id",
        materialized.storage_balances_current.keys(),
    )?;

    // --- Upsert endpoints ---
    for endpoint in materialized.endpoints_current.values() {
        tx.execute(
            "INSERT INTO endpoints_current (peer_id, device_id, transport_hint)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(peer_id) DO UPDATE SET
                device_id = excluded.device_id, transport_hint = excluded.transport_hint",
            params![
                &endpoint.peer_id,
                &endpoint.device_id,
                &endpoint.transport_hint,
            ],
        )
        .map_err(|err| ValidationError::io_error(format!("upsert endpoints_current: {err}")))?;
    }
    prune_stale_rows(
        tx,
        "endpoints_current",
        "peer_id",
        materialized.endpoints_current.keys(),
    )?;

    // --- Upsert grant offers ---
    for offer in materialized.grant_offers_current.values() {
        let status_str = match offer.status {
            core_eventlog::GrantOfferStatus::Pending => "pending",
            core_eventlog::GrantOfferStatus::Claimed => "claimed",
            core_eventlog::GrantOfferStatus::Revoked => "revoked",
        };
        let conditions_json = if offer.conditions_json.is_empty() {
            "[]".to_string()
        } else {
            offer.conditions_json.clone()
        };
        tx.execute(
            "INSERT INTO grant_offers (
                offer_id, issuer_persona_id, ephemeral_public_key_hex, sealed_payload_hex,
                relay_hint, expires_at, conditions_json, status, recipient_persona_id, claim_response_hex, claimed_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(offer_id) DO UPDATE SET
                status = excluded.status,
                recipient_persona_id = excluded.recipient_persona_id,
                claim_response_hex = excluded.claim_response_hex,
                claimed_at = excluded.claimed_at",
            params![
                &offer.offer_id,
                &offer.issuer_persona_id,
                &offer.ephemeral_public_key_hex,
                &offer.sealed_payload_hex,
                &offer.relay_hint,
                offer.expires_at as i64,
                &conditions_json,
                status_str,
                &offer.recipient_persona_id,
                &offer.claim_response_hex,
                offer.claimed_at.map(|v| v as i64),
            ],
        )
        .map_err(|err| ValidationError::io_error(format!("upsert grant_offers: {err}")))?;
    }
    // Note: grant offers are append-only (no pruning) — they stay for audit purposes.

    // --- Upsert badges ---
    for badge in materialized.badges_current.values() {
        let status_str = if badge.revoked { "revoked" } else { "active" };
        let (ev_type, ev_payload) = match &badge.evidence {
            Some(e) => (Some(e.evidence_type.as_str()), Some(e.payload_hex.as_str())),
            None => (None, None),
        };
        tx.execute(
            "INSERT INTO badges (
                badge_id, issuer_persona_id, recipient_persona_id, badge_type, display_name,
                evidence_type, evidence_payload_hex, issued_at, expires_at, status, revoked_reason
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(badge_id) DO UPDATE SET
                status = excluded.status,
                revoked_reason = excluded.revoked_reason",
            params![
                &badge.badge_id,
                &badge.issuer_persona_id,
                &badge.recipient_persona_id,
                &badge.badge_type,
                &badge.display_name,
                ev_type,
                ev_payload,
                badge.issued_at as i64,
                badge.expires_at.map(|v| v as i64),
                status_str,
                &badge.revoked_reason,
            ],
        )
        .map_err(|err| ValidationError::io_error(format!("upsert badges: {err}")))?;
    }
    // Note: badges are append-only (no pruning) — they stay for audit purposes.

    // --- Upsert badge disputes ---
    for dispute in materialized.badge_disputes_current.values() {
        tx.execute(
            "INSERT INTO badge_disputes (
                dispute_id, target_badge_id, disputer_persona_id, reason, evidence
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(dispute_id) DO NOTHING",
            params![
                &dispute.dispute_id,
                &dispute.target_badge_id,
                &dispute.disputer_persona_id,
                &dispute.reason,
                &dispute.evidence,
            ],
        )
        .map_err(|err| ValidationError::io_error(format!("upsert badge_disputes: {err}")))?;
    }

    Ok(())
}

/// Delete rows from `table` where `pk_column` is not in `current_keys`.
fn prune_stale_rows<'a>(
    tx: &Transaction<'_>,
    table: &str,
    pk_column: &str,
    current_keys: impl Iterator<Item = &'a String>,
) -> Result<(), ValidationError> {
    let keys: Vec<&str> = current_keys.map(|k| k.as_str()).collect();
    if keys.is_empty() {
        tx.execute(&format!("DELETE FROM {table}"), [])
            .map_err(|err| ValidationError::io_error(format!("prune {table}: {err}")))?;
        return Ok(());
    }
    let placeholders: Vec<String> = (1..=keys.len()).map(|i| format!("?{i}")).collect();
    let sql = format!(
        "DELETE FROM {table} WHERE {pk_column} NOT IN ({})",
        placeholders.join(", ")
    );
    let params: Vec<&dyn rusqlite::types::ToSql> = keys
        .iter()
        .map(|k| k as &dyn rusqlite::types::ToSql)
        .collect();
    tx.execute(&sql, params.as_slice())
        .map_err(|err| ValidationError::io_error(format!("prune {table}: {err}")))?;
    Ok(())
}

pub(crate) fn record_sync_batch(
    tx: &Transaction<'_>,
    batch_id: &str,
    peer_id: &str,
    last_event_id: Option<&str>,
) -> Result<(), ValidationError> {
    tx.execute(
        "INSERT INTO sync_batches (batch_id, cursor_peer_id, last_event_id) VALUES (?1, ?2, ?3)",
        params![batch_id, peer_id, last_event_id],
    )
    .map_err(|err| ValidationError::new(format!("insert sync batch row: {err}")))?;
    Ok(())
}

pub(crate) fn write_peer_cursor(
    tx: &Transaction<'_>,
    peer_id: &str,
    last_event_id: Option<&str>,
) -> Result<(), ValidationError> {
    let watcher_id = peer_cursor_watcher_id(peer_id);
    tx.execute(
        "INSERT INTO watch_state (watcher_id, cursor) VALUES (?1, ?2)
         ON CONFLICT(watcher_id) DO UPDATE SET cursor = excluded.cursor",
        params![watcher_id, last_event_id.unwrap_or("")],
    )
    .map_err(|err| ValidationError::new(format!("upsert peer cursor row: {err}")))?;
    Ok(())
}

pub(crate) fn peer_cursor_watcher_id(peer_id: &str) -> String {
    format!("peer-cursor:{peer_id}")
}

pub(crate) fn root_status_name(status: &RootStatus) -> &'static str {
    match status {
        RootStatus::Active => "active",
        RootStatus::Revoked => "revoked",
    }
}

pub(crate) fn device_status_name(status: &DeviceStatus) -> &'static str {
    match status {
        DeviceStatus::Active => "active",
        DeviceStatus::Revoked => "revoked",
        DeviceStatus::Frozen => "frozen",
        DeviceStatus::Replaced => "replaced",
    }
}

pub(crate) fn persona_status_name(status: &PersonaStatus) -> &'static str {
    match status {
        PersonaStatus::Active => "active",
        PersonaStatus::Revoked => "revoked",
    }
}

pub(crate) fn recovery_request_status_name(status: &RecoveryRequestStatus) -> &'static str {
    match status {
        RecoveryRequestStatus::Requested => "requested",
        RecoveryRequestStatus::Approved => "approved",
        RecoveryRequestStatus::Contested => "contested",
        RecoveryRequestStatus::Rejected => "rejected",
        RecoveryRequestStatus::Executed => "executed",
    }
}

// --- Service binding persistence (local-only) ---

pub(crate) fn write_service_binding(
    conn: &Connection,
    binding: &core_event_types::ServiceBinding,
) -> Result<(), ValidationError> {
    conn.execute(
        "INSERT INTO service_bindings (
            binding_id, persona_id, adapter_kind, service_label,
            endpoint, external_account_id, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(binding_id) DO UPDATE SET
            persona_id = excluded.persona_id,
            adapter_kind = excluded.adapter_kind,
            service_label = excluded.service_label,
            endpoint = excluded.endpoint,
            external_account_id = excluded.external_account_id,
            created_at = excluded.created_at",
        params![
            &binding.id,
            &binding.persona_id,
            &binding.descriptor.adapter_kind,
            &binding.descriptor.service_label,
            &binding.descriptor.endpoint,
            &binding.external_account_id,
            binding.created_at as i64,
        ],
    )
    .map_err(|err| ValidationError::new(format!("write service binding: {err}")))?;
    Ok(())
}

pub(crate) fn load_service_bindings_for_persona(
    conn: &Connection,
    persona_id: &str,
) -> Result<Vec<core_event_types::ServiceBinding>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT binding_id, persona_id, adapter_kind, service_label,
                    endpoint, external_account_id, created_at
             FROM service_bindings WHERE persona_id = ?1 ORDER BY created_at",
        )
        .map_err(|err| ValidationError::new(format!("prepare service bindings query: {err}")))?;

    let rows = stmt
        .query_map(params![persona_id], |row| {
            Ok(core_event_types::ServiceBinding {
                id: row.get(0)?,
                persona_id: row.get(1)?,
                descriptor: core_event_types::ServiceDescriptor {
                    adapter_kind: row.get(2)?,
                    service_label: row.get(3)?,
                    endpoint: row.get(4)?,
                },
                external_account_id: row.get(5)?,
                created_at: row.get::<_, i64>(6)? as u64,
            })
        })
        .map_err(|err| ValidationError::new(format!("query service bindings: {err}")))?;

    let mut bindings = Vec::new();
    for row in rows {
        bindings.push(
            row.map_err(|err| ValidationError::new(format!("read service binding row: {err}")))?,
        );
    }
    Ok(bindings)
}

pub(crate) fn load_all_service_bindings(
    conn: &Connection,
) -> Result<Vec<core_event_types::ServiceBinding>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT binding_id, persona_id, adapter_kind, service_label,
                    endpoint, external_account_id, created_at
             FROM service_bindings ORDER BY persona_id, created_at",
        )
        .map_err(|err| {
            ValidationError::new(format!("prepare all service bindings query: {err}"))
        })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(core_event_types::ServiceBinding {
                id: row.get(0)?,
                persona_id: row.get(1)?,
                descriptor: core_event_types::ServiceDescriptor {
                    adapter_kind: row.get(2)?,
                    service_label: row.get(3)?,
                    endpoint: row.get(4)?,
                },
                external_account_id: row.get(5)?,
                created_at: row.get::<_, i64>(6)? as u64,
            })
        })
        .map_err(|err| ValidationError::new(format!("query all service bindings: {err}")))?;

    let mut bindings = Vec::new();
    for row in rows {
        bindings.push(
            row.map_err(|err| ValidationError::new(format!("read service binding row: {err}")))?,
        );
    }
    Ok(bindings)
}

pub(crate) fn delete_service_binding(
    conn: &Connection,
    binding_id: &str,
) -> Result<bool, ValidationError> {
    let count = conn
        .execute(
            "DELETE FROM service_bindings WHERE binding_id = ?1",
            params![binding_id],
        )
        .map_err(|err| ValidationError::new(format!("delete service binding: {err}")))?;
    Ok(count > 0)
}

// --- Access Grant persistence (ADR 073 — composite grant shape) ---
//
// A grant is a signed chain of SignedBlocks. We persist the whole chain as
// one JSON blob in `blocks_json`. Per-block expiry and per-statement budget
// live inside that blob; top-level columns (status, mode, last_used_at) are
// envelope state only. Projections (effective_expires_at, aggregate_usage,
// resource_types) are computed from blocks on read.
//
// Authoritative on-wire format will move to biscuit-auth tokens once
// core-crypto wires it in; until then blocks_json is the durable store.

fn blocks_to_json(blocks: &[core_grant_types::SignedBlock]) -> Result<String, ValidationError> {
    serde_json::to_string(blocks)
        .map_err(|err| ValidationError::new(format!("serialize grant blocks: {err}")))
}

fn blocks_from_json(json: &str) -> Result<Vec<core_grant_types::SignedBlock>, ValidationError> {
    serde_json::from_str(json)
        .map_err(|err| ValidationError::new(format!("deserialize grant blocks: {err}")))
}

pub(crate) fn write_access_grant(
    conn: &Connection,
    grant: &core_grant_types::AccessGrant,
) -> Result<(), ValidationError> {
    let blocks_json = blocks_to_json(&grant.blocks)?;
    // Only persist terminal-ish stored statuses. Derived `Expired` / `Pending`
    // are never written; `ExhaustedByBudget` + `Paused` are distinct persisted
    // terminals / pauses.
    let stored_status = match grant.status {
        core_grant_types::GrantStatus::Revoked => "revoked",
        core_grant_types::GrantStatus::ExhaustedByBudget => "exhausted_by_budget",
        core_grant_types::GrantStatus::Paused => "paused",
        _ => "active",
    };
    let attestation_json = serde_json::to_string(&grant.attestation)
        .map_err(|err| ValidationError::new(format!("encode grant attestation: {err}")))?;

    // Envelope-level projections for indexing / listing convenience.
    let effective_expires_at = grant.effective_expires_at();
    let resource_types_csv = grant
        .resource_types()
        .iter()
        .map(|rt| rt.as_str())
        .collect::<Vec<_>>()
        .join(",");

    conn.execute(
        "INSERT INTO access_grants (
            grant_id, version, issuing_persona_id, recipient_kind, recipient_id,
            recipient_profile, status, mode, blocks_json, label,
            created_at, updated_at, expires_at,
            revoked_at, revoked_reason, last_used_at,
            resource_types_csv, attestation_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
        ON CONFLICT(grant_id) DO UPDATE SET
            version = excluded.version,
            status = excluded.status,
            mode = excluded.mode,
            blocks_json = excluded.blocks_json,
            label = excluded.label,
            updated_at = excluded.updated_at,
            expires_at = excluded.expires_at,
            revoked_at = excluded.revoked_at,
            revoked_reason = excluded.revoked_reason,
            last_used_at = excluded.last_used_at,
            resource_types_csv = excluded.resource_types_csv,
            attestation_json = excluded.attestation_json",
        params![
            &grant.id,
            grant.version as i64,
            &grant.issuing_persona_id,
            grant.recipient_kind.as_str(),
            &grant.recipient_id,
            grant.recipient_profile.as_str(),
            stored_status,
            grant.mode.as_str(),
            &blocks_json,
            &grant.label,
            grant.created_at as i64,
            grant.updated_at as i64,
            effective_expires_at.map(|v| v as i64),
            grant.revoked_at.map(|v| v as i64),
            &grant.revoked_reason,
            grant.last_used_at.map(|v| v as i64),
            &resource_types_csv,
            &attestation_json,
        ],
    )
    .map_err(|err| ValidationError::new(format!("write access grant: {err}")))?;
    Ok(())
}

pub(crate) fn write_access_grant_history(
    conn: &Connection,
    entry: &core_grant_types::AccessGrantHistoryEntry,
) -> Result<(), ValidationError> {
    conn.execute(
        "INSERT INTO access_grant_history (
            history_id, grant_id, version, action, timestamp, blocks_snapshot, note
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            &entry.history_id,
            &entry.grant_id,
            entry.version as i64,
            &entry.action,
            entry.timestamp as i64,
            &entry.blocks_snapshot,
            &entry.note,
        ],
    )
    .map_err(|err| ValidationError::new(format!("write access grant history: {err}")))?;
    Ok(())
}

fn row_to_access_grant(
    row: &rusqlite::Row,
    now: u64,
) -> rusqlite::Result<core_grant_types::AccessGrant> {
    let grant_id: String = row.get(0)?;
    let version: i64 = row.get(1)?;
    let issuing_persona_id: String = row.get(2)?;
    let recipient_kind_str: String = row.get(3)?;
    let recipient_id: String = row.get(4)?;
    let recipient_profile_str: String = row.get(5)?;
    let stored_status: String = row.get(6)?;
    let mode_str: String = row.get(7)?;
    let blocks_json: String = row.get(8)?;
    let label: Option<String> = row.get(9)?;
    let created_at: i64 = row.get(10)?;
    let updated_at: i64 = row.get(11)?;
    let expires_at: Option<i64> = row.get(12)?;
    let revoked_at: Option<i64> = row.get(13)?;
    let revoked_reason: Option<String> = row.get(14)?;
    let last_used_at: Option<i64> = row.get(15)?;
    // resource_types_csv (col 16) is a projection for indexing; not used on read
    let attestation_json: String = row.get(17)?;

    let recipient_kind = core_event_types::PresentationAudienceKind::parse(&recipient_kind_str)
        .unwrap_or(core_event_types::PresentationAudienceKind::Service);
    let recipient_profile = core_grant_types::RecipientProfile::parse(&recipient_profile_str)
        .unwrap_or(core_grant_types::RecipientProfile::Human);
    let mode = core_grant_types::GrantMode::parse(&mode_str)
        .unwrap_or(core_grant_types::GrantMode::OneShot);
    let blocks = blocks_from_json(&blocks_json).unwrap_or_default();
    let exp = expires_at.map(|v| v as u64);
    // Derive nbf from blocks for the status computation.
    let nb = blocks.iter().filter_map(|sb| sb.block.nbf).max();
    let status = core_grant_types::GrantStatus::derive(&stored_status, nb, exp, now);
    let attestation =
        serde_json::from_str::<core_grant_types::AttestationBinding>(&attestation_json)
            .unwrap_or_default();

    Ok(core_grant_types::AccessGrant {
        id: grant_id,
        version: version as u32,
        issuing_persona_id,
        recipient_kind,
        recipient_id,
        recipient_profile,
        status,
        mode,
        blocks,
        attestation,
        created_at: created_at as u64,
        updated_at: updated_at as u64,
        revoked_at: revoked_at.map(|v| v as u64),
        revoked_reason,
        last_used_at: last_used_at.map(|v| v as u64),
        label,
    })
}

const ACCESS_GRANT_COLUMNS: &str =
    "grant_id, version, issuing_persona_id, recipient_kind, recipient_id,
     recipient_profile, status, mode, blocks_json, label,
     created_at, updated_at, expires_at,
     revoked_at, revoked_reason, last_used_at,
     resource_types_csv, attestation_json";

pub(crate) fn load_access_grant(
    conn: &Connection,
    grant_id: &str,
    now: u64,
) -> Result<Option<core_grant_types::AccessGrant>, ValidationError> {
    let sql = format!("SELECT {ACCESS_GRANT_COLUMNS} FROM access_grants WHERE grant_id = ?1");
    conn.query_row(&sql, params![grant_id], |row| row_to_access_grant(row, now))
        .optional()
        .map_err(|err| ValidationError::new(format!("load access grant: {err}")))
}

pub(crate) fn load_access_grants_by_persona(
    conn: &Connection,
    persona_id: Option<&str>,
    recipient_profile: Option<core_grant_types::RecipientProfile>,
    status_filter: Option<&str>,
    now: u64,
) -> Result<Vec<core_grant_types::AccessGrant>, ValidationError> {
    let mut conditions = Vec::new();
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(pid) = persona_id {
        conditions.push(format!("issuing_persona_id = ?{}", param_values.len() + 1));
        param_values.push(Box::new(pid.to_string()));
    }
    if let Some(rp) = recipient_profile {
        conditions.push(format!("recipient_profile = ?{}", param_values.len() + 1));
        param_values.push(Box::new(rp.as_str().to_string()));
    }
    if let Some(sf) = status_filter {
        conditions.push(format!("status = ?{}", param_values.len() + 1));
        param_values.push(Box::new(sf.to_string()));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };

    let sql = format!(
        "SELECT {ACCESS_GRANT_COLUMNS} FROM access_grants{where_clause} ORDER BY created_at DESC"
    );

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| ValidationError::new(format!("prepare access grants query: {err}")))?;

    let params: Vec<&dyn rusqlite::types::ToSql> =
        param_values.iter().map(|p| p.as_ref()).collect();
    let rows = stmt
        .query_map(params.as_slice(), |row| row_to_access_grant(row, now))
        .map_err(|err| ValidationError::new(format!("query access grants: {err}")))?;

    let mut grants = Vec::new();
    for row in rows {
        grants.push(
            row.map_err(|err| ValidationError::new(format!("read access grant row: {err}")))?,
        );
    }
    Ok(grants)
}

pub(crate) fn load_access_grants_for_recipient(
    conn: &Connection,
    recipient_kind: core_event_types::PresentationAudienceKind,
    recipient_id: &str,
    now: u64,
) -> Result<Vec<core_grant_types::AccessGrant>, ValidationError> {
    let sql = format!(
        "SELECT {ACCESS_GRANT_COLUMNS} FROM access_grants
         WHERE recipient_kind = ?1 AND recipient_id = ?2
         ORDER BY created_at DESC"
    );

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| ValidationError::new(format!("prepare recipient grants query: {err}")))?;

    let rows = stmt
        .query_map(params![recipient_kind.as_str(), recipient_id], |row| {
            row_to_access_grant(row, now)
        })
        .map_err(|err| ValidationError::new(format!("query recipient grants: {err}")))?;

    let mut grants = Vec::new();
    for row in rows {
        grants.push(row.map_err(|err| ValidationError::new(format!("read grant row: {err}")))?);
    }
    Ok(grants)
}

pub(crate) fn load_access_grant_history(
    conn: &Connection,
    grant_id: &str,
) -> Result<Vec<core_grant_types::AccessGrantHistoryEntry>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT history_id, grant_id, version, action, timestamp, blocks_snapshot, note
             FROM access_grant_history WHERE grant_id = ?1 ORDER BY timestamp ASC",
        )
        .map_err(|err| ValidationError::new(format!("prepare grant history query: {err}")))?;

    let rows = stmt
        .query_map(params![grant_id], |row| {
            Ok(core_grant_types::AccessGrantHistoryEntry {
                history_id: row.get(0)?,
                grant_id: row.get(1)?,
                version: row.get::<_, i64>(2)? as u32,
                action: row.get(3)?,
                timestamp: row.get::<_, i64>(4)? as u64,
                blocks_snapshot: row.get(5)?,
                note: row.get(6)?,
            })
        })
        .map_err(|err| ValidationError::new(format!("query grant history: {err}")))?;

    let mut entries = Vec::new();
    for row in rows {
        entries.push(
            row.map_err(|err| ValidationError::new(format!("read grant history row: {err}")))?,
        );
    }
    Ok(entries)
}

pub(crate) fn load_grant_history_timeline(
    conn: &Connection,
    persona_id: Option<&str>,
    limit: usize,
    before: Option<u64>,
) -> Result<Vec<core_grant_types::AccessGrantHistoryEntry>, ValidationError> {
    let (sql, param_values): (String, Vec<Box<dyn rusqlite::types::ToSql>>) =
        match (persona_id, before) {
            (Some(pid), Some(ts)) => (
                "SELECT h.history_id, h.grant_id, h.version, h.action, h.timestamp,
                        h.blocks_snapshot, h.note
                 FROM access_grant_history h
                 JOIN access_grants g ON h.grant_id = g.grant_id
                 WHERE g.issuing_persona_id = ?1 AND h.timestamp < ?2
                 ORDER BY h.timestamp DESC LIMIT ?3"
                    .to_string(),
                vec![
                    Box::new(pid.to_string()) as Box<dyn rusqlite::types::ToSql>,
                    Box::new(ts as i64),
                    Box::new(limit as i64),
                ],
            ),
            (Some(pid), None) => (
                "SELECT h.history_id, h.grant_id, h.version, h.action, h.timestamp,
                        h.blocks_snapshot, h.note
                 FROM access_grant_history h
                 JOIN access_grants g ON h.grant_id = g.grant_id
                 WHERE g.issuing_persona_id = ?1
                 ORDER BY h.timestamp DESC LIMIT ?2"
                    .to_string(),
                vec![
                    Box::new(pid.to_string()) as Box<dyn rusqlite::types::ToSql>,
                    Box::new(limit as i64),
                ],
            ),
            (None, Some(ts)) => (
                "SELECT history_id, grant_id, version, action, timestamp,
                        blocks_snapshot, note
                 FROM access_grant_history
                 WHERE timestamp < ?1
                 ORDER BY timestamp DESC LIMIT ?2"
                    .to_string(),
                vec![
                    Box::new(ts as i64) as Box<dyn rusqlite::types::ToSql>,
                    Box::new(limit as i64),
                ],
            ),
            (None, None) => (
                "SELECT history_id, grant_id, version, action, timestamp,
                        blocks_snapshot, note
                 FROM access_grant_history
                 ORDER BY timestamp DESC LIMIT ?1"
                    .to_string(),
                vec![Box::new(limit as i64) as Box<dyn rusqlite::types::ToSql>],
            ),
        };

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| ValidationError::new(format!("prepare grant timeline query: {err}")))?;

    let params: Vec<&dyn rusqlite::types::ToSql> =
        param_values.iter().map(|p| p.as_ref()).collect();

    let rows = stmt
        .query_map(params.as_slice(), |row| {
            Ok(core_grant_types::AccessGrantHistoryEntry {
                history_id: row.get(0)?,
                grant_id: row.get(1)?,
                version: row.get::<_, i64>(2)? as u32,
                action: row.get(3)?,
                timestamp: row.get::<_, i64>(4)? as u64,
                blocks_snapshot: row.get(5)?,
                note: row.get(6)?,
            })
        })
        .map_err(|err| ValidationError::new(format!("query grant timeline: {err}")))?;

    let mut entries = Vec::new();
    for row in rows {
        entries.push(
            row.map_err(|err| ValidationError::new(format!("read grant timeline row: {err}")))?,
        );
    }
    Ok(entries)
}

pub(crate) fn delete_access_grant(
    conn: &Connection,
    grant_id: &str,
) -> Result<bool, ValidationError> {
    // Delete history first, then the grant itself
    conn.execute(
        "DELETE FROM access_grant_history WHERE grant_id = ?1",
        params![grant_id],
    )
    .map_err(|err| ValidationError::new(format!("delete grant history: {err}")))?;
    let count = conn
        .execute(
            "DELETE FROM access_grants WHERE grant_id = ?1",
            params![grant_id],
        )
        .map_err(|err| ValidationError::new(format!("delete access grant: {err}")))?;
    Ok(count > 0)
}

// ---------------------------------------------------------------------------
// Grant offers (ADR 027)
// ---------------------------------------------------------------------------

pub(crate) fn load_grant_offer(
    conn: &Connection,
    offer_id: &str,
) -> Result<Option<core_eventlog::GrantOfferRecord>, ValidationError> {
    conn.query_row(
        "SELECT offer_id, issuer_persona_id, ephemeral_public_key_hex, sealed_payload_hex,
                relay_hint, expires_at, status, recipient_persona_id, claim_response_hex, claimed_at,
                conditions_json
         FROM grant_offers WHERE offer_id = ?1",
        params![offer_id],
        |row| {
            let status_str: String = row.get(6)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)? as u64,
                status_str,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<i64>>(9)?.map(|v| v as u64),
                row.get::<_, String>(10).unwrap_or_else(|_| "[]".to_string()),
            ))
        },
    )
    .optional()
    .map_err(|err| ValidationError::new(format!("load grant offer: {err}")))?
    .map(|(offer_id, issuer_persona_id, ek_hex, payload_hex, relay_hint, expires_at, status_str, recipient, claim_response, claimed_at, cond_json)| {
        let status = match status_str.as_str() {
            "claimed" => core_eventlog::GrantOfferStatus::Claimed,
            "revoked" => core_eventlog::GrantOfferStatus::Revoked,
            _ => core_eventlog::GrantOfferStatus::Pending,
        };
        Ok(core_eventlog::GrantOfferRecord {
            offer_id,
            issuer_persona_id,
            ephemeral_public_key_hex: ek_hex,
            sealed_payload_hex: payload_hex,
            relay_hint,
            expires_at,
            conditions_json: cond_json,
            status,
            recipient_persona_id: recipient,
            claim_response_hex: claim_response,
            claimed_at,
        })
    })
    .transpose()
}

pub(crate) fn load_grant_offers_by_persona(
    conn: &Connection,
    persona_id: &str,
) -> Result<Vec<core_eventlog::GrantOfferRecord>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT offer_id, issuer_persona_id, ephemeral_public_key_hex, sealed_payload_hex,
                    relay_hint, expires_at, status, recipient_persona_id, claim_response_hex, claimed_at,
                    conditions_json
             FROM grant_offers WHERE issuer_persona_id = ?1 ORDER BY expires_at DESC",
        )
        .map_err(|err| ValidationError::new(format!("prepare grant offer query: {err}")))?;
    let rows = stmt
        .query_map(params![persona_id], |row| {
            let status_str: String = row.get(6)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)? as u64,
                status_str,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<i64>>(9)?.map(|v| v as u64),
                row.get::<_, String>(10)
                    .unwrap_or_else(|_| "[]".to_string()),
            ))
        })
        .map_err(|err| ValidationError::new(format!("query grant offers: {err}")))?;
    let mut result = Vec::new();
    for row in rows {
        let (
            offer_id,
            issuer_persona_id,
            ek_hex,
            payload_hex,
            relay_hint,
            expires_at,
            status_str,
            recipient,
            claim_response,
            claimed_at,
            cond_json,
        ) = row.map_err(|err| ValidationError::new(format!("read grant offer row: {err}")))?;
        let status = match status_str.as_str() {
            "claimed" => core_eventlog::GrantOfferStatus::Claimed,
            "revoked" => core_eventlog::GrantOfferStatus::Revoked,
            _ => core_eventlog::GrantOfferStatus::Pending,
        };
        result.push(core_eventlog::GrantOfferRecord {
            offer_id,
            issuer_persona_id,
            ephemeral_public_key_hex: ek_hex,
            sealed_payload_hex: payload_hex,
            relay_hint,
            expires_at,
            conditions_json: cond_json,
            status,
            recipient_persona_id: recipient,
            claim_response_hex: claim_response,
            claimed_at,
        });
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Badge persistence
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(crate) fn write_badge(
    conn: &Connection,
    badge: &core_eventlog::BadgeRecord,
) -> Result<(), ValidationError> {
    let status_str = if badge.revoked { "revoked" } else { "active" };
    let (ev_type, ev_payload) = match &badge.evidence {
        Some(e) => (Some(e.evidence_type.as_str()), Some(e.payload_hex.as_str())),
        None => (None, None),
    };
    conn.execute(
        "INSERT INTO badges (
            badge_id, issuer_persona_id, recipient_persona_id, badge_type, display_name,
            evidence_type, evidence_payload_hex, issued_at, expires_at, status, revoked_reason
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        ON CONFLICT(badge_id) DO UPDATE SET
            status = excluded.status,
            revoked_reason = excluded.revoked_reason",
        params![
            &badge.badge_id,
            &badge.issuer_persona_id,
            &badge.recipient_persona_id,
            &badge.badge_type,
            &badge.display_name,
            ev_type,
            ev_payload,
            badge.issued_at as i64,
            badge.expires_at.map(|v| v as i64),
            status_str,
            &badge.revoked_reason,
        ],
    )
    .map_err(|err| ValidationError::io_error(format!("write badge: {err}")))?;
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn load_badges(
    conn: &Connection,
    persona_id: &str,
) -> Result<Vec<core_eventlog::BadgeRecord>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT badge_id, issuer_persona_id, recipient_persona_id, badge_type, display_name,
                    evidence_type, evidence_payload_hex, issued_at, expires_at, status, revoked_reason
             FROM badges WHERE issuer_persona_id = ?1 OR recipient_persona_id = ?1
             ORDER BY issued_at DESC",
        )
        .map_err(|err| ValidationError::new(format!("prepare badge query: {err}")))?;
    let rows = stmt
        .query_map(params![persona_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)? as u64,
                row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
                row.get::<_, String>(9)?,
                row.get::<_, Option<String>>(10)?,
            ))
        })
        .map_err(|err| ValidationError::new(format!("query badges: {err}")))?;
    let mut result = Vec::new();
    for row in rows {
        let (
            badge_id,
            issuer,
            recipient,
            btype,
            dname,
            ev_type,
            ev_payload,
            issued_at,
            expires_at,
            status_str,
            revoked_reason,
        ) = row.map_err(|err| ValidationError::new(format!("read badge row: {err}")))?;
        let evidence = match (ev_type, ev_payload) {
            (Some(et), Some(ph)) if !et.is_empty() => Some(core_event_types::BadgeEvidence {
                evidence_type: et,
                payload_hex: ph,
            }),
            _ => None,
        };
        result.push(core_eventlog::BadgeRecord {
            badge_id,
            issuer_persona_id: issuer,
            recipient_persona_id: recipient,
            badge_type: btype,
            display_name: dname,
            evidence,
            issued_at,
            expires_at,
            revoked: status_str == "revoked",
            revoked_reason,
        });
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Badge visibility persistence (local-only, ADR 008)
// ---------------------------------------------------------------------------

/// Set badge visibility for a persona. `visible=true` means the badge appears
/// in the persona's public gallery. This is local-only data — it never leaves
/// the device or appears in the event log.
pub(crate) fn set_badge_visibility(
    conn: &Connection,
    badge_id: &str,
    persona_id: &str,
    visible: bool,
) -> Result<(), ValidationError> {
    conn.execute(
        "INSERT INTO badge_visibility (badge_id, persona_id, visible)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(badge_id, persona_id) DO UPDATE SET visible = excluded.visible",
        params![badge_id, persona_id, visible as i64],
    )
    .map_err(|err| ValidationError::io_error(format!("set badge visibility: {err}")))?;
    Ok(())
}

/// Load the badge gallery for a persona: all active, non-expired recipient badges
/// that the persona has explicitly marked visible. Filtered at the SQL level.
pub(crate) fn load_badge_gallery(
    conn: &Connection,
    persona_id: &str,
    now_secs: u64,
) -> Result<Vec<(core_eventlog::BadgeRecord, bool)>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT b.badge_id, b.issuer_persona_id, b.recipient_persona_id, b.badge_type,
                    b.display_name, b.evidence_type, b.evidence_payload_hex, b.issued_at,
                    b.expires_at, b.status, b.revoked_reason,
                    COALESCE(bv.visible, 0) AS visible
             FROM badges b
             LEFT JOIN badge_visibility bv
                ON b.badge_id = bv.badge_id AND bv.persona_id = ?1
             WHERE b.recipient_persona_id = ?1
               AND b.status = 'active'
               AND (b.expires_at IS NULL OR b.expires_at > ?2)
             ORDER BY b.issued_at DESC",
        )
        .map_err(|err| ValidationError::new(format!("prepare gallery query: {err}")))?;
    let rows = stmt
        .query_map(params![persona_id, now_secs as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, i64>(11)?,
            ))
        })
        .map_err(|err| ValidationError::new(format!("query gallery: {err}")))?;
    let mut result = Vec::new();
    for row in rows {
        let (
            badge_id,
            issuer,
            recipient,
            btype,
            dname,
            ev_type,
            ev_payload,
            issued_at,
            expires_at,
            status_str,
            revoked_reason,
            visible_int,
        ) = row.map_err(|err| ValidationError::new(format!("read gallery row: {err}")))?;
        let evidence = match (ev_type, ev_payload) {
            (Some(et), Some(ph)) if !et.is_empty() => Some(core_event_types::BadgeEvidence {
                evidence_type: et,
                payload_hex: ph,
            }),
            _ => None,
        };
        result.push((
            core_eventlog::BadgeRecord {
                badge_id,
                issuer_persona_id: issuer,
                recipient_persona_id: recipient,
                badge_type: btype,
                display_name: dname,
                evidence,
                issued_at: issued_at as u64,
                expires_at: expires_at.map(|v| v as u64),
                revoked: status_str == "revoked",
                revoked_reason,
            },
            visible_int != 0,
        ));
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Badge dispute persistence (ADR 030 counter-attestation)
// ---------------------------------------------------------------------------

/// Write a badge dispute record to the database.
#[allow(dead_code)]
pub(crate) fn write_badge_dispute(
    conn: &Connection,
    dispute: &core_eventlog::BadgeDisputeRecord,
) -> Result<(), ValidationError> {
    conn.execute(
        "INSERT INTO badge_disputes (
            dispute_id, target_badge_id, disputer_persona_id, reason, evidence
        ) VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(dispute_id) DO NOTHING",
        params![
            &dispute.dispute_id,
            &dispute.target_badge_id,
            &dispute.disputer_persona_id,
            &dispute.reason,
            &dispute.evidence,
        ],
    )
    .map_err(|err| ValidationError::io_error(format!("write badge dispute: {err}")))?;
    Ok(())
}

/// Load all disputes targeting a specific badge.
#[allow(dead_code)]
pub(crate) fn load_badge_disputes(
    conn: &Connection,
    target_badge_id: &str,
) -> Result<Vec<core_eventlog::BadgeDisputeRecord>, ValidationError> {
    let mut stmt = conn
        .prepare(
            "SELECT dispute_id, target_badge_id, disputer_persona_id, reason, evidence
             FROM badge_disputes WHERE target_badge_id = ?1",
        )
        .map_err(|err| ValidationError::new(format!("prepare dispute query: {err}")))?;
    let rows = stmt
        .query_map(params![target_badge_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(|err| ValidationError::new(format!("query disputes: {err}")))?;
    let mut result = Vec::new();
    for row in rows {
        let (dispute_id, target, disputer, reason, evidence) =
            row.map_err(|err| ValidationError::new(format!("read dispute row: {err}")))?;
        result.push(core_eventlog::BadgeDisputeRecord {
            dispute_id,
            target_badge_id: target,
            disputer_persona_id: disputer,
            reason,
            evidence,
        });
    }
    Ok(result)
}

/// Count disputes for a badge from identities within a given set (e.g. trust graph reachable set).
#[allow(dead_code)]
pub(crate) fn count_badge_disputes_from_set(
    conn: &Connection,
    target_badge_id: &str,
    persona_ids: &[&str],
) -> Result<u32, ValidationError> {
    if persona_ids.is_empty() {
        return Ok(0);
    }
    // For small sets, use IN clause. For large sets, a temp table would be better.
    let placeholders: Vec<String> = persona_ids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 2))
        .collect();
    let sql = format!(
        "SELECT COUNT(*) FROM badge_disputes WHERE target_badge_id = ?1 AND disputer_persona_id IN ({})",
        placeholders.join(", ")
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| ValidationError::new(format!("prepare dispute count: {err}")))?;

    let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    params_vec.push(Box::new(target_badge_id.to_string()));
    for &pid in persona_ids {
        params_vec.push(Box::new(pid.to_string()));
    }
    let params_refs: Vec<&dyn rusqlite::types::ToSql> =
        params_vec.iter().map(|p| p.as_ref()).collect();

    let count: u32 = stmt
        .query_row(params_refs.as_slice(), |row| row.get(0))
        .map_err(|err| ValidationError::new(format!("count disputes: {err}")))?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// Credential deposit persistence (P29)
// ---------------------------------------------------------------------------

/// Row type returned by credential deposit queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDepositRow {
    pub deposit_id: String,
    pub grant_id: String,
    pub credential_id: String,
    pub issuer_id: String,
    pub encrypted_blocks_json: String,
    pub status: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub revoked_reason: Option<String>,
}

pub(crate) fn write_credential_deposit(
    conn: &Connection,
    deposit: &core_eventlog::CredentialDepositRecord,
) -> Result<(), ValidationError> {
    let status_str = match deposit.status {
        core_eventlog::CredentialDepositStatus::Active => "active",
        core_eventlog::CredentialDepositStatus::Revoked => "revoked",
    };
    conn.execute(
        "INSERT INTO credential_deposits (
            deposit_id, grant_id, credential_id, issuer_id,
            encrypted_blocks_json, status, created_at, expires_at,
            revoked_at, revoked_reason
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        ON CONFLICT(deposit_id) DO UPDATE SET
            status = excluded.status,
            revoked_at = excluded.revoked_at,
            revoked_reason = excluded.revoked_reason",
        params![
            &deposit.deposit_id,
            &deposit.grant_id,
            &deposit.credential_id,
            &deposit.issuer_id,
            &deposit.encrypted_blocks_json,
            status_str,
            deposit.created_at as i64,
            deposit.expires_at.map(|v| v as i64),
            deposit.revoked_at.map(|v| v as i64),
            &deposit.revoked_reason,
        ],
    )
    .map_err(|err| ValidationError::new(format!("write credential deposit: {err}")))?;
    Ok(())
}

pub(crate) fn load_credential_deposit_by_grant(
    conn: &Connection,
    grant_id: &str,
) -> Result<Option<CredentialDepositRow>, ValidationError> {
    conn.query_row(
        "SELECT deposit_id, grant_id, credential_id, issuer_id,
                encrypted_blocks_json, status, created_at, expires_at,
                revoked_at, revoked_reason
         FROM credential_deposits WHERE grant_id = ?1 AND status = 'active'
         LIMIT 1",
        params![grant_id],
        |row| {
            Ok(CredentialDepositRow {
                deposit_id: row.get(0)?,
                grant_id: row.get(1)?,
                credential_id: row.get(2)?,
                issuer_id: row.get(3)?,
                encrypted_blocks_json: row.get(4)?,
                status: row.get(5)?,
                created_at: row.get::<_, i64>(6)? as u64,
                expires_at: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                revoked_at: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
                revoked_reason: row.get(9)?,
            })
        },
    )
    .optional()
    .map_err(|err| ValidationError::new(format!("load credential deposit: {err}")))
}

pub(crate) fn revoke_credential_deposit(
    conn: &Connection,
    grant_id: &str,
    reason: Option<&str>,
    revoked_at: u64,
) -> Result<(), ValidationError> {
    conn.execute(
        "UPDATE credential_deposits SET status = 'revoked', revoked_at = ?1, revoked_reason = ?2
         WHERE grant_id = ?3 AND status = 'active'",
        params![revoked_at as i64, reason, grant_id],
    )
    .map_err(|err| ValidationError::new(format!("revoke credential deposit: {err}")))?;
    Ok(())
}
