use core_event_types::BlockStore;
use core_types::ValidationError;
use rusqlite::{Connection, OptionalExtension, params};

/// SQLite-backed BlockStore implementation.
///
/// Stores encrypted blocks in the `local_blocks` table. Suitable for
/// development, small payloads, and single-file portability.
pub struct SqliteBlockStore<'a> {
    conn: &'a Connection,
}

impl<'a> SqliteBlockStore<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }
}

impl BlockStore for SqliteBlockStore<'_> {
    fn put_block(
        &self,
        chunk_id: &str,
        nonce_hex: &str,
        ciphertext: &[u8],
    ) -> Result<(), ValidationError> {
        let ciphertext_bytes = ciphertext.len() as i64;
        self.conn
            .execute(
                "INSERT INTO local_blocks (chunk_id, ciphertext_bytes, nonce_hex, ciphertext)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(chunk_id) DO UPDATE SET
                    ciphertext_bytes = excluded.ciphertext_bytes,
                    nonce_hex = excluded.nonce_hex,
                    ciphertext = excluded.ciphertext",
                params![chunk_id, ciphertext_bytes, nonce_hex, ciphertext],
            )
            .map_err(|err| ValidationError::new(format!("put block: {err}")))?;
        Ok(())
    }

    fn get_block(&self, chunk_id: &str) -> Result<Option<(String, Vec<u8>)>, ValidationError> {
        self.conn
            .query_row(
                "SELECT nonce_hex, ciphertext
                 FROM local_blocks
                 WHERE chunk_id = ?1 AND nonce_hex IS NOT NULL AND ciphertext IS NOT NULL",
                params![chunk_id],
                |row| {
                    let nonce_hex: String = row.get(0)?;
                    let ciphertext: Vec<u8> = row.get(1)?;
                    Ok((nonce_hex, ciphertext))
                },
            )
            .optional()
            .map_err(|err| ValidationError::new(format!("get block: {err}")))
    }

    fn delete_block(&self, chunk_id: &str) -> Result<(), ValidationError> {
        self.conn
            .execute(
                "DELETE FROM local_blocks WHERE chunk_id = ?1",
                params![chunk_id],
            )
            .map_err(|err| ValidationError::new(format!("delete block: {err}")))?;
        Ok(())
    }

    fn has_block(&self, chunk_id: &str) -> Result<bool, ValidationError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM local_blocks WHERE chunk_id = ?1 AND ciphertext IS NOT NULL",
                params![chunk_id],
                |row| row.get(0),
            )
            .map_err(|err| ValidationError::new(format!("check block existence: {err}")))?;
        Ok(count > 0)
    }

    fn list_block_ids(&self) -> Result<Vec<String>, ValidationError> {
        let mut stmt = self
            .conn
            .prepare("SELECT chunk_id FROM local_blocks WHERE ciphertext IS NOT NULL ORDER BY chunk_id ASC")
            .map_err(|err| ValidationError::new(format!("prepare block id list: {err}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|err| ValidationError::new(format!("query block ids: {err}")))?;

        let mut ids = Vec::new();
        for row in rows {
            ids.push(row.map_err(|err| ValidationError::new(format!("read block id: {err}")))?);
        }
        Ok(ids)
    }
}
