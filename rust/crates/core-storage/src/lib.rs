use core_types::{FileManifest, StorageLedgerEntry, StorageRelationship};

pub fn create_relationship(id: impl Into<String>, local_peer_id: impl Into<String>, remote_peer_id: impl Into<String>) -> StorageRelationship {
    StorageRelationship {
        id: id.into(),
        local_peer_id: local_peer_id.into(),
        remote_peer_id: remote_peer_id.into(),
        approved: true,
    }
}

pub fn publish_manifest(id: impl Into<String>, chunk_count: u32) -> FileManifest {
    FileManifest {
        id: id.into(),
        chunk_count,
    }
}

pub fn ledger_delta(relationship_id: impl Into<String>, stored_bytes_delta: i64) -> StorageLedgerEntry {
    StorageLedgerEntry {
        relationship_id: relationship_id.into(),
        stored_bytes_delta,
    }
}

