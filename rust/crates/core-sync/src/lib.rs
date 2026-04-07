use core_types::{PeerCursor, RelayEnvelope, SyncBatch};

pub fn new_cursor(peer_id: impl Into<String>) -> PeerCursor {
    PeerCursor {
        peer_id: peer_id.into(),
        last_event_id: None,
    }
}

pub fn new_batch(id: impl Into<String>, event_ids: Vec<String>) -> SyncBatch {
    SyncBatch {
        id: id.into(),
        event_ids,
    }
}

pub fn wrap_for_relay(id: impl Into<String>, opaque_payload: Vec<u8>) -> RelayEnvelope {
    RelayEnvelope {
        id: id.into(),
        opaque_payload,
    }
}

