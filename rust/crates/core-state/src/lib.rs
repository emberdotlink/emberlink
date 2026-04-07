use std::collections::BTreeMap;

use core_crypto::Verifier;
use core_events::EventEnvelope;
use core_types::{EventType, ValidationError, Validate};

pub const SQLITE_MIGRATION_V1: &str = r#"
CREATE TABLE events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    schema_version TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload BLOB NOT NULL
);

CREATE TABLE event_refs (
    event_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    target_event_id TEXT NOT NULL
);

CREATE TABLE event_signatures (
    event_id TEXT NOT NULL PRIMARY KEY,
    signer TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE sync_batches (
    batch_id TEXT NOT NULL PRIMARY KEY,
    cursor_peer_id TEXT NOT NULL,
    last_event_id TEXT
);
"#;

#[derive(Debug, Default)]
pub struct EventStore {
    events: Vec<EventEnvelope>,
    materialized: BTreeMap<String, EventType>,
}

impl EventStore {
    pub fn append(
        &mut self,
        event: EventEnvelope,
        verifier: &impl Verifier,
    ) -> Result<(), ValidationError> {
        event.validate()?;
        if !verifier.verify(&event.signer, &event.payload, &event.signature) {
            return Err(ValidationError::new("signature verification failed"));
        }

        self.materialize(&event);
        self.events.push(event);
        Ok(())
    }

    pub fn rebuild(&mut self) {
        self.materialized.clear();
        let snapshot = self.events.clone();
        for event in &snapshot {
            self.materialize(event);
        }
    }

    pub fn current_event_type_for(&self, event_id: &str) -> Option<EventType> {
        self.materialized.get(event_id).copied()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    fn materialize(&mut self, event: &EventEnvelope) {
        self.materialized
            .insert(event.event_id.clone(), event.event_type);
    }
}

#[cfg(test)]
mod tests {
    use core_crypto::{FixtureSigner, FixtureVerifier};
    use core_events::EventEnvelope;
    use core_types::{EventType, IdentityRoot};

    use super::*;

    #[test]
    fn append_and_rebuild_are_deterministic() {
        let signer = FixtureSigner::new("fixture_signer");
        let verifier = FixtureVerifier;
        let root = IdentityRoot {
            id: "root-1".into(),
            display_name: "Primary".into(),
        };
        let event = EventEnvelope::new("evt-1", EventType::RootCreated, &root, &signer);
        let mut store = EventStore::default();

        store.append(event, &verifier).unwrap();
        assert_eq!(store.event_count(), 1);
        assert_eq!(store.current_event_type_for("evt-1"), Some(EventType::RootCreated));

        store.rebuild();
        assert_eq!(store.current_event_type_for("evt-1"), Some(EventType::RootCreated));
    }
}
