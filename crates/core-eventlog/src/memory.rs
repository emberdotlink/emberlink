use std::collections::{BTreeMap, BTreeSet, HashMap};

use core_crypto::{DOMAIN_EVENT, Verifier};
use core_event_types::{
    EventBody, EventRefRelation, EventSubject, EventType, FileManifest, KeyRole, SignerBinding,
    SubjectKind,
};
use core_events::{EventEnvelope, EventRef};
use core_principals::PeerCursor;
use core_types::{SchemaVersion, Validate, ValidationError};

use crate::materialize::{advance_chain_head, apply_event, apply_storage_event, check_chain};
use crate::{AllowAllAuthorizer, Authorizer, EventLog, MaterializedState, SyncBatchRecord};

/// P79.1a M-2: upper bound for caller-supplied `now_epoch_secs` in the
/// in-memory log. `core-state::EventStore::append_with_authorizer` clamps
/// to `system_now + 300s` using the real wall clock, but the memory log is
/// a WASM / test fixture (it compiles to `wasm32-unknown-unknown` where
/// `SystemTime` is unavailable), so we apply a fixed year-2500 ceiling
/// instead. This is an imperfect match — a crafted timestamp anywhere in
/// the range `(real_now, 2500)` still bypasses cooldowns — but it prevents
/// `u64::MAX` / `i64::MAX` style sentinels and keeps the memory log from
/// silently inheriting the core-state gap when it is embedded elsewhere.
/// Production surfaces that need real wall-clock enforcement must run
/// behind `core-state::EventStore`, not `MemoryEventLog`.
///
/// Value: 2500-01-01T00:00:00Z in epoch seconds.
pub const MEMORY_LOG_NOW_CEILING: u64 = 16_725_225_600;
fn clamp_now(now_epoch_secs: u64) -> u64 {
    now_epoch_secs.min(MEMORY_LOG_NOW_CEILING)
}

/// In-memory event log implementation for WASM and testing.
///
/// All data is held in memory with no persistence layer. Suitable for
/// browser extension runtimes (`wasm32-unknown-unknown`) and unit tests
/// that don't need SQLite.
#[derive(Debug)]
pub struct MemoryEventLog {
    events: Vec<EventEnvelope>,
    event_index: HashMap<String, usize>,
    type_index: HashMap<EventType, Vec<usize>>,
    materialized: MaterializedState,
    storage_manifests: BTreeMap<String, FileManifest>,
    peer_cursors: HashMap<String, Option<String>>,
    sync_batches: Vec<SyncBatchRecord>,
}

impl Default for MemoryEventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryEventLog {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            event_index: HashMap::new(),
            type_index: HashMap::new(),
            materialized: MaterializedState::default(),
            storage_manifests: BTreeMap::new(),
            peer_cursors: HashMap::new(),
            sync_batches: Vec::new(),
        }
    }

    /// Access storage manifests (file manifests published via events).
    pub fn storage_manifests(&self) -> &BTreeMap<String, FileManifest> {
        &self.storage_manifests
    }

    fn append_validated(&mut self, event: EventEnvelope) -> Result<(), ValidationError> {
        // BEGIN IMMEDIATE analog for the in-memory log.
        //
        // The authorize → check_chain → apply_event → advance_chain_head →
        // apply_storage_event sequence mutates `materialized` mid-stream. If
        // `apply_storage_event` (or any later step) fails after `apply_event`
        // has already succeeded, `materialized` is half-mutated while the
        // event is never persisted to `self.events`, leaving derived state
        // inconsistent with the authoritative event log. The daemon SQL path
        // closes the same gap with `BEGIN IMMEDIATE` + RAII rollback
        // (REVIEW2-F3, commit ed832de6); we mirror it here with a
        // snapshot/restore guard so any error rolls back atomically.
        //
        // Pattern matches `import_sync_batch` below.
        let snapshot_materialized = self.materialized.clone();
        let snapshot_manifests = self.storage_manifests.clone();

        check_chain(&self.materialized, &event)?;
        if let Err(err) = apply_event(&mut self.materialized, &event) {
            self.materialized = snapshot_materialized;
            self.storage_manifests = snapshot_manifests;
            return Err(err);
        }
        advance_chain_head(&mut self.materialized, &event);
        if let Err(err) =
            apply_storage_event(&mut self.storage_manifests, &event, &self.materialized)
        {
            self.materialized = snapshot_materialized;
            self.storage_manifests = snapshot_manifests;
            return Err(err);
        }

        let idx = self.events.len();
        self.event_index.insert(event.event_id.clone(), idx);
        self.type_index
            .entry(event.event_type)
            .or_default()
            .push(idx);
        self.events.push(event);
        Ok(())
    }

    fn rebuild_indices(&mut self) {
        self.event_index = self
            .events
            .iter()
            .enumerate()
            .map(|(i, e)| (e.event_id.clone(), i))
            .collect();
        self.type_index.clear();
        for (i, e) in self.events.iter().enumerate() {
            self.type_index.entry(e.event_type).or_default().push(i);
        }
    }
}

impl EventLog for MemoryEventLog {
    fn append(
        &mut self,
        event: EventEnvelope,
        verifier: &dyn Verifier,
    ) -> Result<(), ValidationError> {
        self.append_with_authorizer(event, verifier, &AllowAllAuthorizer, 0)
    }

    fn append_with_authorizer(
        &mut self,
        event: EventEnvelope,
        verifier: &dyn Verifier,
        authorizer: &dyn Authorizer,
        now_epoch_secs: u64,
    ) -> Result<(), ValidationError> {
        // P79.1a M-2: clamp caller-supplied `now_epoch_secs` to a hard
        // ceiling so that sentinels like `u64::MAX` cannot bypass cooldowns
        // or flip expiry checks. The clamp is imperfect (a crafted timestamp
        // below the ceiling still bypasses cooldowns that end before it), so
        // production surfaces must use core-state::EventStore's wall-clock
        // clamp instead.
        let effective_now = clamp_now(now_epoch_secs);
        event.validate()?;
        if !core_crypto::verify_with_context(
            DOMAIN_EVENT,
            verifier,
            &event.signer,
            &event.signed_bytes(),
            &event.signature,
        ) {
            return Err(ValidationError::new("signature verification failed"));
        }
        // Internal store append — raw errors for precise callers.
        authorizer.authorize_raw(&event, &self.materialized, effective_now)?;
        self.append_validated(event)
    }

    fn rebuild(&mut self) -> Result<(), ValidationError> {
        let events = std::mem::take(&mut self.events);
        self.materialized = MaterializedState::default();
        self.storage_manifests.clear();

        for event in &events {
            apply_event(&mut self.materialized, event)?;
            advance_chain_head(&mut self.materialized, event);
            apply_storage_event(&mut self.storage_manifests, event, &self.materialized)?;
        }

        self.events = events;
        self.rebuild_indices();
        Ok(())
    }

    fn materialized(&self) -> &MaterializedState {
        &self.materialized
    }

    fn events(&self) -> &[EventEnvelope] {
        &self.events
    }

    fn event_count(&self) -> usize {
        self.events.len()
    }

    fn has_event(&self, event_id: &str) -> bool {
        self.event_index.contains_key(event_id)
    }

    fn current_event_type_for(&self, event_id: &str) -> Option<EventType> {
        self.event_index
            .get(event_id)
            .map(|&idx| self.events[idx].event_type)
    }

    fn event_ids(&self) -> Vec<String> {
        self.events
            .iter()
            .map(|event| event.event_id.clone())
            .collect()
    }

    fn event_id_set(&self) -> &HashMap<String, usize> {
        &self.event_index
    }

    fn events_by_ids(&self, event_ids: &[String]) -> Vec<EventEnvelope> {
        event_ids
            .iter()
            .filter_map(|event_id| {
                self.event_index
                    .get(event_id.as_str())
                    .map(|&idx| self.events[idx].clone())
            })
            .collect()
    }

    fn events_of_type(&self, event_type: EventType) -> Vec<EventEnvelope> {
        self.type_index
            .get(&event_type)
            .map(|indices| {
                indices
                    .iter()
                    .map(|&idx| self.events[idx].clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn events_of_type_rev(&self, event_type: EventType) -> Vec<EventEnvelope> {
        self.type_index
            .get(&event_type)
            .map(|indices| {
                indices
                    .iter()
                    .rev()
                    .map(|&idx| self.events[idx].clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn export_events(&self) -> String {
        let mut lines = Vec::new();
        for event in &self.events {
            let refs_str = event
                .refs
                .iter()
                .map(|r| format!("{}:{}:{}", r.relation.as_str(), r.target_event_id, r.seq))
                .collect::<Vec<_>>()
                .join(",");
            let payload_hex = core_types::bytes_to_hex(&event.payload);
            let signature_str = &event.signature.0;
            lines.push(format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                event.event_id,
                event.schema_version,
                event.event_type.as_str(),
                event.subject.kind.as_str(),
                event.subject.subject_id,
                event.signer_binding.signer.kind.as_str(),
                event.signer_binding.signer.subject_id,
                event.signer_binding.role.as_str(),
                event.signer_binding.key_id,
                event.signer.0,
                payload_hex,
                signature_str,
                refs_str,
            ));
        }
        lines.join("\n")
    }

    fn import_events(
        &mut self,
        data: &str,
        verifier: &dyn Verifier,
        authorizer: &dyn Authorizer,
        now_epoch_secs: u64,
    ) -> Result<usize, ValidationError> {
        use core_crypto::{PublicKey, Signature};

        let mut imported = 0;
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() < 12 {
                return Err(ValidationError::new(format!(
                    "import line has {} fields, expected at least 12",
                    fields.len()
                )));
            }

            let event_id = fields[0];
            if self.events.iter().any(|e| e.event_id == event_id) {
                continue;
            }

            let schema_version = SchemaVersion::parse(fields[1]).ok_or_else(|| {
                ValidationError::new(format!("invalid schema version: {}", fields[1]))
            })?;
            let event_type = EventType::parse(fields[2]).ok_or_else(|| {
                ValidationError::new(format!("unknown event type: {}", fields[2]))
            })?;
            let subject_kind = SubjectKind::parse(fields[3]).ok_or_else(|| {
                ValidationError::new(format!("unknown subject kind: {}", fields[3]))
            })?;
            let subject = EventSubject::new(subject_kind, fields[4]);
            let signer_kind = SubjectKind::parse(fields[5]).ok_or_else(|| {
                ValidationError::new(format!("unknown signer kind: {}", fields[5]))
            })?;
            let signer_binding = SignerBinding {
                signer: EventSubject::new(signer_kind, fields[6]),
                role: KeyRole::parse(fields[7]).ok_or_else(|| {
                    ValidationError::new(format!("unknown key role: {}", fields[7]))
                })?,
                key_id: fields[8].to_string(),
            };
            let signer_public_key = PublicKey(fields[9].to_string());
            let payload = core_types::hex_to_bytes(fields[10])
                .map_err(|err| ValidationError::new(format!("invalid payload hex: {err}")))?;
            let signature = Signature(fields[11].to_string());

            let refs_str = if fields.len() > 12 { fields[12] } else { "" };
            let refs = if refs_str.is_empty() {
                Vec::new()
            } else {
                refs_str
                    .split(',')
                    .map(|r| {
                        let parts: Vec<&str> = r.splitn(3, ':').collect();
                        if parts.len() < 2 {
                            return Err(ValidationError::new(format!("invalid ref: {r}")));
                        }
                        let relation = EventRefRelation::parse(parts[0]).ok_or_else(|| {
                            ValidationError::new(format!("unknown ref relation: {}", parts[0]))
                        })?;
                        let seq: u64 = if parts.len() == 3 {
                            parts[2].parse().map_err(|_| {
                                ValidationError::new(format!("invalid ref seq in: {r}"))
                            })?
                        } else {
                            0
                        };
                        Ok(EventRef {
                            relation,
                            target_event_id: parts[1].to_string(),
                            seq,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?
            };

            let body = EventBody::decode_canonical(&payload)?;

            let envelope = EventEnvelope {
                schema_version,
                event_id: event_id.to_string(),
                event_type,
                subject,
                signer_binding,
                signer: signer_public_key,
                payload,
                refs,
                signature,
                body,
            };

            // P79.1a M-2: append_with_authorizer clamps internally, but we
            // keep the original value here so downstream callers see the
            // unclamped input via the trait contract.
            self.append_with_authorizer(envelope, verifier, authorizer, now_epoch_secs)?;
            imported += 1;
        }
        Ok(imported)
    }

    fn peer_cursor(&self, peer_id: &str) -> Result<PeerCursor, ValidationError> {
        Ok(PeerCursor {
            peer_id: peer_id.to_string(),
            last_event_id: self.peer_cursors.get(peer_id).cloned().unwrap_or(None),
        })
    }

    fn peer_cursors(&self) -> Result<Vec<PeerCursor>, ValidationError> {
        let mut cursors: Vec<PeerCursor> = self
            .peer_cursors
            .iter()
            .map(|(peer_id, last_event_id)| PeerCursor {
                peer_id: peer_id.clone(),
                last_event_id: last_event_id.clone(),
            })
            .collect();
        cursors.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        Ok(cursors)
    }

    fn sync_batches(&self) -> Result<Vec<SyncBatchRecord>, ValidationError> {
        Ok(self.sync_batches.clone())
    }

    fn import_sync_batch(
        &mut self,
        peer_id: &str,
        batch_id: &str,
        events: &[EventEnvelope],
        last_remote_event_id: Option<&str>,
        verifier: &dyn Verifier,
        authorizer: &dyn Authorizer,
        now_epoch_secs: u64,
    ) -> Result<usize, ValidationError> {
        // P79.1a M-2: clamp here so every authorize call below sees the
        // same bounded value, even though we inline the authorize call
        // rather than delegating to `append_with_authorizer`.
        let effective_now = clamp_now(now_epoch_secs);
        let seen_ids: BTreeSet<&str> = self.event_index.keys().map(|k| k.as_str()).collect();
        let mut imported = Vec::new();

        // Snapshot state for rollback on error
        let snapshot_materialized = self.materialized.clone();
        let snapshot_manifests = self.storage_manifests.clone();

        for event in events {
            event.validate()?;
            if !core_crypto::verify_with_context(
                DOMAIN_EVENT,
                verifier,
                &event.signer,
                &event.signed_bytes(),
                &event.signature,
            ) {
                self.materialized = snapshot_materialized;
                self.storage_manifests = snapshot_manifests;
                return Err(ValidationError::new("signature verification failed"));
            }
            if seen_ids.contains(event.event_id.as_str())
                || imported
                    .iter()
                    .any(|e: &EventEnvelope| e.event_id == event.event_id)
            {
                continue;
            }
            if let Err(err) = authorizer.authorize_raw(event, &self.materialized, effective_now) {
                self.materialized = snapshot_materialized;
                self.storage_manifests = snapshot_manifests;
                return Err(err);
            }
            if let Err(err) = check_chain(&self.materialized, event) {
                self.materialized = snapshot_materialized;
                self.storage_manifests = snapshot_manifests;
                return Err(err);
            }
            if let Err(err) = apply_event(&mut self.materialized, event) {
                self.materialized = snapshot_materialized;
                self.storage_manifests = snapshot_manifests;
                return Err(err);
            }
            advance_chain_head(&mut self.materialized, event);
            if let Err(err) =
                apply_storage_event(&mut self.storage_manifests, event, &self.materialized)
            {
                self.materialized = snapshot_materialized;
                self.storage_manifests = snapshot_manifests;
                return Err(err);
            }
            imported.push(event.clone());
        }

        // Record sync metadata
        self.sync_batches.push(SyncBatchRecord {
            batch_id: batch_id.to_string(),
            peer_id: peer_id.to_string(),
            last_event_id: last_remote_event_id.map(|s| s.to_string()),
        });
        if let Some(last_id) = last_remote_event_id {
            self.peer_cursors
                .insert(peer_id.to_string(), Some(last_id.to_string()));
        }

        let imported_count = imported.len();
        let base = self.events.len();
        for (offset, event) in imported.iter().enumerate() {
            let idx = base + offset;
            self.event_index.insert(event.event_id.clone(), idx);
            self.type_index
                .entry(event.event_type)
                .or_default()
                .push(idx);
        }
        self.events.extend(imported);
        Ok(imported_count)
    }
}

#[cfg(test)]
mod tests {
    use core_crypto::{FixtureSigner, FixtureVerifier};
    use core_event_types::{
        DeviceAddedEvent, EventBody, PersonaCreatedEvent, RootCreatedEvent, SignerBinding,
    };
    use core_events::EventEnvelope;
    use core_principals::{KeyAlgorithm, PublicKeyMaterial, SurvivalMode};
    use proptest::prelude::*;

    use super::*;

    const PROPTEST_CASES: u32 = 64;

    #[derive(Clone, Debug)]
    enum ChainOp {
        Device(u8),
        Persona(u8),
    }

    fn test_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: key_id.into(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: format!("ed25519:{key_id}"),
        }
    }

    fn test_encryption_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: format!("enc-{key_id}"),
            algorithm: KeyAlgorithm::AgeX25519,
            public_key: format!("age1{key_id}fixture"),
        }
    }

    fn append_typed_with_refs(
        log: &mut MemoryEventLog,
        event_id: &str,
        body: EventBody,
        signer_binding: SignerBinding,
        refs: Vec<core_events::EventRef>,
    ) {
        let signer = FixtureSigner::new(signer_binding.key_id.clone());
        let event =
            EventEnvelope::from_body(event_id, body, refs, signer_binding, &signer).unwrap();
        log.append(event, &FixtureVerifier).unwrap();
    }

    fn root_event() -> EventEnvelope {
        let signer_binding = SignerBinding::root("root-a", "key-root-a");
        EventEnvelope::from_body(
            "evt-root-0",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a"),
            }),
            Vec::new(),
            signer_binding,
            &FixtureSigner::new("key-root-a"),
        )
        .unwrap()
    }

    fn chain_step_event(
        idx: usize,
        op: &ChainOp,
        prev_event_id: String,
        seq: u64,
    ) -> EventEnvelope {
        let body = match op {
            ChainOp::Device(label) => EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: format!("device-{idx}"),
                label: format!("Device {label}"),
                initial_key: test_key(&format!("key-device-{idx}")),
                initial_encryption_key: test_encryption_key(&format!("device-{idx}")),
            }),
            ChainOp::Persona(label) => EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: format!("persona-{idx}"),
                label: format!("Persona {label}"),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key(&format!("key-persona-{idx}")),
            }),
        };
        EventEnvelope::from_body(
            format!("evt-step-{idx}"),
            body,
            vec![core_events::EventRef::previous(prev_event_id, seq)],
            SignerBinding::root("root-a", "key-root-a"),
            &FixtureSigner::new("key-root-a"),
        )
        .unwrap()
    }

    fn arb_chain_op() -> impl Strategy<Value = ChainOp> {
        prop_oneof![
            (0u8..32).prop_map(ChainOp::Device),
            (0u8..32).prop_map(ChainOp::Persona),
        ]
    }

    /// Returns the (prev_event_id, next_seq) for a given root, or None if no head yet.
    fn chain_next(log: &MemoryEventLog, root_id: &str) -> Option<(String, u64)> {
        log.materialized()
            .root_chain_heads
            .get(root_id)
            .map(|(id, seq)| (id.clone(), seq + 1))
    }

    fn setup_identity(log: &mut MemoryEventLog) -> (String, String, String) {
        append_typed_with_refs(
            log,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a"),
            }),
            SignerBinding::root("root-a", "key-root-a"),
            Vec::new(),
        );

        let (prev_id, next_seq) = chain_next(log, "root-a").unwrap();
        append_typed_with_refs(
            log,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a"),
                initial_encryption_key: test_encryption_key("device-a"),
            }),
            SignerBinding::root("root-a", "key-root-a"),
            vec![core_events::EventRef::previous(prev_id, next_seq)],
        );

        let (prev_id, next_seq) = chain_next(log, "root-a").unwrap();
        append_typed_with_refs(
            log,
            "evt-persona-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Work".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-a"),
            }),
            SignerBinding::root("root-a", "key-root-a"),
            vec![core_events::EventRef::previous(prev_id, next_seq)],
        );

        (
            "root-a".to_string(),
            "device-a".to_string(),
            "persona-a".to_string(),
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

        // Anchor: core_eventlog_proptest_invariants_landed
        #[test]
        fn generated_append_sequences_preserve_chain_head_and_rebuild_state(
            ops in proptest::collection::vec(arb_chain_op(), 0..48),
        ) {
            let mut log = MemoryEventLog::new();
            let root = root_event();
            log.append(root.clone(), &FixtureVerifier).unwrap();
            let mut expected_ids = vec![root.event_id];

            for (idx, op) in ops.iter().enumerate() {
                let (prev_event_id, seq) = chain_next(&log, "root-a").unwrap();
                let event = chain_step_event(idx, op, prev_event_id, seq);
                log.append(event.clone(), &FixtureVerifier).unwrap();
                expected_ids.push(event.event_id);

                prop_assert_eq!(log.event_count(), expected_ids.len());
                let actual_ids = log.event_ids();
                prop_assert_eq!(actual_ids.as_slice(), expected_ids.as_slice());
                let (head_event_id, head_seq) = log
                    .materialized()
                    .root_chain_heads
                    .get("root-a")
                    .cloned()
                    .unwrap();
                prop_assert_eq!(head_event_id.as_str(), expected_ids.last().unwrap().as_str());
                prop_assert_eq!(head_seq, idx as u64 + 1);
            }

            let materialized_before = log.materialized().clone();
            let event_ids_before = log.event_ids();
            log.rebuild().unwrap();

            let event_ids_after = log.event_ids();
            prop_assert_eq!(event_ids_after.as_slice(), event_ids_before.as_slice());
            prop_assert_eq!(
                &log.materialized().root_chain_heads,
                &materialized_before.root_chain_heads
            );
            prop_assert_eq!(
                &log.materialized().roots_current,
                &materialized_before.roots_current
            );
            prop_assert_eq!(
                &log.materialized().devices_current,
                &materialized_before.devices_current
            );
            prop_assert_eq!(
                &log.materialized().personas_current,
                &materialized_before.personas_current
            );
        }

        #[test]
        fn generated_bad_next_events_are_rejected_without_mutating_log(
            ops in proptest::collection::vec(arb_chain_op(), 0..32),
            tamper_signature in any::<bool>(),
            bad_label in 0u8..32,
        ) {
            let mut log = MemoryEventLog::new();
            log.append(root_event(), &FixtureVerifier).unwrap();

            for (idx, op) in ops.iter().enumerate() {
                let (prev_event_id, seq) = chain_next(&log, "root-a").unwrap();
                let event = chain_step_event(idx, op, prev_event_id, seq);
                log.append(event, &FixtureVerifier).unwrap();
            }

            let before_ids = log.event_ids();
            let before_count = log.event_count();
            let before_head = log.materialized().root_chain_heads.get("root-a").cloned();
            let (prev_event_id, seq) = chain_next(&log, "root-a").unwrap();
            let mut event = chain_step_event(
                ops.len(),
                &ChainOp::Device(bad_label),
                prev_event_id,
                seq,
            );

            if tamper_signature {
                event.signature.0.push_str("tampered");
            } else {
                event.refs = vec![core_events::EventRef::previous("evt-not-the-head", seq)];
            }

            prop_assert!(log.append(event, &FixtureVerifier).is_err());
            prop_assert_eq!(log.event_count(), before_count);
            prop_assert_eq!(log.event_ids(), before_ids);
            prop_assert_eq!(
                log.materialized().root_chain_heads.get("root-a").cloned(),
                before_head
            );
        }
    }

    #[test]
    fn new_log_is_empty() {
        let log = MemoryEventLog::new();
        assert_eq!(log.event_count(), 0);
        assert!(log.events().is_empty());
        assert!(log.materialized().roots_current.is_empty());
    }

    #[test]
    fn append_and_query_events() {
        let mut log = MemoryEventLog::new();
        let (root_id, device_id, persona_id) = setup_identity(&mut log);

        assert_eq!(log.event_count(), 3);
        assert!(log.has_event(&log.events()[0].event_id));
        assert!(log.materialized().roots_current.contains_key(&root_id));
        assert!(log.materialized().devices_current.contains_key(&device_id));
        assert!(
            log.materialized()
                .personas_current
                .contains_key(&persona_id)
        );
    }

    #[test]
    fn events_of_type_filtering() {
        let mut log = MemoryEventLog::new();
        setup_identity(&mut log);

        let root_events = log.events_of_type(EventType::RootCreated);
        assert_eq!(root_events.len(), 1);

        let device_events = log.events_of_type(EventType::DeviceAdded);
        assert_eq!(device_events.len(), 1);

        let rev = log.events_of_type_rev(EventType::RootCreated);
        assert_eq!(rev.len(), 1);
        assert_eq!(rev[0].event_id, root_events[0].event_id);
    }

    #[test]
    fn export_import_roundtrip() {
        let mut log = MemoryEventLog::new();
        setup_identity(&mut log);

        let exported = log.export_events();

        let mut log2 = MemoryEventLog::new();
        let imported = log2
            .import_events(&exported, &FixtureVerifier, &AllowAllAuthorizer, 0)
            .unwrap();
        assert_eq!(imported, 3);
        assert_eq!(log2.event_count(), 3);
        assert_eq!(log2.materialized().roots_current.len(), 1);
    }

    #[test]
    fn rebuild_restores_state() {
        let mut log = MemoryEventLog::new();
        setup_identity(&mut log);

        log.rebuild().unwrap();
        assert_eq!(log.event_count(), 3);
        assert_eq!(log.materialized().roots_current.len(), 1);
        assert_eq!(log.materialized().devices_current.len(), 1);
        assert_eq!(log.materialized().personas_current.len(), 1);
    }

    #[test]
    fn peer_cursor_tracking() {
        let log = MemoryEventLog::new();
        let cursor = log.peer_cursor("peer-1").unwrap();
        assert_eq!(cursor.peer_id, "peer-1");
        assert!(cursor.last_event_id.is_none());

        let all = log.peer_cursors().unwrap();
        assert!(all.is_empty());
    }

    #[test]
    fn sync_batch_import() {
        let mut source = MemoryEventLog::new();
        setup_identity(&mut source);

        let events: Vec<EventEnvelope> = source.events().to_vec();

        let mut target = MemoryEventLog::new();
        let count = target
            .import_sync_batch(
                "peer-1",
                "batch-1",
                &events,
                Some(&events.last().unwrap().event_id),
                &FixtureVerifier,
                &AllowAllAuthorizer,
                0,
            )
            .unwrap();
        assert_eq!(count, 3);
        assert_eq!(target.event_count(), 3);

        let cursor = target.peer_cursor("peer-1").unwrap();
        assert_eq!(
            cursor.last_event_id.as_deref(),
            Some(events.last().unwrap().event_id.as_str())
        );

        let batches = target.sync_batches().unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].batch_id, "batch-1");
    }

    #[test]
    fn events_by_ids_preserves_order() {
        let mut log = MemoryEventLog::new();
        setup_identity(&mut log);

        let ids: Vec<String> = log.event_ids();
        let reversed: Vec<String> = ids.iter().rev().cloned().collect();
        let result = log.events_by_ids(&reversed);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].event_id, reversed[0]);
        assert_eq!(result[2].event_id, reversed[2]);
    }

    #[test]
    fn default_impl_works() {
        let log = MemoryEventLog::default();
        assert_eq!(log.event_count(), 0);
    }

    #[test]
    fn duplicate_sync_events_skipped() {
        let mut source = MemoryEventLog::new();
        setup_identity(&mut source);
        let events: Vec<EventEnvelope> = source.events().to_vec();

        let mut target = MemoryEventLog::new();
        target
            .import_sync_batch(
                "peer-1",
                "batch-1",
                &events,
                Some(&events.last().unwrap().event_id),
                &FixtureVerifier,
                &AllowAllAuthorizer,
                0,
            )
            .unwrap();

        // Re-import same events — should all be skipped
        let count = target
            .import_sync_batch(
                "peer-1",
                "batch-2",
                &events,
                Some(&events.last().unwrap().event_id),
                &FixtureVerifier,
                &AllowAllAuthorizer,
                0,
            )
            .unwrap();
        assert_eq!(count, 0);
        assert_eq!(target.event_count(), 3);
    }

    // ── P79.1a M-2: clamp_now caps caller-supplied now_epoch_secs ──

    #[test]
    fn clamp_now_allows_reasonable_timestamps() {
        // 2025-01-01T00:00:00Z ≈ 1_735_689_600.
        let t = 1_735_689_600_u64;
        assert_eq!(
            super::clamp_now(t),
            t,
            "reasonable timestamps pass through unchanged"
        );
        assert_eq!(super::clamp_now(0), 0);
        assert_eq!(super::clamp_now(1), 1);
    }

    #[test]
    fn clamp_now_caps_u64_max_to_ceiling() {
        // u64::MAX is well above the year-2500 ceiling — clamp must cap it.
        let clamped = super::clamp_now(u64::MAX);
        assert_eq!(clamped, super::MEMORY_LOG_NOW_CEILING);
        assert!(
            clamped < u64::MAX,
            "u64::MAX must be strictly reduced by clamp_now",
        );
    }

    #[test]
    fn clamp_now_at_ceiling_unchanged() {
        assert_eq!(
            super::clamp_now(super::MEMORY_LOG_NOW_CEILING),
            super::MEMORY_LOG_NOW_CEILING,
        );
    }

    #[test]
    fn clamp_now_above_ceiling_capped() {
        assert_eq!(
            super::clamp_now(super::MEMORY_LOG_NOW_CEILING + 1),
            super::MEMORY_LOG_NOW_CEILING,
        );
    }

    /// P79.1a M-2: Build a test key whose stored `public_key` actually equals
    /// the pubkey the FixtureSigner derives (required by the C-1 pubkey-material
    /// binding check, which IdentityAuthorizer enforces).
    fn bound_test_key(key_id: &str) -> PublicKeyMaterial {
        use core_crypto::Signer as _;
        let signer = FixtureSigner::new(key_id);
        PublicKeyMaterial {
            key_id: key_id.into(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: signer.public_key().0,
        }
    }

    #[test]
    fn append_with_u64_max_clamped_for_authorize() {
        // Build a grant offer whose `expires_at` sits just above the
        // MEMORY_LOG_NOW_CEILING. A claim attempted with `now_epoch_secs =
        // u64::MAX` would be rejected as "expired" if authorize saw the raw
        // input, but after clamping `now` becomes the ceiling, which is
        // strictly less than `expires_at` → the claim succeeds. This
        // demonstrates the clamp is in effect.
        let mut source = MemoryEventLog::new();
        // Root.
        append_typed_with_refs(
            &mut source,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: bound_test_key("key-root-a"),
            }),
            SignerBinding::root("root-a", "key-root-a"),
            Vec::new(),
        );
        // Device to satisfy setup_identity-style layout (not required).
        let (prev_id, next_seq) = chain_next(&source, "root-a").unwrap();
        append_typed_with_refs(
            &mut source,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: bound_test_key("key-device-a"),
                initial_encryption_key: test_encryption_key("device-a"),
            }),
            SignerBinding::root("root-a", "key-root-a"),
            vec![core_events::EventRef::previous(prev_id, next_seq)],
        );
        // Two personas under the root.
        let (prev_id, next_seq) = chain_next(&source, "root-a").unwrap();
        append_typed_with_refs(
            &mut source,
            "evt-persona-a",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "A".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: bound_test_key("key-persona-a"),
            }),
            SignerBinding::root("root-a", "key-root-a"),
            vec![core_events::EventRef::previous(prev_id, next_seq)],
        );
        let (prev_id, next_seq) = chain_next(&source, "root-a").unwrap();
        append_typed_with_refs(
            &mut source,
            "evt-persona-b",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-b".into(),
                label: "B".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: bound_test_key("key-persona-b"),
            }),
            SignerBinding::root("root-a", "key-root-a"),
            vec![core_events::EventRef::previous(prev_id, next_seq)],
        );
        // Grant offer with expires_at just above the ceiling.
        // GrantOfferCreated is persona-signed — root_id() returns None → chain check skipped.
        let expires_at = super::MEMORY_LOG_NOW_CEILING + 10;
        append_typed_with_refs(
            &mut source,
            "evt-offer",
            EventBody::GrantOfferCreated(core_event_types::GrantOfferCreatedEvent {
                offer_id: "offer-m2".into(),
                issuer_persona_id: "persona-a".into(),
                ephemeral_public_key_hex: "aa".into(),
                sealed_payload_hex: "bb".into(),
                relay_hint: None,
                expires_at,
                conditions_json: String::new(),
            }),
            SignerBinding::persona("persona-a", "key-persona-a"),
            Vec::new(),
        );
        // Now submit a claim signed by persona-b with now_epoch_secs =
        // u64::MAX. Before the clamp, authorize would see u64::MAX and
        // reject "grant offer has expired". After the clamp, effective_now
        // = NOW_CEILING < expires_at → accepted.
        let claim = EventEnvelope::from_body(
            "evt-claim-m2",
            EventBody::GrantOfferClaimed(core_event_types::GrantOfferClaimedEvent {
                offer_id: "offer-m2".into(),
                recipient_persona_id: "persona-b".into(),
                claim_response_hex: "cc".into(),
                claimed_at: 1,
            }),
            vec![],
            SignerBinding::persona("persona-b", "key-persona-b"),
            &FixtureSigner::new("key-persona-b"),
        )
        .unwrap();
        let result = source.append_with_authorizer(
            claim,
            &FixtureVerifier,
            &crate::IdentityAuthorizer,
            u64::MAX,
        );
        assert!(
            result.is_ok(),
            "clamped now must not mark the offer as expired: {:?}",
            result,
        );
    }
}
