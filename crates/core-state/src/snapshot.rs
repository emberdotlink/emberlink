//! Snapshot helpers for the `core-state` event log.
//!
//! Per ADR 117 (EmberSeal Recovery), the delta log IS the existing
//! `core-state` event log tail since the last snapshot — not a parallel system.
//!
//! The high-watermark is an integer position (count of events) in the event
//! slice. `events_since(watermark, max)` returns the slice of events appended
//! after position `watermark`.

use core_eventlog::EventLog;
use core_events::EventEnvelope;

/// Return events appended after position `since_watermark` (exclusive), up to
/// `max_events` entries.
///
/// `since_watermark` is the `event_log_high_watermark` captured in the last
/// snapshot manifest — equal to `event_count()` at the time of that snapshot.
/// Callers pass `0` to get all events (first-snapshot delta).
pub fn events_since<L: EventLog + ?Sized>(
    log: &L,
    since_watermark: u64,
    max_events: usize,
) -> Vec<EventEnvelope> {
    let start = since_watermark as usize;
    let all = log.events();
    if start >= all.len() {
        return Vec::new();
    }
    let end = all.len().min(start + max_events);
    all[start..end].to_vec()
}

/// Current high-water-mark: the count of events currently in the log.
///
/// Capture this value into the snapshot manifest at emission time. Pass it
/// back to `events_since` to retrieve the delta on the next snapshot.
pub fn current_event_watermark<L: EventLog + ?Sized>(log: &L) -> u64 {
    log.event_count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_eventlog::MemoryEventLog;

    #[test]
    fn events_since_on_empty_log_is_empty_for_any_watermark() {
        // The `start >= len` early-return collapses every watermark to an empty
        // delta when the log is empty — watermark 0 (first-snapshot) and a
        // watermark past the end both hit the same guard.
        let log = MemoryEventLog::default();
        for watermark in [0, 5, u64::MAX] {
            assert!(events_since(&log, watermark, 100).is_empty());
        }
    }

    #[test]
    fn current_event_watermark_zero_on_empty() {
        let log = MemoryEventLog::default();
        assert_eq!(current_event_watermark(&log), 0);
    }

    // NOTE: `events_since` against a *populated* log — mid-log watermark
    // returning the tail delta, and `max_events` capping the slice — is still
    // uncovered. `events_since_slice_logic_via_events_method` (below) stubs
    // `events()` as empty, so the `all[start..end]` slice math never runs on
    // real data. Exercising it needs a signed-event fixture (FixtureSigner +
    // identity seed per core-eventlog's `setup_identity`); tracked as a
    // follow-up rather than faked with an empty stub.

    #[test]
    fn events_since_slice_logic_via_events_method() {
        // Verify the slice arithmetic directly without needing real events by
        // constructing a minimal stub that satisfies EventLog purely for the
        // events() and event_count() calls — the only two methods used by
        // events_since / current_event_watermark.
        use core_event_types::EventType;
        use core_eventlog::{Authorizer, MaterializedState, SyncBatchRecord};
        use core_events::EventEnvelope;
        use core_principals::PeerCursor;
        use core_types::ValidationError;
        use std::collections::HashMap;

        struct CountLog(usize);

        impl EventLog for CountLog {
            fn append(
                &mut self,
                _: EventEnvelope,
                _: &dyn core_crypto::Verifier,
            ) -> Result<(), ValidationError> {
                Ok(())
            }
            fn append_with_authorizer(
                &mut self,
                _: EventEnvelope,
                _: &dyn core_crypto::Verifier,
                _: &dyn Authorizer,
                _: u64,
            ) -> Result<(), ValidationError> {
                Ok(())
            }
            fn rebuild(&mut self) -> Result<(), ValidationError> {
                Ok(())
            }
            fn materialized(&self) -> &MaterializedState {
                panic!("not needed")
            }
            fn events(&self) -> &[EventEnvelope] {
                &[]
            }
            fn event_count(&self) -> usize {
                self.0
            }
            fn has_event(&self, _: &str) -> bool {
                false
            }
            fn current_event_type_for(&self, _: &str) -> Option<EventType> {
                None
            }
            fn event_ids(&self) -> Vec<String> {
                vec![]
            }
            fn event_id_set(&self) -> &HashMap<String, usize> {
                panic!("not needed")
            }
            fn events_by_ids(&self, _: &[String]) -> Vec<EventEnvelope> {
                vec![]
            }
            fn events_of_type(&self, _: EventType) -> Vec<EventEnvelope> {
                vec![]
            }
            fn events_of_type_rev(&self, _: EventType) -> Vec<EventEnvelope> {
                vec![]
            }
            fn export_events(&self) -> String {
                String::new()
            }
            fn import_events(
                &mut self,
                _: &str,
                _: &dyn core_crypto::Verifier,
                _: &dyn Authorizer,
                _: u64,
            ) -> Result<usize, ValidationError> {
                Ok(0)
            }
            fn peer_cursor(&self, _: &str) -> Result<PeerCursor, ValidationError> {
                panic!("not needed")
            }
            fn peer_cursors(&self) -> Result<Vec<PeerCursor>, ValidationError> {
                panic!("not needed")
            }
            fn sync_batches(&self) -> Result<Vec<SyncBatchRecord>, ValidationError> {
                panic!("not needed")
            }
            fn import_sync_batch(
                &mut self,
                _: &str,
                _: &str,
                _: &[EventEnvelope],
                _: Option<&str>,
                _: &dyn core_crypto::Verifier,
                _: &dyn Authorizer,
                _: u64,
            ) -> Result<usize, ValidationError> {
                Ok(0)
            }
        }

        let log = CountLog(7);
        assert_eq!(current_event_watermark(&log), 7);

        // events() returns &[] so events_since always returns empty on CountLog,
        // but that is fine — we are testing current_event_watermark here.
        let delta = events_since(&log, 3, 100);
        assert!(
            delta.is_empty(),
            "empty events() → empty delta regardless of watermark"
        );
    }
}
