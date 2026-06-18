use std::collections::HashMap;

use core_crypto::Verifier;
use core_event_types::EventType;
use core_events::EventEnvelope;
use core_principals::PeerCursor;
use core_types::ValidationError;

use crate::{Authorizer, MaterializedState, SyncBatchRecord};

/// Core event log operations that any backend must support.
///
/// This trait captures the protocol-critical operations: appending events,
/// querying the event log, accessing materialized state, and sync primitives.
/// Local vault, manifest, and credential storage remain on the concrete
/// `EventStore` implementation since they are inherently storage-specific.
pub trait EventLog {
    /// Append an event without authorization checks (uses AllowAllAuthorizer).
    fn append(
        &mut self,
        event: EventEnvelope,
        verifier: &dyn Verifier,
    ) -> Result<(), ValidationError>;

    /// Append an event with authorization checks.
    fn append_with_authorizer(
        &mut self,
        event: EventEnvelope,
        verifier: &dyn Verifier,
        authorizer: &dyn Authorizer,
        now_epoch_secs: u64,
    ) -> Result<(), ValidationError>;

    /// Rebuild in-memory state from the persisted event log.
    fn rebuild(&mut self) -> Result<(), ValidationError>;

    /// Access the current materialized state derived from the event log.
    fn materialized(&self) -> &MaterializedState;

    // -- Event querying --

    /// All events in insertion order.
    fn events(&self) -> &[EventEnvelope];

    /// Number of events in the log.
    fn event_count(&self) -> usize;

    /// Check whether an event with the given ID exists.
    fn has_event(&self, event_id: &str) -> bool;

    /// Resolve the event type for a given event ID.
    fn current_event_type_for(&self, event_id: &str) -> Option<EventType>;

    /// All event IDs in insertion order.
    fn event_ids(&self) -> Vec<String>;

    /// The event ID index (event_id -> position). Avoids cloning full ID list.
    fn event_id_set(&self) -> &HashMap<String, usize>;

    /// Retrieve events by a list of IDs (preserving request order, skipping missing).
    fn events_by_ids(&self, event_ids: &[String]) -> Vec<EventEnvelope>;

    /// Iterate events of a specific type in insertion order.
    fn events_of_type(&self, event_type: EventType) -> Vec<EventEnvelope>;

    /// Iterate events of a specific type in reverse (most recent first).
    fn events_of_type_rev(&self, event_type: EventType) -> Vec<EventEnvelope>;

    // -- Import / export --

    /// Export all events as portable TSV lines.
    fn export_events(&self) -> String;

    /// Import events from portable TSV lines through the authorizer.
    fn import_events(
        &mut self,
        data: &str,
        verifier: &dyn Verifier,
        authorizer: &dyn Authorizer,
        now_epoch_secs: u64,
    ) -> Result<usize, ValidationError>;

    // -- Sync primitives --

    /// Get the sync cursor for a specific peer.
    fn peer_cursor(&self, peer_id: &str) -> Result<PeerCursor, ValidationError>;

    /// Get all peer sync cursors.
    fn peer_cursors(&self) -> Result<Vec<PeerCursor>, ValidationError>;

    /// Get all sync batch records.
    fn sync_batches(&self) -> Result<Vec<SyncBatchRecord>, ValidationError>;

    /// Import a batch of events from a sync peer.
    #[allow(clippy::too_many_arguments)]
    fn import_sync_batch(
        &mut self,
        peer_id: &str,
        batch_id: &str,
        events: &[EventEnvelope],
        last_remote_event_id: Option<&str>,
        verifier: &dyn Verifier,
        authorizer: &dyn Authorizer,
        now_epoch_secs: u64,
    ) -> Result<usize, ValidationError>;
}
