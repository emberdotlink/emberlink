//! core-event-types — audit-log wire format.
//!
//!
//! Holds the event envelope shapes (`events.rs`) and the storage
//! relationships those events refer to (`FileManifest`,
//! `StorageLedgerEntry`, `StorageRelationship`, `SurvivalMode`).
//! `events` and `storage` co-locate because they compose at the wire:
//! event records reference storage relationships directly.
//!
//! Per design.
//!
//! design §Lock 5 forbids glob re-exports at crate roots as a god-crate
//! navigability fix. This crate is a deliberate exception: it is
//! single-concern (events + storage wire format) and exposes ~60 types
//! from its two sub-modules. Going there means going to the events
//! surface; the glob hides nothing.

pub mod events;
pub mod storage;

pub use events::*;
pub use storage::*;
