//! core-event-types — audit-log wire format.
//!
//! CLASSIFICATION: PUBLIC
//!
//! Holds the event envelope shapes (`events.rs`) and the storage
//! relationships those events refer to (`FileManifest`,
//! `StorageLedgerEntry`, `StorageRelationship`, `SurvivalMode`).
//! `events` and `storage` co-locate because they compose at the wire:
//! event records reference storage relationships directly.
//!
//! Per ADR 156.
//!
//! ADR 156 §Lock 5 forbids glob re-exports at crate roots as a god-crate
//! navigability fix. This crate is a deliberate exception: it is
//! single-concern (events + storage wire format) and exposes ~60 types
//! from its two sub-modules. Going there means going to the events
//! surface; the glob hides nothing.

pub mod action_ref;
pub mod delegation_receipt;
pub mod events;
pub mod execution_contract;
pub mod rail;
pub mod storage;

pub use action_ref::{ActionRef, ActionRefPattern, ActionSelector};
pub use delegation_receipt::PregrantPath;
pub use events::*;
pub use execution_contract::{
    AuditPolicy, ExecutionContract, InteractionClass, LeasePolicy, MaterialExposure,
    MaterializationPolicy, RevocationStrategy, RunnerClass, RunnerPolicy, TopologyPolicy,
};
pub use rail::RailTrustContract;
pub use storage::*;
