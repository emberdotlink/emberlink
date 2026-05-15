//!
//! `ember audit ...` CLI subcommands. The receipt-query path lives in
//! `bin/ember.rs::AuditAction::{Show, Export, Explain, Query}` against a
//! direct `DaemonStore::open` — those are read-only operations that the
//! CLI can perform without involving the running daemon. The chain
//! verify path (this module's `verify`) is different: it routes through
//! the daemon's `audit_verify` socket method so the operator gets the
//! authoritative answer from the trust authority that owns the chain.

pub mod verify;
