// CLASSIFICATION: PUBLIC
//! `ember device …` CLI surfaces for enrolled-device introspection +
//! authority-set management.
//!
//! `device list` — operator-visibility inventory of enrolled presence
//! devices (ADR 200). Read-only, ConnectOnly. Ships as V030-EMBER-DEVICE-LIST.
//!
//! `device revoke` — drop an enrolled presence Device out of the operator's
//! authority set (ADR 200 §5/§6). Authority-widening per ADR 206 §1.
//! Refuses to revoke the last active presence Device (would brick widening).
//! Ships as V030-EMBER-DEVICE-REVOKE.
//!
pub mod list;
pub mod revoke;
