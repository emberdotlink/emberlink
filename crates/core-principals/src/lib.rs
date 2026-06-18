//! core-principals — identity primitive type definitions.
//!
//! CLASSIFICATION: PUBLIC
//!
//! Holds the type definitions for the actor layer: persona, identity,
//! recovery, trust, credential-delivery, network endpoints, and the
//! key/trust type tags (`KeyAlgorithm`, `PublicKeyMaterial`,
//! `TrustThreshold`).
//!
//! Distinct from the Layer-3 crates `core-identity` / `core-personas`
//! / `core-trust` — those carry *operations on* these types; this
//! crate carries the type definitions themselves.
//!
//! Name aligns with the `PrincipalId` vocabulary used in
//! `Grant.issuer`. Per ADR 156.
//!
//! ADR 156 §Lock 5 forbids glob re-exports at crate roots as a god-crate
//! navigability fix. Single-concern crate exception (same logic as
//! core-event-types): the actor-types surface IS this crate.

pub mod credential_delivery;
pub mod identity;
pub mod network;
pub mod parse;
pub mod persona;
pub mod recovery;
pub mod trust;

pub use credential_delivery::*;
pub use identity::*;
pub use network::*;
pub use parse::parse_public_key_material;
pub use persona::*;
pub use recovery::*;
pub use trust::*;
