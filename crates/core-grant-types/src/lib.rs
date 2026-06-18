//! core-grant-types — grant-protocol type definitions.
//!
//! CLASSIFICATION: PUBLIC
//!
//! Holds the grant-protocol type definitions: `grant_link`,
//! `grant_conditions`, `grant_receipt`, `approval`, `policy`,
//! `qr_encoding`, and the Biscuit-inspired grant chain types
//! (`Block`, `SignedBlock`, `AttestationBinding`, `Statement`,
//! `StatementId`, `Usage`, `AccessGrant`, `Budget`, `GrantMode`,
//! `GrantStatus`, `RecipientProfile`).
//!
//! Distinct from `core-grants` (Layer-3 grant *protocol logic* —
//! chain construction, scope evaluation, store). This crate carries
//! only the type definitions.
//!
//! Per ADR 156. Trust-boundary crate — CODEOWNERS protected.
//!
//! No globbed re-exports at the crate root.

pub mod approval;
pub mod capabilities;
pub mod grant_chain;
pub mod grant_conditions;
pub mod grant_link;
pub mod grant_receipt;
pub mod policy;
pub mod qr_encoding;

pub use grant_chain::{
    AccessGrant, AccessGrantDetail, AccessGrantHistoryEntry, AccessGrantSummary, Action,
    ApprovalChallenge, ApprovalMethod, AttestationBinding, AttestationStatus, Block, Budget,
    CanDelegate, Condition, GrantMode, GrantProposal, GrantStatus, PrincipalId, RecipientProfile,
    ResourceSelector, ResourceType, SignedBlock, Statement, StatementId, StatementProposal, Usage,
};

pub use grant_link::GrantLink;
pub use qr_encoding::{
    QR_MAX_ALPHANUMERIC_CHARS, QR_PREFIX, QrError, SealedOffer, decode_sealed_offer,
    encode_sealed_offer,
};
