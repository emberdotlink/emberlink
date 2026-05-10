//! Receipt format v2 (per design).
//!
//! Atomic + session scopes, JCS canonicalization, blake3 receipt_id,
//! Persona-signed envelopes. This module owns the SHARED type surface;
//! kind-specific bodies (e.g. session.claude_code per implementation-note-12) live
//! in sibling modules under `receipt/`.

pub mod atomic;
pub mod envelope;
pub mod body;
pub mod cohort_a;
pub mod merkle;
pub mod sign;

pub use atomic::{
    BindingBody, BrokerMintBody, IdentityRotatedBody, KmsBody, SealUnsealedBody,
    SnapshotEmittedBody, RECEIPT_KIND_BINDING_DELETED, RECEIPT_KIND_BINDING_REGISTERED,
    RECEIPT_KIND_BINDING_REVOKED, RECEIPT_KIND_BINDING_UPDATED, RECEIPT_KIND_BROKER_MINT,
    RECEIPT_KIND_IDENTITY_ROTATED, RECEIPT_KIND_KMS_DECRYPT, RECEIPT_KIND_KMS_ENCRYPT,
    RECEIPT_KIND_SEAL_UNSEALED, RECEIPT_KIND_SNAPSHOT_EMITTED,
};
pub use envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
pub use body::{ClaimEvent, ClaimKind, ReceiptBody};
pub use cohort_a::{
    AuditGap, ClaudeCodeBody, RECEIPT_KIND_CLAUDE_CODE, TerminationReason,
};
pub use merkle::{merkle_leaf, merkle_root};
pub use sign::{SignError, compute_receipt_id, sign_receipt_v2, verify_receipt_v2};
