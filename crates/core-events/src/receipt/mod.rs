//! Receipt format v2 (per design).
//!
//! Atomic + session scopes, JCS canonicalization, blake3 receipt_id,
//! Persona-signed envelopes. This module owns the SHARED type surface;
//! kind-specific bodies (e.g. session.claude_code per implementation-note-47) live
//! in sibling modules under `receipt/`.

pub mod atomic;
pub mod body;
pub mod cohort_a;
pub mod envelope;
pub mod merkle;
pub mod sign;

pub use atomic::{
    AuditChainRepairFinalizeBody, AuditChainV1SegmentBridgeUnattestedBody, BindingBody,
    BridgeSegmentGenesis, BrokerMintBody, ExecCompletionBody, IdentityRotatedBody,
    IdentityRotationWitnessBody, KmsBody, LocalStateKeyResolveBody, LocalStateKeyRotationBody,
    RECEIPT_KIND_AUDIT_CHAIN_REPAIR_FINALIZE, RECEIPT_KIND_AUDIT_CHAIN_REPAIR_TOMBSTONE,
    RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_UNATTESTED, RECEIPT_KIND_BINDING_DELETED,
    RECEIPT_KIND_BINDING_REGISTERED, RECEIPT_KIND_BINDING_REVOKED, RECEIPT_KIND_BINDING_UPDATED,
    RECEIPT_KIND_BROKER_MINT, RECEIPT_KIND_EXEC_COMPLETION, RECEIPT_KIND_IDENTITY_ROTATED,
    RECEIPT_KIND_IDENTITY_ROTATION_WITNESS, RECEIPT_KIND_KMS_DECRYPT, RECEIPT_KIND_KMS_ENCRYPT,
    RECEIPT_KIND_LOCAL_STATE_KEY_RESOLVE, RECEIPT_KIND_LOCAL_STATE_KEY_ROTATION,
    RECEIPT_KIND_SEAL_UNSEALED, RECEIPT_KIND_SNAPSHOT_EMITTED, SealUnsealedBody,
    SnapshotEmittedBody,
};
pub use body::{ClaimEvent, ClaimKind, ClaimSegmentDigest, ReceiptBody};
pub use cohort_a::{
    AuditGap, ClaudeCodeBody, RECEIPT_KIND_CLAUDE_CODE, RECEIPT_KIND_COMPOSITE_GRANT,
    TerminationReason,
};
pub use envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
pub use merkle::{claim_history_merkle_root, claim_segment_digest_leaf, merkle_leaf, merkle_root};
pub use sign::{
    RECEIPT_KIND_SPAWN_WITNESS, RotationWitnessEntry, SignError, compute_receipt_id,
    sign_receipt_v2, sign_spawn_witness_parent_signature,
    spawn_witness_canonical_bytes_for_parent, verify_receipt_v2,
    verify_receipt_v2_with_rotation_chain, verify_spawn_witness_parent_signature,
};
