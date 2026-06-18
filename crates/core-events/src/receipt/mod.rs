//! Receipt format v2 (per ADR 118).
//!
//! Atomic + session scopes, JCS canonicalization, blake3 receipt_id,
//! Persona-signed envelopes. This module owns the SHARED type surface;
//! kind-specific bodies (e.g. session.claude_code per COHORT-A-7) live
//! in sibling modules under `receipt/`.

pub mod atomic;
pub mod body;
pub mod cohort_a;
pub mod envelope;
pub mod merkle;
pub mod sign;

pub use atomic::{
    AttenuationAxis, AttenuationSummary, AuditChainRepairFinalizeBody,
    AuditChainV1SegmentBridgeAttestedBody, AuditChainV1SegmentBridgeRefusedBody,
    AuditChainV1SegmentBridgeUnattestedBody, AuditRestoreFromDumpBody, AuthorityDelegatedBody,
    AuthorityGrantIssuedBody, AuthorityPresenceProof, BindingBody, BridgeSegmentGenesis,
    BrokerMintBody, ExecCompletionBody, HeadlessDelegatedMaterial, HeadlessEnrollmentBody,
    HeadlessRevocationBody, IdentityRotatedBody, IdentityRotationWitnessBody, KmsBody,
    LocalStateKeyResolveBody, LocalStateKeyRotationBody, PRESENCE_BASIS_INHERITED_NARROWING,
    PaymentEvaluatedBody, PaymentEvaluatedState, PaymentSettledBody, PaymentSettledState,
    PresenceBasis, ProxyCallBody, RECEIPT_KIND_AUDIT_CHAIN_REPAIR_FINALIZE,
    RECEIPT_KIND_AUDIT_CHAIN_REPAIR_TOMBSTONE, RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_ATTESTED,
    RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_REFUSED,
    RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_UNATTESTED, RECEIPT_KIND_AUDIT_RESTORE_FROM_DUMP,
    RECEIPT_KIND_AUTHORITY_DELEGATED, RECEIPT_KIND_AUTHORITY_GRANT_ISSUED,
    RECEIPT_KIND_BINDING_DELETED, RECEIPT_KIND_BINDING_REGISTERED, RECEIPT_KIND_BINDING_REVOKED,
    RECEIPT_KIND_BINDING_UPDATED, RECEIPT_KIND_BRIDGE_CERT_REFRESH_FAILED,
    RECEIPT_KIND_BRIDGE_CERT_REFRESHED, RECEIPT_KIND_BRIDGE_CERT_SUPERSEDED,
    RECEIPT_KIND_BROKER_MINT, RECEIPT_KIND_EXEC_COMPLETION, RECEIPT_KIND_HEADLESS_ENROLLMENT,
    RECEIPT_KIND_HEADLESS_REVOCATION, RECEIPT_KIND_IDENTITY_ROTATED,
    RECEIPT_KIND_IDENTITY_ROTATION_WITNESS, RECEIPT_KIND_KMS_DECRYPT, RECEIPT_KIND_KMS_ENCRYPT,
    RECEIPT_KIND_LOCAL_STATE_KEY_RESOLVE, RECEIPT_KIND_LOCAL_STATE_KEY_ROTATION,
    RECEIPT_KIND_PAYMENT_EVALUATED, RECEIPT_KIND_PAYMENT_SETTLED, RECEIPT_KIND_PROXY_CALL,
    RECEIPT_KIND_RECOVERY_ACTION, RECEIPT_KIND_SEAL_UNSEALED, RECEIPT_KIND_SERVICE_INSTALLED_V1,
    RECEIPT_KIND_SERVICE_UNINSTALLED_V1, RECEIPT_KIND_SNAPSHOT_EMITTED,
    RECEIPT_KIND_VAULT_MEK_ROTATION, RecoveryActionBody, SealUnsealedBody, ServiceInstalledBody,
    ServiceUninstalledBody, SnapshotEmittedBody, StatementProjection, VaultMekRotationBody,
};
pub use body::{
    BridgeCertRefreshFailedBody, BridgeCertRefreshTriggerReason, BridgeCertRefreshedBody,
    BridgeCertSupersededBody, ClaimEvent, ClaimKind, ClaimSegmentDigest, ReceiptBody,
};
pub use cohort_a::{
    AuditGap, ClaudeCodeBody, RECEIPT_KIND_CLAUDE_CODE, RECEIPT_KIND_COMPOSITE_GRANT,
    TerminationReason,
};
pub use envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
pub use merkle::{claim_history_merkle_root, claim_segment_digest_leaf, merkle_leaf, merkle_root};
pub use sign::{
    RECEIPT_KIND_SPAWN_WITNESS, RotationWitnessEntry, SignError, compute_receipt_id,
    sign_receipt_v2, sign_spawn_witness_parent_signature, spawn_witness_canonical_bytes_for_parent,
    verify_receipt_v2, verify_receipt_v2_with_rotation_chain,
    verify_spawn_witness_parent_signature,
};
