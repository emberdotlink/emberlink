//! Atomic Receipt v2 kinds. design §"Body shape per kind".
//!
//! Each constant is the locked `kind` discriminator placed on
//! `ReceiptEnvelope.kind`. Body structs round-trip cleanly through serde_json
//! and slot into `ReceiptEnvelope.body`.

use serde::{Deserialize, Serialize};

// ===== Kind discriminator constants (locked, must NOT change) =====

pub const RECEIPT_KIND_BROKER_MINT: &str = "broker.mint";
pub const RECEIPT_KIND_KMS_ENCRYPT: &str = "kms.encrypt";
pub const RECEIPT_KIND_KMS_DECRYPT: &str = "kms.decrypt";
pub const RECEIPT_KIND_BINDING_REGISTERED: &str = "binding.registered";
pub const RECEIPT_KIND_BINDING_UPDATED: &str = "binding.updated";
pub const RECEIPT_KIND_BINDING_REVOKED: &str = "binding.revoked";
pub const RECEIPT_KIND_BINDING_DELETED: &str = "binding.deleted";
pub const RECEIPT_KIND_SEAL_UNSEALED: &str = "seal.unsealed";
pub const RECEIPT_KIND_SNAPSHOT_EMITTED: &str = "snapshot.emitted";
pub const RECEIPT_KIND_IDENTITY_ROTATED: &str = "identity.rotated";

// ===== Body structs =====

/// Body for `broker.mint` — broker minted a scoped, time-bounded credential lease.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerMintBody {
    pub vault_key: String,
    pub scope_template_id: String,
    pub scope_resolved: Vec<String>,
    pub ttl_seconds: u64,
    pub expires_at: String,
    pub revoke_token_hash: String,
}

/// Body for `kms.encrypt` and `kms.decrypt` — KMS envelope operation.
/// `operation` discriminates between the two.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KmsBody {
    pub key_id: String,
    pub operation: String, // "encrypt" or "decrypt"
    pub ciphertext_hash: String,
    pub envelope_format: String,
}

/// Body for `binding.{registered,updated,revoked,deleted}` — service-account-to-Persona binding lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BindingBody {
    pub namespace: String,
    pub sa_name: String,
    pub persona_id: String,
    pub persona_display_name: String,
    pub scopes_granted: Vec<String>,
    pub binding_request_id: String,
}

/// Body for `seal.unsealed` — sealed snapshot was opened for recovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealUnsealedBody {
    pub snapshot_id: String,
    pub unsealed_at: String,
    pub recovery_authority: String,
}

/// Body for `snapshot.emitted` — daemon emitted a periodic snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotEmittedBody {
    pub snapshot_id: String,
    pub snapshot_hash: String,
    pub emitted_at: String,
    pub content_addressed_uri: String,
}

/// Body for `identity.rotated` — daemon Persona key rotated (per design).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityRotatedBody {
    pub old_persona_id: String,
    pub new_persona_id: String,
    pub rotated_at: String,
    pub rotation_authority: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
    use crate::receipt::sign::{sign_receipt_v2, verify_receipt_v2};
    use core_crypto::{FixtureSigner, Signer};

    #[test]
    fn kind_constants_match_adr_118() {
        assert_eq!(RECEIPT_KIND_BROKER_MINT, "broker.mint");
        assert_eq!(RECEIPT_KIND_KMS_ENCRYPT, "kms.encrypt");
        assert_eq!(RECEIPT_KIND_KMS_DECRYPT, "kms.decrypt");
        assert_eq!(RECEIPT_KIND_BINDING_REGISTERED, "binding.registered");
        assert_eq!(RECEIPT_KIND_BINDING_UPDATED, "binding.updated");
        assert_eq!(RECEIPT_KIND_BINDING_REVOKED, "binding.revoked");
        assert_eq!(RECEIPT_KIND_BINDING_DELETED, "binding.deleted");
        assert_eq!(RECEIPT_KIND_SEAL_UNSEALED, "seal.unsealed");
        assert_eq!(RECEIPT_KIND_SNAPSHOT_EMITTED, "snapshot.emitted");
        assert_eq!(RECEIPT_KIND_IDENTITY_ROTATED, "identity.rotated");
    }

    #[test]
    fn broker_mint_body_round_trips() {
        let body = BrokerMintBody {
            vault_key: "anthropic-key".into(),
            scope_template_id: "tier0-default".into(),
            scope_resolved: vec!["llm:generate".into(), "credential:read".into()],
            ttl_seconds: 1800,
            expires_at: "2026-05-02T20:00:00Z".into(),
            revoke_token_hash: "blake3:abc123".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: BrokerMintBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn kms_body_round_trips() {
        let body = KmsBody {
            key_id: "kek-default".into(),
            operation: "encrypt".into(),
            ciphertext_hash: "blake3:def456".into(),
            envelope_format: "AES-256-GCM-Ed25519".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: KmsBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn binding_body_round_trips() {
        let body = BindingBody {
            namespace: "ns-prod".into(),
            sa_name: "ml-eval".into(),
            persona_id: "persona-001".into(),
            persona_display_name: "ML Eval Worker".into(),
            scopes_granted: vec!["llm:generate".into()],
            binding_request_id: "br-001".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: BindingBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn seal_unsealed_body_round_trips() {
        let body = SealUnsealedBody {
            snapshot_id: "snap-001".into(),
            unsealed_at: "2026-05-02T20:00:00Z".into(),
            recovery_authority: "operator-biometric".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: SealUnsealedBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn snapshot_emitted_body_round_trips() {
        let body = SnapshotEmittedBody {
            snapshot_id: "snap-002".into(),
            snapshot_hash: "blake3:ghi789".into(),
            emitted_at: "2026-05-02T20:00:00Z".into(),
            content_addressed_uri: "blob:tz-content/blake3/ghi789".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: SnapshotEmittedBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn identity_rotated_body_round_trips() {
        let body = IdentityRotatedBody {
            old_persona_id: "persona-old".into(),
            new_persona_id: "persona-new".into(),
            rotated_at: "2026-05-02T20:00:00Z".into(),
            rotation_authority: "scheduled-90d".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: IdentityRotatedBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn end_to_end_broker_mint_sign_verify() {
        let signer = FixtureSigner::new("receipt-v2-atomic-broker");
        let pk = signer.public_key();
        let body = BrokerMintBody {
            vault_key: "anthropic-key".into(),
            scope_template_id: "tier0-default".into(),
            scope_resolved: vec!["llm:generate".into()],
            ttl_seconds: 1800,
            expires_at: "2026-05-02T20:00:00Z".into(),
            revoke_token_hash: "blake3:abc".into(),
        };
        let mut env = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: RECEIPT_KIND_BROKER_MINT.to_string(),
            receipt_id: String::new(),
            daemon_root_id: "daemon-fixture".into(),
            traceparent: None,
            termination_authority: TerminationAuthority::UserSession,
            body: serde_json::to_value(&body).unwrap(),
            signature: None,
        };
        sign_receipt_v2(&mut env, &signer).unwrap();
        verify_receipt_v2(&env, &pk, &core_crypto::FixtureVerifier).unwrap();
    }
}
