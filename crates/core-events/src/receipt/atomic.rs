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
/// implementation-note-42 —
/// co-signed attestation that bridges between identity-key epochs at
/// MEK rotation time. Per design Receipt v2 chain-continuity rule +
/// design catalog discipline. Anchor:
/// `identity_rotation_witness_body_landed`.
pub const RECEIPT_KIND_IDENTITY_ROTATION_WITNESS: &str = "identity.rotation_witness";
pub const RECEIPT_KIND_LOCAL_STATE_KEY_RESOLVE: &str = "local_state.key_resolve";
pub const RECEIPT_KIND_LOCAL_STATE_KEY_ROTATION: &str = "local_state.key_rotation";
/// implementation-note-43 — emberd emits this kind on every
/// `ExecFrame::Exit` arriving from the in-container `ember-exec`
/// sidecar. The body shape ([`ExecCompletionBody`]) carries the seven
/// fields design §"Body shape per kind" pins for the in-container
/// exec audit trail: `persona_id`, `grant_id`, `binary_path`,
/// `binary_blake3`, `target_uid`, `exit_code`, `materialized_at`.
pub const RECEIPT_KIND_EXEC_COMPLETION: &str = "exec.completion";

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

/// Body for `identity.rotation_witness` — co-signed attestation that
/// bridges between identity-key epochs at MEK rotation time. Per
/// design Receipt v2 chain-continuity rule + design catalog
/// discipline.
///
/// Anchor: `identity_rotation_witness_body_landed`.
///
/// **Pre:** `prev_epoch_root_id != next_epoch_root_id` — the bridge
/// must connect distinct epochs; an identity-rotation witness would
/// defeat the chain-continuity purpose.
///
/// **Pre:** `signature_by_prev_root` non-empty AND
/// `signature_by_next_root` non-empty — co-signature is required to
/// bind both epochs; a one-sided witness cannot bridge.
///
/// **Post:** round-trips through JCS canonicalization → blake3
/// receipt-id derivation → serde deserialization preserving all
/// fields byte-for-byte (verified by T1 property test).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityRotationWitnessBody {
    /// Identity-root ID prior to the rotation.
    pub prev_epoch_root_id: String,
    /// Identity-root ID after the rotation.
    pub next_epoch_root_id: String,
    /// Timestamp of the rotation (epoch seconds, UTC).
    pub rotated_at_epoch_secs: u64,
    /// Signature over the rotation by the *previous* epoch root key.
    pub signature_by_prev_root: String,
    /// Signature over the rotation by the *next* epoch root key.
    pub signature_by_next_root: String,
    /// Optional human-readable rotation reason (e.g., `"scheduled"`,
    /// `"key-compromise"`, `"operator-init"`).
    pub rotation_reason: Option<String>,
}

impl IdentityRotationWitnessBody {
    /// Validate the body's `Pre:` invariants documented on the struct.
    ///
    /// Returns `Ok(())` when:
    /// - `prev_epoch_root_id != next_epoch_root_id`
    /// - `signature_by_prev_root` is non-empty
    /// - `signature_by_next_root` is non-empty
    ///
    /// Returns `Err(&'static str)` naming the violated invariant
    /// otherwise. The error strings are stable and may be matched in
    /// tests.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.prev_epoch_root_id == self.next_epoch_root_id {
            return Err("prev_epoch_root_id must differ from next_epoch_root_id");
        }
        if self.signature_by_prev_root.is_empty() {
            return Err("signature_by_prev_root must be non-empty");
        }
        if self.signature_by_next_root.is_empty() {
            return Err("signature_by_next_root must be non-empty");
        }
        Ok(())
    }
}

/// Body for `local_state.key_resolve` — daemon vended the per-caller
/// local-state content key. Emitted per `daemon-sole-keychain-client`
/// proposal §"Three new daemon socket methods" + design separate-uid
/// authorization substrate.
///
/// `resolved_or_generated` discriminates whether the key was already in
/// the daemon vault (`"resolved"`) or generated fresh on this call
/// (`"generated"`). The latter signals a first-touch or migration boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalStateKeyResolveBody {
    pub peer_uid: u32,
    pub caller: String,
    pub vault_namespace: String,
    pub resolved_or_generated: String,
}

/// Body for `local_state.key_rotation` — daemon-side atomic rotation of
/// a per-caller local-state content key. `old_key_hash` / `new_key_hash`
/// are blake3 hashes of the key material (never the keys themselves).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalStateKeyRotationBody {
    pub peer_uid: u32,
    pub caller: String,
    pub vault_namespace: String,
    pub old_key_hash: String,
    pub new_key_hash: String,
}

/// Body for `exec.completion` — emberd-side Receipt v2 emission on every
/// `ExecFrame::Exit` arriving from the in-container `ember-exec` sidecar.
///
/// Per implementation-note-43 and the parent
/// implementation-note-44 acceptance — emberd (not ember-exec) is
/// the receipt signer; the in-container sidecar reports the child's
/// exit code over the UDS frame protocol, and emberd composes the
/// signed v2 envelope.
///
/// Field provenance:
///
/// - `persona_id` — the persona under which `broker.resolve` issued the
///   spawn handle (the caller persona that authorised this exec).
/// - `grant_id` — the standing parent grant that authorised the exec.
/// - `binary_path` — absolute path inside the container of the binary
///   that was just executed.
/// - `binary_blake3` — the hex-encoded blake3 content hash emberd
///   verified BEFORE sending the `SpawnDirective` to the in-container
///   sidecar. Recorded as the receipt's authoritative hash so audit
///   chains preserve "the bytes the daemon actually approved", not a
///   recomputation by an untrusted post-execve verifier.
/// - `target_uid` — the unprivileged uid the in-container sidecar
///   dropped to before `execve` (subtask B's `drop_privileges`).
/// - `exit_code` — the child's exit status as reported by
///   `ExecFrame::Exit { code }`.
/// - `materialized_at` — RFC3339 wall-clock at which emberd composed
///   the receipt (i.e. when the Exit frame arrived, NOT the in-container
///   child's own clock — ember-exec is not a trust root for time).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecCompletionBody {
    pub persona_id: String,
    pub grant_id: String,
    pub binary_path: String,
    pub binary_blake3: String,
    pub target_uid: u32,
    pub exit_code: i32,
    pub materialized_at: String,
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
        assert_eq!(
            RECEIPT_KIND_LOCAL_STATE_KEY_RESOLVE,
            "local_state.key_resolve"
        );
        assert_eq!(
            RECEIPT_KIND_LOCAL_STATE_KEY_ROTATION,
            "local_state.key_rotation"
        );
        assert_eq!(RECEIPT_KIND_EXEC_COMPLETION, "exec.completion");
        assert_eq!(
            RECEIPT_KIND_IDENTITY_ROTATION_WITNESS,
            "identity.rotation_witness"
        );
    }

    #[test]
    fn exec_completion_body_round_trips() {
        let body = ExecCompletionBody {
            persona_id: "11111111-1111-1111-1111-111111111111".into(),
            grant_id: "22222222-2222-2222-2222-222222222222".into(),
            binary_path: "/usr/local/bin/scion-test-binary".into(),
            binary_blake3: "deadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00d"
                .into(),
            target_uid: 1234,
            exit_code: 0,
            materialized_at: "2026-05-12T18:00:00Z".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: ExecCompletionBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn local_state_key_resolve_body_round_trips() {
        let body = LocalStateKeyResolveBody {
            peer_uid: 501,
            caller: "cli".into(),
            vault_namespace: "local-state/cli".into(),
            resolved_or_generated: "generated".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: LocalStateKeyResolveBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn local_state_key_rotation_body_round_trips() {
        let body = LocalStateKeyRotationBody {
            peer_uid: 501,
            caller: "gui".into(),
            vault_namespace: "local-state/gui".into(),
            old_key_hash: "blake3:olddead".into(),
            new_key_hash: "blake3:newbeef".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: LocalStateKeyRotationBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
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
            presence_kind: None,
            body: serde_json::to_value(&body).unwrap(),
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut env, &signer).unwrap();
        verify_receipt_v2(&env, &pk, &core_crypto::FixtureVerifier).unwrap();
    }

    #[test]
    fn identity_rotation_witness_body_round_trips() {
        let body = IdentityRotationWitnessBody {
            prev_epoch_root_id: "persona-epoch-old".into(),
            next_epoch_root_id: "persona-epoch-new".into(),
            rotated_at_epoch_secs: 1_715_000_000,
            signature_by_prev_root: "ed25519sig:abcdef".into(),
            signature_by_next_root: "ed25519sig:fedcba".into(),
            rotation_reason: Some("scheduled".into()),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: IdentityRotationWitnessBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn identity_rotation_witness_rejects_same_epoch_ids() {
        let body = IdentityRotationWitnessBody {
            prev_epoch_root_id: "persona-epoch-same".into(),
            next_epoch_root_id: "persona-epoch-same".into(),
            rotated_at_epoch_secs: 1_715_000_000,
            signature_by_prev_root: "ed25519sig:abc".into(),
            signature_by_next_root: "ed25519sig:def".into(),
            rotation_reason: None,
        };
        let err = body
            .validate()
            .expect_err("identity rotation between equal epoch ids must be rejected");
        assert!(
            err.contains("prev_epoch_root_id"),
            "error must name the violated invariant; got {err}"
        );
    }

    #[test]
    fn identity_rotation_witness_rejects_empty_prev_signature() {
        let body = IdentityRotationWitnessBody {
            prev_epoch_root_id: "persona-epoch-old".into(),
            next_epoch_root_id: "persona-epoch-new".into(),
            rotated_at_epoch_secs: 1_715_000_000,
            signature_by_prev_root: String::new(),
            signature_by_next_root: "ed25519sig:def".into(),
            rotation_reason: None,
        };
        let err = body
            .validate()
            .expect_err("empty signature_by_prev_root must be rejected");
        assert!(
            err.contains("signature_by_prev_root"),
            "error must name the violated invariant; got {err}"
        );
    }

    #[test]
    fn identity_rotation_witness_rejects_empty_next_signature() {
        let body = IdentityRotationWitnessBody {
            prev_epoch_root_id: "persona-epoch-old".into(),
            next_epoch_root_id: "persona-epoch-new".into(),
            rotated_at_epoch_secs: 1_715_000_000,
            signature_by_prev_root: "ed25519sig:abc".into(),
            signature_by_next_root: String::new(),
            rotation_reason: None,
        };
        let err = body
            .validate()
            .expect_err("empty signature_by_next_root must be rejected");
        assert!(
            err.contains("signature_by_next_root"),
            "error must name the violated invariant; got {err}"
        );
    }
}

#[cfg(test)]
mod proptests {
    //! T1 property tests for `IdentityRotationWitnessBody`.
    //!
    //! Per `.claude/rules/test-tiers.md` — every new body shape on a
    //! `core-*` crate ships at least one T1 property test that
    //! exercises the documented Pre/Post conditions. Here the Post
    //! contract is "JCS canonicalize → serde round-trip preserves all
    //! fields"; the Pre contract is validated by the
    //! `validate_round_trip_witness_passes_validate` property.
    //!
    //! Anchor: `identity_rotation_witness_body_landed`.
    use super::*;
    use core_crypto::canonicalize_jcs;
    use proptest::prelude::*;

    fn arb_witness() -> impl Strategy<Value = IdentityRotationWitnessBody> {
        // Generate distinct prev/next epoch ids so the body is valid;
        // negative cases are covered by the unit tests above.
        (
            "[a-z0-9-]{1,32}",
            "[a-z0-9-]{1,32}",
            any::<u64>(),
            "ed25519sig:[a-f0-9]{2,64}",
            "ed25519sig:[a-f0-9]{2,64}",
            prop::option::of("[a-z_-]{1,32}"),
        )
            .prop_filter("prev/next epoch ids must differ", |t| t.0 != t.1)
            .prop_map(|(prev, next, ts, sig_p, sig_n, reason)| {
                IdentityRotationWitnessBody {
                    prev_epoch_root_id: prev,
                    next_epoch_root_id: next,
                    rotated_at_epoch_secs: ts,
                    signature_by_prev_root: sig_p,
                    signature_by_next_root: sig_n,
                    rotation_reason: reason,
                }
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Post-condition: JCS canonicalization is stable across the
        /// serde round-trip. Encoding the body, deserializing the JSON
        /// form, and re-encoding must produce byte-identical JCS
        /// output. Drift here invalidates persisted receipt-ids.
        #[test]
        fn jcs_round_trip_is_stable(body in arb_witness()) {
            let v1 = serde_json::to_value(&body).expect("serialize");
            let jcs1 = canonicalize_jcs(&v1).expect("jcs1");
            let back: IdentityRotationWitnessBody =
                serde_json::from_value(v1).expect("deserialize");
            prop_assert_eq!(&body, &back);
            let v2 = serde_json::to_value(&back).expect("re-serialize");
            let jcs2 = canonicalize_jcs(&v2).expect("jcs2");
            prop_assert_eq!(jcs1, jcs2);
        }

        /// Pre-condition: every body produced by the arb_witness
        /// generator satisfies `validate()`. This pins the generator
        /// to the valid region so the round-trip property does not
        /// accidentally exercise invariant-violating inputs.
        #[test]
        fn arb_witness_passes_validate(body in arb_witness()) {
            prop_assert!(body.validate().is_ok());
        }
    }
}
