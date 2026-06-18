//! `core-receipts` — receipt v2 surface for verify dispatch + redaction +
//! tool registry (TZ-RECEIPT-V2-CLI).
//!
//! This crate is the home for *behavior* applied to receipts:
//!
//! - [`redaction`] — scrub secrets from a receipt JSON before export.
//! - [`tool_registry`] — table of known ember-X tools used to validate
//!   tool references in v2 receipts.
//! - [`ReceiptV2`] + [`verify_v2`] — the v2 receipt struct used by
//!   `ember receipt verify` to route based on the on-disk `version` field.
//! - [`SpawnWitness`] — body shape for `spawn.witness` Receipt v2 kind
//!   (SCION-RECEIPT-V2-SPAWN-WITNESS, CRIT-7): the parent-persona dual
//!   signature that binds a spawned persona to its parent's authorization.
//!
//! v1 (`core_grant_types::grant_receipt::GrantReceipt`) is preserved for
//! back-compat; this crate does not re-export it.

pub mod redaction;
pub mod tool_registry;

use serde::{Deserialize, Serialize};
use tool_registry::ToolRegistry;

/// Locked `kind` discriminator for `spawn.witness` Receipt v2 envelopes.
/// Placed on `ReceiptEnvelope.kind` per ADR 118 §"Envelope".
pub const RECEIPT_KIND_SPAWN_WITNESS: &str = "spawn.witness";

/// Locked at `2`. Receipts with a different `version` field must NOT be
/// accepted by [`verify_v2`].
pub const RECEIPT_VERSION_V2: u32 = 2;

/// Receipt v2 — same shape as v1 but with an explicit `version` field and a
/// `redactions_applied` flag indicating whether the receipt has been scrubbed
/// for export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptV2 {
    /// Schema version. Must be [`RECEIPT_VERSION_V2`].
    pub version: u32,
    /// Receipt id, e.g. `rct_abc123`.
    pub id: String,
    /// Grant id this receipt corresponds to.
    pub grant_id: String,
    /// Tool id used during the session, looked up against [`ToolRegistry`].
    pub tool_id: String,
    /// Whether redaction rules have been applied to this receipt body.
    pub redactions_applied: bool,
    /// Body — opaque JSON; v2 leaves the per-kind body shape to the verifier.
    pub body: serde_json::Value,
}

impl ReceiptV2 {
    /// Construct a fresh receipt with `version` pinned to v2 and no redactions
    /// applied yet.
    pub fn new(
        id: impl Into<String>,
        grant_id: impl Into<String>,
        tool_id: impl Into<String>,
    ) -> Self {
        Self {
            version: RECEIPT_VERSION_V2,
            id: id.into(),
            grant_id: grant_id.into(),
            tool_id: tool_id.into(),
            redactions_applied: false,
            body: serde_json::Value::Null,
        }
    }
}

/// Body for `spawn.witness` Receipt v2 kind (SCION-RECEIPT-V2-SPAWN-WITNESS).
///
/// Binds a spawned persona to its parent's authorization: the parent persona
/// signs `JCS(body)` with `parent_signature` excluded, then the issuer
/// (typically `emberd`) signs the outer Receipt envelope per ADR 118.
///
/// **CRIT-7 mitigation:** without `parent_signature`, an `emberd` impersonator
/// could forge a fresh `spawned_persona_id` and present it as legitimate. The
/// dual-signature binding requires the parent to have authorized the spawn,
/// preventing unilateral persona fabrication.
///
/// **bridge_ca_fingerprint_in_spawn_receipt** — Slice C (ADR 154 component 3,
/// META-AP-DAEMON-BRIDGE-CA-SE-SEALED-C-RECEIPT-FINGERPRINT): the
/// [`Self::ca_fingerprint`] field binds the spawn to the daemon's
/// SE-sealed Bridge CA (blake3-256 of the CA verifying-key bytes). Slice D
/// compares the connecting client cert's issuer fingerprint against the
/// fingerprint embedded in the corresponding spawn receipt; a mismatch raises
/// `bridge.ca_fingerprint_mismatch`. The field is appended at the END of the
/// struct with `#[serde(default)]` so pre-Slice-C receipts on disk
/// deserialize with a zeroed fingerprint (Slice D treats `[0u8; 32]` as
/// "fingerprint not asserted" and falls back to legacy verification).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpawnWitness {
    /// Persona id created by `emberd` for the spawned child.
    pub spawned_persona_id: String,
    /// Persona id of the parent that requested the spawn.
    pub parent_persona_id: String,
    /// Docker / SCION container id hosting the spawned persona.
    pub container_id: String,
    /// Grant id authorizing the spawn operation.
    pub spawn_grant_id: String,
    /// Ed25519 signature by the parent persona over JCS of this body with
    /// `parent_signature` excluded. Wire form: `ed25519sig:<hex>` (matches
    /// `core_crypto::Signature`'s canonical representation).
    pub parent_signature: String,
    /// Bridge-CA fingerprint (blake3-256 of the daemon's Bridge CA verifying
    /// key SPKI bytes). Appended at the END of the struct with
    /// `#[serde(default)]` so pre-Slice-C receipts deserialize with a zeroed
    /// fingerprint. `[0u8; 32]` is the checkpoint for "fingerprint not
    /// asserted" — Slice D's verification path treats that as "skip the
    /// fingerprint comparison" rather than rejecting the receipt outright.
    /// See ADR 154 component 3 / META-AP-DAEMON-BRIDGE-CA-SE-SEALED-C.
    #[serde(default)]
    pub ca_fingerprint: [u8; 32],
}

impl SpawnWitness {
    /// Construct a fresh `SpawnWitness` with `parent_signature` empty.
    ///
    /// Use [`canonical_bytes_for_parent_signature`] to obtain the bytes the
    /// parent must sign, then populate `parent_signature` before placing this
    /// body on a `ReceiptEnvelope`.
    pub fn new(
        spawned_persona_id: impl Into<String>,
        parent_persona_id: impl Into<String>,
        container_id: impl Into<String>,
        spawn_grant_id: impl Into<String>,
    ) -> Self {
        Self {
            spawned_persona_id: spawned_persona_id.into(),
            parent_persona_id: parent_persona_id.into(),
            container_id: container_id.into(),
            spawn_grant_id: spawn_grant_id.into(),
            parent_signature: String::new(),
            ca_fingerprint: [0u8; 32],
        }
    }

    /// Builder-style setter for the Bridge-CA fingerprint. Callers that
    /// know the daemon's Bridge CA fingerprint (i.e. the daemon spawn
    /// emission path on `emit_spawn_witness_receipt`) chain this onto
    /// [`Self::new`] before computing the parent signature so the parent
    /// attests to the CA binding alongside the persona/container/grant
    /// fields. Pre-Slice-C callers that have no fingerprint to bind leave
    /// the field at its `[0u8; 32]` default — Slice D treats that checkpoint
    /// as "fingerprint not asserted". See `bridge_ca_fingerprint_in_spawn_receipt`.
    pub fn with_ca_fingerprint(mut self, ca_fingerprint: [u8; 32]) -> Self {
        self.ca_fingerprint = ca_fingerprint;
        self
    }

    /// Return the JSON representation of this body with `parent_signature`
    /// removed. Pair with `core_crypto::canonicalize_jcs` to produce the
    /// exact bytes the parent persona must Ed25519-sign.
    ///
    /// **Pre:** `parent_signature` may be empty or populated — either way it
    /// is excluded from the returned value.
    /// **Post:** the returned `serde_json::Value` is an Object with exactly
    /// the four non-signature fields.
    pub fn body_for_parent_signature(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).expect("SpawnWitness serializes to Value");
        if let serde_json::Value::Object(map) = &mut v {
            map.remove("parent_signature");
        }
        v
    }
}

/// Verification outcome from [`verify_v2`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Receipt passed all v2 invariants.
    Ok,
    /// Receipt's `version` field is not [`RECEIPT_VERSION_V2`].
    VersionMismatch { found: u32, expected: u32 },
    /// `tool_id` does not appear in the supplied [`ToolRegistry`].
    UnknownTool { tool_id: String },
}

impl VerifyResult {
    /// `true` iff the receipt verified cleanly.
    pub fn is_ok(&self) -> bool {
        matches!(self, VerifyResult::Ok)
    }
}

/// Validate a [`ReceiptV2`] against the tool registry.
///
/// Pre: `receipt.version == 2`. Post: returns [`VerifyResult::Ok`] iff
/// `tool_id` is registered AND `version` is exactly `2`. Errors are reported
/// as variants of [`VerifyResult`] rather than `Result` so the CLI can format
/// each kind distinctly.
pub fn verify_v2(receipt: &ReceiptV2, registry: &ToolRegistry) -> VerifyResult {
    if receipt.version != RECEIPT_VERSION_V2 {
        return VerifyResult::VersionMismatch {
            found: receipt.version,
            expected: RECEIPT_VERSION_V2,
        };
    }
    if registry.lookup(&receipt.tool_id).is_none() {
        return VerifyResult::UnknownTool {
            tool_id: receipt.tool_id.clone(),
        };
    }
    VerifyResult::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verify_v2_happy_path() {
        let r = ReceiptV2::new("rct_1", "grt_1", "ember-aws");
        let registry = ToolRegistry::new_default();
        assert_eq!(verify_v2(&r, &registry), VerifyResult::Ok);
    }

    #[test]
    fn verify_v2_rejects_version_mismatch() {
        let mut r = ReceiptV2::new("rct_1", "grt_1", "ember-aws");
        r.version = 1;
        let registry = ToolRegistry::new_default();
        match verify_v2(&r, &registry) {
            VerifyResult::VersionMismatch { found, expected } => {
                assert_eq!(found, 1);
                assert_eq!(expected, 2);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_v2_rejects_unknown_tool() {
        let r = ReceiptV2::new("rct_1", "grt_1", "ember-bogus");
        let registry = ToolRegistry::new_default();
        match verify_v2(&r, &registry) {
            VerifyResult::UnknownTool { tool_id } => {
                assert_eq!(tool_id, "ember-bogus");
            }
            other => panic!("expected UnknownTool, got {other:?}"),
        }
    }

    #[test]
    fn receipt_v2_round_trips_via_serde() {
        let r = ReceiptV2 {
            version: RECEIPT_VERSION_V2,
            id: "rct_x".into(),
            grant_id: "grt_x".into(),
            tool_id: "ember-aws".into(),
            redactions_applied: true,
            body: json!({ "password": "<REDACTED>" }),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: ReceiptV2 = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn version_field_pins_at_2() {
        let r = ReceiptV2::new("a", "b", "ember-aws");
        assert_eq!(r.version, 2);
    }

    #[test]
    fn spawn_witness_kind_constant_matches_adr() {
        assert_eq!(RECEIPT_KIND_SPAWN_WITNESS, "spawn.witness");
    }

    #[test]
    fn spawn_witness_round_trips_via_serde() {
        let w = SpawnWitness {
            spawned_persona_id: "persona-child-001".into(),
            parent_persona_id: "persona-parent-001".into(),
            container_id: "container-abc".into(),
            spawn_grant_id: "grant-spawn-001".into(),
            parent_signature: "ed25519sig:deadbeef".into(),
            ca_fingerprint: [0u8; 32],
        };
        let s = serde_json::to_string(&w).unwrap();
        let back: SpawnWitness = serde_json::from_str(&s).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn spawn_witness_body_for_parent_signature_omits_signature() {
        let w = SpawnWitness {
            spawned_persona_id: "persona-child-001".into(),
            parent_persona_id: "persona-parent-001".into(),
            container_id: "container-abc".into(),
            spawn_grant_id: "grant-spawn-001".into(),
            parent_signature: "ed25519sig:deadbeef".into(),
            ca_fingerprint: [0u8; 32],
        };
        let v = w.body_for_parent_signature();
        let obj = v.as_object().expect("body serializes to object");
        assert!(!obj.contains_key("parent_signature"));
        assert!(obj.contains_key("spawned_persona_id"));
        assert!(obj.contains_key("parent_persona_id"));
        assert!(obj.contains_key("container_id"));
        assert!(obj.contains_key("spawn_grant_id"));
        // ca_fingerprint is included in the parent-signed body — the parent
        // attests to the CA binding alongside the persona/container/grant
        // fields (Slice C, bridge_ca_fingerprint_in_spawn_receipt).
        assert!(obj.contains_key("ca_fingerprint"));
        assert_eq!(obj.len(), 5);
    }

    #[test]
    fn spawn_witness_body_for_parent_signature_stable_across_signature_changes() {
        // Whatever the parent_signature field holds, the value-to-be-signed
        // must remain identical — otherwise the parent can never produce a
        // signature that matches what the verifier recomputes.
        let mut w = SpawnWitness::new("child", "parent", "container", "grant");
        let body_empty = w.body_for_parent_signature();
        w.parent_signature = "ed25519sig:111".into();
        let body_v1 = w.body_for_parent_signature();
        w.parent_signature = "ed25519sig:222".into();
        let body_v2 = w.body_for_parent_signature();
        assert_eq!(body_empty, body_v1);
        assert_eq!(body_v1, body_v2);
    }

    #[test]
    fn spawn_witness_new_leaves_signature_empty() {
        let w = SpawnWitness::new("c", "p", "ctr", "grt");
        assert!(w.parent_signature.is_empty());
        assert_eq!(w.spawned_persona_id, "c");
        assert_eq!(w.parent_persona_id, "p");
        assert_eq!(w.container_id, "ctr");
        assert_eq!(w.spawn_grant_id, "grt");
        // Pre-Slice-C default: callers that don't know the CA fingerprint
        // leave the field zeroed (Slice D treats it as "not asserted").
        assert_eq!(w.ca_fingerprint, [0u8; 32]);
    }

    /// META-AP-DAEMON-BRIDGE-CA-SE-SEALED-C-RECEIPT-FINGERPRINT — Slice C.
    ///
    /// A SpawnWitness with a populated `ca_fingerprint` round-trips through
    /// serde JSON without losing or mutating the fingerprint bytes.
    /// `#[serde(default)]` on the field also means pre-Slice-C wire forms
    /// (no `ca_fingerprint` key) deserialize cleanly into `[0u8; 32]` — that
    /// branch is asserted in the second half of this test.
    #[test]
    fn spawn_witness_ca_fingerprint() {
        // Distinctive non-zero fingerprint so a zero-fill bug would surface.
        let known_fp: [u8; 32] = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18,
        ];
        let w = SpawnWitness::new("child", "parent", "container", "grant")
            .with_ca_fingerprint(known_fp);
        assert_eq!(w.ca_fingerprint, known_fp);

        let serialized = serde_json::to_string(&w).expect("serialize");
        let back: SpawnWitness = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(back.ca_fingerprint, known_fp);
        assert_eq!(w, back);

        // Pre-Slice-C wire form (no ca_fingerprint key) must deserialize
        // with a zeroed fingerprint via #[serde(default)].
        let legacy_json = serde_json::json!({
            "spawned_persona_id": "child",
            "parent_persona_id": "parent",
            "container_id": "container",
            "spawn_grant_id": "grant",
            "parent_signature": "ed25519sig:deadbeef",
        });
        let legacy: SpawnWitness =
            serde_json::from_value(legacy_json).expect("legacy receipts deserialize");
        assert_eq!(legacy.ca_fingerprint, [0u8; 32]);
    }
}
