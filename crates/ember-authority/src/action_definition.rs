use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{
    audit::decode_canonical,
    model::{ActionRef, DEFINITION_BYTES, DEFINITION_DIGEST, Refusal, signed_bundle_bytes},
};

const DEFINITION_DOMAIN: &[u8] = b"emberlink.action-definition/v1\0";
const BUNDLE_DOMAIN: &[u8] = b"emberlink.action-definition-bundle/v1\0";
pub const PUBLISHER_ID: &str = "publisher:packet-fixture";
pub const SIGNER_KEY_ID: &str = "publisher:packet-fixture:key-productbase-s4-vector";
pub const PUBLISHER_PUBLIC_KEY: &str = "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=";
pub const PUBLISHER_NOT_AFTER: u64 = 4_102_444_800;
const MAX_REGISTRY_BYTES: usize = 1_048_576;

#[derive(Clone, Debug)]
pub struct ResolvedDefinition {
    pub action_ref: ActionRef,
    pub digest: String,
    pub definition: Value,
}

#[derive(Clone)]
pub struct ActionDefinitionRegistry {
    canonical_definition: String,
}

impl ActionDefinitionRegistry {
    pub fn initialize(signed_bundle_bytes: &str) -> Result<String, Refusal> {
        verify_signed_bundle(signed_bundle_bytes)?;
        Ok(signed_bundle_bytes.to_owned())
    }

    pub fn restore(opaque_owner_bytes: &str) -> Result<Self, Refusal> {
        verify_signed_bundle(opaque_owner_bytes)
            .map_err(|_| Refusal::new("registry_restore_failed"))?;
        Ok(Self {
            canonical_definition: DEFINITION_BYTES.to_owned(),
        })
    }

    pub fn resolve(
        &self,
        action_ref: &ActionRef,
        expected_digest: &str,
        now: u64,
    ) -> Result<ResolvedDefinition, Refusal> {
        if action_ref != &ActionRef::diagnostic() {
            return Err(Refusal::new("unknown_definition"));
        }
        if expected_digest.is_empty() {
            return Err(Refusal::new("definition_digest_required"));
        }
        if expected_digest != DEFINITION_DIGEST {
            return Err(Refusal::new("definition_digest_mismatch"));
        }
        if now >= PUBLISHER_NOT_AFTER {
            return Err(Refusal::new("publisher_not_trusted"));
        }
        let definition: Value = decode_canonical(
            self.canonical_definition.as_bytes(),
            MAX_REGISTRY_BYTES,
            "invalid_definition",
        )?;
        validate_closed_definition(&definition)?;
        Ok(ResolvedDefinition {
            action_ref: action_ref.clone(),
            digest: expected_digest.to_owned(),
            definition,
        })
    }
}

pub fn verify_fixture_vector() -> Result<(), Refusal> {
    verify_signed_bundle(&signed_bundle_bytes())
}

fn verify_signed_bundle(bytes: &str) -> Result<(), Refusal> {
    let envelope: Value = decode_canonical(bytes.as_bytes(), MAX_REGISTRY_BYTES, "invalid_bundle")?;
    let envelope_object = envelope
        .as_object()
        .ok_or_else(|| Refusal::new("invalid_bundle"))?;
    let envelope_keys = ["bundle", "bundle_digest", "signature", "signer_key_id"];
    if envelope_object.len() != envelope_keys.len()
        || envelope_keys
            .iter()
            .any(|key| !envelope_object.contains_key(*key))
    {
        return Err(Refusal::new("invalid_bundle"));
    }
    if envelope["signer_key_id"] != SIGNER_KEY_ID {
        return Err(Refusal::new("publisher_not_trusted"));
    }
    let bundle = &envelope["bundle"];
    let bundle_object = bundle
        .as_object()
        .ok_or_else(|| Refusal::new("invalid_bundle"))?;
    let bundle_keys = [
        "bundle_revision",
        "definitions",
        "plugin_address",
        "plugin_version",
        "previous_bundle_digest",
        "published_at",
        "publisher_id",
        "schema",
    ];
    if bundle_object.len() != bundle_keys.len()
        || bundle_keys
            .iter()
            .any(|key| !bundle_object.contains_key(*key))
        || bundle["schema"] != "emberlink.action-definition-bundle/v1"
        || bundle["publisher_id"] != PUBLISHER_ID
        || bundle["plugin_address"] != "packet-fixture.local/packet-fixture/diagnostic"
        || bundle["plugin_version"] != "0.1.0"
        || bundle["bundle_revision"] != 1
        || !bundle["previous_bundle_digest"].is_null()
        || bundle["published_at"] != 0
    {
        return Err(Refusal::new("invalid_bundle"));
    }
    let definitions = bundle["definitions"]
        .as_array()
        .ok_or_else(|| Refusal::new("invalid_bundle"))?;
    if definitions.len() != 1 {
        return Err(Refusal::new("invalid_bundle"));
    }
    validate_closed_definition(&definitions[0])?;
    let wrapper = json!({
        "schema": "emberlink.action-definition/v1",
        "publisher_id": PUBLISHER_ID,
        "plugin_address": "packet-fixture.local/packet-fixture/diagnostic",
        "definition": &definitions[0],
    });
    let canonical_wrapper =
        serde_jcs::to_vec(&wrapper).map_err(|_| Refusal::new("invalid_definition"))?;
    if domain_digest(DEFINITION_DOMAIN, &canonical_wrapper) != DEFINITION_DIGEST {
        return Err(Refusal::new("definition_digest_mismatch"));
    }
    let canonical_bundle = serde_jcs::to_vec(bundle).map_err(|_| Refusal::new("invalid_bundle"))?;
    let mut preimage = BUNDLE_DOMAIN.to_vec();
    preimage.extend_from_slice(SIGNER_KEY_ID.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&canonical_bundle);
    let bundle_digest = format!("sha256:{}", hex::encode(Sha256::digest(&preimage)));
    if envelope["bundle_digest"] != bundle_digest {
        return Err(Refusal::new("bundle_digest_mismatch"));
    }
    let public: [u8; 32] = STANDARD
        .decode(PUBLISHER_PUBLIC_KEY)
        .map_err(|_| Refusal::new("invalid_signature"))?
        .try_into()
        .map_err(|_| Refusal::new("invalid_signature"))?;
    let signature_text = envelope["signature"]
        .as_str()
        .ok_or_else(|| Refusal::new("invalid_signature"))?;
    let signature: [u8; 64] = STANDARD
        .decode(signature_text)
        .map_err(|_| Refusal::new("invalid_signature"))?
        .try_into()
        .map_err(|_| Refusal::new("invalid_signature"))?;
    VerifyingKey::from_bytes(&public)
        .map_err(|_| Refusal::new("invalid_signature"))?
        .verify(&preimage, &Signature::from_bytes(&signature))
        .map_err(|_| Refusal::new("invalid_signature"))?;
    Ok(())
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn validate_closed_definition(value: &Value) -> Result<(), Refusal> {
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("invalid_definition"))?;
    let required = [
        "action_ref",
        "audit_fields",
        "default_runner_classes",
        "delivery_lane",
        "handler_ref",
        "idempotency",
        "input_schema",
        "interaction_class",
        "material_classes",
        "need_template",
        "output_schema",
        "provider_adapter",
        "result_frame_count_ceiling",
        "result_frame_payload_allowlist",
        "risk_tier",
        "runner_adapter",
        "semantic_labels",
        "summary",
        "target_template",
    ];
    if object.len() != required.len() || required.iter().any(|key| !object.contains_key(*key)) {
        return Err(Refusal::new("invalid_definition"));
    }
    if value["action_ref"] != serde_json::to_value(ActionRef::diagnostic()).unwrap()
        || value["delivery_lane"] != "sealed-exec"
        || value["result_frame_count_ceiling"] != 1
        || value["runner_adapter"] != "builtin.diagnostic.authority-status/v1"
        || value["handler_ref"] != "builtin.diagnostic.authority-status/v1"
    {
        return Err(Refusal::new("invalid_definition"));
    }
    let allowlist = value["result_frame_payload_allowlist"]
        .as_array()
        .ok_or_else(|| Refusal::new("invalid_definition"))?;
    if allowlist.len() != 1
        || allowlist[0]
            != json!({
                "payload_schema_identifier": "emberlink.diagnostic-facts",
                "payload_schema_version": "v1",
                "payload_semantics": "diagnostic-facts",
            })
    {
        return Err(Refusal::new("invalid_definition"));
    }
    Ok(())
}
