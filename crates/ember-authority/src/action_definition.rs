use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{
    audit::decode_canonical,
    initialization::{InitialActionDefinitionRecord, PublisherTrustRoot},
    model::{ActionRef, Refusal},
};

const DEFINITION_DOMAIN: &[u8] = b"emberlink.action-definition/v1\0";
const BUNDLE_DOMAIN: &[u8] = b"emberlink.action-definition-bundle/v1\0";
const MAX_REGISTRY_BYTES: usize = 1_048_576;
const MAX_REGISTRY_STATE_BYTES: usize = 2_097_152;
const DIAGNOSTIC_DEFINITION: &str = r#"{"action_ref":{"action_key":"authority_status","action_version":"v2","plugin_address":"packet-fixture.local/packet-fixture/diagnostic"},"audit_fields":["action_ref","definition_digest","input.challenge","output.journal_health"],"default_runner_classes":["builtin"],"delivery_lane":"sealed-exec","handler_ref":"builtin.diagnostic.authority-status/v1","idempotency":"idempotent","input_schema":{"additionalProperties":false,"properties":{"challenge":{"maxLength":64,"minLength":1,"type":"string"}},"required":["challenge"],"type":"object"},"interaction_class":"inline_interactive","material_classes":["non_secret"],"need_template":{"items":[{"material_class":"non_secret","permissions":["authority.status.read"],"provider":"ember.local","required":true}],"schema":"emberlink.need-template/v1"},"output_schema":{"additionalProperties":false,"properties":{"challenge":{"maxLength":64,"minLength":1,"type":"string"},"journal_health":{"maxLength":5,"minLength":5,"type":"string"}},"required":["challenge","journal_health"],"type":"object"},"provider_adapter":"builtin/non-secret","result_frame_count_ceiling":1,"result_frame_payload_allowlist":[{"payload_schema_identifier":"emberlink.diagnostic-facts","payload_schema_version":"v1","payload_semantics":"diagnostic-facts"}],"risk_tier":"low","runner_adapter":"builtin.diagnostic.authority-status/v1","semantic_labels":["diagnostic"],"summary":"Read local authority journal health","target_template":{"input_path":"input.challenge","kind":"exact","schema":"emberlink.target-template/v1"}}"#;

#[derive(Clone, Debug)]
pub struct ResolvedDefinition {
    pub action_ref: ActionRef,
    pub digest: String,
    pub definition: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryState {
    publisher: PublisherTrustRoot,
    publisher_active: bool,
    definition_digest: String,
    definition_active: bool,
    signed_bundle: String,
}

#[derive(Clone)]
pub struct ActionDefinitionRegistry {
    publisher: PublisherTrustRoot,
    publisher_active: bool,
    definition_digest: String,
    definition_active: bool,
    canonical_definition: String,
    signed_bundle: String,
}

impl ActionDefinitionRegistry {
    pub fn initialize(
        publisher: &PublisherTrustRoot,
        definition: &InitialActionDefinitionRecord,
    ) -> Result<String, Refusal> {
        verify_signed_bundle(
            &definition.signed_bundle,
            publisher,
            &definition.action_definition_digest,
        )?;
        serde_jcs::to_string(&RegistryState {
            publisher: publisher.clone(),
            publisher_active: true,
            definition_digest: definition.action_definition_digest.clone(),
            definition_active: true,
            signed_bundle: definition.signed_bundle.clone(),
        })
        .map_err(|_| Refusal::new("invalid_bundle"))
    }

    pub fn restore(opaque_owner_bytes: &str) -> Result<Self, Refusal> {
        let state: RegistryState = decode_canonical(
            opaque_owner_bytes.as_bytes(),
            MAX_REGISTRY_STATE_BYTES,
            "registry_restore_failed",
        )?;
        let definition = verify_signed_bundle(
            &state.signed_bundle,
            &state.publisher,
            &state.definition_digest,
        )?;
        let canonical_definition = serde_jcs::to_string(&definition)
            .map_err(|_| Refusal::new("registry_restore_failed"))?;
        Ok(Self {
            publisher: state.publisher,
            publisher_active: state.publisher_active,
            definition_digest: state.definition_digest,
            definition_active: state.definition_active,
            canonical_definition,
            signed_bundle: state.signed_bundle,
        })
    }

    pub fn resolve(
        &self,
        action_ref: &ActionRef,
        expected_digest: &str,
        now: u64,
    ) -> Result<ResolvedDefinition, Refusal> {
        if expected_digest.is_empty() {
            return Err(Refusal::new("definition_digest_required"));
        }
        if expected_digest != self.definition_digest {
            return Err(Refusal::new("definition_digest_mismatch"));
        }
        if !self.publisher_active || !self.definition_active {
            return Err(Refusal::new("definition_inactive"));
        }
        // This tranche has no registry mutation path. Rollback of the
        // containing registry bytes is enforced by DurableStore's
        // protected-tip high-water record.
        if now >= self.publisher.not_after {
            return Err(Refusal::new("publisher_not_trusted"));
        }
        let authenticated_definition = verify_signed_bundle(
            &self.signed_bundle,
            &self.publisher,
            &self.definition_digest,
        )?;
        if serde_jcs::to_string(&authenticated_definition)
            .map_err(|_| Refusal::new("registry_restore_failed"))?
            != self.canonical_definition
        {
            return Err(Refusal::new("registry_restore_failed"));
        }
        let definition: Value = decode_canonical(
            self.canonical_definition.as_bytes(),
            MAX_REGISTRY_BYTES,
            "invalid_definition",
        )?;
        validate_closed_definition(&definition)?;
        let stored_ref: ActionRef = serde_json::from_value(definition["action_ref"].clone())
            .map_err(|_| Refusal::new("invalid_definition"))?;
        if action_ref != &stored_ref {
            return Err(Refusal::new("unknown_definition"));
        }
        Ok(ResolvedDefinition {
            action_ref: action_ref.clone(),
            digest: expected_digest.to_owned(),
            definition,
        })
    }
}

fn verify_signed_bundle(
    bytes: &str,
    publisher: &PublisherTrustRoot,
    expected_definition_digest: &str,
) -> Result<Value, Refusal> {
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
    if envelope["signer_key_id"] != publisher.signer_key_id {
        return Err(Refusal::new("publisher_not_trusted"));
    }
    let bundle = &envelope["bundle"];
    let canonical_bundle = serde_jcs::to_vec(bundle).map_err(|_| Refusal::new("invalid_bundle"))?;
    let mut preimage = BUNDLE_DOMAIN.to_vec();
    preimage.extend_from_slice(publisher.signer_key_id.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&canonical_bundle);
    let public: [u8; 32] = STANDARD
        .decode(&publisher.public_key)
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
    let bundle_digest = format!("sha256:{}", hex::encode(Sha256::digest(&preimage)));
    if envelope["bundle_digest"] != bundle_digest {
        return Err(Refusal::new("bundle_digest_mismatch"));
    }
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
        || bundle["publisher_id"] != publisher.publisher_id
        || bundle["bundle_revision"] != 1
        || !bundle["previous_bundle_digest"].is_null()
    {
        return Err(Refusal::new("invalid_bundle"));
    }
    let plugin_address = bundle["plugin_address"]
        .as_str()
        .ok_or_else(|| Refusal::new("invalid_bundle"))?;
    let definitions = bundle["definitions"]
        .as_array()
        .ok_or_else(|| Refusal::new("invalid_bundle"))?;
    if definitions.len() != 1 {
        return Err(Refusal::new("invalid_bundle"));
    }
    validate_closed_definition(&definitions[0])?;
    let wrapper = json!({
        "schema": "emberlink.action-definition/v1",
        "publisher_id": publisher.publisher_id,
        "plugin_address": plugin_address,
        "definition": &definitions[0],
    });
    let canonical_wrapper =
        serde_jcs::to_vec(&wrapper).map_err(|_| Refusal::new("invalid_definition"))?;
    if domain_digest(DEFINITION_DOMAIN, &canonical_wrapper) != expected_definition_digest {
        return Err(Refusal::new("definition_digest_mismatch"));
    }
    Ok(definitions[0].clone())
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn validate_closed_definition(value: &Value) -> Result<(), Refusal> {
    let canonical = serde_jcs::to_string(value).map_err(|_| Refusal::new("invalid_definition"))?;
    if canonical != DIAGNOSTIC_DEFINITION {
        return Err(Refusal::new("invalid_definition"));
    }
    Ok(())
}
