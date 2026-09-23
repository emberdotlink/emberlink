use core_crypto::{PublicKey, Signature, Signer, Verifier};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{canonical::LenEncoder, model::Refusal};

pub const PURPOSE_ROOT: &str = "root-signing";
pub const PURPOSE_GRANT: &str = "grant-signing";
pub const PURPOSE_RECEIPT: &str = "receipt-signing";
pub const PURPOSE_ACTION_PERMIT: &str = "action-permit-signing";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMaterial {
    pub key_id: String,
    pub purpose: String,
    pub generation: u64,
    pub public_key: String,
    pub private_key: String,
    pub authorization_signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceState {
    pub root: DeviceMaterial,
    pub grant: DeviceMaterial,
    pub receipt: DeviceMaterial,
    pub action_permit: DeviceMaterial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCustodyEvidence {
    pub schema: String,
    pub custody_class: String,
    pub device_set_digest: String,
    pub possession_signatures: Vec<String>,
}

#[derive(Clone)]
pub struct PurposeSigner {
    purpose: &'static str,
    material: DeviceMaterial,
    signing_key: SigningKey,
}

impl PurposeSigner {
    fn from_material(purpose: &'static str, material: &DeviceMaterial) -> Result<Self, Refusal> {
        if material.purpose != purpose || material.generation != 1 {
            return Err(Refusal::new("device_purpose_mismatch"));
        }
        let encoded = material
            .private_key
            .strip_prefix("ed25519-secret:")
            .ok_or_else(|| Refusal::new("device_key_invalid"))?;
        let raw = hex::decode(encoded).map_err(|_| Refusal::new("device_key_invalid"))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| Refusal::new("device_key_invalid"))?;
        let signing_key = SigningKey::from_bytes(&bytes);
        let public_key = format!(
            "ed25519:{}",
            hex::encode(signing_key.verifying_key().to_bytes())
        );
        if public_key != material.public_key {
            return Err(Refusal::new("device_key_invalid"));
        }
        Ok(Self {
            purpose,
            material: material.clone(),
            signing_key,
        })
    }

    pub fn purpose(&self) -> &'static str {
        self.purpose
    }

    pub fn key_id(&self) -> &str {
        &self.material.key_id
    }

    pub fn generation(&self) -> u64 {
        self.material.generation
    }
}

/// Payload domains each purpose key is allowed to sign. A purpose key asked to
/// sign any other payload returns an unusable signature, so misuse fails closed
/// at verification instead of producing a valid cross-purpose signature.
fn label_prefix(label: &str) -> Vec<u8> {
    let mut bytes = (label.len() as u64).to_be_bytes().to_vec();
    bytes.extend_from_slice(label.as_bytes());
    bytes
}

fn contains(payload: &[u8], needle: &[u8]) -> bool {
    payload.windows(needle.len()).any(|window| window == needle)
}

fn is_receipt_envelope(payload: &[u8]) -> bool {
    payload.first() == Some(&b'{')
        && contains(payload, b"\"receipt_id\"")
        && contains(payload, b"\"termination_authority\"")
}

fn purpose_allows(purpose: &str, payload: &[u8]) -> bool {
    let possession = label_prefix("ember/initial-device-possession/v1");
    if payload.starts_with(&possession) {
        return true;
    }
    match purpose {
        PURPOSE_ROOT => payload.starts_with(&label_prefix("ember/root-initialization-intent/v1")),
        PURPOSE_ACTION_PERMIT => payload.starts_with(b"ember/action-permit-signature-input/v1\0"),
        PURPOSE_RECEIPT => is_receipt_envelope(payload),
        _ => false,
    }
}

impl Signer for PurposeSigner {
    fn sign(&self, payload: &[u8]) -> Signature {
        if !purpose_allows(self.purpose, payload) {
            return Signature(String::new());
        }
        let signature = self.signing_key.sign(payload);
        Signature(format!("ed25519sig:{}", hex::encode(signature.to_bytes())))
    }

    fn public_key(&self) -> PublicKey {
        PublicKey(self.material.public_key.clone())
    }
}

pub struct DeviceCustody {
    state: DeviceState,
}

impl DeviceCustody {
    pub fn generate() -> Result<DeviceState, Refusal> {
        let mut root = new_device(PURPOSE_ROOT);
        let mut grant = new_device(PURPOSE_GRANT);
        let mut receipt = new_device(PURPOSE_RECEIPT);
        let mut action_permit = new_device(PURPOSE_ACTION_PERMIT);
        let root_private = root.private_key.clone();
        for device in [&mut root, &mut grant, &mut receipt, &mut action_permit] {
            let bytes = authorization_bytes(device)?;
            device.authorization_signature = sign_raw(&root_private, &bytes)?;
        }
        let state = DeviceState {
            root,
            grant,
            receipt,
            action_permit,
        };
        Self::restore(&state)?;
        Ok(state)
    }

    pub fn restore(state: &DeviceState) -> Result<Self, Refusal> {
        let verifier = core_crypto::Ed25519Verifier;
        for (purpose, device) in state.devices() {
            if device.purpose != purpose || device.generation != 1 {
                return Err(Refusal::new("device_purpose_mismatch"));
            }
            let bytes = authorization_bytes(device)?;
            if !verifier.verify(
                &PublicKey(state.root.public_key.clone()),
                &bytes,
                &Signature(device.authorization_signature.clone()),
            ) {
                return Err(Refusal::new("device_authorization_invalid"));
            }
            PurposeSigner::from_material(purpose, device)?;
        }
        let mut raw_keys = state
            .devices()
            .into_iter()
            .map(|(_, device)| canonical_public_key(&device.public_key))
            .collect::<Result<Vec<_>, _>>()?;
        raw_keys.sort();
        raw_keys.dedup();
        let mut fingerprints = state
            .devices()
            .into_iter()
            .map(|(purpose, device)| signing_key_fingerprint(&device.public_key, purpose))
            .collect::<Result<Vec<_>, _>>()?;
        fingerprints.sort();
        fingerprints.dedup();
        // Distinct purposes must also be distinct key material: the fingerprint
        // mixes in the purpose label, so identical keys would otherwise pass.
        if fingerprints.len() != 4 || raw_keys.len() != 4 {
            return Err(Refusal::new("device_fingerprint_collision"));
        }
        Ok(Self {
            state: state.clone(),
        })
    }

    pub fn custody_evidence(
        state: &DeviceState,
        custody_class: &str,
    ) -> Result<DeviceCustodyEvidence, Refusal> {
        if custody_class != "qualification-software" {
            return Err(Refusal::new("device_custody_invalid"));
        }
        let custody = Self::restore(state)?;
        let digest = device_set_digest(state)?;
        let challenge = possession_challenge(&digest)?;
        let mut possession_signatures = Vec::with_capacity(4);
        for (purpose, material) in state.devices() {
            possession_signatures.push(
                PurposeSigner::from_material(purpose, material)?
                    .sign(&challenge)
                    .0,
            );
        }
        let _ = custody;
        Ok(DeviceCustodyEvidence {
            schema: "ember.initial-device-custody-evidence/v1".into(),
            custody_class: custody_class.into(),
            device_set_digest: digest,
            possession_signatures,
        })
    }

    pub fn verify_custody_evidence(
        state: &DeviceState,
        evidence: &DeviceCustodyEvidence,
    ) -> Result<(), Refusal> {
        if evidence.schema != "ember.initial-device-custody-evidence/v1"
            || evidence.custody_class != "qualification-software"
            || evidence.device_set_digest != device_set_digest(state)?
            || evidence.possession_signatures.len() != 4
        {
            return Err(Refusal::new("device_custody_invalid"));
        }
        let verifier = core_crypto::Ed25519Verifier;
        let challenge = possession_challenge(&evidence.device_set_digest)?;
        for (((_, material), signature), expected_index) in state
            .devices()
            .into_iter()
            .zip(&evidence.possession_signatures)
            .zip(0..4)
        {
            if expected_index >= 4
                || !verifier.verify(
                    &PublicKey(material.public_key.clone()),
                    &challenge,
                    &Signature(signature.clone()),
                )
            {
                return Err(Refusal::new("device_custody_invalid"));
            }
        }
        Ok(())
    }

    pub fn root_signer(&self) -> Result<PurposeSigner, Refusal> {
        PurposeSigner::from_material(PURPOSE_ROOT, &self.state.root)
    }

    pub fn receipt_signer(&self) -> Result<PurposeSigner, Refusal> {
        PurposeSigner::from_material(PURPOSE_RECEIPT, &self.state.receipt)
    }

    pub fn action_permit_signer(&self) -> Result<PurposeSigner, Refusal> {
        PurposeSigner::from_material(PURPOSE_ACTION_PERMIT, &self.state.action_permit)
    }

    pub fn receipt_public_key(&self) -> PublicKey {
        PublicKey(self.state.receipt.public_key.clone())
    }

    pub fn root_public_key(&self) -> PublicKey {
        PublicKey(self.state.root.public_key.clone())
    }

    pub fn state(&self) -> &DeviceState {
        &self.state
    }
}

impl DeviceState {
    fn devices(&self) -> Vec<(&'static str, &DeviceMaterial)> {
        vec![
            (PURPOSE_ROOT, &self.root),
            (PURPOSE_GRANT, &self.grant),
            (PURPOSE_RECEIPT, &self.receipt),
            (PURPOSE_ACTION_PERMIT, &self.action_permit),
        ]
    }
}

fn new_device(purpose: &'static str) -> DeviceMaterial {
    let (public_key, private_key) = new_key();
    let fingerprint = signing_key_fingerprint(&public_key, purpose).expect("generated key");
    DeviceMaterial {
        key_id: format!("device:{purpose}:{}", &fingerprint[7..23]),
        purpose: purpose.to_owned(),
        generation: 1,
        public_key,
        private_key,
        authorization_signature: String::new(),
    }
}

fn new_key() -> (String, String) {
    use rand_core::{OsRng, RngCore as _};
    let mut seed = [0_u8; 32];
    OsRng.fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    let public = format!("ed25519:{}", hex::encode(key.verifying_key().to_bytes()));
    let private = format!("ed25519-secret:{}", hex::encode(seed));
    seed.fill(0);
    (public, private)
}

fn authorization_bytes(material: &DeviceMaterial) -> Result<Vec<u8>, Refusal> {
    let mut encoder = LenEncoder::new("ember/device-authorization-chain-record/v1")?;
    encoder
        .string(&material.key_id)?
        .string(&material.purpose)?
        .u64(material.generation)
        .string(&material.public_key)?;
    Ok(encoder.finish())
}

fn sign_raw(private: &str, payload: &[u8]) -> Result<String, Refusal> {
    let bytes = hex::decode(
        private
            .strip_prefix("ed25519-secret:")
            .ok_or_else(|| Refusal::new("device_key_invalid"))?,
    )
    .map_err(|_| Refusal::new("device_key_invalid"))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Refusal::new("device_key_invalid"))?;
    let signature = SigningKey::from_bytes(&seed).sign(payload);
    Ok(format!("ed25519sig:{}", hex::encode(signature.to_bytes())))
}

fn canonical_public_key(public_key: &str) -> Result<Vec<u8>, Refusal> {
    let raw = public_key
        .strip_prefix("ed25519:")
        .ok_or_else(|| Refusal::new("device_key_invalid"))?;
    let bytes = hex::decode(raw).map_err(|_| Refusal::new("device_key_invalid"))?;
    let canonical: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Refusal::new("device_key_invalid"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&canonical)
        .map_err(|_| Refusal::new("device_key_invalid"))?;
    Ok(canonical.to_vec())
}

pub fn signing_key_fingerprint(public_key: &str, purpose: &str) -> Result<String, Refusal> {
    let raw = canonical_public_key(public_key)?;
    let mut bytes = Vec::new();
    for field in [
        b"ember/signing-public-key/v1".as_slice(),
        b"ed25519".as_slice(),
        purpose.as_bytes(),
        raw.as_slice(),
    ] {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))))
}

pub fn authority_fingerprint(public_key: &str) -> Result<String, Refusal> {
    let raw = canonical_public_key(public_key)?;
    let mut bytes = Vec::new();
    for field in [b"ember/authority-fingerprint/v1".as_slice(), raw.as_slice()] {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))))
}

pub fn device_set_digest(state: &DeviceState) -> Result<String, Refusal> {
    let mut encoder = LenEncoder::new("ember/initial-device-set/v1")?;
    for (purpose, material) in state.devices() {
        let bytes = authorization_bytes(material)?;
        encoder.string(purpose)?.string(&hex::encode(bytes))?;
    }
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(encoder.finish()))
    ))
}

fn possession_challenge(device_set_digest: &str) -> Result<Vec<u8>, Refusal> {
    let mut encoder = LenEncoder::new("ember/initial-device-possession/v1")?;
    encoder.digest(device_set_digest)?;
    Ok(encoder.finish())
}
