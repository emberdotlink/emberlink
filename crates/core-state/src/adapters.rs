use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use core_crypto::{
    LocalKeySigner, Signer as CryptoSigner, public_key_raw_bytes, sha256_digest_raw,
};
use core_types::{
    ClaimType, ImportedClaim, PresentationResult, ServiceAdapter, ServiceBinding, Validate,
    ValidationError,
};
use csv::{ReaderBuilder, StringRecord, Trim};
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordImportFormat {
    OnePasswordCsv,
    BitwardenCsv,
}

impl PasswordImportFormat {
    fn external_issuer(self) -> &'static str {
        match self {
            Self::OnePasswordCsv => "1password",
            Self::BitwardenCsv => "bitwarden",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordImportAdapter {
    format: PasswordImportFormat,
    csv_text: String,
}

impl PasswordImportAdapter {
    pub fn new(format: PasswordImportFormat, csv_text: impl Into<String>) -> Self {
        Self {
            format,
            csv_text: csv_text.into(),
        }
    }

    fn validate_binding(&self, binding: &ServiceBinding) -> Result<(), ValidationError> {
        binding.validate()?;
        if binding.descriptor.adapter_kind != "password" {
            return Err(ValidationError::new(format!(
                "password import adapter requires adapter_kind=password, got {}",
                binding.descriptor.adapter_kind
            )));
        }
        Ok(())
    }

    fn import_rows(&self) -> Result<Vec<ImportedClaim>, ValidationError> {
        let mut reader = ReaderBuilder::new()
            .trim(Trim::All)
            .flexible(true)
            .from_reader(self.csv_text.as_bytes());
        let headers = reader
            .headers()
            .map_err(|err| {
                ValidationError::new(format!("read password import csv headers: {err}"))
            })?
            .clone();

        let mut imported = Vec::new();
        for record in reader.records() {
            let record: StringRecord = record.map_err(|err| {
                ValidationError::new(format!("read password import csv row: {err}"))
            })?;
            let row = normalized_row(&headers, &record);
            let claim = match self.format {
                PasswordImportFormat::OnePasswordCsv => parse_onepassword_row(&row, self.format)?,
                PasswordImportFormat::BitwardenCsv => parse_bitwarden_row(&row, self.format)?,
            };
            if let Some(claim) = claim {
                claim.validate()?;
                imported.push(claim);
            }
        }
        Ok(imported)
    }
}

impl ServiceAdapter for PasswordImportAdapter {
    fn present(
        &self,
        binding: &ServiceBinding,
        _disclosure_payload: &[u8],
    ) -> Result<PresentationResult, ValidationError> {
        self.validate_binding(binding)?;
        Ok(PresentationResult::Error {
            message: "password import adapters only support import".into(),
        })
    }

    fn import(&self, binding: &ServiceBinding) -> Result<Vec<ImportedClaim>, ValidationError> {
        self.validate_binding(binding)?;
        self.import_rows()
    }

    fn verify_binding(&self, binding: &ServiceBinding) -> Result<bool, ValidationError> {
        self.validate_binding(binding)?;
        Ok(true)
    }
}

fn normalized_row(headers: &StringRecord, record: &StringRecord) -> BTreeMap<String, String> {
    headers
        .iter()
        .zip(record.iter())
        .map(|(header, value): (&str, &str)| (normalize_header(header), value.trim().to_string()))
        .collect()
}

fn normalize_header(header: &str) -> String {
    header.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

fn parse_onepassword_row(
    row: &BTreeMap<String, String>,
    format: PasswordImportFormat,
) -> Result<Option<ImportedClaim>, ValidationError> {
    build_password_claim(
        row.get("title").cloned().unwrap_or_default(),
        row.get("url").cloned().unwrap_or_default(),
        row.get("username").cloned().unwrap_or_default(),
        row.get("password").cloned().unwrap_or_default(),
        parse_totp_secret(row.get("otpauth").map(String::as_str).unwrap_or_default()),
        row.get("notes").cloned().unwrap_or_default(),
        format,
    )
}

fn parse_bitwarden_row(
    row: &BTreeMap<String, String>,
    format: PasswordImportFormat,
) -> Result<Option<ImportedClaim>, ValidationError> {
    let entry_type = row
        .get("type")
        .map(|value| value.trim())
        .unwrap_or_default();
    if !entry_type.is_empty() && !entry_type.eq_ignore_ascii_case("login") {
        return Ok(None);
    }

    build_password_claim(
        row.get("name").cloned().unwrap_or_default(),
        row.get("login_uri").cloned().unwrap_or_default(),
        row.get("login_username").cloned().unwrap_or_default(),
        row.get("login_password").cloned().unwrap_or_default(),
        parse_totp_secret(
            row.get("login_totp")
                .map(String::as_str)
                .unwrap_or_default(),
        ),
        row.get("notes").cloned().unwrap_or_default(),
        format,
    )
}

fn parse_totp_secret(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(secret_idx) = raw.find("secret=") {
        let secret = &raw[(secret_idx + "secret=".len())..];
        let end = secret.find('&').unwrap_or(secret.len());
        return Some(secret[..end].to_string());
    }
    Some(raw.to_string())
}

fn build_password_claim(
    service_name: String,
    service_url: String,
    username: String,
    password: String,
    totp_secret: Option<String>,
    notes: String,
    format: PasswordImportFormat,
) -> Result<Option<ImportedClaim>, ValidationError> {
    if service_name.trim().is_empty()
        && service_url.trim().is_empty()
        && username.trim().is_empty()
        && password.trim().is_empty()
        && totp_secret.is_none()
        && notes.trim().is_empty()
    {
        return Ok(None);
    }

    let claim = ImportedClaim {
        claim_type: ClaimType::SelfAsserted.as_str().into(),
        payload_json: json!({
            "schema": "emberlink:claim:password:1.0",
            "service_name": service_name,
            "service_url": service_url,
            "username": username,
            "password": password,
            "totp_secret": totp_secret,
            "notes": notes,
        })
        .to_string(),
        external_issuer: format.external_issuer().into(),
        external_issued_at: None,
        external_expires_at: None,
    };
    Ok(Some(claim))
}

// ---------------------------------------------------------------------------
// PasskeyAdapter — WebAuthn virtual authenticator backed by Ed25519 device keys
// ---------------------------------------------------------------------------

/// Emberlink-specific AAGUID for WebAuthn attestation.
/// First 16 bytes of SHA-256("emberlink-virtual-authenticator-v1").
// Pre-computed: sha256("emberlink-virtual-authenticator-v1")[..16]
const EMBERLINK_AAGUID: [u8; 16] = [
    0x8b, 0x3a, 0x4e, 0xf1, 0xc7, 0x02, 0xd9, 0x5b, 0xa1, 0x6e, 0x33, 0xf8, 0x7c, 0x49, 0x10,
    0xdd,
];

/// COSE algorithm identifier for EdDSA.
const COSE_ALG_EDDSA: i64 = -8;
/// COSE key type for Octet Key Pair (OKP).
const COSE_KTY_OKP: i64 = 1;
/// COSE curve identifier for Ed25519.
const COSE_CRV_ED25519: i64 = 6;

/// Authenticator flags: user-present (UP) + attested-credential-data (AT).
const AUTH_FLAG_UP_AT: u8 = 0x41;
/// Authenticator flags: user-present (UP) only.
const AUTH_FLAG_UP: u8 = 0x01;

/// Parsed metadata stored in `ServiceBinding.external_account_id` for passkey bindings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PasskeyBindingMeta {
    pub rp_id: String,
    pub credential_id: String, // base64url-encoded
    pub device_key_id: String,
    pub sign_count: u32,
}

/// Result of a WebAuthn registration ceremony.
#[derive(Debug, Clone)]
pub struct PasskeyRegistrationResult {
    pub credential_id_b64url: String,
    pub attestation_object: Vec<u8>,
    pub client_data_json: Vec<u8>,
}

/// Result of a WebAuthn authentication ceremony.
#[derive(Debug, Clone)]
pub struct PasskeyAssertionResult {
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub client_data_json: Vec<u8>,
}

/// WebAuthn virtual authenticator backed by an Emberlink Ed25519 device key.
pub struct PasskeyAdapter {
    signer: LocalKeySigner,
    device_key_id: String,
}

impl PasskeyAdapter {
    pub fn new(signer: LocalKeySigner, device_key_id: String) -> Self {
        Self {
            signer,
            device_key_id,
        }
    }

    /// Perform a WebAuthn registration ceremony, producing an attestation object
    /// and clientDataJSON suitable for a relying party.
    pub fn register(
        &self,
        rp_id: &str,
        rp_origin: &str,
        user_id: &[u8],
        user_name: &str,
        challenge: &[u8],
    ) -> Result<(PasskeyRegistrationResult, PasskeyBindingMeta), ValidationError> {
        let _ = (user_id, user_name); // reserved for future extensions

        // Generate a random credential ID (32 bytes).
        let credential_id: Vec<u8> = {
            let random_hex = core_crypto::generate_random_identifier("cred");
            sha256_digest_raw(random_hex.as_bytes()).to_vec()
        };
        let credential_id_b64url = URL_SAFE_NO_PAD.encode(&credential_id);

        let public_key = self.signer.public_key();
        let pk_bytes = public_key_raw_bytes(&public_key)?;

        // Build COSE Ed25519 public key (CBOR map).
        let cose_key = build_cose_ed25519_public_key(&pk_bytes)?;

        // Build attested credential data.
        let attested_cred_data = build_attested_credential_data(&EMBERLINK_AAGUID, &credential_id, &cose_key);

        // Build authenticator data (with attested credential data).
        let auth_data = build_authenticator_data(rp_id, AUTH_FLAG_UP_AT, 0, Some(&attested_cred_data));

        // Build attestation object (fmt=none).
        let attestation_object = build_attestation_object(&auth_data)?;

        // Build clientDataJSON.
        let challenge_b64url = URL_SAFE_NO_PAD.encode(challenge);
        let client_data_json = build_client_data_json("webauthn.create", &challenge_b64url, rp_origin);

        let meta = PasskeyBindingMeta {
            rp_id: rp_id.to_string(),
            credential_id: credential_id_b64url.clone(),
            device_key_id: self.device_key_id.clone(),
            sign_count: 0,
        };

        Ok((
            PasskeyRegistrationResult {
                credential_id_b64url,
                attestation_object,
                client_data_json,
            },
            meta,
        ))
    }

    /// Perform a WebAuthn authentication ceremony, producing an assertion
    /// that a relying party can verify.
    pub fn authenticate(
        &self,
        meta: &mut PasskeyBindingMeta,
        challenge: &[u8],
        rp_origin: &str,
    ) -> Result<PasskeyAssertionResult, ValidationError> {
        meta.sign_count += 1;

        // Build authenticator data (no attested credential data for assertion).
        let auth_data = build_authenticator_data(&meta.rp_id, AUTH_FLAG_UP, meta.sign_count, None);

        // Build clientDataJSON.
        let challenge_b64url = URL_SAFE_NO_PAD.encode(challenge);
        let client_data_json = build_client_data_json("webauthn.get", &challenge_b64url, rp_origin);

        // Sign: authenticatorData || SHA-256(clientDataJSON).
        let client_data_hash = sha256_digest_raw(&client_data_json);
        let mut signed_payload = auth_data.clone();
        signed_payload.extend_from_slice(&client_data_hash);

        let signature = self.signer.sign(&signed_payload);
        let sig_hex = &signature.0;
        // Signature is stored as "ed25519sig:<hex>".
        let sig_bytes = core_types::hex_to_bytes(
            sig_hex
                .strip_prefix("ed25519sig:")
                .ok_or_else(|| ValidationError::new("unexpected signature format"))?,
        )?;

        Ok(PasskeyAssertionResult {
            authenticator_data: auth_data,
            signature: sig_bytes,
            client_data_json,
        })
    }
}

impl ServiceAdapter for PasskeyAdapter {
    fn present(
        &self,
        binding: &ServiceBinding,
        disclosure_payload: &[u8],
    ) -> Result<PresentationResult, ValidationError> {
        validate_passkey_binding(binding, &self.device_key_id)?;

        // Parse disclosure_payload as JSON challenge: {"challenge": "<b64url>", "rp_origin": "..."}
        let challenge_obj: serde_json::Value = serde_json::from_slice(disclosure_payload)
            .map_err(|err| ValidationError::new(format!("parse passkey challenge: {err}")))?;

        let challenge_b64 = challenge_obj["challenge"]
            .as_str()
            .ok_or_else(|| ValidationError::new("missing 'challenge' in passkey presentation"))?;
        let rp_origin = challenge_obj["rp_origin"]
            .as_str()
            .ok_or_else(|| ValidationError::new("missing 'rp_origin' in passkey presentation"))?;

        let challenge_bytes = URL_SAFE_NO_PAD
            .decode(challenge_b64)
            .map_err(|err| ValidationError::new(format!("decode challenge: {err}")))?;

        let mut meta: PasskeyBindingMeta = serde_json::from_str(&binding.external_account_id)
            .map_err(|err| ValidationError::new(format!("parse passkey binding meta: {err}")))?;

        let assertion = self.authenticate(&mut meta, &challenge_bytes, rp_origin)?;

        let response = json!({
            "authenticator_data": URL_SAFE_NO_PAD.encode(&assertion.authenticator_data),
            "signature": URL_SAFE_NO_PAD.encode(&assertion.signature),
            "client_data_json": URL_SAFE_NO_PAD.encode(&assertion.client_data_json),
            "credential_id": meta.credential_id,
        });

        Ok(PresentationResult::Accepted {
            response_payload: Some(response.to_string()),
        })
    }

    fn import(&self, _binding: &ServiceBinding) -> Result<Vec<ImportedClaim>, ValidationError> {
        Ok(vec![]) // passkeys are registered locally, not imported
    }

    fn verify_binding(&self, binding: &ServiceBinding) -> Result<bool, ValidationError> {
        validate_passkey_binding(binding, &self.device_key_id)?;
        Ok(true)
    }
}

fn validate_passkey_binding(
    binding: &ServiceBinding,
    expected_device_key_id: &str,
) -> Result<(), ValidationError> {
    binding.validate()?;
    if binding.descriptor.adapter_kind != "passkey" {
        return Err(ValidationError::new(format!(
            "passkey adapter requires adapter_kind=passkey, got {}",
            binding.descriptor.adapter_kind
        )));
    }
    let meta: PasskeyBindingMeta = serde_json::from_str(&binding.external_account_id)
        .map_err(|err| ValidationError::new(format!("parse passkey binding meta: {err}")))?;
    if meta.device_key_id != expected_device_key_id {
        return Err(ValidationError::new(format!(
            "binding device key {} does not match adapter key {}",
            meta.device_key_id, expected_device_key_id
        )));
    }
    Ok(())
}

/// Verify a WebAuthn assertion (what an RP server would do).
/// Returns Ok(true) if the signature is valid.
pub fn verify_passkey_assertion(
    public_key_bytes: &[u8; 32],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> Result<bool, ValidationError> {
    use ed25519_dalek::{Signature as DalekSig, VerifyingKey, Verifier as DalekVerifier};

    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|err| ValidationError::new(format!("invalid public key: {err}")))?;

    let client_data_hash = sha256_digest_raw(client_data_json);
    let mut signed_payload = authenticator_data.to_vec();
    signed_payload.extend_from_slice(&client_data_hash);

    let sig = DalekSig::from_slice(signature)
        .map_err(|err| ValidationError::new(format!("invalid signature: {err}")))?;

    Ok(verifying_key.verify(&signed_payload, &sig).is_ok())
}

// ---------------------------------------------------------------------------
// WebAuthn CBOR structure helpers
// ---------------------------------------------------------------------------

fn build_client_data_json(ceremony_type: &str, challenge_b64url: &str, origin: &str) -> Vec<u8> {
    // WebAuthn spec requires this exact field order for canonical JSON.
    let json = json!({
        "type": ceremony_type,
        "challenge": challenge_b64url,
        "origin": origin,
        "crossOrigin": false,
    });
    serde_json::to_vec(&json).expect("clientDataJSON serialization cannot fail")
}

fn build_authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested_cred_data: Option<&[u8]>,
) -> Vec<u8> {
    let rp_id_hash = sha256_digest_raw(rp_id.as_bytes());
    let mut data = Vec::with_capacity(37 + attested_cred_data.map_or(0, |d| d.len()));
    data.extend_from_slice(&rp_id_hash); // 32 bytes
    data.push(flags);                     // 1 byte
    data.extend_from_slice(&sign_count.to_be_bytes()); // 4 bytes
    if let Some(acd) = attested_cred_data {
        data.extend_from_slice(acd);
    }
    data
}

fn build_attested_credential_data(
    aaguid: &[u8; 16],
    credential_id: &[u8],
    cose_public_key: &[u8],
) -> Vec<u8> {
    let cred_id_len = credential_id.len() as u16;
    let mut data = Vec::with_capacity(16 + 2 + credential_id.len() + cose_public_key.len());
    data.extend_from_slice(aaguid);
    data.extend_from_slice(&cred_id_len.to_be_bytes());
    data.extend_from_slice(credential_id);
    data.extend_from_slice(cose_public_key);
    data
}

fn build_cose_ed25519_public_key(public_key_bytes: &[u8; 32]) -> Result<Vec<u8>, ValidationError> {
    use ciborium::Value as CborValue;

    // COSE Key structure for Ed25519:
    // {1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: <public_key_bytes>}
    let cose_map = CborValue::Map(vec![
        (
            CborValue::Integer(1.into()),
            CborValue::Integer(COSE_KTY_OKP.into()),
        ),
        (
            CborValue::Integer(3.into()),
            CborValue::Integer(COSE_ALG_EDDSA.into()),
        ),
        (
            CborValue::Integer((-1i64).into()),
            CborValue::Integer(COSE_CRV_ED25519.into()),
        ),
        (
            CborValue::Integer((-2i64).into()),
            CborValue::Bytes(public_key_bytes.to_vec()),
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&cose_map, &mut buf)
        .map_err(|err| ValidationError::new(format!("CBOR encode COSE key: {err}")))?;
    Ok(buf)
}

fn build_attestation_object(auth_data: &[u8]) -> Result<Vec<u8>, ValidationError> {
    use ciborium::Value as CborValue;

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("none".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data.to_vec()),
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&att_obj, &mut buf)
        .map_err(|err| ValidationError::new(format!("CBOR encode attestation object: {err}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password_binding() -> ServiceBinding {
        ServiceBinding {
            id: "binding-password-import".into(),
            persona_id: "persona-a".into(),
            descriptor: core_types::ServiceDescriptor {
                adapter_kind: "password".into(),
                service_label: "Password Import".into(),
                endpoint: "file://import.csv".into(),
            },
            external_account_id: "local-import".into(),
            created_at: 1,
        }
    }

    #[test]
    fn bitwarden_csv_import_produces_password_claims() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nPersonal,0,login,GitHub,work account,,,https://github.com,operator,secret,ABC123\n";
        let adapter = PasswordImportAdapter::new(PasswordImportFormat::BitwardenCsv, csv);

        let claims = adapter.import(&password_binding()).unwrap();

        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].claim_type, "self-asserted");
        assert_eq!(claims[0].external_issuer, "bitwarden");
        assert!(
            claims[0]
                .payload_json
                .contains("\"schema\":\"emberlink:claim:password:1.0\"")
        );
        assert!(
            claims[0]
                .payload_json
                .contains("\"service_name\":\"GitHub\"")
        );
        assert!(
            claims[0]
                .payload_json
                .contains("\"totp_secret\":\"ABC123\"")
        );
    }

    #[test]
    fn onepassword_csv_import_extracts_otpauth_secret() {
        let csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nGitHub,https://github.com,operator,secret,otpauth://totp/GitHub?secret=ABC123&issuer=GitHub,0,0,,work account\n";
        let adapter = PasswordImportAdapter::new(PasswordImportFormat::OnePasswordCsv, csv);

        let claims = adapter.import(&password_binding()).unwrap();

        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].external_issuer, "1password");
        assert!(
            claims[0]
                .payload_json
                .contains("\"service_name\":\"GitHub\"")
        );
        assert!(
            claims[0]
                .payload_json
                .contains("\"totp_secret\":\"ABC123\"")
        );
    }

    // --- Passkey adapter tests ---

    fn fixture_passkey_adapter() -> (PasskeyAdapter, String) {
        let signer = core_crypto::FixtureSigner::new("passkey-test-device");
        let key_id = "key-passkey-test-device".to_string();
        let local_signer = core_crypto::LocalKeySigner::from_local_key_pair(
            &core_crypto::LocalKeyPair {
                key_id: key_id.clone(),
                algorithm: core_types::KeyAlgorithm::Ed25519,
                public_key: signer.public_key().0.clone(),
                private_key: fixture_private_key("passkey-test-device"),
            },
        )
        .unwrap();
        (PasskeyAdapter::new(local_signer, key_id.clone()), key_id)
    }

    fn fixture_private_key(seed_label: &str) -> String {
        // Reproduce the same derivation as FixtureSigner to get the private key hex.
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(format!("emberlink-fixture-signer:{seed_label}").as_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest[..32]);
        format!("ed25519-secret:{}", core_types::bytes_to_hex(&seed))
    }

    fn passkey_binding(meta: &PasskeyBindingMeta) -> ServiceBinding {
        ServiceBinding {
            id: "binding-passkey-github".into(),
            persona_id: "persona-a".into(),
            descriptor: core_types::ServiceDescriptor {
                adapter_kind: "passkey".into(),
                service_label: "GitHub".into(),
                endpoint: "https://github.com".into(),
            },
            external_account_id: serde_json::to_string(meta).unwrap(),
            created_at: 1,
        }
    }

    #[test]
    fn passkey_registration_produces_valid_cbor() {
        let (adapter, _key_id) = fixture_passkey_adapter();
        let challenge = b"test-challenge-32-bytes-padding!";

        let (result, meta) = adapter
            .register("github.com", "https://github.com", b"user1", "operator", challenge)
            .unwrap();

        // Credential ID should be non-empty base64url.
        assert!(!result.credential_id_b64url.is_empty());
        assert_eq!(meta.rp_id, "github.com");
        assert_eq!(meta.sign_count, 0);

        // Attestation object should be valid CBOR.
        let att: ciborium::Value =
            ciborium::from_reader(result.attestation_object.as_slice()).unwrap();
        if let ciborium::Value::Map(entries) = &att {
            let keys: Vec<_> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let ciborium::Value::Text(s) = k {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            assert!(keys.contains(&"fmt"));
            assert!(keys.contains(&"attStmt"));
            assert!(keys.contains(&"authData"));
        } else {
            panic!("attestation object is not a CBOR map");
        }

        // clientDataJSON should be valid JSON with expected fields.
        let client_data: serde_json::Value =
            serde_json::from_slice(&result.client_data_json).unwrap();
        assert_eq!(client_data["type"], "webauthn.create");
        assert_eq!(client_data["origin"], "https://github.com");
    }

    #[test]
    fn passkey_authenticate_produces_verifiable_signature() {
        let (adapter, _key_id) = fixture_passkey_adapter();
        let challenge = b"registration-challenge-padding!!";

        let (_reg_result, mut meta) = adapter
            .register("github.com", "https://github.com", b"user1", "operator", challenge)
            .unwrap();

        let auth_challenge = b"authentication-challenge-pad!!!!";
        let assertion = adapter
            .authenticate(&mut meta, auth_challenge, "https://github.com")
            .unwrap();

        assert_eq!(meta.sign_count, 1);

        // Verify the assertion using the adapter's public key.
        let pk = adapter.signer.public_key();
        let pk_bytes = public_key_raw_bytes(&pk).unwrap();
        let valid = verify_passkey_assertion(
            &pk_bytes,
            &assertion.authenticator_data,
            &assertion.client_data_json,
            &assertion.signature,
        )
        .unwrap();
        assert!(valid, "passkey assertion signature must verify");
    }

    #[test]
    fn passkey_service_adapter_present_roundtrip() {
        let (adapter, _key_id) = fixture_passkey_adapter();
        let challenge = b"registration-challenge-padding!!";

        let (_reg_result, meta) = adapter
            .register("github.com", "https://github.com", b"user1", "operator", challenge)
            .unwrap();

        let binding = passkey_binding(&meta);
        let auth_challenge = URL_SAFE_NO_PAD.encode(b"service-auth-challenge-padding!!");
        let payload = json!({
            "challenge": auth_challenge,
            "rp_origin": "https://github.com",
        });

        let result = adapter
            .present(&binding, serde_json::to_vec(&payload).unwrap().as_slice())
            .unwrap();

        match result {
            PresentationResult::Accepted {
                response_payload: Some(resp),
            } => {
                let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
                assert!(parsed["authenticator_data"].is_string());
                assert!(parsed["signature"].is_string());
                assert!(parsed["credential_id"].is_string());
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn passkey_verify_binding_rejects_wrong_adapter_kind() {
        let (adapter, _key_id) = fixture_passkey_adapter();
        let binding = ServiceBinding {
            id: "binding-wrong".into(),
            persona_id: "persona-a".into(),
            descriptor: core_types::ServiceDescriptor {
                adapter_kind: "oauth2".into(),
                service_label: "Wrong".into(),
                endpoint: "https://example.com".into(),
            },
            external_account_id: "{}".into(),
            created_at: 1,
        };
        assert!(adapter.verify_binding(&binding).is_err());
    }

    #[test]
    fn passkey_sign_count_increments() {
        let (adapter, _key_id) = fixture_passkey_adapter();
        let challenge = b"registration-challenge-padding!!";
        let (_reg_result, mut meta) = adapter
            .register("github.com", "https://github.com", b"user1", "operator", challenge)
            .unwrap();

        assert_eq!(meta.sign_count, 0);

        adapter
            .authenticate(&mut meta, b"challenge-1-padding-bytes!!!!!!!", "https://github.com")
            .unwrap();
        assert_eq!(meta.sign_count, 1);

        adapter
            .authenticate(&mut meta, b"challenge-2-padding-bytes!!!!!!!", "https://github.com")
            .unwrap();
        assert_eq!(meta.sign_count, 2);
    }

    #[test]
    fn passkey_multiple_rp_registrations() {
        let (adapter, _key_id) = fixture_passkey_adapter();

        let (_r1, meta1) = adapter
            .register("github.com", "https://github.com", b"u1", "operator", b"c1-padding-bytes!!!")
            .unwrap();
        let (_r2, meta2) = adapter
            .register("gitlab.com", "https://gitlab.com", b"u1", "operator", b"c2-padding-bytes!!!")
            .unwrap();

        assert_eq!(meta1.rp_id, "github.com");
        assert_eq!(meta2.rp_id, "gitlab.com");
        assert_ne!(meta1.credential_id, meta2.credential_id);
    }
}
