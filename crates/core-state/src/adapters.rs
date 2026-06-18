use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use core_crypto::{
    LocalKeySigner, Signer as CryptoSigner, public_key_raw_bytes, sha256_digest_raw,
};
use core_event_types::{
    ClaimType, ImportedClaim, PresentationResult, ServiceAdapter, ServiceBinding,
};
use core_types::{Validate, ValidationError};
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
    0x8b, 0x3a, 0x4e, 0xf1, 0xc7, 0x02, 0xd9, 0x5b, 0xa1, 0x6e, 0x33, 0xf8, 0x7c, 0x49, 0x10, 0xdd,
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
        let attested_cred_data =
            build_attested_credential_data(&EMBERLINK_AAGUID, &credential_id, &cose_key);

        // Build authenticator data (with attested credential data).
        let auth_data =
            build_authenticator_data(rp_id, AUTH_FLAG_UP_AT, 0, Some(&attested_cred_data));

        // Build attestation object (fmt=none).
        let attestation_object = build_attestation_object(&auth_data)?;

        // Build clientDataJSON.
        let challenge_b64url = URL_SAFE_NO_PAD.encode(challenge);
        let client_data_json =
            build_client_data_json("webauthn.create", &challenge_b64url, rp_origin);

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
    use ed25519_dalek::{Signature as DalekSig, Verifier as DalekVerifier, VerifyingKey};

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
    data.push(flags); // 1 byte
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
        (CborValue::Text("attStmt".into()), CborValue::Map(vec![])),
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

// ---------------------------------------------------------------------------
// OAuthAdapter — OAuth2 Authorization Code flow with PKCE
// ---------------------------------------------------------------------------

/// Metadata stored in `ServiceBinding.external_account_id` for OAuth bindings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OAuthBindingMeta {
    /// OAuth2 client identifier registered with the provider.
    pub client_id: String,
    /// Authorization endpoint URL (e.g., `<https://accounts.google.com/o/oauth2/v2/auth>`).
    pub authorization_endpoint: String,
    /// Token endpoint URL (e.g., `<https://oauth2.googleapis.com/token>`).
    pub token_endpoint: String,
    /// Redirect URI registered with the provider.
    pub redirect_uri: String,
    /// Space-separated OAuth scopes (e.g., "openid profile email").
    pub scopes: String,
}

/// Request to start an OAuth2 authorization flow.
/// Returned from `present()` when action is "authorize".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OAuthAuthorizeRequest {
    /// Full authorization URL the caller should redirect to.
    pub authorization_url: String,
    /// PKCE code verifier — caller must store this and send it back in the exchange step.
    pub code_verifier: String,
    /// State parameter for CSRF protection.
    pub state: String,
}

/// Request to exchange an authorization code for tokens.
/// Returned from `present()` when action is "exchange".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OAuthTokenExchangeRequest {
    /// Token endpoint URL to POST to.
    pub token_endpoint: String,
    /// Form-encoded body parameters for the token exchange.
    pub body_params: BTreeMap<String, String>,
}

/// Result of parsing an OIDC ID token's claims.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OAuthTokenClaims {
    pub subject: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub issuer: Option<String>,
    pub issued_at: Option<u64>,
    pub expires_at: Option<u64>,
}

/// OAuth2 adapter implementing the ServiceAdapter trait.
///
/// This adapter does NOT make HTTP calls. It builds authorization URLs and
/// token exchange request parameters. The caller (CLI, GUI, extension) is
/// responsible for executing the actual HTTP requests.
#[derive(Debug, Clone, Copy, Default)]
pub struct OAuthAdapter;

impl OAuthAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Build an OAuth2 authorization URL with PKCE S256 challenge.
    pub fn build_authorize_request(
        meta: &OAuthBindingMeta,
    ) -> Result<OAuthAuthorizeRequest, ValidationError> {
        // Generate code_verifier: 32 random bytes, base64url-encoded (43-128 chars per RFC 7636).
        let random_id = core_crypto::generate_random_identifier("pkce");
        let verifier_bytes = sha256_digest_raw(random_id.as_bytes());
        let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        // code_challenge = BASE64URL(SHA256(code_verifier))
        let challenge_hash = sha256_digest_raw(code_verifier.as_bytes());
        let code_challenge = URL_SAFE_NO_PAD.encode(challenge_hash);

        // State parameter for CSRF protection.
        let state_id = core_crypto::generate_random_identifier("state");
        let state = URL_SAFE_NO_PAD.encode(sha256_digest_raw(state_id.as_bytes()));

        let authorization_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&state={}",
            meta.authorization_endpoint,
            urlencoding::encode(&meta.client_id),
            urlencoding::encode(&meta.redirect_uri),
            urlencoding::encode(&meta.scopes),
            urlencoding::encode(&code_challenge),
            urlencoding::encode(&state),
        );

        Ok(OAuthAuthorizeRequest {
            authorization_url,
            code_verifier,
            state,
        })
    }

    /// Build a token exchange request from an authorization code and PKCE verifier.
    pub fn build_token_exchange_request(
        meta: &OAuthBindingMeta,
        code: &str,
        code_verifier: &str,
    ) -> Result<OAuthTokenExchangeRequest, ValidationError> {
        if code.is_empty() {
            return Err(ValidationError::new("authorization code must not be empty"));
        }
        if code_verifier.is_empty() {
            return Err(ValidationError::new("code_verifier must not be empty"));
        }

        let mut body_params = BTreeMap::new();
        body_params.insert("grant_type".into(), "authorization_code".into());
        body_params.insert("code".into(), code.into());
        body_params.insert("redirect_uri".into(), meta.redirect_uri.clone());
        body_params.insert("client_id".into(), meta.client_id.clone());
        body_params.insert("code_verifier".into(), code_verifier.into());

        Ok(OAuthTokenExchangeRequest {
            token_endpoint: meta.token_endpoint.clone(),
            body_params,
        })
    }

    /// Parse the claims portion of an OIDC ID token (JWT payload, already base64url-decoded).
    /// This does NOT verify the JWT signature — the caller should verify with the provider's JWK.
    pub fn parse_id_token_claims(id_token_jwt: &str) -> Result<OAuthTokenClaims, ValidationError> {
        // JWT format: header.payload.signature — we extract the payload.
        let parts: Vec<&str> = id_token_jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(ValidationError::new(
                "invalid JWT format: expected header.payload.signature",
            ));
        }
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|err| ValidationError::new(format!("decode JWT payload: {err}")))?;
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|err| ValidationError::new(format!("parse JWT payload JSON: {err}")))?;

        Ok(OAuthTokenClaims {
            subject: payload["sub"].as_str().map(String::from),
            email: payload["email"].as_str().map(String::from),
            name: payload["name"].as_str().map(String::from),
            issuer: payload["iss"].as_str().map(String::from),
            issued_at: payload["iat"].as_u64(),
            expires_at: payload["exp"].as_u64(),
        })
    }
}

fn validate_oauth_binding(binding: &ServiceBinding) -> Result<OAuthBindingMeta, ValidationError> {
    binding.validate()?;
    if binding.descriptor.adapter_kind != "oauth2" {
        return Err(ValidationError::new(format!(
            "oauth adapter requires adapter_kind=oauth2, got {}",
            binding.descriptor.adapter_kind
        )));
    }
    let meta: OAuthBindingMeta = serde_json::from_str(&binding.external_account_id)
        .map_err(|err| ValidationError::new(format!("parse oauth binding meta: {err}")))?;
    if meta.client_id.is_empty() {
        return Err(ValidationError::new("oauth binding client_id is empty"));
    }
    if meta.authorization_endpoint.is_empty() {
        return Err(ValidationError::new(
            "oauth binding authorization_endpoint is empty",
        ));
    }
    if meta.token_endpoint.is_empty() {
        return Err(ValidationError::new(
            "oauth binding token_endpoint is empty",
        ));
    }
    Ok(meta)
}

impl ServiceAdapter for OAuthAdapter {
    fn present(
        &self,
        binding: &ServiceBinding,
        disclosure_payload: &[u8],
    ) -> Result<PresentationResult, ValidationError> {
        let meta = validate_oauth_binding(binding)?;

        let request: serde_json::Value = serde_json::from_slice(disclosure_payload)
            .map_err(|err| ValidationError::new(format!("parse oauth request: {err}")))?;

        let action = request["action"]
            .as_str()
            .ok_or_else(|| ValidationError::new("missing 'action' in oauth request"))?;

        match action {
            "authorize" => {
                let auth_req = Self::build_authorize_request(&meta)?;
                Ok(PresentationResult::Accepted {
                    response_payload: Some(serde_json::to_string(&auth_req).map_err(|err| {
                        ValidationError::new(format!("serialize authorize response: {err}"))
                    })?),
                })
            }
            "exchange" => {
                let code = request["code"]
                    .as_str()
                    .ok_or_else(|| ValidationError::new("missing 'code' in exchange request"))?;
                let code_verifier = request["code_verifier"].as_str().ok_or_else(|| {
                    ValidationError::new("missing 'code_verifier' in exchange request")
                })?;
                let exchange_req = Self::build_token_exchange_request(&meta, code, code_verifier)?;
                Ok(PresentationResult::Accepted {
                    response_payload: Some(serde_json::to_string(&exchange_req).map_err(
                        |err| ValidationError::new(format!("serialize exchange response: {err}")),
                    )?),
                })
            }
            other => Ok(PresentationResult::Rejected {
                reason: format!("unknown oauth action: {other}"),
            }),
        }
    }

    fn import(&self, binding: &ServiceBinding) -> Result<Vec<ImportedClaim>, ValidationError> {
        let meta = validate_oauth_binding(binding)?;

        // Import parses an OIDC ID token stored in the binding's descriptor endpoint
        // as a fallback. In practice, the caller passes token responses through present().
        // Here we return empty — tokens are ephemeral and not directly importable.
        let _ = meta;
        Ok(vec![])
    }

    fn verify_binding(&self, binding: &ServiceBinding) -> Result<bool, ValidationError> {
        validate_oauth_binding(binding)?;
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// OidcClaimAdapter — Translates Emberlink disclosure artifacts into OIDC claims
// ---------------------------------------------------------------------------

/// Standard OIDC claim names that Emberlink disclosure fields can map to.
const OIDC_CLAIM_MAPPINGS: &[(&str, &str)] = &[
    ("full_name", "name"),
    ("name", "name"),
    ("given_name", "given_name"),
    ("first_name", "given_name"),
    ("family_name", "family_name"),
    ("last_name", "family_name"),
    ("email", "email"),
    ("email_address", "email"),
    ("phone", "phone_number"),
    ("phone_number", "phone_number"),
    ("birthdate", "birthdate"),
    ("date_of_birth", "birthdate"),
    ("address", "address"),
    ("picture", "picture"),
    ("profile_url", "profile"),
    ("website", "website"),
    ("gender", "gender"),
    ("locale", "locale"),
    ("timezone", "zoneinfo"),
    ("zoneinfo", "zoneinfo"),
    ("nickname", "nickname"),
    ("preferred_username", "preferred_username"),
    ("username", "preferred_username"),
];

/// Adapter that translates Emberlink disclosure artifacts into OIDC-compatible
/// claim sets for presentation to relying parties.
///
/// The adapter receives a disclosure payload (JSON with Emberlink field names)
/// and maps recognized fields to standard OIDC claim names (RFC 5.1).
#[derive(Debug, Clone, Copy, Default)]
pub struct OidcClaimAdapter;

impl OidcClaimAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Map Emberlink disclosure fields to standard OIDC claim names.
    /// Unknown fields are passed through with an "emberlink:" prefix.
    pub fn map_to_oidc_claims(
        disclosure_fields: &serde_json::Value,
    ) -> Result<serde_json::Value, ValidationError> {
        let obj = disclosure_fields
            .as_object()
            .ok_or_else(|| ValidationError::new("disclosure payload must be a JSON object"))?;

        let mut oidc_claims = serde_json::Map::new();

        for (key, value) in obj {
            let oidc_key = OIDC_CLAIM_MAPPINGS
                .iter()
                .find(|(ember_name, _)| *ember_name == key.as_str())
                .map(|(_, oidc_name)| (*oidc_name).to_string())
                .unwrap_or_else(|| format!("emberlink:{key}"));

            oidc_claims.insert(oidc_key, value.clone());
        }

        Ok(serde_json::Value::Object(oidc_claims))
    }

    /// Parse an OIDC ID token and convert its claims into ImportedClaims.
    pub fn import_id_token(
        id_token_jwt: &str,
        provider_label: &str,
    ) -> Result<Vec<ImportedClaim>, ValidationError> {
        let claims = OAuthAdapter::parse_id_token_claims(id_token_jwt)?;
        let mut imported = Vec::new();

        if let Some(ref email) = claims.email {
            imported.push(ImportedClaim {
                claim_type: ClaimType::ServiceIssued.as_str().into(),
                payload_json: json!({
                    "schema": "emberlink:claim:email:1.0",
                    "email": email,
                })
                .to_string(),
                external_issuer: provider_label.into(),
                external_issued_at: claims.issued_at,
                external_expires_at: claims.expires_at,
            });
        }

        if let Some(ref name) = claims.name {
            imported.push(ImportedClaim {
                claim_type: ClaimType::ServiceIssued.as_str().into(),
                payload_json: json!({
                    "schema": "emberlink:claim:name:1.0",
                    "name": name,
                })
                .to_string(),
                external_issuer: provider_label.into(),
                external_issued_at: claims.issued_at,
                external_expires_at: claims.expires_at,
            });
        }

        if let Some(ref subject) = claims.subject {
            imported.push(ImportedClaim {
                claim_type: ClaimType::ServiceIssued.as_str().into(),
                payload_json: json!({
                    "schema": "emberlink:claim:oidc-subject:1.0",
                    "subject": subject,
                    "issuer": claims.issuer,
                })
                .to_string(),
                external_issuer: provider_label.into(),
                external_issued_at: claims.issued_at,
                external_expires_at: claims.expires_at,
            });
        }

        Ok(imported)
    }
}

fn validate_oidc_binding(binding: &ServiceBinding) -> Result<(), ValidationError> {
    binding.validate()?;
    if binding.descriptor.adapter_kind != "oidc" {
        return Err(ValidationError::new(format!(
            "oidc claim adapter requires adapter_kind=oidc, got {}",
            binding.descriptor.adapter_kind
        )));
    }
    Ok(())
}

impl ServiceAdapter for OidcClaimAdapter {
    fn present(
        &self,
        binding: &ServiceBinding,
        disclosure_payload: &[u8],
    ) -> Result<PresentationResult, ValidationError> {
        validate_oidc_binding(binding)?;

        let fields: serde_json::Value = serde_json::from_slice(disclosure_payload)
            .map_err(|err| ValidationError::new(format!("parse oidc disclosure: {err}")))?;

        let oidc_claims = Self::map_to_oidc_claims(&fields)?;

        Ok(PresentationResult::Accepted {
            response_payload: Some(
                serde_json::to_string(&oidc_claims)
                    .map_err(|err| ValidationError::new(format!("serialize oidc claims: {err}")))?,
            ),
        })
    }

    fn import(&self, binding: &ServiceBinding) -> Result<Vec<ImportedClaim>, ValidationError> {
        validate_oidc_binding(binding)?;
        // OIDC import happens through OAuthAdapter's token flow + import_id_token.
        Ok(vec![])
    }

    fn verify_binding(&self, binding: &ServiceBinding) -> Result<bool, ValidationError> {
        validate_oidc_binding(binding)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password_binding() -> ServiceBinding {
        ServiceBinding {
            id: "binding-password-import".into(),
            persona_id: "persona-a".into(),
            descriptor: core_event_types::ServiceDescriptor {
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
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nPersonal,0,login,GitHub,work account,,,https://github.com,alice,secret,ABC123\n";
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
        let csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nGitHub,https://github.com,alice,secret,otpauth://totp/GitHub?secret=ABC123&issuer=GitHub,0,0,,work account\n";
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
        let local_signer =
            core_crypto::LocalKeySigner::from_local_key_pair(&core_crypto::LocalKeyPair {
                key_id: key_id.clone(),
                algorithm: core_principals::KeyAlgorithm::Ed25519,
                public_key: signer.public_key().0.clone(),
                private_key: fixture_private_key("passkey-test-device"),
            })
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
            descriptor: core_event_types::ServiceDescriptor {
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
            .register(
                "github.com",
                "https://github.com",
                b"user1",
                "alice",
                challenge,
            )
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
            .register(
                "github.com",
                "https://github.com",
                b"user1",
                "alice",
                challenge,
            )
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
            .register(
                "github.com",
                "https://github.com",
                b"user1",
                "alice",
                challenge,
            )
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
            descriptor: core_event_types::ServiceDescriptor {
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
            .register(
                "github.com",
                "https://github.com",
                b"user1",
                "alice",
                challenge,
            )
            .unwrap();

        assert_eq!(meta.sign_count, 0);

        adapter
            .authenticate(
                &mut meta,
                b"challenge-1-padding-bytes!!!!!!!",
                "https://github.com",
            )
            .unwrap();
        assert_eq!(meta.sign_count, 1);

        adapter
            .authenticate(
                &mut meta,
                b"challenge-2-padding-bytes!!!!!!!",
                "https://github.com",
            )
            .unwrap();
        assert_eq!(meta.sign_count, 2);
    }

    #[test]
    fn passkey_multiple_rp_registrations() {
        let (adapter, _key_id) = fixture_passkey_adapter();

        let (_r1, meta1) = adapter
            .register(
                "github.com",
                "https://github.com",
                b"u1",
                "alice",
                b"c1-padding-bytes!!!",
            )
            .unwrap();
        let (_r2, meta2) = adapter
            .register(
                "gitlab.com",
                "https://gitlab.com",
                b"u1",
                "alice",
                b"c2-padding-bytes!!!",
            )
            .unwrap();

        assert_eq!(meta1.rp_id, "github.com");
        assert_eq!(meta2.rp_id, "gitlab.com");
        assert_ne!(meta1.credential_id, meta2.credential_id);
    }

    // --- OAuth adapter tests ---

    fn oauth_binding_meta() -> OAuthBindingMeta {
        OAuthBindingMeta {
            client_id: "test-client-id".into(),
            authorization_endpoint: "https://auth.example.com/authorize".into(),
            token_endpoint: "https://auth.example.com/token".into(),
            redirect_uri: "http://localhost:8080/callback".into(),
            scopes: "openid profile email".into(),
        }
    }

    fn oauth_binding() -> ServiceBinding {
        ServiceBinding {
            id: "binding-oauth-github".into(),
            persona_id: "persona-a".into(),
            descriptor: core_event_types::ServiceDescriptor {
                adapter_kind: "oauth2".into(),
                service_label: "GitHub".into(),
                endpoint: "https://github.com".into(),
            },
            external_account_id: serde_json::to_string(&oauth_binding_meta()).unwrap(),
            created_at: 1,
        }
    }

    #[test]
    fn oauth_authorize_builds_valid_url() {
        let meta = oauth_binding_meta();
        let req = OAuthAdapter::build_authorize_request(&meta).unwrap();

        assert!(
            req.authorization_url
                .starts_with("https://auth.example.com/authorize?")
        );
        assert!(req.authorization_url.contains("response_type=code"));
        assert!(req.authorization_url.contains("client_id=test-client-id"));
        assert!(req.authorization_url.contains("code_challenge_method=S256"));
        assert!(
            req.authorization_url
                .contains("scope=openid%20profile%20email")
        );
        assert!(!req.code_verifier.is_empty());
        assert!(!req.state.is_empty());
    }

    #[test]
    fn oauth_authorize_pkce_verifier_differs_each_call() {
        let meta = oauth_binding_meta();
        let req1 = OAuthAdapter::build_authorize_request(&meta).unwrap();
        let req2 = OAuthAdapter::build_authorize_request(&meta).unwrap();
        assert_ne!(req1.code_verifier, req2.code_verifier);
        assert_ne!(req1.state, req2.state);
    }

    #[test]
    fn oauth_token_exchange_builds_correct_params() {
        let meta = oauth_binding_meta();
        let req =
            OAuthAdapter::build_token_exchange_request(&meta, "auth-code-123", "verifier-abc")
                .unwrap();

        assert_eq!(req.token_endpoint, "https://auth.example.com/token");
        assert_eq!(req.body_params["grant_type"], "authorization_code");
        assert_eq!(req.body_params["code"], "auth-code-123");
        assert_eq!(req.body_params["code_verifier"], "verifier-abc");
        assert_eq!(req.body_params["client_id"], "test-client-id");
        assert_eq!(
            req.body_params["redirect_uri"],
            "http://localhost:8080/callback"
        );
    }

    #[test]
    fn oauth_token_exchange_rejects_empty_code() {
        let meta = oauth_binding_meta();
        let err = OAuthAdapter::build_token_exchange_request(&meta, "", "verifier").unwrap_err();
        assert!(err.to_string().contains("authorization code"));
    }

    #[test]
    fn oauth_token_exchange_rejects_empty_verifier() {
        let meta = oauth_binding_meta();
        let err = OAuthAdapter::build_token_exchange_request(&meta, "code", "").unwrap_err();
        assert!(err.to_string().contains("code_verifier"));
    }

    #[test]
    fn oauth_parse_id_token_claims() {
        // Build a fake JWT with base64url-encoded header.payload.signature.
        let header = URL_SAFE_NO_PAD.encode(b"{}");
        let payload_json = json!({
            "sub": "user-123",
            "email": "alice@example.com",
            "name": "Alice Example",
            "iss": "https://auth.example.com",
            "iat": 1700000000u64,
            "exp": 1700003600u64,
        });
        let payload = URL_SAFE_NO_PAD.encode(payload_json.to_string().as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(b"fake-sig");
        let jwt = format!("{header}.{payload}.{signature}");

        let claims = OAuthAdapter::parse_id_token_claims(&jwt).unwrap();
        assert_eq!(claims.subject.as_deref(), Some("user-123"));
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(claims.name.as_deref(), Some("Alice Example"));
        assert_eq!(claims.issuer.as_deref(), Some("https://auth.example.com"));
        assert_eq!(claims.issued_at, Some(1700000000));
        assert_eq!(claims.expires_at, Some(1700003600));
    }

    #[test]
    fn oauth_parse_id_token_rejects_invalid_jwt() {
        assert!(OAuthAdapter::parse_id_token_claims("not-a-jwt").is_err());
        assert!(OAuthAdapter::parse_id_token_claims("a.b").is_err());
    }

    #[test]
    fn oauth_service_adapter_authorize_roundtrip() {
        let adapter = OAuthAdapter::new();
        let binding = oauth_binding();
        let payload = json!({"action": "authorize"});

        let result = adapter
            .present(&binding, serde_json::to_vec(&payload).unwrap().as_slice())
            .unwrap();

        match result {
            PresentationResult::Accepted {
                response_payload: Some(resp),
            } => {
                let parsed: OAuthAuthorizeRequest = serde_json::from_str(&resp).unwrap();
                assert!(parsed.authorization_url.contains("response_type=code"));
                assert!(!parsed.code_verifier.is_empty());
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn oauth_service_adapter_exchange_roundtrip() {
        let adapter = OAuthAdapter::new();
        let binding = oauth_binding();
        let payload = json!({
            "action": "exchange",
            "code": "auth-code-xyz",
            "code_verifier": "verifier-abc",
        });

        let result = adapter
            .present(&binding, serde_json::to_vec(&payload).unwrap().as_slice())
            .unwrap();

        match result {
            PresentationResult::Accepted {
                response_payload: Some(resp),
            } => {
                let parsed: OAuthTokenExchangeRequest = serde_json::from_str(&resp).unwrap();
                assert_eq!(parsed.body_params["code"], "auth-code-xyz");
                assert_eq!(parsed.body_params["code_verifier"], "verifier-abc");
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn oauth_service_adapter_rejects_unknown_action() {
        let adapter = OAuthAdapter::new();
        let binding = oauth_binding();
        let payload = json!({"action": "unknown"});

        let result = adapter
            .present(&binding, serde_json::to_vec(&payload).unwrap().as_slice())
            .unwrap();

        assert!(matches!(result, PresentationResult::Rejected { .. }));
    }

    #[test]
    fn oauth_verify_binding_rejects_wrong_adapter_kind() {
        let adapter = OAuthAdapter::new();
        let binding = ServiceBinding {
            id: "binding-wrong".into(),
            persona_id: "persona-a".into(),
            descriptor: core_event_types::ServiceDescriptor {
                adapter_kind: "passkey".into(),
                service_label: "Wrong".into(),
                endpoint: "https://example.com".into(),
            },
            external_account_id: "{}".into(),
            created_at: 1,
        };
        assert!(adapter.verify_binding(&binding).is_err());
    }

    // --- OIDC claim adapter tests ---

    fn oidc_binding() -> ServiceBinding {
        ServiceBinding {
            id: "binding-oidc-google".into(),
            persona_id: "persona-a".into(),
            descriptor: core_event_types::ServiceDescriptor {
                adapter_kind: "oidc".into(),
                service_label: "Google".into(),
                endpoint: "https://accounts.google.com".into(),
            },
            external_account_id: "google-user-123".into(),
            created_at: 1,
        }
    }

    #[test]
    fn oidc_maps_standard_fields() {
        let disclosure = json!({
            "full_name": "Alice Example",
            "email": "alice@example.com",
            "phone": "+1-555-0100",
            "birthdate": "1990-01-01",
        });

        let oidc = OidcClaimAdapter::map_to_oidc_claims(&disclosure).unwrap();
        let obj = oidc.as_object().unwrap();

        assert_eq!(obj["name"], "Alice Example");
        assert_eq!(obj["email"], "alice@example.com");
        assert_eq!(obj["phone_number"], "+1-555-0100");
        assert_eq!(obj["birthdate"], "1990-01-01");
    }

    #[test]
    fn oidc_prefixes_unknown_fields() {
        let disclosure = json!({
            "email": "alice@example.com",
            "custom_field": "custom_value",
        });

        let oidc = OidcClaimAdapter::map_to_oidc_claims(&disclosure).unwrap();
        let obj = oidc.as_object().unwrap();

        assert_eq!(obj["email"], "alice@example.com");
        assert_eq!(obj["emberlink:custom_field"], "custom_value");
    }

    #[test]
    fn oidc_rejects_non_object_payload() {
        let disclosure = json!("not an object");
        assert!(OidcClaimAdapter::map_to_oidc_claims(&disclosure).is_err());
    }

    #[test]
    fn oidc_service_adapter_present_roundtrip() {
        let adapter = OidcClaimAdapter::new();
        let binding = oidc_binding();
        let payload = json!({
            "full_name": "Alice Example",
            "email": "alice@example.com",
        });

        let result = adapter
            .present(&binding, serde_json::to_vec(&payload).unwrap().as_slice())
            .unwrap();

        match result {
            PresentationResult::Accepted {
                response_payload: Some(resp),
            } => {
                let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
                assert_eq!(parsed["name"], "Alice Example");
                assert_eq!(parsed["email"], "alice@example.com");
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn oidc_verify_binding_rejects_wrong_adapter_kind() {
        let adapter = OidcClaimAdapter::new();
        let binding = ServiceBinding {
            id: "binding-wrong".into(),
            persona_id: "persona-a".into(),
            descriptor: core_event_types::ServiceDescriptor {
                adapter_kind: "oauth2".into(),
                service_label: "Wrong".into(),
                endpoint: "https://example.com".into(),
            },
            external_account_id: "id".into(),
            created_at: 1,
        };
        assert!(adapter.verify_binding(&binding).is_err());
    }

    #[test]
    fn oidc_import_id_token_produces_claims() {
        let header = URL_SAFE_NO_PAD.encode(b"{}");
        let payload_json = json!({
            "sub": "user-456",
            "email": "bob@example.com",
            "name": "Bob Example",
            "iss": "https://accounts.google.com",
            "iat": 1700000000u64,
            "exp": 1700003600u64,
        });
        let payload = URL_SAFE_NO_PAD.encode(payload_json.to_string().as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(b"fake-sig");
        let jwt = format!("{header}.{payload}.{signature}");

        let claims = OidcClaimAdapter::import_id_token(&jwt, "google").unwrap();

        assert_eq!(claims.len(), 3); // email, name, subject
        assert!(
            claims
                .iter()
                .any(|c| c.payload_json.contains("bob@example.com"))
        );
        assert!(
            claims
                .iter()
                .any(|c| c.payload_json.contains("Bob Example"))
        );
        assert!(claims.iter().any(|c| c.payload_json.contains("user-456")));
        assert!(claims.iter().all(|c| c.external_issuer == "google"));
        assert!(claims.iter().all(|c| c.claim_type == "service-issued"));
    }
}
