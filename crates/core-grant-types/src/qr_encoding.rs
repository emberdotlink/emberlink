//! QR-compatible encoding for sealed grant offers.
//!
//! Offline grant exchange (subway stickers, business cards) needs the full
//! sealed offer payload in a QR code — no relay required. This module encodes
//! the offer as CBOR + Base45, which is alphanumeric-safe and QR-efficient.
//!
//! # Size budget
//!
//! QR version 25, error-correction level M: 1853 alphanumeric characters.
//! We enforce a conservative 1800-character limit to leave headroom.
//!
//! # Wire format
//!
//! ```text
//! EL1:<base45(cbor(SealedOffer))>
//! ```
//!
//! The `EL1:` prefix identifies the format version and makes the QR scannable
//! as a non-URL string (prevents apps from misinterpreting it as a URL).

use serde::{Deserialize, Serialize};

use core_types::ValidationError;

/// Maximum alphanumeric characters that fit in a QR version 25 code at
/// error-correction level M (1853 chars). We use 1800 to leave headroom.
pub const QR_MAX_ALPHANUMERIC_CHARS: usize = 1800;

/// Human-readable prefix that appears before the base45-encoded payload.
/// `EL` = Emberlink, `1` = format version.
pub const QR_PREFIX: &str = "EL1:";

/// The sealed offer payload that travels in a QR code.
///
/// Contains everything a recipient needs to claim a grant without network
/// access or relay coordination. The `sealed_payload_hex` is the encrypted
/// grant parameters; only the holder of the ephemeral private key (the
/// issuer) can later validate the claim response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedOffer {
    /// Unique offer identifier. Format: `offer-{ulid}`.
    pub offer_id: String,
    /// Hex-encoded ephemeral public key. The sealed payload is encrypted
    /// to the corresponding private key.
    pub ephemeral_public_key_hex: String,
    /// Hex-encoded sealed grant payload (encrypted grant parameters).
    pub sealed_payload_hex: String,
    /// Expiry timestamp (epoch seconds).
    pub expires_at: u64,
    /// Issuer's signature over `offer_id|ek_hex|expires_at`.
    pub issuer_signature: String,
}

/// Error type for QR encoding/decoding failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrError(pub String);

impl QrError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl core::fmt::Display for QrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<QrError> for ValidationError {
    fn from(e: QrError) -> Self {
        ValidationError::invalid_format(e.0)
    }
}

/// Encode a [`SealedOffer`] to a QR-ready alphanumeric string.
///
/// Output format: `EL1:<base45(cbor(offer))>`
///
/// Returns `Err` if the payload exceeds the QR size budget.
pub fn encode_sealed_offer(offer: &SealedOffer) -> Result<String, QrError> {
    // Serialize to CBOR
    let cbor_bytes = to_cbor(offer)?;

    // Encode with Base45
    let b45 = base45::encode(&cbor_bytes);

    // Prepend version prefix
    let qr_string = format!("{QR_PREFIX}{b45}");

    // Validate size budget
    if qr_string.len() > QR_MAX_ALPHANUMERIC_CHARS {
        return Err(QrError::new(format!(
            "encoded offer is {} chars, exceeds QR v25 budget of {} chars",
            qr_string.len(),
            QR_MAX_ALPHANUMERIC_CHARS
        )));
    }

    Ok(qr_string)
}

/// Maximum raw input length accepted by [`decode_sealed_offer`].
///
/// Slightly above the encode-side cap (`QR_MAX_ALPHANUMERIC_CHARS = 1800`) to
/// tolerate minor trailing whitespace while still rejecting oversized payloads
/// that could exhaust memory during Base45/CBOR processing.
pub const QR_DECODE_MAX_INPUT_LEN: usize = 2000;

/// Upper bound on decoded CBOR bytes we will accept. Base45 expands roughly
/// 3:2, so 2000 input chars → ~1334 decoded bytes. We allow 1500 as headroom.
const CBOR_MAX_DECODED_BYTES: usize = 1500;

/// Maximum allowed length for individual string fields inside a decoded
/// [`SealedOffer`]. Hex-encoded X25519 keys are 64 chars; sealed payloads and
/// signatures should be well under 1024. We use 1024 as a generous ceiling.
const FIELD_MAX_LEN: usize = 1024;

/// Decode a QR string back to a [`SealedOffer`].
///
/// Expects format: `EL1:<base45(cbor(offer))>`
///
/// Enforces size limits at every stage to prevent memory exhaustion from
/// oversized or malicious input (see security finding C-H2).
pub fn decode_sealed_offer(qr_string: &str) -> Result<SealedOffer, QrError> {
    // 1. Hard length check on raw input before any processing.
    if qr_string.len() > QR_DECODE_MAX_INPUT_LEN {
        return Err(QrError::new(format!(
            "input length {} exceeds decode limit of {} chars",
            qr_string.len(),
            QR_DECODE_MAX_INPUT_LEN
        )));
    }

    // 2. Strip the version prefix.
    let b45 = qr_string
        .strip_prefix(QR_PREFIX)
        .ok_or_else(|| QrError::new(format!("missing prefix '{QR_PREFIX}'")))?;

    // 3. Decode Base45.
    let cbor_bytes =
        base45::decode(b45).map_err(|e| QrError::new(format!("base45 decode error: {e}")))?;

    // 4. Bounded CBOR size check.
    if cbor_bytes.len() > CBOR_MAX_DECODED_BYTES {
        return Err(QrError::new(format!(
            "decoded CBOR payload is {} bytes, exceeds limit of {} bytes",
            cbor_bytes.len(),
            CBOR_MAX_DECODED_BYTES
        )));
    }

    // 5. Deserialize from CBOR.
    let offer: SealedOffer = from_cbor(&cbor_bytes)?;

    // 6. Field-level validation — reject offers with abnormally large fields.
    validate_field_len("offer_id", &offer.offer_id)?;
    validate_field_len("ephemeral_public_key_hex", &offer.ephemeral_public_key_hex)?;
    validate_field_len("sealed_payload_hex", &offer.sealed_payload_hex)?;
    validate_field_len("issuer_signature", &offer.issuer_signature)?;

    Ok(offer)
}

/// Reject individual fields that exceed the safety ceiling.
fn validate_field_len(name: &str, value: &str) -> Result<(), QrError> {
    if value.len() > FIELD_MAX_LEN {
        return Err(QrError::new(format!(
            "field '{name}' is {} chars, exceeds limit of {FIELD_MAX_LEN}",
            value.len()
        )));
    }
    Ok(())
}

// --- CBOR helpers ---

fn to_cbor(offer: &SealedOffer) -> Result<Vec<u8>, QrError> {
    let mut buf = Vec::new();
    ciborium::into_writer(offer, &mut buf)
        .map_err(|e| QrError::new(format!("CBOR encode error: {e}")))?;
    Ok(buf)
}

fn from_cbor(bytes: &[u8]) -> Result<SealedOffer, QrError> {
    ciborium::from_reader(bytes).map_err(|e| QrError::new(format!("CBOR decode error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_offer() -> SealedOffer {
        SealedOffer {
            offer_id: "offer-abc123".to_string(),
            ephemeral_public_key_hex: "deadbeef01020304".to_string(),
            sealed_payload_hex: "cafebabe0a0b0c0d".to_string(),
            expires_at: 1700000000,
            issuer_signature: "sig0011aabb".to_string(),
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let offer = sample_offer();
        let qr = encode_sealed_offer(&offer).expect("encode should succeed");
        assert!(
            qr.starts_with(QR_PREFIX),
            "encoded string must start with prefix"
        );
        let decoded = decode_sealed_offer(&qr).expect("decode should succeed");
        assert_eq!(decoded, offer);
    }

    #[test]
    fn encoded_string_is_alphanumeric_plus_colon() {
        let offer = sample_offer();
        let qr = encode_sealed_offer(&offer).unwrap();
        // QR alphanumeric mode supports: 0-9, A-Z, space, $%*+-./:
        // Base45 uses 0-9, A-Z, space, $%*+-./ — all valid in QR alphanumeric.
        // Our prefix adds ':' which is also valid.
        let invalid: Vec<char> = qr
            .chars()
            .filter(|c| !c.is_ascii_alphanumeric() && !" $%*+-./:".contains(*c))
            .collect();
        assert!(
            invalid.is_empty(),
            "encoded string contains chars invalid for QR alphanumeric mode: {invalid:?}"
        );
    }

    #[test]
    fn within_qr_size_budget() {
        let offer = sample_offer();
        let qr = encode_sealed_offer(&offer).unwrap();
        assert!(
            qr.len() <= QR_MAX_ALPHANUMERIC_CHARS,
            "sample offer encodes to {} chars, exceeds budget of {}",
            qr.len(),
            QR_MAX_ALPHANUMERIC_CHARS
        );
    }

    #[test]
    fn oversized_payload_rejected() {
        let mut offer = sample_offer();
        // Generate a payload that will definitely exceed the QR budget
        offer.sealed_payload_hex = "ab".repeat(2000);
        let result = encode_sealed_offer(&offer);
        assert!(result.is_err(), "oversized offer should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.0.contains("exceeds QR"),
            "error message should mention QR budget: {err}"
        );
    }

    #[test]
    fn missing_prefix_rejected() {
        let result = decode_sealed_offer("NOPREFIX:SOMEDATA");
        assert!(result.is_err());
        assert!(result.unwrap_err().0.contains("missing prefix"));
    }

    #[test]
    fn invalid_base45_rejected() {
        // EL1: prefix followed by bytes that aren't valid base45
        let result = decode_sealed_offer("EL1:\x00\x01\x02");
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_oversized_input() {
        // Input exceeding QR_DECODE_MAX_INPUT_LEN must be rejected before
        // any Base45/CBOR processing occurs.
        let oversized = format!("EL1:{}", "A".repeat(QR_DECODE_MAX_INPUT_LEN));
        let result = decode_sealed_offer(&oversized);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.0.contains("exceeds decode limit"),
            "expected decode-limit error, got: {err}"
        );
    }

    #[test]
    fn decode_rejects_oversized_field() {
        // Craft an offer with a single field exceeding FIELD_MAX_LEN, but
        // small enough to pass the raw-input and CBOR-size checks.
        let mut offer = sample_offer();
        offer.sealed_payload_hex = "ab".repeat(600); // 1200 chars > FIELD_MAX_LEN (1024)
        // Encode via CBOR+Base45 manually to bypass encode-side size check
        let cbor = {
            let mut buf = Vec::new();
            ciborium::into_writer(&offer, &mut buf).unwrap();
            buf
        };
        let b45 = base45::encode(&cbor);
        let qr = format!("{QR_PREFIX}{b45}");
        // Only test if the crafted payload fits within the decode input limit
        if qr.len() <= QR_DECODE_MAX_INPUT_LEN {
            let result = decode_sealed_offer(&qr);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                err.0.contains("exceeds limit"),
                "expected field-limit error, got: {err}"
            );
        }
    }

    mod property_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn round_trip_arbitrary(
                offer_id in "[a-z0-9-]{5,20}",
                ek_hex in "[0-9a-f]{16,64}",
                sealed_hex in "[0-9a-f]{16,200}",
                expires_at in 1_000_000_u64..2_000_000_000_u64,
                sig in "[0-9a-f]{10,64}",
            ) {
                let offer = SealedOffer {
                    offer_id,
                    ephemeral_public_key_hex: ek_hex,
                    sealed_payload_hex: sealed_hex,
                    expires_at,
                    issuer_signature: sig,
                };
                if let Ok(qr) = encode_sealed_offer(&offer) {
                    let decoded = decode_sealed_offer(&qr).expect("decode must succeed if encode succeeded");
                    prop_assert_eq!(decoded, offer);
                }
                // If encode failed it's because of size budget — that's OK
            }
        }
    }
}
