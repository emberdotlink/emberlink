//! Channel pointer — a small signed document (1-hr TTL) referencing the current
//! per-release manifest for each channel (release / dev / canary).
//!
//! # channel_pointer
//!
//! The `ChannelPointer` is the first layer of the update discovery flow defined
//! in ADR 169 D2. The daemon polls the channel pointer endpoint (1-hr cache TTL)
//! to detect when a new manifest has been published without incurring a per-poll
//! manifest download.
//!
//! ## Canonical signing encoding
//!
//! The Ed25519 signature covers a length-prefixed byte payload built as follows:
//!
//! 1. Domain-separation prefix: `"emberlink/v1/channel-pointer"` (UTF-8, no NUL).
//! 2. For each signed field in order — `channel`, `manifest_uri`,
//!    `manifest_digest_hex`, `issued_at_unix_ms`, `ttl_ms` — a u64 big-endian
//!    length prefix followed by the field's UTF-8 bytes (or 8 raw bytes for
//!    the two `u64` integer fields).
//!
//! ## TTL enforcement
//!
//! | Channel | Max stale before fail-closed |
//! |---|---|
//! | `Release` | 2 hours (7 200 000 ms) |
//! | `Canary`  | 2 hours (7 200 000 ms) |
//! | `Dev`     | 24 hours (86 400 000 ms) per ADR 169 D6 dev-channel relaxation |

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The maximum age in milliseconds before a `Release` or `Canary` channel
/// pointer is considered stale and rejected fail-closed.
pub const RELEASE_CANARY_MAX_STALE_MS: u64 = 7_200_000; // 2 hours

/// The maximum age in milliseconds before a `Dev` channel pointer is
/// considered stale and rejected fail-closed (ADR 169 D6 relaxation).
pub const DEV_MAX_STALE_MS: u64 = 86_400_000; // 24 hours

/// Domain-separation prefix used in the canonical signing payload.
const DOMAIN_PREFIX: &[u8] = b"emberlink/v1/channel-pointer";

/// Update channel identifying the release stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Release,
    Dev,
    Canary,
}

/// A small signed document referencing the current per-release manifest for
/// a given channel. The daemon polls the channel pointer endpoint (1-hr cache
/// TTL) to determine whether a new manifest is available without incurring a
/// full manifest download on every poll cycle.
///
/// The `signature` covers the canonical encoding of all other fields; see the
/// module-level doc-comment for the encoding algorithm.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelPointer {
    pub channel: Channel,
    pub manifest_uri: String,
    pub manifest_digest_hex: String,
    pub issued_at_unix_ms: u64,
    pub ttl_ms: u64,
    pub signature: Vec<u8>,
}

/// Errors returned by [`verify_channel_pointer`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChannelPointerError {
    #[error(
        "channel pointer signature is invalid; the pointer may have been tampered with \
         or was signed by an untrusted key"
    )]
    SignatureInvalid,

    #[error(
        "channel pointer has expired (issued_at={issued_at_unix_ms}ms, ttl={ttl_ms}ms, \
         now={now_unix_ms}ms, max_stale={max_stale_ms}ms)"
    )]
    Expired {
        issued_at_unix_ms: u64,
        ttl_ms: u64,
        now_unix_ms: u64,
        max_stale_ms: u64,
    },

    #[error(
        "channel pointer issued_at ({issued_at_unix_ms}ms) is in the future \
         relative to now ({now_unix_ms}ms)"
    )]
    NotYetValid {
        issued_at_unix_ms: u64,
        now_unix_ms: u64,
    },
}

/// Build the canonical byte payload that the Ed25519 signature covers.
///
/// Encoding (append in order):
/// 1. `u64 BE` length of domain prefix, then domain prefix bytes.
/// 2. For `channel`: `u64 BE` length of its snake_case string, then its bytes.
/// 3. For `manifest_uri`: `u64 BE` length, then bytes.
/// 4. For `manifest_digest_hex`: `u64 BE` length, then bytes.
/// 5. For `issued_at_unix_ms`: 8-byte `u64 BE` value (length field = 8, then value).
/// 6. For `ttl_ms`: 8-byte `u64 BE` value (length field = 8, then value).
fn canonical_payload(
    channel: &Channel,
    manifest_uri: &str,
    manifest_digest_hex: &str,
    issued_at_unix_ms: u64,
    ttl_ms: u64,
) -> Vec<u8> {
    let channel_str = match channel {
        Channel::Release => "release",
        Channel::Dev => "dev",
        Channel::Canary => "canary",
    };

    let mut buf = Vec::new();

    // Domain-separation prefix
    let prefix_len = DOMAIN_PREFIX.len() as u64;
    buf.extend_from_slice(&prefix_len.to_be_bytes());
    buf.extend_from_slice(DOMAIN_PREFIX);

    // channel
    let ch_bytes = channel_str.as_bytes();
    buf.extend_from_slice(&(ch_bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(ch_bytes);

    // manifest_uri
    let uri_bytes = manifest_uri.as_bytes();
    buf.extend_from_slice(&(uri_bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(uri_bytes);

    // manifest_digest_hex
    let digest_bytes = manifest_digest_hex.as_bytes();
    buf.extend_from_slice(&(digest_bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(digest_bytes);

    // issued_at_unix_ms — 8-byte u64 BE; length prefix = 8
    buf.extend_from_slice(&8u64.to_be_bytes());
    buf.extend_from_slice(&issued_at_unix_ms.to_be_bytes());

    // ttl_ms — 8-byte u64 BE; length prefix = 8
    buf.extend_from_slice(&8u64.to_be_bytes());
    buf.extend_from_slice(&ttl_ms.to_be_bytes());

    buf
}

/// Sign a new channel pointer.
///
/// `ttl_ms` should be 3_600_000 (1 hour) for normal operation. The caller
/// supplies `issued_at_unix_ms` so tests can control the clock without
/// `std::time` coupling.
pub fn sign_channel_pointer(
    channel: Channel,
    manifest_uri: String,
    manifest_digest_hex: String,
    ttl_ms: u64,
    issued_at_unix_ms: u64,
    signing_key: &SigningKey,
) -> ChannelPointer {
    let payload = canonical_payload(
        &channel,
        &manifest_uri,
        &manifest_digest_hex,
        issued_at_unix_ms,
        ttl_ms,
    );
    let sig: Signature = signing_key.sign(&payload);
    ChannelPointer {
        channel,
        manifest_uri,
        manifest_digest_hex,
        issued_at_unix_ms,
        ttl_ms,
        signature: sig.to_bytes().to_vec(),
    }
}

/// Returns the fail-closed max-stale window in milliseconds for a given channel.
///
/// Per ADR 169 D6:
/// - `Release` and `Canary`: 2 hours
/// - `Dev`: 24 hours
fn max_stale_ms(channel: &Channel) -> u64 {
    match channel {
        Channel::Release | Channel::Canary => RELEASE_CANARY_MAX_STALE_MS,
        Channel::Dev => DEV_MAX_STALE_MS,
    }
}

/// Verify a channel pointer against a known verifying key and the current clock.
///
/// # Errors
///
/// - [`ChannelPointerError::SignatureInvalid`] — signature does not verify.
/// - [`ChannelPointerError::NotYetValid`] — `issued_at_unix_ms > now_unix_ms`.
/// - [`ChannelPointerError::Expired`] — the pointer has been stale longer than
///   the channel's max-stale window (2 h for Release/Canary, 24 h for Dev).
pub fn verify_channel_pointer(
    p: &ChannelPointer,
    verifying_key: &VerifyingKey,
    now_unix_ms: u64,
) -> Result<(), ChannelPointerError> {
    // 1. Signature check first — fail-fast on tampered data.
    if p.signature.len() != 64 {
        return Err(ChannelPointerError::SignatureInvalid);
    }
    let sig_arr: [u8; 64] = p.signature[..64].try_into().unwrap();
    let signature = Signature::from_bytes(&sig_arr);

    let payload = canonical_payload(
        &p.channel,
        &p.manifest_uri,
        &p.manifest_digest_hex,
        p.issued_at_unix_ms,
        p.ttl_ms,
    );

    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| ChannelPointerError::SignatureInvalid)?;

    // 2. Clock checks — only after the signature is valid.
    if p.issued_at_unix_ms > now_unix_ms {
        return Err(ChannelPointerError::NotYetValid {
            issued_at_unix_ms: p.issued_at_unix_ms,
            now_unix_ms,
        });
    }

    let age_ms = now_unix_ms - p.issued_at_unix_ms;
    let channel_max_stale = max_stale_ms(&p.channel);

    if age_ms > channel_max_stale {
        return Err(ChannelPointerError::Expired {
            issued_at_unix_ms: p.issued_at_unix_ms,
            ttl_ms: p.ttl_ms,
            now_unix_ms,
            max_stale_ms: channel_max_stale,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const ONE_HOUR_MS: u64 = 3_600_000;
    const ISSUED_AT: u64 = 1_000_000_000_000; // arbitrary epoch ms

    fn test_signing_key() -> SigningKey {
        let seed: [u8; 32] = [42u8; 32];
        SigningKey::from_bytes(&seed)
    }

    fn test_pointer(channel: Channel, issued_at_unix_ms: u64) -> (ChannelPointer, VerifyingKey) {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let ptr = sign_channel_pointer(
            channel,
            "https://manifests.emberlink.dev/v0.3.0/amd64.manifest.json".to_string(),
            "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab".to_string(),
            ONE_HOUR_MS,
            issued_at_unix_ms,
            &sk,
        );
        (ptr, vk)
    }

    /// round-trip: sign then verify with a fresh clock inside TTL window
    #[test]
    fn round_trip_sign_verify() {
        let (ptr, vk) = test_pointer(Channel::Release, ISSUED_AT);
        // now = issued_at + 30 min (well within 1-hr TTL and 2-hr max-stale)
        let now = ISSUED_AT + 30 * 60 * 1000;
        verify_channel_pointer(&ptr, &vk, now).expect("should verify");
    }

    /// release channel: stale 3h → Expired (max-stale = 2h)
    #[test]
    fn expired_release_3h_stale() {
        let (ptr, vk) = test_pointer(Channel::Release, ISSUED_AT);
        // now = issued_at + 3 hours → 3h stale > 2h max-stale
        let now = ISSUED_AT + 3 * ONE_HOUR_MS;
        let err = verify_channel_pointer(&ptr, &vk, now).unwrap_err();
        assert!(
            matches!(err, ChannelPointerError::Expired { .. }),
            "expected Expired, got {err:?}"
        );
    }

    /// dev channel: 12h stale is within the 24h relaxation window
    #[test]
    fn dev_channel_tolerates_12h_stale() {
        let (ptr, vk) = test_pointer(Channel::Dev, ISSUED_AT);
        // now = issued_at + 12 hours → 12h stale < 24h max-stale
        let now = ISSUED_AT + 12 * ONE_HOUR_MS;
        verify_channel_pointer(&ptr, &vk, now).expect("dev channel should accept 12h stale");
    }

    /// tampered signature → SignatureInvalid
    #[test]
    fn tampered_signature_invalid() {
        let (mut ptr, vk) = test_pointer(Channel::Release, ISSUED_AT);
        // Flip a byte in the signature.
        ptr.signature[0] ^= 0xFF;
        let now = ISSUED_AT + 30 * 60 * 1000;
        let err = verify_channel_pointer(&ptr, &vk, now).unwrap_err();
        assert!(
            matches!(err, ChannelPointerError::SignatureInvalid),
            "expected SignatureInvalid, got {err:?}"
        );
    }
}
