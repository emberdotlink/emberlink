//! Credential delivery protocol types (P29).
//!
//! These types define the wire protocol for delivering encrypted credential
//! data from a grant issuer to a grant recipient via the relay. The relay
//! never sees plaintext — it stores opaque ciphertext blobs.

/// Maximum age (seconds) of a credential fetch request before it's considered stale.
/// Prevents replay of captured requests.
pub const FETCH_REQUEST_MAX_AGE_SECS: u64 = 300;

fn signing_payload_v2(domain: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(domain.as_bytes());
    out.push(b'\n');
    for field in fields {
        let len = u64::try_from(field.len()).expect("field length exceeds u64");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// Request to fetch credential data authorized by a grant.
/// The requester proves grant ownership by signing a canonical payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialFetchRequest {
    pub grant_id: String,
    pub credential_id: String,
    pub requester_id: String,
    /// Hex-encoded signature over [`Self::signing_payload`].
    pub requester_signature: String,
    /// Unix timestamp (seconds) — bounded by [`FETCH_REQUEST_MAX_AGE_SECS`].
    pub timestamp: u64,
    /// Random nonce to prevent replay within the freshness window.
    pub nonce: String,
}

impl CredentialFetchRequest {
    /// Canonical signing payload: deterministic byte sequence that the requester
    /// signs and the relay/issuer verifies. Version 2 uses length-prefixed
    /// fields so principal-controlled identifiers cannot shift field boundaries.
    pub fn signing_payload(&self) -> Vec<u8> {
        let timestamp = self.timestamp.to_string();
        signing_payload_v2(
            "emberlink:credential-fetch:2",
            &[
                self.grant_id.as_bytes(),
                self.credential_id.as_bytes(),
                self.requester_id.as_bytes(),
                timestamp.as_bytes(),
                self.nonce.as_bytes(),
            ],
        )
    }
}

/// Response containing encrypted credential blocks wrapped to the recipient's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialFetchResponse {
    pub grant_id: String,
    pub credential_id: String,
    /// Recipient persona ID — response is bound to a specific requester.
    pub recipient_id: String,
    pub encrypted_blocks: Vec<EncryptedCredentialBlock>,
    /// Hex-encoded issuer signature over [`Self::signing_payload`].
    pub issuer_signature: String,
    /// Echo of the request nonce — binds response to a specific request.
    pub request_nonce: String,
}

impl CredentialFetchResponse {
    /// Canonical signing payload for the issuer.
    pub fn signing_payload(&self) -> Vec<u8> {
        // Include block count but not block contents (signature covers the envelope,
        // encryption covers the data).
        let block_count = self.encrypted_blocks.len().to_string();
        signing_payload_v2(
            "emberlink:credential-response:2",
            &[
                self.grant_id.as_bytes(),
                self.credential_id.as_bytes(),
                self.recipient_id.as_bytes(),
                self.request_nonce.as_bytes(),
                block_count.as_bytes(),
            ],
        )
    }
}

/// A single encrypted block of credential data.
/// Uses XChaCha20-Poly1305, consistent with the vault encryption scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedCredentialBlock {
    pub block_index: u32,
    /// Ciphertext bytes (opaque to relay).
    pub ciphertext: Vec<u8>,
    /// 24-byte nonce for XChaCha20-Poly1305.
    pub nonce: Vec<u8>,
}

/// Deposit request — issuer deposits credential blocks for a grant recipient.
/// Stored at the relay keyed by grant_id, fetched by the recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDeposit {
    pub grant_id: String,
    pub credential_id: String,
    pub encrypted_blocks: Vec<EncryptedCredentialBlock>,
    pub issuer_id: String,
    /// Hex-encoded issuer signature over [`Self::signing_payload`].
    pub issuer_signature: String,
    /// Unix timestamp (seconds) after which the relay may purge this deposit.
    pub expires_at: u64,
}

impl CredentialDeposit {
    /// Canonical signing payload for the issuer.
    pub fn signing_payload(&self) -> Vec<u8> {
        let expires_at = self.expires_at.to_string();
        let block_count = self.encrypted_blocks.len().to_string();
        signing_payload_v2(
            "emberlink:credential-deposit:2",
            &[
                self.grant_id.as_bytes(),
                self.credential_id.as_bytes(),
                self.issuer_id.as_bytes(),
                expires_at.as_bytes(),
                block_count.as_bytes(),
            ],
        )
    }
}

/// Revocation notice — issuer revokes credential access, relay tombstones the deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRevocation {
    pub grant_id: String,
    pub issuer_id: String,
    /// Hex-encoded issuer signature over [`Self::signing_payload`].
    pub issuer_signature: String,
    pub reason: Option<String>,
}

impl CredentialRevocation {
    /// Canonical signing payload for the issuer.
    pub fn signing_payload(&self) -> Vec<u8> {
        signing_payload_v2(
            "emberlink:credential-revoke:2",
            &[self.grant_id.as_bytes(), self.issuer_id.as_bytes()],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_deposit_signing_payload_deterministic() {
        let deposit = CredentialDeposit {
            grant_id: "grant-001".into(),
            credential_id: "cred-001".into(),
            encrypted_blocks: vec![EncryptedCredentialBlock {
                block_index: 0,
                ciphertext: vec![0xDE, 0xAD],
                nonce: vec![0; 24],
            }],
            issuer_id: "persona-alice".into(),
            issuer_signature: "sig".into(),
            expires_at: 1700000000,
        };
        let p1 = deposit.signing_payload();
        let p2 = deposit.signing_payload();
        assert_eq!(p1, p2);
        assert!(String::from_utf8_lossy(&p1).starts_with("emberlink:credential-deposit:2\n"));
    }

    #[test]
    fn credential_fetch_request_signing_payload_deterministic() {
        let req = CredentialFetchRequest {
            grant_id: "g1".into(),
            credential_id: "c1".into(),
            requester_id: "r1".into(),
            requester_signature: "ignored".into(),
            timestamp: 100,
            nonce: "n1".into(),
        };
        let p1 = req.signing_payload();
        let p2 = req.signing_payload();
        assert_eq!(p1, p2);
        assert!(String::from_utf8_lossy(&p1).starts_with("emberlink:credential-fetch:2\n"));
    }

    #[test]
    fn credential_revocation_signing_payload_deterministic() {
        let rev = CredentialRevocation {
            grant_id: "g1".into(),
            issuer_id: "i1".into(),
            issuer_signature: "ignored".into(),
            reason: Some("expired".into()),
        };
        let p1 = rev.signing_payload();
        let p2 = rev.signing_payload();
        assert_eq!(p1, p2);
        assert!(String::from_utf8_lossy(&p1).starts_with("emberlink:credential-revoke:2\n"));
    }

    #[test]
    fn credential_fetch_request_pipe_fields_do_not_collide() {
        let a = CredentialFetchRequest {
            grant_id: "grant|cred".into(),
            credential_id: "id".into(),
            requester_id: "requester".into(),
            requester_signature: "ignored".into(),
            timestamp: 100,
            nonce: "nonce".into(),
        };
        let b = CredentialFetchRequest {
            grant_id: "grant".into(),
            credential_id: "cred|id".into(),
            requester_id: "requester".into(),
            requester_signature: "ignored".into(),
            timestamp: 100,
            nonce: "nonce".into(),
        };
        assert_ne!(a.signing_payload(), b.signing_payload());
    }

    #[test]
    fn credential_fetch_response_pipe_fields_do_not_collide() {
        let a = CredentialFetchResponse {
            grant_id: "grant|cred".into(),
            credential_id: "id".into(),
            recipient_id: "recipient".into(),
            encrypted_blocks: vec![],
            issuer_signature: "ignored".into(),
            request_nonce: "nonce".into(),
        };
        let b = CredentialFetchResponse {
            grant_id: "grant".into(),
            credential_id: "cred|id".into(),
            recipient_id: "recipient".into(),
            encrypted_blocks: vec![],
            issuer_signature: "ignored".into(),
            request_nonce: "nonce".into(),
        };
        assert_ne!(a.signing_payload(), b.signing_payload());
    }

    #[test]
    fn credential_deposit_pipe_fields_do_not_collide() {
        let a = CredentialDeposit {
            grant_id: "grant|cred".into(),
            credential_id: "id".into(),
            encrypted_blocks: vec![],
            issuer_id: "issuer".into(),
            issuer_signature: "ignored".into(),
            expires_at: 1700000000,
        };
        let b = CredentialDeposit {
            grant_id: "grant".into(),
            credential_id: "cred|id".into(),
            encrypted_blocks: vec![],
            issuer_id: "issuer".into(),
            issuer_signature: "ignored".into(),
            expires_at: 1700000000,
        };
        assert_ne!(a.signing_payload(), b.signing_payload());
    }

    #[test]
    fn credential_revocation_pipe_fields_do_not_collide() {
        let a = CredentialRevocation {
            grant_id: "grant|issuer".into(),
            issuer_id: "id".into(),
            issuer_signature: "ignored".into(),
            reason: None,
        };
        let b = CredentialRevocation {
            grant_id: "grant".into(),
            issuer_id: "issuer|id".into(),
            issuer_signature: "ignored".into(),
            reason: None,
        };
        assert_ne!(a.signing_payload(), b.signing_payload());
    }
}
