//! Shared first-grant walkthrough receipt builder.
//!
//! The daemon owns persona-secret signing. Plain `ember init` still writes the
//! receipt file locally, but the installed-path receipt body and signature now
//! come from this shared builder so the CLI does not need a local
//! `persona_signer` when the daemon socket is live.

use chrono::Utc;
use core_crypto::Signer;
use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
use core_events::receipt::sign::sign_receipt_v2;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Receipt kind discriminator for the first-grant walkthrough receipt.
pub const RECEIPT_KIND_INIT_FIRST_GRANT: &str = "init.first_grant";

/// Serialized first-grant walkthrough receipt file written to
/// `<data_dir>/receipts/first.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct FirstGrantReceiptFile {
    pub issuer: FirstGrantIssuer,
    pub evidence: FirstGrantEvidence,
    pub lifecycle: FirstGrantLifecycle,
    pub receipt: ReceiptEnvelope,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirstGrantIssuer {
    pub persona: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirstGrantEvidence {
    pub signed: bool,
    pub hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirstGrantLifecycle {
    pub issued_at: String,
    pub revoked_at: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("sign receipt v2: {0}")]
    Sign(#[from] core_events::receipt::sign::SignError),
    #[error("serialize receipt: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Build the canonical signed first-grant walkthrough receipt file.
pub fn build_first_grant_receipt_file(
    persona_id: &str,
    signer: &dyn Signer,
) -> Result<FirstGrantReceiptFile, BuildError> {
    let now = Utc::now();
    let issued_at = now.to_rfc3339();
    let revoked_at = (now + chrono::Duration::seconds(60)).to_rfc3339();

    let body = serde_json::json!({
        "issuer_persona": persona_id,
        "agent": "first-grant-tutorial",
        "scope": "init",
        "ttl_seconds": 60,
        "issued_at": issued_at,
        "revoked_at": revoked_at,
        "note": "illustrative grant written by ember init - verifiable offline"
    });

    let mut envelope = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_INIT_FIRST_GRANT.to_string(),
        receipt_id: String::new(),
        daemon_root_id: persona_id.to_string(),
        traceparent: None,
        termination_authority: TerminationAuthority::UserSession,
        presence_kind: None,
        body,
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };

    sign_receipt_v2(&mut envelope, signer)?;

    let envelope_json = serde_json::to_string(&envelope)?;
    let hash_bytes = Sha256::digest(envelope_json.as_bytes());
    let hash = format!("sha256:{}", hex::encode(hash_bytes));

    Ok(FirstGrantReceiptFile {
        issuer: FirstGrantIssuer {
            persona: persona_id.to_string(),
        },
        evidence: FirstGrantEvidence { signed: true, hash },
        lifecycle: FirstGrantLifecycle {
            issued_at,
            revoked_at,
        },
        receipt: envelope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_first_grant_receipt_file_returns_signed_receipt() {
        let signer = core_crypto::FixtureSigner::new("daemon-init-first-grant");
        let file = build_first_grant_receipt_file("persona-test", &signer).expect("build");

        assert_eq!(file.issuer.persona, "persona-test");
        assert!(file.evidence.signed);
        assert!(file.evidence.hash.starts_with("sha256:"));
        assert!(!file.lifecycle.issued_at.is_empty());
        assert!(!file.lifecycle.revoked_at.is_empty());
        assert_eq!(file.receipt.kind, RECEIPT_KIND_INIT_FIRST_GRANT);
        assert!(!file.receipt.receipt_id.is_empty());
        assert!(file.receipt.signature.is_some());
    }
}
