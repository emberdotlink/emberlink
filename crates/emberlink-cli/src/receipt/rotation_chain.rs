//! `ember receipt verify --offline` rotation-chain walker (CLI side of
//! META-AP-DAEMON-MEK-PERSISTENCE-E-4).
//!
//! Slice E3 ships [`core_events::receipt::sign::verify_receipt_v2_with_rotation_chain`]
//! — the pure walker. This module is the CLI-side adapter:
//!
//! - reads `identity.rotation_witness` Receipts from the local events.jsonl
//!   store,
//! - sorts them ascending by `rotated_at_epoch_secs`,
//! - lifts each into a [`core_events::receipt::sign::RotationWitnessEntry`]
//!   (the chain entry the walker consumes),
//! - and surfaces distinct, CTA-bearing error messages for the two failure
//!   modes the brief calls out: `UntrustedSigner` ("missing rotation witness
//!   for epoch X") vs `BrokenChain` ("rotation witness at <iso> failed
//!   signature check").
//!
//! ## Pubkey resolution
//!
//! Slice E1's `IdentityRotationWitnessBody` shipped the bridge as opaque
//! epoch-root *IDs* (`prev_epoch_root_id` / `next_epoch_root_id`), not the
//! `core_crypto::PublicKey` material the walker needs. Slice E2 will own the
//! production wire-up from epoch-root IDs to public keys via the daemon
//! vault.
//!
//! Until E2 lands, the CLI loader honours two **advisory** body fields the
//! witness writer may include to short-circuit resolution:
//!
//! - `prev_identity_pub` — the wire form of the prior epoch's pubkey.
//! - `new_identity_pub`  — the wire form of the next  epoch's pubkey.
//!
//! These fields ride alongside the canonical body — JCS preserves them
//! deterministically, so signing/verification of the witness envelope is
//! unaffected. Real daemons will populate the fields at write time once
//! Slice E2 wires the lookup; the CLI integration tests populate them
//! directly via FixtureSigner-built synthetic chains.
//!
//! Anchor: `ember_receipt_verify_walks_rotation_chain`.

use core_crypto::PublicKey;
use core_events::receipt::envelope::ReceiptEnvelope;
use core_events::receipt::sign::{RotationWitnessEntry, SignError};
use std::path::Path;

/// Errors produced by the rotation-chain loader. Verifier errors (the actual
/// walker output) ride [`core_events::receipt::sign::SignError`] and are
/// formatted separately by [`format_chain_failure`].
#[derive(Debug)]
pub enum ChainLoadError {
    /// The events.jsonl file could not be opened.
    EventsRead {
        path: String,
        source: std::io::Error,
    },
    /// A witness envelope in the local store is missing the advisory
    /// `prev_identity_pub` / `new_identity_pub` body fields that the CLI
    /// needs to lift the entry into the walker.
    WitnessMissingPubkeyHint {
        receipt_id: String,
        field: &'static str,
    },
}

impl std::fmt::Display for ChainLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainLoadError::EventsRead { path, source } => {
                write!(f, "could not read {path}: {source}")
            }
            ChainLoadError::WitnessMissingPubkeyHint { receipt_id, field } => {
                write!(
                    f,
                    "rotation witness {receipt_id} is missing body.{field}; \
                     this CLI build needs the advisory pubkey hint (Slice E2 \
                     vault resolution not yet wired). Re-export the witness \
                     with the pubkey hint populated or run `ember receipt \
                     verify --file` against the daemon's online verifier."
                )
            }
        }
    }
}

impl std::error::Error for ChainLoadError {}

/// Load every `identity.rotation_witness` envelope from the events.jsonl at
/// `path`, sort ascending by `rotated_at_epoch_secs`, and lift each into a
/// [`RotationWitnessEntry`] consumable by Slice E3's walker.
///
/// **Pre:** `path` exists and is readable.
/// **Post:** the returned slice is sorted ascending by `rotation_at`, which
///          is the walker's monotonicity invariant. The walker enforces it
///          too — but doing the sort at load time means the CLI reports
///          `BrokenChain` only when the on-disk store is inconsistent, not
///          when the operator's filesystem has unspecified ordering.
///
/// Non-witness envelopes are silently skipped — events.jsonl is a shared log.
pub fn list_witnesses_ascending(path: &Path) -> Result<Vec<RotationWitnessEntry>, ChainLoadError> {
    let raw = std::fs::read_to_string(path).map_err(|e| ChainLoadError::EventsRead {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut entries: Vec<RotationWitnessEntry> = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let envelope: ReceiptEnvelope = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            // Lines that don't fit ReceiptEnvelope shape (queue events, etc.)
            // are tolerated — events.jsonl is shared with non-receipt records.
            Err(_) => continue,
        };
        if envelope.kind != core_events::receipt::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS {
            continue;
        }
        entries.push(envelope_to_entry(envelope)?);
    }
    entries.sort_by_key(|e| e.rotation_at);
    Ok(entries)
}

/// Lift a single witness envelope into a [`RotationWitnessEntry`]. Pulls the
/// `rotated_at_epoch_secs` for ordering and the advisory `prev_identity_pub`
/// / `new_identity_pub` pubkey hints (see module docs).
fn envelope_to_entry(envelope: ReceiptEnvelope) -> Result<RotationWitnessEntry, ChainLoadError> {
    let rotation_at = envelope
        .body
        .get("rotated_at_epoch_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let prior_pub = body_pubkey_hint(&envelope, "prev_identity_pub")?;
    let new_pub = body_pubkey_hint(&envelope, "new_identity_pub")?;
    Ok(RotationWitnessEntry {
        envelope,
        prior_identity_pub: prior_pub,
        new_identity_pub: new_pub,
        rotation_at,
    })
}

fn body_pubkey_hint(
    envelope: &ReceiptEnvelope,
    field: &'static str,
) -> Result<PublicKey, ChainLoadError> {
    let s = envelope
        .body
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| ChainLoadError::WitnessMissingPubkeyHint {
            receipt_id: envelope.receipt_id.clone(),
            field,
        })?;
    Ok(PublicKey(s.to_string()))
}

/// One-line success message naming chain depth + iso timespan, per the brief.
pub fn format_chain_success(target: &ReceiptEnvelope, chain: &[RotationWitnessEntry]) -> String {
    if chain.is_empty() {
        return format!("Verified: receipt {} (no rotation hops)", target.receipt_id);
    }
    let first = chain.first().map(|e| e.rotation_at).unwrap_or(0);
    let last = chain.last().map(|e| e.rotation_at).unwrap_or(0);
    let iso1 = epoch_secs_to_iso(first);
    let iso2 = epoch_secs_to_iso(last);
    format!(
        "Verified: receipt {} via {} rotation(s); chain spans {iso1} → {iso2}",
        target.receipt_id,
        chain.len()
    )
}

/// CTA-bearing error message for the two distinguishable failure modes.
pub fn format_chain_failure(err: &SignError, chain: &[RotationWitnessEntry]) -> String {
    match err {
        SignError::UntrustedSigner => {
            let next_unbridged = chain.last().map(|e| e.rotation_at).unwrap_or(0);
            let iso = if next_unbridged == 0 {
                "<no witness loaded>".to_string()
            } else {
                epoch_secs_to_iso(next_unbridged)
            };
            format!(
                "Verification FAILED: untrusted signer — missing rotation witness for epoch \
                 after {iso}. CTA: run `ember receipt list --kind identity.rotation_witness` \
                 to inspect the local chain; the daemon may not have witnessed the rotation \
                 that produced this Receipt's signer."
            )
        }
        SignError::BrokenChain { index, reason } => {
            let witness_iso = chain
                .get(*index)
                .map(|e| epoch_secs_to_iso(e.rotation_at))
                .unwrap_or_else(|| "<unknown epoch>".to_string());
            format!(
                "Verification FAILED: broken chain — rotation witness at {witness_iso} \
                 (index {index}) failed signature check: {reason}. CTA: the local witness \
                 store is inconsistent; re-export from the authoritative daemon or restore \
                 from backup."
            )
        }
        other => format!("Verification FAILED: {other}"),
    }
}

/// Best-effort ISO 8601 formatter for epoch-seconds.
fn epoch_secs_to_iso(secs: u64) -> String {
    let secs_i = i64::try_from(secs).unwrap_or(i64::MAX);
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs_i, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| format!("epoch+{secs}s"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::{FixtureSigner, Signer};
    use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
    use core_events::receipt::sign::sign_receipt_v2;
    use serde_json::json;
    use tempfile::TempDir;

    fn make_witness_envelope(
        prior_signer: &FixtureSigner,
        new_signer: &FixtureSigner,
        prev_id: &str,
        next_id: &str,
        rotated_at: u64,
    ) -> ReceiptEnvelope {
        let prior_pub = prior_signer.public_key();
        let new_pub = new_signer.public_key();
        let body = json!({
            "prev_epoch_root_id": prev_id,
            "next_epoch_root_id": next_id,
            "rotated_at_epoch_secs": rotated_at,
            "signature_by_prev_root": "ed25519sig:00",
            "signature_by_next_root": "ed25519sig:01",
            "prev_identity_pub": prior_pub.0,
            "new_identity_pub": new_pub.0,
        });
        let mut env = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: core_events::receipt::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS.to_string(),
            receipt_id: String::new(),
            daemon_root_id: prev_id.to_string(),
            traceparent: None,
            termination_authority: TerminationAuthority::DaemonPersona,
            presence_kind: None,
            body,
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut env, prior_signer).unwrap();
        env
    }

    /// Append the envelope to a tempdir-scoped events.jsonl path.
    fn append_envelope_jsonl(path: &Path, env: &ReceiptEnvelope) {
        use std::io::Write;
        let line = serde_json::to_string(env).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    #[test]
    fn list_witnesses_ascending_returns_sorted() {
        let tmp = TempDir::new().unwrap();
        let events = tmp.path().join("events.jsonl");

        let s0 = FixtureSigner::new("rc-e0");
        let s1 = FixtureSigner::new("rc-e1");
        let s2 = FixtureSigner::new("rc-e2");

        // Write out-of-order to confirm the loader sorts.
        let w_late = make_witness_envelope(&s1, &s2, "epoch-1", "epoch-2", 2_000);
        let w_early = make_witness_envelope(&s0, &s1, "epoch-0", "epoch-1", 1_000);
        append_envelope_jsonl(&events, &w_late);
        append_envelope_jsonl(&events, &w_early);

        let entries = list_witnesses_ascending(&events).expect("load chain");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].rotation_at, 1_000);
        assert_eq!(entries[1].rotation_at, 2_000);
        assert_eq!(entries[0].prior_identity_pub, s0.public_key());
        assert_eq!(entries[0].new_identity_pub, s1.public_key());
        assert_eq!(entries[1].new_identity_pub, s2.public_key());
    }

    #[test]
    fn list_witnesses_skips_non_witness_lines() {
        let tmp = TempDir::new().unwrap();
        let events = tmp.path().join("events.jsonl");
        // Non-receipt line; gibberish line.
        std::fs::write(
            &events,
            "{\"some\":\"unrelated\"}\nnot-json-at-all\n",
        )
        .unwrap();
        let entries = list_witnesses_ascending(&events).expect("tolerant load");
        assert!(entries.is_empty());
    }

    #[test]
    fn format_chain_success_names_depth_and_span() {
        let s0 = FixtureSigner::new("rc-success-0");
        let s1 = FixtureSigner::new("rc-success-1");
        let s2 = FixtureSigner::new("rc-success-2");
        let chain = vec![
            RotationWitnessEntry {
                envelope: make_witness_envelope(&s0, &s1, "epoch-0", "epoch-1", 1_000),
                prior_identity_pub: s0.public_key(),
                new_identity_pub: s1.public_key(),
                rotation_at: 1_000,
            },
            RotationWitnessEntry {
                envelope: make_witness_envelope(&s1, &s2, "epoch-1", "epoch-2", 2_000),
                prior_identity_pub: s1.public_key(),
                new_identity_pub: s2.public_key(),
                rotation_at: 2_000,
            },
        ];
        let mut target = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: "atomic.tool_call".into(),
            receipt_id: String::new(),
            daemon_root_id: "epoch-0".into(),
            traceparent: None,
            termination_authority: TerminationAuthority::UserSession,
            presence_kind: None,
            body: json!({"tool":"echo"}),
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut target, &s2).unwrap();
        let msg = format_chain_success(&target, &chain);
        assert!(msg.contains("via 2 rotation(s)"), "msg={msg}");
        assert!(msg.contains("→"), "msg={msg}");
    }

    #[test]
    fn format_chain_failure_distinguishes_untrusted_vs_broken() {
        let s0 = FixtureSigner::new("fail-0");
        let s1 = FixtureSigner::new("fail-1");
        let entry = RotationWitnessEntry {
            envelope: make_witness_envelope(&s0, &s1, "epoch-0", "epoch-1", 9_999),
            prior_identity_pub: s0.public_key(),
            new_identity_pub: s1.public_key(),
            rotation_at: 9_999,
        };
        let untrusted = format_chain_failure(&SignError::UntrustedSigner, std::slice::from_ref(&entry));
        assert!(
            untrusted.contains("missing rotation witness"),
            "msg={untrusted}"
        );
        assert!(untrusted.contains("CTA:"), "msg={untrusted}");

        let broken = format_chain_failure(
            &SignError::BrokenChain {
                index: 0,
                reason: "out-of-order".to_string(),
            },
            &[entry],
        );
        assert!(broken.contains("broken chain"), "msg={broken}");
        assert!(
            broken.contains("failed signature check"),
            "msg={broken}"
        );
        assert!(broken.contains("CTA:"), "msg={broken}");
    }

    #[test]
    fn missing_pubkey_hint_surfaces_actionable_error() {
        let tmp = TempDir::new().unwrap();
        let events = tmp.path().join("events.jsonl");
        let s0 = FixtureSigner::new("hint-missing-0");
        // Build envelope without the pubkey hints — sign as the prior key
        // anyway so the body is well-formed beyond the missing advisory
        // fields.
        let body = json!({
            "prev_epoch_root_id": "epoch-0",
            "next_epoch_root_id": "epoch-1",
            "rotated_at_epoch_secs": 1_000,
            "signature_by_prev_root": "ed25519sig:00",
            "signature_by_next_root": "ed25519sig:01",
        });
        let mut env = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: core_events::receipt::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS.to_string(),
            receipt_id: String::new(),
            daemon_root_id: "epoch-0".into(),
            traceparent: None,
            termination_authority: TerminationAuthority::DaemonPersona,
            presence_kind: None,
            body,
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut env, &s0).unwrap();
        append_envelope_jsonl(&events, &env);
        let err = list_witnesses_ascending(&events).expect_err("must reject missing hint");
        let msg = err.to_string();
        assert!(
            msg.contains("prev_identity_pub") || msg.contains("new_identity_pub"),
            "msg={msg}"
        );
    }

    // Silence dead_code for the helper used only by other test modules in
    // this crate (the integration test reaches in via crate::receipt).
    #[test]
    fn signer_is_invocable() {
        let s = FixtureSigner::new("noop");
        let _ = s.sign(b"hi");
    }
}
