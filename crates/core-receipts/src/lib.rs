//! `core-receipts` — receipt v2 surface for verify dispatch + redaction +
//! tool registry (implementation-note-17).
//!
//! This crate is the home for *behavior* applied to receipts:
//!
//! - [`redaction`] — scrub secrets from a receipt JSON before export.
//! - [`tool_registry`] — table of known ember-X tools used to validate
//!   tool references in v2 receipts.
//! - [`ReceiptV2`] + [`verify_v2`] — the v2 receipt struct used by
//!   `ember receipt verify` to route based on the on-disk `version` field.
//!
//! v1 (`core_types::grant_receipt::GrantReceipt`) is preserved for
//! back-compat; this crate does not re-export it.

pub mod redaction;
pub mod tool_registry;

use serde::{Deserialize, Serialize};
use tool_registry::ToolRegistry;

/// Locked at `2`. Receipts with a different `version` field must NOT be
/// accepted by [`verify_v2`].
pub const RECEIPT_VERSION_V2: u32 = 2;

/// Receipt v2 — same shape as v1 but with an explicit `version` field and a
/// `redactions_applied` flag indicating whether the receipt has been scrubbed
/// for export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptV2 {
    /// Schema version. Must be [`RECEIPT_VERSION_V2`].
    pub version: u32,
    /// Receipt id, e.g. `rct_abc123`.
    pub id: String,
    /// Grant id this receipt corresponds to.
    pub grant_id: String,
    /// Tool id used during the session, looked up against [`ToolRegistry`].
    pub tool_id: String,
    /// Whether redaction rules have been applied to this receipt body.
    pub redactions_applied: bool,
    /// Body — opaque JSON; v2 leaves the per-kind body shape to the verifier.
    pub body: serde_json::Value,
}

impl ReceiptV2 {
    /// Construct a fresh receipt with `version` pinned to v2 and no redactions
    /// applied yet.
    pub fn new(id: impl Into<String>, grant_id: impl Into<String>, tool_id: impl Into<String>) -> Self {
        Self {
            version: RECEIPT_VERSION_V2,
            id: id.into(),
            grant_id: grant_id.into(),
            tool_id: tool_id.into(),
            redactions_applied: false,
            body: serde_json::Value::Null,
        }
    }
}

/// Verification outcome from [`verify_v2`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Receipt passed all v2 invariants.
    Ok,
    /// Receipt's `version` field is not [`RECEIPT_VERSION_V2`].
    VersionMismatch { found: u32, expected: u32 },
    /// `tool_id` does not appear in the supplied [`ToolRegistry`].
    UnknownTool { tool_id: String },
}

impl VerifyResult {
    /// `true` iff the receipt verified cleanly.
    pub fn is_ok(&self) -> bool {
        matches!(self, VerifyResult::Ok)
    }
}

/// Validate a [`ReceiptV2`] against the tool registry.
///
/// Pre: `receipt.version == 2`. Post: returns [`VerifyResult::Ok`] iff
/// `tool_id` is registered AND `version` is exactly `2`. Errors are reported
/// as variants of [`VerifyResult`] rather than `Result` so the CLI can format
/// each kind distinctly.
pub fn verify_v2(receipt: &ReceiptV2, registry: &ToolRegistry) -> VerifyResult {
    if receipt.version != RECEIPT_VERSION_V2 {
        return VerifyResult::VersionMismatch {
            found: receipt.version,
            expected: RECEIPT_VERSION_V2,
        };
    }
    if registry.lookup(&receipt.tool_id).is_none() {
        return VerifyResult::UnknownTool {
            tool_id: receipt.tool_id.clone(),
        };
    }
    VerifyResult::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verify_v2_happy_path() {
        let r = ReceiptV2::new("rct_1", "grt_1", "ember-aws");
        let registry = ToolRegistry::new_default();
        assert_eq!(verify_v2(&r, &registry), VerifyResult::Ok);
    }

    #[test]
    fn verify_v2_rejects_version_mismatch() {
        let mut r = ReceiptV2::new("rct_1", "grt_1", "ember-aws");
        r.version = 1;
        let registry = ToolRegistry::new_default();
        match verify_v2(&r, &registry) {
            VerifyResult::VersionMismatch { found, expected } => {
                assert_eq!(found, 1);
                assert_eq!(expected, 2);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_v2_rejects_unknown_tool() {
        let r = ReceiptV2::new("rct_1", "grt_1", "ember-bogus");
        let registry = ToolRegistry::new_default();
        match verify_v2(&r, &registry) {
            VerifyResult::UnknownTool { tool_id } => {
                assert_eq!(tool_id, "ember-bogus");
            }
            other => panic!("expected UnknownTool, got {other:?}"),
        }
    }

    #[test]
    fn receipt_v2_round_trips_via_serde() {
        let r = ReceiptV2 {
            version: RECEIPT_VERSION_V2,
            id: "rct_x".into(),
            grant_id: "grt_x".into(),
            tool_id: "ember-aws".into(),
            redactions_applied: true,
            body: json!({ "password": "<REDACTED>" }),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: ReceiptV2 = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn version_field_pins_at_2() {
        let r = ReceiptV2::new("a", "b", "ember-aws");
        assert_eq!(r.version, 2);
    }
}
