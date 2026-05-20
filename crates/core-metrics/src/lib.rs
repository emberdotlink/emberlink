//! `core-metrics` — Prometheus instrumentation primitives per design.
//!
//! Type-only scaffolding for now. Histogram bucket constants, closed-set
//! label newtypes, forbidden-field gate. The actual Prometheus exporter
//! wiring lives in a downstream crate (`emberd-metrics` or similar) and
//! consumes these primitives.
//!
//! This crate is `no_std`-friendly in spirit (no I/O, no `tokio`, no
//! native deps) so it compiles to `wasm32-unknown-unknown` per
//! `.claude/rules/library-crates.md`.

use serde::{Deserialize, Serialize};

/// Default histogram buckets for latency-shaped metrics, in seconds.
/// Powers-of-two-ish from 1ms to ~30s — the observed working range for
/// Emberlink RPC + receipt-issuance + broker-mint paths.
pub const HISTOGRAM_BUCKETS_LATENCY_SECONDS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// Default histogram buckets for size-shaped metrics, in bytes.
/// Spans serialized-receipt sizes (~200B) up to bulk-export sizes (~1MB).
pub const HISTOGRAM_BUCKETS_BYTES: &[f64] = &[
    128.0,
    256.0,
    512.0,
    1024.0,
    4096.0,
    16384.0,
    65536.0,
    262_144.0,
    1_048_576.0,
];

/// Receipt kind, mirrored from design §"Kinds". Newtype-bound so labels
/// can never carry an open string — Prometheus cardinality is bounded at
/// the type level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKindLabel {
    SessionClaudeCode,
    GrantIssue,
    GrantRevoke,
    BrokerMint,
    KmsUnseal,
    SnapshotIssue,
    DaemonBoot,
    IdentityRotate,
}

impl ReceiptKindLabel {
    /// Stable label string for Prometheus exposition.
    pub fn as_label(self) -> &'static str {
        match self {
            ReceiptKindLabel::SessionClaudeCode => "session_claude_code",
            ReceiptKindLabel::GrantIssue => "grant_issue",
            ReceiptKindLabel::GrantRevoke => "grant_revoke",
            ReceiptKindLabel::BrokerMint => "broker_mint",
            ReceiptKindLabel::KmsUnseal => "kms_unseal",
            ReceiptKindLabel::SnapshotIssue => "snapshot_issue",
            ReceiptKindLabel::DaemonBoot => "daemon_boot",
            ReceiptKindLabel::IdentityRotate => "identity_rotate",
        }
    }
}

/// Receipt outcome label — closed set so the {receipt_kind, outcome}
/// cross-product cardinality is bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeLabel {
    Ok,
    Denied,
    Errored,
    TimedOut,
}

impl OutcomeLabel {
    pub fn as_label(self) -> &'static str {
        match self {
            OutcomeLabel::Ok => "ok",
            OutcomeLabel::Denied => "denied",
            OutcomeLabel::Errored => "errored",
            OutcomeLabel::TimedOut => "timed_out",
        }
    }
}

/// Forbidden-field gate: rejects label values that match patterns
/// known to leak credentials, keys, or grants.toml content. Callers
/// MUST run every dynamic label value through this gate before
/// passing to a metrics backend.
///
/// Conservative pattern set — additive over time as new leak shapes
/// surface. Not a full sanitizer; trips loudly so the offending
/// instrumentation site gets fixed at the source.
pub fn forbidden_label_value(value: &str) -> Option<&'static str> {
    let lc = value.to_ascii_lowercase();
    // Credential prefixes — the leaked-secret detector hooks
    if value.starts_with("ghp_") || value.starts_with("github_pat_") {
        return Some("github_token_prefix");
    }
    if value.starts_with("sk-ant-") {
        return Some("anthropic_key_prefix");
    }
    if value.starts_with("AKIA") || value.starts_with("ASIA") {
        return Some("aws_access_key_prefix");
    }
    if value.starts_with("cfat_") {
        return Some("cloudflare_token_prefix");
    }
    if value.starts_with("hvs.") {
        return Some("vault_token_prefix");
    }
    if value.contains("BEGIN PRIVATE KEY") || value.contains("BEGIN RSA PRIVATE KEY") {
        return Some("pem_block");
    }
    // grants.toml content shapes — these belong in receipts not labels
    if lc.contains("scope = ") || lc.contains("predicate = ") {
        return Some("grants_toml_fragment");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_buckets_latency_are_monotonic() {
        let mut prev = 0.0;
        for &b in HISTOGRAM_BUCKETS_LATENCY_SECONDS {
            assert!(b > prev, "buckets must be strictly increasing");
            prev = b;
        }
    }

    #[test]
    fn histogram_buckets_bytes_are_monotonic() {
        let mut prev = 0.0;
        for &b in HISTOGRAM_BUCKETS_BYTES {
            assert!(b > prev, "buckets must be strictly increasing");
            prev = b;
        }
    }

    #[test]
    fn receipt_kind_label_round_trip() {
        let kinds = [
            ReceiptKindLabel::SessionClaudeCode,
            ReceiptKindLabel::GrantIssue,
            ReceiptKindLabel::BrokerMint,
            ReceiptKindLabel::KmsUnseal,
        ];
        for k in kinds {
            let label = k.as_label();
            assert!(!label.contains(' '));
            assert!(label.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    #[test]
    fn outcome_label_stable_strings() {
        assert_eq!(OutcomeLabel::Ok.as_label(), "ok");
        assert_eq!(OutcomeLabel::Denied.as_label(), "denied");
        assert_eq!(OutcomeLabel::Errored.as_label(), "errored");
        assert_eq!(OutcomeLabel::TimedOut.as_label(), "timed_out");
    }

    #[test]
    fn forbidden_gate_rejects_known_credential_prefixes() {
        assert_eq!(
            forbidden_label_value("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            Some("github_token_prefix")
        );
        assert_eq!(
            forbidden_label_value("sk-ant-api03-yyyyyyyyyyyyyyyyyyyyyyyy"),
            Some("anthropic_key_prefix")
        );
        assert_eq!(
            forbidden_label_value("AKIAEXAMPLE12345"),
            Some("aws_access_key_prefix")
        );
        assert_eq!(
            forbidden_label_value("cfat_zzzzzzzz"),
            Some("cloudflare_token_prefix")
        );
        assert_eq!(forbidden_label_value("hvs.AAA"), Some("vault_token_prefix"));
    }

    #[test]
    fn forbidden_gate_rejects_pem_block() {
        let pem = "\x2d----BEGIN PRIVATE KEY-----\nfoo\n-----END PRIVATE KEY-----";
        assert_eq!(forbidden_label_value(pem), Some("pem_block"));
    }

    #[test]
    fn forbidden_gate_rejects_grants_toml_fragment() {
        assert_eq!(
            forbidden_label_value("scope = \"vault.read\""),
            Some("grants_toml_fragment")
        );
        assert_eq!(
            forbidden_label_value("predicate = \"path.startswith(/v1/)\""),
            Some("grants_toml_fragment")
        );
    }

    #[test]
    fn forbidden_gate_passes_safe_values() {
        assert_eq!(forbidden_label_value("session_claude_code"), None);
        assert_eq!(forbidden_label_value("ok"), None);
        assert_eq!(forbidden_label_value("namespace/sa-name"), None);
    }
}
