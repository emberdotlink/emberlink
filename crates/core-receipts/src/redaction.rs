//! Receipt redaction rule engine (TZ-RECEIPT-V2-CLI).
//!
//! Receipts contain raw tool outputs that may include secrets, PII, or PHI;
//! redaction is applied before a receipt is exported (e.g. to a third party
//! for audit verification).
//!
//! Rules use a glob-style path syntax against the receipt's JSON tree:
//! `events.*.tool_output.aws.secret_access_key`. A `*` segment matches a
//! single object key or array index; multi-segment globs are not supported
//! (keep the matcher dumb and fast).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A single redaction rule: which JSON path to match, and what to do with values
/// found there.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionRule {
    /// Glob pattern matching the JSON path inside the receipt (e.g.
    /// `events.*.tool_output.aws.secret_access_key`). Each `.`-separated
    /// segment is matched literally except `*`, which matches any single
    /// segment (object key or array index).
    pub path: String,
    /// What to replace matched values with.
    pub strategy: RedactionStrategy,
}

/// Replacement strategy for a matched JSON value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RedactionStrategy {
    /// Replace with a fixed string (e.g. `"<REDACTED>"`).
    Mask(String),
    /// Replace with a hex-encoded SHA-256 hash of the original (preserves
    /// correlation across receipts without leaking the value).
    Hash,
    /// Remove the field entirely.
    Drop,
}

/// Summary of which paths were redacted and how many values matched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionReport {
    /// Concrete JSON paths (no `*`) that were matched and redacted.
    pub paths_redacted: Vec<String>,
    /// Total number of values matched across all rules.
    pub total_matches: usize,
}

/// Apply each rule to the receipt JSON in order. Returns a [`RedactionReport`]
/// describing what was scrubbed.
pub fn apply_redactions(receipt: &mut Value, rules: &[RedactionRule]) -> RedactionReport {
    let mut report = RedactionReport::default();
    for rule in rules {
        let segments: Vec<&str> = rule.path.split('.').collect();
        if segments.is_empty() {
            continue;
        }
        apply_rule_inner(
            receipt,
            &segments,
            0,
            &rule.strategy,
            &mut Vec::new(),
            &mut report,
        );
    }
    report
}

/// Default rule set: redact common secret-shape paths as `<REDACTED>`.
///
/// Covers: AWS / GCP / Azure / Vault credential fields plus generic
/// `password` / `private_key` / `api_key` patterns. Each glob walks any depth
/// via the `**`-like behavior of repeated `*` segments at the leading edge.
pub fn default_redaction_rules() -> Vec<RedactionRule> {
    let masked = RedactionStrategy::Mask("<REDACTED>".to_string());
    let leaf_paths = [
        "aws.secret_access_key",
        "aws.session_token",
        "gcp.access_token",
        "azure.access_token",
        "vault_token",
        "password",
        "private_key",
        "api_key",
    ];
    let mut rules = Vec::with_capacity(leaf_paths.len() * MAX_DEPTH);
    for leaf in leaf_paths {
        // Materialise rules for receipts up to MAX_DEPTH levels of nesting.
        // We do it this way (rather than a true `**` matcher) to keep the
        // matcher simple, single-pass, and free of regex dependencies.
        for depth in 0..MAX_DEPTH {
            let prefix = "*.".repeat(depth);
            rules.push(RedactionRule {
                path: format!("{prefix}{leaf}"),
                strategy: masked.clone(),
            });
        }
    }
    rules
}

const MAX_DEPTH: usize = 8;

/// Compile-time visible alias for downstream callers that want a constant-
/// looking identifier for the canonical default rule set. Both spellings
/// (`DEFAULT_REDACTION_RULES()` and `default_redaction_rules()`) return the
/// same `Vec`.
#[allow(non_snake_case)]
pub fn DEFAULT_REDACTION_RULES() -> Vec<RedactionRule> {
    default_redaction_rules()
}

fn apply_rule_inner(
    node: &mut Value,
    segments: &[&str],
    idx: usize,
    strategy: &RedactionStrategy,
    path_so_far: &mut Vec<String>,
    report: &mut RedactionReport,
) {
    if idx == segments.len() {
        // Terminal: redact this value in place.
        let concrete_path = path_so_far.join(".");
        if !concrete_path.is_empty() {
            report.paths_redacted.push(concrete_path);
        } else {
            report.paths_redacted.push("<root>".to_string());
        }
        report.total_matches += 1;
        match strategy {
            RedactionStrategy::Mask(s) => {
                *node = Value::String(s.clone());
            }
            RedactionStrategy::Hash => {
                let original = serde_json::to_vec(node).unwrap_or_default();
                let mut hasher = Sha256::new();
                hasher.update(&original);
                let digest = hex::encode(hasher.finalize());
                *node = Value::String(format!("sha256:{digest}"));
            }
            RedactionStrategy::Drop => {
                *node = Value::Null;
            }
        }
        return;
    }

    let seg = segments[idx];
    match node {
        Value::Object(map) => {
            // Collect keys to recurse into (avoid borrow issues).
            let keys: Vec<String> = if seg == "*" {
                map.keys().cloned().collect()
            } else if map.contains_key(seg) {
                vec![seg.to_string()]
            } else {
                Vec::new()
            };
            // Track which keys to drop entirely (for terminal Drop strategy).
            let mut drop_keys: Vec<String> = Vec::new();
            let is_terminal_drop =
                idx + 1 == segments.len() && matches!(strategy, RedactionStrategy::Drop);
            for k in keys {
                path_so_far.push(k.clone());
                if is_terminal_drop {
                    let concrete_path = path_so_far.join(".");
                    report.paths_redacted.push(concrete_path);
                    report.total_matches += 1;
                    drop_keys.push(k);
                } else if let Some(child) = map.get_mut(&k) {
                    apply_rule_inner(child, segments, idx + 1, strategy, path_so_far, report);
                }
                path_so_far.pop();
            }
            for k in drop_keys {
                map.remove(&k);
            }
        }
        Value::Array(arr) => {
            // For arrays, `*` matches every index; a digit segment matches that index.
            let indices: Vec<usize> = if seg == "*" {
                (0..arr.len()).collect()
            } else if let Ok(i) = seg.parse::<usize>() {
                if i < arr.len() { vec![i] } else { Vec::new() }
            } else {
                Vec::new()
            };
            for i in indices {
                path_so_far.push(i.to_string());
                if let Some(child) = arr.get_mut(i) {
                    apply_rule_inner(child, segments, idx + 1, strategy, path_so_far, report);
                }
                path_so_far.pop();
            }
        }
        _ => { /* scalar: cannot descend, no match */ }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    #[test]
    fn mask_replaces_value() {
        let mut v = json!({ "password": "hunter2" });
        let rules = vec![RedactionRule {
            path: "password".to_string(),
            strategy: RedactionStrategy::Mask("<REDACTED>".to_string()),
        }];
        let report = apply_redactions(&mut v, &rules);
        assert_eq!(v["password"], json!("<REDACTED>"));
        assert_eq!(report.total_matches, 1);
        assert_eq!(report.paths_redacted, vec!["password"]);
    }

    #[test]
    fn hash_replaces_with_sha256_prefix() {
        let mut v = json!({ "private_key": "abc123" });
        let rules = vec![RedactionRule {
            path: "private_key".to_string(),
            strategy: RedactionStrategy::Hash,
        }];
        apply_redactions(&mut v, &rules);
        let s = v["private_key"].as_str().unwrap();
        assert!(s.starts_with("sha256:"), "got {s}");
        assert_eq!(s.len(), "sha256:".len() + 64);
    }

    #[test]
    fn drop_removes_field() {
        let mut v = json!({ "api_key": "x", "keep": "y" });
        let rules = vec![RedactionRule {
            path: "api_key".to_string(),
            strategy: RedactionStrategy::Drop,
        }];
        let report = apply_redactions(&mut v, &rules);
        assert!(v.get("api_key").is_none());
        assert_eq!(v["keep"], json!("y"));
        assert_eq!(report.total_matches, 1);
    }

    #[test]
    fn missing_path_is_no_op() {
        let mut v = json!({ "other": "x" });
        let rules = vec![RedactionRule {
            path: "password".to_string(),
            strategy: RedactionStrategy::Mask("<REDACTED>".to_string()),
        }];
        let report = apply_redactions(&mut v, &rules);
        assert_eq!(report.total_matches, 0);
        assert!(report.paths_redacted.is_empty());
        assert_eq!(v["other"], json!("x"));
    }

    #[test]
    fn glob_star_matches_array_elements() {
        let mut v = json!({
            "events": [
                { "tool_output": { "password": "a" } },
                { "tool_output": { "password": "b" } }
            ]
        });
        let rules = vec![RedactionRule {
            path: "events.*.tool_output.password".to_string(),
            strategy: RedactionStrategy::Mask("<REDACTED>".to_string()),
        }];
        let report = apply_redactions(&mut v, &rules);
        assert_eq!(report.total_matches, 2);
        assert_eq!(
            v["events"][0]["tool_output"]["password"],
            json!("<REDACTED>")
        );
        assert_eq!(
            v["events"][1]["tool_output"]["password"],
            json!("<REDACTED>")
        );
    }

    #[test]
    fn multiple_rules_apply_in_order() {
        let mut v = json!({
            "password": "p",
            "api_key": "k"
        });
        let rules = vec![
            RedactionRule {
                path: "password".to_string(),
                strategy: RedactionStrategy::Mask("<REDACTED>".to_string()),
            },
            RedactionRule {
                path: "api_key".to_string(),
                strategy: RedactionStrategy::Drop,
            },
        ];
        let report = apply_redactions(&mut v, &rules);
        assert_eq!(report.total_matches, 2);
        assert_eq!(v["password"], json!("<REDACTED>"));
        assert!(v.get("api_key").is_none());
    }

    #[test]
    fn large_nested_receipt_redacts_all_secrets() {
        let mut v = json!({
            "events": [
                {
                    "tool_output": {
                        "aws": { "secret_access_key": "AKIA...", "session_token": "TKN" },
                        "harmless": "ok"
                    }
                },
                {
                    "tool_output": {
                        "gcp": { "access_token": "ya29..." },
                        "vault_token": "s.foo"
                    }
                }
            ]
        });
        let rules = default_redaction_rules();
        let report = apply_redactions(&mut v, &rules);
        // We expect 4 matches: aws.secret_access_key, aws.session_token,
        // gcp.access_token, vault_token (each once).
        assert_eq!(report.total_matches, 4, "report: {report:?}");
        assert_eq!(
            v["events"][0]["tool_output"]["aws"]["secret_access_key"],
            json!("<REDACTED>")
        );
        assert_eq!(
            v["events"][0]["tool_output"]["aws"]["session_token"],
            json!("<REDACTED>")
        );
        assert_eq!(
            v["events"][1]["tool_output"]["gcp"]["access_token"],
            json!("<REDACTED>")
        );
        assert_eq!(
            v["events"][1]["tool_output"]["vault_token"],
            json!("<REDACTED>")
        );
        assert_eq!(v["events"][0]["tool_output"]["harmless"], json!("ok"));
    }

    #[test]
    fn default_rules_cover_aws_gcp_azure_vault_generic() {
        let rules = default_redaction_rules();
        // Every leaf in the spec must appear at least once.
        let leaves = [
            "aws.secret_access_key",
            "aws.session_token",
            "gcp.access_token",
            "azure.access_token",
            "vault_token",
            "password",
            "private_key",
            "api_key",
        ];
        for leaf in leaves {
            let any = rules.iter().any(|r| r.path.ends_with(leaf));
            assert!(any, "default rules missing leaf: {leaf}");
        }
    }

    fn scalar_value() -> impl Strategy<Value = Value> {
        prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|n| Value::Number(n.into())),
            "[a-zA-Z0-9 _.-]{0,32}".prop_map(Value::String),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        // Anchor: core_receipts_proptest_redaction_landed
        #[test]
        fn hash_strategy_matches_sha256_of_original_json(value in scalar_value()) {
            let mut v = json!({ "secret": value.clone(), "keep": "unchanged" });
            let rules = vec![RedactionRule {
                path: "secret".to_string(),
                strategy: RedactionStrategy::Hash,
            }];
            let expected = {
                let original = serde_json::to_vec(&value).unwrap();
                let mut hasher = Sha256::new();
                hasher.update(&original);
                format!("sha256:{}", hex::encode(hasher.finalize()))
            };

            let report = apply_redactions(&mut v, &rules);

            prop_assert_eq!(report.total_matches, 1);
            prop_assert_eq!(report.paths_redacted, vec!["secret"]);
            prop_assert_eq!(&v["secret"], &Value::String(expected));
            prop_assert_eq!(&v["keep"], &json!("unchanged"));
        }

        #[test]
        fn wildcard_array_mask_reports_every_matched_index(values in proptest::collection::vec("[a-zA-Z0-9 _.-]{0,16}", 0..16)) {
            let events: Vec<Value> = values
                .iter()
                .enumerate()
                .map(|(idx, value)| json!({
                    "password": value,
                    "keep": format!("keep-{idx}"),
                }))
                .collect();
            let mut v = json!({ "events": events });
            let rules = vec![RedactionRule {
                path: "events.*.password".to_string(),
                strategy: RedactionStrategy::Mask("<REDACTED>".to_string()),
            }];

            let report = apply_redactions(&mut v, &rules);

            prop_assert_eq!(report.total_matches, values.len());
            prop_assert_eq!(
                report.paths_redacted,
                (0..values.len())
                    .map(|idx| format!("events.{idx}.password"))
                    .collect::<Vec<_>>()
            );
            for idx in 0..values.len() {
                prop_assert_eq!(&v["events"][idx]["password"], &json!("<REDACTED>"));
                prop_assert_eq!(&v["events"][idx]["keep"], &json!(format!("keep-{idx}")));
            }
        }

        #[test]
        fn non_matching_literal_rule_preserves_document(key in "[a-z]{1,12}", value in scalar_value()) {
            prop_assume!(key != "password");
            let original = json!({ key.clone(): value, "stable": ["left", "alone"] });
            let mut v = original.clone();
            let rules = vec![RedactionRule {
                path: "password".to_string(),
                strategy: RedactionStrategy::Mask("<REDACTED>".to_string()),
            }];

            let report = apply_redactions(&mut v, &rules);

            prop_assert_eq!(report.total_matches, 0);
            prop_assert!(report.paths_redacted.is_empty());
            prop_assert_eq!(v, original);
        }

        #[test]
        fn drop_object_field_removes_only_target(secret in scalar_value(), keep in scalar_value()) {
            let mut v = json!({ "api_key": secret, "keep": keep.clone() });
            let rules = vec![RedactionRule {
                path: "api_key".to_string(),
                strategy: RedactionStrategy::Drop,
            }];

            let report = apply_redactions(&mut v, &rules);

            prop_assert_eq!(report.total_matches, 1);
            prop_assert_eq!(report.paths_redacted, vec!["api_key"]);
            prop_assert!(v.get("api_key").is_none());
            prop_assert_eq!(&v["keep"], &keep);
        }
    }
}
