//! CLASSIFICATION: PUBLIC
//!
//! Closed-set redaction rules for `ember audit export`.
//!
//! ADR 160 Component 5 deliberately rejects custom regexes. Every rule
//! here has a fixed semantic and produces deterministic witnesses keyed by
//! the export salt, so the exported manifest can explain exactly what was
//! transformed.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RedactionRule {
    #[serde(rename = "gh-token-values")]
    GhTokenValues,
    #[serde(rename = "pr-titles")]
    PrTitles,
    #[serde(rename = "binary-paths")]
    BinaryPaths,
}

impl RedactionRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GhTokenValues => "gh-token-values",
            Self::PrTitles => "pr-titles",
            Self::BinaryPaths => "binary-paths",
        }
    }
}

impl std::fmt::Display for RedactionRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RedactionRule {
    type Err = RedactionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "gh-token-values" => Ok(Self::GhTokenValues),
            "pr-titles" => Ok(Self::PrTitles),
            "binary-paths" => Ok(Self::BinaryPaths),
            other => Err(RedactionError::UnknownRule(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RedactionError {
    #[error("unknown redaction rule '{0}' (supported: gh-token-values, pr-titles, binary-paths)")]
    UnknownRule(String),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionStats {
    pub values_changed: usize,
}

pub fn parse_redaction_rules(input: Option<&str>) -> Result<Vec<RedactionRule>, RedactionError> {
    let Some(input) = input else {
        return Ok(Vec::new());
    };
    let mut rules = Vec::new();
    for raw in input.split(',') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let rule = RedactionRule::from_str(trimmed)?;
        if !rules.contains(&rule) {
            rules.push(rule);
        }
    }
    rules.sort();
    Ok(rules)
}

pub fn apply_redactions(
    value: &mut Value,
    rules: &[RedactionRule],
    salt: &[u8; 32],
    home: Option<&str>,
) -> RedactionStats {
    let mut stats = RedactionStats::default();
    redact_value(value, rules, salt, home, None, &mut stats);
    stats
}

fn redact_value(
    value: &mut Value,
    rules: &[RedactionRule],
    salt: &[u8; 32],
    home: Option<&str>,
    key: Option<&str>,
    stats: &mut RedactionStats,
) {
    match value {
        Value::Object(map) => {
            for (child_key, child_value) in map.iter_mut() {
                redact_value(child_value, rules, salt, home, Some(child_key), stats);
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_value(item, rules, salt, home, key, stats);
            }
        }
        Value::String(s) => {
            let original = s.clone();
            let mut current = original.clone();
            for rule in rules {
                match rule {
                    RedactionRule::GhTokenValues => {
                        current = redact_gh_token_values(&current, salt);
                    }
                    RedactionRule::PrTitles => {
                        if key.map(is_pr_title_key).unwrap_or(false) {
                            current = redaction_marker(salt, &current);
                        }
                    }
                    RedactionRule::BinaryPaths => {
                        if let Some(home) = home {
                            current = redact_home_paths(&current, home);
                        }
                    }
                }
            }
            if current != original {
                *s = current;
                stats.values_changed += 1;
            }
        }
        _ => {}
    }
}

fn is_pr_title_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k == "title"
        || k == "pr_title"
        || k == "pull_request_title"
        || k == "commit_message"
        || k == "commitmessage"
        || k == "message"
}

fn redact_gh_token_values(input: &str, salt: &[u8; 32]) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    let mut changed = false;

    while let Some(idx) = rest.find("GH_TOKEN=") {
        let (before, after_before) = rest.split_at(idx);
        out.push_str(before);
        out.push_str("GH_TOKEN=");
        let value_start = "GH_TOKEN=".len();
        let after = &after_before[value_start..];
        let end = after
            .char_indices()
            .find_map(|(i, ch)| is_token_delimiter(ch).then_some(i))
            .unwrap_or(after.len());
        let token = &after[..end];
        if token.is_empty() || token.starts_with("<redacted-blake3:") {
            out.push_str(token);
        } else {
            out.push_str(&redaction_marker(salt, token));
            changed = true;
        }
        rest = &after[end..];
    }
    out.push_str(rest);

    if !changed && looks_like_github_token(input) {
        return redaction_marker(salt, input);
    }
    out
}

fn is_token_delimiter(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ';' | ')' | ']' | '}')
}

fn looks_like_github_token(input: &str) -> bool {
    let s = input.trim();
    (s.starts_with("ghp_") || s.starts_with("github_pat_")) && s.len() > 8
}

fn redact_home_paths(input: &str, home: &str) -> String {
    if home.is_empty() || !input.contains(home) {
        return input.to_string();
    }
    let home_slash = format!("{home}/");
    let mut out = input.replace(&home_slash, "~/");
    if out == home {
        out = "~".to_string();
    }
    out
}

pub fn redaction_marker(salt: &[u8; 32], input: &str) -> String {
    let digest = blake3::keyed_hash(salt, input.as_bytes()).to_hex();
    let short = &digest.as_str()[..16];
    format!("<redacted-blake3:{short};len={}>", input.chars().count())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_closed_rule_set_only() {
        let rules = parse_redaction_rules(Some("binary-paths, gh-token-values")).unwrap();
        assert_eq!(
            rules,
            vec![RedactionRule::GhTokenValues, RedactionRule::BinaryPaths]
        );
        assert!(parse_redaction_rules(Some("custom-regex")).is_err());
    }

    #[test]
    fn redacts_github_token_values_with_salt_witness() {
        let salt = [7u8; 32];
        let token = ["ghp", "_secret123"].join("");
        let mut value = json!({"env": format!("GH_TOKEN={token} echo ok")});
        let stats = apply_redactions(&mut value, &[RedactionRule::GhTokenValues], &salt, None);
        assert_eq!(stats.values_changed, 1);
        let rendered = value["env"].as_str().unwrap();
        assert!(rendered.starts_with("GH_TOKEN=<redacted-blake3:"));
        assert!(rendered.contains(";len=13>"));
        assert!(!rendered.contains("ghp_secret123"));
    }

    #[test]
    fn same_input_differs_across_export_salts() {
        let a = redaction_marker(&[1u8; 32], "Fix production deploy");
        let b = redaction_marker(&[2u8; 32], "Fix production deploy");
        assert_ne!(a, b);
    }

    #[test]
    fn redacts_pr_titles_and_home_paths() {
        let salt = [3u8; 32];
        let mut value = json!({
            "title": "Ship the thing",
            "binary": "/Users/alice/bin/gh"
        });
        let stats = apply_redactions(
            &mut value,
            &[RedactionRule::PrTitles, RedactionRule::BinaryPaths],
            &salt,
            Some("/Users/alice"),
        );
        assert_eq!(stats.values_changed, 2);
        assert!(
            value["title"]
                .as_str()
                .unwrap()
                .starts_with("<redacted-blake3:")
        );
        assert_eq!(value["binary"], "~/bin/gh");
    }
}
