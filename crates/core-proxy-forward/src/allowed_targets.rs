//! CLASSIFICATION: PUBLIC
//! One canonical storage+parse encoding for grant `allowed_targets` (ADR 207
//! SEAM-8B follow-up — `allowed_targets_storage_and_parse_one_encoding`).
//!
//! Write site (`create_grant` in `ember-daemon`) serialises the operator's
//! input array via `serde_json::to_string` — storage is therefore always a
//! JSON array of host patterns. Read sites (proxy forward gate, standing-
//! grant matcher, dashboard UI) parse through [`parse_allowed_targets`]
//! here. Comma-form is gone; per-entry validation is enforced at the write
//! site via [`validate_allowed_target_entry`].

/// Parse a stored `allowed_targets` string into trimmed, non-empty host
/// patterns.
///
/// - A JSON-array source (`["a.com","*.b.com"]`) yields each entry trimmed,
///   skipping empties.
/// - A bare single-pattern source (`api.acme.com`) is treated as one entry —
///   preserves both the existing forward-runtime unit tests (single-string
///   inputs) and the raw-SQL test fixtures that `UPDATE grants SET
///   allowed_targets = '<host>'` directly.
/// - An empty / whitespace-only source yields an empty vec — caller decides
///   what that means (the proxy gate treats it as deny-all).
pub fn parse_allowed_targets(s: &str) -> Vec<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with('[')
        && let Ok(arr) = serde_json::from_str::<Vec<String>>(trimmed)
    {
        return arr
            .into_iter()
            .map(|e| e.trim().to_string())
            .filter(|e| !e.is_empty())
            .collect();
    }
    // Falls through to single-entry treatment on malformed JSON, which
    // for a string that starts with `[` is almost certainly garbage —
    // returning an empty vec would fail-closed silently, while a single
    // garbage entry will simply not match any host (still deny). Tested
    // by `parse_allowed_targets_malformed_json_falls_through_safely`.
    vec![trimmed.to_string()]
}

/// Reject host-pattern entries flagged by the ADR 207 SEAM-8B adversarial
/// review at the `create_grant` write site:
///   - empty string
///   - bare `*` (would universally allow)
///   - `*.` with empty domain (would match any trailing-dot FQDN — the LOW
///     over-match flagged in SEAM-8B)
///
/// Returns the human-readable refusal reason on `Err`.
pub fn validate_allowed_target_entry(entry: &str) -> Result<(), &'static str> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Err("entry must not be empty");
    }
    if trimmed == "*" {
        return Err("bare '*' is not a valid host pattern");
    }
    if let Some(domain) = trimmed.strip_prefix("*.")
        && domain.trim().is_empty()
    {
        return Err("'*.' with empty domain is not a valid host pattern");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_allowed_targets_json_array_single_entry() {
        assert_eq!(
            parse_allowed_targets("[\"api.acme.com\"]"),
            vec!["api.acme.com".to_string()]
        );
    }

    #[test]
    fn parse_allowed_targets_json_array_multi_entry() {
        assert_eq!(
            parse_allowed_targets("[\"api.acme.com\",\"*.acme.org\"]"),
            vec!["api.acme.com".to_string(), "*.acme.org".to_string()]
        );
    }

    #[test]
    fn parse_allowed_targets_bare_string_is_single_entry() {
        // Preserves forward.rs single-string fixtures and raw-SQL test
        // UPDATEs (`SET allowed_targets = 'api.github.com'`).
        assert_eq!(
            parse_allowed_targets("api.acme.com"),
            vec!["api.acme.com".to_string()]
        );
    }

    #[test]
    fn parse_allowed_targets_empty_is_empty_vec() {
        assert!(parse_allowed_targets("").is_empty());
        assert!(parse_allowed_targets("   ").is_empty());
    }

    #[test]
    fn parse_allowed_targets_json_array_skips_empty_entries() {
        assert_eq!(
            parse_allowed_targets("[\"\",\"api.acme.com\",\"  \"]"),
            vec!["api.acme.com".to_string()]
        );
    }

    #[test]
    fn parse_allowed_targets_malformed_json_falls_through_safely() {
        // A `[`-prefixed but invalid JSON string is treated as a single
        // entry — will not match any real host, so the proxy gate denies.
        let entries = parse_allowed_targets("[broken");
        assert_eq!(entries, vec!["[broken".to_string()]);
    }

    #[test]
    fn validate_allowed_target_entry_accepts_normal_hosts() {
        assert!(validate_allowed_target_entry("api.acme.com").is_ok());
        assert!(validate_allowed_target_entry("*.acme.com").is_ok());
    }

    #[test]
    fn validate_allowed_target_entry_rejects_empty() {
        assert!(validate_allowed_target_entry("").is_err());
        assert!(validate_allowed_target_entry("   ").is_err());
    }

    #[test]
    fn validate_allowed_target_entry_rejects_bare_star() {
        assert!(validate_allowed_target_entry("*").is_err());
    }

    #[test]
    fn validate_allowed_target_entry_rejects_star_dot_empty_domain() {
        assert!(validate_allowed_target_entry("*.").is_err());
        assert!(validate_allowed_target_entry("*.   ").is_err());
    }
}
