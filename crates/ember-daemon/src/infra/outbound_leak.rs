/// Outbound leak detection primitives.
///
/// Pure, stateless scanning functions that detect known credential formats and
/// active-grant plaintext fingerprints in outbound request bodies and URLs.
///
/// # Byte-offset semantics
///
/// All offsets refer to the raw byte position in the content slice passed to the
/// scanning function. If the caller pre-decodes base64 or gzip before calling,
/// offsets refer to the *decoded* byte stream — document that at the call site.
///
/// # Size cap
///
/// `scan_body` and `scan_response` refuse to scan inputs larger than `SCAN_CAP`
/// bytes. Inputs that exceed the cap return a single synthetic `LeakPattern::Oversized`
/// hit with `offset = 0` and `length = 0`, then return without further scanning.
/// This defends against memory-bomb attacks via enormous response bodies.
use aho_corasick::AhoCorasick;
use once_cell::sync::Lazy;
use regex::bytes::Regex;

/// Maximum body size that will be fully scanned.
const SCAN_CAP: usize = 1024 * 1024; // 1 MiB

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A detected leak in outbound content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakHit {
    /// Where in the request the match was found.
    pub location: LeakLocation,
    /// What kind of credential pattern matched.
    pub pattern: LeakPattern,
    /// Byte offset of match start in the original content (for audit log).
    pub offset: usize,
    /// Length of matched substring in bytes.
    pub length: usize,
}

/// Which part of an HTTP transaction the match occurred in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakLocation {
    /// Query string or path component of a URL.
    Url,
    /// A header value. `Authorization` is explicitly excluded — only OTHER
    /// headers are scanned (that value is the intended credential carrier).
    HeaderValue,
    /// The outbound request body.
    RequestBody,
    /// The inbound response body (data-exfil / "server echoes my secret" case).
    ResponseBody,
}

/// The category of credential format that matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeakPattern {
    /// Anthropic API key — `sk-ant-api\d+-[A-Za-z0-9_-]{80,}`
    AnthropicApiKey,
    /// OpenAI project key — `sk-proj-[A-Za-z0-9_-]{40,}`
    /// or legacy key — `sk-[A-Za-z0-9_-]{40,}` (matched only when the
    /// longer Anthropic pattern does NOT apply)
    OpenAIApiKey,
    /// GitHub classic PAT — `ghp_[A-Za-z0-9]{36}` or fine-grained PAT —
    /// `github_pat_[A-Za-z0-9_]{82}`
    GitHubPAT,
    /// GitHub OAuth token — `gho_[A-Za-z0-9]{36}`
    GitHubOAuth,
    /// GitHub App installation or user-to-server token —
    /// `ghs_[A-Za-z0-9]{36}` or `ghu_[A-Za-z0-9]{36}`
    GitHubApp,
    /// Slack bot token — `xoxb-…`
    SlackBot,
    /// Slack user token — `xoxp-…`
    SlackUser,
    /// Slack app token — `xoxa-…`
    SlackApp,
    /// AWS IAM access key ID — `AKIA[A-Z0-9]{16}` (exactly 20 chars total)
    AwsAccessKey,
    /// GCP service account JSON key — JSON field `"private_key_id":` followed
    /// by a 40-hex string.
    GcpServiceAccountKey,
    /// Active grant plaintext prefix — caller-supplied known-secret prefix
    /// detected via `scan_grant_plaintext`.
    GrantPlaintextPrefix,
    /// Input exceeded `SCAN_CAP`; scanning was aborted.
    Oversized,
}

// ---------------------------------------------------------------------------
// Pattern registry
// ---------------------------------------------------------------------------

/// (pattern_enum_constructor, regex_source)
///
/// **Order matters**: patterns are tested longest / most-specific first so
/// that, e.g., an Anthropic key that also contains `sk-` is attributed to
/// `AnthropicApiKey` and NOT `OpenAIApiKey`. The loop below skips byte
/// ranges already claimed by an earlier (higher-priority) match.
static PATTERNS: Lazy<Vec<(LeakPattern, Regex)>> = Lazy::new(|| {
    let defs: &[(&str, &str)] = &[
        // Most specific patterns first (longest prefixes / most constraints)
        ("AnthropicApiKey", r"sk-ant-api\d+-[A-Za-z0-9_-]{80,}"),
        ("GitHubPAT_finegrained", r"github_pat_[A-Za-z0-9_]{82}"),
        ("GitHubPAT", r"ghp_[A-Za-z0-9]{36}"),
        ("GitHubOAuth", r"gho_[A-Za-z0-9]{36}"),
        ("GitHubApp", r"(?:ghs_|ghu_)[A-Za-z0-9]{36}"),
        ("SlackBot", r"xoxb-[0-9]+-[0-9]+-[0-9]+-[a-zA-Z0-9]+"),
        ("SlackUser", r"xoxp-[0-9]+-[0-9]+-[0-9]+-[a-zA-Z0-9]+"),
        ("SlackApp", r"xoxa-[0-9]+-[0-9]+-[0-9]+-[a-zA-Z0-9]+"),
        // AWS key: exactly 20 chars (AKIA + 16)
        ("AwsAccessKey", r"AKIA[A-Z0-9]{16}(?:[^A-Z0-9]|$)"),
        // GCP: "private_key_id" JSON field with 40-hex value
        (
            "GcpServiceAccountKey",
            r#""private_key_id"\s*:\s*"[0-9a-f]{40}""#,
        ),
        // OpenAI: project keys first (more specific), then legacy keys
        ("OpenAIApiKey_proj", r"sk-proj-[A-Za-z0-9_-]{40,}"),
        ("OpenAIApiKey", r"sk-[A-Za-z0-9_-]{40,}"),
    ];

    defs.iter()
        .map(|(tag, src)| {
            let pat = match *tag {
                "AnthropicApiKey" => LeakPattern::AnthropicApiKey,
                "GitHubPAT_finegrained" => LeakPattern::GitHubPAT,
                "GitHubPAT" => LeakPattern::GitHubPAT,
                "GitHubOAuth" => LeakPattern::GitHubOAuth,
                "GitHubApp" => LeakPattern::GitHubApp,
                "SlackBot" => LeakPattern::SlackBot,
                "SlackUser" => LeakPattern::SlackUser,
                "SlackApp" => LeakPattern::SlackApp,
                "AwsAccessKey" => LeakPattern::AwsAccessKey,
                "GcpServiceAccountKey" => LeakPattern::GcpServiceAccountKey,
                "OpenAIApiKey_proj" => LeakPattern::OpenAIApiKey,
                "OpenAIApiKey" => LeakPattern::OpenAIApiKey,
                _ => unreachable!(),
            };
            let re =
                Regex::new(src).unwrap_or_else(|e| panic!("bad outbound_leak pattern {tag}: {e}"));
            (pat, re)
        })
        .collect()
});

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Scan `content` using the compiled pattern list.
/// Returns hits with byte offsets in `content`. Overlapping ranges claimed
/// by an earlier (higher-priority) pattern are skipped for later patterns.
fn scan_bytes(content: &[u8], location: LeakLocation) -> Vec<LeakHit> {
    // Track claimed byte ranges to implement "longest / most-specific wins".
    // We use a simple sorted vec of (start, end) ranges and skip any match
    // whose start falls inside an already-claimed range.
    let mut claimed: Vec<(usize, usize)> = Vec::new();

    let mut hits: Vec<LeakHit> = Vec::new();

    for (pattern, re) in PATTERNS.iter() {
        for m in re.find_iter(content) {
            let start = m.start();
            let end = m.end();

            // Skip if this byte range overlaps an already-claimed match.
            if claimed.iter().any(|&(cs, ce)| start < ce && end > cs) {
                continue;
            }

            // AWS key regex ends with a lookahead-substitute `(?:[^A-Z0-9]|$)`.
            // Trim the non-key trailing byte from the match length.
            let (actual_start, actual_len) = if matches!(pattern, LeakPattern::AwsAccessKey) {
                // The regex matches 20 key chars + optional 1 trailing char.
                // Clamp length to exactly 20.
                let key_len = m.as_bytes().len().min(20);
                (start, key_len)
            } else {
                (start, end - start)
            };

            claimed.push((start, end));
            hits.push(LeakHit {
                location,
                pattern: pattern.clone(),
                offset: actual_start,
                length: actual_len,
            });
        }
    }

    hits.sort_by_key(|h| h.offset);
    hits
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan a URL (path + query string) for known credential patterns.
pub fn scan_url(url: &str) -> Vec<LeakHit> {
    scan_bytes(url.as_bytes(), LeakLocation::Url)
}

/// Scan a request or other body for known credential patterns.
///
/// Returns a single `LeakPattern::Oversized` hit and stops if `body` exceeds
/// `SCAN_CAP` (1 MiB).
pub fn scan_body(body: &[u8], location: LeakLocation) -> Vec<LeakHit> {
    if body.len() > SCAN_CAP {
        return vec![LeakHit {
            location,
            pattern: LeakPattern::Oversized,
            offset: 0,
            length: 0,
        }];
    }
    scan_bytes(body, location)
}

/// Scan a response body for known credential patterns.
///
/// Same detection logic as `scan_body` but uses `LeakLocation::ResponseBody`.
/// Captures the "server echoes a secret back" data-exfil case.
pub fn scan_response(body: &[u8]) -> Vec<LeakHit> {
    scan_body(body, LeakLocation::ResponseBody)
}

/// Check whether any active-grant plaintext prefix appears in `content`.
///
/// The caller is responsible for feeding the current grant set's known secret
/// prefixes — this function is deliberately stateless. For performance, uses
/// Aho-Corasick multi-pattern search (O(n + |sum_of_pattern_lengths|) over the
/// content, regardless of prefix count). Suitable for hot-path use in Cycle 2's
/// composite proxy rewrite.
///
/// Returns one `LeakHit` per occurrence (overlapping matches are NOT collapsed
/// here — every prefix occurrence is reported so the caller can decide policy).
/// `location` is always `LeakLocation::RequestBody`; callers that want a
/// different location should adjust after the call.
pub fn scan_grant_plaintext(content: &[u8], prefixes: &[&[u8]]) -> Vec<LeakHit> {
    if prefixes.is_empty() || content.is_empty() {
        return Vec::new();
    }

    // Build the automaton; panics only if patterns are empty (guarded above).
    let ac = AhoCorasick::new(prefixes)
        .unwrap_or_else(|e| panic!("outbound_leak: aho-corasick build failed: {e}"));

    ac.find_iter(content)
        .map(|m| LeakHit {
            location: LeakLocation::RequestBody,
            pattern: LeakPattern::GrantPlaintextPrefix,
            offset: m.start(),
            length: m.end() - m.start(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- positive hits per pattern ----------------------------------------

    #[test]
    fn detects_anthropic_key_in_url() {
        let key = "sk-ant-api03-".to_string() + &"A".repeat(80);
        let url = format!("https://example.com/api?token={key}");
        let hits = scan_url(&url);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pattern, LeakPattern::AnthropicApiKey);
        // Verify offset reproduces the match.
        let matched = &url.as_bytes()[hits[0].offset..hits[0].offset + hits[0].length];
        assert!(matched.starts_with(b"sk-ant-api03-"));
    }

    #[test]
    fn detects_github_pat_in_request_body() {
        let body = format!(r#"{{"token":"ghp_{}", "other":"value"}}"#, "B".repeat(36));
        let hits = scan_body(body.as_bytes(), LeakLocation::RequestBody);
        assert!(hits.iter().any(|h| h.pattern == LeakPattern::GitHubPAT));
    }

    #[test]
    fn detects_github_finegrained_pat() {
        let body = format!("Authorization: github_pat_{}", "C".repeat(82));
        let hits = scan_body(body.as_bytes(), LeakLocation::RequestBody);
        assert!(hits.iter().any(|h| h.pattern == LeakPattern::GitHubPAT));
    }

    #[test]
    fn detects_openai_proj_key_in_header_value() {
        let val = format!("Bearer sk-proj-{}", "D".repeat(40));
        let hits = scan_body(val.as_bytes(), LeakLocation::HeaderValue);
        assert!(hits.iter().any(|h| h.pattern == LeakPattern::OpenAIApiKey));
    }

    #[test]
    fn detects_openai_legacy_key() {
        let val = format!("sk-{}", "E".repeat(48));
        let hits = scan_url(&val);
        assert!(hits.iter().any(|h| h.pattern == LeakPattern::OpenAIApiKey));
    }

    #[test]
    fn detects_aws_access_key_in_body() {
        let body = b"AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE end";
        let hits = scan_body(body, LeakLocation::RequestBody);
        assert_eq!(hits.len(), 1, "hits: {hits:?}");
        assert_eq!(hits[0].pattern, LeakPattern::AwsAccessKey);
        // AWS key must be exactly 20 chars.
        assert_eq!(hits[0].length, 20);
    }

    #[test]
    fn detects_gcp_service_account_key() {
        let body = br#"{"private_key_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}"#;
        let hits = scan_body(body, LeakLocation::RequestBody);
        assert!(
            hits.iter()
                .any(|h| h.pattern == LeakPattern::GcpServiceAccountKey)
        );
    }

    #[test]
    fn detects_github_oauth_token() {
        let body = format!("token=gho_{}", "F".repeat(36));
        let hits = scan_body(body.as_bytes(), LeakLocation::RequestBody);
        assert!(hits.iter().any(|h| h.pattern == LeakPattern::GitHubOAuth));
    }

    #[test]
    fn detects_github_app_ghs_token() {
        let body = format!("ghs_{}", "G".repeat(36));
        let hits = scan_body(body.as_bytes(), LeakLocation::RequestBody);
        assert!(hits.iter().any(|h| h.pattern == LeakPattern::GitHubApp));
    }

    #[test]
    fn detects_github_app_ghu_token() {
        let body = format!("ghu_{}", "H".repeat(36));
        let hits = scan_body(body.as_bytes(), LeakLocation::RequestBody);
        assert!(hits.iter().any(|h| h.pattern == LeakPattern::GitHubApp));
    }

    #[test]
    fn detects_slack_bot_token() {
        let body = b"xoxb-123456-789012-345678-abcdef123456";
        let hits = scan_body(body, LeakLocation::RequestBody);
        assert!(hits.iter().any(|h| h.pattern == LeakPattern::SlackBot));
    }

    #[test]
    fn detects_slack_user_token() {
        let body = b"xoxp-123456-789012-345678-abcdef123456";
        let hits = scan_body(body, LeakLocation::RequestBody);
        assert!(hits.iter().any(|h| h.pattern == LeakPattern::SlackUser));
    }

    #[test]
    fn detects_slack_app_token() {
        let body = b"xoxa-2-123456-789012-345678-abcdef123456";
        let hits = scan_body(body, LeakLocation::RequestBody);
        assert!(hits.iter().any(|h| h.pattern == LeakPattern::SlackApp));
    }

    #[test]
    fn scan_response_uses_response_body_location() {
        let body = format!("sk-proj-{}", "R".repeat(40));
        let hits = scan_response(body.as_bytes());
        assert!(!hits.is_empty());
        assert!(
            hits.iter()
                .all(|h| h.location == LeakLocation::ResponseBody)
        );
    }

    // ---- negative / no false positives ------------------------------------

    #[test]
    fn no_match_sk_prefix_too_short() {
        // "sk-" followed by only 10 chars — not a valid OpenAI key.
        let hits = scan_url("https://example.com?q=sk-tooshort12");
        assert!(hits.is_empty(), "unexpected hits: {hits:?}");
    }

    #[test]
    fn no_match_ghp_prefix_too_short() {
        // `ghp_` with only 10 chars after — not a valid PAT.
        let hits = scan_body(b"ghp_tooshort10", LeakLocation::RequestBody);
        assert!(hits.is_empty(), "unexpected hits: {hits:?}");
    }

    #[test]
    fn no_match_random_hex_40_chars() {
        // A 40-char hex string with no recognized prefix is not an AWS key.
        let body = b"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let hits = scan_body(body, LeakLocation::RequestBody);
        assert!(hits.is_empty(), "unexpected hits: {hits:?}");
    }

    #[test]
    fn no_match_akia_wrong_chars() {
        // AKIA followed by lowercase — not a valid AWS key.
        let body = b"AKIAiosfodnn7example";
        let hits = scan_body(body, LeakLocation::RequestBody);
        assert!(hits.is_empty(), "unexpected hits: {hits:?}");
    }

    // ---- overlapping pattern dedup ----------------------------------------

    #[test]
    fn anthropic_key_wins_over_openai_prefix() {
        // An Anthropic key starts with `sk-ant-api…` which also contains `sk-`.
        // Only AnthropicApiKey should be reported, not OpenAIApiKey.
        let key = format!("sk-ant-api03-{}", "A".repeat(80));
        let hits = scan_url(&key);

        let anthropic_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.pattern == LeakPattern::AnthropicApiKey)
            .collect();
        let openai_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.pattern == LeakPattern::OpenAIApiKey)
            .collect();

        assert_eq!(
            anthropic_hits.len(),
            1,
            "expected exactly one AnthropicApiKey hit"
        );
        assert_eq!(
            openai_hits.len(),
            0,
            "OpenAIApiKey must not fire for Anthropic key"
        );
    }

    // ---- byte offset correctness ------------------------------------------

    #[test]
    fn offset_reproduces_match() {
        let prefix = "prefix_data_";
        let key = format!("ghp_{}", "K".repeat(36));
        let content = format!("{prefix}{key}suffix");
        let hits = scan_body(content.as_bytes(), LeakLocation::RequestBody);
        let gh_hit = hits
            .iter()
            .find(|h| h.pattern == LeakPattern::GitHubPAT)
            .expect("expected GitHubPAT hit");

        let slice = &content.as_bytes()[gh_hit.offset..gh_hit.offset + gh_hit.length];
        assert_eq!(
            slice,
            key.as_bytes(),
            "offset+length must reproduce the match"
        );
        assert_eq!(gh_hit.offset, prefix.len(), "offset must point past prefix");
    }

    // ---- oversized input --------------------------------------------------

    #[test]
    fn oversized_body_returns_single_oversized_hit() {
        let big = vec![b'x'; SCAN_CAP + 1];
        let hits = scan_body(&big, LeakLocation::RequestBody);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pattern, LeakPattern::Oversized);
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[0].length, 0);
    }

    #[test]
    fn at_cap_boundary_is_not_oversized() {
        // Exactly at SCAN_CAP — should scan normally (empty result for random data).
        let at_cap = vec![b'z'; SCAN_CAP];
        let hits = scan_body(&at_cap, LeakLocation::RequestBody);
        assert!(
            hits.iter().all(|h| h.pattern != LeakPattern::Oversized),
            "exactly SCAN_CAP bytes must not trigger Oversized"
        );
    }

    // ---- scan_grant_plaintext ---------------------------------------------

    #[test]
    fn grant_plaintext_detects_prefix() {
        let prefix: &[u8] = b"token-ABCDEF";
        let content = b"outbound body containing token-ABCDEF inside";
        let hits = scan_grant_plaintext(content, &[prefix]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pattern, LeakPattern::GrantPlaintextPrefix);
        assert_eq!(hits[0].offset, "outbound body containing ".len());
        assert_eq!(hits[0].length, prefix.len());
    }

    #[test]
    fn grant_plaintext_no_hit_when_absent() {
        let prefix: &[u8] = b"token-ABCDEF";
        let content = b"nothing interesting here";
        let hits = scan_grant_plaintext(content, &[prefix]);
        assert!(hits.is_empty());
    }

    #[test]
    fn grant_plaintext_multiple_prefixes() {
        let p1: &[u8] = b"secret-AAA";
        let p2: &[u8] = b"secret-BBB";
        let content = b"secret-AAA and secret-BBB both present";
        let hits = scan_grant_plaintext(content, &[p1, p2]);
        assert_eq!(hits.len(), 2);
    }

    // ---- empty / edge cases -----------------------------------------------

    #[test]
    fn empty_url_returns_empty() {
        assert!(scan_url("").is_empty());
    }

    #[test]
    fn empty_body_returns_empty() {
        assert!(scan_body(&[], LeakLocation::RequestBody).is_empty());
    }

    #[test]
    fn empty_response_returns_empty() {
        assert!(scan_response(&[]).is_empty());
    }

    #[test]
    fn grant_plaintext_empty_prefixes_returns_empty() {
        let hits = scan_grant_plaintext(b"some content", &[]);
        assert!(hits.is_empty());
    }

    #[test]
    fn grant_plaintext_empty_content_returns_empty() {
        let hits = scan_grant_plaintext(&[], &[b"prefix"]);
        assert!(hits.is_empty());
    }
}
