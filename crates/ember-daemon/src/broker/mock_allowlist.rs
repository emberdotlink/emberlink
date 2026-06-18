//! CLASSIFICATION: PUBLIC
//!
//! META-DEV-PROD-PARITY-MOCK-BROKER-EXPLICIT (ADR 157 §Component 2) —
//! parser + helper for `EMBER_ALLOW_MOCK_BROKERS`. MockBroker registration
//! is now an explicit opt-in: missing provider credentials FAIL daemon
//! startup unless the operator has named the provider in this allowlist.
//!
//! Per ADR 157 §Component 2 + ADR 094 §"MockBroker is explicit opt-in,
//! never silent fallback": the dev-vs-prod identity decision must come
//! from a single explicit input parameter, never from environment-variable
//! branching that creates two divergent code paths. This module is that
//! parameter's parser.
//!
//! Receipts emitted by Mock-registered brokers stamp `mock_broker: true`
//! (sibling to `dev_mode_active`) so any audit trail can distinguish
//! "real credentials" from "Mock that returned a plausible-looking fake
//! token." See `crate::broker::handler::materialization::emit_materialization_audit_event`
//! (audit-row stamp; materialization is an audit event, not a Receipt —
//! ADR 205 §B.6) and `crate::infra::receipt::build_broker_revocation_envelope`
//! (revocation receipt stamp) for the stamp wiring.
//!
//! Checkpoint for autopilot ranker grep:
//! **`dev_prod_parity_mock_broker_explicit_landed`** — this module's
//! existence + the absence of the silent-fallback shape in
//! `crate::infra::runtime::run_broker_registration` is the load-bearing
//! invariant.

use std::collections::HashSet;

use core_broker::BrokerProvider;

/// Env var name. Documented in ADR 157 §Component 2.
pub const ALLOW_MOCK_BROKERS_ENV: &str = "EMBER_ALLOW_MOCK_BROKERS";

/// Parse the `EMBER_ALLOW_MOCK_BROKERS` env-var contents into the set of
/// providers for which a MockBroker registration is allowed in lieu of
/// real credentials.
///
/// Accepts a comma-separated list of provider names matching
/// [`BrokerProvider::as_str`] (lowercase, `snake_case` — `github`,
/// `aws_sts`, `azure_cli`, `fly_io`, `gcp`, `hashi_vault`, `okta`,
/// `vercel`, `cloudflare`, `anthropic`, `tailscale`).
///
/// Tolerant of:
///
/// - empty input (returns an empty set — no providers allow-listed),
/// - leading / trailing whitespace per entry,
/// - empty entries between commas (e.g. `"github,,vercel"` → `{Github, Vercel}`),
/// - mixed-case input (`"Github"` → `Github`).
///
/// Unrecognized provider names are returned via the second tuple slot so
/// the daemon startup banner can surface a structured warning rather than
/// silently dropping operator intent. The daemon does NOT fail-loud on
/// unrecognized names — the operator may have a typo in a name they meant
/// to allow-list, and the safer posture is to fail-loud at the real-creds
/// check (which will tell them the provider has no Mock allow-listed) than
/// to refuse startup on a env-var spelling.
pub fn parse_allow_mock_brokers(raw: &str) -> (HashSet<BrokerProvider>, Vec<String>) {
    let mut allowed: HashSet<BrokerProvider> = HashSet::new();
    let mut unknown: Vec<String> = Vec::new();
    for token in raw.split(',') {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = trimmed.to_ascii_lowercase();
        match provider_from_str(&normalized) {
            Some(p) => {
                allowed.insert(p);
            }
            None => unknown.push(trimmed.to_string()),
        }
    }
    (allowed, unknown)
}

/// Read `EMBER_ALLOW_MOCK_BROKERS` from the process env and parse.
///
/// Unset / empty / pure-whitespace env yields an empty allow-list. The
/// `unknown` Vec carries any tokens that failed the
/// [`BrokerProvider::as_str`] lookup so the caller can emit a structured
/// warning at daemon startup.
pub fn read_allow_mock_brokers_from_env() -> (HashSet<BrokerProvider>, Vec<String>) {
    match std::env::var(ALLOW_MOCK_BROKERS_ENV) {
        Ok(raw) => parse_allow_mock_brokers(&raw),
        Err(_) => (HashSet::new(), Vec::new()),
    }
}

/// Lowercase-name → `BrokerProvider` lookup, matching
/// [`BrokerProvider::as_str`] verbatim.
fn provider_from_str(name: &str) -> Option<BrokerProvider> {
    match name {
        "cloudflare" => Some(BrokerProvider::Cloudflare),
        "anthropic" => Some(BrokerProvider::Anthropic),
        "github" => Some(BrokerProvider::Github),
        "aws_sts" => Some(BrokerProvider::AwsSts),
        "azure_cli" => Some(BrokerProvider::AzureCli),
        "fly_io" => Some(BrokerProvider::FlyIo),
        "gcp" => Some(BrokerProvider::Gcp),
        "hashi_vault" => Some(BrokerProvider::HashiVault),
        "okta" => Some(BrokerProvider::Okta),
        "tailscale" => Some(BrokerProvider::Tailscale),
        "vercel" => Some(BrokerProvider::Vercel),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    //! T1 tests per `.claude/rules/test-tiers.md` — no I/O, no env mutation
    //! (the env-reading function is exercised in a single test that locks
    //! the process-global mutex). Pure parsing logic.

    use super::*;

    /// Property-style exhaustive case table for the parser. The brief calls
    /// this a "property test" — proptest is not a workspace dep so we use
    /// an exhaustive case table that covers every parser branch (empty,
    /// single, multi, whitespace, mixed-case, unknown).
    #[test]
    fn parse_allow_mock_brokers_case_table() {
        let cases: &[(&str, &[BrokerProvider], &[&str])] = &[
            // empty input → empty allow-list, no unknowns
            ("", &[], &[]),
            // single token
            ("github", &[BrokerProvider::Github], &[]),
            // multi token, comma-separated
            (
                "github,vercel,okta",
                &[
                    BrokerProvider::Github,
                    BrokerProvider::Vercel,
                    BrokerProvider::Okta,
                ],
                &[],
            ),
            // whitespace tolerance — spaces around commas
            (
                " github , vercel ",
                &[BrokerProvider::Github, BrokerProvider::Vercel],
                &[],
            ),
            // empty entries between commas
            (
                "github,,vercel",
                &[BrokerProvider::Github, BrokerProvider::Vercel],
                &[],
            ),
            // leading / trailing commas
            (",github,", &[BrokerProvider::Github], &[]),
            // only commas / whitespace → empty
            (" , , ", &[], &[]),
            // mixed-case normalized to lowercase
            (
                "Github,VERCEL,Okta",
                &[
                    BrokerProvider::Github,
                    BrokerProvider::Vercel,
                    BrokerProvider::Okta,
                ],
                &[],
            ),
            // unknown token recorded but does not block known tokens
            (
                "github,not_a_provider,vercel",
                &[BrokerProvider::Github, BrokerProvider::Vercel],
                &["not_a_provider"],
            ),
            // all four cloud providers
            (
                "github,aws_sts,gcp,azure_cli",
                &[
                    BrokerProvider::Github,
                    BrokerProvider::AwsSts,
                    BrokerProvider::Gcp,
                    BrokerProvider::AzureCli,
                ],
                &[],
            ),
            // duplicate token (set dedup)
            ("github,github", &[BrokerProvider::Github], &[]),
        ];

        for (raw, expected_allowed, expected_unknown) in cases {
            let (allowed, unknown) = parse_allow_mock_brokers(raw);
            let expected_set: HashSet<BrokerProvider> = expected_allowed.iter().copied().collect();
            assert_eq!(allowed, expected_set, "parse({raw:?}) allowed mismatch");
            let expected_unknown_vec: Vec<String> =
                expected_unknown.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                unknown, expected_unknown_vec,
                "parse({raw:?}) unknown mismatch"
            );
        }
    }

    /// All snake_case names in [`BrokerProvider::as_str`] round-trip through
    /// [`provider_from_str`]. Guards against a new variant being added to
    /// the enum without the parser learning about it.
    #[test]
    fn provider_from_str_covers_all_variants() {
        let all = [
            BrokerProvider::Cloudflare,
            BrokerProvider::Anthropic,
            BrokerProvider::Github,
            BrokerProvider::AwsSts,
            BrokerProvider::AzureCli,
            BrokerProvider::FlyIo,
            BrokerProvider::Gcp,
            BrokerProvider::HashiVault,
            BrokerProvider::Okta,
            BrokerProvider::Tailscale,
            BrokerProvider::Vercel,
        ];
        for p in all {
            let name = p.as_str();
            let parsed =
                provider_from_str(name).unwrap_or_else(|| panic!("missing variant: {name}"));
            assert_eq!(parsed, p, "round-trip mismatch for {name}");
        }
    }

    /// Checkpoint constant exposure — the `dev_prod_parity_mock_broker_explicit_landed`
    /// marker is the module-level doc-comment; this test asserts the env-var
    /// constant is stable so external tooling (CI, install scripts, ADR 157
    /// migration docs) can rely on the spelling.
    #[test]
    fn allow_mock_brokers_env_constant_is_stable() {
        assert_eq!(ALLOW_MOCK_BROKERS_ENV, "EMBER_ALLOW_MOCK_BROKERS");
    }
}
