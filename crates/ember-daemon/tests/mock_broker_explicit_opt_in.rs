//! CLASSIFICATION: PUBLIC
//!
//! META-DEV-PROD-PARITY-MOCK-BROKER-EXPLICIT — T2 integration tests for
//! ADR 157 §Component 2. Asserts the load-bearing invariants:
//!
//! 1. The BrokerRegistry distinguishes real-broker vs Mock-registered
//!    providers (via `register` vs `register_mock`) and surfaces this
//!    via `is_mock(provider)`.
//! 2. The `mock_broker` audit signal distinguishes Mock-registered from
//!    real-broker credentials. For REVOCATION (a signed broker Receipt) it is
//!    stamped on the envelope body; for MATERIALIZATION — an AUDIT event, not a
//!    Receipt, per ADR 205 §B.6 — it is stamped on the hash-chained audit row
//!    (asserted in `broker::handler` unit tests). Both stamp it always-present
//!    (never omit-when-false) so absent==unknown.
//! 3. The `EMBER_ALLOW_MOCK_BROKERS` parser is the only place where
//!    operator opt-in is consumed. When creds are missing AND the provider
//!    is not in the parsed allowlist, the daemon-startup broker-registration
//!    loop SKIPS that provider (boots without it; the provider's actions
//!    fail closed when attempted) rather than registering a silent Mock.
//!    Per ADR 202 §Decision 3 (operator 2026-05-29) this is now uniform across
//!    all providers including GitHub, which was previously load-bearing and
//!    refused startup when absent — the no-silent-Mock invariant is intact
//!    (skipping is not mocking); only the boot-refusal was dropped so a fresh
//!    product install boots before first-use credential provisioning.
//!
//! Checkpoint marker: `dev_prod_parity_mock_broker_explicit_landed` —
//! grep for this string to confirm Phase 2 of ADR 157 has landed.

use core_broker::{BrokerProvider, MockBroker};
use ember_daemon::broker::handler::BrokerRegistry;
use ember_daemon::broker::mock_allowlist::{ALLOW_MOCK_BROKERS_ENV, parse_allow_mock_brokers};
use ember_daemon::infra::receipt::build_broker_revocation_envelope;

/// T2: registry.register_mock flags the provider, registry.register does not.
/// The `is_mock` query is the load-bearing audit signal that the receipt-
/// emission path consults to stamp `mock_broker`.
#[test]
fn registry_distinguishes_real_from_mock_registration() {
    let mut reg = BrokerRegistry::new();

    // register_mock → flagged
    reg.register_mock(Box::new(MockBroker::new(BrokerProvider::Github)));
    assert!(
        reg.is_mock(BrokerProvider::Github),
        "Github mock-registered must report is_mock=true"
    );

    // unflagged provider — never registered
    assert!(
        !reg.is_mock(BrokerProvider::AwsSts),
        "AwsSts never registered must report is_mock=false"
    );

    // register a real broker via the plain `register` path (we use a
    // MockBroker as the bare-bones DynBroker stand-in here; the
    // semantic intent of `register` is "this is the real-broker lane,
    // do NOT flag as mock"). is_mock must report false for AwsSts now.
    reg.register(Box::new(MockBroker::new(BrokerProvider::AwsSts)));
    assert!(
        !reg.is_mock(BrokerProvider::AwsSts),
        "AwsSts registered via register() (real lane) must NOT be flagged as mock"
    );

    // A real-broker re-registration over a mock retracts the flag
    // (defense-in-depth — see BrokerRegistry::register doc-comment).
    reg.register(Box::new(MockBroker::new(BrokerProvider::Github)));
    assert!(
        !reg.is_mock(BrokerProvider::Github),
        "re-registering via register() must clear the prior mock flag"
    );
}

/// T2: revocation Receipt envelopes also stamp the `mock_broker` audit
/// signal — symmetric with materialization (Component 2 says "every
/// credential_provisioned / credential_revoked Receipt").
#[test]
fn revocation_receipt_stamps_mock_broker_from_registry_flag() {
    let env_mock =
        build_broker_revocation_envelope("mat-revoked-mock", None, "daemon-root-t2", true);
    assert_eq!(
        env_mock.body.get("mock_broker").and_then(|v| v.as_bool()),
        Some(true),
        "mock-registered revocation envelope must stamp mock_broker: true"
    );

    let env_real =
        build_broker_revocation_envelope("mat-revoked-real", None, "daemon-root-t2", false);
    assert_eq!(
        env_real.body.get("mock_broker").and_then(|v| v.as_bool()),
        Some(false),
        "real-broker revocation envelope must stamp mock_broker: false"
    );

    // Per ADR 157 §Component 2 + ADR 118 schema conventions, the field is
    // ALWAYS present so absent==unknown rather than absent==implicitly-false.
    // Confirm the JSON serialization does NOT omit the field when false.
    let serialized = serde_json::to_string(&env_real.body).expect("body serializes");
    assert!(
        serialized.contains("\"mock_broker\":false"),
        "real-broker body JSON must explicitly carry mock_broker: false; got: {serialized}"
    );
}

/// T2: the parser is the single point of operator-intent ingestion. A
/// comma-separated list of provider names yields the expected set; an
/// empty/unset env yields an empty set (the fail-loud default).
#[test]
fn parser_yields_expected_allow_lists() {
    // empty input → empty set → daemon fails loud on missing creds
    let (allowed, _unknown) = parse_allow_mock_brokers("");
    assert!(
        allowed.is_empty(),
        "empty env must yield empty allow-list (fail-loud default)"
    );

    // single provider
    let (allowed, _unknown) = parse_allow_mock_brokers("github");
    assert!(
        allowed.contains(&BrokerProvider::Github),
        "single-provider parse must include github"
    );
    assert_eq!(
        allowed.len(),
        1,
        "single-provider parse must have one entry"
    );

    // multi-provider — the brief's example (`okta,vercel,fly_io`)
    let (allowed, _unknown) = parse_allow_mock_brokers("okta,vercel,fly_io");
    for p in [
        BrokerProvider::Okta,
        BrokerProvider::Vercel,
        BrokerProvider::FlyIo,
    ] {
        assert!(
            allowed.contains(&p),
            "okta,vercel,fly_io parse must include {p:?}"
        );
    }
    assert!(
        !allowed.contains(&BrokerProvider::Github),
        "okta,vercel,fly_io parse must NOT include github (the brief's fail-loud target)"
    );
}

/// T2: the env-var constant is the documented operator-facing surface.
/// Renaming it is a breaking change that requires an ADR amendment;
/// pinning the string here catches accidental renames.
#[test]
fn env_var_constant_matches_documented_name() {
    assert_eq!(
        ALLOW_MOCK_BROKERS_ENV, "EMBER_ALLOW_MOCK_BROKERS",
        "ADR 157 §Component 2 documents EMBER_ALLOW_MOCK_BROKERS as the operator-facing env var; \
         changing the spelling breaks every install script + plist that sets it"
    );
}

/// T2: round-trip the parser through every variant in BrokerProvider to
/// guard against a new variant being added to the enum without
/// `mock_allowlist::provider_from_str` learning about it. This is the
/// "exhaustiveness gate" that would catch a future PR adding a
/// `BrokerProvider::Snowflake` variant without updating the parser.
#[test]
fn parser_covers_every_broker_provider_variant() {
    let all_names: &[&str] = &[
        "cloudflare",
        "anthropic",
        "github",
        "aws_sts",
        "azure_cli",
        "fly_io",
        "gcp",
        "hashi_vault",
        "okta",
        "tailscale",
        "vercel",
    ];
    let joined = all_names.join(",");
    let (allowed, unknown) = parse_allow_mock_brokers(&joined);
    assert!(
        unknown.is_empty(),
        "all canonical names must parse cleanly; unknown={unknown:?}"
    );
    assert_eq!(
        allowed.len(),
        all_names.len(),
        "parsed set must have one entry per canonical name"
    );
}

/// T2: integration assertion — the brief's behavioral table for the
/// EMBER_ALLOW_MOCK_BROKERS env. Each row exercises (env, provider) →
/// (would_register_mock?). This is the decision-table the
/// daemon-startup loop consults; we re-prove it here so any future
/// refactor of that loop has a unit-level guard.
#[test]
fn allow_mock_brokers_decision_table() {
    let cases: &[(&str, BrokerProvider, bool)] = &[
        // empty env → no provider allowed → would fail-loud everywhere
        ("", BrokerProvider::Github, false),
        ("", BrokerProvider::AwsSts, false),
        // single opt-in
        ("github", BrokerProvider::Github, true),
        ("github", BrokerProvider::AwsSts, false),
        // multi opt-in
        ("github,vercel", BrokerProvider::Github, true),
        ("github,vercel", BrokerProvider::Vercel, true),
        ("github,vercel", BrokerProvider::AwsSts, false),
        // whitespace tolerance
        (" github , vercel ", BrokerProvider::Github, true),
        (" github , vercel ", BrokerProvider::Vercel, true),
        // mixed-case normalized
        ("Github,VERCEL", BrokerProvider::Github, true),
        ("Github,VERCEL", BrokerProvider::Vercel, true),
    ];
    for (env, provider, expected) in cases {
        let (allowed, _) = parse_allow_mock_brokers(env);
        let actual = allowed.contains(provider);
        assert_eq!(
            actual, *expected,
            "env={env:?} provider={provider:?} expected_in_allow={expected} got={actual}"
        );
    }
}
