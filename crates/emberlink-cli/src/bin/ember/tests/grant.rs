use super::*;
use core_grant_types::Usage;

fn anthropic_ref(
    kind: AnthropicRuntimeCredentialKind,
    credential_name: &str,
) -> AnthropicRuntimeCredentialRef {
    AnthropicRuntimeCredentialRef {
        kind,
        credential_name: credential_name.to_string(),
    }
}

/// Build a fake JWT `header.PAYLOAD.sig` whose middle segment is the given
/// claims JSON (base64url, no padding). Mirrors the daemon's codex_oauth test
/// helper — we only decode claims, never verify the signature.
fn fake_jwt(claims_json: &str) -> String {
    use base64::Engine as _;
    let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes());
    format!(
        "{}.{}.{}",
        b64("{\"alg\":\"none\"}"),
        b64(claims_json),
        b64("sig")
    )
}

#[test]
fn short_secret_fingerprint_is_stable_and_domain_separated() {
    // Deterministic: same (domain, secret) → same 24-hex-char fingerprint.
    let a = short_secret_fingerprint("anthropic-api-key", "sk-ant-secret");
    let b = short_secret_fingerprint("anthropic-api-key", "sk-ant-secret");
    assert_eq!(a, b);
    assert_eq!(a.len(), 24, "12 bytes of sha256 → 24 hex chars");
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));

    // Domain-separated: same secret, different domain → different fingerprint.
    let other_domain = short_secret_fingerprint("anthropic-plan-claude-oauth", "sk-ant-secret");
    assert_ne!(a, other_domain);

    // Value-sensitive: different secret → different fingerprint.
    let other_secret = short_secret_fingerprint("anthropic-api-key", "sk-ant-other");
    assert_ne!(a, other_secret);
}

#[test]
fn anthropic_runtime_credential_from_value_builds_keyed_slug() {
    let oauth = anthropic_runtime_credential_from_value(
        AnthropicRuntimeCredentialKind::OAuthToken,
        "sk-ant-oat01-abc",
    );
    assert_eq!(oauth.kind, AnthropicRuntimeCredentialKind::OAuthToken);
    assert!(
        oauth
            .credential_name()
            .starts_with(CLAUDE_CODE_ANTHROPIC_PLAN_OAUTH_RUNTIME_CREDENTIAL_PREFIX),
        "oauth slug must carry the plan prefix: {}",
        oauth.credential_name()
    );
    assert_eq!(
        claude_code_anthropic_runtime_credential_kind_from_name(oauth.credential_name()),
        Some(AnthropicRuntimeCredentialKind::OAuthToken)
    );

    let api = anthropic_runtime_credential_from_value(
        AnthropicRuntimeCredentialKind::ApiKey,
        "sk-ant-api03-xyz",
    );
    assert!(
        api.credential_name()
            .starts_with(CLAUDE_CODE_ANTHROPIC_API_KEY_RUNTIME_CREDENTIAL_PREFIX),
        "api-key slug must carry the api-key prefix: {}",
        api.credential_name()
    );
    assert_eq!(
        claude_code_anthropic_runtime_credential_kind_from_name(api.credential_name()),
        Some(AnthropicRuntimeCredentialKind::ApiKey)
    );

    // The same value under different kinds yields distinct slugs (domain
    // separation), and the slug is deterministic for a fixed (kind, value).
    let api_again = anthropic_runtime_credential_from_value(
        AnthropicRuntimeCredentialKind::ApiKey,
        "sk-ant-api03-xyz",
    );
    assert_eq!(api.credential_name(), api_again.credential_name());
    assert_ne!(oauth.credential_name(), api.credential_name());
}

#[test]
fn claude_code_credential_kind_rejects_flat_and_foreign_names() {
    // Legacy flat slugs no longer resolve to a kind.
    assert_eq!(
        claude_code_anthropic_runtime_credential_kind_from_name("anthropic/oauth-token"),
        None
    );
    assert_eq!(
        claude_code_anthropic_runtime_credential_kind_from_name("anthropic-key"),
        None
    );
    // Foreign provider names never resolve.
    assert_eq!(
        claude_code_anthropic_runtime_credential_kind_from_name("openai/plan/chatgpt-oauth/a/b"),
        None
    );
    // Keyed slugs resolve to their kind.
    assert_eq!(
        claude_code_anthropic_runtime_credential_kind_from_name(TEST_ANTHROPIC_OAUTH_CREDENTIAL),
        Some(AnthropicRuntimeCredentialKind::OAuthToken)
    );
    assert_eq!(
        claude_code_anthropic_runtime_credential_kind_from_name(TEST_ANTHROPIC_API_CREDENTIAL),
        Some(AnthropicRuntimeCredentialKind::ApiKey)
    );
}

#[test]
fn codex_openai_credential_name_keys_on_account_and_subject() {
    let blob = ember_daemon::infra::codex_oauth::CodexTokenBlob {
        id_token: Some(fake_jwt(
            r#"{"sub":"user-42","https://api.openai.com/auth":{"chatgpt_account_id":"acct-7"}}"#,
        )),
        access_token: "at".into(),
        refresh_token: None,
        account_id: None,
    };
    let name = codex_openai_chatgpt_runtime_credential_name(&blob);
    assert_eq!(name, "openai/plan/chatgpt-oauth/acct-7/user-42");
    assert!(is_codex_openai_chatgpt_runtime_credential_name(&name));
}

#[test]
fn codex_openai_credential_name_falls_back_when_subject_or_account_absent() {
    // No id_token at all → account=unknown-account, subject=token fingerprint.
    let blob = ember_daemon::infra::codex_oauth::CodexTokenBlob {
        id_token: None,
        access_token: "access-token-value".into(),
        refresh_token: None,
        account_id: None,
    };
    let name = codex_openai_chatgpt_runtime_credential_name(&blob);
    assert!(
        name.starts_with("openai/plan/chatgpt-oauth/unknown-account/token-"),
        "absent account+subject must fall back to a token fingerprint: {name}"
    );
    assert!(is_codex_openai_chatgpt_runtime_credential_name(&name));
    // Deterministic for the same token bytes.
    assert_eq!(name, codex_openai_chatgpt_runtime_credential_name(&blob));
}

#[test]
fn is_codex_openai_credential_name_rejects_flat_and_foreign_names() {
    assert!(!is_codex_openai_chatgpt_runtime_credential_name(
        "openai/chatgpt-oauth"
    ));
    assert!(!is_codex_openai_chatgpt_runtime_credential_name(
        TEST_ANTHROPIC_OAUTH_CREDENTIAL
    ));
    assert!(is_codex_openai_chatgpt_runtime_credential_name(
        TEST_OPENAI_CHATGPT_CREDENTIAL
    ));
}

#[test]
fn preferred_existing_codex_credential_picks_keyed_slug_only() {
    let entries = vec![
        serde_json::json!({ "name": "openai/chatgpt-oauth" }),
        serde_json::json!({ "name": TEST_OPENAI_CHATGPT_CREDENTIAL }),
        serde_json::json!({ "name": TEST_ANTHROPIC_OAUTH_CREDENTIAL }),
    ];
    assert_eq!(
        preferred_existing_codex_openai_runtime_credential(&entries).as_deref(),
        Some(TEST_OPENAI_CHATGPT_CREDENTIAL)
    );

    // No keyed credential present → None (flat/foreign names are ignored).
    let none = vec![
        serde_json::json!({ "name": "openai/chatgpt-oauth" }),
        serde_json::json!({ "name": TEST_ANTHROPIC_API_CREDENTIAL }),
    ];
    assert_eq!(
        preferred_existing_codex_openai_runtime_credential(&none),
        None
    );
}

#[test]
fn derived_credential_names_satisfy_the_daemon_vault_name_grammar() {
    // Regression for review findings F2/F3/F5/F7: a derived slug that the
    // daemon's `vault.add` rejects dead-ends `ember init` at the store step on a
    // name the operator cannot change. Every name we produce MUST pass the REAL
    // daemon validator — including for adversarial real-world inputs (digit-
    // leading hex fingerprints ~62.5% of values; UUID / underscore / uppercase /
    // dot account+subject). This round-trip is what the prior tests missed (they
    // used hand-written grammar-valid fixtures).
    use ember_daemon::infra::vault::validate_credential_name;

    for kind in [
        AnthropicRuntimeCredentialKind::OAuthToken,
        AnthropicRuntimeCredentialKind::ApiKey,
    ] {
        for i in 0..40 {
            let value = format!("sk-ant-secret-{i}");
            let name = anthropic_runtime_credential_from_value(kind, &value).credential_name;
            validate_credential_name(&name)
                .unwrap_or_else(|e| panic!("anthropic slug {name:?} rejected by daemon: {e:?}"));
        }
    }

    let codex_cases = [
        r#"{"sub":"User_AbC","https://api.openai.com/auth":{"chatgpt_account_id":"5e6f7a8b-1234-90ab-cdef-001122334455"}}"#,
        r#"{"sub":"auth0|abc.DEF/ghi","https://api.openai.com/auth":{"chatgpt_account_id":"acct_7"}}"#,
        r#"{"sub":"   ","https://api.openai.com/auth":{"chatgpt_account_id":"!!!"}}"#,
    ];
    for claims in codex_cases {
        let blob = ember_daemon::infra::codex_oauth::CodexTokenBlob {
            id_token: Some(fake_jwt(claims)),
            access_token: "access-token".into(),
            refresh_token: None,
            account_id: None,
        };
        let name = codex_openai_chatgpt_runtime_credential_name(&blob);
        validate_credential_name(&name)
            .unwrap_or_else(|e| panic!("codex slug {name:?} rejected by daemon: {e:?}"));
        assert!(is_codex_openai_chatgpt_runtime_credential_name(&name));
    }
}

#[test]
fn credential_identity_segment_conforms_to_vault_grammar() {
    use ember_daemon::infra::vault::validate_credential_name;
    // The sanitized segment must always satisfy `^[a-z][a-z0-9-]*$` so it can be
    // a vault-name path segment (review F8 — previously untested).
    let cases = [
        ("5e6f7a8b-1234", "id-5e6f7a8b-1234"), // digit-leading UUID → letter-tagged
        ("acct_7", "acct-7"),                  // underscore → dash
        ("User-AbC", "user-abc"),              // uppercase → lowercase
        ("a.b/c d", "a-b-c-d"),                // dots/slashes/spaces → single dashes
        ("!!!", "unknown"),                    // all-dropped → fallback
        ("  ", "unknown"),                     // whitespace-only → fallback
        ("--x--", "x"),                        // edge dashes trimmed
    ];
    for (raw, expected) in cases {
        let seg = credential_identity_segment(raw);
        assert_eq!(seg, expected, "segment for {raw:?}");
        // Wrap in a 2-segment name so the validator sees it as a path segment.
        validate_credential_name(&format!("openai/{seg}"))
            .unwrap_or_else(|e| panic!("segment {seg:?} (from {raw:?}) not grammar-valid: {e:?}"));
    }
}

#[test]
fn render_claude_runtime_auth_status_names_exact_follow_up_paths() {
    let rendered =
        render_claude_runtime_auth_status(&AnthropicRuntimeCredentialAvailability::Absent, "ember");
    assert!(rendered.contains("claude setup-token"));
    assert!(rendered.contains(CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL_PATTERN));
    assert!(rendered.contains("ANTHROPIC_API_KEY"));
    assert!(rendered.contains("ember init --for claude"));
}

#[test]
fn render_claude_runtime_auth_status_uses_explicit_repo_build_ember_command() {
    let rendered = render_claude_runtime_auth_status(
        &AnthropicRuntimeCredentialAvailability::Absent,
        "/home/operator/emberlink-example/target/debug/ember",
    );
    assert!(rendered.contains("claude setup-token"));
    assert!(rendered.contains(CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL_PATTERN));
    assert!(rendered.contains("/home/operator/emberlink-example/target/debug/ember init --for claude"));
    assert!(rendered.contains("ANTHROPIC_API_KEY"));
}

#[test]
fn render_claude_runtime_auth_status_names_existing_vault_entry() {
    let rendered = render_claude_runtime_auth_status(
        &AnthropicRuntimeCredentialAvailability::ExistingVaultEntry(anthropic_ref(
            AnthropicRuntimeCredentialKind::ApiKey,
            TEST_ANTHROPIC_API_CREDENTIAL,
        )),
        "ember",
    );
    assert!(rendered.contains("reusing anthropic/api/key/test-api from vault"));
}

#[test]
fn render_claude_runtime_auth_status_names_existing_oauth_vault_entry() {
    let rendered = render_claude_runtime_auth_status(
        &AnthropicRuntimeCredentialAvailability::ExistingVaultEntry(anthropic_ref(
            AnthropicRuntimeCredentialKind::OAuthToken,
            TEST_ANTHROPIC_OAUTH_CREDENTIAL,
        )),
        "ember",
    );
    assert!(rendered.contains("reusing anthropic/plan/claude-oauth/test-oauth from vault"));
}

#[test]
fn render_claude_init_summary_app_ready_centers_launch() {
    let rendered = render_claude_init_summary(
        "claude-code-default",
        true,
        Path::new("/tmp/grant-template.toml"),
        true,
        Path::new("/tmp/shadow"),
        AnthropicRuntimeCredentialAvailability::StoredFromEnv(anthropic_ref(
            AnthropicRuntimeCredentialKind::OAuthToken,
            TEST_ANTHROPIC_OAUTH_CREDENTIAL,
        )),
        &ClaudeCodeGrantProvisioning {
            id: "grant-1".to_string(),
            expires_at: Some("2026-05-25T00:00:00Z".to_string()),
            created: true,
            brokered_anthropic_runtime: true,
        },
        Path::new("/tmp/settings.json"),
        &emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture::AppConfiguredReal,
        None,
        None,
        "ember",
    );
    assert!(rendered.contains("Claude ready"));
    assert!(rendered.contains("ember claude"));
    assert!(rendered.contains("ember receipt list"));
    assert!(rendered.contains("Find the receipt after the first brokered action"));
    assert!(rendered.contains("GitHub: App lane ready"));
    assert!(!rendered.contains("ember github setup"));
    assert!(!rendered.contains("ember receipt show"));
}

#[test]
fn render_claude_init_summary_github_gap_centers_setup() {
    let rendered = render_claude_init_summary(
        "claude-code-default",
        false,
        Path::new("/tmp/grant-template.toml"),
        false,
        Path::new("/tmp/shadow"),
        AnthropicRuntimeCredentialAvailability::Absent,
        &ClaudeCodeGrantProvisioning {
            id: "grant-2".to_string(),
            expires_at: Some("2026-05-25T00:00:00Z".to_string()),
            created: false,
            brokered_anthropic_runtime: false,
        },
        Path::new("/tmp/settings.json"),
        &emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture::AppNotConfigured,
        Some("GitHub App credentials still need setup."),
        None,
        "ember",
    );
    assert!(rendered.contains("Claude needs one more step"));
    assert!(rendered.contains("ember github setup"));
    assert!(rendered.contains("Launch now if you do not need GitHub-brokered actions yet"));
    assert!(rendered.contains("Attention"));
}

#[test]
fn render_codex_init_summary_centers_launch_and_native_auth() {
    let rendered = render_codex_init_summary(
        "codex-default",
        true,
        Path::new("/tmp/grant-template-codex.toml"),
        true,
        &CodexGrantProvisioning {
            id: "grant-3".to_string(),
            expires_at: Some("2026-05-25T00:00:00Z".to_string()),
            created: true,
        },
        "ember",
    );
    assert!(rendered.contains("Codex ready"));
    assert!(rendered.contains("ember codex"));
    assert!(rendered.contains("ember receipt list"));
    assert!(rendered.contains("codex login status"));
    assert!(rendered.contains("Auth: remains managed by Codex"));
    assert!(!rendered.contains("ember receipt show"));
}

#[test]
fn render_basic_init_summary_centers_target_selection_and_receipt() {
    let rendered = render_basic_init_summary(
        Path::new("/tmp/config.toml"),
        Path::new("/tmp/policy.toml"),
        Path::new("/tmp/data/daemon.db"),
        "persona-root",
        "root",
        "managed by daemon (no CLI keychain bootstrap)",
        true,
        Path::new("/tmp/run/daemon.sock"),
        Some(&FirstGrantReceiptSummaryView {
            path: PathBuf::from("/tmp/data/receipts/first.json"),
            signature_prefix: "ed25519sig:abcd".to_string(),
            hash_prefix: "sha256:1234".to_string(),
            reused_existing: false,
        }),
        "ember",
    );
    assert!(rendered.contains("Ember ready"));
    assert!(rendered.contains("First proof"));
    assert!(rendered.contains("ember init --for claude"));
    assert!(rendered.contains("ember init --for codex"));
    assert!(rendered.contains("/tmp/data/receipts/first.json"));
    assert!(rendered.contains("Verify the first receipt offline"));
    assert!(
        rendered.contains(
            emberlink_cli::onboarding::first_grant::INIT_FIRST_GRANT_RECEIPT_EMIT_SENTINEL
        )
    );
}

#[test]
fn render_basic_init_summary_local_fallback_points_to_daemon_install() {
    let rendered = render_basic_init_summary(
        Path::new("/tmp/config.toml"),
        Path::new("/tmp/policy.toml"),
        Path::new("/tmp/data/daemon.db"),
        "persona-root",
        "root",
        "passphrase source: EMBER_VAULT_PASSPHRASE",
        false,
        Path::new("/tmp/run/daemon.sock"),
        None,
        "ember",
    );
    assert!(rendered.contains("Ember initialized in local fallback mode"));
    assert!(rendered.contains("sudo ember daemon install"));
    assert!(rendered.contains("ember status"));
    assert!(rendered.contains("local fallback"));
}

#[test]
fn preferred_existing_claude_runtime_credential_prefers_oauth() {
    let entries = vec![
        serde_json::json!({ "name": TEST_ANTHROPIC_API_CREDENTIAL }),
        serde_json::json!({ "name": TEST_ANTHROPIC_OAUTH_CREDENTIAL }),
    ];
    let credential = preferred_existing_claude_code_anthropic_runtime_credential(&entries)
        .expect("oauth credential should be preferred");
    assert_eq!(credential.kind, AnthropicRuntimeCredentialKind::OAuthToken);
    assert_eq!(
        credential.credential_name(),
        TEST_ANTHROPIC_OAUTH_CREDENTIAL
    );
}

#[test]
fn parse_usd_to_cents_accepts_decimal() {
    assert_eq!(parse_usd_to_cents("0.50").unwrap(), 50);
    assert_eq!(parse_usd_to_cents("1.00").unwrap(), 100);
    assert_eq!(parse_usd_to_cents("0.01").unwrap(), 1);
    assert_eq!(parse_usd_to_cents("10").unwrap(), 1000);
}

#[test]
fn parse_usd_to_cents_rejects_negative() {
    assert!(parse_usd_to_cents("-1.00").is_err());
    assert!(parse_usd_to_cents("-0.01").is_err());
}

#[test]
fn parse_duration_s_m_h_d() {
    assert_eq!(parse_duration("15s").unwrap(), 15);
    assert_eq!(parse_duration("5m").unwrap(), 300);
    assert_eq!(parse_duration("2h").unwrap(), 7200);
    assert_eq!(parse_duration("1d").unwrap(), 86400);
    assert_eq!(parse_duration("60").unwrap(), 60);
}

#[test]
fn parse_duration_rejects_overflow_on_days() {
    // u64::MAX / 86400 + 1 parses fine as u64 but overflows when multiplied by 86400
    let overflow_days = u64::MAX / 86400 + 1;
    let input = format!("{overflow_days}d");
    assert!(
        parse_duration(&input).is_err(),
        "days overflow should return Err"
    );
    // Same for hours: u64::MAX / 3600 + 1
    let overflow_hours = u64::MAX / 3600 + 1;
    let input = format!("{overflow_hours}h");
    assert!(
        parse_duration(&input).is_err(),
        "hours overflow should return Err"
    );
    // Same for minutes: u64::MAX / 60 + 1
    let overflow_mins = u64::MAX / 60 + 1;
    let input = format!("{overflow_mins}m");
    assert!(
        parse_duration(&input).is_err(),
        "minutes overflow should return Err"
    );
}

#[test]
fn build_budget_from_flags_all_set() {
    let b = build_budget(Some(20_000), Some(50), Some(100), Some(3600)).unwrap();
    assert_eq!(b.tokens, Some(20_000));
    assert_eq!(b.cents, Some(50));
    assert_eq!(b.requests, Some(100));
    assert_eq!(b.wall_clock_secs, Some(3600));
}

#[test]
fn build_budget_from_flags_none_set() {
    assert!(build_budget(None, None, None, None).is_none());
}

#[test]
fn build_composite_grant_statements_four_statements() {
    let stmts = build_composite_grant_statements(
        Some("obj-github-token"),
        Some(20_000),
        Some(50),
        Some(1800),
    );
    assert_eq!(stmts.len(), 4, "expected 4 statements");

    // Statement 0: Credential custody
    assert_eq!(stmts[0].credential_name, "obj-github-token");
    assert_eq!(stmts[0].resource_type, ResourceType::Credential);
    assert!(stmts[0].actions.contains(&"credential:read".to_string()));
    assert_eq!(
        stmts[0].resource,
        ResourceSelector::Exact {
            value: "obj-github-token".to_string()
        }
    );
    assert!(
        stmts[0].budget.is_none(),
        "credential statement must have no budget"
    );

    // Statement 1: GitHub operation authority — github:* on * (the dev0
    // ceiling, distinct from the credential:read custody statement above).
    assert_eq!(
        stmts[1].actions,
        vec!["github:*".to_string()],
        "github authority statement must declare exactly github:*"
    );
    assert_eq!(
        stmts[1].resource,
        ResourceSelector::Glob {
            pattern: "*".to_string()
        },
        "github authority must be over all of the owner's repos (*)"
    );
    assert!(
        stmts[1].budget.is_none(),
        "github authority statement carries no budget"
    );
    // Authority ⊥ custody: this is NOT the credential:read statement.
    assert!(
        !stmts[1].actions.contains(&"credential:read".to_string()),
        "github authority must not be the custody statement"
    );

    // Statement 2: Session
    assert_eq!(stmts[2].resource_type, ResourceType::Session);
    assert!(stmts[2].actions.contains(&"llm:generate".to_string()));
    assert_eq!(
        stmts[2].resource,
        ResourceSelector::Glob {
            pattern: "anthropic/*".to_string()
        }
    );
    let session_budget = stmts[2]
        .budget
        .as_ref()
        .expect("session must have a budget");
    assert_eq!(session_budget.tokens, Some(20_000));
    assert_eq!(session_budget.cents, Some(50));

    // Statement 3: Time
    assert_eq!(stmts[3].resource_type, ResourceType::Time);
    assert!(stmts[3].actions.contains(&"time:wall_clock".to_string()));
    assert_eq!(stmts[3].resource, ResourceSelector::Any);
    let time_budget = stmts[3].budget.as_ref().expect("time must have a budget");
    assert_eq!(time_budget.wall_clock_secs, Some(1800));
}

#[test]
fn build_composite_grant_statements_no_credential_returns_empty() {
    let stmts = build_composite_grant_statements(None, Some(20_000), Some(50), Some(1800));
    assert!(
        stmts.is_empty(),
        "no credential_resource means no statements"
    );
}

#[test]
fn build_composite_grant_statements_no_budgets_still_four_statements() {
    let stmts = build_composite_grant_statements(Some("obj-github-token"), None, None, None);
    assert_eq!(stmts.len(), 4);
    // stmts[1] is the github:* authority statement (always budget-less).
    assert_eq!(stmts[1].actions, vec!["github:*".to_string()]);
    assert!(
        stmts[2].budget.is_none(),
        "session budget absent when no token/cent flags"
    );
    assert!(
        stmts[3].budget.is_none(),
        "time budget absent when no seconds flag"
    );
}

#[test]
fn claude_code_runtime_grant_statements_include_github_ceiling() {
    let stmts = build_claude_code_anthropic_runtime_statements(TEST_ANTHROPIC_OAUTH_CREDENTIAL);
    assert_eq!(stmts.len(), 3);
    assert_eq!(stmts[0].actions, vec!["credential:read".to_string()]);
    assert_eq!(stmts[1].actions, vec!["github:*".to_string()]);
    assert_eq!(
        stmts[1].resource,
        ResourceSelector::Glob {
            pattern: "*".to_string()
        },
        "delegated ember-gh sessions need a durable github ceiling to narrow"
    );
    assert_eq!(stmts[2].actions, vec!["llm:generate".to_string()]);
}

#[test]
fn codex_runtime_grant_statements_include_github_ceiling() {
    let stmts = build_codex_openai_runtime_statements(TEST_OPENAI_CHATGPT_CREDENTIAL);
    assert_eq!(stmts.len(), 3);
    assert_eq!(stmts[0].actions, vec!["credential:read".to_string()]);
    assert_eq!(stmts[1].actions, vec!["github:*".to_string()]);
    assert_eq!(
        stmts[1].resource,
        ResourceSelector::Glob {
            pattern: "*".to_string()
        },
        "codex delegated ember-gh sessions need the same durable github ceiling"
    );
    assert_eq!(stmts[2].actions, vec!["llm:generate".to_string()]);
}

// --- helpers for render_grant_budget tests ---

fn make_test_statement(
    sid: &str,
    rt: ResourceType,
    resource: &str,
    budget: Option<Budget>,
    usage: Usage,
) -> Statement {
    Statement {
        sid: sid.into(),
        resource_type: rt,
        actions: vec!["read".to_string()],
        resource: ResourceSelector::Glob {
            pattern: resource.to_string(),
        },
        budget,
        usage,
        conditions: vec![],
        can_delegate: None,
    }
}

fn make_test_grant(statements_by_block: Vec<Vec<Statement>>) -> AccessGrant {
    use core_event_types::PresentationAudienceKind;
    use core_grant_types::{
        AttestationBinding, Block, GrantMode, GrantStatus, RecipientProfile, SignedBlock,
    };
    let blocks: Vec<SignedBlock> = statements_by_block
        .into_iter()
        .map(|stmts| SignedBlock {
            block: Block {
                statements: stmts,
                nbf: None,
                expires_at: None,
                issued_by: "persona-test".into(),
                issued_at: 0,
                approval: None,
                note: None,
            },
            pubkey_next: "deadbeef".into(),
            signature: "cafebabe".into(),
        })
        .collect();
    AccessGrant {
        id: "grant-test".into(),
        version: 1,
        issuing_persona_id: "persona-test".into(),
        recipient_kind: PresentationAudienceKind::Service,
        recipient_id: "cred".into(),
        recipient_profile: RecipientProfile::Agent,
        status: GrantStatus::Active,
        mode: GrantMode::OneShot,
        blocks,
        attestation: AttestationBinding::default(),
        created_at: 0,
        updated_at: 0,
        revoked_at: None,
        revoked_reason: None,
        last_used_at: None,
        label: None,
    }
}

#[test]
fn grant_budget_renders_populated_grant() {
    let stmt = make_test_statement(
        "S0",
        ResourceType::Session,
        "llm:generate",
        Some(Budget {
            tokens: Some(20_000),
            cents: Some(50),
            requests: None,
            workload_hours: None,
            wall_clock_secs: None,
        }),
        Usage {
            tokens: 14_342,
            cents: 37,
            last_updated: 0,
            ..Usage::default()
        },
    );
    let grant = make_test_grant(vec![vec![stmt]]);
    // Should not panic; budget and usage are populated.
    let out = render_grant_budget(&grant);
    assert!(out.contains("14342"), "missing token usage: {out}");
    assert!(out.contains("20000"), "missing token cap: {out}");
}

#[test]
fn grant_budget_renders_dash_when_usage_stale() {
    let stmt = make_test_statement(
        "S0",
        ResourceType::Session,
        "llm:generate",
        Some(Budget {
            tokens: Some(20_000),
            cents: None,
            requests: None,
            workload_hours: None,
            wall_clock_secs: None,
        }),
        Usage {
            tokens: 5_000,
            last_updated: 0,
            ..Usage::default()
        },
    );
    let grant = make_test_grant(vec![vec![stmt]]);
    // Stale usage — runway should show dash.
    let out = render_grant_budget(&grant);
    assert!(
        out.contains("Runway:  —"),
        "expected stale runway dash: {out}"
    );
}

#[test]
fn render_single_statement_no_budget() {
    let stmt = make_test_statement(
        "S0",
        ResourceType::Credential,
        "credential:*",
        None,
        Usage::default(),
    );
    let grant = make_test_grant(vec![vec![stmt]]);
    let out = render_grant_budget(&grant);
    assert!(out.contains("Grant grant-test"), "missing header: {out}");
    assert!(
        out.contains("Budget:  (none)"),
        "expected no-budget line: {out}"
    );
    // Single-statement grants must NOT show per-statement header.
    assert!(
        !out.contains("Statement S0"),
        "should not show stmt header for single: {out}"
    );
}

#[test]
fn render_composite_three_statements() {
    let s0 = make_test_statement(
        "S0",
        ResourceType::Credential,
        "credential:*",
        None,
        Usage::default(),
    );
    let s1 = make_test_statement(
        "S1",
        ResourceType::Session,
        "llm:generate",
        Some(Budget {
            tokens: Some(20_000),
            cents: Some(100),
            requests: None,
            workload_hours: None,
            wall_clock_secs: None,
        }),
        Usage {
            tokens: 12_450,
            cents: 85,
            requests: 0,
            workload_hours: 0,
            wall_clock_secs: 0,
            last_updated: 0,
            cents_micro: 85_000_000,
        },
    );
    let s2 = make_test_statement(
        "S2",
        ResourceType::Time,
        "session:*",
        Some(Budget {
            tokens: None,
            cents: None,
            requests: None,
            workload_hours: None,
            wall_clock_secs: Some(1800),
        }),
        Usage {
            tokens: 0,
            cents: 0,
            requests: 0,
            workload_hours: 0,
            wall_clock_secs: 240,
            last_updated: 0,
            cents_micro: 0,
        },
    );
    let grant = make_test_grant(vec![vec![s0, s1, s2]]);
    let out = render_grant_budget(&grant);

    // Should have per-statement headers.
    assert!(out.contains("Statement S0"), "missing S0 header: {out}");
    assert!(out.contains("Statement S1"), "missing S1 header: {out}");
    assert!(out.contains("Statement S2"), "missing S2 header: {out}");

    // S0 has no budget.
    assert!(
        out.contains("Budget:  (none)"),
        "expected no-budget for S0: {out}"
    );

    // S1 shows token and cent usage.
    assert!(out.contains("12450"), "missing token usage: {out}");
    assert!(out.contains("20000"), "missing token cap: {out}");
    assert!(out.contains("62%"), "wrong token pct: {out}");
    assert!(out.contains("85%"), "wrong cent pct: {out}");

    // S2 shows wall-clock usage.
    assert!(out.contains("240"), "missing wall-clock used: {out}");
    assert!(out.contains("1800"), "missing wall-clock cap: {out}");
    assert!(out.contains("13%"), "wrong wall-clock pct: {out}");
}

fn parse_grant_create(args: &[&str]) -> GrantAction {
    use clap::Parser as _;
    let full: Vec<&str> = std::iter::once("ember")
        .chain(std::iter::once("grant"))
        .chain(std::iter::once("create"))
        .chain(args.iter().copied())
        .collect();
    let cli = Cli::try_parse_from(&full).expect("parse failed");
    match cli.command {
        Commands::Grant { action } => action,
        _ => panic!("expected Grant command"),
    }
}

#[test]
fn grant_create_ttl_parses_humantime_and_bare_integer() {
    for (input, expected_secs) in [("5s", 5u64), ("5m", 300), ("2h", 7200), ("30", 30)] {
        let action = parse_grant_create(&[
            "--persona",
            "p1",
            "--credential",
            "cred-x",
            "--scope",
            "read",
            "--ttl",
            input,
        ]);
        match action {
            GrantAction::Create { ttl, .. } => {
                let s = ttl.as_deref().unwrap_or("");
                let parsed = parse_duration(s).expect("should parse");
                assert_eq!(parsed, expected_secs, "input={input}");
            }
            _ => panic!("expected GrantAction::Create"),
        }
    }
}

#[test]
fn parse_grant_create_spend_flags_route_into_spend_shape() {
    let action = parse_grant_create(&[
        "--persona",
        "p1",
        "--kind",
        "spend",
        "--vendor",
        "clearbit",
        "--max-cents",
        "4900",
        "--window",
        "24h",
        "--hard-cap",
        "25000",
    ]);
    match action {
        GrantAction::Create {
            kind,
            credential,
            scope,
            vendor,
            max_cents,
            window,
            hard_cap,
            ..
        } => {
            assert_eq!(kind, Some(GrantSurfaceKind::Spend));
            assert!(credential.is_none());
            assert!(scope.is_none());
            assert_eq!(vendor.as_deref(), Some("clearbit"));
            assert_eq!(max_cents, Some(4_900));
            assert_eq!(window.as_deref(), Some("24h"));
            assert_eq!(hard_cap, Some(25_000));
        }
        _ => panic!("expected GrantAction::Create"),
    }
}

#[test]
fn build_spend_grant_create_spec_emits_payment_statement_shape() {
    let spec = build_spend_grant_create_spec(
        "persona-1",
        "clearbit",
        Some(4_900),
        Some(25_000),
        Some(86_400),
    );
    assert_eq!(spec.persona_id, "persona-1");
    assert_eq!(spec.credential_name, "payment/clearbit");
    assert_eq!(spec.scope, "payment:charge");
    assert_eq!(spec.ttl_secs, Some(86_400));
    assert_eq!(spec.statements.len(), 1);
    let stmt = &spec.statements[0];
    assert_eq!(stmt.resource_type, ResourceType::Payment);
    assert_eq!(stmt.credential_name, "payment/clearbit");
    assert_eq!(stmt.actions, vec!["payment:charge".to_string()]);
    assert_eq!(stmt.resource, ResourceSelector::Any);
    assert_eq!(
        stmt.budget.as_ref().and_then(|budget| budget.cents),
        Some(25_000)
    );
    assert!(stmt.conditions.iter().any(|condition| matches!(
        condition,
        Condition::MerchantAllowlist { merchants } if merchants == &vec!["clearbit".to_string()]
    )));
    assert!(stmt.conditions.iter().any(|condition| matches!(
        condition,
        Condition::Range { field, min, max }
            if field == "amount_cents" && *min == Some(0) && *max == Some(4_900)
    )));
}

#[test]
fn read_attempt_toml_inserts_attempt_id_when_missing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let attempt = tmp.path().join("attempt.toml");
    std::fs::write(
        &attempt,
        "vendor = \"clearbit\"\namount_cents = 4900\nshadow = true\n",
    )
    .expect("write attempt");
    let params = read_attempt_toml(&attempt).expect("attempt toml");
    assert_eq!(params.get("vendor"), Some(&serde_json::json!("clearbit")));
    assert_eq!(params.get("amount_cents"), Some(&serde_json::json!(4900)));
    assert_eq!(params.get("shadow"), Some(&serde_json::json!(true)));
    let attempt_id = params
        .get("attempt_id")
        .and_then(|value| value.as_str())
        .expect("inserted attempt_id");
    assert!(attempt_id.starts_with("cli-attempt-"));
}

#[test]
fn grant_create_routes_full_shape_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("create_grant"));
            assert_eq!(
                request["params"]["persona_id"],
                serde_json::json!("persona-1")
            );
            assert_eq!(
                request["params"]["credential_name"],
                serde_json::json!("api-key")
            );
            assert_eq!(request["params"]["scope"], serde_json::json!("read"));
            assert_eq!(request["params"]["ttl_secs"], serde_json::json!(600));
            assert_eq!(request["params"]["max_uses_per_hour"], serde_json::json!(5));
            assert_eq!(
                request["params"]["allowed_hours_start"],
                serde_json::json!(9)
            );
            assert_eq!(
                request["params"]["allowed_hours_end"],
                serde_json::json!(17)
            );
            assert_eq!(
                request["params"]["allowed_targets"],
                serde_json::json!(["api.example.com", "uploads.example.com"])
            );
            assert_eq!(
                request["params"]["max_delegation_depth"],
                serde_json::json!(2)
            );
            assert_eq!(request["params"]["budget"]["tokens"], serde_json::json!(42));
            assert_eq!(
                request["params"]["max_children_per_day"],
                serde_json::json!(3)
            );
            assert_eq!(
                request["params"]["auto_delegate_scope_template"],
                serde_json::json!("github:push:acme/*")
            );

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {
                    "id": "grant-123",
                    "expires_at": null,
                    "budget": {"tokens": 42},
                },
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let spec = GrantCreateSpec {
        persona: "persona-1".to_string(),
        credential: "api-key".to_string(),
        scope: "read".to_string(),
        ttl_secs: Some(600),
        max_uses_per_hour: Some(5),
        allowed_hours_start: Some(9),
        allowed_hours_end: Some(17),
        allowed_targets: Some(vec![
            "api.example.com".to_string(),
            "uploads.example.com".to_string(),
        ]),
        max_delegation_depth: Some(2),
        budget: Some(Budget {
            tokens: Some(42),
            cents: None,
            requests: None,
            workload_hours: None,
            wall_clock_secs: None,
        }),
        max_children_per_day: Some(3),
        auto_delegate_scope_template: Some("github:push:acme/*".to_string()),
    };

    let (dispatch, response) = run_grant_create(&config, &spec).expect("grant create via daemon");
    assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
    assert_eq!(response["id"], serde_json::json!("grant-123"));
    server.join().expect("fake daemon thread");
}

#[test]
fn grant_create_composite_routes_statement_chain_through_daemon() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(
                request["method"],
                serde_json::json!("create_composite_grant")
            );
            assert_eq!(
                request["params"]["persona_id"],
                serde_json::json!("persona-1")
            );
            assert_eq!(
                request["params"]["credential_name"],
                serde_json::json!(TEST_ANTHROPIC_API_CREDENTIAL)
            );
            assert_eq!(
                request["params"]["scope"],
                serde_json::json!("claude-code-default-v1")
            );
            let statements = request["params"]["statements"]
                .as_array()
                .expect("statements array");
            assert_eq!(statements.len(), 3);
            assert_eq!(
                statements[0]["resource_type"],
                serde_json::json!("credential")
            );
            assert_eq!(statements[1]["actions"][0], serde_json::json!("github:*"));
            assert_eq!(statements[1]["resource"]["pattern"], serde_json::json!("*"));
            assert_eq!(
                statements[2]["resource"]["pattern"],
                serde_json::json!("anthropic/*")
            );

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {
                    "id": "grant-composite-123",
                    "expires_at": null,
                    "statement_count": 2,
                },
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let spec = CompositeGrantCreateSpec {
        persona_id: "persona-1".to_string(),
        credential_name: TEST_ANTHROPIC_API_CREDENTIAL.to_string(),
        scope: "claude-code-default-v1".to_string(),
        ttl_secs: Some(600),
        max_delegation_depth: Some(1),
        statements: build_claude_code_anthropic_runtime_statements(TEST_ANTHROPIC_API_CREDENTIAL),
    };

    let (dispatch, response) =
        run_grant_create_composite(&config, &spec).expect("composite grant create via daemon");
    assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
    assert_eq!(response["id"], serde_json::json!("grant-composite-123"));
    server.join().expect("fake daemon thread");
}

#[test]
fn grant_status_supports_anthropic_gateway_requires_both_statements() {
    let compatible = serde_json::json!({
        "live_lease": true,
        "statements": [
            {
                "resource_type": "credential",
                "actions": ["credential:read"],
                "resource": {"kind": "exact", "value": TEST_ANTHROPIC_API_CREDENTIAL}
            },
            {
                "resource_type": "session",
                "actions": ["llm:generate"],
                "resource": {"kind": "glob", "pattern": "anthropic/*"}
            },
            {
                "resource_type": "credential",
                "actions": ["github:*"],
                "resource": {"kind": "glob", "pattern": "*"}
            }
        ]
    });
    assert!(
        grant_status_supports_anthropic_gateway(&compatible, TEST_ANTHROPIC_API_CREDENTIAL),
        "expected matching credential + session statements to qualify"
    );

    let missing_session = serde_json::json!({
        "live_lease": true,
        "statements": [
            {
                "resource_type": "credential",
                "actions": ["credential:read"],
                "resource": {"kind": "exact", "value": TEST_ANTHROPIC_API_CREDENTIAL}
            },
            {
                "resource_type": "credential",
                "actions": ["github:*"],
                "resource": {"kind": "glob", "pattern": "*"}
            }
        ]
    });
    assert!(
        !grant_status_supports_anthropic_gateway(&missing_session, TEST_ANTHROPIC_API_CREDENTIAL),
        "credential statement alone must not qualify as an Anthropic gateway grant"
    );

    let missing_github_ceiling = serde_json::json!({
        "live_lease": true,
        "statements": [
            {
                "resource_type": "credential",
                "actions": ["credential:read"],
                "resource": {"kind": "exact", "value": TEST_ANTHROPIC_API_CREDENTIAL}
            },
            {
                "resource_type": "session",
                "actions": ["llm:generate"],
                "resource": {"kind": "glob", "pattern": "anthropic/*"}
            }
        ]
    });
    assert!(
        !grant_status_supports_anthropic_gateway(
            &missing_github_ceiling,
            TEST_ANTHROPIC_API_CREDENTIAL
        ),
        "model-only grants must not qualify; delegated ember-gh needs a github:* ceiling"
    );
}

#[test]
fn grant_status_supports_anthropic_gateway_matches_oauth_credential_name() {
    let compatible = serde_json::json!({
        "live_lease": true,
        "statements": [
            {
                "resource_type": "credential",
                "actions": ["credential:read"],
                "resource": {"kind": "exact", "value": TEST_ANTHROPIC_OAUTH_CREDENTIAL}
            },
            {
                "resource_type": "session",
                "actions": ["llm:generate"],
                "resource": {"kind": "glob", "pattern": "anthropic/*"}
            },
            {
                "resource_type": "credential",
                "actions": ["github:*"],
                "resource": {"kind": "glob", "pattern": "*"}
            }
        ]
    });
    assert!(
        grant_status_supports_anthropic_gateway(&compatible, TEST_ANTHROPIC_OAUTH_CREDENTIAL),
        "oauth credential name must qualify when the session statement matches"
    );
    assert!(
        !grant_status_supports_anthropic_gateway(&compatible, TEST_ANTHROPIC_API_CREDENTIAL),
        "credential statement must match the selected anthropic credential name exactly"
    );
}

#[test]
fn grant_status_supports_any_anthropic_gateway_accepts_any_exact_credential() {
    let compatible = serde_json::json!({
        "live_lease": true,
        "statements": [
            {
                "resource_type": "credential",
                "actions": ["credential:read"],
                "resource": {"kind": "exact", "value": TEST_ANTHROPIC_OAUTH_CREDENTIAL}
            },
            {
                "resource_type": "session",
                "actions": ["llm:generate"],
                "resource": {"kind": "glob", "pattern": "anthropic/*"}
            },
            {
                "resource_type": "credential",
                "actions": ["github:*"],
                "resource": {"kind": "glob", "pattern": "*"}
            }
        ]
    });
    assert!(
        grant_status_supports_any_anthropic_gateway(&compatible),
        "any exact credential read paired with the anthropic session statement should qualify"
    );
}

#[test]
fn grant_status_supports_codex_gateway_requires_openai_and_github_ceiling() {
    let compatible = serde_json::json!({
        "live_lease": true,
        "statements": [
            {
                "resource_type": "credential",
                "actions": ["credential:read"],
                "resource": {"kind": "exact", "value": TEST_OPENAI_CHATGPT_CREDENTIAL}
            },
            {
                "resource_type": "session",
                "actions": ["llm:generate"],
                "resource": {"kind": "glob", "pattern": "openai/*"}
            },
            {
                "resource_type": "credential",
                "actions": ["github:*"],
                "resource": {"kind": "glob", "pattern": "*"}
            }
        ]
    });
    assert!(grant_status_supports_codex_openai_gateway(
        &compatible,
        TEST_OPENAI_CHATGPT_CREDENTIAL
    ));

    let missing_github_ceiling = serde_json::json!({
        "live_lease": true,
        "statements": [
            {
                "resource_type": "credential",
                "actions": ["credential:read"],
                "resource": {"kind": "exact", "value": TEST_OPENAI_CHATGPT_CREDENTIAL}
            },
            {
                "resource_type": "session",
                "actions": ["llm:generate"],
                "resource": {"kind": "glob", "pattern": "openai/*"}
            }
        ]
    });
    assert!(
        !grant_status_supports_codex_openai_gateway(
            &missing_github_ceiling,
            TEST_OPENAI_CHATGPT_CREDENTIAL
        ),
        "model-only Codex grants must not qualify for delegated ember-gh sessions"
    );
}

#[test]
fn ensure_claude_code_anthropic_runtime_credential_reuses_existing_oauth_vault_entry() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("vault_list"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": [
                    {"id": 1, "name": TEST_ANTHROPIC_OAUTH_CREDENTIAL, "metadata": {"source": "test"}},
                    {"id": 2, "name": TEST_ANTHROPIC_API_CREDENTIAL, "metadata": null}
                ]
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let availability = ensure_claude_code_anthropic_runtime_credential(&config)
        .expect("existing OAuth vault entry should be preferred");
    match availability {
        AnthropicRuntimeCredentialAvailability::ExistingVaultEntry(credential) => {
            assert_eq!(credential.kind, AnthropicRuntimeCredentialKind::OAuthToken);
            assert_eq!(
                credential.credential_name(),
                TEST_ANTHROPIC_OAUTH_CREDENTIAL
            );
        }
        other => panic!("expected existing OAuth vault entry, got {other:?}"),
    }
    server.join().expect("fake daemon thread");
}

#[test]
fn ensure_claude_code_runtime_grant_reuses_existing_brokered_grant_when_kind_unknown() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            for expected_method in ["list_grants", "grant_status"] {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!(expected_method));

                let response = match expected_method {
                    "list_grants" => serde_json::json!({
                        "id": request["id"],
                        "result": [{
                            "id": "grant-anthropic-123",
                            "persona_id": "persona-1",
                            "credential_name": TEST_ANTHROPIC_API_CREDENTIAL,
                            "scope": "claude-code-default-v1",
                            "expires_at": "2026-05-25T01:01:16.056355+00:00",
                            "max_delegation_depth": 1
                        }]
                    }),
                    "grant_status" => serde_json::json!({
                        "id": request["id"],
                        "result": {
                            "live_lease": true,
                            "statements": [
                                {
                                    "resource_type": "credential",
                                    "actions": ["credential:read"],
                                    "resource": {"kind": "exact", "value": TEST_ANTHROPIC_API_CREDENTIAL}
                                },
                                {
                                    "resource_type": "session",
                                    "actions": ["llm:generate"],
                                    "resource": {"kind": "glob", "pattern": "anthropic/*"}
                                },
                                {
                                    "resource_type": "credential",
                                    "actions": ["github:*"],
                                    "resource": {"kind": "glob", "pattern": "*"}
                                }
                            ]
                        }
                    }),
                    _ => unreachable!(),
                };

                let mut encoded =
                    serde_json::to_string(&response).expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let grant = ensure_claude_code_runtime_grant(&config, "persona-1", None)
        .expect("existing brokered grant should be reused");
    assert_eq!(grant.id, "grant-anthropic-123");
    assert_eq!(
        grant.expires_at.as_deref(),
        Some("2026-05-25T01:01:16.056355+00:00")
    );
    assert!(!grant.created);
    assert!(grant.brokered_anthropic_runtime);
    server.join().expect("fake daemon thread");
}

#[test]
fn ensure_claude_code_runtime_grant_prefers_existing_oauth_grant_when_kind_unknown() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            for expected_method in ["list_grants", "grant_status", "grant_status"] {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!(expected_method));

                let response = match expected_method {
                    "list_grants" => serde_json::json!({
                        "id": request["id"],
                        "result": [
                            {
                                "id": "grant-anthropic-api",
                                "persona_id": "persona-1",
                                "credential_name": TEST_ANTHROPIC_API_CREDENTIAL,
                                "scope": "claude-code-default-v1",
                                "expires_at": "2026-05-25T01:01:16.056355+00:00",
                                "max_delegation_depth": 1
                            },
                            {
                                "id": "grant-anthropic-oauth",
                                "persona_id": "persona-1",
                                "credential_name": TEST_ANTHROPIC_OAUTH_CREDENTIAL,
                                "scope": "claude-code-default-v1",
                                "expires_at": "2026-05-25T02:01:16.056355+00:00",
                                "max_delegation_depth": 1
                            }
                        ]
                    }),
                    "grant_status" => {
                        let grant_id = request["params"]["id"].as_str().unwrap_or_default();
                        let credential_name = match grant_id {
                            "grant-anthropic-api" => TEST_ANTHROPIC_API_CREDENTIAL,
                            "grant-anthropic-oauth" => TEST_ANTHROPIC_OAUTH_CREDENTIAL,
                            other => panic!("unexpected grant_status id: {other}"),
                        };
                        serde_json::json!({
                            "id": request["id"],
                            "result": {
                                "live_lease": true,
                                "statements": [
                                    {
                                        "resource_type": "credential",
                                        "actions": ["credential:read"],
                                        "resource": {"kind": "exact", "value": credential_name}
                                    },
                                    {
                                        "resource_type": "session",
                                        "actions": ["llm:generate"],
                                        "resource": {"kind": "glob", "pattern": "anthropic/*"}
                                    },
                                    {
                                        "resource_type": "credential",
                                        "actions": ["github:*"],
                                        "resource": {"kind": "glob", "pattern": "*"}
                                    }
                                ]
                            }
                        })
                    }
                    _ => unreachable!(),
                };

                let mut encoded =
                    serde_json::to_string(&response).expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let grant = ensure_claude_code_runtime_grant(&config, "persona-1", None)
        .expect("existing brokered OAuth grant should be preferred");
    assert_eq!(grant.id, "grant-anthropic-oauth");
    assert_eq!(
        grant.expires_at.as_deref(),
        Some("2026-05-25T02:01:16.056355+00:00")
    );
    assert!(!grant.created);
    assert!(grant.brokered_anthropic_runtime);
    server.join().expect("fake daemon thread");
}

#[test]
fn ensure_claude_code_runtime_grant_prefers_matching_brokered_grant_over_ambient_fallback() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            for expected_method in ["list_grants", "grant_status", "grant_status"] {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!(expected_method));

                let response = match expected_method {
                    "list_grants" => serde_json::json!({
                        "id": request["id"],
                        "result": [
                            {
                                "id": "grant-ambient-1",
                                "persona_id": "persona-1",
                                "credential_name": "claude-code-default-v1",
                                "scope": "claude-code-default-v1",
                                "expires_at": "2026-05-25T00:01:16.056355+00:00",
                                "max_delegation_depth": 1
                            },
                            {
                                "id": "grant-anthropic-oauth",
                                "persona_id": "persona-1",
                                "credential_name": TEST_ANTHROPIC_OAUTH_CREDENTIAL,
                                "scope": "claude-code-default-v1",
                                "expires_at": "2026-05-25T02:01:16.056355+00:00",
                                "max_delegation_depth": 1
                            }
                        ]
                    }),
                    "grant_status" => {
                        let grant_id = request["params"]["id"].as_str().unwrap_or_default();
                        let result = match grant_id {
                            "grant-ambient-1" => {
                                serde_json::json!({"live_lease": true, "statements": []})
                            }
                            "grant-anthropic-oauth" => serde_json::json!({
                                "live_lease": true,
                                "statements": [
                                    {
                                        "resource_type": "credential",
                                        "actions": ["credential:read"],
                                        "resource": {"kind": "exact", "value": TEST_ANTHROPIC_OAUTH_CREDENTIAL}
                                    },
                                    {
                                        "resource_type": "session",
                                        "actions": ["llm:generate"],
                                        "resource": {"kind": "glob", "pattern": "anthropic/*"}
                                    },
                                    {
                                        "resource_type": "credential",
                                        "actions": ["github:*"],
                                        "resource": {"kind": "glob", "pattern": "*"}
                                    }
                                ]
                            }),
                            other => panic!("unexpected grant_status id: {other}"),
                        };
                        serde_json::json!({
                            "id": request["id"],
                            "result": result
                        })
                    }
                    _ => unreachable!(),
                };

                let mut encoded =
                    serde_json::to_string(&response).expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let grant = ensure_claude_code_runtime_grant(
        &config,
        "persona-1",
        Some(TEST_ANTHROPIC_OAUTH_CREDENTIAL),
    )
    .expect("brokered OAuth grant should beat earlier ambient fallback");
    assert_eq!(grant.id, "grant-anthropic-oauth");
    assert!(grant.brokered_anthropic_runtime);
    server.join().expect("fake daemon thread");
}

#[test]
fn ensure_claude_code_runtime_grant_rejects_legacy_default_without_anthropic_credential() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            for expected_method in ["list_grants", "grant_status"] {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!(expected_method));

                let response = match expected_method {
                    "list_grants" => serde_json::json!({
                        "id": request["id"],
                        "result": [{
                            "id": "grant-ambient-1",
                            "persona_id": "persona-1",
                            "credential_name": "claude-code-default-v1",
                            "scope": "claude-code-default-v1",
                            "expires_at": "2026-05-25T00:01:16.056355+00:00",
                            "max_delegation_depth": 1
                        }]
                    }),
                    "grant_status" => serde_json::json!({
                        "id": request["id"],
                        "result": {
                            "live_lease": true,
                            "statements": []
                        }
                    }),
                    _ => unreachable!(),
                };

                let mut encoded =
                    serde_json::to_string(&response).expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let err = ensure_claude_code_runtime_grant(&config, "persona-1", None)
        .expect_err("legacy Claude default grants must not satisfy model auth");
    let message = err.to_string();
    assert!(message.contains(CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL_PATTERN));
    assert!(message.contains("Local-only claude-code-default-v1"));
    server.join().expect("fake daemon thread");
}

#[test]
fn ensure_codex_runtime_grant_rejects_legacy_default_without_openai_credential() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            // `ensure_codex_runtime_grant(.., None)` resolves the keyed
            // credential lazily via `vault_list` BEFORE `list_grants`.
            for expected_method in ["vault_list", "list_grants"] {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!(expected_method));

                let response = match expected_method {
                    "list_grants" => serde_json::json!({
                        "id": request["id"],
                        "result": [{
                            "id": "grant-codex-ambient",
                            "persona_id": "persona-1",
                            "credential_name": "codex-default-v1",
                            "scope": "codex-default-v1",
                            "expires_at": "2026-05-25T00:01:16.056355+00:00",
                            "max_delegation_depth": 1
                        }]
                    }),
                    "vault_list" => serde_json::json!({
                        "id": request["id"],
                        "result": []
                    }),
                    _ => unreachable!(),
                };

                let mut encoded =
                    serde_json::to_string(&response).expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let err = ensure_codex_runtime_grant(&config, "persona-1", None)
        .expect_err("legacy Codex default grants must not satisfy model auth");
    let message = err.to_string();
    assert!(message.contains(CODEX_OPENAI_CHATGPT_RUNTIME_CREDENTIAL_PATTERN));
    assert!(message.contains("Local-only codex-default-v1"));
    server.join().expect("fake daemon thread");
}

#[test]
fn ensure_codex_runtime_grant_skips_existing_gateway_without_live_lease() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            for expected_method in ["list_grants", "grant_status", "create_composite_grant"] {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!(expected_method));

                let response = match expected_method {
                    "list_grants" => serde_json::json!({
                        "id": request["id"],
                        "result": [{
                            "id": "grant-codex-stale",
                            "persona_id": "persona-1",
                            "credential_name": TEST_OPENAI_CHATGPT_CREDENTIAL,
                            "scope": "codex-default-v1",
                            "expires_at": "2026-05-25T01:01:16.056355+00:00",
                            "max_delegation_depth": 1
                        }]
                    }),
                    "grant_status" => serde_json::json!({
                        "id": request["id"],
                        "result": {
                            "live_lease": false,
                            "statements": [
                                {
                                    "resource_type": "credential",
                                    "actions": ["credential:read"],
                                    "resource": {"kind": "exact", "value": TEST_OPENAI_CHATGPT_CREDENTIAL}
                                },
                                {
                                    "resource_type": "session",
                                    "actions": ["llm:generate"],
                                    "resource": {"kind": "glob", "pattern": "openai/*"}
                                },
                                {
                                    "resource_type": "credential",
                                    "actions": ["github:*"],
                                    "resource": {"kind": "glob", "pattern": "*"}
                                }
                            ]
                        }
                    }),
                    "create_composite_grant" => {
                        assert_eq!(
                            request["params"]["persona_id"],
                            serde_json::json!("persona-1")
                        );
                        assert_eq!(
                            request["params"]["credential_name"],
                            serde_json::json!(TEST_OPENAI_CHATGPT_CREDENTIAL)
                        );
                        serde_json::json!({
                            "id": request["id"],
                            "result": {
                                "id": "grant-codex-fresh",
                                "expires_at": "2026-05-25T02:01:16.056355+00:00"
                            }
                        })
                    }
                    _ => unreachable!(),
                };

                let mut encoded =
                    serde_json::to_string(&response).expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let grant =
        ensure_codex_runtime_grant(&config, "persona-1", Some(TEST_OPENAI_CHATGPT_CREDENTIAL))
            .expect("missing live lease must force fresh Codex grant mint");
    assert_eq!(grant.id, "grant-codex-fresh");
    assert!(grant.created);
    server.join().expect("fake daemon thread");
}

#[test]
fn ensure_cursor_runtime_grant_skips_existing_grant_without_live_lease() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let cursor_default_credential = || format!("cursor-{}-v1", "default");
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            for expected_method in ["list_grants", "grant_status", "create_grant"] {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!(expected_method));

                let response = match expected_method {
                    "list_grants" => serde_json::json!({
                        "id": request["id"],
                        "result": [{
                            "id": "grant-cursor-stale",
                            "persona_id": "persona-1",
                            "credential_name": cursor_default_credential(),
                            "scope": cursor_default_credential(),
                            "expires_at": "2026-05-25T01:01:16.056355+00:00",
                            "status": "active",
                            "max_delegation_depth": 1
                        }]
                    }),
                    "grant_status" => serde_json::json!({
                        "id": request["id"],
                        "result": {
                            "kind": "grant",
                            "id": "grant-cursor-stale",
                            "live_lease": false,
                            "statements": []
                        }
                    }),
                    "create_grant" => {
                        assert_eq!(
                            request["params"]["persona_id"],
                            serde_json::json!("persona-1")
                        );
                        assert_eq!(
                            request["params"]["credential_name"],
                            serde_json::json!(cursor_default_credential())
                        );
                        assert_eq!(
                            request["params"]["scope"],
                            serde_json::json!(cursor_default_credential())
                        );
                        assert_eq!(
                            request["params"]["max_delegation_depth"],
                            serde_json::json!(1)
                        );
                        serde_json::json!({
                            "id": request["id"],
                            "result": {
                                "id": "grant-cursor-fresh",
                                "expires_at": "2026-05-25T02:01:16.056355+00:00"
                            }
                        })
                    }
                    _ => unreachable!(),
                };

                let mut encoded =
                    serde_json::to_string(&response).expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let grant = ensure_cursor_runtime_grant(&config, "persona-1")
        .expect("missing live lease must force fresh Cursor grant mint");
    assert_eq!(grant.id, "grant-cursor-fresh");
    assert!(grant.created);
    server.join().expect("fake daemon thread");
}

#[test]
fn grant_list_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("list_operator_grants"));
            assert_eq!(request["params"]["active_only"], serde_json::json!(true));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": [
                    {
                        "id": "grant-1",
                        "persona_id": "persona-a",
                        "credential_name": "cred-a",
                        "scope": "read",
                        "status": "active",
                        "expires_at": null
                    },
                    {
                        "id": "grant-2",
                        "persona_id": "persona-b",
                        "credential_name": "cred-b",
                        "scope": "write",
                        "status": "paused",
                        "expires_at": "2026-06-01T00:00:00Z"
                    }
                ],
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, list) = run_grant_list(&config, true).expect("grant list via daemon");
    assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["id"], serde_json::json!("grant-1"));
    assert_eq!(list[1]["status"], serde_json::json!("paused"));
    server.join().expect("fake daemon thread");
}

#[test]
fn spend_grant_list_routes_through_daemon_and_filters_payment_statements() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            for expected_method in ["list_operator_grants", "grant_status", "grant_status"] {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!(expected_method));

                let response = match expected_method {
                    "list_operator_grants" => serde_json::json!({
                        "id": request["id"],
                        "result": [
                            {
                                "id": "grant-payment",
                                "persona_id": "persona-a",
                                "credential_name": "payment/clearbit",
                                "scope": "payment:charge",
                                "status": "active",
                                "expires_at": null
                            },
                            {
                                "id": "grant-session",
                                "persona_id": "persona-b",
                                "credential_name": TEST_ANTHROPIC_OAUTH_CREDENTIAL,
                                "scope": "model:invoke",
                                "status": "active",
                                "expires_at": null
                            }
                        ]
                    }),
                    "grant_status" => match request["params"]["id"].as_str().unwrap() {
                        "grant-payment" => serde_json::json!({
                            "id": request["id"],
                            "result": {
                                "kind": "grant",
                                "id": "grant-payment",
                                "persona_id": "persona-a",
                                "credential_name": "payment/clearbit",
                                "scope": "payment:charge",
                                "status": "active",
                                "expires_at": null,
                                "created_at": "2026-05-26T00:00:00Z",
                                "statements": [{
                                    "sid": "P1",
                                    "resource_type": "payment",
                                    "actions": ["payment:charge"],
                                    "resource": {"kind": "any"},
                                    "budget": {"cents": 25000},
                                    "usage": {"cents": 1200, "last_updated": 1, "cents_micro": 1200000000},
                                    "conditions": [
                                        Condition::MerchantAllowlist {
                                            merchants: vec!["clearbit".to_string()],
                                        },
                                        Condition::Range {
                                            field: "amount_cents".to_string(),
                                            min: Some(0),
                                            max: Some(4_900),
                                        }
                                    ],
                                    "reserved_cents": 4900
                                }]
                            }
                        }),
                        "grant-session" => serde_json::json!({
                            "id": request["id"],
                            "result": {
                                "kind": "grant",
                                "id": "grant-session",
                                "persona_id": "persona-b",
                                "credential_name": TEST_ANTHROPIC_OAUTH_CREDENTIAL,
                                "scope": "model:invoke",
                                "status": "active",
                                "expires_at": null,
                                "created_at": "2026-05-26T00:00:00Z",
                                "statements": [{
                                    "sid": "S1",
                                    "resource_type": "session",
                                    "actions": ["llm:generate"],
                                    "resource": {"kind": "glob", "pattern": "anthropic/*"},
                                    "budget": {"tokens": 20000},
                                    "usage": {"tokens": 4000, "last_updated": 1},
                                    "conditions": [],
                                    "reserved_cents": 0
                                }]
                            }
                        }),
                        other => panic!("unexpected grant_status id: {other}"),
                    },
                    _ => unreachable!(),
                };

                let mut encoded =
                    serde_json::to_string(&response).expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, rows) =
        run_spend_grant_list(&config, true).expect("spend grant list via daemon");
    assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, "grant-payment");
    assert_eq!(rows[0].vendor, "clearbit");
    assert_eq!(rows[0].threshold_cents, Some(4_900));
    assert_eq!(rows[0].hard_cap_cents, Some(25_000));
    assert_eq!(rows[0].used_cents, 1_200);
    assert_eq!(rows[0].reserved_cents, 4_900);
    server.join().expect("fake daemon thread");
}

#[test]
fn grant_evaluate_routes_attempt_through_daemon() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let attempt_path = tmp.path().join("attempt.toml");
    std::fs::write(
        &attempt_path,
        "vendor = \"clearbit\"\namount_cents = 4900\nshadow = false\n",
    )
    .expect("write attempt");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            for expected_method in ["grant_status", "evaluate_tool_call"] {
                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!(expected_method));

                let response = match expected_method {
                    "grant_status" => serde_json::json!({
                        "id": request["id"],
                        "result": {
                            "kind": "grant",
                            "id": "grant-payment",
                            "persona_id": "persona-a",
                            "credential_name": "payment/clearbit",
                            "scope": "payment:charge",
                            "status": "active",
                            "expires_at": null,
                            "created_at": "2026-05-26T00:00:00Z",
                            "statements": [{
                                "sid": "P1",
                                "resource_type": "payment",
                                "actions": ["payment:charge"],
                                "resource": {"kind": "any"},
                                "budget": {"cents": 25000},
                                "usage": {"cents": 0, "last_updated": 1},
                                "conditions": [
                                    Condition::MerchantAllowlist {
                                        merchants: vec!["clearbit".to_string()],
                                    },
                                    Condition::Range {
                                        field: "amount_cents".to_string(),
                                        min: Some(0),
                                        max: Some(4_900),
                                    }
                                ],
                                "reserved_cents": 0
                            }]
                        }
                    }),
                    "evaluate_tool_call" => {
                        assert_eq!(request["params"]["persona"], serde_json::json!("persona-a"));
                        assert_eq!(
                            request["params"]["tool_name"],
                            serde_json::json!("payment:charge")
                        );
                        assert_eq!(
                            request["params"]["grant_id"],
                            serde_json::json!("grant-payment")
                        );
                        assert_eq!(
                            request["params"]["params"]["vendor"],
                            serde_json::json!("clearbit")
                        );
                        assert_eq!(
                            request["params"]["params"]["amount_cents"],
                            serde_json::json!(4900)
                        );
                        let attempt_id = request["params"]["params"]["attempt_id"]
                            .as_str()
                            .expect("attempt id inserted");
                        assert!(attempt_id.starts_with("cli-attempt-"));
                        serde_json::json!({
                            "id": request["id"],
                            "result": {
                                "permit": true,
                                "grant_id": "grant-payment",
                                "reason": "reserved",
                                "emitted_event_id": "evt-123"
                            }
                        })
                    }
                    _ => unreachable!(),
                };

                let mut encoded =
                    serde_json::to_string(&response).expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, decision) = run_grant_evaluate(&config, "grant-payment", &attempt_path)
        .expect("grant evaluate via daemon");
    assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
    assert_eq!(decision["permit"], serde_json::json!(true));
    assert_eq!(decision["grant_id"], serde_json::json!("grant-payment"));
    server.join().expect("fake daemon thread");
}

#[test]
fn grant_expire_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("expire_grants"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {"expired_count": 3},
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, count) = run_grant_expire(&config).expect("grant expire via daemon");
    assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
    assert_eq!(count, 3);
    server.join().expect("fake daemon thread");
}

#[test]
fn grant_expire_without_daemon_does_not_fallback_to_local_store() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());

    let err = run_grant_expire(&config).expect_err("missing daemon socket must fail");

    assert!(
        err.to_string().contains("daemon unavailable"),
        "error should point at daemon transport, got: {err}"
    );
}

#[test]
fn grant_extend_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("extend_grant"));
            assert_eq!(
                request["params"]["grant_id"],
                serde_json::json!("grant-123")
            );
            assert_eq!(request["params"]["add_tokens"], serde_json::json!(10));
            assert_eq!(request["params"]["add_cents"], serde_json::json!(25));
            assert_eq!(request["params"]["add_ttl_secs"], serde_json::json!(900));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {
                    "grant_id": "grant-123",
                    "expires_at": null,
                    "budget": {"tokens": 10, "cents": 25},
                },
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let dispatch = run_grant_extend(&config, "grant-123", Some(10), Some(25), Some(900))
        .expect("grant extend via daemon");
    assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
    server.join().expect("fake daemon thread");
}

#[test]
fn grant_delegate_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut status_stream =
                accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut status_reader = std::io::BufReader::new(
                status_stream
                    .try_clone()
                    .expect("clone fake daemon grant_status stream"),
            );
            let mut line = String::new();
            status_reader
                .read_line(&mut line)
                .expect("read fake grant_status request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake grant_status request");
            assert_eq!(request["method"], serde_json::json!("grant_status"));
            assert_eq!(request["params"]["id"], serde_json::json!("grant-parent"));
            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {
                    "kind": "grant",
                    "id": "grant-parent",
                    "persona_id": "persona-owner",
                },
            }))
            .expect("encode fake grant_status response");
            encoded.push('\n');
            status_stream
                .write_all(encoded.as_bytes())
                .expect("write fake grant_status response");

            let mut delegate_stream =
                accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut delegate_reader = std::io::BufReader::new(
                delegate_stream
                    .try_clone()
                    .expect("clone fake daemon delegate_grant stream"),
            );
            line.clear();
            delegate_reader
                .read_line(&mut line)
                .expect("read fake delegate_grant request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake delegate_grant request");
            assert_eq!(request["method"], serde_json::json!("delegate_grant"));
            assert_eq!(
                request["params"]["parent_grant_id"],
                serde_json::json!("grant-parent")
            );
            assert_eq!(
                request["params"]["child_persona_id"],
                serde_json::json!("persona-child")
            );
            assert_eq!(request["params"]["scope"], serde_json::json!("read"));
            assert_eq!(
                request["params"]["caller_persona_id"],
                serde_json::json!("persona-owner")
            );
            assert_eq!(request["params"]["ttl_secs"], serde_json::json!(600));
            assert_eq!(request["params"]["budget"]["tokens"], serde_json::json!(42));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {
                    "id": "grant-child",
                    "parent": "grant-parent",
                    "persona_id": "persona-child",
                    "scope": "read",
                    "expires_at": null,
                    "budget": {"tokens": 42},
                },
            }))
            .expect("encode fake delegate_grant response");
            encoded.push('\n');
            delegate_stream
                .write_all(encoded.as_bytes())
                .expect("write fake delegate_grant response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, info) = run_grant_delegate(
        &config,
        "grant-parent",
        "persona-child",
        "read",
        Some(600),
        Some(Budget {
            tokens: Some(42),
            cents: None,
            requests: None,
            workload_hours: None,
            wall_clock_secs: None,
        }),
    )
    .expect("grant delegate via daemon");
    assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
    assert_eq!(info["id"], serde_json::json!("grant-child"));
    server.join().expect("fake daemon thread");
}

#[test]
fn grant_budget_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("grant_status"));
            assert_eq!(request["params"]["id"], serde_json::json!("grant-123"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {
                    "kind": "grant",
                    "id": "grant-123",
                    "persona_id": "persona-owner",
                    "status": "active",
                    "expires_at": null,
                    "statements": [{
                        "sid": "S0",
                        "block_index": 0,
                        "resource_type": "credential",
                        "resource": {"kind": "exact", "value": "alpha/token"},
                        "budget": {"tokens": 100},
                        "usage": {"tokens": 10, "last_updated": 1},
                        "conditions": []
                    }]
                },
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, rendered) =
        run_grant_budget(&config, "grant-123").expect("grant budget via daemon");
    assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
    assert!(rendered.contains("Grant grant-123"));
    assert!(rendered.contains("Persona: persona-owner"));
    assert!(rendered.contains("tokens:"));
    server.join().expect("fake daemon thread");
}
