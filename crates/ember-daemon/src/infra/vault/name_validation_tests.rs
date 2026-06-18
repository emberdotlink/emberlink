use super::*;

#[test]
fn accepts_canonical_names() {
    for name in [
        "gh-token",
        "cloudflare/zone/abc",
        "cloudflare/account-c5/api-token",
        "x",
        "long-name-here",
    ] {
        assert!(
            validate_credential_name(name).is_ok(),
            "rejected canonical: {name}"
        );
    }
}

#[test]
fn rejects_uppercase() {
    assert!(validate_credential_name("GH-Token").is_err());
    assert!(validate_credential_name("github/Foo").is_err());
}

#[test]
fn rejects_underscores_dots_spaces() {
    for bad in ["foo_bar", "foo.bar", "foo bar", "foo@bar"] {
        assert!(
            validate_credential_name(bad).is_err(),
            "accepted bad: {bad}"
        );
    }
}

#[test]
fn rejects_leading_hyphen_or_slash() {
    assert!(validate_credential_name("-foo").is_err());
    assert!(validate_credential_name("/foo").is_err());
}

#[test]
fn rejects_empty_segments() {
    assert!(validate_credential_name("foo//bar").is_err());
    assert!(validate_credential_name("foo/").is_err());
}

#[test]
fn rejects_too_deep() {
    // 8 segments — exceeds the ADR 099 §5.1 hard cap of 7.
    assert!(validate_credential_name("a/b/c/d/e/f/g/h").is_err());
}

#[test]
fn accepts_max_depth() {
    // 7 segments — at the ADR 099 §5.1 hard cap.
    assert!(validate_credential_name("a/b/c/d/e/f/g").is_ok());
}

/// ARCH-BROKER-VAULT-CUTOVER-PR1-ADRS Phase 1 — the v2 path grammar
/// (ADR 099 §5.3) introduces credential-type intermediate segments like
/// `github/apps/<slug>/install-<id>/private-key` which are 5 segments
/// deep. The previous `> 4` cap rejected these; the lifted `> 7` cap
/// admits the v2 shapes used by `ember broker register github`.
#[test]
fn validate_credential_name_accepts_five_segment_v2_path() {
    assert!(
        validate_credential_name("github/apps/test-slug/install-12345/private-key").is_ok(),
        "5-segment v2 path should be accepted under ADR 099 §5.3"
    );
}

/// Partner test — 8 segments must still be rejected at the new hard cap.
#[test]
fn validate_credential_name_rejects_eight_segment_path() {
    let outcome = validate_credential_name("a/b/c/d/e/f/g/h");
    match outcome {
        Err(VaultNameError::TooManySegments { count }) => assert_eq!(count, 8),
        other => panic!("expected TooManySegments {{ count: 8 }}, got {other:?}"),
    }
}

#[test]
fn rejects_too_long() {
    assert!(validate_credential_name(&"a".repeat(129)).is_err());
}
