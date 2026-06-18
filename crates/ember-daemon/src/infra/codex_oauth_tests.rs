//! CLASSIFICATION: PUBLIC
//!
//! Unit tests for codex GPT-plan OAuth token handling (P22-S2).

use super::*;
use base64::Engine;

/// Build a fake JWT (`header.payload.sig`) carrying `claims_json` as the
/// payload. Signature is a non-empty placeholder — we never verify signatures
/// (the OAuth server does), we only decode claims.
fn fake_jwt(claims_json: &str) -> String {
    let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes());
    format!(
        "{}.{}.{}",
        b64("{\"alg\":\"none\"}"),
        b64(claims_json),
        b64("sig")
    )
}

#[test]
fn provenance_constants_match_codex_contract() {
    // Fails loudly if a vendored value drifts from codex-rs's documented
    // contract (the whole point of vendoring-with-provenance).
    assert_eq!(CHATGPT_OAUTH_CLIENT_ID, "app_EMoamEEZ73f0CkXaXp7hrann");
    assert_eq!(
        CHATGPT_REFRESH_TOKEN_URL,
        "https://auth.openai.com/oauth/token"
    );
}

#[test]
fn parses_bare_tokens_object() {
    let json =
        r#"{"id_token":"x.y.z","access_token":"at","refresh_token":"rt","account_id":"acct-1"}"#;
    let blob = parse_token_blob(json.as_bytes()).unwrap();
    assert_eq!(blob.access_token, "at");
    assert_eq!(blob.refresh_token.as_deref(), Some("rt"));
    assert_eq!(blob.account_id.as_deref(), Some("acct-1"));
}

#[test]
fn parses_full_auth_json_with_nested_tokens() {
    let json = r#"{"OPENAI_API_KEY":null,"tokens":{"access_token":"at","refresh_token":"rt"},"last_refresh":"2026-05-27T00:00:00Z"}"#;
    let blob = parse_token_blob(json.as_bytes()).unwrap();
    assert_eq!(blob.access_token, "at");
    assert_eq!(blob.refresh_token.as_deref(), Some("rt"));
}

#[test]
fn tolerates_unknown_fields() {
    // Version-resilience: a newer codex adding fields must not break parsing.
    let json = r#"{"access_token":"at","some_new_field_v2":42,"nested":{"a":1}}"#;
    let blob = parse_token_blob(json.as_bytes()).unwrap();
    assert_eq!(blob.access_token, "at");
}

#[test]
fn missing_access_token_errors() {
    let json = r#"{"refresh_token":"rt"}"#;
    assert!(matches!(
        parse_token_blob(json.as_bytes()),
        Err(CodexOAuthError::MissingAccessToken)
    ));
}

#[test]
fn invalid_json_errors() {
    assert!(matches!(
        parse_token_blob(b"not json"),
        Err(CodexOAuthError::Json(_))
    ));
}

#[test]
fn account_id_prefers_explicit_field() {
    let id_token =
        fake_jwt(r#"{"https://api.openai.com/auth":{"chatgpt_account_id":"from-claim"}}"#);
    let blob = CodexTokenBlob {
        id_token: Some(id_token),
        access_token: "at".into(),
        refresh_token: None,
        account_id: Some("explicit".into()),
    };
    assert_eq!(account_id(&blob).as_deref(), Some("explicit"));
}

#[test]
fn account_id_falls_back_to_id_token_claim() {
    let id_token =
        fake_jwt(r#"{"https://api.openai.com/auth":{"chatgpt_account_id":"from-claim"}}"#);
    let blob = CodexTokenBlob {
        id_token: Some(id_token),
        access_token: "at".into(),
        refresh_token: None,
        account_id: None,
    };
    assert_eq!(account_id(&blob).as_deref(), Some("from-claim"));
}

#[test]
fn subject_reads_id_token_sub_claim() {
    let id_token = fake_jwt(r#"{"sub":"user-123"}"#);
    let blob = CodexTokenBlob {
        id_token: Some(id_token),
        access_token: "at".into(),
        refresh_token: None,
        account_id: None,
    };
    assert_eq!(subject(&blob).as_deref(), Some("user-123"));
}

#[test]
fn subject_absent_when_no_id_token() {
    let blob = CodexTokenBlob {
        id_token: None,
        access_token: "at".into(),
        refresh_token: None,
        account_id: None,
    };
    assert_eq!(subject(&blob), None);
}

#[test]
fn is_fedramp_reads_id_token_claim() {
    let id_token =
        fake_jwt(r#"{"https://api.openai.com/auth":{"chatgpt_account_is_fedramp":true}}"#);
    let blob = CodexTokenBlob {
        id_token: Some(id_token),
        access_token: "at".into(),
        refresh_token: None,
        account_id: None,
    };
    assert!(is_fedramp(&blob));
}

#[test]
fn needs_refresh_true_when_within_window() {
    let now = chrono::Utc::now();
    // exp 10 minutes out, window is 60 minutes → needs refresh.
    let exp = (now + chrono::Duration::minutes(10)).timestamp();
    let access = fake_jwt(&format!(r#"{{"exp":{exp}}}"#));
    let blob = CodexTokenBlob {
        id_token: None,
        access_token: access,
        refresh_token: Some("rt".into()),
        account_id: None,
    };
    assert!(needs_refresh(&blob, now));
    assert!(!is_hard_expired(&blob, now));
}

#[test]
fn needs_refresh_false_when_comfortably_valid() {
    let now = chrono::Utc::now();
    // exp 10 days out (like a real ChatGPT access token) → no refresh.
    let exp = (now + chrono::Duration::days(10)).timestamp();
    let access = fake_jwt(&format!(r#"{{"exp":{exp}}}"#));
    let blob = CodexTokenBlob {
        id_token: None,
        access_token: access,
        refresh_token: Some("rt".into()),
        account_id: None,
    };
    assert!(!needs_refresh(&blob, now));
}

#[test]
fn hard_expired_detected() {
    let now = chrono::Utc::now();
    let exp = (now - chrono::Duration::hours(1)).timestamp();
    let access = fake_jwt(&format!(r#"{{"exp":{exp}}}"#));
    let blob = CodexTokenBlob {
        id_token: None,
        access_token: access,
        refresh_token: Some("rt".into()),
        account_id: None,
    };
    assert!(is_hard_expired(&blob, now));
    assert!(needs_refresh(&blob, now));
}

#[test]
fn unparseable_exp_does_not_trigger_refresh() {
    // No `exp` claim → we forward as-is rather than spuriously burning a
    // rotating refresh token.
    let access = fake_jwt(r#"{"sub":"u"}"#);
    let blob = CodexTokenBlob {
        id_token: None,
        access_token: access,
        refresh_token: Some("rt".into()),
        account_id: None,
    };
    assert!(!needs_refresh(&blob, chrono::Utc::now()));
}

#[test]
fn apply_refresh_rotates_refresh_token() {
    let mut blob = CodexTokenBlob {
        id_token: Some("old-id".into()),
        access_token: "old-access".into(),
        refresh_token: Some("old-refresh".into()),
        account_id: Some("acct".into()),
    };
    apply_refresh(
        &mut blob,
        RefreshOutcome {
            id_token: Some("new-id".into()),
            access_token: Some("new-access".into()),
            refresh_token: Some("new-refresh".into()),
        },
    );
    assert_eq!(blob.access_token, "new-access");
    assert_eq!(blob.refresh_token.as_deref(), Some("new-refresh"));
    assert_eq!(blob.id_token.as_deref(), Some("new-id"));
    // account_id preserved (server didn't return one).
    assert_eq!(blob.account_id.as_deref(), Some("acct"));
}

#[test]
fn apply_refresh_keeps_old_refresh_token_when_absent() {
    // Server returned only a new access token (no rotation this time).
    let mut blob = CodexTokenBlob {
        id_token: None,
        access_token: "old-access".into(),
        refresh_token: Some("keep-me".into()),
        account_id: None,
    };
    apply_refresh(
        &mut blob,
        RefreshOutcome {
            id_token: None,
            access_token: Some("new-access".into()),
            refresh_token: None,
        },
    );
    assert_eq!(blob.access_token, "new-access");
    assert_eq!(blob.refresh_token.as_deref(), Some("keep-me"));
}

#[test]
fn classify_refresh_failure_permanent_codes() {
    use reqwest::StatusCode;
    let cases = [
        (r#"{"error":{"code":"refresh_token_expired"}}"#, "expired"),
        (r#"{"error":{"code":"refresh_token_reused"}}"#, "reused"),
        (
            r#"{"error":{"code":"refresh_token_invalidated"}}"#,
            "revoked",
        ),
    ];
    for (body, want) in cases {
        match classify_refresh_failure(StatusCode::BAD_REQUEST, body) {
            RefreshError::Permanent(reason) => assert_eq!(reason, want),
            other => panic!("expected Permanent({want}), got {other:?}"),
        }
    }
}

#[test]
fn classify_refresh_failure_unauthorized_is_permanent() {
    use reqwest::StatusCode;
    assert!(matches!(
        classify_refresh_failure(StatusCode::UNAUTHORIZED, "{}"),
        RefreshError::Permanent(_)
    ));
}

#[test]
fn classify_refresh_failure_5xx_is_transient() {
    use reqwest::StatusCode;
    assert!(matches!(
        classify_refresh_failure(StatusCode::INTERNAL_SERVER_ERROR, "upstream boom"),
        RefreshError::Transient(_)
    ));
}
