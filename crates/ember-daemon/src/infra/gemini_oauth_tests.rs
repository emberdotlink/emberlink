//! CLASSIFICATION: PUBLIC
//!
//! Unit tests for the gemini Code Assist OAuth helpers (network-free — the
//! refresh HTTP itself is exercised end-to-end in the operator live-verify /
//! daemon integration path; here we pin the pure parse / expiry / merge /
//! error-classification logic).

use super::*;
use chrono::{TimeZone, Utc};

fn ts_ms(secs_from_epoch: i64) -> i64 {
    secs_from_epoch * 1000
}

#[test]
fn parse_accepts_bare_credentials_object() {
    let json = br#"{"access_token":"ya29.AT","refresh_token":"1//RT","token_type":"Bearer","scope":"https://www.googleapis.com/auth/cloud-platform","expiry_date":1750000000000}"#;
    let blob = parse_oauth_blob(json).expect("parse");
    assert_eq!(blob.access_token, "ya29.AT");
    assert_eq!(blob.refresh_token.as_deref(), Some("1//RT"));
    assert_eq!(blob.expiry_date, Some(1_750_000_000_000));
}

#[test]
fn parse_accepts_tokens_wrapper() {
    let json = br#"{"tokens":{"access_token":"ya29.AT","refresh_token":"1//RT"},"other":1}"#;
    let blob = parse_oauth_blob(json).expect("parse");
    assert_eq!(blob.access_token, "ya29.AT");
    assert_eq!(blob.refresh_token.as_deref(), Some("1//RT"));
}

#[test]
fn parse_rejects_missing_access_token() {
    assert!(parse_oauth_blob(br#"{"refresh_token":"1//RT"}"#).is_err());
    assert!(parse_oauth_blob(br#"{"access_token":""}"#).is_err());
    assert!(parse_oauth_blob(b"not json").is_err());
}

#[test]
fn serialize_round_trips() {
    let blob = GeminiOAuthBlob {
        access_token: "ya29.AT".into(),
        refresh_token: Some("1//RT".into()),
        token_type: Some("Bearer".into()),
        scope: None,
        id_token: None,
        expiry_date: Some(ts_ms(1_750_000_000)),
    };
    let bytes = serialize_oauth_blob(&blob);
    let back = parse_oauth_blob(&bytes).expect("re-parse");
    assert_eq!(back.access_token, "ya29.AT");
    assert_eq!(back.refresh_token.as_deref(), Some("1//RT"));
    assert_eq!(back.expiry_date, Some(ts_ms(1_750_000_000)));
}

#[test]
fn needs_refresh_window_logic() {
    let now = Utc.timestamp_opt(1_750_000_000, 0).unwrap();
    let at = |exp_secs: i64| GeminiOAuthBlob {
        access_token: "x".into(),
        expiry_date: Some(ts_ms(exp_secs)),
        ..Default::default()
    };
    // Comfortably valid (1h out) → no refresh.
    assert!(!needs_refresh(&at(1_750_000_000 + 3600), now));
    // Within the 5-min window → refresh.
    assert!(needs_refresh(&at(1_750_000_000 + 60), now));
    // Already past → refresh.
    assert!(needs_refresh(&at(1_750_000_000 - 10), now));
    // Unknown expiry → refresh to be safe.
    let no_exp = GeminiOAuthBlob {
        access_token: "x".into(),
        ..Default::default()
    };
    assert!(needs_refresh(&no_exp, now));
}

#[test]
fn is_hard_expired_logic() {
    let now = Utc.timestamp_opt(1_750_000_000, 0).unwrap();
    let past = GeminiOAuthBlob {
        access_token: "x".into(),
        expiry_date: Some(ts_ms(1_750_000_000 - 10)),
        ..Default::default()
    };
    let future = GeminiOAuthBlob {
        access_token: "x".into(),
        expiry_date: Some(ts_ms(1_750_000_000 + 600)),
        ..Default::default()
    };
    let unknown = GeminiOAuthBlob {
        access_token: "x".into(),
        ..Default::default()
    };
    assert!(is_hard_expired(&past, now));
    assert!(!is_hard_expired(&future, now));
    // Unknown expiry is NOT hard-expired (lets a transient blip fall back).
    assert!(!is_hard_expired(&unknown, now));
}

#[test]
fn apply_refresh_updates_token_and_recomputes_expiry_keeps_refresh_token() {
    let now = Utc.timestamp_opt(1_750_000_000, 0).unwrap();
    let mut blob = GeminiOAuthBlob {
        access_token: "old".into(),
        refresh_token: Some("1//RT".into()),
        expiry_date: Some(ts_ms(1_750_000_000 - 10)),
        ..Default::default()
    };
    apply_refresh(
        &mut blob,
        RefreshOutcome {
            access_token: Some("ya29.NEW".into()),
            expires_in_secs: Some(3600),
            id_token: Some("idtok".into()),
            scope: Some("scopeval".into()),
            token_type: Some("Bearer".into()),
        },
        now,
    );
    assert_eq!(blob.access_token, "ya29.NEW");
    // Google does not rotate the refresh token — it must be preserved.
    assert_eq!(blob.refresh_token.as_deref(), Some("1//RT"));
    // expiry recomputed to now + 3600s, in ms.
    assert_eq!(blob.expiry_date, Some(now.timestamp_millis() + 3_600_000));
    assert_eq!(blob.id_token.as_deref(), Some("idtok"));
    assert_eq!(blob.scope.as_deref(), Some("scopeval"));
    assert!(!needs_refresh(&blob, now));
}

#[test]
fn apply_refresh_saturates_on_absurd_expires_in() {
    // A hostile/garbage `expires_in` must not panic (debug overflow) or wrap on
    // the shared proxy thread — the expiry recompute saturates (L1).
    let now = Utc.timestamp_opt(1_750_000_000, 0).unwrap();
    let mut blob = GeminiOAuthBlob {
        access_token: "old".into(),
        refresh_token: Some("1//RT".into()),
        ..Default::default()
    };
    apply_refresh(
        &mut blob,
        RefreshOutcome {
            access_token: Some("new".into()),
            expires_in_secs: Some(i64::MAX),
            ..Default::default()
        },
        now,
    );
    assert_eq!(blob.expiry_date, Some(i64::MAX));
    assert_eq!(blob.access_token, "new");
    // Still parseable / not hard-expired (saturated far into the future).
    assert!(!is_hard_expired(&blob, now));
}

#[test]
fn classify_refresh_failure_permanent_vs_transient() {
    use reqwest::StatusCode;
    // Google's expired/revoked refresh token → invalid_grant → permanent.
    assert!(matches!(
        classify_refresh_failure(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#
        ),
        RefreshError::Permanent(_)
    ));
    assert!(matches!(
        classify_refresh_failure(StatusCode::UNAUTHORIZED, "{}"),
        RefreshError::Permanent(_)
    ));
    // 5xx / unknown → transient (retryable).
    assert!(matches!(
        classify_refresh_failure(StatusCode::SERVICE_UNAVAILABLE, "upstream blip"),
        RefreshError::Transient(_)
    ));
}
