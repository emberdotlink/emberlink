//! GitHub App manifest helpers.
//!
//! This module exposes the GitHub App install URL, the permission-floor
//! reference text printed by `ember github app show`, and the manifest body used
//! by the operator-owned manifest flow.
//!
//!   * `print_install_url()` — return the canonical install URL.
//!   * `show_manifest()`     — print the concise manifest reference to stdout.
//!
//! Permission floor:
//!
//! | Resource      | Access | Notes |
//! |---------------|--------|-------|
//! | contents      | write  | broker mints sub-scoped 1h tokens per grant; App is the credential ceiling |
//! | pull_requests | write  | create / merge / comment |
//! | issues        | write  | file / comment per agent activity |
//! | actions       | read   | workflow run status |
//! | metadata      | read   | mandatory for any GitHub App |
//!
//! Workflows, secrets, and administration are explicitly **denied** on the
//! floor.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};

/// Concise GitHub App manifest reference printed by `ember github app show`.
///
/// Keep this user-facing: the long internal rationale lives in the private docs
/// tree, while this output gives operators the install URL, permission floor,
/// denied permissions, and exact JSON body.
pub const PUBLIC_MANIFEST_DOC: &str = r#"# Emberlink GitHub App

The GitHub App lane lets the local daemon mint short-lived installation tokens
for approved GitHub actions. Installing the public App alone is not enough for a
local setup; the daemon still needs an operator-owned App credential registered
through `ember github setup` or `ember github app register`.

Install URL:

https://github.com/apps/emberlink/installations/new

Permission floor:

| Permission | Access |
|---|---|
| contents | write |
| pull_requests | write |
| issues | write |
| actions | read |
| metadata | read |

Denied permissions:

- Workflows
- Secrets
- Administration

Manifest body:

```json
{
  "name": "Emberlink",
  "url": "https://emberlink.dev/",
  "hook_attributes": {
    "url": "https://emberlink.dev/api/github/hook",
    "active": true
  },
  "redirect_url": "https://emberlink.dev/onboarding/github-app/installed",
  "callback_urls": [
    "https://emberlink.dev/onboarding/github-app/oauth"
  ],
  "public": true,
  "default_permissions": {
    "contents": "write",
    "pull_requests": "write",
    "issues": "write",
    "actions": "read",
    "metadata": "read"
  },
  "default_events": [
    "pull_request"
  ]
}
```
"#;

/// Personal-account endpoint for GitHub's App manifest form flow.
pub const MANIFEST_REGISTRATION_URL: &str = "https://github.com/settings/apps/new";

/// Canonical install URL. The App slug is `emberlink`; the
/// `/installations/new` suffix is GitHub's standard install flow path.
pub const INSTALL_URL: &str = "https://github.com/apps/emberlink/installations/new";

/// Return the canonical install URL as an owned `String`.
///
/// Callers typically print this verbatim; the function shape (rather than a
/// bare `&'static str` accessor) keeps the surface symmetric with
/// `show_manifest`.
pub fn print_install_url() -> String {
    INSTALL_URL.to_string()
}

/// Print the embedded manifest body to stdout.
///
/// The body is a concise markdown reference: install URL, permission floor,
/// denied permissions, and JSON manifest block.
pub fn show_manifest() {
    print!("{PUBLIC_MANIFEST_DOC}");
}

/// Build the GitHub App manifest body for the operator-owned manifest flow.
///
/// The permission floor intentionally matches `PUBLIC_MANIFEST_DOC`.
/// `redirect_url` is flow-local and points at the CLI's loopback callback.
pub fn build_manifest_body(redirect_url: &str) -> Value {
    json!({
        "name": "Emberlink",
        "url": "https://emberlink.dev/",
        "hook_attributes": {
            "url": "https://emberlink.dev/api/github/hook",
            "active": true,
        },
        "redirect_url": redirect_url,
        "callback_urls": [
            redirect_url,
        ],
        "public": true,
        "default_permissions": {
            "contents": "write",
            "pull_requests": "write",
            "issues": "write",
            "actions": "read",
            "metadata": "read",
        },
        "default_events": [
            "pull_request",
        ],
    })
}

/// Generate the CSRF state token used by the manifest flow.
pub fn generate_manifest_state() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("OS entropy failure: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Return a local HTML page that POSTs the manifest to GitHub.
///
/// GitHub requires a browser-owned form POST to `/settings/apps/new`; the CLI
/// serves this page from loopback so the operator can continue in their
/// authenticated browser session without the PEM ever touching disk.
pub fn manifest_registration_form_html(
    manifest: &Value,
    state: &str,
) -> Result<String, serde_json::Error> {
    let manifest_json = serde_json::to_string(manifest)?;
    let escaped_manifest = html_attr_escape(&manifest_json);
    let escaped_state = html_attr_escape(state);
    Ok(format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Emberlink GitHub App setup</title></head>
<body>
<form id="emberlink-gh-app-manifest" action="{MANIFEST_REGISTRATION_URL}?state={escaped_state}" method="post">
  <input type="hidden" name="manifest" value="{escaped_manifest}">
  <button type="submit">Create GitHub App</button>
</form>
<script>document.getElementById("emberlink-gh-app-manifest").submit();</script>
</body>
</html>"#
    ))
}

fn html_attr_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Parse GitHub's loopback callback target and return the temporary code.
pub fn parse_manifest_callback_target(
    target: &str,
    expected_state: &str,
) -> Result<String, String> {
    let (path, query) = target
        .split_once('?')
        .ok_or_else(|| "manifest callback missing query string".to_string())?;
    if path != "/callback" {
        return Err(format!(
            "manifest callback reached unexpected path `{path}`"
        ));
    }

    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "code" => code = Some(value),
            "state" => state = Some(value),
            _ => {}
        }
    }

    let state = state.ok_or_else(|| "manifest callback missing state".to_string())?;
    if state != expected_state {
        return Err("manifest callback state did not match this setup flow".to_string());
    }
    let code = code.ok_or_else(|| "manifest callback missing code".to_string())?;
    if code.trim().is_empty() {
        return Err("manifest callback code was empty".to_string());
    }
    Ok(code.to_string())
}

#[derive(Clone, Deserialize)]
pub struct ManifestConversion {
    pub id: u64,
    pub slug: String,
    pub pem: String,
    pub html_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub webhook_secret: Option<String>,
}

impl ManifestConversion {
    pub fn installation_url(&self) -> String {
        format!("https://github.com/apps/{}/installations/new", self.slug)
    }

    pub fn pem_present(&self) -> bool {
        !self.pem.trim().is_empty()
    }
}

/// Mint a short-lived (10-minute) RS256 GitHub App JWT from the App ID and
/// PEM private key.
///
/// App-level GitHub API calls (such as `GET /app/installations`) authenticate
/// with this JWT, not an installation token. The shape mirrors the broker's
/// `canonicalize_github_slug` mint: `iss = app_id`, RS256, `exp - iat = 600s`
/// (GitHub's documented maximum), with `iat` backdated 60s to tolerate clock
/// skew per GitHub's guidance.
///
/// The PEM bytes are consumed in memory; the returned JWT is a bearer token
/// the caller MUST NOT log.
pub fn build_app_jwt(app_id: u64, pem: &str) -> Result<String, String> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde::Serialize;

    #[derive(Serialize)]
    struct AppJwtClaims {
        iss: String,
        iat: i64,
        exp: i64,
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("system clock error: {e}"))?
        .as_secs() as i64;

    let claims = AppJwtClaims {
        iss: app_id.to_string(),
        iat: now - 60,
        exp: now + 540,
    };

    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| {
        format!("App private key parse failed (expected a PKCS#8 or PKCS#1 RSA PEM): {e}")
    })?;

    jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|e| format!("App JWT signing failed: {e}"))
}

#[derive(Clone, Deserialize)]
struct InstallationAccount {
    #[serde(default)]
    login: Option<String>,
}

#[derive(Clone, Deserialize)]
struct RawInstallation {
    id: u64,
    #[serde(default)]
    account: Option<InstallationAccount>,
    #[serde(default)]
    repository_selection: Option<String>,
}

/// A GitHub App installation resolved from `GET /app/installations`.
///
/// This is the in-process flow state P16-S3 consumes to vault-provision the
/// credential triple; S2 captures it but does not persist it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedInstallation {
    pub installation_id: u64,
    pub account_login: Option<String>,
    pub repository_selection: Option<String>,
}

/// Parse GitHub's `GET /app/installations` array response into resolved
/// installations, preserving GitHub's order.
///
/// GitHub returns an empty array while the App is registered but not yet
/// installed on any account or repository — that is the "created but not
/// installed yet" interstitial state, surfaced to the caller as `Ok(vec![])`,
/// not an error.
pub fn parse_installations(body: &Value) -> Result<Vec<ResolvedInstallation>, String> {
    let arr = body
        .as_array()
        .ok_or_else(|| "expected a JSON array of installations".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let raw: RawInstallation = serde_json::from_value(item.clone())
            .map_err(|e| format!("installation entry parse failed: {e}"))?;
        out.push(ResolvedInstallation {
            installation_id: raw.id,
            account_login: raw.account.and_then(|a| a.login),
            repository_selection: raw.repository_selection,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_rsa_private_key_pem(body: &str) -> String {
        format!(
            "{}RSA PRIVATE KEY-----\n{body}\n{}RSA PRIVATE KEY-----\n",
            "-----BEGIN ", "-----END "
        )
    }

    #[test]
    fn embedded_manifest_pulled_in() {
        assert!(
            !PUBLIC_MANIFEST_DOC.is_empty(),
            "embedded manifest must be non-empty"
        );
    }

    #[test]
    fn manifest_documents_floor_permissions() {
        // Any silent expansion or contraction of these permissions should
        // fail this test until the doc is updated explicitly. The set
        // matches the ARCH-PUBLIC-GH-APP-MANIFEST brief and is the credential
        // ceiling the broker mints sub-scoped tokens against (ADR 094).
        for checkpoint in ["contents", "pull_requests", "issues", "actions", "metadata"] {
            assert!(
                PUBLIC_MANIFEST_DOC.contains(checkpoint),
                "manifest doc missing floor anchor: {checkpoint}"
            );
        }
    }

    #[test]
    fn manifest_documents_denylist() {
        // The deny-list is load-bearing — if the doc stops calling out
        // workflows/secrets/admin as denied, a future contributor might
        // assume they're permitted. Lock the language here.
        for denied in ["Workflows", "Secrets", "Administration"] {
            assert!(
                PUBLIC_MANIFEST_DOC.contains(denied),
                "manifest doc missing denylist callout: {denied}"
            );
        }
    }

    #[test]
    fn install_url_is_canonical() {
        let url = print_install_url();
        assert_eq!(url, INSTALL_URL);
        assert!(url.starts_with("https://github.com/apps/"));
        assert!(url.ends_with("/installations/new"));
    }

    #[test]
    fn show_manifest_does_not_panic() {
        // Smoke test — calling show_manifest must not panic. Output goes to
        // stdout; cargo test captures it by default.
        show_manifest();
    }

    #[test]
    fn build_manifest_body_matches_permission_floor_with_loopback_redirect() {
        let body = build_manifest_body("http://127.0.0.1:49152/callback");

        assert_eq!(
            body["redirect_url"],
            json!("http://127.0.0.1:49152/callback")
        );
        assert_eq!(body["default_permissions"]["contents"], json!("write"));
        assert_eq!(body["default_permissions"]["pull_requests"], json!("write"));
        assert_eq!(body["default_permissions"]["issues"], json!("write"));
        assert_eq!(body["default_permissions"]["actions"], json!("read"));
        assert_eq!(body["default_permissions"]["metadata"], json!("read"));
        assert_eq!(body["default_events"], json!(["pull_request"]));
    }

    #[test]
    fn manifest_form_posts_manifest_and_state_without_leaking_to_text() {
        let body = build_manifest_body("http://127.0.0.1:49152/callback");
        let html = manifest_registration_form_html(&body, "state-123").expect("form html");

        assert!(html.contains(MANIFEST_REGISTRATION_URL));
        assert!(html.contains("state=state-123"));
        assert!(html.contains("&quot;name&quot;:&quot;Emberlink&quot;"));
        assert!(html.contains("method=\"post\""));
    }

    #[test]
    fn callback_parser_requires_matching_state_and_code() {
        let code =
            parse_manifest_callback_target("/callback?code=abc123&state=expected", "expected")
                .expect("callback code");
        assert_eq!(code, "abc123");

        let err = parse_manifest_callback_target("/callback?code=abc123&state=wrong", "expected")
            .expect_err("state mismatch should fail");
        assert!(err.contains("state did not match"));
    }

    #[test]
    fn build_app_jwt_rejects_non_pem_input() {
        let err = build_app_jwt(123, "this is not a pem").expect_err("bogus PEM must fail");
        assert!(
            err.contains("App private key parse failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_installations_empty_array_is_not_installed_yet() {
        let parsed = parse_installations(&json!([])).expect("empty array parses");
        assert!(
            parsed.is_empty(),
            "empty installation list is the not-installed-yet state, not an error"
        );
    }

    #[test]
    fn parse_installations_extracts_id_account_and_selection() {
        let body = json!([
            {
                "id": 987654,
                "account": { "login": "octo-org" },
                "repository_selection": "selected",
                "extra_field_ignored": true
            }
        ]);
        let parsed = parse_installations(&body).expect("installation array parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0],
            ResolvedInstallation {
                installation_id: 987654,
                account_login: Some("octo-org".to_string()),
                repository_selection: Some("selected".to_string()),
            }
        );
    }

    #[test]
    fn parse_installations_tolerates_missing_optional_fields() {
        let body = json!([{ "id": 42 }]);
        let parsed = parse_installations(&body).expect("minimal installation parses");
        assert_eq!(parsed[0].installation_id, 42);
        assert_eq!(parsed[0].account_login, None);
        assert_eq!(parsed[0].repository_selection, None);
    }

    #[test]
    fn parse_installations_rejects_non_array() {
        let err = parse_installations(&json!({"message": "Bad credentials"}))
            .expect_err("object body is not an installation array");
        assert!(
            err.contains("expected a JSON array"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn conversion_install_url_uses_created_app_slug_without_printing_pem() {
        let response: ManifestConversion = serde_json::from_value(json!({
            "id": 123,
            "slug": "ember-engine",
            "pem": fake_rsa_private_key_pem("secret"),
            "html_url": "https://github.com/apps/ember-engine",
            "client_id": "Iv1.test",
            "client_secret": "secret",
            "webhook_secret": "hook",
        }))
        .expect("conversion response");

        assert_eq!(
            response.installation_url(),
            "https://github.com/apps/ember-engine/installations/new"
        );
        assert!(response.pem_present());
    }
}
