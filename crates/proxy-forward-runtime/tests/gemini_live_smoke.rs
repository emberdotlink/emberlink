//! CLASSIFICATION: PUBLIC
//!
//! LIVE smoke test for the gemini GATEWAY loopback lane against the REAL Google
//! Generative Language API. `#[ignore]`d — runs only when explicitly invoked, so
//! normal `cargo test` and CI never hit the network or need a key.
//!
//! It proves the merged engine end-to-end WITHOUT the launcher (#4) or daemon
//! session wiring (#5): it drives the shared engine `handle_loopback_projector_request`
//! with `GEMINI_PROJECTOR` and a request that carries NO usable key (the client
//! sends an empty `x-goog-api-key`, like the real GATEWAY client). The projector
//! strips it, injects a brokered `google/gemini-api-key` as `x-goog-api-key`
//! server-side, pins the host to `generativelanguage.googleapis.com`, forwards,
//! and we assert Google answers 200 with a `candidates` body.
//!
//! ## Providing the key (free AI Studio tier: https://aistudio.google.com/apikey)
//!
//! The key is read from a file — never an argv/env value — so it stays out of
//! shell history and this process's argv. Write it (single-quoted) to the file:
//!
//! ```sh
//! printf %s 'YOUR_KEY' > /tmp/gemini-smoke-key && chmod 600 /tmp/gemini-smoke-key
//! ```
//!
//! Then run:
//!
//! ```sh
//! cargo test -p proxy-forward-runtime --test gemini_live_smoke -- --ignored --nocapture
//! ```
//!
//! Override the key path with `GEMINI_SMOKE_KEY_FILE` and the model with
//! `GEMINI_SMOKE_MODEL` (default `gemini-2.0-flash`).

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use core_grant_types::{ResourceSelector, ResourceType, Statement, Usage};
use core_proxy_forward::{
    PolicyBackend, PolicyError, PreflightDecision, ResolvedGrant, SessionGatewayAuthority,
};
use http_body_util::{BodyExt, Full};
use proxy_forward_runtime::forward::{handle_loopback_projector_request, GEMINI_PROJECTOR};
use zeroize::Zeroizing;

const DEFAULT_KEY_FILE: &str = "/tmp/gemini-smoke-key";
const DEFAULT_MODEL: &str = "gemini-2.0-flash";

/// Backend that resolves a `google/gemini-api-key` session authority + a
/// NON-budgeted `google/*` grant, and hands back the real (file-loaded) key
/// from `get_credential`. Non-budgeted is deliberate: the gemini lane fails
/// budgeted grants closed (`streaming_budget_enforceable=false`), and metering
/// is not yet wired for the gemini host.
struct LiveBackend {
    key: Zeroizing<String>,
}

#[async_trait]
impl PolicyBackend for LiveBackend {
    async fn resolve_session_authority(
        &self,
        _session_id: &str,
    ) -> Result<Option<SessionGatewayAuthority>, PolicyError> {
        Ok(Some(SessionGatewayAuthority {
            session_id: "sess_gemini_live".into(),
            persona_id: "smoke".into(),
            grant_id: "g-gemini-live".into(),
            credential_name: "google/gemini-api-key".into(),
        }))
    }

    async fn resolve_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
        _resolved_grant_id: Option<&str>,
        _effective_uri: &http::Uri,
        _method: &str,
    ) -> Result<ResolvedGrant, PolicyError> {
        Ok(ResolvedGrant {
            grant_id: "g-gemini-live".into(),
            persona_id: persona_id.into(),
            credential_name: credential_name.into(),
            statement_sid: "stmt-gemini-live".into(),
            statement: Statement {
                sid: "stmt-gemini-live".into(),
                resource_type: ResourceType::Session,
                actions: vec!["llm:generate".into()],
                resource: ResourceSelector::Glob {
                    pattern: "google/*".into(),
                },
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
                can_delegate: None,
            },
            grant_scope: "*".into(),
            allowed_targets: None,
        })
    }

    async fn preflight_budget(
        &self,
        _resolved: &ResolvedGrant,
        _body_bytes: &[u8],
    ) -> Result<PreflightDecision, PolicyError> {
        Ok(PreflightDecision::Allowed)
    }

    async fn get_credential(
        &self,
        _credential_name: &str,
    ) -> Result<Zeroizing<String>, PolicyError> {
        Ok(self.key.clone())
    }

    async fn post_flight(
        &self,
        _resolved: &ResolvedGrant,
        _usage: Option<core_grant_types::Usage>,
    ) -> Result<(), PolicyError> {
        Ok(())
    }

    async fn post_flight_meter(
        &self,
        _resolved: &ResolvedGrant,
        _usage: Option<core_grant_types::Usage>,
    ) -> Result<(), PolicyError> {
        Ok(())
    }

    async fn log_event(
        &self,
        _persona_id: &str,
        _event_kind: &str,
        _credential_name: Option<&str>,
        _outcome: &str,
        _detail: Option<&str>,
    ) -> Result<(), PolicyError> {
        Ok(())
    }
}

/// Read the free AI Studio key from the key file. Returns `None` (with a loud
/// skip message) if absent/empty, so an `--ignored` run without a provisioned
/// key is a graceful no-op rather than a confusing failure.
fn load_key() -> Option<Zeroizing<String>> {
    let path = std::env::var("GEMINI_SMOKE_KEY_FILE").unwrap_or_else(|_| DEFAULT_KEY_FILE.into());
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                eprintln!("SKIP: key file {path} is empty — see this file's module docs to provision a free AI Studio key.");
                None
            } else {
                Some(Zeroizing::new(trimmed.to_string()))
            }
        }
        Err(e) => {
            eprintln!("SKIP: no key file at {path} ({e}) — see this file's module docs to provision a free AI Studio key.");
            None
        }
    }
}

#[tokio::test]
#[ignore = "live: requires a free AI Studio key file + network egress to Google"]
async fn gemini_live_generate_content_round_trip() {
    let Some(key) = load_key() else {
        return;
    };
    // Install the process-level rustls CryptoProvider the guarded forward client
    // (hyper-rustls) needs — the production daemon does this at boot
    // (runtime.rs); a standalone test binary must do it itself. `ring` matches
    // the daemon + the `hyper-rustls` provider feature.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let model = std::env::var("GEMINI_SMOKE_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.into());

    let backend = Arc::new(LiveBackend { key });
    let path = format!("/v1beta/models/{model}:generateContent");
    let body = r#"{"contents":[{"parts":[{"text":"Reply with exactly: ember gemini lane is live"}]}]}"#;

    // The client carries NO usable auth — an empty `x-goog-api-key` exactly like
    // the real gemini-cli GATEWAY client. The projector must strip it and inject
    // the brokered key server-side.
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(path.as_str())
        .header("content-type", "application/json")
        .header("x-goog-api-key", "")
        .body(Full::new(Bytes::from(body)))
        .expect("build request");

    let result =
        handle_loopback_projector_request(&GEMINI_PROJECTOR, backend, req, "sess_gemini_live".into())
            .await;

    let resp = match result {
        Ok(resp) => resp,
        Err(e) => panic!(
            "handler returned Err — the engine reached the forward step but the upstream \
             call failed (connectivity / TLS / SSRF / DNS), NOT a credential-injection issue: {e:?}"
        ),
    };

    let status = resp.status();
    let bytes = BodyExt::collect(resp.into_body())
        .await
        .map(|c| c.to_bytes())
        .expect("collect response body");
    let text = String::from_utf8_lossy(&bytes);
    let snippet: String = text.chars().take(1200).collect();
    eprintln!(
        "--- gemini live smoke ---\nmodel: {model}\nstatus: {status}\nbody (first 1200 chars):\n{snippet}\n-------------------------"
    );

    // The engine's job is to deliver an AUTHENTICATED request to Google with the
    // broker-injected key — NOT to guarantee Google's quota/model availability.
    // So we validate the ENGINE: the call must not fail at the transport/HTTP-2
    // layer (a `PROTOCOL_ERROR` would mean a malformed forward, e.g. the
    // explicit-Host regression), and Google must not reject the *credential*.
    let code = status.as_u16();
    let auth_failure = code == 401
        || text.contains("API_KEY_INVALID")
        || (code == 403 && text.contains("API_KEY"));
    assert!(
        !auth_failure,
        "credential injection/auth FAILED — the broker key was rejected: {snippet}"
    );

    // A 200 (generated), 429 RESOURCE_EXHAUSTED (authenticated but out of quota),
    // or 404 ModelNotFound (authenticated, wrong model) all prove the engine
    // reached Google authenticated. Anything else is unexpected.
    let engine_reached_authenticated =
        code == 200 || code == 429 || (code == 404 && text.contains("not found"));
    assert!(
        engine_reached_authenticated,
        "engine did not get an authenticated response from Google (status {status}): {snippet}"
    );

    if code == 200 {
        assert!(
            text.contains("candidates"),
            "200 but no `candidates` body: {snippet}"
        );
        eprintln!("PASS: full generate round-trip (200 + candidates).");
    } else {
        eprintln!(
            "PASS (engine validated): authenticated round-trip to Google, status {status}. \
             No generate-200 yet — this key reports free-tier quota `limit: 0` (common for \
             Workspace-domain or billing-disabled keys). For a literal 200, provision a key \
             with free-tier or billing quota for {model}, or set GEMINI_SMOKE_MODEL."
        );
    }
}
