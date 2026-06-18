//! Cloudflare broker — issues scoped API tokens via `POST /user/tokens`
//! and actively revokes them via `DELETE /user/tokens/:id`.
//!
//! Phase 1 of ADR 094 + ADR 096. The Cloudflare API supports per-issuance
//! token minting with explicit scope (`policies[]`, zone, `permissions[]`)
//! and TTL (`expires_on`), making this the "fresh mint per issuance" broker
//! case — structurally different from the AnthropicBroker, which serves a
//! stored workspace key. See ADR 094 §Phase 1 for the full issuance flow.
//!
//! WASM: ureq does not compile to `wasm32-unknown-unknown`, so this
//! module is gated `#[cfg(not(target_arch = "wasm32"))]` at the
//! `lib.rs` level. WASM consumers of `core-broker` see the trait + the
//! `MockBroker`, but cannot construct the real Cloudflare client.

use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential, MintStamp};

const DEFAULT_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Provider-specific scope payload for the Cloudflare broker.
///
/// Maps directly to the Cloudflare `POST /user/tokens` body:
/// - `name` is the human-readable label for the token (visible in the
///   Cloudflare dashboard and the Grant Receipt).
/// - `policies` is the list of permission policies (resource + permission
///   group pairs). At minimum, one policy scoping to a zone + `dns:edit`
///   is required for the Pulumi IaC use case described in ADR 094 §Phase 1.
/// - `expires_at` is the upstream hard expiration. The broker passes it
///   through to the Cloudflare API. If `None`, the broker computes
///   `now + ttl` and sends that. Cloudflare will reject timestamps in the
///   past.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareScope {
    pub name: String,
    pub policies: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Cloudflare API token broker.
///
/// Construct with [`CloudflareBroker::new`] for production (talks to
/// `https://api.cloudflare.com/client/v4`) or
/// [`CloudflareBroker::with_base_url`] to point at a test server /
/// `ember-proxy` egress.
pub struct CloudflareBroker {
    admin_token: SecretString,
    http: ureq::Agent,
    base_url: String,
}

impl CloudflareBroker {
    /// Production constructor — points at `https://api.cloudflare.com/client/v4`.
    pub fn new(admin_token: SecretString) -> Self {
        Self::with_base_url(admin_token, DEFAULT_BASE.to_string())
    }

    /// Test / `ember-proxy` constructor — points at the supplied base URL.
    /// Trailing slash is normalized off so the URL builder can append
    /// `/user/tokens` paths uniformly.
    pub fn with_base_url(admin_token: SecretString, base_url: String) -> Self {
        // ureq v3: disable http_status_as_error so 4xx/5xx come back as
        // Ok(Response) with a non-success status, matching the v2
        // body-on-error behavior the upstream-error reporting here
        // depends on (see anthropic.rs for full rationale).
        let http: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_recv_response(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            admin_token,
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Authorization header value. Centralized so `issue` and `revoke`
    /// cannot drift on auth.
    fn auth_header(&self) -> String {
        format!("Bearer {}", self.admin_token.expose_secret())
    }
}

/// Subset of the Cloudflare `POST /user/tokens` response we need.
///
/// The Cloudflare API wraps all responses in a `{ "result": {...}, "success": bool }`
/// envelope. We only deserialize the fields we surface back to the caller.
/// `expires_on` is optional because tokens created without a TTL omit it.
#[derive(Debug, Deserialize)]
struct TokenResult {
    id: String,
    value: String,
    #[serde(default)]
    expires_on: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    success: bool,
    result: Option<TokenResult>,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

impl Broker for CloudflareBroker {
    fn provider(&self) -> BrokerProvider {
        BrokerProvider::Cloudflare
    }

    async fn issue(&self, req: BrokerRequest) -> Result<BrokeredCredential, BrokerError> {
        if req.provider != BrokerProvider::Cloudflare {
            return Err(BrokerError::InvalidScope(format!(
                "cloudflare broker received request for {}",
                req.provider.as_str()
            )));
        }
        let scope: CloudflareScope = serde_json::from_value(req.scope.clone())
            .map_err(|e| BrokerError::InvalidScope(e.to_string()))?;

        // Compute `expires_on`: prefer the scope-level timestamp, fall back to
        // now + ttl converted to a UTC datetime for the Cloudflare API.
        // Use SystemTime (no chrono `clock` feature needed) and convert.
        let now_st = SystemTime::now();
        let expires_on: DateTime<Utc> = scope.expires_at.unwrap_or_else(|| {
            let expires_st = now_st + req.ttl;
            expires_st.into()
        });
        let not_before: DateTime<Utc> = now_st.into();

        let url = format!("{}/user/tokens", self.base_url);
        let body = serde_json::json!({
            "name": scope.name,
            "policies": scope.policies,
            "not_before": not_before.to_rfc3339(),
            "expires_on": expires_on.to_rfc3339(),
        });

        let resp = self
            .http
            .post(&url)
            .header("Authorization", &self.auth_header())
            .header("Content-Type", "application/json")
            .send_json(body);

        let body_text = match resp {
            Ok(mut r) => {
                let status = r.status();
                let body = r
                    .body_mut()
                    .read_to_string()
                    .map_err(|e| BrokerError::Upstream(format!("read body: {e}")))?;
                if !status.is_success() {
                    return Err(BrokerError::Upstream(format!(
                        "cloudflare POST /user/tokens returned {}: {body}",
                        status.as_u16()
                    )));
                }
                body
            }
            Err(e) => return Err(BrokerError::Upstream(format!("transport: {e}"))),
        };

        let parsed: TokenResponse = serde_json::from_str(&body_text).map_err(|e| {
            BrokerError::Upstream(format!("decode token response: {e}; body={body_text}"))
        })?;

        if !parsed.success {
            return Err(BrokerError::Upstream(format!(
                "cloudflare POST /user/tokens failed: errors={:?}",
                parsed.errors
            )));
        }

        let result = parsed.result.ok_or_else(|| {
            BrokerError::Upstream("cloudflare response missing result field".to_string())
        })?;

        // Prefer the upstream-reported `expires_on` (so any clamp Cloudflare
        // applied is reflected); fall back to the computed value we sent so
        // the receipt still has a valid expiry.
        let expires_at: SystemTime = result
            .expires_on
            .map(|t| t.into())
            .unwrap_or_else(|| SystemTime::now() + req.ttl);

        Ok(BrokeredCredential {
            token: SecretString::from(result.value),
            expires_at,
            materialization_id: result.id,
            // Cloudflare's token response carries policy but the
            // projector/clamp pair is deferred to BKR-5 (ADR 213 G1).
            mint_stamp: MintStamp::Opaque,
        })
    }

    async fn revoke(&self, materialization_id: &str) -> Result<(), BrokerError> {
        if materialization_id.is_empty() {
            return Err(BrokerError::UnknownMaterialization(String::new()));
        }
        let url = format!("{}/user/tokens/{materialization_id}", self.base_url);

        let resp = self
            .http
            .delete(&url)
            .header("Authorization", &self.auth_header())
            .header("Content-Type", "application/json")
            .call();

        match resp {
            Ok(mut r) => {
                let code = r.status().as_u16();
                if code == 200 || code == 204 {
                    Ok(())
                } else if code == 404 {
                    Err(BrokerError::UnknownMaterialization(
                        materialization_id.to_string(),
                    ))
                } else {
                    let body = r.body_mut().read_to_string().unwrap_or_default();
                    Err(BrokerError::Upstream(format!(
                        "cloudflare DELETE /user/tokens/{materialization_id} \
                         returned {code}: {body}"
                    )))
                }
            }
            Err(e) => Err(BrokerError::Upstream(format!("transport: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use serde_json::json;

    use super::*;

    /// Minimal blocking executor — same shape as the one in `lib.rs`
    /// tests. The futures returned by CloudflareBroker's async methods
    /// only do blocking I/O (they don't yield), so a single poll
    /// completes them. We still loop in case poll-readiness changes.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        use std::pin::pin;
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }
        let waker: Waker = Arc::new(NoopWaker).into();
        let mut ctx = Context::from_waker(&waker);
        let mut pinned = pin!(f);
        loop {
            if let Poll::Ready(v) = pinned.as_mut().poll(&mut ctx) {
                return v;
            }
        }
    }

    /// Captured request — just what tests need to assert against.
    #[derive(Debug, Clone)]
    struct CapturedRequest {
        method: String,
        path: String,
        auth: Option<String>,
        body: String,
    }

    /// Canned response.
    #[derive(Debug, Clone)]
    struct CannedResponse {
        status: u16,
        body: String,
    }

    /// Tiny single-shot HTTP/1.1 server: binds 127.0.0.1:0, accepts ONE
    /// connection, returns the canned response for whatever the client
    /// sends. The captured request is recorded into the shared `Mutex`
    /// so the test thread can assert against it after the server exits.
    fn spawn_one_shot(
        canned: CannedResponse,
        captured: Arc<Mutex<Option<CapturedRequest>>>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let base = format!("http://{addr}");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

            // Status line.
            let mut status_line = String::new();
            reader.read_line(&mut status_line).expect("read status");
            let mut sl = status_line.split_whitespace();
            let method = sl.next().unwrap_or("").to_string();
            let path = sl.next().unwrap_or("").to_string();

            // Headers.
            let mut auth = None;
            let mut content_length: usize = 0;
            loop {
                let mut hline = String::new();
                if reader.read_line(&mut hline).expect("read header") == 0 {
                    break;
                }
                let hline = hline.trim_end_matches(['\r', '\n']);
                if hline.is_empty() {
                    break;
                }
                if let Some((k, v)) = hline.split_once(':') {
                    let k = k.trim().to_ascii_lowercase();
                    let v = v.trim().to_string();
                    match k.as_str() {
                        "authorization" => auth = Some(v),
                        "content-length" => {
                            content_length = v.parse().unwrap_or(0);
                        }
                        _ => {}
                    }
                }
            }

            // Body.
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                reader.read_exact(&mut body).expect("read body");
            }
            let body_str = String::from_utf8_lossy(&body).to_string();

            *captured.lock().expect("captured") = Some(CapturedRequest {
                method,
                path,
                auth,
                body: body_str,
            });

            // Response.
            let body_bytes = canned.body.as_bytes();
            let response = format!(
                "HTTP/1.1 {} OK\r\n\
                 content-type: application/json\r\n\
                 content-length: {}\r\n\
                 connection: close\r\n\
                 \r\n",
                canned.status,
                body_bytes.len()
            );
            stream.write_all(response.as_bytes()).expect("write hdr");
            stream.write_all(body_bytes).expect("write body");
            stream.flush().ok();
        });
        (base, handle)
    }

    fn cf_request(name: &str) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::Cloudflare,
            scope: json!({
                "name": name,
                "policies": [
                    {
                        "effect": "allow",
                        "resources": { "com.cloudflare.api.account.zone.*": "*" },
                        "permission_groups": [{ "id": "c8fed203ed3043cba015a93ad1616f1f", "name": "DNS Write" }]
                    }
                ]
            }),
            ttl: Duration::from_secs(900),
            contract_id: None,
            action_ref: None,
            workspace_ref: None,
            subject_ref: None,
            coordination_ref: None,
            caller_ref: None,
            authority_ref: None,
            reason: "unit test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    #[test]
    fn issue_success_returns_token_and_id_and_sets_bearer_auth() {
        let canned = CannedResponse {
            status: 200,
            body: json!({
                "success": true,
                "errors": [],
                "result": {
                    "id": "cf-token-id-ABCDEF",
                    "value": "v1.0-cf-token-value-XXXX",
                    "expires_on": "2026-12-31T23:59:59Z",
                }
            })
            .to_string(),
        };
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured.clone());

        let broker = CloudflareBroker::with_base_url(
            SecretString::from("admin-token-123".to_string()),
            base,
        );
        let cred = block_on(broker.issue(cf_request("demo-token"))).expect("issue ok");

        handle.join().expect("server thread");
        let req = captured
            .lock()
            .expect("captured")
            .clone()
            .expect("captured req");

        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/user/tokens");
        assert_eq!(req.auth.as_deref(), Some("Bearer admin-token-123"));
        let parsed_body: serde_json::Value = serde_json::from_str(&req.body).expect("body json");
        assert_eq!(parsed_body["name"], "demo-token");
        assert!(parsed_body["policies"].is_array());

        assert_eq!(cred.materialization_id, "cf-token-id-ABCDEF");
        assert_eq!(cred.token.expose_secret(), "v1.0-cf-token-value-XXXX");
    }

    #[test]
    fn issue_4xx_failure_maps_to_upstream_error() {
        let canned = CannedResponse {
            status: 400,
            body: json!({
                "success": false,
                "errors": [{"code": 6003, "message": "Invalid request"}]
            })
            .to_string(),
        };
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured);

        let broker = CloudflareBroker::with_base_url(SecretString::from("tok".to_string()), base);
        let err = block_on(broker.issue(cf_request("bad"))).expect_err("must fail");
        handle.join().expect("server thread");
        match err {
            BrokerError::Upstream(msg) => {
                assert!(msg.contains("400"), "expected status code in msg: {msg}");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[test]
    fn issue_success_false_maps_to_upstream_error() {
        let canned = CannedResponse {
            status: 200,
            body: json!({
                "success": false,
                "errors": [{"code": 9109, "message": "Invalid token TTL"}],
                "result": null
            })
            .to_string(),
        };
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured);

        let broker = CloudflareBroker::with_base_url(SecretString::from("tok".to_string()), base);
        let err = block_on(broker.issue(cf_request("bad"))).expect_err("must fail");
        handle.join().expect("server thread");
        match err {
            BrokerError::Upstream(msg) => {
                assert!(msg.contains("failed"), "expected 'failed' in msg: {msg}");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[test]
    fn revoke_success_returns_ok_and_sends_delete() {
        let canned = CannedResponse {
            status: 200,
            body: json!({"success": true, "result": {"id": "cf-token-id-ZZZ"}}).to_string(),
        };
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured.clone());

        let broker = CloudflareBroker::with_base_url(SecretString::from("tok".to_string()), base);
        block_on(broker.revoke("cf-token-id-ZZZ")).expect("revoke ok");

        handle.join().expect("server thread");
        let req = captured
            .lock()
            .expect("captured")
            .clone()
            .expect("captured req");
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, "/user/tokens/cf-token-id-ZZZ");
        assert_eq!(req.auth.as_deref(), Some("Bearer tok"));
    }

    #[test]
    fn revoke_404_maps_to_unknown_materialization() {
        let canned = CannedResponse {
            status: 404,
            body: json!({"success": false, "errors": [{"code": 10000, "message": "Not found"}]})
                .to_string(),
        };
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured);

        let broker = CloudflareBroker::with_base_url(SecretString::from("tok".to_string()), base);
        let err = block_on(broker.revoke("does-not-exist")).expect_err("must fail");
        handle.join().expect("server thread");
        match err {
            BrokerError::UnknownMaterialization(id) => {
                assert_eq!(id, "does-not-exist");
            }
            other => panic!("expected UnknownMaterialization, got {other:?}"),
        }
    }

    #[test]
    fn provider_returns_cloudflare() {
        let broker = CloudflareBroker::new(SecretString::from("admin".to_string()));
        assert_eq!(broker.provider(), BrokerProvider::Cloudflare);
    }

    #[test]
    fn issue_rejects_request_for_other_provider() {
        let broker = CloudflareBroker::new(SecretString::from("admin".to_string()));
        let mut req = cf_request("demo");
        req.provider = BrokerProvider::Anthropic;
        let err = block_on(broker.issue(req)).expect_err("must fail");
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[test]
    fn cloudflare_scope_round_trips_with_optional_expiry() {
        let s = CloudflareScope {
            name: "test-token".to_string(),
            policies: vec![json!({"effect": "allow"})],
            expires_at: Some(
                DateTime::parse_from_rfc3339("2026-12-31T23:59:59Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        };
        let v = serde_json::to_value(&s).unwrap();
        let back: CloudflareScope = serde_json::from_value(v).unwrap();
        assert_eq!(back.name, "test-token");
        assert_eq!(back.policies.len(), 1);
        assert!(back.expires_at.is_some());

        // Optional field: omitted from JSON should still parse.
        let bare: CloudflareScope = serde_json::from_value(json!({
            "name": "bare",
            "policies": []
        }))
        .unwrap();
        assert!(bare.expires_at.is_none());
    }
}
