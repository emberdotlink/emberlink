//! Anthropic broker — issues workspace API keys via the
//! `POST /v1/organizations/api_keys` admin endpoint and revokes them
//! by setting `status=inactive` via `PATCH /v1/organizations/api_keys/<id>`.
//!
//! Phase 2 of ADR 094 + ADR 096. The trait shape is async-by-default
//! (per `BROKER-CRATE-SCAFFOLD`); the HTTP transport itself is `ureq`
//! (sync) — each `issue` / `revoke` call is wrapped so the future
//! returned by the trait method completes once the blocking call returns.
//! This is acceptable here because the daemon runs broker calls on a
//! dedicated tokio task and the per-call latency budget is dominated by
//! the upstream round-trip.
//!
//! WASM: ureq does not compile to `wasm32-unknown-unknown`, so this
//! module is gated `#[cfg(not(target_arch = "wasm32"))]` at the
//! `lib.rs` level. WASM consumers of `core-broker` see the trait + the
//! `MockBroker`, but cannot construct the real Anthropic client.

use std::time::{Duration, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    Broker, BrokerError, BrokerProvider, BrokerRequest, BrokerUsage, BrokeredCredential, MintStamp,
    UsagePeriod,
};

const DEFAULT_BASE: &str = "https://api.anthropic.com";
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Provider-specific scope payload for the Anthropic broker.
///
/// `name` is the human-readable label that will surface in the
/// Anthropic console (and in the Grant Receipt).
///
/// `expires_at` is the upstream-side hard expiration. The broker
/// passes it through to the Admin API; the Admin API will refuse a
/// timestamp in the past. If `None`, the workspace key is created
/// without an upstream expiration and the daemon's revoke path is the
/// only kill switch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicScope {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Anthropic Admin-API broker.
///
/// Construct with [`AnthropicBroker::new`] for production (talks to
/// `https://api.anthropic.com`) or [`AnthropicBroker::with_base_url`]
/// to point at a test server / `ember-proxy` egress.
pub struct AnthropicBroker {
    admin_token: SecretString,
    http: ureq::Agent,
    base_url: String,
}

impl AnthropicBroker {
    /// Production constructor — points at `https://api.anthropic.com`.
    pub fn new(admin_token: SecretString) -> Self {
        Self::with_base_url(admin_token, DEFAULT_BASE.to_string())
    }

    /// Test / `ember-proxy` constructor — points at the supplied base URL.
    /// Trailing slash is normalized off so the URL builder can append
    /// `/v1/...` paths uniformly.
    pub fn with_base_url(admin_token: SecretString, base_url: String) -> Self {
        // ureq v3: disable http_status_as_error so 4xx/5xx come back as
        // Ok(Response) with a non-success status. The body-on-error
        // surface below relies on reading the body after the call
        // returns; the legacy v2 `Error::Status(code, r)` arm with
        // body-read is gone (Error::StatusCode in v3 drops the body).
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

    /// Produces the per-request header set. Centralized so `issue`
    /// and `revoke` cannot drift on auth.
    fn headers(&self) -> [(&'static str, String); 3] {
        [
            ("x-api-key", self.admin_token.expose_secret().to_string()),
            ("anthropic-version", ANTHROPIC_VERSION.to_string()),
            ("content-type", "application/json".to_string()),
        ]
    }
}

/// Subset of the Anthropic Admin-API workspace-key response we need.
///
/// We only deserialize the fields we surface back to the caller; any
/// other fields the API may return are ignored. `expires_at` is
/// optional because workspace keys created without an explicit
/// expiration omit the field on read-back.
#[derive(Debug, Deserialize)]
struct WorkspaceKeyResponse {
    id: String,
    /// The actual API key string. Anthropic returns this exactly once
    /// at creation time; subsequent reads do not echo it.
    api_key: String,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
}

/// One record from the Usage & Cost API paginated response.
///
/// The API returns a list of `BillingUsage` objects under the
/// `results` key. We aggregate these to produce a single `BrokerUsage`.
/// Fields are `#[serde(default)]` so missing fields (e.g., when
/// caching was not used) deserialize as zero rather than failing.
#[derive(Debug, Deserialize, Default)]
struct UsageRecord {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
}

/// Top-level paginated response from `GET /v1/organizations/usage_report/messages`.
#[derive(Debug, Deserialize)]
struct UsageReportResponse {
    results: Vec<UsageRecord>,
    #[serde(default)]
    has_more: bool,
    #[serde(default)]
    next_page: Option<String>,
}

/// Anthropic public model pricing (USD per million tokens) used for
/// cost estimation. These are approximate at the time of writing;
/// actual billing is authoritative.
///
/// We use claude-3-5-sonnet as the reference model for the estimate.
/// The estimate is intentionally conservative (rounds up).
const INPUT_PRICE_PER_M: f64 = 3.0;
const OUTPUT_PRICE_PER_M: f64 = 15.0;
const CACHE_READ_PRICE_PER_M: f64 = 0.30;
const CACHE_CREATION_PRICE_PER_M: f64 = 3.75;

impl AnthropicBroker {
    /// Fetches all pages of usage records for `key_id` within the
    /// given time window. Returns the aggregated totals.
    fn fetch_usage_pages(
        &self,
        key_id: &str,
        start: &str,
        end: &str,
    ) -> Result<(u64, u64, u64, u64), BrokerError> {
        let mut total_input: u64 = 0;
        let mut total_output: u64 = 0;
        let mut total_cache_read: u64 = 0;
        let mut total_cache_creation: u64 = 0;

        let mut next_page: Option<String> = None;

        loop {
            let mut url = format!(
                "{}/v1/organizations/usage_report/messages?api_key_id={}&start_time={}&end_time={}",
                self.base_url, key_id, start, end
            );
            if let Some(ref cursor) = next_page {
                url.push_str("&page=");
                url.push_str(cursor);
            }

            let mut request = self.http.get(&url);
            for (k, v) in self.headers() {
                request = request.header(k, &v);
            }
            let resp = request.call();

            let body_text = match resp {
                Ok(mut r) => {
                    let status = r.status();
                    let body = r
                        .body_mut()
                        .read_to_string()
                        .map_err(|e| BrokerError::Upstream(format!("read usage body: {e}")))?;
                    if !status.is_success() {
                        return Err(BrokerError::Upstream(format!(
                            "anthropic GET /v1/organizations/usage_report/messages returned {}: {body}",
                            status.as_u16()
                        )));
                    }
                    body
                }
                Err(e) => return Err(BrokerError::Upstream(format!("transport: {e}"))),
            };

            let page: UsageReportResponse = serde_json::from_str(&body_text).map_err(|e| {
                BrokerError::Upstream(format!("decode usage report: {e}; body={body_text}"))
            })?;

            for rec in &page.results {
                total_input += rec.input_tokens;
                total_output += rec.output_tokens;
                total_cache_read += rec.cache_read_input_tokens;
                total_cache_creation += rec.cache_creation_input_tokens;
            }

            if page.has_more {
                next_page = page.next_page;
                if next_page.is_none() {
                    // has_more without a cursor — defensive stop.
                    break;
                }
            } else {
                break;
            }
        }

        Ok((
            total_input,
            total_output,
            total_cache_read,
            total_cache_creation,
        ))
    }
}

/// Estimate cost in US cents (integer, rounded up) from token counts.
fn estimate_cost_cents(
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_creation_tokens: u64,
) -> u64 {
    let cost_usd = (input_tokens as f64 / 1_000_000.0) * INPUT_PRICE_PER_M
        + (output_tokens as f64 / 1_000_000.0) * OUTPUT_PRICE_PER_M
        + (cache_read_tokens as f64 / 1_000_000.0) * CACHE_READ_PRICE_PER_M
        + (cache_creation_tokens as f64 / 1_000_000.0) * CACHE_CREATION_PRICE_PER_M;
    // Convert to cents, round up.
    (cost_usd * 100.0).ceil() as u64
}

impl Broker for AnthropicBroker {
    fn provider(&self) -> BrokerProvider {
        BrokerProvider::Anthropic
    }

    async fn issue(&self, req: BrokerRequest) -> Result<BrokeredCredential, BrokerError> {
        if req.provider != BrokerProvider::Anthropic {
            return Err(BrokerError::InvalidScope(format!(
                "anthropic broker received request for {}",
                req.provider.as_str()
            )));
        }
        let scope: AnthropicScope = serde_json::from_value(req.scope.clone())
            .map_err(|e| BrokerError::InvalidScope(e.to_string()))?;

        let url = format!("{}/v1/organizations/api_keys", self.base_url);
        let mut body = serde_json::Map::new();
        body.insert("name".into(), serde_json::Value::String(scope.name));
        if let Some(t) = scope.expires_at {
            // RFC3339 with `Z` suffix — what the Admin API accepts.
            body.insert(
                "expires_at".into(),
                serde_json::Value::String(t.to_rfc3339()),
            );
        }
        let body = serde_json::Value::Object(body);

        let mut request = self.http.post(&url);
        for (k, v) in self.headers() {
            request = request.header(k, &v);
        }
        let resp = request.send_json(body);

        let body_text = match resp {
            Ok(mut r) => {
                let status = r.status();
                let body = r
                    .body_mut()
                    .read_to_string()
                    .map_err(|e| BrokerError::Upstream(format!("read body: {e}")))?;
                if !status.is_success() {
                    return Err(BrokerError::Upstream(format!(
                        "anthropic POST /v1/organizations/api_keys returned {}: {body}",
                        status.as_u16()
                    )));
                }
                body
            }
            Err(e) => return Err(BrokerError::Upstream(format!("transport: {e}"))),
        };

        let parsed: WorkspaceKeyResponse = serde_json::from_str(&body_text).map_err(|e| {
            BrokerError::Upstream(format!(
                "decode workspace-key response: {e}; body={body_text}"
            ))
        })?;

        // Compute `expires_at` for the BrokeredCredential. Prefer the
        // upstream-reported timestamp (so any clamp Anthropic applied
        // is reflected); fall back to `now + req.ttl` so the receipt
        // still has a useful upper bound when Anthropic returns no
        // expiration (e.g., the workspace-key was created without one).
        let expires_at = parsed
            .expires_at
            .map(|t| t.into())
            .unwrap_or_else(|| SystemTime::now() + req.ttl);

        Ok(BrokeredCredential {
            token: SecretString::from(parsed.api_key),
            expires_at,
            materialization_id: parsed.id,
            // Anthropic is introspection-less (ADR 213 G3): the workspace key
            // yields no scope echo — enforcement is the proxy-mediated
            // budget/ttl, not a checkable native scope. `MintStamp::Opaque`
            // is the canonical encoding for "no attestation" (replaces the
            // legacy `provider_scope_attestable = Some(false)` discriminator).
            mint_stamp: MintStamp::Opaque,
        })
    }

    async fn revoke(&self, materialization_id: &str) -> Result<(), BrokerError> {
        if materialization_id.is_empty() {
            return Err(BrokerError::UnknownMaterialization(String::new()));
        }
        let url = format!(
            "{}/v1/organizations/api_keys/{materialization_id}",
            self.base_url
        );
        let body = serde_json::json!({ "status": "inactive" });

        let mut request = self.http.patch(&url);
        for (k, v) in self.headers() {
            request = request.header(k, &v);
        }
        let resp = request.send_json(body);

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
                        "anthropic PATCH /v1/organizations/api_keys/{materialization_id} \
                         returned {code}: {body}"
                    )))
                }
            }
            Err(e) => Err(BrokerError::Upstream(format!("transport: {e}"))),
        }
    }

    async fn reconcile_usage(
        &self,
        materialization_id: &str,
        period: UsagePeriod,
    ) -> Result<BrokerUsage, BrokerError> {
        if materialization_id.is_empty() {
            return Err(BrokerError::InvalidScope(
                "materialization_id must not be empty".to_string(),
            ));
        }

        // Convert SystemTime → DateTime<Utc> → RFC3339 with 'Z' suffix,
        // which is what the Anthropic API's `start_time` / `end_time`
        // query params expect.
        let start_dt: DateTime<Utc> = period.start.into();
        let end_dt: DateTime<Utc> = period.end.into();
        let start_str = start_dt.to_rfc3339_opts(SecondsFormat::Secs, true);
        let end_str = end_dt.to_rfc3339_opts(SecondsFormat::Secs, true);

        let (input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens) =
            self.fetch_usage_pages(materialization_id, &start_str, &end_str)?;

        let cost_cents_estimate = estimate_cost_cents(
            input_tokens,
            output_tokens,
            cache_read_input_tokens,
            cache_creation_input_tokens,
        );

        Ok(BrokerUsage {
            input_tokens,
            output_tokens,
            cache_read_input_tokens,
            cache_creation_input_tokens,
            cost_cents_estimate,
            period_start: period.start,
            period_end: period.end,
        })
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
    /// tests. The futures returned by AnthropicBroker's async methods
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
        api_key: Option<String>,
        anthropic_version: Option<String>,
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
            let mut api_key = None;
            let mut anthropic_version = None;
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
                        "x-api-key" => api_key = Some(v),
                        "anthropic-version" => anthropic_version = Some(v),
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
                api_key,
                anthropic_version,
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

    fn anthropic_request(name: &str) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::Anthropic,
            scope: json!({ "name": name }),
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
    fn issue_success_returns_token_and_id_and_sets_admin_headers() {
        let canned = CannedResponse {
            status: 200,
            body: json!({
                "id": "apikey_01ABCDEFGHIJK",
                "api_key": "sk-ant-workspace-XXXX",
                "name": "demo-key",
                "expires_at": "2026-12-31T23:59:59Z",
            })
            .to_string(),
        };
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured.clone());

        let broker =
            AnthropicBroker::with_base_url(SecretString::from("admin-token-123".to_string()), base);
        let cred = block_on(broker.issue(anthropic_request("demo-key"))).expect("issue ok");

        handle.join().expect("server thread");
        let req = captured
            .lock()
            .expect("captured")
            .clone()
            .expect("captured req");

        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/v1/organizations/api_keys");
        assert_eq!(req.api_key.as_deref(), Some("admin-token-123"));
        assert_eq!(req.anthropic_version.as_deref(), Some("2023-06-01"));
        let parsed_body: serde_json::Value = serde_json::from_str(&req.body).expect("body json");
        assert_eq!(parsed_body["name"], "demo-key");

        assert_eq!(cred.materialization_id, "apikey_01ABCDEFGHIJK");
        assert_eq!(cred.token.expose_secret(), "sk-ant-workspace-XXXX");
    }

    #[test]
    fn issue_4xx_failure_maps_to_upstream_error() {
        let canned = CannedResponse {
            status: 400,
            body: json!({"type": "error", "error": {"message": "bad name"}}).to_string(),
        };
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured);

        let broker = AnthropicBroker::with_base_url(SecretString::from("tok".to_string()), base);
        let err = block_on(broker.issue(anthropic_request("bad"))).expect_err("must fail");
        handle.join().expect("server thread");
        match err {
            BrokerError::Upstream(msg) => {
                assert!(msg.contains("400"), "expected status code in msg: {msg}");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[test]
    fn revoke_success_returns_ok_and_sends_status_inactive() {
        let canned = CannedResponse {
            status: 200,
            body: json!({"id": "apikey_01ZZZ", "status": "inactive"}).to_string(),
        };
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured.clone());

        let broker = AnthropicBroker::with_base_url(SecretString::from("tok".to_string()), base);
        block_on(broker.revoke("apikey_01ZZZ")).expect("revoke ok");

        handle.join().expect("server thread");
        let req = captured
            .lock()
            .expect("captured")
            .clone()
            .expect("captured req");
        assert_eq!(req.method, "PATCH");
        assert_eq!(req.path, "/v1/organizations/api_keys/apikey_01ZZZ");
        assert_eq!(req.api_key.as_deref(), Some("tok"));
        let body: serde_json::Value = serde_json::from_str(&req.body).expect("body json");
        assert_eq!(body["status"], "inactive");
    }

    #[test]
    fn revoke_404_maps_to_unknown_materialization() {
        let canned = CannedResponse {
            status: 404,
            body: json!({"type": "error", "error": {"message": "not found"}}).to_string(),
        };
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured);

        let broker = AnthropicBroker::with_base_url(SecretString::from("tok".to_string()), base);
        let err = block_on(broker.revoke("apikey_does_not_exist")).expect_err("must fail");
        handle.join().expect("server thread");
        match err {
            BrokerError::UnknownMaterialization(id) => {
                assert_eq!(id, "apikey_does_not_exist");
            }
            other => panic!("expected UnknownMaterialization, got {other:?}"),
        }
    }

    #[test]
    fn provider_returns_anthropic() {
        let broker = AnthropicBroker::new(SecretString::from("admin".to_string()));
        assert_eq!(broker.provider(), BrokerProvider::Anthropic);
    }

    #[test]
    fn issue_rejects_request_for_other_provider() {
        let broker = AnthropicBroker::new(SecretString::from("admin".to_string()));
        let mut req = anthropic_request("demo");
        req.provider = BrokerProvider::Cloudflare;
        let err = block_on(broker.issue(req)).expect_err("must fail");
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[test]
    fn anthropic_scope_round_trips_with_optional_expiry() {
        let s = AnthropicScope {
            name: "k".to_string(),
            expires_at: Some(
                DateTime::parse_from_rfc3339("2026-12-31T23:59:59Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        };
        let v = serde_json::to_value(&s).unwrap();
        let back: AnthropicScope = serde_json::from_value(v).unwrap();
        assert_eq!(back.name, "k");
        assert!(back.expires_at.is_some());

        // Optional field: omitted from JSON should still parse.
        let bare: AnthropicScope = serde_json::from_value(json!({"name":"k"})).unwrap();
        assert!(bare.expires_at.is_none());
    }

    // ----------------------------------------------------------------
    // reconcile_usage tests
    // ----------------------------------------------------------------

    /// Returns a UsagePeriod spanning a fixed 15-minute window so tests
    /// produce deterministic query-string values.
    fn fixed_period() -> UsagePeriod {
        use std::time::UNIX_EPOCH;
        // 2026-04-26T22:15:00Z and 2026-04-26T22:30:00Z as UNIX timestamps.
        UsagePeriod {
            start: UNIX_EPOCH + Duration::from_secs(1_745_705_700),
            end: UNIX_EPOCH + Duration::from_secs(1_745_706_600),
        }
    }

    /// Single-page usage response with known token counts.
    fn usage_page_single(
        input: u64,
        output: u64,
        cache_read: u64,
        cache_creation: u64,
    ) -> CannedResponse {
        CannedResponse {
            status: 200,
            body: json!({
                "results": [{
                    "input_tokens": input,
                    "output_tokens": output,
                    "cache_read_input_tokens": cache_read,
                    "cache_creation_input_tokens": cache_creation,
                }],
                "has_more": false,
            })
            .to_string(),
        }
    }

    #[test]
    fn reconcile_usage_success_aggregates_token_counts_and_sets_auth_headers() {
        let canned = usage_page_single(1000, 500, 200, 100);
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured.clone());

        let broker =
            AnthropicBroker::with_base_url(SecretString::from("admin-tok".to_string()), base);
        let usage =
            block_on(broker.reconcile_usage("apikey_abc", fixed_period())).expect("reconcile ok");

        handle.join().expect("server thread");
        let req = captured.lock().expect("captured").clone().expect("req");

        assert_eq!(req.method, "GET");
        assert!(
            req.path
                .starts_with("/v1/organizations/usage_report/messages"),
            "path={}",
            req.path
        );
        assert!(
            req.path.contains("api_key_id=apikey_abc"),
            "missing api_key_id param in path={}",
            req.path
        );
        assert_eq!(req.api_key.as_deref(), Some("admin-tok"));
        assert_eq!(req.anthropic_version.as_deref(), Some("2023-06-01"));

        assert_eq!(usage.input_tokens, 1000);
        assert_eq!(usage.output_tokens, 500);
        assert_eq!(usage.cache_read_input_tokens, 200);
        assert_eq!(usage.cache_creation_input_tokens, 100);
    }

    #[test]
    fn reconcile_usage_preserves_period_start_and_end() {
        let canned = usage_page_single(0, 0, 0, 0);
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured);

        let broker = AnthropicBroker::with_base_url(SecretString::from("tok".to_string()), base);
        let period = fixed_period();
        let usage = block_on(broker.reconcile_usage("apikey_xyz", period)).expect("ok");
        handle.join().expect("server");

        assert_eq!(usage.period_start, period.start);
        assert_eq!(usage.period_end, period.end);
    }

    #[test]
    fn reconcile_usage_cost_estimate_is_nonzero_for_real_tokens() {
        // 1M input + 1M output at reference pricing should produce a
        // non-zero cost estimate.
        let canned = usage_page_single(1_000_000, 1_000_000, 0, 0);
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured);

        let broker = AnthropicBroker::with_base_url(SecretString::from("tok".to_string()), base);
        let usage = block_on(broker.reconcile_usage("apikey_cost", fixed_period())).expect("ok");
        handle.join().expect("server");

        // 1M input @ $3/M = $3, 1M output @ $15/M = $15 → $18 → 1800 cents.
        assert_eq!(usage.cost_cents_estimate, 1800);
    }

    #[test]
    fn reconcile_usage_zero_tokens_gives_zero_cost() {
        let canned = usage_page_single(0, 0, 0, 0);
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured);

        let broker = AnthropicBroker::with_base_url(SecretString::from("tok".to_string()), base);
        let usage = block_on(broker.reconcile_usage("apikey_zero", fixed_period())).expect("ok");
        handle.join().expect("server");

        assert_eq!(usage.cost_cents_estimate, 0);
        assert_eq!(usage.input_tokens, 0);
        assert_eq!(usage.output_tokens, 0);
    }

    #[test]
    fn reconcile_usage_4xx_maps_to_upstream_error() {
        let canned = CannedResponse {
            status: 403,
            body: json!({"type": "error", "error": {"message": "forbidden"}}).to_string(),
        };
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured);

        let broker = AnthropicBroker::with_base_url(SecretString::from("tok".to_string()), base);
        let err =
            block_on(broker.reconcile_usage("apikey_err", fixed_period())).expect_err("must fail");
        handle.join().expect("server");

        match err {
            BrokerError::Upstream(msg) => {
                assert!(msg.contains("403"), "expected status in msg: {msg}");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[test]
    fn reconcile_usage_empty_materialization_id_is_invalid_scope() {
        let broker = AnthropicBroker::new(SecretString::from("tok".to_string()));
        let err = block_on(broker.reconcile_usage("", fixed_period())).expect_err("must fail");
        assert!(
            matches!(err, BrokerError::InvalidScope(_)),
            "expected InvalidScope, got {err:?}"
        );
    }

    #[test]
    fn reconcile_usage_missing_optional_token_fields_default_to_zero() {
        // Response with only input_tokens — cache fields absent.
        let canned = CannedResponse {
            status: 200,
            body: json!({
                "results": [{"input_tokens": 42, "output_tokens": 7}],
                "has_more": false,
            })
            .to_string(),
        };
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let (base, handle) = spawn_one_shot(canned, captured);

        let broker = AnthropicBroker::with_base_url(SecretString::from("tok".to_string()), base);
        let usage = block_on(broker.reconcile_usage("apikey_partial", fixed_period())).expect("ok");
        handle.join().expect("server");

        assert_eq!(usage.input_tokens, 42);
        assert_eq!(usage.output_tokens, 7);
        assert_eq!(usage.cache_read_input_tokens, 0);
        assert_eq!(usage.cache_creation_input_tokens, 0);
    }
}
