//! CLASSIFICATION: PUBLIC
//!
//! Generic LLM/HTTP credential-injection forwarding core.
//!
//! Extracted verbatim out of `ember-daemon/src/infra/proxy.rs` (P22-S2) so a
//! future separate `ember-proxy` process can link the forwarding pipeline
//! WITHOUT pulling emberd's vault/MEK. Every policy/credential/metering
//! decision routes through the `core_proxy_forward::PolicyBackend` trait, so
//! the code here touches zero daemon types (`DaemonStore`, `Vault`,
//! `DaemonPolicyBackend`, `DaemonEventSink`, `ProxyState`). The daemon's
//! in-process LLM proxy keeps behaving identically by depending on this crate
//! and importing the moved items.
//!
//! The git-echo lane, `DaemonPolicyBackend`/`DaemonEventSink`, the
//! post-flight-meter helpers that touch the store, and the `run_proxy`
//! bind/annotate wrapper all STAY in `ember-daemon`; the generic accept-loop
//! body lives here as `run_forward_accept_loop`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::LengthLimitError;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Frame, SizeHint};
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::Sleep;
use zeroize::Zeroizing;

#[cfg(any(test, feature = "test-support"))]
use core_proxy_forward::r#match::{MethodTier, github_target_matches, method_tier, wildcard_match};
use core_proxy_forward::r#match::{
    effective_scope_uri, extract_github_branch, extract_host_from_url, glob_match_branch,
    host_matches_domain, is_git_smart_http_path, request_to_action_resource,
};
use core_proxy_forward::{
    PolicyBackend, ProxyCallReceiptRequest, ResolvedGrant, ThresholdAxis, ThresholdBand,
};
use hyper::http;

use crate::pricing;

/// Error returned by the generic forwarding pipeline (`handle_request`,
/// `run_forward_accept_loop`).
///
/// Mirrors the variant set the daemon's `ProxyError` exposes for the
/// forwarding path — `handle_request` only ever constructs `PolicyBackend`,
/// `Http`, `Client`, and (via `From<std::io::Error>` on the accept loop) `Io`.
/// The daemon keeps its own richer `ProxyError` (which carries `Store` /
/// `Vault` variants for the git-echo lane) and adapts this via
/// `From<ForwardError>`.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("client error: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),
    #[error("http error: {0}")]
    Http(#[from] hyper::http::Error),
    #[error("policy backend error: {0}")]
    PolicyBackend(core_proxy_forward::PolicyError),
}

/// Pure header parser for the attachment-endpoint headers.
///
/// Moved out of `ember-daemon`'s `infra::attachment` (which keeps its own
/// `pub(crate)` copy for the socket lane) so the forwarding core severs its
/// last daemon-module reference. Behaviour is identical: returns
/// `Some((attachment_id, endpoint_token))` only when both `X-Ember-Attachment-Id`
/// and `X-Ember-Endpoint-Token` are present and non-empty.
fn attachment_endpoint_from_headers(headers: &hyper::HeaderMap) -> Option<(&str, &str)> {
    let attachment_id = headers
        .get("x-ember-attachment-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())?;
    let endpoint_token = headers
        .get("x-ember-endpoint-token")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())?;
    Some((attachment_id, endpoint_token))
}

/// Transport abstraction the forwarding accept loop drives.
///
/// P22-S2 (ADR 197 §1) — the LLM gateway moves from a loopback `TcpListener`
/// (no peer identity, port-squattable) to a per-session peercred-gated `0700`
/// Unix socket. This trait is the seam that lets `proxy-forward-runtime` stay
/// free of daemon types (`PeerCredPrincipal`, `DaemonStore`, the binary-pin
/// manifest): the daemon implements `ProxyAcceptor` for its `UnixListener`
/// wrapper and performs the **full fail-closed gate** — `SO_PEERCRED` uid
/// match + reuse-immune liveness + binary attestation + launcher pid-tree
/// instance-binding — inside `accept_authorized`, returning only an
/// already-authorized connection. A rejected connection surfaces as
/// `Ok(None)` so the loop drops it and keeps serving without tearing down.
///
/// `?Send` because the daemon's UDS acceptor touches the `!Send` `DaemonStore`
/// / vault (manifest load) at accept time, on the same single-threaded
/// `LocalSet` the loop runs on.
/// An accepted, authorized connection plus the transport's binding context.
///
/// P22-S2 (ADR 197 §2): a per-session peercred-gated UDS acceptor knows *which*
/// session the socket belongs to once the accept-time gate passes, so it can
/// carry that `session_binding` into forwarding — `handle_request` then
/// resolves the credential identity from the socket's session (no caller-
/// supplied bearer). The transitional `TcpListener` lane has no kernel peer
/// identity, so its binding is `None` and resolution falls back to the
/// attachment-endpoint headers exactly as before.
pub struct AuthorizedConnection<C> {
    /// The ready-to-serve stream (`TcpStream` / `UnixStream`).
    pub conn: C,
    /// `Some(session_id)` when the connection was authorized on a per-session
    /// socket bound to that session; `None` for the header-authenticated TCP
    /// lane.
    pub session_binding: Option<String>,
}

#[async_trait::async_trait(?Send)]
pub trait ProxyAcceptor: 'static {
    /// The accepted, authorized connection stream (`TcpStream` /
    /// `UnixStream`). Must satisfy the hyper `serve_connection` IO bounds.
    type Conn: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static;

    /// Accept the next connection and run the transport's authorization
    /// gate. `Ok(Some(authorized))` is an authorized, ready-to-serve
    /// connection (carrying its optional session binding); `Ok(None)` is a
    /// connection the gate rejected (closed by dropping the stream) — the loop
    /// continues; `Err` is a fatal accept error logged by the loop.
    async fn accept_authorized(&self) -> std::io::Result<Option<AuthorizedConnection<Self::Conn>>>;
}

/// Transitional blanket impl for the loopback `TcpListener` path. Carries NO
/// peer gate and NO session binding — TCP loopback exposes no kernel peer
/// identity, so this matches the pre-P22-S2 behaviour exactly (resolution via
/// attachment-endpoint headers). Retained behind the daemon's transitional
/// flag for non-Claude/Codex Anthropic clients during cutover; removed once
/// every consumer reaches the per-session UDS.
#[async_trait::async_trait(?Send)]
impl ProxyAcceptor for TcpListener {
    type Conn = tokio::net::TcpStream;

    async fn accept_authorized(&self) -> std::io::Result<Option<AuthorizedConnection<Self::Conn>>> {
        let (stream, _addr) = self.accept().await?;
        Ok(Some(AuthorizedConnection {
            conn: stream,
            session_binding: None,
        }))
    }
}

/// Generic accept loop for the forwarding proxy.
///
/// Extracted from `ember-daemon`'s `run_proxy`: the `LocalSet` +
/// `select!` accept loop that dispatches each connection to
/// `handle_request`. The daemon keeps a thin `run_proxy` wrapper that binds
/// the listener (with its bind-error annotation), constructs the
/// `DaemonPolicyBackend`, and then drives this loop.
///
/// P22-S2 — generalized over `ProxyAcceptor` so the same loop drives both the
/// transitional `TcpListener` (blanket impl above) and the daemon's
/// peercred-gated per-session `UnixListener` acceptor. The per-connection
/// authorization runs inside `accept_authorized`; the loop body
/// (`serve_connection` dispatching `handle_request`) is otherwise unchanged.
///
/// Runs on a single-threaded `LocalSet` so a `!Send` backend (the daemon's
/// `DaemonPolicyBackend`, which wraps the `!Send` SQLite store) never crosses
/// a thread boundary.
pub async fn run_forward_accept_loop<A, B>(
    acceptor: A,
    backend: Arc<B>,
    mut shutdown: watch::Receiver<bool>,
) where
    A: ProxyAcceptor,
    B: PolicyBackend,
{
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            loop {
                tokio::select! {
                    accept = acceptor.accept_authorized() => {
                        match accept {
                            Ok(Some(authorized)) => {
                                let backend = Arc::clone(&backend);
                                let session_binding = authorized.session_binding;
                                let io = TokioIo::new(authorized.conn);
                                tokio::task::spawn_local(async move {
                                    let svc = hyper::service::service_fn(move |req| {
                                        let backend = Arc::clone(&backend);
                                        let session_binding = session_binding.clone();
                                        async move { handle_request(backend, req, session_binding).await }
                                    });
                                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                                        .serve_connection(io, svc)
                                        .await
                                    {
                                        tracing::warn!(error = %e, "proxy connection error");
                                    }
                                });
                            }
                            Ok(None) => {
                                // Connection rejected by the acceptor's
                                // fail-closed gate (peercred / attestation /
                                // instance-binding). Already closed by the
                                // impl dropping the stream; keep serving.
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "proxy accept error");
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        })
        .await;
}

/// Per-session accept loop for the codex loopback-TCP responses lane
/// (P22-S2 / ADR 197 codex).
///
/// Mirrors [`run_forward_accept_loop`] but dispatches every connection to
/// [`handle_codex_responses_request`] with the acceptor's bound `session_id`,
/// rather than to the header-driven [`handle_request`]. The session id is the
/// trusted binding the daemon's codex registry sets at `register_session`; the
/// handler resolves persona / grant / credential entirely server-side from it,
/// because codex sends no `X-Ember-*` headers (it only POSTs a JSON body to
/// `base_url/responses`).
///
/// This lane carries NO peer-attestation gate: a non-root daemon cannot read a
/// loopback-TCP peer's kernel identity (`proc_pidfdinfo` is `CHECK_SAME_USER`
/// gated, and macOS exposes no TCP audit token). The lane is credential-safe
/// BY CONSTRUCTION — strict endpoint, header strip, server-side credential
/// injection, server-side upstream pin — not by gate arms. See the module
/// docs in `ember-daemon/src/infra/codex_proxy.rs` and ADR 197.
pub async fn run_loopback_projector_accept_loop<B>(
    listener: TcpListener,
    session_id: String,
    projector: &'static LoopbackProjector,
    backend: Arc<B>,
    mut shutdown: watch::Receiver<bool>,
) where
    B: PolicyBackend,
{
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, _addr)) => {
                                let backend = Arc::clone(&backend);
                                let session_id = session_id.clone();
                                let io = TokioIo::new(stream);
                                tokio::task::spawn_local(async move {
                                    let svc = hyper::service::service_fn(move |req| {
                                        let backend = Arc::clone(&backend);
                                        let session_id = session_id.clone();
                                        async move {
                                            handle_loopback_projector_request(
                                                projector, backend, req, session_id,
                                            )
                                            .await
                                        }
                                    });
                                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                                        .serve_connection(io, svc)
                                        .await
                                    {
                                        tracing::warn!(lane = projector.name, error = %e, "loopback projector connection error");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!(lane = projector.name, error = %e, "loopback projector accept error");
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        })
        .await;
}

/// Thin codex-specific wrapper over [`run_loopback_projector_accept_loop`],
/// preserving the original call site (`crates/ember-daemon/src/infra/codex_proxy.rs`)
/// and the loopback integration test. Dispatches with [`CODEX_PROJECTOR`].
pub async fn run_codex_forward_accept_loop<B>(
    listener: TcpListener,
    session_id: String,
    backend: Arc<B>,
    shutdown: watch::Receiver<bool>,
) where
    B: PolicyBackend,
{
    run_loopback_projector_accept_loop(listener, session_id, &CODEX_PROJECTOR, backend, shutdown)
        .await;
}

/// The single upstream the codex responses lane is permitted to forward to.
/// Pinned SERVER-SIDE: codex never supplies a target, so there is no
/// client-controlled upstream to forge (INV-4 in the plan). Exact host
/// equality — no subdomain match, no redirect.
///
/// **P22-S2 GPT-plan rework:** this is the ChatGPT *plan/subscription* backend
/// (`AuthMode::Chatgpt` in codex), NOT the API/SDK `api.openai.com` lane (that
/// is a separate, out-of-scope effort). codex natively talks to this exact
/// host and path when signed in with a ChatGPT subscription; we keep the real
/// codex binary in the loop and inject the broker-held OAuth credential so the
/// request is wire-indistinguishable from ordinary first-party codex usage.
pub const CODEX_UPSTREAM_HOST: &str = "chatgpt.com";
/// Full upstream URL the codex responses lane forwards to. Mirrors codex's
/// `CHATGPT_CODEX_BASE_URL` (`https://chatgpt.com/backend-api/codex`) +
/// `/responses` endpoint (codex-rs `model-provider-info/src/lib.rs`,
/// `core/src/client.rs`).
pub const CODEX_UPSTREAM_URL: &str = "https://chatgpt.com/backend-api/codex/responses";

/// `originator` header value codex emits on every request
/// (`DEFAULT_ORIGINATOR`, codex-rs `login/src/auth/default_client.rs`). codex
/// sends this natively, but the request-header pass-through could drop it, so
/// the proxy guarantees it on the GPT-plan inject path — the ChatGPT backend
/// uses it to recognise first-party codex traffic.
pub const CHATGPT_ORIGINATOR: &str = "codex_cli_rs";

/// Header carrying the ChatGPT workspace/account id
/// (codex-rs `model-provider/src/bearer_auth_provider.rs`). HTTP header names
/// are case-insensitive; this is the canonical casing codex uses.
pub const CHATGPT_ACCOUNT_ID_HEADER: &str = "chatgpt-account-id";

/// Operator-only env override for the pinned codex upstream URL.
///
/// VERSION-RESILIENCE (operator, 2026-05-31): the ChatGPT backend path is
/// server-controlled by OpenAI and stable across codex versions, but if it ever
/// moves, an operator can repin without a rebuild. Operator-controlled
/// (daemon-process env), NOT session/model controllable, so it does not weaken
/// the server-side upstream pin. Mirrors codex's own `chatgpt_base_url`
/// overridability.
pub const CODEX_UPSTREAM_URL_OVERRIDE_ENV: &str = "EMBER_CODEX_UPSTREAM_URL";

/// The pinned codex upstream URL, honouring [`CODEX_UPSTREAM_URL_OVERRIDE_ENV`].
pub fn codex_upstream_url() -> std::borrow::Cow<'static, str> {
    match std::env::var(CODEX_UPSTREAM_URL_OVERRIDE_ENV) {
        Ok(v) if !v.trim().is_empty() => std::borrow::Cow::Owned(v),
        _ => std::borrow::Cow::Borrowed(CODEX_UPSTREAM_URL),
    }
}

/// The host of the pinned codex upstream (derived from [`codex_upstream_url`]),
/// used to reconstruct the outbound `Host` header. Falls back to the compiled
/// default host if the override URL can't be parsed.
pub fn codex_upstream_host() -> String {
    let url = codex_upstream_url();
    url.parse::<http::Uri>()
        .ok()
        .and_then(|u| u.host().map(|h| h.to_string()))
        .unwrap_or_else(|| CODEX_UPSTREAM_HOST.to_string())
}

// ============================================================================
// ADR 215 §2 — the loopback-projector model.
//
// codex (today) and gemini (next slice) are *session-id-bound loopback-TCP*
// lanes: a third-party CLI is redirected to a per-session loopback port and the
// daemon injects the credential server-side, so the client process holds no
// secret (structural credential absence). ADR 215 §93/§100 keep this transport
// DISTINCT from the host peer-cred-UDS LLM lane (`handle_request`) — do not fold
// them: peer-cred is a kernel fact for the host case, loopback-TCP is the
// permanent fallback for cross-uid macOS sockets.
//
// Everything these lanes share is the engine below
// (`handle_loopback_projector_request`); everything that differs is data on a
// `LoopbackProjector`, mirroring the table-driven `HarnessSpec` registry (#6213).
// Adding a loopback lane = add one `const PROJECTOR` (+ one `CredentialInjection`
// variant if it needs a new credential strategy).
// ============================================================================

/// Per-lane strict-gate predicate: which `(method, uri)` pairs this lane admits
/// at all. Everything else fails closed with 403.
pub type LoopbackAccepts = fn(&hyper::Method, &http::Uri) -> bool;

/// Per-lane upstream resolver: maps the inbound request URI to the
/// `(full_upstream_url, upstream_host)` to forward to. codex ignores the inbound
/// URI (single pinned endpoint); a path-routed lane derives the upstream path
/// from it.
pub type LoopbackUpstream = fn(&http::Uri) -> (String, String);

/// Per-lane outbound-header builder (pass-through / allowlist). Same shape as
/// [`passthrough_codex_request_headers`] / [`filter_request_headers`].
pub type LoopbackPrepareHeaders =
    fn(hyper::http::request::Builder, &hyper::HeaderMap) -> hyper::http::request::Builder;

/// How a [`LoopbackProjector`] acquires and injects its per-session credential.
///
/// The loopback family shares one forward engine; only the credential strategy
/// differs. Today the sole strategy is codex's ChatGPT subscription-plan OAuth.
/// The gemini GATEWAY slice adds an `ApiKeyHeader(&'static str)` variant that
/// resolves a brokered API key and injects it under a named header
/// (e.g. `x-goog-api-key`) — additive, no change to this engine.
pub enum CredentialInjection {
    /// codex: resolve the structured ChatGPT plan auth (Bearer access token +
    /// account id, refreshed daemon-side) via
    /// [`core_proxy_forward::PolicyBackend::resolve_chatgpt_plan_auth`] and
    /// inject it with [`inject_chatgpt_plan_auth`].
    ChatgptPlan,
    /// gemini GATEWAY: resolve a single opaque brokered API key via
    /// [`core_proxy_forward::PolicyBackend::get_credential`] and inject
    /// it under the named request header with [`inject_api_key_header`]. The
    /// tuple holds the header name (a lowercase `&'static str` safe for
    /// [`hyper::header::HeaderName::from_static`], e.g. `"x-goog-api-key"`). The
    /// gemini-cli GATEWAY client emits an empty `x-goog-api-key: ''` and holds
    /// no key itself; the daemon fills it server-side (structural credential
    /// absence).
    ApiKeyHeader(&'static str),
    /// gemini Code Assist ("Sign in with Google"): resolve a short-window OAuth
    /// Bearer access token (refreshed daemon-side from the vault-held
    /// `oauth_creds` blob) via
    /// [`core_proxy_forward::PolicyBackend::resolve_oauth_bearer`] and inject it
    /// as `Authorization: Bearer <token>` with [`inject_oauth_bearer`]. The
    /// gemini-cli signs Code Assist requests client-side with google-auth-library,
    /// so the projector STRIPS whatever it signed and replaces it with the
    /// broker token — the durable `refresh_token` stays daemon-only (the same
    /// strip-and-inject shape as codex's [`ChatgptPlan`], not a bearer-less
    /// client mode).
    OAuthBearer,
}

/// A session-bound loopback projector: a third-party CLI redirected to a
/// per-session loopback-TCP port, with the daemon injecting the credential
/// server-side. Everything NOT on this struct is the shared engine
/// ([`handle_loopback_projector_request`]).
pub struct LoopbackProjector {
    /// Stable lane label for logs / audit (`credential.access` detail, the
    /// `tracing` `lane` field). e.g. `"codex"`.
    pub name: &'static str,
    /// Strict gate — the only `(method, uri)` pairs this lane admits.
    pub accepts: LoopbackAccepts,
    /// `<provider>/` prefix the session credential MUST carry (defence-in-depth
    /// against shipping a non-matching secret upstream). e.g. `"openai/"`.
    pub provider_prefix: &'static str,
    /// Resolve the pinned upstream `(full_url, host)` from the request URI.
    pub upstream: LoopbackUpstream,
    /// Whether a spend *budget* can be ENFORCED on this lane's streaming
    /// responses. Usage is always metered post-flight (recorded after each
    /// request); this flag is narrower — it asks whether spend can be capped
    /// *during* a stream. When `false`, a grant carrying a budget fails closed
    /// before any credential is resolved, because the lane streams and
    /// post-flight metering learns the spend too late to stop an overrun
    /// (codex: SSE from chatgpt.com, no in-stream enforcement yet). Un-budgeted
    /// grants are unaffected and still metered.
    pub streaming_budget_enforceable: bool,
    /// Credential acquisition + injection strategy.
    pub injection: CredentialInjection,
    /// Build the outbound request headers (pass-through / allowlist) before the
    /// credential is injected.
    pub prepare_headers: LoopbackPrepareHeaders,
    /// `credential.access` audit-log detail for this lane. e.g. `"codex-responses"`.
    pub access_detail: &'static str,
}

/// Per-request resolved credential material: produced by the acquisition step
/// and consumed by the injection step of [`handle_loopback_projector_request`].
/// One variant per [`CredentialInjection`] strategy.
enum ResolvedInjection {
    ChatgptPlan(core_proxy_forward::ChatgptPlanAuth),
    /// gemini GATEWAY: the brokered API key + the header it injects under.
    /// `value` is `Zeroizing` so the secret is wiped on drop.
    ApiKeyHeader {
        header_name: &'static str,
        value: zeroize::Zeroizing<String>,
    },
    /// gemini Code Assist: the broker-resolved OAuth Bearer access token,
    /// injected as `Authorization: Bearer <value>`. `Zeroizing` so the secret
    /// is wiped on drop.
    OAuthBearer { value: zeroize::Zeroizing<String> },
}

/// Strict gate for the codex responses lane: only `POST /v1/responses` with no
/// query string (mirrors codex-responses-api-proxy). Case-sensitive path.
fn codex_accepts(method: &hyper::Method, uri: &http::Uri) -> bool {
    method == hyper::Method::POST && uri.path() == "/v1/responses" && uri.query().is_none()
}

/// Upstream resolver for codex: the single pinned ChatGPT backend, ignoring the
/// inbound request URI (codex never supplies a target).
fn codex_upstream_for(_uri: &http::Uri) -> (String, String) {
    (codex_upstream_url().into_owned(), codex_upstream_host())
}

/// The codex GPT-plan loopback projector (ADR 215 §2; transport remains the
/// documented loopback-TCP exception per §100).
pub const CODEX_PROJECTOR: LoopbackProjector = LoopbackProjector {
    name: "codex",
    accepts: codex_accepts,
    provider_prefix: "openai/",
    upstream: codex_upstream_for,
    streaming_budget_enforceable: false,
    injection: CredentialInjection::ChatgptPlan,
    prepare_headers: passthrough_codex_request_headers,
    access_detail: "codex-responses",
};

// Compile-time guard: codex cannot enforce a spend budget on its SSE stream
// (usage is metered post-flight — too late to cap an in-flight stream), so the
// engine fails budgeted grants closed (see `handle_loopback_projector_request`
// step 7). Flipping this to `true` without first wiring in-stream budget
// enforcement would silently let a budgeted stream overrun its cap — so it
// breaks the BUILD, not just a test.
const _: () = assert!(!CODEX_PROJECTOR.streaming_budget_enforceable);

/// The pinned upstream host for the gemini GATEWAY lane (Google's Generative
/// Language API). The lane forwards the client-provided path+query (gemini has
/// many `/v1beta/models/{model}:{method}` endpoints) but pins the HOST
/// server-side — the client never supplies a target host, only a path.
pub const GEMINI_UPSTREAM_HOST: &str = "generativelanguage.googleapis.com";

/// Operator-only env override for the pinned gemini upstream host.
///
/// Mirrors [`CODEX_UPSTREAM_URL_OVERRIDE_ENV`] but is a HOST (not a full URL):
/// the gemini lane builds the URL from this host + the client's path+query, so
/// only the host is operator-repinnable. Operator-controlled (daemon-process
/// env), NOT session/model controllable, so it does not weaken the server-side
/// host pin.
pub const GEMINI_UPSTREAM_HOST_OVERRIDE_ENV: &str = "EMBER_GEMINI_UPSTREAM_HOST";

/// The pinned gemini upstream host, honouring [`GEMINI_UPSTREAM_HOST_OVERRIDE_ENV`].
pub fn gemini_upstream_host() -> String {
    match std::env::var(GEMINI_UPSTREAM_HOST_OVERRIDE_ENV) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => GEMINI_UPSTREAM_HOST.to_string(),
    }
}

/// Strict gate for the gemini GATEWAY lane: only `POST` to a
/// `/v1beta/models/{model}:{method}` generate/embed/count endpoint.
///
/// Unlike codex (which pins a single URL and forbids queries), gemini has many
/// model+method paths and its streaming method carries a `?alt=sse` query, so
/// this gate ALLOWS a query string. Defence-in-depth: a legitimate loopback
/// request is origin-form (path + optional query only); we reject any inbound
/// URI carrying a scheme or authority so a client cannot smuggle a host change
/// that could survive upstream construction. (Belt-and-braces — the upstream
/// resolver forwards only `path_and_query()`, which structurally drops any
/// authority, and the Host header is reconstructed server-side.)
fn gemini_accepts(method: &hyper::Method, uri: &http::Uri) -> bool {
    if method != hyper::Method::POST {
        return false;
    }
    // Origin-form only: no scheme, no authority. A network-path reference like
    // `//evil.example/v1beta/...` parses `evil.example` as the authority; reject
    // it here rather than rely solely on `path_and_query()` dropping it.
    if uri.scheme().is_some() || uri.authority().is_some() {
        return false;
    }
    let path = uri.path();
    // Reject empty segments (`//`), dot-segments (`.`/`..`), and ANY
    // percent-encoding (`%`): keep the client on the intended
    // `/v1beta/models/{model}:{method}` endpoints rather than letting a literal
    // OR percent-encoded traversal (`%2e%2e`, `%2f`, `%5c`) normalise elsewhere
    // on the pinned host once the upstream server decodes it. `gemini_accepts`
    // matches the RAW, un-decoded `uri.path()`, so a `%2e%2e` segment would slip
    // a bare `seg == ".."` check; rejecting `%` outright closes the whole
    // encoded-traversal / encoded-separator class in one cut. The
    // `@google/genai` SDK only ever builds clean ASCII-slug paths (no `%`, no
    // dot-segments — the `:method` colon is literal), so this never rejects
    // legitimate gemini traffic.
    if path.contains("//")
        || path.contains('%')
        || path.split('/').any(|seg| seg == ".." || seg == ".")
    {
        return false;
    }
    path.starts_with("/v1beta/models/")
        && (path.ends_with(":generateContent")
            || path.ends_with(":streamGenerateContent")
            || path.ends_with(":countTokens")
            || path.ends_with(":embedContent"))
}

/// Upstream resolver for gemini: pin the host server-side ([`gemini_upstream_host`])
/// and forward the client-provided path+query verbatim. `path_and_query()` from
/// a parsed request carries no authority, so the host cannot be forged through
/// the path; the gate above additionally rejects any authority-bearing URI.
fn gemini_upstream_for(uri: &http::Uri) -> (String, String) {
    let host = gemini_upstream_host();
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    (format!("https://{host}{path_and_query}"), host)
}

/// The gemini GATEWAY loopback projector. Transport remains the documented
/// loopback-TCP exception shared with codex. Brokers a
/// `google/gemini-api-key` and injects it as `x-goog-api-key` server-side.
pub const GEMINI_PROJECTOR: LoopbackProjector = LoopbackProjector {
    name: "gemini",
    accepts: gemini_accepts,
    provider_prefix: "google/",
    upstream: gemini_upstream_for,
    streaming_budget_enforceable: false,
    injection: CredentialInjection::ApiKeyHeader("x-goog-api-key"),
    prepare_headers: passthrough_gemini_request_headers,
    access_detail: "gemini-generate",
};

// Compile-time guard: gemini `:streamGenerateContent?alt=sse` streams SSE the
// same way codex does — usage is metered post-flight, too late to cap an
// in-flight stream — so budgeted grants fail closed (see the streaming-budget
// gate in `handle_loopback_projector_request`). Flipping this to `true` without
// first wiring in-stream budget enforcement (tracked:
// ADR215-LOOPBACK-STREAMING-BUDGET-ENFORCE) would silently let a budgeted
// stream overrun — so it breaks the BUILD, not just a test.
const _: () = assert!(!GEMINI_PROJECTOR.streaming_budget_enforceable);

/// The pinned upstream host for the gemini Code Assist ("Sign in with Google")
/// lane — Google's Cloud Code / Code Assist API. The free "Login with Google"
/// tier is served here (NOT the API-key `generativelanguage.googleapis.com`
/// host the GATEWAY lane uses).
pub const GEMINI_CODE_ASSIST_HOST: &str = "cloudcode-pa.googleapis.com";

/// Operator-only env override for the pinned Code Assist upstream host. Mirrors
/// [`GEMINI_UPSTREAM_HOST_OVERRIDE_ENV`]; daemon-process env, not
/// session/model-controllable.
pub const GEMINI_CODE_ASSIST_HOST_OVERRIDE_ENV: &str = "EMBER_GEMINI_CODE_ASSIST_HOST";

/// The pinned Code Assist upstream host, honouring [`GEMINI_CODE_ASSIST_HOST_OVERRIDE_ENV`].
pub fn gemini_code_assist_host() -> String {
    match std::env::var(GEMINI_CODE_ASSIST_HOST_OVERRIDE_ENV) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => GEMINI_CODE_ASSIST_HOST.to_string(),
    }
}

/// Strict gate for the gemini Code Assist lane: `GET`/`POST` to the
/// `v1internal` custom-verb endpoints the gemini-cli `CodeAssistServer` calls
/// (`{base}/v1internal:<method>`, e.g. `:generateContent`,
/// `:streamGenerateContent`, `:loadCodeAssist`, `:onboardUser`, `:countTokens`)
/// or a GET long-running-operation poll
/// (`{base}/v1internal/operations/<name>`).
///
/// Unlike the GATEWAY lane this admits BOTH methods (the CLI does GET reads +
/// POST writes) and is version-resilient on the `:<method>` token (gemini-cli
/// adds Code Assist methods across releases). It does NOT enumerate the method
/// names: the OAuth Bearer's audience is the entire Code Assist API on the
/// pinned host, so any `v1internal` method is within that single audience —
/// the security boundary is the host pin + the `/v1internal` prefix + the
/// Bearer audience, not a per-method allowlist (same reasoning as the GATEWAY
/// host pin). Defence-in-depth: origin-form only (no scheme/authority), and no
/// `//` / `.` / `..` / percent-encoded traversal.
///
/// SCOPE BREADTH (adversarial M2 — accepted): admitting any `:<method>` means a
/// grant scoped to `llm:generate google/*` authorizes the WHOLE Code Assist API
/// surface on the pinned host — generation, the `loadCodeAssist`/`onboardUser`
/// handshake, AND settings-style methods (e.g. `:setCodeAssistGlobalUserSetting`).
/// The verb (`llm:generate`) does not distinguish generate-from-administer on
/// this lane. This is same-host / same-OAuth-audience reachability (no
/// cross-tenant or cross-host escalation; the Bearer can only do what that one
/// Google account is entitled to), chosen for version-resilience (gemini-cli
/// adds Code Assist methods across releases). If finer scoping is wanted later,
/// the matched resource slug already carries the method name
/// (`google/v1internal:<method>`), so a tighter statement glob
/// (e.g. `google/v1internal:*GenerateContent`) can clamp it WITHOUT changing
/// this gate.
fn gemini_code_assist_accepts(method: &hyper::Method, uri: &http::Uri) -> bool {
    if method != hyper::Method::GET && method != hyper::Method::POST {
        return false;
    }
    if uri.scheme().is_some() || uri.authority().is_some() {
        return false;
    }
    let path = uri.path();
    if path.contains("//")
        || path.contains('%')
        || path.split('/').any(|seg| seg == ".." || seg == ".")
    {
        return false;
    }
    // Custom-verb form `/v1internal:<method>` — a single colon-method token
    // with no further path segments.
    if let Some(rest) = path.strip_prefix("/v1internal:") {
        return !rest.is_empty() && !rest.contains('/');
    }
    // Long-running-operation poll `/v1internal/operations/<name>` — GET only,
    // with a bare
    // operation name only: no `/` sub-path and no `:` sub-verb. The CLI only
    // GETs the operation to poll it; a colon sub-verb (e.g. `operations/x:cancel`)
    // is a mutation we do not admit (adversarial M1), mirroring the single-token
    // discipline of the `:<method>` branch above.
    if let Some(op) = path.strip_prefix("/v1internal/operations/") {
        return method == hyper::Method::GET
            && !op.is_empty()
            && !op.contains('/')
            && !op.contains(':');
    }
    false
}

/// Upstream resolver for the gemini Code Assist lane: pin the host server-side
/// ([`gemini_code_assist_host`]) and forward the client path+query verbatim
/// (`path_and_query()` carries no authority; the gate rejects authority-bearing
/// URIs).
fn gemini_code_assist_upstream_for(uri: &http::Uri) -> (String, String) {
    let host = gemini_code_assist_host();
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    (format!("https://{host}{path_and_query}"), host)
}

/// The gemini Code Assist OAuth loopback projector (ADR 215 slice 2). Brokers a
/// `google/`-prefixed OAuth credential (`oauth_creds` blob) and injects a
/// daemon-refreshed `Authorization: Bearer <access_token>` server-side; the
/// gemini-cli's own client-side Bearer is stripped first. Transport remains the
/// documented loopback-TCP exception shared with codex + the GATEWAY lane.
/// Reuses [`passthrough_gemini_request_headers`] — its strip list already drops
/// `authorization` (the CLI's signed Bearer) plus host/accept-encoding/etc.
pub const GEMINI_CODE_ASSIST_PROJECTOR: LoopbackProjector = LoopbackProjector {
    name: "gemini-code-assist",
    accepts: gemini_code_assist_accepts,
    provider_prefix: "google/",
    upstream: gemini_code_assist_upstream_for,
    streaming_budget_enforceable: false,
    injection: CredentialInjection::OAuthBearer,
    prepare_headers: passthrough_gemini_request_headers,
    access_detail: "gemini-code-assist",
};

// Compile-time guard: Code Assist `:streamGenerateContent?alt=sse` streams SSE,
// metered post-flight (too late to cap), so budgeted grants fail closed — same
// rationale + tracking (ADR215-LOOPBACK-STREAMING-BUDGET-ENFORCE) as the codex
// and gemini GATEWAY lanes. Flipping to `true` without in-stream enforcement
// breaks the BUILD.
const _: () = assert!(!GEMINI_CODE_ASSIST_PROJECTOR.streaming_budget_enforceable);

/// Strict, credential-safe handler for a session-bound loopback-TCP projector
/// (ADR 215 §2). [`CODEX_PROJECTOR`] is the first; the engine is shared and the
/// per-lane differences ride on `projector`. Reach it via the thin
/// [`handle_codex_responses_request`] wrapper (or a future lane's wrapper).
///
/// Security contract (mirrors OpenAI's own `codex-responses-api-proxy`):
///  1. STRICT ENDPOINT — only the `(method, uri)` pairs `projector.accepts`
///     admits are reachable; everything else returns 403 (fail-closed). For
///     codex that is exactly `POST /v1/responses` with no query string.
///  2. CLIENT-SUPPLIED AUTH NEVER REACHES UPSTREAM — the injection step strips
///     any `Authorization`/`x-api-key`/account header the caller sent and
///     injects only the broker-resolved credential. The lane's authentic
///     non-auth headers are preserved by `projector.prepare_headers` so the
///     request stays wire-faithful to first-party traffic.
///  3. CREDENTIAL RESOLVED SERVER-SIDE FROM THE SESSION — persona, grant, and
///     credential name come from `backend.resolve_session_authority(session_id)`,
///     never from caller-supplied headers. The credential material itself is
///     acquired server-side per `projector.injection`.
///  4. UPSTREAM PINNED SERVER-SIDE — `projector.upstream` resolves it; the
///     client never supplies a target.
///  5. FAIL-CLOSED — an unknown / closed session, or any resolution failure,
///     denies (403) without synthesizing a credential or forwarding anything.
pub async fn handle_loopback_projector_request<B, ReqB>(
    projector: &'static LoopbackProjector,
    backend: Arc<B>,
    req: Request<ReqB>,
    session_id: String,
) -> Result<Response<ProxyBody>, ForwardError>
where
    B: PolicyBackend,
    ReqB: Body + Send + 'static,
    ReqB::Data: Send,
    ReqB::Error: std::error::Error + Send + Sync + 'static,
{
    // 1. STRICT GATE — only the `(method, uri)` pairs this lane admits. Mirrors
    //    codex-responses-api-proxy lib.rs:170-179 for the codex lane.
    if !(projector.accepts)(req.method(), req.uri()) {
        tracing::warn!(
            lane = projector.name,
            session_id = %session_id,
            method = %req.method(),
            path = %req.uri().path(),
            has_query = req.uri().query().is_some(),
            "loopback projector lane: rejecting a request the strict gate does not admit"
        );
        return Ok(forbidden(&format!(
            "{} lane: request rejected by the strict endpoint gate",
            projector.name
        )));
    }

    // 2. RESOLVE SERVER-SIDE from the session binding (NOT from headers).
    let authority = match backend.resolve_session_authority(&session_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            tracing::warn!(
                lane = projector.name,
                session_id = %session_id,
                "loopback projector lane: no gateway authority for session — failing closed"
            );
            return Ok(forbidden(&format!(
                "{} lane: session has no gateway authority",
                projector.name
            )));
        }
        Err(e) => {
            tracing::warn!(lane = projector.name, error = ?e, session_id = %session_id, "loopback projector lane: session authority resolution failed");
            return Ok(forbidden(&format!(
                "{} lane: session authority unavailable",
                projector.name
            )));
        }
    };

    let persona_id = authority.persona_id.clone();
    let credential_name = authority.credential_name.clone();

    // PROVIDER GATE (adversarial must-fix): this lane pins the upstream and
    // injects the session's resolved credential. `resolve_session_authority`
    // returns whatever credential the session's grant carries — so a session
    // bound to a persona whose grant is NOT under this lane's provider (e.g. a
    // codex session bound to `anthropic/oauth-token` or a GitHub token) would
    // otherwise ship that secret to the pinned upstream. Assert the credential
    // carries the lane's `<provider>/` prefix (the `<provider>/<name>`
    // convention) and FAIL CLOSED otherwise — defence-in-depth on top of the
    // grant-scope check below.
    if !credential_name.starts_with(projector.provider_prefix) {
        tracing::warn!(
            lane = projector.name,
            session_id = %session_id,
            persona_id = %persona_id,
            credential_name = %credential_name,
            provider_prefix = projector.provider_prefix,
            "loopback projector lane: session grant credential is not under the lane's provider — failing closed (refusing to inject a non-matching secret to the pinned upstream)"
        );
        return Ok(forbidden(&format!(
            "{} lane: session credential is not under the expected provider ({})",
            projector.name, projector.provider_prefix
        )));
    }

    // Preserve the client's HTTP method end-to-end. codex + the gemini GATEWAY
    // lane only ever POST, but the gemini Code Assist lane also issues GETs
    // (long-running-operation polls + `getCodeAssistGlobalUserSetting`) during
    // its `loadCodeAssist`/`onboardUser` handshake; hardcoding POST would break
    // those. The strict gate already constrains which methods each lane admits.
    let req_method = req.method().clone();

    // Upstream is pinned server-side; the client never supplies a target.
    let (upstream_url, upstream_host) = (projector.upstream)(req.uri());
    let effective_uri_http: http::Uri = upstream_url
        .parse()
        .unwrap_or_else(|_| http::Uri::default());

    // 3. AUTHORIZE — same boundary as the LLM lane: resolve the grant +
    //    applicable statement for the request's method against the pinned
    //    upstream endpoint.
    let resolved = match backend
        .resolve_grant(
            &persona_id,
            &credential_name,
            Some(authority.grant_id.as_str()),
            &effective_uri_http,
            req_method.as_str(),
        )
        .await
    {
        Ok(r) => r,
        Err(core_proxy_forward::PolicyError::NotFound(msg)) => {
            return Ok(forbidden(&msg));
        }
        Err(core_proxy_forward::PolicyError::Forbidden(msg)) => {
            if msg == "no_applicable_statement" || msg == "unsupported HTTP method" {
                return Ok(no_applicable_statement_response());
            } else if msg == "denied_subtarget_scope" || msg == "unevaluable_condition" {
                // ADR 207 seam 8B — both are scope-tightness denials: the
                // request resolved to a statement whose scope (subtarget glob,
                // or an unevaluable condition clamp) does not cover it.
                return Ok(scope_violation_response());
            }
            return Ok(forbidden(&msg));
        }
        Err(e) => return Err(ForwardError::PolicyBackend(e)),
    };

    // Collect the request body (bounded). Needed for preflight + forwarding.
    let (parts, incoming_body) = req.into_parts();
    let body_bytes_in = match Limited::new(incoming_body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return Ok(payload_too_large("request body exceeds 10 MiB limit"));
        }
        Err(e) => {
            tracing::warn!(lane = projector.name, error = %e, "loopback projector lane: request body collection failed");
            return Ok(internal_error("failed to read request body"));
        }
    };

    // Pre-flight budget check (same as the LLM lane).
    match backend
        .preflight_budget(&resolved, body_bytes_in.as_ref())
        .await
    {
        Ok(core_proxy_forward::PreflightDecision::Allowed) => {}
        Ok(core_proxy_forward::PreflightDecision::Rejected { axis, limit, used }) => {
            tracing::warn!(
                lane = projector.name,
                grant_id = %resolved.grant_id,
                statement_sid = %resolved.statement_sid,
                axis, limit, used,
                "loopback projector lane: budget pre-flight rejection"
            );
            return Ok(budget_exhausted_response(
                &resolved.grant_id,
                &resolved.statement_sid,
                axis,
                limit,
                used,
            ));
        }
        Err(e) => {
            tracing::warn!(lane = projector.name, error = ?e, "loopback projector lane: preflight_budget backend error");
            return Err(ForwardError::PolicyBackend(e));
        }
    }

    // Budgeted grants fail closed on lanes that cannot ENFORCE a spend budget
    // during a stream (codex: usage is metered post-flight, too late to cap an
    // in-flight SSE stream). Un-budgeted grants are unaffected. The audit-event
    // payload below is intentionally codex-specific — codex is today's only such
    // lane; the gemini slice revisits this when it decides its own
    // streaming-budget enforcement.
    if !projector.streaming_budget_enforceable && statement_has_effective_budget(&resolved.statement) {
        tracing::warn!(
            lane = projector.name,
            session_id = %session_id,
            persona_id = %persona_id,
            grant_id = %resolved.grant_id,
            statement_sid = %resolved.statement_sid,
            "loopback projector lane: budgeted streaming is not meterable on this lane — failing closed"
        );
        if let Err(e) = backend
            .log_event(
                &persona_id,
                "proxy.denied_stream_budget",
                Some(&credential_name),
                "openai_streaming_unmetered",
                Some("budgeted codex responses stream blocked until OpenAI streaming metering exists"),
            )
            .await
        {
            tracing::warn!(lane = projector.name, error = ?e, persona_id = %persona_id, "loopback projector lane: log_event failed");
        }
        return Ok(openai_streaming_budget_gate_response());
    }

    // 4. ACQUIRE this lane's credential server-side, per its injection strategy.
    //    The resolved material is consumed by the matching injector below; it
    //    never crosses back to the client.
    let resolved_injection = match projector.injection {
        CredentialInjection::ChatgptPlan => {
            // STRUCTURED ChatGPT plan auth (access token + account id). The
            // daemon refreshes the access token against
            // `auth.openai.com/oauth/token` near expiry and persists the rotated
            // `refresh_token` to vault — that secret never crosses this boundary
            // (the proxy receives only what it injects).
            match backend.resolve_chatgpt_plan_auth(&credential_name).await {
                Ok(a) => ResolvedInjection::ChatgptPlan(a),
                Err(core_proxy_forward::PolicyError::NotFound(_)) => {
                    return Ok(internal_error("credential not found in vault"));
                }
                Err(core_proxy_forward::PolicyError::Forbidden(msg)) => {
                    // Refresh token expired/reused/revoked → operator must
                    // re-auth (`codex login` + re-add the credential). Surface a
                    // clear, recoverable 403 (the client renders the body)
                    // rather than a flat 500.
                    tracing::warn!(lane = projector.name, persona_id = %persona_id, reason = %msg, "loopback projector lane: chatgpt plan auth lapsed — re-auth required");
                    return Ok(forbidden(&format!(
                        "chatgpt plan auth lapsed ({msg}): re-run `codex login` and re-add the credential to the vault"
                    )));
                }
                Err(e) => {
                    tracing::warn!(lane = projector.name, error = ?e, persona_id = %persona_id, "loopback projector lane: chatgpt plan auth resolution failed");
                    return Err(ForwardError::PolicyBackend(e));
                }
            }
        }
        CredentialInjection::ApiKeyHeader(header_name) => {
            // gemini GATEWAY: a single opaque brokered API key, decrypted from
            // vault and returned `Zeroizing`. Injected as a header below; it
            // never crosses back to the client.
            match backend.get_credential(&credential_name).await {
                Ok(value) => ResolvedInjection::ApiKeyHeader { header_name, value },
                Err(core_proxy_forward::PolicyError::NotFound(_)) => {
                    return Ok(internal_error("credential not found in vault"));
                }
                Err(core_proxy_forward::PolicyError::Forbidden(msg)) => {
                    tracing::warn!(lane = projector.name, persona_id = %persona_id, reason = %msg, "loopback projector lane: api-key credential forbidden");
                    return Ok(forbidden(&format!(
                        "{} lane: credential access denied ({msg})",
                        projector.name
                    )));
                }
                Err(e) => {
                    tracing::warn!(lane = projector.name, error = ?e, persona_id = %persona_id, "loopback projector lane: api-key credential resolution failed");
                    return Err(ForwardError::PolicyBackend(e));
                }
            }
        }
        CredentialInjection::OAuthBearer => {
            // gemini Code Assist: a short-window OAuth Bearer access token,
            // refreshed daemon-side from the vault-held `oauth_creds` blob. The
            // `refresh_token` never crosses this boundary (daemon-only). Injected
            // as `Authorization: Bearer` below.
            match backend.resolve_oauth_bearer(&credential_name).await {
                Ok(value) => ResolvedInjection::OAuthBearer { value },
                Err(core_proxy_forward::PolicyError::NotFound(_)) => {
                    return Ok(internal_error("credential not found in vault"));
                }
                Err(core_proxy_forward::PolicyError::Forbidden(msg)) => {
                    // Refresh token expired/reused/revoked → operator must
                    // re-run the gemini "Sign in with Google" flow + re-add the
                    // credential. Recoverable 403, not a flat 500.
                    tracing::warn!(lane = projector.name, persona_id = %persona_id, reason = %msg, "loopback projector lane: oauth bearer lapsed — re-auth required");
                    return Ok(forbidden(&format!(
                        "{} lane: oauth credential lapsed ({msg}): re-run the gemini Sign-in-with-Google flow and re-add the credential to the vault",
                        projector.name
                    )));
                }
                Err(e) => {
                    tracing::warn!(lane = projector.name, error = ?e, persona_id = %persona_id, "loopback projector lane: oauth bearer resolution failed");
                    return Err(ForwardError::PolicyBackend(e));
                }
            }
        }
    };

    if let Err(e) = backend
        .log_event(
            &persona_id,
            "credential.access",
            Some(&credential_name),
            "allowed",
            Some(projector.access_detail),
        )
        .await
    {
        tracing::warn!(lane = projector.name, error = ?e, persona_id = %persona_id, "loopback projector lane: log_event failed");
    }

    // Build the HTTPS client.
    let client = build_guarded_forward_client();

    // 5. PASS-THROUGH + INJECT + PIN. `projector.prepare_headers` decides which
    //    of the client's headers survive (codex PRESERVES its authentic non-auth
    //    headers — `OpenAI-Beta`, `session_id`, `originator`, `x-codex-*`,
    //    attestation — so the upstream sees first-party codex traffic; only auth
    //    + host + hop-by-hop + accept-encoding are stripped). We then inject the
    //    broker auth per the lane's injection strategy; the upstream authority
    //    comes from the server-pinned absolute `upstream_url` (hyper derives the
    //    `Host`/`:authority` from it — we do not set an explicit `Host`).
    let mut outgoing = Request::builder()
        .method(req_method)
        .uri(upstream_url.as_str());
    outgoing = (projector.prepare_headers)(outgoing, &parts.headers);

    let mut outgoing_req = outgoing.body(Full::new(body_bytes_in)).map_err(|e| {
        tracing::warn!(lane = projector.name, error = %e, "loopback projector lane: failed to build outgoing request");
        ForwardError::Http(e)
    })?;

    match resolved_injection {
        ResolvedInjection::ChatgptPlan(plan_auth) => {
            // inject_chatgpt_plan_auth strips any client `authorization`/
            // `x-api-key`/`chatgpt-account-id` and inserts the broker-resolved
            // Bearer + account-id + originator (+ fedramp). Refresh_token never
            // reaches here.
            if inject_chatgpt_plan_auth(outgoing_req.headers_mut(), &plan_auth).is_err() {
                tracing::warn!(lane = projector.name, persona_id = %persona_id, "loopback projector lane: chatgpt plan auth not representable as header values");
                return Ok(internal_error(
                    "credential not representable as a header value",
                ));
            }
        }
        ResolvedInjection::ApiKeyHeader { header_name, value } => {
            // gemini GATEWAY: strip any client-supplied `authorization`/
            // `x-api-key`/`x-goog-api-key` and insert the broker-resolved key
            // under `header_name`. The client emits an empty `x-goog-api-key`;
            // the broker value replaces it.
            if inject_api_key_header(outgoing_req.headers_mut(), header_name, &value).is_err() {
                tracing::warn!(lane = projector.name, persona_id = %persona_id, "loopback projector lane: api key not representable as a header value");
                return Ok(internal_error(
                    "credential not representable as a header value",
                ));
            }
        }
        ResolvedInjection::OAuthBearer { value } => {
            // gemini Code Assist: strip the client's signed `Authorization`
            // (+ `x-api-key`/`x-goog-api-key`) and inject the broker-resolved,
            // daemon-refreshed `Authorization: Bearer <token>`.
            if inject_oauth_bearer(outgoing_req.headers_mut(), &value).is_err() {
                tracing::warn!(lane = projector.name, persona_id = %persona_id, "loopback projector lane: oauth bearer not representable as a header value");
                return Ok(internal_error(
                    "credential not representable as a header value",
                ));
            }
        }
    }

    // Do NOT set an explicit `Host` header. The outgoing request carries the
    // server-pinned absolute `upstream_url`, so hyper derives the authority from
    // it: `Host` for HTTP/1.1, the `:authority` pseudo-header for HTTP/2. The
    // `prepare_headers` step already stripped the client's `Host`, so nothing
    // client-controlled leaks regardless. Inserting an explicit `Host` here is
    // not just redundant — over HTTP/2 it ships a `host` header ALONGSIDE the
    // derived `:authority`, which strict upstream GFEs (verified against
    // `generativelanguage.googleapis.com`, and the same class as
    // `chatgpt.com`) reset with `PROTOCOL_ERROR`. The pinned URI is the single
    // source of the upstream authority. (`upstream_host` is still used below for
    // post-flight metering — provider lookup is by host.)
    let upstream_resp = client.request(outgoing_req).await.map_err(|e| {
        tracing::warn!(lane = projector.name, error = %e, "loopback projector lane: upstream request failed");
        ForwardError::Client(e)
    })?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    // codex `/v1/responses` streams SSE; forward chunk-at-a-time with no
    // per-frame idle watchdog (codex streams are long-lived). Non-streaming
    // responses (errors, short JSON) go through the buffered path.
    if is_streaming_upstream(&resp_headers) {
        let Some(streaming_slot) = StreamingSlot::try_acquire() else {
            tracing::warn!(
                lane = projector.name,
                inflight = STREAMING_REQUESTS_INFLIGHT.load(Ordering::Acquire),
                cap = MAX_CONCURRENT_STREAMING,
                "loopback projector lane: streaming concurrency cap reached — rejecting"
            );
            return Ok(service_unavailable(
                "streaming concurrency cap reached; retry shortly",
            ));
        };
        let meter_backend = Arc::clone(&backend);
        let meter_resolved = resolved.clone();
        let meter_host = upstream_host.clone();
        let meter_cb = TeeMeterCallback::new(
            move |summary: pricing::UsageSummary, _outcome: StreamOutcome| {
                let usage = usage_from_summary(&meter_host, &summary);
                let backend = Arc::clone(&meter_backend);
                let resolved = meter_resolved.clone();
                tokio::task::spawn_local(async move {
                    if let Err(e) = backend.post_flight(&resolved, usage).await {
                        tracing::warn!(lane = projector.name, error = ?e, grant_id = %resolved.grant_id, "loopback projector lane: post_flight failed in streaming meter");
                    }
                });
            },
        );
        let tee_body = TeeBody::new_with_slot(
            upstream_resp.into_body(),
            MAX_STREAMING_RESPONSE_BYTES,
            meter_cb,
            Some(streaming_slot),
        );
        let mut builder = Response::builder().status(status);
        for (name, value) in &resp_headers {
            if name.as_str().eq_ignore_ascii_case("content-length") {
                continue;
            }
            builder = builder.header(name, value);
        }
        return Ok(builder.body(ProxyBody::Streaming(tee_body)).unwrap());
    }

    let resp_body = match Limited::new(upstream_resp.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return Ok(payload_too_large(
                "upstream response body exceeds 10 MiB limit",
            ));
        }
        Err(e) => {
            tracing::warn!(lane = projector.name, error = %e, "loopback projector lane: upstream response body collection failed");
            return Ok(internal_error("failed to read upstream response body"));
        }
    };

    let usage = meter_response(&upstream_host, resp_body.as_ref());
    if let Err(e) = backend.post_flight(&resolved, usage).await {
        tracing::warn!(lane = projector.name, error = ?e, grant_id = %resolved.grant_id, "loopback projector lane: post_flight failed");
    }

    let mut builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        builder = builder.header(name, value);
    }
    Ok(builder.body(box_full(Full::new(resp_body))).unwrap())
}

/// Thin codex-specific wrapper over [`handle_loopback_projector_request`],
/// preserving the original call site
/// (`crates/ember-daemon/src/infra/codex_proxy.rs`) and the inline + loopback
/// integration tests. Dispatches with [`CODEX_PROJECTOR`].
pub async fn handle_codex_responses_request<B, ReqB>(
    backend: Arc<B>,
    req: Request<ReqB>,
    session_id: String,
) -> Result<Response<ProxyBody>, ForwardError>
where
    B: PolicyBackend,
    ReqB: Body + Send + 'static,
    ReqB::Data: Send,
    ReqB::Error: std::error::Error + Send + Sync + 'static,
{
    handle_loopback_projector_request(&CODEX_PROJECTOR, backend, req, session_id).await
}

// ===== moved from proxy.rs lines 38-142 =====
/// Maximum bytes the proxy will buffer from a single request or non-streaming
/// response body before returning 413 Payload Too Large.
///
/// An unbounded `.collect()` lets a single large POST
/// exhaust daemon RSS. 10 MiB is comfortably above the largest legitimate
/// Anthropic request body (≈ 200 KB for a maximal prompt) while keeping the
/// worst-case allocation per request well below the streaming cap of
/// `MAX_CONCURRENT_STREAMING × MAX_STREAMING_RESPONSE_BYTES` = 32 MiB. If a
/// real caller genuinely needs bigger bodies the proxy is the wrong tool —
/// data that large should go directly to the upstream, not through the
/// credential-injection layer.
pub const MAX_BODY_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

/// Upper bound on the bytes a streaming proxy response is allowed to
/// accumulate before we abort the downstream tee.
///
/// C44-TEE-MEM (2026-04-23): lowered from 16 MiB to 1 MiB. The tee exists
/// to parse post-flight usage metadata, not to replay content bodies. An
/// Anthropic SSE usage frame is <1 KB; the entire `message_delta`/
/// `message_stop` control path for a realistic response fits in tens of
/// KB. The previous 16 MiB ceiling was sized for "the largest possible
/// body we'd ever want to buffer" — but N concurrent streams × 16 MiB is
/// a trivial DoS vector (100 stalled streams = 1.6 GiB RSS). Combined
/// with `MAX_CONCURRENT_STREAMING` below, worst-case exposure is bounded
/// at `MAX_CONCURRENT_STREAMING * MAX_STREAMING_RESPONSE_BYTES` = 32 MiB.
///
/// Tradeoff: a pathological upstream that emits >1 MiB of SSE metadata
/// trips the cap, the stream ends `Partial`, and whatever usage was
/// accumulated up to the abort is metered. Real Anthropic traffic does
/// not approach this ceiling; if we start seeing legitimate Partial
/// aborts in production, revisit the number (raise it, or move to
/// incremental SSE parsing — option A in the original task).
pub const MAX_STREAMING_RESPONSE_BYTES: usize = 1024 * 1024;

/// Maximum number of streaming proxy requests allowed in flight at once.
///
/// C44-TEE-MEM (2026-04-23): each in-flight streaming request owns a
/// `TeeBody` accumulator up to `MAX_STREAMING_RESPONSE_BYTES`. Without
/// this gate, a hostile or buggy agent could open arbitrarily many
/// streaming requests with slow (or stalled) client-side reads and pin
/// unbounded RSS on the daemon. The gate is per-daemon-process and
/// rejects new streaming requests with HTTP 503 when saturated.
///
/// Non-streaming requests are NOT gated — they collect into a single
/// `Bytes` bounded by the upstream `Content-Length`, which is already a
/// natural cap. Tune upward with evidence if legitimate clients hit the
/// ceiling; 32 matches the realistic concurrency profile of a single
/// developer's agent fleet.
pub const MAX_CONCURRENT_STREAMING: usize = 32;

/// Process-global count of streaming proxy requests currently in flight.
///
/// Incremented on entry to the streaming dispatch branch in
/// `handle_request`, decremented via an RAII guard held by `TeeBody` so
/// the slot is released on clean EOF, cap abort, upstream error, or
/// client disconnect (which drops the response body mid-poll).
///
/// `AtomicUsize` rather than a `tokio::sync::Semaphore` because we want
/// a non-blocking `try_acquire` + immediate 503, not a queue that holds
/// a hyper connection open while the caller waits.
pub static STREAMING_REQUESTS_INFLIGHT: AtomicUsize = AtomicUsize::new(0);

/// RAII handle that decrements `STREAMING_REQUESTS_INFLIGHT` on drop.
/// Held by `TeeBody` for the lifetime of a streaming response so every
/// terminal path (clean EOF, upstream error, cap abort, client
/// disconnect mid-stream) releases the slot exactly once.
pub struct StreamingSlot;

impl StreamingSlot {
    /// Attempt to reserve one of `MAX_CONCURRENT_STREAMING` streaming
    /// slots. Returns `Some(guard)` when accepted; `None` when the
    /// per-process cap is saturated. Callers convert `None` into HTTP
    /// 503 so the client can retry later.
    pub fn try_acquire() -> Option<Self> {
        // `fetch_update` is the lock-free CAS loop that makes "read,
        // test, increment" atomic — a naive `load` + `store` pair would
        // let two threads both observe the limit as unsaturated and
        // both increment past it.
        STREAMING_REQUESTS_INFLIGHT
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                if n >= MAX_CONCURRENT_STREAMING {
                    None
                } else {
                    Some(n + 1)
                }
            })
            .ok()
            .map(|_| StreamingSlot)
    }

    /// Current in-flight count. Test-only; production code uses the
    /// guard lifetime itself, not the scalar.
    #[cfg(any(test, feature = "test-support"))]
    pub fn inflight() -> usize {
        STREAMING_REQUESTS_INFLIGHT.load(Ordering::Acquire)
    }
}

impl Drop for StreamingSlot {
    fn drop(&mut self) {
        // `Release` pairs with the `AcqRel` on acquisition so the
        // decrement is visible to the next acquirer on another thread.
        STREAMING_REQUESTS_INFLIGHT.fetch_sub(1, Ordering::Release);
    }
}

// ===== moved from proxy.rs lines 144-532 =====
/// Body type used for all proxy responses. Unifies the buffered error paths
/// (bad_request, forbidden, ...) with the streaming SSE tee so
/// `handle_request` has a single concrete return type.
///
/// We can't use `http_body_util::combinators::UnsyncBoxBody` here because
/// its constructor requires the inner body to be `Send + 'static`, and the
/// SSE tee captures `Arc<ProxyState>` whose embedded `rusqlite::Connection`
/// is `!Send`. The proxy runs on a `LocalSet` so `Send` is irrelevant; the
/// enum gives us static dispatch over the two body shapes without that
/// bound.
pub enum ProxyBody {
    Buffered(Full<Bytes>),
    Streaming(TeeBody<Incoming>),
    /// Pure passthrough — forwards upstream `Incoming` frames directly to
    /// the client without buffering or accumulating. Used by the git-echo
    /// path (P69L.0b) so git pack-objects streams flow through without
    /// ever residing fully in daemon memory. Also available to the
    /// Anthropic streaming path (P69L.1) via `stream_response`.
    ///
    /// P69L.0b-P0-GATE + P69L.0b-P1-DROP-GUARD (2026-04-24): carries an
    /// RAII `StreamingSlot` + byte/outcome counters so the passthrough
    /// path (a) participates in the `MAX_CONCURRENT_STREAMING` gate that
    /// protects the daemon from unbounded concurrent upstream flows and
    /// (b) emits an observability log line on drop covering both clean
    /// EOF ("complete") and mid-stream client disconnect ("partial").
    Passthrough(PassthroughBody<Incoming>),
}

/// Body wrapper over `hyper::body::Incoming` that (a) holds the
/// streaming-concurrency slot for the lifetime of the response body,
/// (b) counts bytes forwarded to the client, and (c) emits an
/// observability log line on drop so mid-stream disconnects surface
/// without needing a terminal frame.
///
/// C44-TEE-MEM (P69L.0b-P0-GATE + P69L.0b-P1-DROP-GUARD 2026-04-24):
/// this mirrors `TeeBody`'s RAII-slot pattern but without accumulation —
/// the passthrough path does NOT need the tee buffer because git
/// smart-HTTP bodies are forwarded chunk-for-chunk to the client. The
/// slot + drop guard give us the same "every terminal path releases
/// resources exactly once" contract `TeeBody` has.
///
/// P69L.0b-P1-ERROR-SIGNAL (2026-04-24): before emitting the terminal
/// `Poll::Ready(None)`, `poll_frame` synthesises an HTTP/1.1 chunked
/// trailer frame containing:
///
/// ```text
/// x-ember-stream-outcome: complete   (clean upstream EOF)
/// x-ember-stream-outcome: partial    (upstream error or watchdog abort)
/// ```
///
/// Clients that read trailers (via `http_body::Body::poll_frame` after
/// data exhaustion, or higher-level `BodyExt::collect`) can examine this
/// header to distinguish a clean transfer from a mid-stream failure
/// without relying on byte counts or TCP error signals. The trailer
/// value is the authoritative source of truth; the `proxy.stream` audit
/// event (P69L.0b-P1-AUDIT) always uses the same string so log and wire
/// agree exactly.
///
/// Note: when the body is *dropped* before reaching a terminal frame
/// (client disconnect) there is no trailer — the drop-guard log line
/// records `outcome=partial` instead.
pub struct PassthroughBody<B = Incoming> {
    inner: B,
    /// Concurrency gate slot. `Some` in production; `None` only for
    /// unit tests that exercise the body shape directly. Dropped
    /// automatically with the struct (Rust field-drop order releases
    /// `slot` after we've logged in `Drop::drop`).
    _slot: Option<StreamingSlot>,
    /// Running total of body bytes forwarded downstream. Updated inside
    /// `poll_frame` for each data frame; read by `Drop` for the
    /// observability log. `Arc` so tests can observe it even after the
    /// body itself is dropped, with zero extra cost on the hot path
    /// (one atomic-add per data frame).
    ///
    /// `pub` so ember-daemon's in-tree `proxy::tests` (which observe the
    /// drop-time byte count directly) keep compiling across the crate
    /// boundary; production code only ever mutates it via `poll_frame`.
    pub bytes_forwarded: Arc<AtomicU64>,
    /// Stream outcome state machine. `0 = inflight`, `1 = complete`
    /// (clean EOF observed), `2 = partial` (upstream error or body
    /// dropped before EOF). Drop treats anything other than
    /// `complete` as `partial`.
    ///
    /// `pub` for the same cross-crate-test reason as `bytes_forwarded`.
    pub outcome: Arc<AtomicU8>,
    /// P69L.0b-P0-TIMEOUTS: per-frame idle watchdog. When `Some`, the
    /// body aborts with `outcome=partial reason=frame-idle-timeout` if
    /// no data frame arrives within this duration. `None` disables the
    /// watchdog (legacy behaviour, used by tests that exercise the body
    /// shape without wall-clock dependency).
    frame_idle_deadline: Option<Duration>,
    /// Lazily-created sleep future that fires when the frame-idle
    /// watchdog elapses. Recreated each time a data frame arrives so
    /// the deadline resets on every observed frame.
    frame_idle_sleep: Option<Pin<Box<Sleep>>>,
    /// Set to `true` when the frame-idle watchdog has already fired;
    /// subsequent polls return `Ready(None)` immediately. Prevents
    /// double-firing if hyper polls after we've aborted.
    frame_idle_fired: bool,
    /// P69L.0b-P1-ERROR-SIGNAL: tracks whether the trailer has been
    /// emitted yet. `false` = not yet (initial state); `true` = already
    /// emitted. Once the upstream reaches a terminal condition (clean EOF,
    /// upstream error, watchdog abort), `poll_frame` emits the
    /// `x-ember-stream-outcome` trailer frame and sets this to `true`.
    /// Subsequent polls skip straight to `Ready(None)`.
    trailer_emitted: bool,
    /// P69L.0b-P1-AUDIT: correlating identifier threaded from
    /// `handle_git_echo` entry through to drop-time `proxy.stream`
    /// emission. `None` on code paths that don't participate in the
    /// git-echo audit trail (e.g., Anthropic SSE via `stream_response`).
    request_id: Option<Arc<str>>,
    /// Test-only deterministic hook. Set by unit tests so `Drop` can
    /// publish the final outcome without depending on a tracing
    /// subscriber. `None` in production — the `tracing::info!` call is
    /// the observable signal.
    #[cfg(any(test, feature = "test-support"))]
    test_outcome_sink: Option<Arc<AtomicU8>>,
    /// Test-only bytes-forwarded hook — same rationale as
    /// `test_outcome_sink` but for the accumulated byte count, so a
    /// test can assert both invariants without log scraping.
    #[cfg(any(test, feature = "test-support"))]
    test_bytes_sink: Option<Arc<AtomicU64>>,
}

/// Outcome constants for `PassthroughBody::outcome`. Kept as bare
/// integers (not an enum) because `AtomicU8` can't hold a repr-enum
/// and we want branch-free atomic updates on the hot path.
pub const PASSTHROUGH_INFLIGHT: u8 = 0;
pub const PASSTHROUGH_COMPLETE: u8 = 1;
pub const PASSTHROUGH_PARTIAL: u8 = 2;

/// The header name for the stream-outcome trailer emitted by
/// `PassthroughBody` (P69L.0b-P1-ERROR-SIGNAL).
pub const STREAM_OUTCOME_TRAILER_NAME: &str = "x-ember-stream-outcome";

/// Build the `x-ember-stream-outcome` HTTP trailer `HeaderMap` for the
/// given outcome constant. `PASSTHROUGH_COMPLETE` → `"complete"`, any
/// other value → `"partial"`. Called by `PassthroughBody::poll_frame`
/// just before emitting the terminal `Ready(None)`.
pub fn build_outcome_trailer(outcome: u8) -> hyper::HeaderMap {
    let mut map = hyper::HeaderMap::new();
    let value = if outcome == PASSTHROUGH_COMPLETE {
        hyper::header::HeaderValue::from_static("complete")
    } else {
        hyper::header::HeaderValue::from_static("partial")
    };
    map.insert(
        hyper::header::HeaderName::from_static(STREAM_OUTCOME_TRAILER_NAME),
        value,
    );
    map
}

impl<B> PassthroughBody<B> {
    /// Construct a production `PassthroughBody`. Callers MUST have
    /// acquired `slot` via `StreamingSlot::try_acquire` before invoking
    /// this — `stream_response` is the sanctioned call site.
    pub fn new(inner: B, slot: Option<StreamingSlot>) -> Self {
        Self {
            inner,
            _slot: slot,
            bytes_forwarded: Arc::new(AtomicU64::new(0)),
            outcome: Arc::new(AtomicU8::new(PASSTHROUGH_INFLIGHT)),
            frame_idle_deadline: None,
            frame_idle_sleep: None,
            frame_idle_fired: false,
            trailer_emitted: false,
            request_id: None,
            #[cfg(any(test, feature = "test-support"))]
            test_outcome_sink: None,
            #[cfg(any(test, feature = "test-support"))]
            test_bytes_sink: None,
        }
    }

    /// Attach a correlating `request_id` so the drop-time `proxy.stream`
    /// log line can be joined with the `credential.access` entry emitted
    /// at `handle_git_echo` entry. Called by `handle_git_echo` after
    /// acquiring the streaming slot; never called on the Anthropic SSE path.
    pub fn with_request_id(mut self, id: Arc<str>) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Enable the per-frame idle watchdog. When no data frame is observed
    /// from `inner` for at least `deadline`, `poll_frame` aborts the
    /// stream with `outcome=partial` and the drop-guard log line reports
    /// `reason=frame-idle-timeout`. Called by
    /// `stream_response_with_frame_idle` on the production path.
    pub fn with_frame_idle(mut self, deadline: Duration) -> Self {
        self.frame_idle_deadline = Some(deadline);
        self
    }

    /// Install deterministic test sinks so a unit test can observe the
    /// drop-time outcome + byte count without depending on a tracing
    /// subscriber. Called once at construction in tests; never in
    /// production (gated by `#[cfg(any(test, feature = "test-support"))]`).
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_test_sinks(
        mut self,
        outcome_sink: Arc<AtomicU8>,
        bytes_sink: Arc<AtomicU64>,
    ) -> Self {
        self.test_outcome_sink = Some(outcome_sink);
        self.test_bytes_sink = Some(bytes_sink);
        self
    }
}

impl<B> Body for PassthroughBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // `B: Unpin` lets us project structurally through a plain
        // `&mut` — no unsafe needed here. The inner body is free to
        // move during poll (Unpin). Other fields (`Arc`, `Option`,
        // integers) are trivially Unpin; the `Pin<Box<Sleep>>` stays
        // pinned on the heap regardless of how `this` moves.
        let this = self.get_mut();

        // P69L.0b-P1-ERROR-SIGNAL: once the trailer has been emitted,
        // every subsequent poll returns `Ready(None)` — the body is done.
        // Also covers the frame-idle-watchdog termination path: the
        // watchdog arm sets `trailer_emitted = true` before returning the
        // trailer frame, so repeat polls land here and end cleanly.
        if this.trailer_emitted {
            return Poll::Ready(None);
        }

        // P69L.0b-P0-TIMEOUTS: frame_idle_fired is set by the watchdog arm
        // inside the Pending branch and is always accompanied by
        // `trailer_emitted = true` in the same poll, so this guard is a
        // defence-in-depth check for any future code path that sets
        // `frame_idle_fired` without also emitting the trailer.
        if this.frame_idle_fired {
            this.trailer_emitted = true;
            let trailer = build_outcome_trailer(PASSTHROUGH_PARTIAL);
            return Poll::Ready(Some(Ok(Frame::trailers(trailer))));
        }

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => {
                // If the frame-idle watchdog is enabled, (re)arm the
                // sleep on first Pending after the last frame and poll
                // it. When it elapses, we abort the stream with
                // `outcome=partial reason=frame-idle-timeout`.
                if let Some(deadline) = this.frame_idle_deadline {
                    let sleep = this
                        .frame_idle_sleep
                        .get_or_insert_with(|| Box::pin(tokio::time::sleep(deadline)));
                    match sleep.as_mut().poll(cx) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(()) => {
                            this.frame_idle_fired = true;
                            this.outcome.store(PASSTHROUGH_PARTIAL, Ordering::Release);
                            let bytes = this.bytes_forwarded.load(Ordering::Relaxed);
                            tracing::warn!(
                                bytes_forwarded = bytes,
                                deadline_secs = deadline.as_secs(),
                                reason = "frame-idle-timeout",
                                "proxy stream aborted — frame-idle watchdog fired",
                            );
                            // Emit the outcome trailer immediately. The
                            // next poll sees `frame_idle_fired = true`
                            // and hits the guard above to emit the
                            // trailer, then `trailer_emitted = true`
                            // closes the body with `Ready(None)`.
                            this.trailer_emitted = true;
                            let trailer = build_outcome_trailer(PASSTHROUGH_PARTIAL);
                            Poll::Ready(Some(Ok(Frame::trailers(trailer))))
                        }
                    }
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(None) => {
                // Clean upstream EOF → outcome transitions to `complete`.
                // Emit the `x-ember-stream-outcome: complete` trailer so
                // the client can distinguish a clean transfer from a
                // partial one. The next poll sees `trailer_emitted = true`
                // and returns `Ready(None)`.
                this.outcome.store(PASSTHROUGH_COMPLETE, Ordering::Release);
                this.trailer_emitted = true;
                let trailer = build_outcome_trailer(PASSTHROUGH_COMPLETE);
                Poll::Ready(Some(Ok(Frame::trailers(trailer))))
            }
            Poll::Ready(Some(Err(e))) => {
                // Upstream error aborts the stream mid-flight. Emit the
                // `x-ember-stream-outcome: partial` trailer so the client
                // can observe the failure without an abrupt TCP close. The
                // error is consumed here; Drop will observe
                // `outcome == PARTIAL` (inflight → partial via Drop).
                tracing::warn!(
                    error = %e,
                    bytes_forwarded = this.bytes_forwarded.load(Ordering::Relaxed),
                    "proxy stream upstream error — emitting partial trailer"
                );
                this.trailer_emitted = true;
                let trailer = build_outcome_trailer(PASSTHROUGH_PARTIAL);
                Poll::Ready(Some(Ok(Frame::trailers(trailer))))
            }
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(chunk) = frame.data_ref() {
                    // `fetch_add` is fine for monotonic counters;
                    // `Relaxed` is enough because we only read it
                    // under `Acquire` in Drop (same thread path in
                    // practice, but Relaxed is architecturally
                    // correct for independent monotonic writes).
                    this.bytes_forwarded
                        .fetch_add(chunk.len() as u64, Ordering::Relaxed);
                    // A data frame arrived — reset the frame-idle
                    // watchdog. Dropping the sleep clears the
                    // registered timer; the next Pending will re-arm
                    // a fresh Sleep at the full deadline.
                    this.frame_idle_sleep = None;
                }
                Poll::Ready(Some(Ok(frame)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        // After the outcome trailer has been emitted, the next poll
        // returns `Ready(None)` — report end-of-stream so callers that
        // short-circuit on this hint (e.g. hyper's response encoder) do
        // not attempt another poll unnecessarily.
        if self.trailer_emitted {
            return true;
        }
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for PassthroughBody<B> {
    fn drop(&mut self) {
        let raw_outcome = self.outcome.load(Ordering::Acquire);
        let final_outcome = if raw_outcome == PASSTHROUGH_COMPLETE {
            PASSTHROUGH_COMPLETE
        } else {
            // Both `inflight` and explicit `partial` collapse to
            // partial on drop. Mid-stream client disconnect is the
            // common case here: hyper drops the response body when
            // the client TCP socket closes before EOF.
            PASSTHROUGH_PARTIAL
        };
        let bytes = self.bytes_forwarded.load(Ordering::Relaxed);
        let outcome_label = match final_outcome {
            PASSTHROUGH_COMPLETE => "complete",
            _ => "partial",
        };
        // P69L.0b-P1-AUDIT: emit `proxy.stream` with the correlating
        // request_id so operators can join this drop-time record with the
        // `credential.access` entry logged at `handle_git_echo` entry.
        // `request_id` is `None` on non-git-echo paths (Anthropic SSE,
        // tests that exercise the body shape directly) — in that case we
        // still emit the observability log line, just without the field.
        match &self.request_id {
            Some(rid) => tracing::info!(
                event = "proxy.stream",
                request_id = %rid,
                bytes_forwarded = bytes,
                outcome = outcome_label,
                "proxy stream closed"
            ),
            None => tracing::info!(
                bytes_forwarded = bytes,
                outcome = outcome_label,
                "proxy stream closed"
            ),
        }
        // Test-only sinks — make the drop observable to unit tests
        // without needing a tracing subscriber.
        #[cfg(any(test, feature = "test-support"))]
        {
            if let Some(sink) = &self.test_outcome_sink {
                sink.store(final_outcome, Ordering::Release);
            }
            if let Some(sink) = &self.test_bytes_sink {
                sink.store(bytes, Ordering::Release);
            }
        }
        // `_slot` drops after this function returns via Rust's
        // field-drop order; no manual release needed.
    }
}

// ===== moved from proxy.rs lines 534-715 =====
/// Wrap a buffered `Full<Bytes>` body in the proxy's unified response body
/// type. Used by every error/response helper so callers don't have to
/// thread the enum tag explicitly.
pub fn box_full(body: Full<Bytes>) -> ProxyBody {
    ProxyBody::Buffered(body)
}

/// Hop-by-hop headers per RFC 7230 §6.1. These MUST NOT be forwarded by a
/// proxy — they describe the single transport hop, not the end-to-end
/// message. `trailer` is the RFC-canonical spelling; we include `trailers`
/// (the plural commonly seen in the wild) defensively.
///
/// Stored lowercased because `HeaderName` comparison is case-insensitive
/// and the RFC tokens are ASCII.
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Explicit allowlist of request headers forwarded to upstream APIs.
///
/// The proxy previously used a blocklist that stripped
/// only `x-ember-*` and `Authorization`, silently forwarding `Cookie`,
/// `Host`, `X-Forwarded-*`, `Proxy-Authorization`, and every other header
/// the client chose to send. An allowlist is the correct security primitive:
/// only headers that upstreams (Anthropic, GitHub, similar REST APIs)
/// actually consume are passed through; everything else is dropped silently.
///
/// `Authorization` is intentionally NOT included — the proxy always injects
/// its own credential and any client-supplied `Authorization` must be
/// stripped before the inject step. See `filter_request_headers`.
///
/// Stored lowercased because `HeaderName` comparison is case-insensitive
/// and all legitimate header names are ASCII.
pub const ALLOWED_REQUEST_HEADERS: &[&str] = &[
    "accept",
    // `accept-encoding` deliberately omitted so the post-flight meter can
    // parse JSON usage blocks.
    // Passing the client's `Accept-Encoding: gzip` through to upstream
    // returns a gzip-compressed response body, which `parse_usage` cannot
    // recognize as JSON (`looks_like_json` checks for a leading `{` or
    // `[`; gzip's magic bytes start with `1f 8b`). The post-flight meter
    // silently drops the call and the budget cap never accumulates.
    // We force `accept-encoding: identity` on every outgoing request
    // below so upstream returns plain JSON; the client SDK doesn't care
    // (the responses are tens-of-KB at most for a 90s demo).
    "accept-language",
    "content-type",
    "content-length",
    "user-agent",
    // Anthropic-specific
    "anthropic-version",
    "anthropic-beta",
    // OpenAI-compatible header used by some providers
    "openai-organization",
];

/// Build an outgoing `Request::Builder` from `src` headers using only the
/// `ALLOWED_REQUEST_HEADERS` allowlist.
///
/// Constructs outbound headers from scratch rather
/// than filtering in-place so there is no risk of accidentally carrying
/// through a header that slips past a blocklist. Any header NOT in
/// `ALLOWED_REQUEST_HEADERS` is dropped silently — including `Cookie`,
/// `Host`, `X-Forwarded-*`, `Forwarded`, `Via`, `Proxy-Authorization`,
/// `Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, and
/// `Connection`.
///
/// `Authorization` is omitted from the allowlist deliberately: callers
/// inject the vault credential themselves after this call so the value is
/// always ember-controlled, never client-controlled.
pub fn filter_request_headers(
    mut builder: hyper::http::request::Builder,
    src: &hyper::HeaderMap,
) -> hyper::http::request::Builder {
    for (name, value) in src {
        let lower = name.as_str();
        if ALLOWED_REQUEST_HEADERS.contains(&lower) {
            builder = builder.header(name, value);
        }
    }
    builder
}

/// Request headers the codex GPT-plan pass-through always DROPS before
/// forwarding to the ChatGPT backend. Everything else codex sends is preserved
/// (see [`passthrough_codex_request_headers`]).
///
/// - auth headers (`authorization`, `x-api-key`, `chatgpt-account-id`): the
///   broker injects its own via [`inject_chatgpt_plan_auth`]; a client-supplied
///   value must never ride through.
/// - `host`: stripped; hyper re-derives the authority from the server-pinned
///   absolute `upstream_url` (`Host` for HTTP/1.1, `:authority` for HTTP/2). We
///   deliberately do NOT set an explicit `Host` — over HTTP/2 it duplicates the
///   derived `:authority` and strict upstream GFEs reset with `PROTOCOL_ERROR`.
/// - `accept-encoding`: forced to `identity` below so the post-flight meter sees
///   plain JSON (same rationale as `ALLOWED_REQUEST_HEADERS`'s omission).
/// - `content-length`: hyper recomputes it from the forwarded body.
/// - hop-by-hop headers are stripped separately ([`HOP_BY_HOP_HEADERS`]).
const CODEX_STRIPPED_REQUEST_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "chatgpt-account-id",
    "host",
    "accept-encoding",
    "content-length",
];

/// Build the outbound request headers for the codex GPT-plan lane by PASSING
/// THROUGH codex's authentic non-auth headers, dropping only the small set in
/// [`CODEX_STRIPPED_REQUEST_HEADERS`] + hop-by-hop headers, then forcing
/// `accept-encoding: identity`.
///
/// Unlike [`filter_request_headers`] (a tight allowlist for the Anthropic
/// lane), this PRESERVES the codex-specific signalling headers the ChatGPT
/// backend expects from first-party codex — `OpenAI-Beta`, `session_id`,
/// `originator`, `x-codex-*`, attestation, etc. The real codex binary is in the
/// loop generating these; dropping them would make the request look unlike
/// codex. The broker auth is injected afterwards by [`inject_chatgpt_plan_auth`].
pub fn passthrough_codex_request_headers(
    mut builder: hyper::http::request::Builder,
    src: &hyper::HeaderMap,
) -> hyper::http::request::Builder {
    for (name, value) in src {
        let lower = name.as_str().to_ascii_lowercase();
        if CODEX_STRIPPED_REQUEST_HEADERS.contains(&lower.as_str())
            || HOP_BY_HOP_HEADERS.contains(&lower.as_str())
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    // Force identity so upstream returns plain JSON the meter can parse.
    builder = builder.header(hyper::header::ACCEPT_ENCODING, "identity");
    builder
}

/// Request headers stripped on the gemini GATEWAY lane before forwarding.
///
/// Mirrors [`CODEX_STRIPPED_REQUEST_HEADERS`]; the only delta is the auth header
/// (`x-goog-api-key` instead of codex's `chatgpt-account-id`):
/// - auth headers (`authorization`, `x-api-key`, `x-goog-api-key`): the broker
///   injects its own via [`inject_api_key_header`]; a client value (the GATEWAY
///   client emits an empty `x-goog-api-key`) must never ride through.
/// - `host`: stripped; hyper re-derives the authority from the server-pinned
///   absolute `upstream_url` (`Host` for HTTP/1.1, `:authority` for HTTP/2). We
///   deliberately do NOT set an explicit `Host` — over HTTP/2 it duplicates the
///   derived `:authority` and strict upstream GFEs reset with `PROTOCOL_ERROR`.
/// - `accept-encoding`: forced to `identity` below so the post-flight meter sees
///   plain JSON.
/// - `content-length`: hyper recomputes it from the forwarded body.
/// - hop-by-hop headers are stripped separately ([`HOP_BY_HOP_HEADERS`]).
const GEMINI_STRIPPED_REQUEST_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-goog-api-key",
    "host",
    "accept-encoding",
    "content-length",
];

/// Build the outbound request headers for the gemini GATEWAY lane by PASSING
/// THROUGH gemini-cli's authentic non-auth headers (`User-Agent`,
/// `content-type`, the `@google/genai` SDK's own signalling), dropping only the
/// set in [`GEMINI_STRIPPED_REQUEST_HEADERS`] + hop-by-hop headers, then forcing
/// `accept-encoding: identity`. Same shape as [`passthrough_codex_request_headers`];
/// the broker key is injected afterwards by [`inject_api_key_header`].
pub fn passthrough_gemini_request_headers(
    mut builder: hyper::http::request::Builder,
    src: &hyper::HeaderMap,
) -> hyper::http::request::Builder {
    for (name, value) in src {
        let lower = name.as_str().to_ascii_lowercase();
        if GEMINI_STRIPPED_REQUEST_HEADERS.contains(&lower.as_str())
            || HOP_BY_HOP_HEADERS.contains(&lower.as_str())
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    // Force identity so upstream returns plain JSON the meter can parse.
    builder = builder.header(hyper::header::ACCEPT_ENCODING, "identity");
    builder
}

/// Inject the broker-resolved ChatGPT plan auth onto an outbound codex request.
///
/// VERSION-RESILIENCE PRINCIPLE (operator, 2026-05-31): we do not control the
/// user's codex version, so the proxy injects ONLY what codex cannot itself
/// provide once we strip its auth — never a hardcoded mirror of a value codex
/// emits natively. The real codex binary is in the loop generating the
/// version-correct `originator`, `OpenAI-Beta`, `session_id`, attestation, and
/// request body; [`passthrough_codex_request_headers`] preserves all of those.
///
/// Strips any client-supplied `authorization`/`x-api-key`/`chatgpt-account-id`
/// (defence-in-depth on top of the pass-through filter) then inserts:
///   - `Authorization: Bearer <access_token>` (codex can't — we disabled its auth)
///   - `ChatGPT-Account-ID: <account_id>` (codex derives this from its auth,
///     which we disabled, so we supply it from the broker-held token)
///   - `X-OpenAI-Fedramp: true` (FedRAMP accounts only — same rationale)
///
/// It does NOT inject `originator`: codex's authentic value already passed
/// through, and overwriting it with a hardcoded constant is exactly the
/// version-drift bug we must avoid. [`CHATGPT_ORIGINATOR`] is only a
/// last-resort backfill applied when codex sent none.
///
/// Returns `Err(())` if the access token is not a valid header value.
// () error is intentional; richer error type is out of scope for the lint-clear.
#[allow(clippy::result_unit_err)]
pub fn inject_chatgpt_plan_auth(
    headers: &mut hyper::HeaderMap,
    auth: &core_proxy_forward::ChatgptPlanAuth,
) -> Result<(), ()> {
    headers.remove("authorization");
    headers.remove("x-api-key");
    headers.remove(CHATGPT_ACCOUNT_ID_HEADER);

    let token = auth.access_token.trim_end_matches(['\r', '\n']);
    let bearer = format!("Bearer {token}");
    let bearer_value = hyper::header::HeaderValue::from_str(&bearer).map_err(|_| ())?;
    headers.insert(hyper::header::AUTHORIZATION, bearer_value);

    if let Some(account_id) = auth.account_id.as_deref()
        && !account_id.is_empty()
    {
        let value = hyper::header::HeaderValue::from_str(account_id).map_err(|_| ())?;
        headers.insert(CHATGPT_ACCOUNT_ID_HEADER, value);
    }

    // Backfill `originator` ONLY if codex did not send its own — never
    // overwrite codex's authentic, version-correct value.
    if !headers.contains_key("originator") {
        headers.insert(
            "originator",
            hyper::header::HeaderValue::from_static(CHATGPT_ORIGINATOR),
        );
    }

    if auth.is_fedramp {
        headers.insert(
            "x-openai-fedramp",
            hyper::header::HeaderValue::from_static("true"),
        );
    }

    Ok(())
}

/// Inject a single opaque brokered API key onto an outbound request under a
/// named header (gemini GATEWAY lane: `x-goog-api-key`).
///
/// Strips any client-supplied `authorization`/`x-api-key`/`<header_name>`
/// (defence-in-depth: the GATEWAY client emits an empty `x-goog-api-key`, and a
/// malicious client must not be able to smuggle its own auth past the broker)
/// then inserts the broker value. `header_name` is a lowercase `&'static str`
/// safe for [`hyper::header::HeaderName::from_static`] (which PANICS on a
/// non-lowercase / invalid name — kept `&'static str` so it is compile-time
/// constrained to the projector's pinned constant, never caller input).
///
/// Returns `Err(())` if the key is not a valid header value.
// () error is intentional; richer error type is out of scope for the lint-clear.
#[allow(clippy::result_unit_err)]
pub fn inject_api_key_header(
    headers: &mut hyper::HeaderMap,
    header_name: &'static str,
    value: &str,
) -> Result<(), ()> {
    headers.remove("authorization");
    headers.remove("x-api-key");
    headers.remove(header_name);
    let v = hyper::header::HeaderValue::from_str(value.trim_end_matches(['\r', '\n']))
        .map_err(|_| ())?;
    headers.insert(hyper::header::HeaderName::from_static(header_name), v);
    Ok(())
}

/// Inject a broker-resolved OAuth Bearer access token as `Authorization: Bearer
/// <token>` (gemini Code Assist lane).
///
/// Strips any client-supplied `authorization` (the gemini-cli signs Code Assist
/// requests client-side with google-auth-library — that Bearer must never ride
/// through) plus `x-api-key`/`x-goog-api-key` (defence-in-depth), then inserts
/// the broker Bearer. The durable `refresh_token` never reaches this layer; the
/// daemon refreshes server-side and passes only the short-window access token.
///
/// Returns `Err(())` if the token is not a valid header value.
// () error is intentional; richer error type is out of scope for the lint-clear.
#[allow(clippy::result_unit_err)]
pub fn inject_oauth_bearer(headers: &mut hyper::HeaderMap, access_token: &str) -> Result<(), ()> {
    headers.remove("authorization");
    headers.remove("x-api-key");
    headers.remove("x-goog-api-key");
    let token = access_token.trim_end_matches(['\r', '\n']);
    let bearer = format!("Bearer {token}");
    let value = hyper::header::HeaderValue::from_str(&bearer).map_err(|_| ())?;
    headers.insert(hyper::header::AUTHORIZATION, value);
    Ok(())
}

/// Strip RFC 7230 §6.1 hop-by-hop headers from a response header map.
///
/// Three steps:
///   1. Parse any upstream `Connection:` token list — it names additional
///      per-hop header fields for this connection (RFC 7230 §6.1 para 3).
///      We collect these BEFORE mutating the map so we don't lose the
///      token list.
///   2. Remove every canonical hop-by-hop header in `HOP_BY_HOP_HEADERS`.
///      `HeaderMap::remove` is case-insensitive so the lowercased tokens
///      match any casing upstream happened to use.
///   3. Remove every additional header name announced by `Connection:`.
///      This closes the "upstream-declared hop-by-hop" tunneling vector
///      where an attacker-controlled upstream smuggles an arbitrary header
///      past a naive forwarder.
///
/// Split out as a module-private function so it is directly unit-testable
/// without standing up hyper client + server plumbing. Called by
/// `stream_response`.
pub fn strip_hop_by_hop_headers(headers: &mut hyper::HeaderMap) {
    let mut connection_listed: Vec<hyper::header::HeaderName> = Vec::new();
    for value in headers.get_all(hyper::header::CONNECTION).iter() {
        if let Ok(s) = value.to_str() {
            for token in s.split(',') {
                let trimmed = token.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(name) = hyper::header::HeaderName::from_bytes(trimmed.as_bytes()) {
                    connection_listed.push(name);
                }
            }
        }
    }

    for name in HOP_BY_HOP_HEADERS {
        if let Ok(header_name) = hyper::header::HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(&header_name);
        }
    }

    for name in connection_listed {
        headers.remove(&name);
    }
}

/// Convert an upstream `Response<Incoming>` into a `Response<ProxyBody>`
/// that streams frames to the client without buffering the body in daemon
/// memory. Status passes through unchanged.
///
/// RFC 7230 §6.1 hop-by-hop headers are stripped before the downstream
/// response is constructed — see `strip_hop_by_hop_headers` for the
/// canonical set + `Connection:`-announced handling.
///
/// Shared by the git-echo path (P69L.0b) and available for the Anthropic
/// streaming path (P69L.1) — both need chunk-at-a-time forwarding without
/// the accumulation overhead of `TeeBody`.
///
/// `slot` is the acquired concurrency gate handle; it rides inside the
/// response body and is released automatically when the body is dropped
/// (clean EOF, upstream error, or client disconnect mid-stream). Callers
/// on the production path pass `Some(slot)` from `StreamingSlot::try_acquire`;
/// test callers may pass `None` to exercise the body shape without
/// touching the process-global gate.
#[allow(dead_code)]
pub fn stream_response(
    upstream: Response<Incoming>,
    slot: Option<StreamingSlot>,
) -> Response<ProxyBody> {
    // Preserved for the Anthropic streaming path (P69L.1) which does not
    // need a frame-idle watchdog (the SSE heartbeat serves that role).
    stream_response_with_frame_idle(upstream, slot, None)
}

/// Variant of `stream_response` that additionally enables the per-frame
/// idle watchdog (P69L.0b-P0-TIMEOUTS). When `frame_idle` is `Some`, the
/// passthrough body will abort with `outcome=partial
/// reason=frame-idle-timeout` if no data frame arrives within the
/// specified deadline. `None` yields the same behaviour as
/// `stream_response`.
pub fn stream_response_with_frame_idle(
    upstream: Response<Incoming>,
    slot: Option<StreamingSlot>,
    frame_idle: Option<Duration>,
) -> Response<ProxyBody> {
    let (mut parts, body) = upstream.into_parts();
    strip_hop_by_hop_headers(&mut parts.headers);
    let mut pb = PassthroughBody::new(body, slot);
    if let Some(deadline) = frame_idle {
        pb = pb.with_frame_idle(deadline);
    }
    Response::from_parts(parts, ProxyBody::Passthrough(pb))
}

// ===== moved from proxy.rs lines 717-754 =====
impl Body for ProxyBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // SAFETY: standard pin-projection over a self-borrowed enum.
        // We don't move out of the projected reference; we only reborrow
        // each variant's payload as `Pin<&mut _>`.
        match unsafe { self.get_unchecked_mut() } {
            ProxyBody::Buffered(b) => unsafe { Pin::new_unchecked(b) }
                .poll_frame(cx)
                // `Full<Bytes>` is infallible; lift its `!` error into
                // `hyper::Error` (statically unreachable).
                .map(|opt| opt.map(|res| res.map_err(|never| match never {}))),
            ProxyBody::Streaming(b) => unsafe { Pin::new_unchecked(b) }.poll_frame(cx),
            ProxyBody::Passthrough(b) => unsafe { Pin::new_unchecked(b) }.poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ProxyBody::Buffered(b) => b.is_end_stream(),
            ProxyBody::Streaming(b) => b.is_end_stream(),
            ProxyBody::Passthrough(b) => b.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            ProxyBody::Buffered(b) => b.size_hint(),
            ProxyBody::Streaming(b) => b.size_hint(),
            ProxyBody::Passthrough(b) => b.size_hint(),
        }
    }
}

// ===== moved from proxy.rs lines 782-784 =====
pub struct ProxyConfig {
    pub bind_addr: std::net::SocketAddr,
}

// ===== moved from proxy.rs lines 1537-2175 =====
/// Outcome of the per-request host-authorization check.
#[derive(Debug, PartialEq, Eq)]
enum HostAuthz {
    Allow,
    DenyNotInAllowlist,
    DenyGenericNoAllowlist,
}

/// DNS resolver wrapper that enforces the SSRF / metadata-IP guard at
/// **connect time** (ADR 205 §4). It defers name resolution to the system
/// resolver, then drops every resolved address whose IP is in a blocked class
/// (cloud metadata, loopback, link-local, RFC-1918, …). If nothing survives,
/// resolution fails closed, so the proxy never opens a socket to a blocked
/// destination.
///
/// Enforcing here (rather than only in the literal pre-flight) makes the guard
/// **structural** and rebinding-safe: hyper's `HttpConnector` resolves the
/// hostname through this resolver immediately before connecting, so a name that
/// resolves — or *re-resolves* on a later request — to `169.254.169.254` cannot
/// slip past a one-shot pre-flight check.
#[derive(Clone)]
struct SsrfGuardResolver {
    inner: GaiResolver,
}

impl SsrfGuardResolver {
    fn new() -> Self {
        Self {
            inner: GaiResolver::new(),
        }
    }
}

impl tower_service::Service<Name> for SsrfGuardResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <GaiResolver as tower_service::Service<Name>>::poll_ready(&mut self.inner, cx)
    }

    fn call(&mut self, name: Name) -> Self::Future {
        #[cfg(any(test, feature = "test-support"))]
        // Integration tests need a deterministic upstream without weakening
        // production SSRF posture; this branch is compiled only for tests.
        if name
            .as_str()
            .eq_ignore_ascii_case("ember-proxy-test.invalid")
        {
            return Box::pin(async { Ok(vec![SocketAddr::from(([127, 0, 0, 1], 0))].into_iter()) });
        }

        let mut inner = self.inner.clone();
        Box::pin(async move {
            let addrs =
                <GaiResolver as tower_service::Service<Name>>::call(&mut inner, name).await?;
            let allowed: Vec<SocketAddr> = addrs
                .filter(|sa| core_proxy_forward::ssrf::classify_blocked_ip(sa.ip()).is_none())
                .collect();
            if allowed.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "SSRF guard: destination resolved only to blocked (metadata/internal) IPs",
                ));
            }
            Ok(allowed.into_iter())
        })
    }
}

/// Build the HTTPS client used to forward to upstreams, with the SSRF /
/// metadata-IP guard ([`SsrfGuardResolver`]) wired into the connector's DNS
/// resolver (ADR 205 §4). Both credential-forwarding lanes (the main forward
/// path and the codex-responses lane) construct their client here so neither
/// can connect to a blocked destination — the guard is impossible to bypass by
/// adding a new forwarding site that forgets the check.
fn build_guarded_forward_client()
-> Client<HttpsConnector<HttpConnector<SsrfGuardResolver>>, Full<Bytes>> {
    let mut http = HttpConnector::new_with_resolver(SsrfGuardResolver::new());
    // Allow the HTTPS wrapper to upgrade the connection; without this the bare
    // HttpConnector refuses non-http schemes.
    http.enforce_http(false);
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new()).build(https)
}

/// Decide whether a forward to `target_host` is authorized by the grant's host
/// constraint, given whether this request resolved to the `generic` provider
/// lane.
///
/// - `Some(allowed_targets)`: the destination host must match an entry
///   (exact, or `*.domain` suffix). Empty/unparsable host → deny.
/// - `None` + generic lane: **fail closed**. The generic lane's matched
///   resource is path-only (host never folded in), so with no allowlist the
///   destination host is entirely agent-controlled (`X-Ember-Target`) and the
///   proxy would inject the operator's vault secret to an arbitrary host —
///   confused-deputy credential exfiltration. A generic credential MUST carry
///   an explicit allowlist.
/// - `None` + non-generic lane (github/llm): allowed. Those lanes bake the
///   host into the matched action+resource, so they are intrinsically
///   host-bound without an allowlist.
// ADR 207 seam 8B — grant-glob target tightness verification + storage/parse
// encoding reconciliation follow-up.
//
// anchor: allowed_targets_storage_and_parse_one_encoding
//
// Storage at the `create_grant` write site is a JSON-array string
// (`serde_json::to_string(arr)`); the parser routes through the shared
// `core_proxy_forward::parse_allowed_targets` helper so the encoding is
// reconciled end-to-end (proxy forward gate, standing-grant matcher, and
// dashboard UI all read the same shape). Per-entry validation
// (`validate_allowed_target_entry`) is enforced at the write site against
// the bare-`*` and `*.<empty>` over-match flagged by SEAM-8B.
//
// Original ADR 207 seam-8B verification chain is preserved verbatim below:
//   1. Generic lane: the destination host is constrained ONLY by
//      `allowed_targets`; `None` fails closed (`DenyGenericNoAllowlist`);
//      membership is exact-or-`*.suffix` via the suffix-safe, case-folded
//      `host_matches_domain` (rejects look-alike `notgithub.com`).
//   2. github/llm lanes: the host is baked into the action classification by
//      `request_to_action_resource` (a request to any non-provider host
//      classifies `generic` and thus requires an allowlist), so `None` →
//      `Allow` is sound only for these intrinsically host-bound lanes.
//   3. An UNBOUNDED statement resource glob (`ResourceSelector::is_unbounded`,
//      `generic:* on *`) widens the PATH/resource axis, never the host — the
//      host clamp above is orthogonal and still enforced. The hypothesized
//      "broad glob + multi-entry allowlist widens the target" hole is NOT real.
//   4. Delegation (`delegate_grant_full_sql`) does NOT propagate
//      `allowed_targets` to the child (the INSERT omits the column → NULL), so
//      a delegated grant cannot widen the host clamp; a delegated generic
//      credential fails closed.
//   5. RESIDUAL FOUND + FIXED (class-completeness pass): the proxy forward
//      matchers `resolve_statement_for_request[_with_uri]` previously matched
//      action+resource while IGNORING `Statement.conditions` (fail-open),
//      diverging from the broker path `clause_covers_need` (documented
//      fail-closed). A `UrlPattern`/`Subpath` condition meant to clamp the
//      target was silently unenforced — confused deputy onto a wider target.
//      Now fail-closed: a conditioned statement does not authorize a forward
//      (`UnevaluableCondition` → `denied_unevaluable_condition`).
fn authorize_forward_host(
    is_generic_lane: bool,
    allowed_targets: Option<&str>,
    target_host: Option<&str>,
) -> HostAuthz {
    match allowed_targets {
        Some(targets) => {
            let entries = core_proxy_forward::parse_allowed_targets(targets);
            let ok = match target_host {
                Some(host) => entries.iter().any(|pattern| {
                    if let Some(domain) = pattern.strip_prefix("*.") {
                        host_matches_domain(host, domain)
                    } else {
                        host == pattern.as_str()
                    }
                }),
                None => false,
            };
            if ok {
                HostAuthz::Allow
            } else {
                HostAuthz::DenyNotInAllowlist
            }
        }
        None if is_generic_lane => HostAuthz::DenyGenericNoAllowlist,
        None => HostAuthz::Allow,
    }
}

fn statement_has_effective_budget(stmt: &core_grant_types::Statement) -> bool {
    stmt.budget
        .as_ref()
        .is_some_and(|budget| !budget.is_none_set())
}

fn request_enables_streaming(uri: &http::Uri, body: &[u8]) -> bool {
    if uri.query().is_some_and(query_enables_streaming) {
        return true;
    }

    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("stream").and_then(|stream| stream.as_bool()))
        .unwrap_or(false)
}

fn query_enables_streaming(query: &str) -> bool {
    query.split('&').any(|pair| {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        if !key.eq_ignore_ascii_case("stream") {
            return false;
        }
        match parts.next() {
            Some(value) => value.eq_ignore_ascii_case("true") || value == "1",
            None => true,
        }
    })
}

fn budgeted_openai_streaming_request_forbidden(
    stmt: &core_grant_types::Statement,
    target_host: &str,
    effective_uri: &http::Uri,
    body: &[u8],
) -> bool {
    statement_has_effective_budget(stmt)
        && pricing::provider_for_host(target_host) == Some(pricing::PROVIDER_OPENAI)
        && request_enables_streaming(effective_uri, body)
}

fn budgeted_openai_streaming_response_forbidden(
    stmt: &core_grant_types::Statement,
    target_host: &str,
    is_streaming_response: bool,
) -> bool {
    is_streaming_response
        && statement_has_effective_budget(stmt)
        && pricing::provider_for_host(target_host) == Some(pricing::PROVIDER_OPENAI)
}

/// Audit any credential-leak (DLP) hits found by the `outbound_leak` scanner
/// (ADR 205 §4). **Detection-only**: the proxy records a leak *fingerprint* —
/// the pattern class, occurrence count, and first byte offset, **never the
/// matched secret bytes** — so an operator can see credential exfiltration
/// through the proxy (or an upstream echoing a secret back), without the proxy
/// itself becoming a place secrets are logged. It does NOT block: a hard deny
/// would false-positive on legitimate secret-bearing API traffic (e.g. an
/// agent rotating a key through a provider API); blocking is a future policy
/// knob layered on this visibility, not the floor.
/// Aggregate DLP hits into a single audit detail string — `Pattern:Location x
/// count @ first_offset`, comma-joined, in stable (sorted) order. Returns
/// `None` for no hits. **Records only the leak *fingerprint*** (class, count,
/// offset) — the matched secret bytes are never included, so the audit log
/// never itself becomes a place secrets land.
fn summarize_dlp_hits(hits: &[core_proxy_forward::outbound_leak::LeakHit]) -> Option<String> {
    if hits.is_empty() {
        return None;
    }
    // Aggregate pattern -> (count, first_offset). Stable order, no secret bytes.
    let mut summary: std::collections::BTreeMap<String, (usize, usize)> =
        std::collections::BTreeMap::new();
    for h in hits {
        let entry = summary
            .entry(format!("{:?}:{:?}", h.pattern, h.location))
            .or_insert((0, h.offset));
        entry.0 += 1;
    }
    Some(
        summary
            .iter()
            .map(|(k, (count, off))| format!("{k}x{count}@{off}"))
            .collect::<Vec<_>>()
            .join(","),
    )
}

async fn audit_dlp_hits<B: PolicyBackend>(
    backend: &B,
    persona_id: &str,
    credential_name: &str,
    event: &str,
    hits: &[core_proxy_forward::outbound_leak::LeakHit],
) {
    let Some(detail) = summarize_dlp_hits(hits) else {
        return;
    };
    tracing::warn!(
        persona_id = %persona_id,
        credential = %credential_name,
        event = %event,
        patterns = %detail,
        "proxy DLP: credential pattern(s) detected (detection-only, not blocked)"
    );
    if let Err(e) = backend
        .log_event(
            persona_id,
            event,
            Some(credential_name),
            "leak_detected",
            Some(&detail),
        )
        .await
    {
        tracing::warn!(error = ?e, persona_id = %persona_id, "DLP log_event failed");
    }
}

/// Public forward entrypoint. Thin timing wrapper over [`handle_request_inner`]
/// (ADR 212 increment 2): measures end-to-end wall-clock per request and hands
/// it to the injected telemetry sink. Latency is observed for EVERY disposition
/// — allowed forward, fail-closed denial, or transport error — so the histogram
/// reflects total proxy handling cost, not just the happy path. The signature
/// is unchanged, so the accept loop calls it identically and the latency
/// observation is a no-op until emberd installs a sink.
pub async fn handle_request<B: PolicyBackend>(
    backend: Arc<B>,
    req: Request<Incoming>,
    session_binding: Option<String>,
) -> Result<Response<ProxyBody>, ForwardError> {
    let started = std::time::Instant::now();
    let result = handle_request_inner(backend, req, session_binding).await;
    crate::telemetry::observe_request(started.elapsed().as_secs_f64());
    result
}

async fn handle_request_inner<B: PolicyBackend>(
    backend: Arc<B>,
    req: Request<Incoming>,
    session_binding: Option<String>,
) -> Result<Response<ProxyBody>, ForwardError> {
    let headers = req.headers();

    let credential_name = match headers
        .get("x-ember-credential")
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.to_string(),
        None => return Ok(bad_request("missing X-Ember-Credential header")),
    };

    let target_url = match headers.get("x-ember-target").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Ok(bad_request("missing X-Ember-Target header")),
    };

    if headers.get("x-ember-grant-id").is_some() {
        return Ok(bad_request(
            "X-Ember-Grant-Id is no longer accepted; use attachment endpoint headers",
        ));
    }

    // P22-S2 (ADR 197 §2): on a per-session peercred-gated UDS the socket path
    // IS the attachment binding and the connection was kernel-attested at
    // accept — resolve the credential identity from the session binding, with
    // NO caller-supplied bearer. The transitional TCP lane has no binding and
    // falls back to the attachment-endpoint headers (attachment_id +
    // endpoint_token) exactly as before. A bearer header presented on the UDS
    // lane is ignored — the socket binding is authoritative.
    let attachment_authority = match session_binding.as_deref() {
        Some(session_id) => backend
            .resolve_attachment_for_session(session_id)
            .await
            .map_err(ForwardError::PolicyBackend)?,
        None => match attachment_endpoint_from_headers(headers) {
            Some((attachment_id, endpoint_token)) => backend
                .resolve_attachment_authority(attachment_id, endpoint_token)
                .await
                .map_err(ForwardError::PolicyBackend)?,
            None => None,
        },
    };

    let persona_id = match attachment_authority.as_ref() {
        Some(authority) => {
            if let Some(asserted) = headers
                .get("x-ember-persona")
                .and_then(|v| v.to_str().ok())
                .filter(|value| !value.is_empty())
                && asserted != authority.runtime_persona_id
            {
                return Ok(forbidden(
                    "X-Ember-Persona does not match attachment authority",
                ));
            }
            authority.runtime_persona_id.clone()
        }
        None => match headers.get("x-ember-persona").and_then(|v| v.to_str().ok()) {
            Some(v) => v.to_string(),
            None => return Ok(bad_request("missing X-Ember-Persona header")),
        },
    };

    // C-1 fix (2026-04-23 adversarial review): collapse scope/forwarding
    // URL split. The forwarding destination is `target_url`; scope checks
    // MUST run against the same authority, not against `req.uri` (which
    // the attacker can forge independently). `effective_scope_uri` rebuilds
    // a canonical URI whose authority always comes from `target_url`.
    let effective_uri = match effective_scope_uri(&target_url, req.uri()) {
        Ok(u) => u,
        Err(msg) => {
            tracing::warn!(
                persona_id = %persona_id,
                credential = %credential_name,
                detail = %msg,
                "invalid X-Ember-Target — denying"
            );
            return Ok(bad_request(&msg));
        }
    };

    let resolved_grant_id = attachment_authority
        .as_ref()
        .map(|authority| authority.grant_id.as_str());

    // Snapshot the HTTP method before req is partially consumed below.
    let req_method_str = req.method().as_str().to_string();

    // Resolve grant + applicable statement via the policy backend. The
    // backend handles: grant lookup, persona/credential validation, status
    // check, per-Statement resolution, and per-Statement revoke check.
    let effective_uri_http: http::Uri = effective_uri
        .to_string()
        .parse()
        .unwrap_or_else(|_| http::Uri::default());
    let resolved = match backend
        .resolve_grant(
            &persona_id,
            &credential_name,
            resolved_grant_id,
            &effective_uri_http,
            &req_method_str,
        )
        .await
    {
        Ok(r) => r,
        Err(core_proxy_forward::PolicyError::NotFound(msg)) => {
            return Ok(forbidden(&msg));
        }
        Err(core_proxy_forward::PolicyError::Forbidden(msg)) => {
            if msg == "no_applicable_statement" || msg == "unsupported HTTP method" {
                return Ok(no_applicable_statement_response());
            } else if msg == "denied_subtarget_scope" || msg == "unevaluable_condition" {
                // ADR 207 seam 8B — both are scope-tightness denials: the
                // request resolved to a statement whose scope (subtarget glob,
                // or an unevaluable condition clamp) does not cover it.
                return Ok(scope_violation_response());
            } else if let Some(sid) = msg.strip_prefix("statement_revoked:") {
                // Beat 7 (SCION 2026-05-15 demo) — structured 403 names which
                // statement was killed so the agent can self-recover or the
                // operator can correlate against the dashboard tile.
                return Ok(statement_revoked_response(&persona_id, sid));
            } else if let Some(rest) = msg.strip_prefix("grant_inactive:") {
                // ADR 190 §4 / ADR 197 §2 — the credential grant lapsed
                // mid-session. Fail closed (no credential injected), but
                // return the base posture's recovery affordance instead of a
                // fatal 403 so the live turn degrades gracefully: `jit` =>
                // re-approvable, `strict` => re-delegate required. Posture is
                // the session's base posture, the unified-lookup point ADR
                // 190 §7 wants the LLM lane to consult. Absent an attachment
                // (raw X-Ember-Persona path) we default to strict — the safer
                // affordance for an unscoped caller. V030-REVOKE-ERROR-MESSAGE:
                // the daemon now appends `:{grant_id}` on the use-time grant-
                // status path; legacy emitters (e.g. `no_live_lease`) carry no
                // grant_id, which we accept and surface as empty.
                let (grant_status, grant_id) = match rest.split_once(':') {
                    Some((status, gid)) => (status, gid),
                    None => (rest, ""),
                };
                let authority_strict = attachment_authority
                    .as_ref()
                    .map(|authority| authority.authority_strict)
                    .unwrap_or(true);
                return Ok(authority_lapsed_response(
                    &persona_id,
                    grant_status,
                    grant_id,
                    authority_strict,
                ));
            }
            return Ok(forbidden(&msg));
        }
        Err(e) => return Err(ForwardError::PolicyBackend(e)),
    };

    // Statement resolution above is the canonical HTTP/LLM authorization
    // boundary. `grant.scope` is a legacy flat projection that cannot
    // faithfully encode composite chains like the Claude launcher's
    // `{credential:read, llm:generate anthropic/*}` statement set.
    //
    // Re-checking the request against `grant.scope` here only creates false
    // denials when the projection is a template id or other coarse metadata.
    // The signed statement chain already bound the request via
    // `request_to_action_resource` + `resolve_statement_for_request_with_uri`.

    // Enforce allowed_targets if the grant specifies them.
    //
    // FINDING-1 fix (cycle 41 Phase E): derive the host from the already-
    // parsed `effective_uri` rather than string-slicing `target_url`. The
    // prior inline parser stopped at the first `/?#`, missing userinfo
    // termination — a target like `https://api.github.com@evil.example/x`
    // would yield `target_host = "api.github.com@evil.example"` and fail
    // the exact-match, then the `target_url.starts_with(pattern)` fallback
    // would match `"api.github.com"` against the URL prefix while Hyper
    // actually forwarded to the userinfo-suffixed real host. Credential
    // exfil vector. Using `hyper::Uri::host()` terminates correctly at `@`
    // and the starts_with fallback is removed entirely.
    // Classify the provider lane for THIS request's destination host using the
    // same canonical mapping the backend matched against. For `github`/`llm`
    // the host is baked into the matched action+resource (a request to the
    // wrong host classifies as `generic` and fails to match a `github:*`/`llm:*`
    // statement), so those lanes are intrinsically host-bound. The `generic`
    // lane's resource is path-only — the host is NEVER folded in — so
    // `allowed_targets` is the ONLY host constraint on a generic credential.
    let is_generic_lane = request_to_action_resource(req.method(), &effective_uri_http)
        .as_ref()
        .and_then(|(action, _)| action.split(':').next())
        == Some("generic");

    match authorize_forward_host(
        is_generic_lane,
        resolved.allowed_targets.as_deref(),
        effective_uri.host(),
    ) {
        HostAuthz::Allow => {
            crate::telemetry::record_host_authz(crate::telemetry::HostAuthzOutcome::Allow);
        }
        HostAuthz::DenyNotInAllowlist => {
            crate::telemetry::record_host_authz(
                crate::telemetry::HostAuthzOutcome::DenyNotInAllowlist,
            );
            return Ok(forbidden(&format!(
                "target {} not in allowed origins: {}",
                target_url,
                resolved.allowed_targets.as_deref().unwrap_or("")
            )));
        }
        HostAuthz::DenyGenericNoAllowlist => {
            crate::telemetry::record_host_authz(
                crate::telemetry::HostAuthzOutcome::DenyGenericNoAllowlist,
            );
            return Ok(forbidden(&format!(
                "generic credential forward to {} refused: the grant has no allowed_targets \
                 host allowlist, so the destination host is unconstrained. Set allowed_targets \
                 on the grant to authorize specific hosts for a generic credential.",
                target_url
            )));
        }
    }

    // SSRF / metadata-IP guard, pre-flight (ADR 205 §4). If `X-Ember-Target`
    // names an IP *literal* in a blocked class — cloud metadata
    // (169.254.169.254 / 100.100.100.200 / fd00:ec2::254), loopback,
    // link-local, RFC-1918, etc. — refuse before any credential is decrypted,
    // with a clear reason. A *hostname* target passes here and is enforced at
    // connect time by the resolver guard on the client below (which also
    // defeats DNS rebinding, since hyper re-resolves through the same guard).
    if let Some(reason) =
        core_proxy_forward::ssrf::host_literal_is_blocked(effective_uri.host().unwrap_or(""))
    {
        tracing::warn!(
            persona_id = %persona_id,
            credential = %credential_name,
            target = %target_url,
            reason = reason.as_str(),
            "proxy: refused forward to blocked destination IP (SSRF/metadata guard)"
        );
        if let Err(e) = backend
            .log_event(
                &persona_id,
                "proxy.denied_ssrf",
                Some(&credential_name),
                "blocked_destination_ip",
                Some(reason.as_str()),
            )
            .await
        {
            tracing::warn!(error = ?e, persona_id = %persona_id, "log_event failed");
        }
        return Ok(forbidden(&format!(
            "target {} refused: destination IP is {} — the proxy does not forward \
             credentials to metadata/internal addresses (SSRF guard)",
            target_url,
            reason.as_str()
        )));
    }

    // Collect the incoming body up front so the Stream C pre-flight
    // budget check has something to estimate against. `body_bytes_in` is
    // then forwarded unchanged.
    //
    // Wrap in Limited so a single oversized POST cannot OOM the daemon.
    let (parts, incoming_body) = req.into_parts();
    let body_bytes_in = match Limited::new(incoming_body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return Ok(payload_too_large("request body exceeds 10 MiB limit"));
        }
        Err(e) => {
            tracing::warn!(error = %e, "request body collection failed");
            return Ok(internal_error("failed to read request body"));
        }
    };

    // Pre-flight Stream C budget check. When the resolved Statement has a
    // `budget.tokens` or `budget.cents` set, estimate the call cost and
    // 429 if it would exceed the remaining allowance. Statements without
    // a budget (TTL-only, credential grants) pass through unchanged.
    match backend
        .preflight_budget(&resolved, body_bytes_in.as_ref())
        .await
    {
        Ok(core_proxy_forward::PreflightDecision::Allowed) => {}
        Ok(core_proxy_forward::PreflightDecision::Rejected { axis, limit, used }) => {
            tracing::warn!(
                grant_id = %resolved.grant_id,
                statement_sid = %resolved.statement_sid,
                axis,
                limit,
                used,
                "budget pre-flight rejection"
            );
            if let Err(e) = backend
                .log_event(
                    &persona_id,
                    "proxy.denied_preflight",
                    Some(&credential_name),
                    "budget_exhausted",
                    Some(&format!(
                        "grant_id={} sid={} axis={axis} limit={limit} used={used}",
                        resolved.grant_id, resolved.statement_sid
                    )),
                )
                .await
            {
                tracing::warn!(error = ?e, grant_id = %resolved.grant_id, statement_sid = %resolved.statement_sid, axis, "log_event failed");
            }
            return Ok(budget_exhausted_response(
                &resolved.grant_id,
                &resolved.statement_sid,
                axis,
                limit,
                used,
            ));
        }
        Err(e) => {
            tracing::warn!(error = ?e, "preflight_budget backend error");
            return Err(ForwardError::PolicyBackend(e));
        }
    }

    let target_host_lower: String = extract_host_from_url(&target_url).unwrap_or_default();
    if budgeted_openai_streaming_request_forbidden(
        &resolved.statement,
        &target_host_lower,
        &effective_uri_http,
        body_bytes_in.as_ref(),
    ) {
        tracing::warn!(
            persona_id = %persona_id,
            credential = %credential_name,
            grant_id = %resolved.grant_id,
            statement_sid = %resolved.statement_sid,
            target_host = %target_host_lower,
            "budgeted OpenAI streaming request is not meterable yet — failing closed before credential injection"
        );
        if let Err(e) = backend
            .log_event(
                &persona_id,
                "proxy.denied_stream_budget",
                Some(&credential_name),
                "openai_streaming_unmetered",
                Some("budgeted OpenAI stream request blocked before upstream forwarding"),
            )
            .await
        {
            tracing::warn!(error = ?e, persona_id = %persona_id, credential = %credential_name, "log_event failed");
        }
        return Ok(openai_streaming_budget_gate_response());
    }

    // Decrypt credential from vault via backend.
    // Wrap in Zeroizing so the raw key bytes are wiped on drop.
    let credential_value: Zeroizing<String> = match backend.get_credential(&credential_name).await {
        Ok(v) => v,
        Err(core_proxy_forward::PolicyError::NotFound(_)) => {
            return Ok(internal_error("credential not found in vault"));
        }
        Err(e) => {
            tracing::warn!(
                error = ?e,
                persona_id = %persona_id,
                credential = %credential_name,
                "vault decrypt failed"
            );
            return Err(ForwardError::PolicyBackend(e));
        }
    };

    // Log the access
    if let Err(e) = backend
        .log_event(
            &persona_id,
            "credential.access",
            Some(&credential_name),
            "allowed",
            None,
        )
        .await
    {
        tracing::warn!(error = ?e, persona_id = %persona_id, credential = %credential_name, "log_event failed");
    }

    // Build an HTTPS-capable client using rustls with system WebPKI roots,
    // with the SSRF / metadata-IP guard wired into the DNS resolver (ADR 205 §4).
    let client = build_guarded_forward_client();

    // P69L.0a: Detect git smart-HTTP paths and branch to Basic auth.
    //
    // Git smart-HTTP transports (`/info/refs?service=git-*-pack` and
    // `/{repo}.git/git-{receive,upload}-pack`) require `Authorization:
    // Basic base64("x-access-token:{token}")` — Bearer is rejected by
    // GitHub's git backend. The detection runs against the effective URI's
    // path+query (derived from `X-Ember-Target`), which is already the
    // single authoritative source used for scope enforcement.
    let effective_path_and_query = effective_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(effective_uri.path());
    let is_git_transport = is_git_smart_http_path(effective_path_and_query);

    // DLP, outbound (ADR 205 §4). Scan the agent-authored URL and request body
    // for known credential fingerprints before forwarding — detects an agent
    // exfiltrating a secret (its own, or one harvested from the host) OUT
    // through the proxy. Detection-only; never logs the secret bytes.
    {
        use core_proxy_forward::outbound_leak::{LeakLocation, scan_body, scan_url};
        let mut hits = scan_url(effective_path_and_query);
        hits.extend(scan_body(body_bytes_in.as_ref(), LeakLocation::RequestBody));
        audit_dlp_hits(
            backend.as_ref(),
            &persona_id,
            &credential_name,
            "proxy.dlp_outbound",
            &hits,
        )
        .await;
    }

    // Build the outgoing request to the upstream. Use `effective_uri`,
    // which composes scheme+authority from `X-Ember-Target` with the
    // request's actual path+query — using the bare `target_url` would
    // forward `POST https://api.anthropic.com/` (root) instead of
    // `POST https://api.anthropic.com/v1/messages`, which Cloudflare
    // serves as a 502 with no useful tracing on our side.
    let mut outgoing = Request::builder()
        .method(parts.method.clone())
        .uri(effective_uri.to_string());

    // Forward only the explicitly-allowed headers to upstream.
    // Allowlist replaces the former blocklist.
    // Cookie, Host, X-Forwarded-*, Forwarded, Via, Authorization, and every
    // other header not in ALLOWED_REQUEST_HEADERS are dropped silently.
    // Authorization is injected from the vault below — client-supplied
    // credentials never reach upstream.
    outgoing = filter_request_headers(outgoing, &parts.headers);

    // Inject the credential in the format the upstream provider expects.
    //
    // Three branches, picked by upstream identity:
    //  1. Anthropic (`api.anthropic.com` and any subdomain) requires
    //     `x-api-key: <token>` and rejects `Authorization: Bearer ...` with
    //     401. Prior unconditional Bearer injection broke every Anthropic
    //     SDK call.
    //  2. Git smart-HTTP (`/info/refs?service=git-*-pack`,
    //     `/{repo}.git/git-{receive,upload}-pack`) requires
    //     `Authorization: Basic base64("x-access-token:{token}")` — Bearer
    //     is rejected by GitHub's git backend.
    //  3. Everything else: generic `Authorization: Bearer <token>`.
    //
    // We use `headers_mut().insert` post-build (rather than chained
    // `.header()`) because `Builder::header` *appends*; if a client sent
    // a placeholder `x-api-key` (the demo SDK does — `api_key="placeholder"`)
    // the allowlist would have to drop it AND we'd still want last-write-
    // wins semantics for the injected credential. Insert replaces, so the
    // client's value is overridden cleanly even if it slipped past the
    // allowlist somehow.
    //
    let mut outgoing_req = outgoing.body(Full::new(body_bytes_in)).map_err(|e| {
        tracing::warn!(error = %e, "failed to build outgoing request");
        ForwardError::Http(e)
    })?;

    let auth_scheme = match inject_provider_auth(
        outgoing_req.headers_mut(),
        &target_host_lower,
        is_git_transport,
        &credential_name,
        &credential_value,
    ) {
        Ok(scheme) => scheme,
        Err(()) => {
            tracing::warn!(
                persona_id = %persona_id,
                credential = %credential_name,
                "credential is not a valid header value"
            );
            return Ok(internal_error(
                "credential not representable as a header value",
            ));
        }
    };
    tracing::debug!(
        persona_id = %persona_id,
        credential = %credential_name,
        target_host = %target_host_lower,
        scheme = auth_scheme.as_str(),
        "auth header injected"
    );

    // Force uncompressed responses upstream
    // so the post-flight meter can parse JSON usage blocks. Anthropic
    // (and OpenAI) default to `gzip` if Accept-Encoding is absent or
    // permissive; identity is the only encoding `parse_usage` understands
    // without an additional decompression step.
    outgoing_req.headers_mut().insert(
        hyper::header::ACCEPT_ENCODING,
        hyper::header::HeaderValue::from_static("identity"),
    );

    let upstream_resp = client.request(outgoing_req).await.map_err(|e| {
        tracing::warn!(error = %e, "upstream request failed");
        ForwardError::Client(e)
    })?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    // P69L.1 streaming detection. Anthropic's `/v1/messages` endpoint emits
    // `message_delta` events as Server-Sent Events with
    // `Content-Type: text/event-stream`. Some providers also use bare
    // `Transfer-Encoding: chunked` without SSE framing (rare for LLM
    // responses, but we honour it so the proxy doesn't silently buffer
    // multi-MB replies). Any other response is treated as a complete
    // payload and goes through the legacy `.collect()` path — this keeps
    // small JSON-shaped responses metered exactly as before.
    let is_streaming_response = is_streaming_upstream(&resp_headers);
    let target_host: String = extract_host_from_url(&target_url).unwrap_or_default();
    tracing::debug!(
        target: "proxy.meter.route",
        target_host = %target_host,
        is_streaming = is_streaming_response,
        content_type = %resp_headers
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        content_encoding = %resp_headers
            .get(hyper::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        transfer_encoding = %resp_headers
            .get(hyper::header::TRANSFER_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "proxy: classifying upstream response for metering"
    );

    if is_streaming_response {
        if budgeted_openai_streaming_response_forbidden(
            &resolved.statement,
            &target_host,
            is_streaming_response,
        ) {
            tracing::warn!(
                persona_id = %persona_id,
                credential = %credential_name,
                grant_id = %resolved.grant_id,
                statement_sid = %resolved.statement_sid,
                target_host = %target_host,
                "budgeted OpenAI streaming response is not meterable yet — failing closed before downstream delivery"
            );
            if let Err(e) = backend
                .log_event(
                    &persona_id,
                    "proxy.denied_stream_budget",
                    Some(&credential_name),
                    "openai_streaming_unmetered_response",
                    Some("budgeted OpenAI streaming response blocked before downstream delivery"),
                )
                .await
            {
                tracing::warn!(error = ?e, persona_id = %persona_id, credential = %credential_name, "log_event failed");
            }
            return Ok(openai_streaming_budget_gate_response());
        }

        // C44-TEE-MEM: gate the streaming path on a per-process
        // concurrency cap BEFORE we commit to building a TeeBody. Each
        // TeeBody owns a buffer up to `MAX_STREAMING_RESPONSE_BYTES`;
        // without this gate a hostile or slow-reading client could
        // pin arbitrarily many of them and OOM the daemon. 503 +
        // Retry-After is the correct wire signal for "transiently
        // over-subscribed" — well-behaved clients will back off.
        let Some(streaming_slot) = StreamingSlot::try_acquire() else {
            tracing::warn!(
                inflight = STREAMING_REQUESTS_INFLIGHT.load(Ordering::Acquire),
                cap = MAX_CONCURRENT_STREAMING,
                target = %target_host,
                "streaming-request concurrency cap reached — rejecting"
            );
            // Metering intentionally skipped: the upstream request was
            // already sent (we needed its response headers to
            // classify as streaming), but we haven't forwarded any
            // bytes to the client. Treating the saturation event as
            // a non-billable daemon-internal failure is the
            // conservative choice. Log it in the audit trail so
            // operators can spot sustained saturation.
            if let Err(e) = backend
                .log_event(
                    &persona_id,
                    "proxy.stream",
                    Some(&credential_name),
                    "rejected",
                    Some(&format!(
                        "streaming concurrency cap {MAX_CONCURRENT_STREAMING} reached"
                    )),
                )
                .await
            {
                tracing::warn!(error = ?e, persona_id = %persona_id, credential = %credential_name, "log_event failed");
            }
            return Ok(service_unavailable(
                "streaming concurrency cap reached; retry shortly",
            ));
        };

        // Tee the upstream body straight to the client while an
        // accumulator in `TeeBody` collects the raw bytes for
        // post-flight metering. When the upstream signals end-of-body
        // (or trips the size cap), `TeeBody` fires the meter callback
        // synchronously from `poll_frame` so the audit/budget
        // bookkeeping matches the buffered path exactly.
        let meter_backend = Arc::clone(&backend);
        let meter_resolved = resolved.clone();
        let meter_host = target_host.clone();
        // Capture the upstream
        // status's 2xx-ness for the meter callback. The closure runs
        // post-flight on the tee thread; `status` itself is moved into
        // the response builder below, so we snapshot the bool here.
        let meter_upstream_ok = status.is_success();
        // Beat 4 demo observability: snapshot per-call context for the
        // `proxy_call` event the meter callback emits. The closure runs
        // post-flight on the tee thread, so every field that travels in
        // the event must be owned (no borrows of `parts`, `effective_uri`,
        // `status`).
        let meter_method = parts.method.as_str().to_string();
        let meter_path = effective_uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| effective_uri.path().to_string());
        let meter_status_code = status.as_u16();
        let meter_cb = TeeMeterCallback::new(
            move |summary: pricing::UsageSummary, tee_outcome: StreamOutcome| {
                // C44-TEE-INCR-PARSE: the SSE wire format itself tells
                // us whether `message_stop` arrived. With incremental
                // parsing the flag is already on `UsageSummary`, so we
                // can downgrade Complete → Partial without a second
                // pass over the bytes (which we no longer keep). The
                // downgrade only applies to Anthropic streams; non-SSE
                // bodies keep the tee-level outcome unchanged.
                let outcome = if tee_outcome == StreamOutcome::Complete
                    && pricing::provider_for_host(&meter_host) == Some(pricing::PROVIDER_ANTHROPIC)
                    && summary.saw_any_usage
                    && !summary.saw_message_stop
                {
                    StreamOutcome::Partial
                } else {
                    tee_outcome
                };

                let usage = usage_from_summary(&meter_host, &summary).map(|mut delta| {
                    delta.requests = record_upstream_request(
                        &meter_host,
                        meter_upstream_ok,
                        summary.saw_any_usage,
                    );
                    delta
                });

                // Beat 4 demo observability — same shape as the buffered
                // path. SSE summaries already split tokens into in/out;
                // fold cache-creation + cache-read into input_tokens to
                // match `folded_usage()` semantics, which is the value
                // billing uses too.
                let pu = summary.folded_usage();
                let proxy_call = ProxyCallReceiptRequest {
                    method: meter_method,
                    path: meter_path,
                    status: meter_status_code,
                    tokens_in: pu.input_tokens,
                    tokens_out: pu.output_tokens,
                    outcome: outcome.audit_tag().to_string(),
                };

                let backend = Arc::clone(&meter_backend);
                let resolved = meter_resolved.clone();
                tokio::task::spawn_local(async move {
                    if let Err(e) = backend.post_flight(&resolved, usage).await {
                        tracing::warn!(
                            error = ?e,
                            grant_id = %resolved.grant_id,
                            "post_flight failed in streaming meter"
                        );
                    }
                    if let Some(receipt_id) =
                        signed_proxy_call_receipt_id(backend.as_ref(), &resolved, &proxy_call).await
                    {
                        emit_proxy_call_event(&resolved, &proxy_call, &receipt_id);
                    }
                });
            },
        );

        let tee_body = TeeBody::new_with_slot(
            upstream_resp.into_body(),
            MAX_STREAMING_RESPONSE_BYTES,
            meter_cb,
            Some(streaming_slot),
        );

        let mut builder = Response::builder().status(status);
        for (name, value) in &resp_headers {
            // Drop `Content-Length` — chunked streaming doesn't carry a
            // known length. Hyper will set the correct framing on the
            // way out.
            if name.as_str().eq_ignore_ascii_case("content-length") {
                continue;
            }
            builder = builder.header(name, value);
        }
        return Ok(builder.body(ProxyBody::Streaming(tee_body)).unwrap());
    }

    // Cap non-streaming response bodies at MAX_BODY_BYTES too.
    // An upstream that returns a multi-hundred-MiB body would otherwise OOM
    // the daemon while buffering it for the post-flight meter.
    let resp_body = match Limited::new(upstream_resp.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return Ok(payload_too_large(
                "upstream response body exceeds 10 MiB limit",
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream response body collection failed");
            return Ok(internal_error("failed to read upstream response body"));
        }
    };

    // DLP, inbound (ADR 205 §4) — the "server echoes a secret back" case. Scan
    // the buffered upstream response for known credential fingerprints.
    // Detection-only; never logs the secret bytes. NOTE: streamed (SSE)
    // responses take the TeeBody path above and are NOT scanned here — that, and
    // the codex-responses lane, are documented follow-ups (BKR-2b2 covers the
    // main forward path's outbound url+body and buffered responses).
    audit_dlp_hits(
        backend.as_ref(),
        &persona_id,
        &credential_name,
        "proxy.dlp_response",
        &core_proxy_forward::outbound_leak::scan_response(resp_body.as_ref()),
    )
    .await;

    // Stream C post-flight meter. Resolve the upstream host and parse
    // the response for token + cent usage. If the target isn't an LLM
    // provider we have pricing for, `meter_response` returns `None` and
    // we skip the increment — the request still forwards unchanged.
    //
    // Pass `status.is_success()`
    // so the meter only credits a billable request to the grant when
    // the upstream actually returned 2xx. A 5xx with a usage-shaped
    // body (rare) does not count.
    let usage = meter_response(&target_host, resp_body.as_ref()).map(|mut delta| {
        delta.requests = record_upstream_request(&target_host, status.is_success(), true);
        delta
    });
    if let Err(e) = backend.post_flight(&resolved, usage).await {
        tracing::warn!(error = ?e, grant_id = %resolved.grant_id, "post_flight failed");
    }

    // Beat 4 demo observability: emit a per-call event so the orchestrator
    // status tail can render `[proxy <agent>] METHOD /path — 200 — N tokens
    // — Receipt <signed-receipt-id>`. Split input/output tokens via a fresh
    // parse_usage call — the buffered body is still in scope. Non-LLM hosts
    // (GitHub etc.) skip token reporting; we still emit a `proxy_call` event
    // when the backend receipt subsystem can mint a signed call receipt.
    {
        let (tin, tout) = pricing::provider_for_host(&target_host)
            .and_then(|provider| pricing::parse_usage(provider, resp_body.as_ref()))
            .map(|pu| (pu.input_tokens, pu.output_tokens))
            .unwrap_or((0, 0));
        let path = effective_uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| effective_uri.path().to_string());
        let proxy_call = ProxyCallReceiptRequest {
            method: parts.method.as_str().to_string(),
            path,
            status: status.as_u16(),
            tokens_in: tin,
            tokens_out: tout,
            outcome: StreamOutcome::Complete.audit_tag().to_string(),
        };
        if let Some(receipt_id) =
            signed_proxy_call_receipt_id(backend.as_ref(), &resolved, &proxy_call).await
        {
            emit_proxy_call_event(&resolved, &proxy_call, &receipt_id);
        }
    }

    let mut builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        builder = builder.header(name, value);
    }

    Ok(builder.body(box_full(Full::new(resp_body))).unwrap())
}

// ===== moved from proxy.rs lines 2177-2231 =====
/// True when the upstream response should be forwarded chunk-by-chunk
/// rather than buffered. We treat SSE (`text/event-stream`) and raw
/// chunked transfer as streaming; everything else is assumed
/// JSON-complete-per-response and goes through the buffered meter path.
pub fn is_streaming_upstream(headers: &hyper::HeaderMap) -> bool {
    if let Some(ct) = headers.get(hyper::header::CONTENT_TYPE)
        && let Ok(ct_str) = ct.to_str()
    {
        // Split on `;` to tolerate `text/event-stream; charset=utf-8`.
        let mime = ct_str.split(';').next().unwrap_or("").trim();
        if mime.eq_ignore_ascii_case("text/event-stream") {
            return true;
        }
    }
    if let Some(te) = headers.get(hyper::header::TRANSFER_ENCODING)
        && let Ok(te_str) = te.to_str()
        && te_str
            .split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
    {
        return true;
    }
    false
}

/// How a streaming response terminated. P69L.1: the receipt / audit trail
/// differentiates a clean stream (`Complete`) from one that was cut short
/// (`Partial`) so operators can tell a fully-metered call from one where
/// the agent was billed for fewer output tokens than it likely produced.
///
/// `Complete` is the only outcome the buffered path can return — a
/// non-streaming response either arrives in full or the request errors
/// before `run_post_flight_meter` is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOutcome {
    /// Buffered (non-streaming) response, or an SSE stream that saw a
    /// terminal `message_stop` event.
    Complete,
    /// Streaming response that ended without a terminal marker — upstream
    /// disconnect, client hang-up, or the daemon's size cap aborted the
    /// tee. Usage for what we *did* see is still recorded.
    Partial,
}

impl StreamOutcome {
    /// Tag appended to the audit log's `outcome`/`details` column so
    /// `ember audit` output distinguishes complete from interrupted
    /// streams at a glance. Keep in sync with any dashboard consumers.
    pub fn audit_tag(self) -> &'static str {
        match self {
            StreamOutcome::Complete => "complete",
            StreamOutcome::Partial => "partial",
        }
    }
}

async fn signed_proxy_call_receipt_id<B: PolicyBackend>(
    backend: &B,
    resolved: &ResolvedGrant,
    call: &ProxyCallReceiptRequest,
) -> Option<String> {
    match backend.issue_proxy_call_receipt(resolved, call).await {
        Ok(Some(receipt_id)) if !receipt_id.trim().is_empty() => Some(receipt_id),
        Ok(Some(_)) => {
            tracing::warn!(
                grant_id = %resolved.grant_id,
                "proxy_call receipt emission returned an empty receipt_id"
            );
            None
        }
        Ok(None) => {
            tracing::warn!(
                grant_id = %resolved.grant_id,
                "proxy_call event omitted because backend did not mint a signed receipt"
            );
            None
        }
        Err(error) => {
            tracing::warn!(
                grant_id = %resolved.grant_id,
                error = ?error,
                "proxy_call receipt emission failed"
            );
            None
        }
    }
}

// ===== moved from proxy.rs lines 2248-2337 =====
/// Beat 4 (SCION × Emberlink demo 2026-05-15) — emit a `proxy_call` event
/// into `.ember/engine/events.jsonl` so the orchestrator status tail can
/// render one log line per upstream call:
///
/// ```text
///   [proxy <agent>] POST /v1/messages — 200 — 312 tokens — Receipt <receipt-id>
/// ```
///
/// The event sits alongside the existing `proxy.meter` audit row (which is
/// the authoritative billing record). This emission is for human-visible
/// observability during the demo and is best-effort: errors are swallowed
/// so an unwritable `.ember/engine/` directory can never wedge the proxy.
///
/// proxy_call_receipt_id_is_signed: the receipt ID is supplied by
/// [`PolicyBackend::issue_proxy_call_receipt`], whose daemon implementation
/// signs and persists a ReceiptEnvelope before this JSONL event is appended.
pub fn emit_proxy_call_event(
    resolved: &ResolvedGrant,
    call: &ProxyCallReceiptRequest,
    receipt_id: &str,
) {
    // Resolve the primary worktree root + engine event-log path via the shared
    // layout contract (core-construct-runtime, below both this forwarding core
    // and the engine per ADR 183/184). Fall back to cwd on failure — the daemon
    // is typically launched from the repo root; this is a best-effort
    // observability path.
    let root = core_construct_runtime::layout::primary_worktree_root()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let events_path = root.join(core_construct_runtime::layout::ENGINE_EVENTS_FILE);

    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let line = serde_json::json!({
        "event": "proxy_call",
        "ts": ts,
        "agent_id": &resolved.persona_id,
        "persona_id": &resolved.persona_id,
        "grant_id": &resolved.grant_id,
        "statement_sid": &resolved.statement_sid,
        "method": &call.method,
        "path": &call.path,
        "status": call.status,
        "tokens_in": call.tokens_in,
        "tokens_out": call.tokens_out,
        "outcome": &call.outcome,
        "receipt_id": receipt_id,
    });
    let serialized = match serde_json::to_string(&line) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = ?e, "proxy_call event: serialize failed");
            return;
        }
    };
    if let Err(e) = core_construct_runtime::layout::append_line(&events_path, &serialized) {
        tracing::warn!(
            error = ?e,
            path = %events_path.display(),
            "proxy_call event: append_line failed (best-effort observability — proxy continues)"
        );
    }
}

// ===== moved from proxy.rs lines 2593-2818 =====
/// Returns `None` for non-LLM hosts or when the summary saw no usage at
/// all — matches the byte-slice `meter_response` semantics so the audit
/// trail and budget machinery behave identically across the two paths.
///
/// `requests` is left at 0 here.
/// Callers add the upstream-confirmed request count via
/// `record_upstream_request` so a network failure / 5xx doesn't inflate
/// the receipt's request tally.
pub fn usage_from_summary(
    target_host: &str,
    summary: &pricing::UsageSummary,
) -> Option<core_grant_types::Usage> {
    let provider = pricing::provider_for_host(target_host)?;
    if !summary.saw_any_usage {
        return None;
    }
    let folded = summary.folded_usage();
    let model = summary.model.clone().unwrap_or_default();
    // Micro-cent precision. See meter_response
    // for the full rationale; the SSE path mirrors the buffered path so
    // both metering routes accumulate budget identically.
    let cents_micro =
        pricing::cents_micro_for(&model, provider, folded.input_tokens, folded.output_tokens);
    Some(core_grant_types::Usage {
        tokens: folded.input_tokens.saturating_add(folded.output_tokens),
        cents: cents_micro / 1_000_000,
        cents_micro,
        // Filled in by the caller
        // via `record_upstream_request` once upstream confirmation is
        // known. Leaving this at 0 here means a path that observes
        // tokens but not a confirmed upstream response (none of the
        // current call sites — but a future one) would not double-count.
        requests: 0,
        workload_hours: 0,
        wall_clock_secs: 0,
        last_updated: 0,
    })
}

pub type TeeMeterFn = dyn FnOnce(pricing::UsageSummary, StreamOutcome);

/// Callback invoked by `TeeBody` when the upstream stream ends (cleanly or
/// via the size cap).
///
/// C44-TEE-INCR-PARSE: the callback used to receive the full byte buffer
/// `(&[u8], StreamOutcome)`. That forced `TeeBody` to accumulate every
/// upstream byte up to a 1 MiB cap — N concurrent stalled streams was
/// `N * 1 MiB` of pinned RSS. The signature now takes a structured
/// `UsageSummary` produced by the incremental SSE parser, so per-stream
/// memory is bounded at `SSE_PARTIAL_FRAME_CAP_BYTES` (8 KiB) regardless
/// of stream length.
pub struct TeeMeterCallback {
    inner: Option<Box<TeeMeterFn>>,
}

impl TeeMeterCallback {
    pub fn new<F: FnOnce(pricing::UsageSummary, StreamOutcome) + 'static>(f: F) -> Self {
        Self {
            inner: Some(Box::new(f)),
        }
    }

    /// Consume the callback and run the meter exactly once. Subsequent
    /// calls are no-ops — defends against `poll_frame` returning
    /// `Ready(None)` after a cap-abort already fired the meter.
    fn fire(&mut self, summary: pricing::UsageSummary, outcome: StreamOutcome) {
        if let Some(f) = self.inner.take() {
            f(summary, outcome);
        }
    }
}

/// Streaming response body that (a) forwards each upstream frame to the
/// client as it arrives and (b) feeds an incremental SSE parser so
/// post-flight metering runs against a structured `UsageSummary` rather
/// than a raw byte buffer.
///
/// C44-TEE-INCR-PARSE: this struct used to hold a `Vec<u8> accumulator`
/// capped at `MAX_STREAMING_RESPONSE_BYTES` (1 MiB). N concurrent stalled
/// streams pinned `N * 1 MiB` of RSS and the meter could only see usage
/// after the full body had been buffered. The accumulator is gone — only
/// the parser's internal partial-frame buffer (≤ 8 KiB) lives alongside
/// the body. Total bytes streamed are still tracked against `cap_bytes`
/// for DoS protection (an abusive upstream that streams gigabytes of
/// junk still trips the cap), but the cap is on a counter, not a buffer.
///
/// Generic over the underlying body type so tests can feed a channel-backed
/// mock without needing a real `hyper::body::Incoming`.
pub struct TeeBody<B> {
    inner: B,
    /// Incremental SSE parser. Owns a bounded partial-frame buffer
    /// (`SSE_PARTIAL_FRAME_CAP_BYTES` = 8 KiB) and the running
    /// `UsageSummary`. Replaces the old raw-byte accumulator.
    parser: pricing::AnthropicSseStreamParser,
    /// Total upstream bytes seen — cap protects the daemon against an
    /// abusive upstream that streams unbounded junk. Counter only; the
    /// bytes themselves are not retained.
    bytes_seen: usize,
    cap_bytes: usize,
    meter: TeeMeterCallback,
    /// `true` once the stream has emitted its terminal frame (success,
    /// upstream error, or cap abort). Prevents the runtime from
    /// re-polling and re-triggering the meter.
    terminated: bool,
    /// `true` once the size cap has been tripped. Readable by tests;
    /// surfaced on the wire only by ending the stream early with
    /// `Ready(None)`. `pub` so ember-daemon's in-tree `proxy::tests` can
    /// assert the cap-abort flag across the crate boundary.
    pub cap_exceeded: bool,
    /// Concurrency-gate slot. Present for production streams created
    /// via `handle_request`'s gated path; `None` in unit tests that
    /// exercise the tee shape without going through the gate. Dropped
    /// when the body itself is dropped, which releases the slot on
    /// every terminal path including client disconnect mid-stream.
    _slot: Option<StreamingSlot>,
}

impl<B> TeeBody<B> {
    /// Test-only constructor that creates an ungated `TeeBody`. Production
    /// code must use `new_with_slot` so the concurrency gate decrement
    /// fires on drop. Guarded by `#[cfg(any(test, feature = "test-support"))]` so the unit tests can
    /// drive a TeeBody without touching `STREAMING_REQUESTS_INFLIGHT`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(inner: B, cap_bytes: usize, meter: TeeMeterCallback) -> Self {
        Self::new_with_slot(inner, cap_bytes, meter, None)
    }

    pub fn new_with_slot(
        inner: B,
        cap_bytes: usize,
        meter: TeeMeterCallback,
        slot: Option<StreamingSlot>,
    ) -> Self {
        Self {
            inner,
            parser: pricing::AnthropicSseStreamParser::new(),
            bytes_seen: 0,
            cap_bytes,
            meter,
            terminated: false,
            cap_exceeded: false,
            _slot: slot,
        }
    }

    /// Test-only accessor for the parser's bounded partial-frame buffer
    /// size — used to assert the per-stream memory invariant.
    #[cfg(any(test, feature = "test-support"))]
    pub fn buffered_bytes(&self) -> usize {
        self.parser.buffered_bytes()
    }
}

impl<B> Body for TeeBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.terminated {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                // Clean upstream EOF. The body-level outcome is `Complete`;
                // if the body shape (SSE) lacks a terminal `message_stop`,
                // the meter callback downgrades to `Partial` based on the
                // structured `UsageSummary` (no second pass over bytes).
                self.terminated = true;
                let summary = self.parser.take_summary();
                self.meter.fire(summary, StreamOutcome::Complete);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                // Upstream error aborts the tee; always `Partial` — we
                // cannot have seen the terminal frame. Still run the
                // meter so usage up to the error is recorded.
                self.terminated = true;
                let summary = self.parser.take_summary();
                self.meter.fire(summary, StreamOutcome::Partial);
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(chunk) = frame.data_ref() {
                    let new_total = self.bytes_seen.saturating_add(chunk.len());
                    if new_total > self.cap_bytes {
                        tracing::warn!(
                            cap = self.cap_bytes,
                            observed = new_total,
                            "proxy streaming response exceeded size cap — aborting"
                        );
                        self.terminated = true;
                        self.cap_exceeded = true;
                        let summary = self.parser.take_summary();
                        // Cap abort is always partial — we deliberately
                        // cut the stream short to protect daemon memory.
                        self.meter.fire(summary, StreamOutcome::Partial);
                        return Poll::Ready(None);
                    }
                    self.bytes_seen = new_total;
                    // Feed the parser incrementally — bounded partial-frame
                    // buffer absorbs cross-chunk frame splits while the
                    // running summary stays current.
                    self.parser.feed(chunk);
                }
                Poll::Ready(Some(Ok(frame)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminated
    }

    fn size_hint(&self) -> SizeHint {
        // Upstream size hint is usually unknown for SSE / chunked. We
        // don't forward it — hyper will pick chunked encoding on our
        // downstream response.
        SizeHint::default()
    }
}

// ===== moved from proxy.rs lines 2820-2904 =====
/// Extract the host from a URL string (e.g. `https://api.anthropic.com/v1`).
/// Returns `None` if the URL is malformed.
/// Provider-aware auth injection for the LLM/HTTP proxy.
///
/// Replaces any client-supplied `Authorization` / `x-api-key` header with a
/// vault-resolved credential in the format the upstream provider expects:
///
/// - **Anthropic** (`api.anthropic.com` and any subdomain): `x-api-key`
///   header for API-key credentials, or `Authorization: Bearer ...` for
///   Claude subscription OAuth credentials.
/// - **Git smart-HTTP**: `Authorization: Basic base64("x-access-token:{token}")`.
/// - **Anything else**: `Authorization: Bearer {token}`.
///
/// Returns `Ok(())` on success and `Err(())` if the credential value cannot
/// be turned into a `HeaderValue` (control chars, newlines, etc.). Callers
/// translate the error into a 500 — a credential the daemon can't even
/// transport upstream is an integrity failure of the vault, not a request
/// problem.
///
/// Prior code unconditionally injected `Authorization: Bearer ...`, which
/// broke every Anthropic SDK call.
// () error is intentional; richer error type is out of scope for the lint-clear.
#[allow(clippy::result_unit_err)]
pub fn inject_provider_auth(
    headers: &mut hyper::HeaderMap,
    target_host_lower: &str,
    is_git_transport: bool,
    credential_name: &str,
    credential: &str,
) -> Result<AuthScheme, ()> {
    let credential = credential.trim_end_matches(['\r', '\n']);

    // Defence-in-depth: strip any client-supplied auth headers before
    // injecting our vault-resolved value. The request-header allowlist
    // already drops `authorization` and `x-api-key`, but `remove` is cheap
    // insurance against future allowlist drift.
    headers.remove("authorization");
    headers.remove("x-api-key");

    if host_matches_domain(target_host_lower, "anthropic.com") {
        // Plan/subscription OAuth credentials (the `sk-ant-oat01…` token) inject
        // `Authorization: Bearer …` + the load-bearing oauth beta marker; API
        // keys inject `x-api-key`. The plan-OAuth lane is named by the
        // standardized prefix `anthropic/plan/claude-oauth/<fingerprint>` — keep
        // this in sync with the daemon-side selector (handlers/session.rs
        // is_anthropic_gateway_credential_name) and emberlink-cli grant.rs;
        // they must not drift (an exact-slug mismatch here silently injects the
        // OAuth token as an API key with no beta marker → Anthropic 401s).
        // The legacy flat `anthropic/oauth-token` is still recognized so a
        // not-yet-re-minted credential authenticates correctly instead of
        // silently falling through to the x-api-key branch.
        const ANTHROPIC_PLAN_OAUTH_PREFIX: &str = "anthropic/plan/claude-oauth/";
        if credential_name.starts_with(ANTHROPIC_PLAN_OAUTH_PREFIX)
            || credential_name == "anthropic/oauth-token"
        {
            let bearer = format!("Bearer {}", credential);
            let bearer_value = hyper::header::HeaderValue::from_str(&bearer).map_err(|_| ())?;
            headers.insert("authorization", bearer_value);
            // Guarantee the OAuth-acceptance beta marker is present. Claude Code
            // sends its own feature-beta set but NOT this marker (confirmed
            // against claude v2.1.158), so merge it into any client-supplied
            // `anthropic-beta` (preserving the feature betas) rather than
            // clobbering. Without it `api.anthropic.com` rejects the OAuth token.
            ensure_anthropic_oauth_beta(headers)?;
            return Ok(AuthScheme::Bearer);
        }
        let key = hyper::header::HeaderValue::from_str(credential).map_err(|_| ())?;
        headers.insert("x-api-key", key);
        return Ok(AuthScheme::Anthropic);
    }
    if is_git_transport {
        let basic = build_github_basic_auth(credential);
        let basic_value = hyper::header::HeaderValue::from_str(&basic).map_err(|_| ())?;
        headers.insert("authorization", basic_value);
        return Ok(AuthScheme::Basic);
    }
    let bearer = format!("Bearer {}", credential);
    let bearer_value = hyper::header::HeaderValue::from_str(&bearer).map_err(|_| ())?;
    headers.insert("authorization", bearer_value);
    Ok(AuthScheme::Bearer)
}

/// The load-bearing `anthropic-beta` marker that makes `api.anthropic.com`
/// accept a Pro/Max OAuth access token (`sk-ant-oat...`) on the Claude Code
/// path. Claude Code sends a wider feature-beta set but does NOT emit this
/// OAuth marker (confirmed against claude v2.1.158), so the proxy must
/// guarantee it whenever it injects an `anthropic/oauth-token` credential.
/// Without it the request authenticates as a plain (non-OAuth) call and the
/// OAuth token is rejected.
pub const ANTHROPIC_OAUTH_BETA_MARKER: &str = "oauth-2025-04-20";

/// Ensure the outbound request carries `anthropic-beta: oauth-2025-04-20`,
/// merging it into any existing comma-separated `anthropic-beta` value so the
/// client's own feature betas are preserved. Idempotent: a no-op if the marker
/// is already present.
fn ensure_anthropic_oauth_beta(headers: &mut hyper::HeaderMap) -> Result<(), ()> {
    let merged = match headers.get("anthropic-beta") {
        Some(existing) => {
            let existing = existing.to_str().map_err(|_| ())?;
            if existing
                .split(',')
                .any(|flag| flag.trim() == ANTHROPIC_OAUTH_BETA_MARKER)
            {
                return Ok(());
            }
            if existing.trim().is_empty() {
                ANTHROPIC_OAUTH_BETA_MARKER.to_string()
            } else {
                format!("{existing},{ANTHROPIC_OAUTH_BETA_MARKER}")
            }
        }
        None => ANTHROPIC_OAUTH_BETA_MARKER.to_string(),
    };
    let value = hyper::header::HeaderValue::from_str(&merged).map_err(|_| ())?;
    headers.insert("anthropic-beta", value);
    Ok(())
}

/// Auth scheme the proxy injected for an outbound request. Returned by
/// [`inject_provider_auth`] so `handle_request` can log + the test harness
/// can echo it back as a response header for assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    /// `x-api-key: <token>` — Anthropic.
    Anthropic,
    /// `Authorization: Basic base64("x-access-token:{token}")` — Git smart-HTTP.
    Basic,
    /// `Authorization: Bearer {token}` — generic / OpenAI-compatible.
    Bearer,
}

impl AuthScheme {
    /// Stable string form used in the test-harness `x-ember-auth-mode`
    /// response header and structured-log fields.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthScheme::Anthropic => "anthropic",
            AuthScheme::Basic => "basic",
            AuthScheme::Bearer => "bearer",
        }
    }
}

// ===== moved from proxy.rs lines 2906-2952 =====
/// Category of scope violation, used to pick an audit outcome string.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeViolationKind {
    /// Generic scope mismatch (provider/action/target/format).
    General,
    /// Subtarget (branch glob) mismatch — the first three scope segments
    /// matched but the request's branch did not satisfy the fourth segment.
    Subtarget,
}

/// Reason a request was rejected by scope enforcement.
///
/// Held as a separate type (rather than `String`) so callers can't
/// accidentally render it into the HTTP response body — scope details are
/// sensitive and should only hit `tracing` + the audit table.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct ScopeViolation {
    pub message: String,
    pub kind: ScopeViolationKind,
}

#[cfg(any(test, feature = "test-support"))]
impl ScopeViolation {
    fn general(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: ScopeViolationKind::General,
        }
    }

    fn subtarget(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: ScopeViolationKind::Subtarget,
        }
    }

    /// Audit outcome string (`denied_scope` or `denied_subtarget_scope`).
    pub fn audit_outcome(&self) -> &'static str {
        match self.kind {
            ScopeViolationKind::General => "denied_scope",
            ScopeViolationKind::Subtarget => "denied_subtarget_scope",
        }
    }
}

// ===== moved from proxy.rs lines 2954-3174 =====
/// Resolve the applicable `Statement` for a request (action, resource) pair
/// against a composite grant chain.
///
/// Walks every `(block_index, statement)` pair in chain order and returns
/// the first whose `applicable_to` predicate holds. When the chain has zero
/// applicable statements the caller MUST deny with
/// `no_applicable_statement_response()` — the authorization primitive never
/// falls back to grant-level enforcement. See ADR 073 § "Allow-only" and
/// SESSION-composite-plan.md §Risks.
///
/// Action matching:
/// - Exact string match (e.g. `"github:read"` matches `"github:read"`).
/// - `"*"` on a Statement matches any request action.
///
/// Resource matching follows `Statement.resource.covers(resource)`. When a
/// grant's selector is an `Exact` match on the credential name (the fallback
/// for credential-type grants where `scope` has no `:target` tail) we also
/// accept the request iff the Statement's action agrees — effectively
/// treating credential-fallback selectors as `Any` because the request's
/// resource is a URI, not a credential name.
pub fn resolve_statement_for_request<'a>(
    grant: &'a core_grant_types::AccessGrant,
    action: &str,
    resource: &str,
) -> Option<(usize, &'a core_grant_types::Statement)> {
    use core_grant_types::ResourceSelector;

    grant.statements().find(|(_, stmt)| {
        let action_ok = stmt.actions.iter().any(|a| a == action || a == "*");
        if !action_ok {
            return false;
        }

        // ADR 207 seam 8B — conditions fail-closed at the use boundary.
        // A statement carrying any `Condition` (UrlPattern / Subpath / Cidr /
        // TimeWindow / MerchantAllowlist / …) must NOT authorize a request
        // here, because use-time condition *satisfaction* is not evaluated on
        // the proxy forward path. Authorizing past an unevaluated condition
        // would silently widen authority — e.g. a `UrlPattern`/`Subpath`
        // condition intended to clamp the target is ignored, so the credential
        // reaches a wider target than the grant authorizes (confused deputy).
        // This mirrors the sibling broker path `clause_covers_need`, which is
        // already documented fail-closed on this axis (core-grants scope.rs
        // §"conditions: fail-closed"). Conditions remain preserved downhill by
        // `check_statement_attenuation` at delegation time.
        if !stmt.conditions.is_empty() {
            return false;
        }

        // Credential-fallback: if the selector is an Exact match on a
        // bare ident (no path separators), the resource match is
        // effectively Any because the request URI will never equal a
        // credential name. This is the canonical shape for
        // credential-type grants whose scope has no `:target` tail.
        match &stmt.resource {
            ResourceSelector::Exact { value }
                if !value.contains('/') && !value.starts_with('/') =>
            {
                true
            }
            other => other.covers(resource),
        }
    })
}

/// Outcome of subtarget-aware per-Statement resolution.
///
/// `Match` is the success path: the resolver found an applicable statement
/// and (if the statement carried a `GlobWithSubtarget`) the subtarget glob
/// matched the request's branch. `SubtargetMiss` means primary matched but
/// the request's branch failed the subtarget glob — caller should deny
/// with `denied_subtarget_scope`. `NoApplicable` is the catch-all "no
/// statement applies" case → `denied_no_applicable_statement`.
#[derive(Debug)]
pub enum ResolveOutcome<'a> {
    Match {
        // P69E.5c: kept for parity with `resolve_statement_for_request`'s
        // `(usize, &Statement)` shape; callers that meter against the
        // resolved statement may want the chain index.
        #[allow(dead_code)]
        index: usize,
        stmt: &'a core_grant_types::Statement,
    },
    SubtargetMiss {
        subtarget_glob: String,
    },
    /// An applicable statement (action + resource matched) carried one or more
    /// `Condition`s that the proxy forward path cannot evaluate, so it is
    /// fail-closed (ADR 207 seam 8B). Distinct from `NoApplicable` so the
    /// caller can emit a legible `denied_unevaluable_condition` audit outcome
    /// rather than the generic "no statement applies". `conditions` names the
    /// condition kinds (no values) for the audit line.
    UnevaluableCondition {
        conditions: String,
    },
    NoApplicable,
}

/// Subtarget-aware variant of [`resolve_statement_for_request`] (P69E.5c).
///
/// Walks the chain in order. For each statement that passes
/// `applicable_to(action, resource)`:
/// - if it has no subtarget → return `Match`.
/// - if it has a subtarget AND a request branch was extractable from the
///   URI AND that branch matches the subtarget glob → return `Match`.
/// - if it has a subtarget but the URI carries no branch OR the branch
///   does not match the glob → record `SubtargetMiss` and keep walking,
///   so a less-restrictive later statement can still match.
///
/// Returning `SubtargetMiss` only when no later statement matched routes
/// the caller to emit `denied_subtarget_scope`, distinguishing this from
/// the generic `denied_no_applicable_statement`.
pub fn resolve_statement_for_request_with_uri<'a>(
    grant: &'a core_grant_types::AccessGrant,
    action: &str,
    resource: &str,
    uri: &hyper::Uri,
) -> ResolveOutcome<'a> {
    use core_grant_types::ResourceSelector;

    let mut subtarget_miss: Option<String> = None;
    let mut condition_miss: Option<String> = None;

    for (idx, stmt) in grant.statements() {
        let action_ok = stmt.actions.iter().any(|a| a == action || a == "*");
        if !action_ok {
            continue;
        }

        // Credential-fallback: an Exact bare-ident selector means "credential
        // surface only" — request URI never equals a credential name, so
        // we treat the selector as Any once the action agrees.
        let primary_ok = match &stmt.resource {
            ResourceSelector::Exact { value }
                if !value.contains('/') && !value.starts_with('/') =>
            {
                true
            }
            other => other.covers(resource),
        };
        if !primary_ok {
            continue;
        }

        // ADR 207 seam 8B — conditions fail-closed at the use boundary.
        // Action + resource matched, but a statement carrying any `Condition`
        // cannot be authorized here: the proxy forward path does not evaluate
        // condition *satisfaction* (UrlPattern / Subpath / Cidr / TimeWindow /
        // MerchantAllowlist / …). Treating such a statement as a match would
        // silently authorize past an unevaluated condition — e.g. a
        // `UrlPattern`/`Subpath` target clamp is ignored and the credential
        // reaches a wider target than the grant authorizes (confused deputy).
        // Record the first miss and keep walking so a less-restrictive
        // *unconditioned* later statement can still legitimately match; if none
        // does we surface `UnevaluableCondition`. Mirrors the broker path
        // `clause_covers_need` (already fail-closed on this axis); conditions
        // stay preserved downhill by `check_statement_attenuation`.
        if !stmt.conditions.is_empty() {
            if condition_miss.is_none() {
                condition_miss = Some(summarize_condition_kinds(&stmt.conditions));
            }
            continue;
        }

        // Primary matched. Check subtarget if the selector carries one.
        if let Some(sub_glob) = stmt.resource.subtarget_glob() {
            // Branch extraction is currently github-only. For non-github
            // providers we fail closed on the subtarget axis and record
            // the miss, mirroring `subtarget_matches`.
            let branch = extract_github_branch(uri.path(), uri.query());
            let subtarget_ok = match branch {
                Some(b) => glob_match_branch(sub_glob, &b),
                None => false,
            };
            if subtarget_ok {
                return ResolveOutcome::Match { index: idx, stmt };
            } else {
                // Record the first subtarget-miss reason so the caller
                // can route to `denied_subtarget_scope` if no later
                // statement covers the request.
                if subtarget_miss.is_none() {
                    subtarget_miss = Some(sub_glob.to_string());
                }
                continue;
            }
        }

        return ResolveOutcome::Match { index: idx, stmt };
    }

    // Precedence among denies (no statement Matched): the conditions axis is
    // the stronger fail-closed gate (an applicable-but-unevaluable statement),
    // so surface it ahead of a subtarget miss. Unconditioned grants leave
    // `condition_miss` empty, so existing subtarget behavior is unchanged.
    if let Some(conditions) = condition_miss {
        return ResolveOutcome::UnevaluableCondition { conditions };
    }
    match subtarget_miss {
        Some(sg) => ResolveOutcome::SubtargetMiss { subtarget_glob: sg },
        None => ResolveOutcome::NoApplicable,
    }
}

/// Summarize the *kinds* of a statement's conditions for an audit line —
/// e.g. `"UrlPattern,MerchantAllowlist"`. Never includes condition *values*
/// (patterns, CIDRs, merchant ids), so the audit log does not become a place
/// grant internals leak. Stable, de-duplicated, comma-joined order.
fn summarize_condition_kinds(conditions: &[core_grant_types::Condition]) -> String {
    use core_grant_types::Condition;
    let mut kinds: Vec<&'static str> = conditions
        .iter()
        .map(|c| match c {
            Condition::Subpath { .. } => "Subpath",
            Condition::OneOf { .. } => "OneOf",
            Condition::NotOneOf { .. } => "NotOneOf",
            Condition::Range { .. } => "Range",
            Condition::Cidr { .. } => "Cidr",
            Condition::UrlPattern { .. } => "UrlPattern",
            Condition::Regex { .. } => "Regex",
            Condition::TimeWindow { .. } => "TimeWindow",
            Condition::MerchantAllowlist { .. } => "MerchantAllowlist",
        })
        .collect();
    kinds.sort_unstable();
    kinds.dedup();
    kinds.join(",")
}

/// Outcome of `preflight_budget_check`. `Allowed` → forward upstream;
/// `Rejected { axis, limit, used }` → 429 with budget-exhausted body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightDecision {
    Allowed,
    Rejected {
        axis: &'static str,
        limit: u64,
        used: u64,
    },
}

/// Pre-flight budget check for a resolved Statement.
///
/// Given the Statement the request resolved to and the request body (used
/// to estimate tokens via `pricing::estimate_call_tokens`), return
/// `Allowed` when the projected token usage plus current usage fits under
/// the Statement's budget, or `Rejected` naming the first exhausted axis.
///
/// Cents are NOT estimated pre-flight because we don't know the model
/// pricing without the response (the `model` field in the request body is
/// advisory; the upstream can substitute). The post-flight meter handles
/// cents. Token estimation uses the byte-length / 4 heuristic from
/// `pricing.rs` which biases conservatively — a request that just fits
/// will pass preflight and the real post-flight math may nudge usage up
/// against the budget.
///
/// Statements without a `budget` (TTL-only) always pass.
pub fn preflight_budget_check(
    stmt: &core_grant_types::Statement,
    request_body: &[u8],
) -> PreflightDecision {
    let Some(budget) = &stmt.budget else {
        return PreflightDecision::Allowed;
    };
    if let Some(cap) = budget.tokens {
        let estimated = pricing::estimate_call_tokens(request_body);
        let projected = stmt.usage.tokens.saturating_add(estimated);
        if projected > cap {
            return PreflightDecision::Rejected {
                axis: "tokens",
                limit: cap,
                used: stmt.usage.tokens,
            };
        }
    }
    // Cents preflight: only block when the existing usage ALREADY exceeds
    // the cents cap (post-flight cents tick can nudge usage over budget
    // between calls). We don't estimate cents up front — see doc above.
    //
    // Compare against the micro-cent
    // accumulator so sub-cent calls aggregate honestly. Fall back to the
    // legacy `cents` axis when cents_micro is unset (zero) so pre-fix
    // grants stored under the old representation still gate correctly.
    if let Some(cap) = budget.cents {
        let cap_micro = cap.saturating_mul(1_000_000);
        let exhausted = if stmt.usage.cents_micro > 0 {
            stmt.usage.cents_micro >= cap_micro
        } else {
            stmt.usage.cents >= cap
        };
        if exhausted {
            return PreflightDecision::Rejected {
                axis: "cents",
                limit: cap,
                used: stmt.usage.cents,
            };
        }
    }
    PreflightDecision::Allowed
}

// ===== moved from proxy.rs lines 3176-3307 =====
/// 429 denial body for a budget-exhausted pre-flight. The body names
/// `axis`, `limit`, and `used` so the agent can back off intelligently
/// without probing. Emitting a structured shape matches the `Error`
/// schema used by Stream D receipts; no secret is leaked because the
/// agent already knows the grant's budget (they've minted/received it).
pub fn budget_exhausted_response(
    grant_id: &str,
    statement_sid: &str,
    axis: &str,
    limit: u64,
    used: u64,
) -> Response<ProxyBody> {
    let body = serde_json::json!({
        "error": "budget_exhausted",
        "grant_id": grant_id,
        "statement_sid": statement_sid,
        "axis": axis,
        "limit": limit,
        "used": used,
    });
    let bytes =
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{\"error\":\"budget_exhausted\"}".to_vec());
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .body(box_full(Full::new(Bytes::from(bytes))))
        .unwrap()
}

pub fn openai_streaming_budget_gate_response() -> Response<ProxyBody> {
    let body = serde_json::json!({
        "error": "openai_streaming_budget_gate",
        "message": "OpenAI streaming responses are disabled for budgeted grants until streaming metering is implemented",
    });
    let bytes = serde_json::to_vec(&body)
        .unwrap_or_else(|_| b"{\"error\":\"openai_streaming_budget_gate\"}".to_vec());
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(box_full(Full::new(Bytes::from(bytes))))
        .unwrap()
}

/// Compute the (token, cents) usage delta from an upstream LLM response
/// body. Returns `None` if the body isn't a recognizable JSON LLM
/// response — the caller should skip metering rather than fail the
/// request (e.g. GitHub + non-LLM providers return here with `None`).
///
/// Provider is resolved from the target host (`api.anthropic.com`,
/// `api.openai.com`); an unknown host returns `None` even if the body
/// looks like JSON — we only meter providers we have a pricing table
/// for.
pub fn meter_response(target_host: &str, response_body: &[u8]) -> Option<core_grant_types::Usage> {
    let Some(provider) = pricing::provider_for_host(target_host) else {
        tracing::info!(
            target: "proxy.meter.skip",
            reason = "no-provider",
            target_host = %target_host,
            body_len = response_body.len(),
            "meter_response: provider_for_host returned None — host not in pricing table"
        );
        return None;
    };
    let Some(parsed) = pricing::parse_usage(provider, response_body) else {
        let head = response_body
            .iter()
            .take(80)
            .map(|b| {
                if b.is_ascii() && !b.is_ascii_control() {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect::<String>();
        tracing::info!(
            target: "proxy.meter.skip",
            reason = "no-usage-parse",
            provider = %provider,
            target_host = %target_host,
            body_len = response_body.len(),
            body_head = %head,
            "meter_response: parse_usage returned None — body lacks recognizable usage block"
        );
        return None;
    };
    let model = pricing::extract_model(provider, response_body).unwrap_or_default();
    // Compute micro-cents (cents × 10⁶) and
    // derive whole cents from it. Without micro-cent precision, sub-cent
    // calls (~0.1¢ on Haiku-4.5) round to 0 per call and the budget cap
    // can never accumulate enough to trip.
    let cents_micro =
        pricing::cents_micro_for(&model, provider, parsed.input_tokens, parsed.output_tokens);
    Some(core_grant_types::Usage {
        tokens: parsed.input_tokens.saturating_add(parsed.output_tokens),
        cents: cents_micro / 1_000_000,
        cents_micro,
        // Leave `requests` at 0
        // here. The caller folds in `record_upstream_request` once the
        // upstream's confirmation status is known, so a 5xx body that
        // happens to carry a usage block doesn't get counted as a
        // billable request.
        requests: 0,
        workload_hours: 0,
        wall_clock_secs: 0,
        last_updated: 0,
    })
}

/// Record a single upstream-confirmed request against the proxy meter.
///
/// `usage.requests` historically
/// incremented by 1 for every proxy invocation that produced a parseable
/// usage block, regardless of whether the upstream's HTTP response was
/// itself a success. The
/// receipt should reflect what actually happened upstream — Anthropic /
/// OpenAI confirmed receiving the request — not what we tried to send.
/// A request counted but rejected by the upstream is a false-positive.
///
/// This function is the single decision point for "does this proxy call
/// count as one request against the grant's request budget?". It
/// returns 1 only when the upstream is a known LLM provider, the HTTP
/// response status is in the 2xx range, and the response body parsed
/// out a real usage signal. All failure paths (network error, timeout,
/// 4xx, 5xx, non-LLM provider, unparseable body) return 0.
///
/// Failure-path note: 4xx is treated as a non-billable failure here
/// even though the request demonstrably reached the upstream. The
/// pricing intent is "billable request" alignment with the provider's
/// own counter; providers do not bill 4xx so neither do we.
pub fn record_upstream_request(
    target_host: &str,
    upstream_status_is_success: bool,
    saw_usage_signal: bool,
) -> u64 {
    if pricing::provider_for_host(target_host).is_none() {
        return 0;
    }
    if !upstream_status_is_success {
        return 0;
    }
    if !saw_usage_signal {
        return 0;
    }
    1
}

// ===== moved from proxy.rs lines 3463-3477 =====
/// 403 denial when zero statements match a request. Never names the
/// statement set — same rationale as `scope_violation_response` (leaking
/// the selector shape is a probe vector). The cause is logged + audited.
pub fn no_applicable_statement_response() -> Response<ProxyBody> {
    let body = serde_json::json!({
        "error": "no_applicable_statement",
    });
    let bytes = serde_json::to_vec(&body)
        .unwrap_or_else(|_| b"{\"error\":\"no_applicable_statement\"}".to_vec());
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(box_full(Full::new(Bytes::from(bytes))))
        .unwrap()
}

// ===== moved from proxy.rs lines 3479-3660 =====
/// Check a grant's `scope` string against the request method and URI.
///
/// Scope grammar (fail closed on anything else):
///
/// ```text
///   <scope> := "*"                       // universal
///            | <provider> ":" <action>
///            | <provider> ":" <action> ":" <target>
///            | <provider> ":" <action> ":" <target> ":" <subtarget>
///
///   <provider>  := "github" | "generic" | "*"
///   <action>    := "read" | "push" | "*"
///   <target>    := owner "/" repo        // for github
///                | <path-prefix>         // for generic
///                | "*"
///   <subtarget> := <glob>                // branch pattern; enforced via
///                                        //  URI-path matching for GitHub
///                                        //  branch endpoints. Git
///                                        //  smart-http body-sniffing is
///                                        //  still deferred.
/// ```
///
/// HTTP method → action bucket:
///
/// * `GET`, `HEAD`, `OPTIONS` → `read` (also allowed by `*`)
/// * `POST`, `PUT`, `PATCH`, `DELETE` → `push` (also allowed by `*`)
/// * anything else → denied
///
/// This function **never widens** a scope: a missing, empty, or
/// unrecognised scope is a denial, and an unknown action never satisfies a
/// write-tier method.
#[cfg(any(test, feature = "test-support"))]
pub fn check_scope(
    scope: &str,
    method: &hyper::Method,
    uri: &hyper::Uri,
) -> Result<(), ScopeViolation> {
    let scope = scope.trim();
    if scope.is_empty() {
        return Err(ScopeViolation::general("empty scope"));
    }

    // Classify the method first; an unknown method is a hard deny so new
    // HTTP verbs can't sneak past the enforcement table.
    let method_tier = method_tier(method)
        .ok_or_else(|| ScopeViolation::general(format!("unsupported method: {method}")))?;

    // "*" alone is the universal scope.
    if scope == "*" {
        return Ok(());
    }

    // Split into at most 4 components. Reject anything with empty segments
    // (e.g. "::", "github::push") so typos fail closed.
    let parts: Vec<&str> = scope.split(':').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(ScopeViolation::general(format!(
            "malformed scope: '{scope}'"
        )));
    }
    if parts.len() > 4 {
        return Err(ScopeViolation::general(format!(
            "scope has too many segments: '{scope}'"
        )));
    }

    // V0 scope grammar requires at least <provider>:<action>. Bare-action
    // forms ("read", "push", "write") are rejected — the composite grant
    // chain is the canonical source, so every fresh-DB scope is fully
    // qualified on mint.
    let (provider, action, target, subtarget) = match parts.as_slice() {
        [provider, action] => (*provider, *action, "*", None),
        [provider, action, target] => (*provider, *action, *target, None),
        [provider, action, target, subtarget] => (*provider, *action, *target, Some(*subtarget)),
        _ => {
            return Err(ScopeViolation::general(format!(
                "malformed scope: '{scope}'"
            )));
        }
    };

    // Validate provider against a closed set. Anything else is a deny.
    match provider {
        "github" => {
            let host = uri.host().unwrap_or("");
            if host != "api.github.com" && host != "github.com" {
                return Err(ScopeViolation::general(format!(
                    "scope restricts to github but host is '{host}'"
                )));
            }
        }
        "generic" | "*" => {}
        other => {
            return Err(ScopeViolation::general(format!(
                "unknown scope provider: '{other}'"
            )));
        }
    }

    // Validate action against the method tier.
    let action_allows_method = matches!(
        (action, method_tier),
        ("*", _) | ("read", MethodTier::Read) | ("push", MethodTier::Write)
    );
    if !action_allows_method {
        return Err(ScopeViolation::general(format!(
            "scope action '{action}' does not permit {method} requests"
        )));
    }

    // Validate target. For github this is "owner/repo" (optionally
    // containing `*` wildcards). For generic this is treated as a path
    // prefix with `*` wildcards. `*` alone always matches.
    if target != "*" {
        let path = uri.path();
        let target_ok = match provider {
            "github" => github_target_matches(target, path),
            // generic + * fall through to path-prefix globbing
            _ => wildcard_match(target, path),
        };
        if !target_ok {
            return Err(ScopeViolation::general(format!(
                "scope target '{target}' does not match request path"
            )));
        }
    }

    // Validate subtarget (branch pattern) when present.
    // Enforced via URI-path matching for GitHub branch endpoints.
    // Git smart-http body-sniffing (/git-receive-pack) is still deferred.
    if let Some(st) = subtarget {
        subtarget_matches(st, uri, provider)?;
    }

    Ok(())
}

/// Check that a scope's subtarget (branch glob) is satisfied by the request URI.
///
/// For `provider == "github"` we extract the branch name from these path shapes:
///   - `/repos/{owner}/{repo}/branches/{branch}[/...]`
///   - `/repos/{owner}/{repo}/git/refs/heads/{branch}[/...]`
///
/// If neither pattern matches we fail closed: we cannot prove which branch is
/// targeted so we deny.  Git smart-http body-sniffing (`/git-receive-pack`) is
/// explicitly out of scope and remains deferred.
///
/// For providers other than `github` (including `generic`/`*`) subtarget
/// enforcement is not defined; we fail closed there too.
#[cfg(any(test, feature = "test-support"))]
pub fn subtarget_matches(
    subtarget_glob: &str,
    uri: &hyper::Uri,
    provider: &str,
) -> Result<(), ScopeViolation> {
    if provider != "github" {
        return Err(ScopeViolation::subtarget(format!(
            "scope subtarget is only supported for provider 'github', not '{provider}'"
        )));
    }

    // Try to extract a branch from any known shape: /branches/{branch},
    // /git/refs/heads/{branch}, or /contents/{path}?ref={branch}.
    let branch = extract_github_branch(uri.path(), uri.query());

    match branch {
        Some(b) => {
            if glob_match_branch(subtarget_glob, &b) {
                Ok(())
            } else {
                Err(ScopeViolation::subtarget(format!(
                    "scope subtarget '{subtarget_glob}' does not match branch '{b}'"
                )))
            }
        }
        None => Err(ScopeViolation::subtarget(
            "scope subtarget requires branch in URI path but path does not contain \
             /branches/ or /git/refs/heads/ or /contents/ (with ?ref=)"
                .to_string(),
        )),
    }
}

// ===== moved from proxy.rs lines 3662-3785 =====
/// Return a structured 403 when the matched statement has been revoked.
///
/// Beat 7 (SCION 2026-05-15 demo) — clients programmatically distinguish
/// "statement_revoked" from generic 403s so they can surface "your statement
/// was revoked by the operator" rather than a flat denial. Unlike
/// `scope_violation_response`, the persona_id and statement_id are NOT
/// information leaks here: the caller supplied the persona_id in the request
/// header (`X-Ember-Persona`) and already has access to the sid via the
/// grant detail page. Naming what was killed accelerates agent self-recovery.
pub fn statement_revoked_response(persona_id: &str, statement_id: &str) -> Response<ProxyBody> {
    let body = serde_json::json!({
        "error": "statement_revoked",
        "persona_id": persona_id,
        "statement_id": statement_id,
    });
    let bytes =
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{\"error\":\"statement_revoked\"}".to_vec());
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(box_full(Full::new(Bytes::from(bytes))))
        .unwrap()
}

/// ADR 190 §4 / ADR 197 §2 — a credential grant went non-active mid-session
/// (`expired` / `revoked` / `parent_cascade_revoked` / `exhausted_by_budget`).
/// Fail closed: still HTTP 403, no credential is injected. But the structured
/// body carries the session base posture's recovery affordance so the
/// harness/operator can recover without a relaunch — `jit` => re-approve,
/// `strict` => re-delegate — instead of an opaque 403 that bricks the turn.
/// The full "request completes across the gap" survival is the lease's job
/// (ADR 197 §3-4); this only makes the failure correct, posture-aware, and
/// recoverable.
///
/// V030-REVOKE-ERROR-MESSAGE: when the status is a revocation terminal
/// (`revoked` / `parent_cascade_revoked` per ADR 114's state machine), the
/// body also carries an operator-facing `message` naming the grant_id, the
/// cause (direct revoke vs cascade from a revoked parent grant), and the
/// canonical v0.3.0 recovery action — exit the current harness session and
/// open a fresh one via `ember claude` / `ember codex`. The
/// session-resume path is deliberately NOT named: it re-attaches to the
/// existing session's `meta.grant_id` and would inherit the dead grant. The
/// operator's 2026-06-10 reframe is that container/process lifecycle is the
/// orchestrator's domain — we revoke authority and emit receipts; the
/// operator/orchestrator handles the session abandon-and-reopen flow.
/// CYRUS's v0.3.1+ `rebind_grant_after_revoke` brief (see
/// `docs/runbook/recovery.md`) replaces the "restart session" recovery with
/// a one-RPC rebind, but at v0.3.0 Revoked is terminal per ADR 114 and
/// abandon-and-reopen is the canonical recovery.
pub fn authority_lapsed_response(
    persona_id: &str,
    grant_status: &str,
    grant_id: &str,
    authority_strict: bool,
) -> Response<ProxyBody> {
    let (posture, recovery) = if authority_strict {
        ("strict", "redelegate")
    } else {
        ("jit", "reapprove")
    };
    let message = revoked_grant_operator_message(grant_status, grant_id);
    let body = serde_json::json!({
        "error": "authority_lapsed",
        "persona_id": persona_id,
        "grant_id": grant_id,
        "grant_status": grant_status,
        "posture": posture,
        "recovery": recovery,
        "message": message,
    });
    let bytes =
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{\"error\":\"authority_lapsed\"}".to_vec());
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(box_full(Full::new(Bytes::from(bytes))))
        .unwrap()
}

/// V030-REVOKE-ERROR-MESSAGE: render an operator-facing message naming the
/// terminal status and the canonical v0.3.0 recovery action for a revoked
/// grant. Distinguishes direct revoke from parent-cascade revoke so the
/// operator knows whether THIS grant was killed or a parent kill cascaded.
/// Non-revocation statuses (`expired` / `exhausted_by_budget`) get a generic
/// message — their recovery is `extend_grant` / re-mint, not session restart,
/// and is owned by other surfaces.
///
/// **Recovery action.** Revoked is terminal per ADR 114: the existing session
/// is alive but cannot make brokered calls. The session-resume path
/// (`ember claude --resume` / `claude --resume`) reads the existing session's
/// `meta.grant_id` and inherits the dead grant — it does NOT mint a fresh
/// authority window. The canonical v0.3.0 recovery is therefore "abandon the
/// container/harness session, then open a fresh one" — exit the existing
/// `claude`/`codex` process and re-open via `ember claude` or `ember codex`.
/// The operator's 2026-06-10 framing (`feedback_authority_is_our_domain_lifecycle_isnt`)
/// is that container/process lifecycle is the orchestrator's domain — we
/// revoke authority and emit receipts; the operator/orchestrator handles the
/// session restart. ADR 209 §8 is out-of-scope for v0.3.0 for the same reason.
fn revoked_grant_operator_message(grant_status: &str, grant_id: &str) -> String {
    match grant_status {
        "revoked" => format!(
            "grant {grant_id} was revoked; this session is alive but cannot make brokered calls. \
             Exit the current `claude`/`codex` process and open a fresh session with `ember claude` or `ember codex` \
             (Revoked is terminal at v0.3.0 per ADR 114; v0.3.0 does not support post-revoke grant rebind — \
             a `rebind_grant_after_revoke` primitive is tracked for v0.3.1+, see `docs/runbook/recovery.md`)"
        ),
        "parent_cascade_revoked" => format!(
            "grant {grant_id} was cascade-revoked by a revocation of one of its parent grants; this session is alive but cannot make brokered calls. \
             Exit the current `claude`/`codex` process and open a fresh session with `ember claude` or `ember codex` under a fresh parent authority \
             (Revoked is terminal at v0.3.0 per ADR 114; v0.3.0 does not support post-revoke grant rebind — \
             a `rebind_grant_after_revoke` primitive is tracked for v0.3.1+, see `docs/runbook/recovery.md`)"
        ),
        other => format!(
            "grant {grant_id} is no longer active (status={other}); see `docs/runbook/recovery.md`"
        ),
    }
}

/// Return a generic 403 for scope violations. The body deliberately does
/// NOT include the grant's scope string — leaking it would let an attacker
/// probe for narrower scopes. The detail is in the daemon log and audit.
pub fn scope_violation_response() -> Response<ProxyBody> {
    let body = serde_json::json!({
        "error": "scope violation",
    });
    let bytes =
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{\"error\":\"scope violation\"}".to_vec());
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(box_full(Full::new(Bytes::from(bytes))))
        .unwrap()
}

pub fn bad_request(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

pub fn forbidden(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

pub fn unauthorized(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

pub fn internal_error(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

/// HTTP 413 response used when a request or response body exceeds
/// `MAX_BODY_BYTES`. Signals to well-behaved clients that the
/// payload is too large to pass through the credential-injection layer.
pub fn payload_too_large(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

/// HTTP 503 response used when the per-process streaming-concurrency
/// cap is saturated (C44-TEE-MEM). A `Retry-After` header signals to
/// well-behaved clients that the condition is transient. Keep the body
/// short — it travels through hyper's small-buffer path and avoids
/// tickling the very accumulator we're protecting.
pub fn service_unavailable(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Retry-After", "1")
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

// ===== moved from proxy.rs lines 1389-1405 (threshold_keys) =====
/// Project the `ThresholdAxis` / `ThresholdBand` enums onto their wire
/// `&'static str` keys. Extracted as a free function so both the sync
/// `record_threshold_crossing_sync` and the async trait impl can share
/// the projection without duplicating the match.
pub fn threshold_keys(axis: ThresholdAxis, band: ThresholdBand) -> (&'static str, &'static str) {
    let axis_str: &'static str = match axis {
        ThresholdAxis::Tokens => "tokens",
        ThresholdAxis::Cents => "cents",
        ThresholdAxis::Requests => "requests",
        ThresholdAxis::WallSeconds => "wall_seconds",
    };
    let band_str: &'static str = match band {
        ThresholdBand::Warning => "warning",
        ThresholdBand::Exhausted => "exhausted",
    };
    (axis_str, band_str)
}

// ===== moved from proxy.rs lines 4405-4452 (b64 helpers) =====
/// Build the `Authorization: Basic ...` value GitHub expects for smart-HTTP
/// over HTTPS with a PAT.
///
/// GitHub's convention for token-based Basic auth is
/// `x-access-token:{pat}` as the `user:password` pair. Any non-empty
/// username works, but `x-access-token` is the documented form for PATs and
/// installation tokens, and keeps audit logs legible.
pub fn build_github_basic_auth(token: &str) -> String {
    let raw = format!("x-access-token:{token}");
    format!("Basic {}", base64_std_encode(raw.as_bytes()))
}

/// Minimal RFC 4648 §4 standard-base64 encoder (padded, no URL-safe
/// substitutions). Kept local to avoid pulling in the `base64` crate for a
/// one-off echo prototype; Day 2's production path will either reuse an
/// existing dep or we'll add one in a scoped PR.
pub fn base64_std_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHABET[(n & 0x3f) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        0 => {}
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
    out
}

#[cfg(test)]
mod smoke_tests {
    //! P22-S2 smoke coverage for the moved forwarding core against the
    //! in-memory `core_proxy_forward::ColocatedBackend`. The exhaustive
    //! behaviour suite (128 cases) stays in `ember-daemon`'s
    //! `infra::proxy::tests` because those exercise `DaemonStore` / `Vault`
    //! / `DaemonPolicyBackend`; this module proves the extracted primitives
    //! link and behave against the trait's in-memory implementation.
    use super::*;
    use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
    use core_proxy_forward::{ColocatedBackend, GrantRecord, ProxyState as ColocatedState};
    use std::sync::Arc as StdArc;

    #[test]
    fn generic_credential_without_allowlist_fails_closed() {
        // The confused-deputy exfil: a generic credential with no
        // allowed_targets must NOT forward to an agent-chosen host.
        assert_eq!(
            authorize_forward_host(true, None, Some("attacker.example")),
            HostAuthz::DenyGenericNoAllowlist
        );
        // Even with no resolvable host, generic + no allowlist denies.
        assert_eq!(
            authorize_forward_host(true, None, None),
            HostAuthz::DenyGenericNoAllowlist
        );
    }

    #[test]
    fn non_generic_lane_without_allowlist_is_allowed() {
        // github/llm lanes bake the host into the matched action+resource, so
        // they are host-bound without an allowlist — must not be blocked.
        assert_eq!(
            authorize_forward_host(false, None, Some("api.github.com")),
            HostAuthz::Allow
        );
    }

    #[test]
    fn allowlist_is_enforced_for_any_lane() {
        // Exact match allowed; non-match denied; wildcard suffix honored.
        assert_eq!(
            authorize_forward_host(true, Some("api.acme.com"), Some("api.acme.com")),
            HostAuthz::Allow
        );
        assert_eq!(
            authorize_forward_host(true, Some("api.acme.com"), Some("attacker.example")),
            HostAuthz::DenyNotInAllowlist
        );
        assert_eq!(
            authorize_forward_host(true, Some("*.acme.com"), Some("api.acme.com")),
            HostAuthz::Allow
        );
        // Allowlist present but host unresolvable → deny.
        assert_eq!(
            authorize_forward_host(false, Some("api.acme.com"), None),
            HostAuthz::DenyNotInAllowlist
        );
    }

    #[test]
    fn allowed_targets_json_array_roundtrips_through_authorize_forward_host() {
        // ADR 207 SEAM-8B follow-up — write site is
        // `serde_json::to_string(arr)`; parser must accept that encoding.
        // Anchor: allowed_targets_storage_and_parse_one_encoding.
        let stored = serde_json::to_string(&vec!["api.acme.com".to_string()]).expect("encode");
        assert_eq!(
            authorize_forward_host(true, Some(stored.as_str()), Some("api.acme.com")),
            HostAuthz::Allow,
            "JSON-array stored at create_grant must round-trip through the proxy gate"
        );
        // A foreign host with the same stored allowlist still denies.
        assert_eq!(
            authorize_forward_host(true, Some(stored.as_str()), Some("attacker.example")),
            HostAuthz::DenyNotInAllowlist
        );
    }

    #[test]
    fn allowed_targets_multi_entry_wildcard_and_exact_both_authorize() {
        let stored =
            serde_json::to_string(&vec!["api.acme.com".to_string(), "*.acme.org".to_string()])
                .expect("encode");
        assert_eq!(
            authorize_forward_host(true, Some(stored.as_str()), Some("api.acme.com")),
            HostAuthz::Allow,
            "exact-match entry in a multi-entry JSON-array allowlist authorises"
        );
        assert_eq!(
            authorize_forward_host(true, Some(stored.as_str()), Some("api.acme.org")),
            HostAuthz::Allow,
            "wildcard entry in a multi-entry JSON-array allowlist authorises"
        );
        assert_eq!(
            authorize_forward_host(true, Some(stored.as_str()), Some("acme.org")),
            HostAuthz::Allow,
            "wildcard suffix matches the bare domain itself"
        );
        assert_eq!(
            authorize_forward_host(true, Some(stored.as_str()), Some("attacker.example")),
            HostAuthz::DenyNotInAllowlist
        );
    }

    #[test]
    fn generic_lane_classification_drives_the_gate() {
        use core_proxy_forward::r#match::request_to_action_resource;
        // An arbitrary host classifies as the `generic` provider (path-only
        // resource) → the gate treats it as generic and requires an allowlist.
        let (action, _) = request_to_action_resource(
            &http::Method::POST,
            &"https://attacker.example/v1/anything".parse().unwrap(),
        )
        .expect("classifies");
        assert_eq!(action.split(':').next(), Some("generic"));
        // github/anthropic hosts do NOT classify as generic.
        let (gh, _) = request_to_action_resource(
            &http::Method::GET,
            &"https://api.github.com/repos/o/r".parse().unwrap(),
        )
        .expect("classifies");
        assert_ne!(gh.split(':').next(), Some("generic"));
    }

    fn statement_with_budget(tokens: Option<u64>) -> Statement {
        Statement {
            sid: "stmt-smoke".into(),
            resource_type: ResourceType::Session,
            actions: vec!["POST".into()],
            resource: ResourceSelector::Glob {
                pattern: "https://api.anthropic.com/*".into(),
            },
            budget: tokens.map(|t| Budget {
                tokens: Some(t),
                cents: None,
                requests: None,
                workload_hours: None,
                wall_clock_secs: None,
            }),
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        }
    }

    fn openai_statement_with_budget(budget: Option<Budget>) -> Statement {
        Statement {
            sid: "stmt-openai".into(),
            resource_type: ResourceType::Session,
            actions: vec!["POST".into()],
            resource: ResourceSelector::Glob {
                pattern: "https://api.openai.com/*".into(),
            },
            budget,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        }
    }

    fn token_budget(tokens: u64) -> Budget {
        Budget {
            tokens: Some(tokens),
            cents: None,
            requests: None,
            workload_hours: None,
            wall_clock_secs: None,
        }
    }

    #[test]
    fn budgeted_openai_json_streaming_request_fails_closed() {
        let stmt = openai_statement_with_budget(Some(token_budget(10_000)));
        let uri: http::Uri = "https://api.openai.com/v1/responses".parse().unwrap();

        assert!(budgeted_openai_streaming_request_forbidden(
            &stmt,
            "api.openai.com",
            &uri,
            br#"{"model":"gpt-4o","stream":true}"#,
        ));
    }

    #[test]
    fn budgeted_openai_query_streaming_request_fails_closed() {
        let stmt = openai_statement_with_budget(Some(token_budget(10_000)));
        let uri: http::Uri = "https://api.openai.com/v1/responses?stream=true"
            .parse()
            .unwrap();

        assert!(budgeted_openai_streaming_request_forbidden(
            &stmt,
            "api.openai.com",
            &uri,
            br#"{"model":"gpt-4o"}"#,
        ));
    }

    #[test]
    fn openai_streaming_gate_only_applies_to_budgeted_openai() {
        let unbudgeted = openai_statement_with_budget(None);
        let empty_budget = openai_statement_with_budget(Some(Budget::default()));
        let budgeted = openai_statement_with_budget(Some(token_budget(10_000)));
        let uri: http::Uri = "https://api.openai.com/v1/responses".parse().unwrap();
        let body = br#"{"stream":true}"#;

        assert!(!budgeted_openai_streaming_request_forbidden(
            &unbudgeted,
            "api.openai.com",
            &uri,
            body,
        ));
        assert!(!budgeted_openai_streaming_request_forbidden(
            &empty_budget,
            "api.openai.com",
            &uri,
            body,
        ));
        assert!(!budgeted_openai_streaming_request_forbidden(
            &budgeted,
            "api.anthropic.com",
            &uri,
            body,
        ));
        assert!(!budgeted_openai_streaming_request_forbidden(
            &budgeted,
            "api.openai.com",
            &uri,
            br#"{"stream":false}"#,
        ));
    }

    #[test]
    fn budgeted_openai_streaming_response_fallback_fails_closed() {
        let stmt = openai_statement_with_budget(Some(token_budget(10_000)));

        assert!(budgeted_openai_streaming_response_forbidden(
            &stmt,
            "api.openai.com",
            true,
        ));
        assert!(!budgeted_openai_streaming_response_forbidden(
            &stmt,
            "api.openai.com",
            false,
        ));
        assert!(!budgeted_openai_streaming_response_forbidden(
            &stmt,
            "api.anthropic.com",
            true,
        ));
    }

    #[tokio::test]
    async fn colocated_backend_resolves_grant_and_credential_through_moved_trait() {
        let state = StdArc::new(ColocatedState::new());
        state.insert_grant(GrantRecord {
            grant_id: "g-smoke".into(),
            persona_id: "alice".into(),
            credential_name: "anthropic/test-credential".into(),
            statements: vec![statement_with_budget(None)],
        });
        state.insert_credential("anthropic/test-credential", "sk-smoke");
        let backend = ColocatedBackend::new(StdArc::clone(&state));

        let uri: http::Uri = "https://api.anthropic.com/v1/messages".parse().unwrap();
        let resolved = backend
            .resolve_grant("alice", "anthropic/test-credential", None, &uri, "POST")
            .await
            .expect("resolve_grant");
        assert_eq!(resolved.grant_id, "g-smoke");

        // The moved pure pre-flight check runs against a no-budget statement.
        assert_eq!(
            preflight_budget_check(&resolved.statement, b"hello world"),
            PreflightDecision::Allowed
        );

        let cred = backend
            .get_credential("anthropic/test-credential")
            .await
            .expect("get_credential");
        assert_eq!(cred.as_str(), "sk-smoke");
    }

    #[tokio::test]
    async fn ssrf_resolver_blocks_loopback_resolution() {
        use tower_service::Service;
        // `localhost` resolves (deterministically, no network) to 127.0.0.1 /
        // ::1 — both blocked. The connect-time guard must fail closed so the
        // proxy never opens a socket to a name that resolves to a blocked IP
        // (the DNS-rebinding-safe enforcement point, not just the literal
        // pre-flight).
        let mut r = SsrfGuardResolver::new();
        let name: Name = "localhost".parse().expect("parse name");
        let err = r
            .call(name)
            .await
            .expect_err("localhost must resolve only to blocked loopback IPs");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "blocked-only resolution must fail closed with PermissionDenied"
        );
    }

    #[tokio::test]
    async fn ssrf_resolver_allows_public_host() {
        use tower_service::Service;
        // A public host must NOT be blocked by the guard itself. If DNS is
        // unavailable (offline CI sandbox) resolution errors with a non-
        // PermissionDenied kind, which we tolerate — the assertion is only that
        // the guard does not refuse a public address.
        let mut r = SsrfGuardResolver::new();
        let name: Name = "one.one.one.one".parse().expect("parse name");
        match r.call(name).await {
            Ok(mut addrs) => assert!(addrs.next().is_some(), "public host yields an address"),
            Err(e) => assert_ne!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied,
                "the guard must not block a public host (1.1.1.1)"
            ),
        }
    }

    #[test]
    fn dlp_summary_aggregates_patterns_and_never_carries_secret_bytes() {
        use core_proxy_forward::outbound_leak::{LeakHit, LeakLocation, LeakPattern};
        // No hits → no audit detail.
        assert_eq!(summarize_dlp_hits(&[]), None);

        let hits = vec![
            LeakHit {
                location: LeakLocation::RequestBody,
                pattern: LeakPattern::GitHubPAT,
                offset: 12,
                length: 40,
            },
            LeakHit {
                location: LeakLocation::RequestBody,
                pattern: LeakPattern::GitHubPAT,
                offset: 80,
                length: 40,
            },
            LeakHit {
                location: LeakLocation::ResponseBody,
                pattern: LeakPattern::AnthropicApiKey,
                offset: 3,
                length: 100,
            },
        ];
        let detail = summarize_dlp_hits(&hits).expect("hits summarized");
        // Two GitHubPAT in the request body collapse to a count of 2 at the
        // first offset; the anthropic response hit is reported once.
        assert!(
            detail.contains("GitHubPAT:RequestBodyx2@12"),
            "got {detail}"
        );
        assert!(
            detail.contains("AnthropicApiKey:ResponseBodyx1@3"),
            "got {detail}"
        );
        // Fingerprint only — the detail must NEVER contain matched secret bytes.
        assert!(!detail.contains("ghp_"), "leaked secret bytes: {detail}");
        assert!(!detail.contains("sk-ant"), "leaked secret bytes: {detail}");
    }

    #[tokio::test]
    async fn moved_preflight_rejects_over_budget_via_colocated_backend() {
        let state = StdArc::new(ColocatedState::new());
        // Statement already at its token cap so the moved trait preflight rejects.
        let mut stmt = statement_with_budget(Some(10));
        stmt.usage.tokens = 10;
        state.insert_grant(GrantRecord {
            grant_id: "g-cap".into(),
            persona_id: "bob".into(),
            credential_name: "anthropic/test-credential".into(),
            statements: vec![stmt],
        });
        let backend = ColocatedBackend::new(StdArc::clone(&state));
        let uri: http::Uri = "https://api.anthropic.com/v1/messages".parse().unwrap();
        let resolved = backend
            .resolve_grant("bob", "anthropic/test-credential", None, &uri, "POST")
            .await
            .unwrap();
        let decision = backend.preflight_budget(&resolved, b"x").await.unwrap();
        assert!(matches!(
            decision,
            core_proxy_forward::PreflightDecision::Rejected { axis: "tokens", .. }
        ));
    }

    #[test]
    fn moved_response_builders_carry_expected_status_codes() {
        assert_eq!(bad_request("x").status(), StatusCode::BAD_REQUEST);
        assert_eq!(forbidden("x").status(), StatusCode::FORBIDDEN);
        assert_eq!(unauthorized("x").status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            internal_error("x").status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            payload_too_large("x").status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            service_unavailable("x").status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            no_applicable_statement_response().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            budget_exhausted_response("g", "s", "tokens", 10, 10).status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            openai_streaming_budget_gate_response().status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn moved_record_upstream_request_counts_only_confirmed_llm_calls() {
        // Known LLM host + 2xx + usage signal => 1.
        assert_eq!(record_upstream_request("api.anthropic.com", true, true), 1);
        // 5xx => 0.
        assert_eq!(record_upstream_request("api.anthropic.com", false, true), 0);
        // Non-LLM host => 0.
        assert_eq!(record_upstream_request("example.com", true, true), 0);
    }

    #[test]
    fn inject_provider_auth_anthropic_oauth_token_uses_bearer_and_adds_oauth_beta() {
        let mut headers = hyper::HeaderMap::new();
        // Client supplied the inert launcher checkpoint + its own feature betas.
        headers.insert(
            "authorization",
            hyper::header::HeaderValue::from_static("Bearer ember-brokered-no-auth"),
        );
        headers.insert(
            "anthropic-beta",
            hyper::header::HeaderValue::from_static("claude-code-20250219,effort-2025-11-24"),
        );
        let scheme = inject_provider_auth(
            &mut headers,
            "api.anthropic.com",
            false,
            "anthropic/oauth-token",
            "sk-ant-oat01-REAL",
        )
        .unwrap();
        assert_eq!(scheme, AuthScheme::Bearer);
        // Checkpoint replaced by the real vault credential.
        assert_eq!(
            headers.get("authorization").unwrap().to_str().unwrap(),
            "Bearer sk-ant-oat01-REAL"
        );
        // OAuth marker present AND the client's feature betas preserved.
        let beta = headers.get("anthropic-beta").unwrap().to_str().unwrap();
        assert!(beta.contains(ANTHROPIC_OAUTH_BETA_MARKER));
        assert!(beta.contains("claude-code-20250219"));
        assert!(beta.contains("effort-2025-11-24"));
        // OAuth lane never sets x-api-key.
        assert!(headers.get("x-api-key").is_none());
    }

    #[test]
    fn inject_provider_auth_oauth_adds_beta_when_client_sends_none() {
        let mut headers = hyper::HeaderMap::new();
        let scheme = inject_provider_auth(
            &mut headers,
            "api.anthropic.com",
            false,
            "anthropic/oauth-token",
            "sk-ant-oat01-REAL",
        )
        .unwrap();
        assert_eq!(scheme, AuthScheme::Bearer);
        assert_eq!(
            headers.get("anthropic-beta").unwrap().to_str().unwrap(),
            ANTHROPIC_OAUTH_BETA_MARKER
        );
    }

    #[test]
    fn inject_provider_auth_standardized_plan_oauth_slug_uses_bearer_and_adds_oauth_beta() {
        // Regression: the standardized `anthropic/plan/claude-oauth/<fingerprint>`
        // name (replacing the flat `anthropic/oauth-token`) MUST take the
        // Bearer + oauth-beta branch — not silently fall through to x-api-key,
        // which Anthropic rejects (review finding F1 / the selector↔injector
        // drift the cred-slug standardization introduced).
        let mut headers = hyper::HeaderMap::new();
        let scheme = inject_provider_auth(
            &mut headers,
            "api.anthropic.com",
            false,
            "anthropic/plan/claude-oauth/fp-ab12cd34ef567890ab12cd34",
            "sk-ant-oat01-REAL",
        )
        .unwrap();
        assert_eq!(scheme, AuthScheme::Bearer);
        assert_eq!(
            headers.get("authorization").unwrap().to_str().unwrap(),
            "Bearer sk-ant-oat01-REAL"
        );
        assert!(
            headers
                .get("anthropic-beta")
                .unwrap()
                .to_str()
                .unwrap()
                .contains(ANTHROPIC_OAUTH_BETA_MARKER)
        );
        assert!(headers.get("x-api-key").is_none());
    }

    #[test]
    fn inject_provider_auth_standardized_api_key_slug_uses_x_api_key_no_oauth_beta() {
        // The standardized API-key name stays on the x-api-key branch.
        let mut headers = hyper::HeaderMap::new();
        let scheme = inject_provider_auth(
            &mut headers,
            "api.anthropic.com",
            false,
            "anthropic/api/key/fp-ab12cd34ef567890ab12cd34",
            "sk-ant-REALKEY",
        )
        .unwrap();
        assert_eq!(scheme, AuthScheme::Anthropic);
        assert_eq!(
            headers.get("x-api-key").unwrap().to_str().unwrap(),
            "sk-ant-REALKEY"
        );
        assert!(headers.get("anthropic-beta").is_none());
        assert!(headers.get("authorization").is_none());
    }

    #[test]
    fn inject_provider_auth_oauth_does_not_duplicate_existing_marker() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "anthropic-beta",
            hyper::header::HeaderValue::from_static("oauth-2025-04-20,claude-code-20250219"),
        );
        inject_provider_auth(
            &mut headers,
            "api.anthropic.com",
            false,
            "anthropic/oauth-token",
            "sk-ant-oat01-REAL",
        )
        .unwrap();
        let beta = headers.get("anthropic-beta").unwrap().to_str().unwrap();
        assert_eq!(beta.matches(ANTHROPIC_OAUTH_BETA_MARKER).count(), 1);
    }

    #[test]
    fn inject_provider_auth_anthropic_api_key_uses_x_api_key_no_oauth_beta() {
        let mut headers = hyper::HeaderMap::new();
        let scheme = inject_provider_auth(
            &mut headers,
            "api.anthropic.com",
            false,
            "anthropic/key",
            "sk-ant-api03-REAL",
        )
        .unwrap();
        assert_eq!(scheme, AuthScheme::Anthropic);
        assert_eq!(
            headers.get("x-api-key").unwrap().to_str().unwrap(),
            "sk-ant-api03-REAL"
        );
        // API-key lane: no Authorization, and we do NOT add the OAuth beta.
        assert!(headers.get("authorization").is_none());
        assert!(headers.get("anthropic-beta").is_none());
    }

    // ─────────────── ADR 207 seam 8B — grant-glob target tightness ───────────────

    /// Build a single-statement `AccessGrant` for resolver tests with a chosen
    /// action, resource selector, and condition set.
    fn grant_single_stmt(
        actions: Vec<String>,
        resource: ResourceSelector,
        conditions: Vec<core_grant_types::Condition>,
    ) -> core_grant_types::AccessGrant {
        let stmt = Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions,
            resource,
            budget: None,
            usage: Usage::default(),
            conditions,
            can_delegate: None,
        };
        core_grant_types::AccessGrant::single_statement(
            "grant-seam8b",
            "persona-8b",
            "agent",
            stmt,
            "x",
            "x",
            0,
        )
    }

    #[test]
    fn conditioned_statement_fails_closed_on_proxy_forward_path() {
        // SEAM8B residual: a statement whose action+resource match the request
        // but which carries a `Condition` (here a `UrlPattern` target clamp)
        // must NOT silently authorize the forward — the proxy does not evaluate
        // condition satisfaction, so using it would let the credential reach a
        // wider target than the grant authorizes (confused deputy). Expect a
        // fail-closed `UnevaluableCondition`, not `Match`.
        use core_grant_types::Condition;
        let uri: hyper::Uri = "https://api.acme.com/v1/anything".parse().unwrap();
        let conditioned = grant_single_stmt(
            vec!["generic:write".into()],
            ResourceSelector::Glob {
                pattern: "*".into(),
            },
            vec![Condition::UrlPattern {
                field: "url".into(),
                pattern: "https://api.acme.com/safe/*".into(),
            }],
        );
        match resolve_statement_for_request_with_uri(
            &conditioned,
            "generic:write",
            "/v1/anything",
            &uri,
        ) {
            ResolveOutcome::UnevaluableCondition { conditions } => {
                assert_eq!(conditions, "UrlPattern");
            }
            other => panic!(
                "conditioned statement must fail closed, got {:?} — \
                 a UrlPattern target clamp would be silently ignored",
                other
            ),
        }

        // Control: the SAME action+resource WITHOUT the condition resolves to a
        // Match — proving it is the condition, not the selector, that gates.
        let unconditioned = grant_single_stmt(
            vec!["generic:write".into()],
            ResourceSelector::Glob {
                pattern: "*".into(),
            },
            vec![],
        );
        assert!(matches!(
            resolve_statement_for_request_with_uri(
                &unconditioned,
                "generic:write",
                "/v1/anything",
                &uri,
            ),
            ResolveOutcome::Match { .. }
        ));
    }

    #[test]
    fn conditioned_statement_fails_closed_on_git_echo_matcher() {
        // The non-URI git-echo matcher must also drop conditioned statements
        // (returns None → caller emits denied_no_applicable_statement).
        use core_grant_types::Condition;
        let conditioned = grant_single_stmt(
            vec!["github:push".into()],
            ResourceSelector::Glob {
                pattern: "owner/repo".into(),
            },
            vec![Condition::TimeWindow {
                start_secs_of_day: 0,
                end_secs_of_day: 3600,
            }],
        );
        assert!(
            resolve_statement_for_request(&conditioned, "github:push", "owner/repo").is_none(),
            "conditioned statement must not match on the git-echo path"
        );
        // Control: unconditioned matches.
        let unconditioned = grant_single_stmt(
            vec!["github:push".into()],
            ResourceSelector::Glob {
                pattern: "owner/repo".into(),
            },
            vec![],
        );
        assert!(
            resolve_statement_for_request(&unconditioned, "github:push", "owner/repo").is_some()
        );
    }

    #[test]
    fn unbounded_resource_glob_widens_path_not_host() {
        // An unbounded statement glob (`generic:write *`) is vacuous on the
        // PATH axis — it resolves any path. It must NOT, however, relax the
        // host clamp: the host is still bound only by `allowed_targets`, and a
        // non-member (or absent allowlist) on the generic lane fails closed.
        // This pins that an unbounded glob does not bypass the target clamp.
        let unbounded = grant_single_stmt(
            vec!["generic:write".into()],
            ResourceSelector::Glob {
                pattern: "*".into(),
            },
            vec![],
        );
        assert!(
            unbounded
                .statements()
                .next()
                .unwrap()
                .1
                .resource
                .is_unbounded()
        );
        let uri: hyper::Uri = "https://attacker.example/anything".parse().unwrap();
        // The statement resolves (path is unbounded)…
        assert!(matches!(
            resolve_statement_for_request_with_uri(&unbounded, "generic:write", "/anything", &uri,),
            ResolveOutcome::Match { .. }
        ));
        // …but the host clamp still governs: generic + no allowlist fails
        // closed, and an allowlist that does not contain the host denies.
        assert_eq!(
            authorize_forward_host(true, None, Some("attacker.example")),
            HostAuthz::DenyGenericNoAllowlist
        );
        assert_eq!(
            authorize_forward_host(true, Some("api.acme.com"), Some("attacker.example")),
            HostAuthz::DenyNotInAllowlist
        );
    }

    #[test]
    fn condition_kind_summary_is_value_free_and_stable() {
        use core_grant_types::Condition;
        let summary = summarize_condition_kinds(&[
            Condition::UrlPattern {
                field: "url".into(),
                pattern: "https://secret.example/*".into(),
            },
            Condition::Cidr {
                field: "ip".into(),
                cidrs: vec!["10.0.0.0/8".into()],
            },
            Condition::UrlPattern {
                field: "url".into(),
                pattern: "https://other.example/*".into(),
            },
        ]);
        // De-duplicated, sorted, kinds only — never the patterns/CIDRs.
        assert_eq!(summary, "Cidr,UrlPattern");
        assert!(!summary.contains("secret.example"));
        assert!(!summary.contains("10.0.0.0"));
    }
}

#[cfg(test)]
mod revoked_grant_message_tests {
    //! V030-REVOKE-ERROR-MESSAGE — the in-flight 403 on a revoked grant
    //! used to surface as a generic `authority_lapsed` body that did not
    //! name the offending grant_id or the canonical recovery action. These
    //! regressions lock the targeted message: terminal status named, grant
    //! id named, the canonical abandon-and-reopen action named
    //! (`ember claude` / `ember codex`), the v0.3.1+ rebind pointer named,
    //! the session-resume path NOT named (it would inherit the dead grant),
    //! and direct revoke distinguished from parent-cascade revoke per
    //! ADR 114's state machine.
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn revoked_grant_error_names_recovery_action_with_session_restart() {
        let resp = authority_lapsed_response("persona-a", "revoked", "grant-r1", true);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "authority_lapsed");
        assert_eq!(json["grant_status"], "revoked");
        assert_eq!(json["grant_id"], "grant-r1");
        let message = json["message"].as_str().expect("message field present");
        assert!(
            message.contains("revoked"),
            "names terminal status: {message}"
        );
        assert!(message.contains("grant-r1"), "names grant_id: {message}");
        assert!(
            message.contains("ember claude") && message.contains("ember codex"),
            "names canonical abandon-and-reopen surfaces: {message}"
        );
        // Session-resume is the trap-door: re-attaching reads the existing
        // meta.grant_id and inherits the dead grant. The message must NOT
        // recommend it.
        assert!(
            !message.contains("--resume"),
            "must not recommend --resume (re-attaches to dead grant): {message}"
        );
        // Forward-pointer to the v0.3.1+ rebind primitive is part of the
        // targeted message contract — operators who hit this repeatedly
        // should know a one-RPC rebind is on the roadmap.
        assert!(
            message.contains("v0.3.1+") && message.contains("rebind"),
            "names the v0.3.1+ rebind pointer: {message}"
        );
        // Direct revoke must NOT use the cascade-specific phrasing.
        assert!(
            !message.contains("cascade-revoked"),
            "direct revoke must not be labeled cascade: {message}"
        );
    }

    #[tokio::test]
    async fn no_live_lease_error_includes_grant_id() {
        // Regression for FREYA #5858 follow-up: the `no_live_lease` path was
        // emitting `grant_inactive:no_live_lease` (no grant_id suffix), so the
        // operator-facing message read "grant  is no longer active" (double
        // space). The daemon now appends `:{grant_id}` on all no_live_lease
        // emission sites; this test locks that the message contains the id.
        let grant_id = "grant-dc1f0ab9-2cb6-4739-82d7-60a3a5ca86b3";
        let resp = authority_lapsed_response("persona-x", "no_live_lease", grant_id, false);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["grant_id"], grant_id);
        let message = json["message"].as_str().expect("message field present");
        assert!(
            message.contains(grant_id),
            "message must include grant_id: {message}"
        );
        // The double-space regression: "grant  is no longer active"
        assert!(
            !message.contains("grant  "),
            "message must not have double space after 'grant': {message}"
        );
        assert!(
            message.contains("grant "),
            "message must have 'grant ' followed by the id: {message}"
        );
    }

    #[tokio::test]
    async fn cascade_revoked_grant_error_distinguishes_from_direct_revoke() {
        let resp =
            authority_lapsed_response("persona-b", "parent_cascade_revoked", "grant-c1", true);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["grant_status"], "parent_cascade_revoked");
        assert_eq!(json["grant_id"], "grant-c1");
        let message = json["message"].as_str().expect("message field present");
        assert!(
            message.contains("cascade-revoked"),
            "distinguishes cascade from direct revoke: {message}"
        );
        assert!(message.contains("parent grant"), "names cause: {message}");
        assert!(message.contains("grant-c1"), "names grant_id: {message}");
        assert!(
            message.contains("ember claude") && message.contains("ember codex"),
            "names canonical abandon-and-reopen surfaces: {message}"
        );
        assert!(
            !message.contains("--resume"),
            "must not recommend --resume (re-attaches to dead grant): {message}"
        );
        assert!(
            message.contains("v0.3.1+") && message.contains("rebind"),
            "names the v0.3.1+ rebind pointer: {message}"
        );

        // Cross-check: the direct-revoke message and the cascade message must
        // differ enough that the operator can tell them apart from message
        // text alone, not just from the structured `grant_status` field.
        let direct = revoked_grant_operator_message("revoked", "grant-c1");
        let cascade = revoked_grant_operator_message("parent_cascade_revoked", "grant-c1");
        assert_ne!(direct, cascade, "messages must distinguish revoke cause");
    }
}

#[cfg(test)]
mod codex_responses_tests {
    //! Unit coverage for the codex loopback-TCP responses lane
    //! (P22-S2 / ADR 197 codex). Network-free: the strict-gate and
    //! fail-closed-no-session paths return BEFORE any upstream call, and the
    //! strip/inject/pin invariants are exercised directly against
    //! `filter_request_headers` + `inject_provider_auth` (the primitives the
    //! handler reuses verbatim). The full end-to-end forward against a mock
    //! upstream lives in the daemon integration tests.
    use super::*;
    use async_trait::async_trait;
    use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
    use core_proxy_forward::{
        PolicyError, PreflightDecision, ResolvedGrant, SessionGatewayAuthority,
    };
    use std::sync::Arc as StdArc;
    use zeroize::Zeroizing;

    /// Test backend that resolves session authority from an in-memory map.
    /// Only the methods the codex handler reaches are meaningful; the rest are
    /// minimal stubs.
    struct CodexTestBackend {
        /// `session_id -> authority`. Absent => fail-closed (None).
        authority: Option<SessionGatewayAuthority>,
        statement_budget: Option<Budget>,
    }

    impl CodexTestBackend {
        fn with_authority() -> Self {
            Self {
                authority: Some(SessionGatewayAuthority {
                    session_id: "sess_codex".into(),
                    persona_id: "alice".into(),
                    grant_id: "g-codex".into(),
                    credential_name: "openai/session-key".into(),
                }),
                statement_budget: None,
            }
        }
        fn with_budgeted_authority() -> Self {
            let mut backend = Self::with_authority();
            backend.statement_budget = Some(Budget {
                tokens: Some(10_000),
                cents: None,
                requests: None,
                workload_hours: None,
                wall_clock_secs: None,
            });
            backend
        }
        fn no_authority() -> Self {
            Self {
                authority: None,
                statement_budget: None,
            }
        }
        /// Session bound to a NON-OpenAI credential (e.g. the persona's first
        /// grant is an Anthropic grant). The provider gate must fail closed.
        fn with_credential(credential_name: &str) -> Self {
            Self {
                authority: Some(SessionGatewayAuthority {
                    session_id: "sess_codex".into(),
                    persona_id: "alice".into(),
                    grant_id: "g-codex".into(),
                    credential_name: credential_name.into(),
                }),
                statement_budget: None,
            }
        }
    }

    fn openai_statement(budget: Option<Budget>) -> Statement {
        Statement {
            sid: "stmt-codex".into(),
            resource_type: ResourceType::Session,
            actions: vec!["POST".into()],
            resource: ResourceSelector::Glob {
                pattern: "https://api.openai.com/*".into(),
            },
            budget,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        }
    }

    #[async_trait]
    impl PolicyBackend for CodexTestBackend {
        async fn resolve_session_authority(
            &self,
            _session_id: &str,
        ) -> Result<Option<SessionGatewayAuthority>, PolicyError> {
            Ok(self.authority.clone())
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
                grant_id: "g-codex".into(),
                persona_id: persona_id.into(),
                credential_name: credential_name.into(),
                statement_sid: "stmt-codex".into(),
                statement: openai_statement(self.statement_budget.clone()),
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
            Ok(Zeroizing::new("sk-vault".into()))
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

    /// Build a request with an empty body. The handler is generic over the
    /// request body, so the gate tests use `Empty<Bytes>` (hyper exposes no
    /// public `Incoming` constructor). The gate / fail-closed paths return
    /// before the body is ever read.
    fn req(method: hyper::Method, uri: &str) -> Request<http_body_util::Empty<Bytes>> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap()
    }

    #[tokio::test]
    async fn codex_responses_rejects_non_post() {
        let backend = StdArc::new(CodexTestBackend::with_authority());
        let resp = handle_codex_responses_request(
            backend,
            req(hyper::Method::GET, "/v1/responses"),
            "sess_codex".into(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn codex_responses_rejects_put() {
        let backend = StdArc::new(CodexTestBackend::with_authority());
        let resp = handle_codex_responses_request(
            backend,
            req(hyper::Method::PUT, "/v1/responses"),
            "sess_codex".into(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn codex_responses_rejects_wrong_path() {
        let backend = StdArc::new(CodexTestBackend::with_authority());
        let resp = handle_codex_responses_request(
            backend,
            req(hyper::Method::POST, "/v1/chat/completions"),
            "sess_codex".into(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn codex_responses_rejects_query_string() {
        let backend = StdArc::new(CodexTestBackend::with_authority());
        let resp = handle_codex_responses_request(
            backend,
            req(hyper::Method::POST, "/v1/responses?stream=true"),
            "sess_codex".into(),
        )
        .await
        .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "query strings are rejected (mirrors codex-responses-api-proxy)"
        );
    }

    #[tokio::test]
    async fn codex_responses_fail_closed_no_session_authority() {
        // POST /v1/responses passes the gate, but the session resolves to no
        // authority => 403, BEFORE any credential synthesis or forwarding.
        let backend = StdArc::new(CodexTestBackend::no_authority());
        let resp = handle_codex_responses_request(
            backend,
            req(hyper::Method::POST, "/v1/responses"),
            "sess_unknown".into(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn codex_responses_fail_closed_non_openai_credential() {
        // Adversarial must-fix: a codex session bound to a NON-OpenAI grant
        // (here `anthropic/oauth-token`) must FAIL CLOSED at the provider gate
        // — never inject that secret as a Bearer to api.openai.com. POST
        // /v1/responses passes the strict gate; the provider gate then denies.
        for cred in ["anthropic/oauth-token", "github/pat", "vault/random"] {
            let backend = StdArc::new(CodexTestBackend::with_credential(cred));
            let resp = handle_codex_responses_request(
                backend,
                req(hyper::Method::POST, "/v1/responses"),
                "sess_codex".into(),
            )
            .await
            .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "non-OpenAI credential {cred} must be refused (no cross-provider leak to OpenAI)"
            );
        }
    }

    #[tokio::test]
    async fn codex_responses_resolves_credential_from_session() {
        // The handler synthesizes credential identity from the session, not
        // from headers. Assert resolve_session_authority is the sole source.
        let backend = CodexTestBackend::with_authority();
        let authority = backend
            .resolve_session_authority("sess_codex")
            .await
            .unwrap()
            .expect("authority resolved from session");
        assert_eq!(authority.persona_id, "alice");
        assert_eq!(authority.credential_name, "openai/session-key");
        assert_eq!(authority.grant_id, "g-codex");
    }

    #[tokio::test]
    async fn codex_responses_budgeted_grant_blocks_streaming_before_plan_auth() {
        // The codex `/v1/responses` lane streams from chatgpt.com. Until the
        // streaming tee can meter OpenAI usage incrementally, a budgeted grant
        // must fail closed before ChatGPT plan auth is resolved or injected.
        let backend = StdArc::new(CodexTestBackend::with_budgeted_authority());
        let resp = handle_codex_responses_request(
            backend,
            req(hyper::Method::POST, "/v1/responses"),
            "sess_codex".into(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn codex_passthrough_preserves_codex_headers_and_strips_auth() {
        // GPT-plan rework: the handler PRESERVES codex's authentic non-auth
        // headers (version-resilience) and strips only auth/host/accept-encoding
        // + hop-by-hop. Prove the pass-through filter behaves so.
        let mut client_headers = hyper::HeaderMap::new();
        // Auth the client must NOT smuggle through:
        client_headers.insert("authorization", "Bearer attacker".parse().unwrap());
        client_headers.insert("x-api-key", "attacker-key".parse().unwrap());
        client_headers.insert("chatgpt-account-id", "attacker-acct".parse().unwrap());
        client_headers.insert("host", "evil.example".parse().unwrap());
        client_headers.insert("connection", "keep-alive".parse().unwrap());
        client_headers.insert("accept-encoding", "gzip".parse().unwrap());
        // Codex's authentic headers that MUST survive:
        client_headers.insert("openai-beta", "responses=v1".parse().unwrap());
        client_headers.insert("originator", "codex_cli_rs".parse().unwrap());
        client_headers.insert("session_id", "thread-123".parse().unwrap());
        client_headers.insert("content-type", "application/json".parse().unwrap());

        let builder = Request::builder()
            .method(hyper::Method::POST)
            .uri(CODEX_UPSTREAM_URL);
        let builder = passthrough_codex_request_headers(builder, &client_headers);
        let outgoing = builder.body(()).unwrap();
        let h = outgoing.headers();

        // Stripped:
        assert!(h.get("authorization").is_none(), "client auth dropped");
        assert!(h.get("x-api-key").is_none(), "client x-api-key dropped");
        assert!(
            h.get("chatgpt-account-id").is_none(),
            "client account-id dropped (broker injects it)"
        );
        assert!(h.get("host").is_none(), "client Host dropped");
        assert!(h.get("connection").is_none(), "hop-by-hop dropped");
        // Forced identity (meter needs plain JSON):
        assert_eq!(
            h.get("accept-encoding").and_then(|v| v.to_str().ok()),
            Some("identity")
        );
        // Codex's authentic headers preserved (the version-resilience point):
        assert_eq!(
            h.get("openai-beta").and_then(|v| v.to_str().ok()),
            Some("responses=v1")
        );
        assert_eq!(
            h.get("originator").and_then(|v| v.to_str().ok()),
            Some("codex_cli_rs")
        );
        assert_eq!(
            h.get("session_id").and_then(|v| v.to_str().ok()),
            Some("thread-123")
        );
        assert_eq!(
            h.get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    #[test]
    fn codex_inject_chatgpt_plan_auth_sets_bearer_and_account_id() {
        let mut headers = hyper::HeaderMap::new();
        // Stale client values that must be replaced/removed:
        headers.insert("authorization", "Bearer attacker".parse().unwrap());
        headers.insert("chatgpt-account-id", "attacker-acct".parse().unwrap());
        let auth = core_proxy_forward::ChatgptPlanAuth {
            access_token: zeroize::Zeroizing::new("at-broker".into()),
            account_id: Some("acct-real".into()),
            is_fedramp: false,
        };
        inject_chatgpt_plan_auth(&mut headers, &auth).expect("inject");
        assert_eq!(
            headers.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer at-broker"),
            "broker Bearer replaces the client's"
        );
        assert_eq!(
            headers
                .get("chatgpt-account-id")
                .and_then(|v| v.to_str().ok()),
            Some("acct-real"),
            "broker account-id replaces the client's"
        );
    }

    #[test]
    fn codex_inject_does_not_overwrite_codex_originator() {
        // Version-resilience: codex's authentic originator must win over our
        // hardcoded backfill.
        let mut headers = hyper::HeaderMap::new();
        headers.insert("originator", "codex_cli_rs_v9_future".parse().unwrap());
        let auth = core_proxy_forward::ChatgptPlanAuth {
            access_token: zeroize::Zeroizing::new("at".into()),
            account_id: None,
            is_fedramp: false,
        };
        inject_chatgpt_plan_auth(&mut headers, &auth).expect("inject");
        assert_eq!(
            headers.get("originator").and_then(|v| v.to_str().ok()),
            Some("codex_cli_rs_v9_future"),
            "codex's authentic originator is preserved, not overwritten"
        );
    }

    #[test]
    fn codex_inject_backfills_originator_when_absent() {
        let mut headers = hyper::HeaderMap::new();
        let auth = core_proxy_forward::ChatgptPlanAuth {
            access_token: zeroize::Zeroizing::new("at".into()),
            account_id: None,
            is_fedramp: false,
        };
        inject_chatgpt_plan_auth(&mut headers, &auth).expect("inject");
        assert_eq!(
            headers.get("originator").and_then(|v| v.to_str().ok()),
            Some(CHATGPT_ORIGINATOR),
            "originator backfilled only when codex sent none"
        );
    }

    #[test]
    fn codex_upstream_is_pinned_to_chatgpt_backend() {
        assert_eq!(CODEX_UPSTREAM_HOST, "chatgpt.com");
        assert_eq!(
            CODEX_UPSTREAM_URL,
            "https://chatgpt.com/backend-api/codex/responses"
        );
        // Default (no override) resolves to the const.
        assert_eq!(codex_upstream_host(), "chatgpt.com");
    }

    #[test]
    fn codex_projector_contract_is_pinned() {
        // The codex projector is the data half of the loopback engine. Pin its
        // fields so an accidental edit (flipping `streaming_budget_enforceable`,
        // or a `provider_prefix` typo that would let a non-OpenAI secret reach
        // the ChatGPT backend) is a RED test, not a silent behavior change.
        assert_eq!(CODEX_PROJECTOR.name, "codex");
        assert_eq!(CODEX_PROJECTOR.provider_prefix, "openai/");
        assert_eq!(CODEX_PROJECTOR.access_detail, "codex-responses");
        // `streaming_budget_enforceable == false` is enforced at compile time by
        // the `const _: () = assert!(...)` guard next to the const definition.
        assert!(
            matches!(CODEX_PROJECTOR.injection, CredentialInjection::ChatgptPlan),
            "codex uses the ChatGPT subscription-plan OAuth injection strategy"
        );
    }

    #[test]
    fn codex_projector_strict_gate_admits_only_post_responses_no_query() {
        // The gate predicate carried on the projector is the same strict
        // single-endpoint gate the handler enforces (mirrors
        // codex-responses-api-proxy): only POST /v1/responses, no query string.
        let accepts = CODEX_PROJECTOR.accepts;
        let uri = |s: &str| s.parse::<http::Uri>().unwrap();
        assert!(accepts(&hyper::Method::POST, &uri("/v1/responses")));
        assert!(!accepts(&hyper::Method::GET, &uri("/v1/responses")));
        assert!(!accepts(&hyper::Method::PUT, &uri("/v1/responses")));
        assert!(!accepts(&hyper::Method::POST, &uri("/v1/chat/completions")));
        assert!(!accepts(&hyper::Method::POST, &uri("/v1/responses?stream=true")));
    }

    #[test]
    fn codex_projector_upstream_ignores_inbound_uri_and_pins_chatgpt() {
        // codex never supplies a target: the projector's upstream resolver must
        // ignore the inbound request URI and always return the pinned ChatGPT
        // backend (full URL + host).
        let upstream = CODEX_PROJECTOR.upstream;
        let (url_a, host_a) = upstream(&"/v1/responses".parse::<http::Uri>().unwrap());
        let (url_b, host_b) = upstream(&"/anything/else?q=1".parse::<http::Uri>().unwrap());
        assert_eq!(url_a, url_b, "upstream is invariant of the inbound URI");
        assert_eq!(host_a, host_b);
        assert_eq!(url_a, codex_upstream_url().into_owned());
        assert_eq!(host_a, codex_upstream_host());
    }
}

#[cfg(test)]
mod gemini_responses_tests {
    //! Unit coverage for the gemini GATEWAY loopback-TCP lane.
    //! Network-free, mirroring `codex_responses_tests`: the strict-gate,
    //! fail-closed (no-session / non-google / budgeted) paths all return BEFORE
    //! any upstream call, and the strip/inject/pin invariants are exercised
    //! directly against `gemini_accepts` / `gemini_upstream_for` /
    //! `passthrough_gemini_request_headers` / `inject_api_key_header`. The full
    //! end-to-end forward against a live Google upstream is a operator
    //! live-verify item + the daemon session-wiring slice (the guarded forward
    //! client pins `https://` and trusts only webpki roots, so a self-signed
    //! mock cannot complete the round trip in a unit test — same boundary codex
    //! draws).
    use super::*;
    use async_trait::async_trait;
    use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
    use core_proxy_forward::{
        PolicyError, PreflightDecision, ResolvedGrant, SessionGatewayAuthority,
    };
    use std::sync::Arc as StdArc;
    use zeroize::Zeroizing;

    /// The fixed broker key the test backend returns from `get_credential`.
    const BROKER_KEY: &str = "AIzaBrokerKeyValue";

    struct GeminiTestBackend {
        authority: Option<SessionGatewayAuthority>,
        statement_budget: Option<Budget>,
    }

    impl GeminiTestBackend {
        fn with_authority() -> Self {
            Self {
                authority: Some(SessionGatewayAuthority {
                    session_id: "sess_gemini".into(),
                    persona_id: "alice".into(),
                    grant_id: "g-gemini".into(),
                    credential_name: "google/gemini-api-key".into(),
                }),
                statement_budget: None,
            }
        }
        fn with_budgeted_authority() -> Self {
            let mut backend = Self::with_authority();
            backend.statement_budget = Some(Budget {
                tokens: Some(10_000),
                cents: None,
                requests: None,
                workload_hours: None,
                wall_clock_secs: None,
            });
            backend
        }
        fn no_authority() -> Self {
            Self {
                authority: None,
                statement_budget: None,
            }
        }
        /// Session bound to a NON-google credential — the provider gate must
        /// fail closed (no cross-provider leak to the pinned Google upstream).
        fn with_credential(credential_name: &str) -> Self {
            Self {
                authority: Some(SessionGatewayAuthority {
                    session_id: "sess_gemini".into(),
                    persona_id: "alice".into(),
                    grant_id: "g-gemini".into(),
                    credential_name: credential_name.into(),
                }),
                statement_budget: None,
            }
        }
    }

    fn google_statement(budget: Option<Budget>) -> Statement {
        Statement {
            sid: "stmt-gemini".into(),
            resource_type: ResourceType::Session,
            actions: vec!["POST".into()],
            resource: ResourceSelector::Glob {
                pattern: "https://generativelanguage.googleapis.com/*".into(),
            },
            budget,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        }
    }

    #[async_trait]
    impl PolicyBackend for GeminiTestBackend {
        async fn resolve_session_authority(
            &self,
            _session_id: &str,
        ) -> Result<Option<SessionGatewayAuthority>, PolicyError> {
            Ok(self.authority.clone())
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
                grant_id: "g-gemini".into(),
                persona_id: persona_id.into(),
                credential_name: credential_name.into(),
                statement_sid: "stmt-gemini".into(),
                statement: google_statement(self.statement_budget.clone()),
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
            Ok(Zeroizing::new(BROKER_KEY.into()))
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

    fn req(method: hyper::Method, uri: &str) -> Request<http_body_util::Empty<Bytes>> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap()
    }

    const GEN_PATH: &str = "/v1beta/models/gemini-3-flash:generateContent";

    #[test]
    fn gemini_projector_contract_is_pinned() {
        // Pin the data half of the loopback engine so an accidental edit (a
        // `provider_prefix` typo that would ship a non-google secret to Google,
        // flipping `streaming_budget_enforceable`, or the wrong injected header)
        // is a RED test rather than a silent behavior change.
        assert_eq!(GEMINI_PROJECTOR.name, "gemini");
        assert_eq!(GEMINI_PROJECTOR.provider_prefix, "google/");
        assert_eq!(GEMINI_PROJECTOR.access_detail, "gemini-generate");
        // `streaming_budget_enforceable == false` is enforced at compile time by
        // the `const _: () = assert!(...)` guard next to the const definition.
        assert!(
            matches!(
                GEMINI_PROJECTOR.injection,
                CredentialInjection::ApiKeyHeader("x-goog-api-key")
            ),
            "gemini uses the API-key-header injection strategy under x-goog-api-key"
        );
    }

    #[test]
    fn gemini_strict_gate_admits_only_post_v1beta_model_methods() {
        let accepts = GEMINI_PROJECTOR.accepts;
        let uri = |s: &str| s.parse::<http::Uri>().unwrap();
        // The four GATEWAY methods, POST:
        assert!(accepts(&hyper::Method::POST, &uri(GEN_PATH)));
        assert!(accepts(
            &hyper::Method::POST,
            &uri("/v1beta/models/gemini-3-flash:streamGenerateContent?alt=sse")
        ));
        assert!(accepts(
            &hyper::Method::POST,
            &uri("/v1beta/models/gemini-3-flash:countTokens")
        ));
        assert!(accepts(
            &hyper::Method::POST,
            &uri("/v1beta/models/text-embedding-004:embedContent")
        ));
        // Wrong method:
        assert!(!accepts(&hyper::Method::GET, &uri(GEN_PATH)));
        assert!(!accepts(&hyper::Method::PUT, &uri(GEN_PATH)));
        // Wrong path / method-suffix not in the allowed set:
        assert!(!accepts(&hyper::Method::POST, &uri("/v1/responses")));
        assert!(!accepts(
            &hyper::Method::POST,
            &uri("/v1beta/models/gemini-3-flash:listModels")
        ));
        // Right method-suffix but wrong prefix:
        assert!(!accepts(
            &hyper::Method::POST,
            &uri("/v1beta/tunedModels/x:generateContent")
        ));
    }

    #[test]
    fn gemini_gate_rejects_authority_and_traversal_smuggling() {
        let accepts = GEMINI_PROJECTOR.accepts;
        // Authority smuggling: a network-path reference parses `evil.example`
        // as the authority — rejected (the host is pinned server-side).
        let smuggled = "//evil.example/v1beta/models/x:generateContent"
            .parse::<http::Uri>()
            .unwrap();
        assert!(
            !accepts(&hyper::Method::POST, &smuggled),
            "a `//`-prefixed path must be rejected"
        );
        // Absolute-form carrying a genuine scheme + authority is rejected by the
        // scheme/authority check (independent of the `//`-path check above).
        let absolute = "https://evil.example/v1beta/models/x:generateContent"
            .parse::<http::Uri>()
            .unwrap();
        assert!(
            absolute.authority().is_some(),
            "sanity: this form parses an authority"
        );
        assert!(
            !accepts(&hyper::Method::POST, &absolute),
            "a URI carrying a scheme/authority must be rejected"
        );
        // Dot-segment / double-slash traversal that still ends in a valid
        // method suffix must not slip past the gate — AND the percent-encoded
        // variants (`%2e%2e`, `%2f`, `%5c`), which the gate matches raw and the
        // upstream server would decode (M1).
        for p in [
            "/v1beta/models/../../v1beta/tunedModels/x:generateContent",
            "/v1beta/models//x:generateContent",
            "/v1beta/models/./x:generateContent",
            "/v1beta/models/%2e%2e/foo:generateContent",
            "/v1beta/models/%2e%2e%2ftunedModels/x:generateContent",
            "/v1beta/models/foo%2fbar:generateContent",
            "/v1beta/models/foo%5cbar:generateContent",
        ] {
            let uri = p.parse::<http::Uri>().unwrap();
            assert!(
                !accepts(&hyper::Method::POST, &uri),
                "traversal path {p} must be rejected"
            );
        }
    }

    #[test]
    fn gemini_upstream_preserves_path_and_query_and_pins_host() {
        let upstream = GEMINI_PROJECTOR.upstream;
        let (url, host) = upstream(
            &"/v1beta/models/gemini-3-flash:streamGenerateContent?alt=sse"
                .parse::<http::Uri>()
                .unwrap(),
        );
        assert_eq!(host, "generativelanguage.googleapis.com");
        assert_eq!(
            url,
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash:streamGenerateContent?alt=sse",
            "the client-supplied path+query is forwarded verbatim under the pinned host"
        );
        assert_eq!(host, gemini_upstream_host());
    }

    #[test]
    fn gemini_upstream_drops_any_authority_in_the_inbound_uri() {
        // Belt-and-braces (the gate already rejects scheme/authority-bearing
        // URIs and `//` paths): even if an absolute-form URI carrying a genuine
        // authority reached the resolver, `path_and_query()` carries no
        // authority, so the upstream stays pinned to the Google host.
        //
        // (`http::Uri` parses `//evil.example/…` as a *path* beginning `//`, not
        // an authority — that vector is caught upstream by the gate's `//`
        // rejection, asserted in `gemini_gate_rejects_authority_and_traversal_smuggling`.)
        let upstream = GEMINI_PROJECTOR.upstream;
        let (url, host) = upstream(
            &"https://evil.example/v1beta/models/x:generateContent"
                .parse::<http::Uri>()
                .unwrap(),
        );
        assert_eq!(host, "generativelanguage.googleapis.com");
        let parsed = url.parse::<http::Uri>().unwrap();
        assert_eq!(
            parsed.host(),
            Some("generativelanguage.googleapis.com"),
            "the upstream host stays pinned regardless of any inbound authority: {url}"
        );
        assert!(
            !url.contains("evil.example"),
            "the smuggled authority must not appear in the upstream URL: {url}"
        );
    }

    #[test]
    fn gemini_passthrough_strips_auth_and_goog_key_preserves_others() {
        let mut client_headers = hyper::HeaderMap::new();
        // Auth the client must NOT smuggle through:
        client_headers.insert("authorization", "Bearer attacker".parse().unwrap());
        client_headers.insert("x-api-key", "attacker-key".parse().unwrap());
        // The GATEWAY client emits an EMPTY x-goog-api-key; an attacker might
        // try a non-empty one. Either way it must be dropped (broker injects).
        client_headers.insert("x-goog-api-key", "attacker-goog-key".parse().unwrap());
        client_headers.insert("host", "evil.example".parse().unwrap());
        client_headers.insert("connection", "keep-alive".parse().unwrap());
        client_headers.insert("accept-encoding", "gzip".parse().unwrap());
        // gemini-cli's authentic headers that MUST survive:
        client_headers.insert("user-agent", "GeminiCLI/1.2.3".parse().unwrap());
        client_headers.insert("content-type", "application/json".parse().unwrap());

        let builder = Request::builder().method(hyper::Method::POST).uri(GEN_PATH);
        let builder = passthrough_gemini_request_headers(builder, &client_headers);
        let outgoing = builder.body(()).unwrap();
        let h = outgoing.headers();

        assert!(h.get("authorization").is_none(), "client auth dropped");
        assert!(h.get("x-api-key").is_none(), "client x-api-key dropped");
        assert!(
            h.get("x-goog-api-key").is_none(),
            "client x-goog-api-key dropped (broker injects it)"
        );
        assert!(h.get("host").is_none(), "client Host dropped");
        assert!(h.get("connection").is_none(), "hop-by-hop dropped");
        assert_eq!(
            h.get("accept-encoding").and_then(|v| v.to_str().ok()),
            Some("identity")
        );
        assert_eq!(
            h.get("user-agent").and_then(|v| v.to_str().ok()),
            Some("GeminiCLI/1.2.3")
        );
        assert_eq!(
            h.get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    #[test]
    fn gemini_inject_api_key_header_strips_client_auth_and_inserts_broker_value() {
        let mut headers = hyper::HeaderMap::new();
        // Stale client values that must be replaced/removed:
        headers.insert("authorization", "Bearer attacker".parse().unwrap());
        headers.insert("x-api-key", "attacker-key".parse().unwrap());
        headers.insert("x-goog-api-key", "".parse().unwrap()); // the GATEWAY empty placeholder
        inject_api_key_header(&mut headers, "x-goog-api-key", BROKER_KEY).expect("inject");
        assert_eq!(
            headers.get("x-goog-api-key").and_then(|v| v.to_str().ok()),
            Some(BROKER_KEY),
            "broker key replaces the client's placeholder"
        );
        assert!(
            headers.get("authorization").is_none(),
            "client authorization stripped"
        );
        assert!(
            headers.get("x-api-key").is_none(),
            "client x-api-key stripped"
        );
    }

    #[test]
    fn gemini_inject_trims_trailing_newline() {
        let mut headers = hyper::HeaderMap::new();
        inject_api_key_header(&mut headers, "x-goog-api-key", "AIzaKey\n").expect("inject");
        assert_eq!(
            headers.get("x-goog-api-key").and_then(|v| v.to_str().ok()),
            Some("AIzaKey"),
            "a trailing newline in the vault value is trimmed (not a header-injection vector)"
        );
    }

    #[tokio::test]
    async fn gemini_fail_closed_no_session_authority() {
        // POST a valid gemini path passes the gate, but the session resolves to
        // no authority => 403, BEFORE any credential read or forwarding.
        let backend = StdArc::new(GeminiTestBackend::no_authority());
        let resp = handle_loopback_projector_request(
            &GEMINI_PROJECTOR,
            backend,
            req(hyper::Method::POST, GEN_PATH),
            "sess_unknown".into(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn gemini_fail_closed_non_google_credential() {
        // A gemini session bound to a NON-google grant must FAIL CLOSED at the
        // provider gate — never inject that secret to the pinned Google
        // upstream. POST a valid path passes the strict gate; the provider gate
        // then denies before `get_credential` is ever called.
        for cred in ["anthropic/oauth-token", "openai/session-key", "github/pat"] {
            let backend = StdArc::new(GeminiTestBackend::with_credential(cred));
            let resp = handle_loopback_projector_request(
                &GEMINI_PROJECTOR,
                backend,
                req(hyper::Method::POST, GEN_PATH),
                "sess_gemini".into(),
            )
            .await
            .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "non-google credential {cred} must be refused (no cross-provider leak to Google)"
            );
        }
    }

    #[tokio::test]
    async fn gemini_rejected_by_strict_gate_before_authority() {
        // GET / wrong path are refused by the strict gate even with a valid
        // session authority bound.
        for (method, path) in [
            (hyper::Method::GET, GEN_PATH),
            (hyper::Method::POST, "/v1/responses"),
            (hyper::Method::POST, "/v1beta/models/x:listModels"),
        ] {
            let backend = StdArc::new(GeminiTestBackend::with_authority());
            let resp = handle_loopback_projector_request(
                &GEMINI_PROJECTOR,
                backend,
                req(method.clone(), path),
                "sess_gemini".into(),
            )
            .await
            .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{method} {path} must be rejected by the strict gate"
            );
        }
    }

    #[tokio::test]
    async fn gemini_budgeted_grant_blocks_streaming_before_key_read() {
        // gemini `:streamGenerateContent?alt=sse` streams SSE the same way codex
        // does; until in-stream metering exists a budgeted grant must fail closed
        // BEFORE the broker key is read or injected.
        let backend = StdArc::new(GeminiTestBackend::with_budgeted_authority());
        let resp = handle_loopback_projector_request(
            &GEMINI_PROJECTOR,
            backend,
            req(hyper::Method::POST, GEN_PATH),
            "sess_gemini".into(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn gemini_upstream_host_default_when_env_unset() {
        // Default (no operator override) resolves to the pinned const.
        // (No env mutation here to avoid cross-test races; the override path is
        // documented + operator-only.)
        if std::env::var(GEMINI_UPSTREAM_HOST_OVERRIDE_ENV).is_err() {
            assert_eq!(gemini_upstream_host(), GEMINI_UPSTREAM_HOST);
        }
    }
}

#[cfg(test)]
mod gemini_code_assist_tests {
    //! Unit coverage for the gemini Code Assist ("Sign in with Google")
    //! loopback lane (ADR 215 slice 2). Network-free, mirroring
    //! `gemini_responses_tests`: gate + fail-closed paths return before any
    //! upstream call; the strip/inject invariant is exercised directly against
    //! `inject_oauth_bearer`. The full forward against the live Code Assist API
    //! is a operator live-verify item + the daemon session-wiring slice.
    use super::*;
    use async_trait::async_trait;
    use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
    use core_proxy_forward::{
        PolicyError, PreflightDecision, ResolvedGrant, SessionGatewayAuthority,
    };
    use std::sync::Arc as StdArc;
    use zeroize::Zeroizing;

    const BROKER_TOKEN: &str = "ya29.BrokerAccessToken";

    struct CodeAssistTestBackend {
        authority: Option<SessionGatewayAuthority>,
        statement_budget: Option<Budget>,
    }

    impl CodeAssistTestBackend {
        fn with_authority() -> Self {
            Self {
                authority: Some(SessionGatewayAuthority {
                    session_id: "sess_gca".into(),
                    persona_id: "alice".into(),
                    grant_id: "g-gca".into(),
                    credential_name: "google/code-assist-oauth".into(),
                }),
                statement_budget: None,
            }
        }
        fn with_budgeted_authority() -> Self {
            let mut b = Self::with_authority();
            b.statement_budget = Some(Budget {
                tokens: Some(10_000),
                cents: None,
                requests: None,
                workload_hours: None,
                wall_clock_secs: None,
            });
            b
        }
        fn no_authority() -> Self {
            Self {
                authority: None,
                statement_budget: None,
            }
        }
        fn with_credential(credential_name: &str) -> Self {
            Self {
                authority: Some(SessionGatewayAuthority {
                    session_id: "sess_gca".into(),
                    persona_id: "alice".into(),
                    grant_id: "g-gca".into(),
                    credential_name: credential_name.into(),
                }),
                statement_budget: None,
            }
        }
    }

    fn google_statement(budget: Option<Budget>) -> Statement {
        Statement {
            sid: "stmt-gca".into(),
            resource_type: ResourceType::Session,
            actions: vec!["llm:generate".into()],
            resource: ResourceSelector::Glob {
                pattern: "google/*".into(),
            },
            budget,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        }
    }

    #[async_trait]
    impl PolicyBackend for CodeAssistTestBackend {
        async fn resolve_session_authority(
            &self,
            _session_id: &str,
        ) -> Result<Option<SessionGatewayAuthority>, PolicyError> {
            Ok(self.authority.clone())
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
                grant_id: "g-gca".into(),
                persona_id: persona_id.into(),
                credential_name: credential_name.into(),
                statement_sid: "stmt-gca".into(),
                statement: google_statement(self.statement_budget.clone()),
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
            // Code Assist resolves via resolve_oauth_bearer, not get_credential.
            Err(PolicyError::Other("unused".into()))
        }
        async fn resolve_oauth_bearer(
            &self,
            _credential_name: &str,
        ) -> Result<Zeroizing<String>, PolicyError> {
            Ok(Zeroizing::new(BROKER_TOKEN.into()))
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

    fn req(method: hyper::Method, uri: &str) -> Request<http_body_util::Empty<Bytes>> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap()
    }

    const GEN_PATH: &str = "/v1internal:generateContent";

    #[test]
    fn code_assist_projector_contract_is_pinned() {
        assert_eq!(GEMINI_CODE_ASSIST_PROJECTOR.name, "gemini-code-assist");
        assert_eq!(GEMINI_CODE_ASSIST_PROJECTOR.provider_prefix, "google/");
        assert_eq!(GEMINI_CODE_ASSIST_PROJECTOR.access_detail, "gemini-code-assist");
        assert!(
            matches!(
                GEMINI_CODE_ASSIST_PROJECTOR.injection,
                CredentialInjection::OAuthBearer
            ),
            "code assist uses the OAuth Bearer injection strategy"
        );
    }

    #[test]
    fn code_assist_gate_admits_v1internal_methods_and_operations() {
        let accepts = GEMINI_CODE_ASSIST_PROJECTOR.accepts;
        let uri = |s: &str| s.parse::<http::Uri>().unwrap();
        // POST custom-verb methods:
        assert!(accepts(&hyper::Method::POST, &uri(GEN_PATH)));
        assert!(accepts(
            &hyper::Method::POST,
            &uri("/v1internal:streamGenerateContent?alt=sse")
        ));
        assert!(accepts(&hyper::Method::POST, &uri("/v1internal:loadCodeAssist")));
        assert!(accepts(&hyper::Method::POST, &uri("/v1internal:onboardUser")));
        // GET reads + operation polls (the handshake needs these):
        assert!(accepts(
            &hyper::Method::GET,
            &uri("/v1internal:getCodeAssistGlobalUserSetting")
        ));
        assert!(accepts(
            &hyper::Method::GET,
            &uri("/v1internal/operations/op-123")
        ));
        assert!(!accepts(
            &hyper::Method::POST,
            &uri("/v1internal/operations/op-123")
        ));
        // Rejected methods:
        assert!(!accepts(&hyper::Method::PUT, &uri(GEN_PATH)));
        assert!(!accepts(&hyper::Method::DELETE, &uri(GEN_PATH)));
        // Wrong prefix / shape:
        assert!(!accepts(
            &hyper::Method::POST,
            &uri("/v1beta/models/gemini-3-flash:generateContent")
        ));
        assert!(!accepts(&hyper::Method::POST, &uri("/v1internal")));
        assert!(!accepts(&hyper::Method::POST, &uri("/v1internal:")));
        // A colon-method must be a single token (no further path segments):
        assert!(!accepts(
            &hyper::Method::POST,
            &uri("/v1internal:generateContent/extra")
        ));
    }

    #[test]
    fn code_assist_gate_rejects_authority_and_traversal() {
        let accepts = GEMINI_CODE_ASSIST_PROJECTOR.accepts;
        let smuggled = "//evil.example/v1internal:generateContent"
            .parse::<http::Uri>()
            .unwrap();
        assert!(!accepts(&hyper::Method::POST, &smuggled));
        let absolute = "https://evil.example/v1internal:generateContent"
            .parse::<http::Uri>()
            .unwrap();
        assert!(!accepts(&hyper::Method::POST, &absolute));
        for p in [
            "/v1internal/operations/../../v1internal:generateContent",
            "/v1internal:%2e%2egenerateContent",
            "/v1internal/operations//x",
            // M1: an operation sub-verb (mutation, e.g. cancel) or sub-path is
            // NOT a bare poll and must be rejected.
            "/v1internal/operations/op-123:cancel",
            "/v1internal/operations/op-123/sub",
        ] {
            let uri = p.parse::<http::Uri>().unwrap();
            assert!(!accepts(&hyper::Method::POST, &uri), "must reject {p}");
        }
    }

    #[test]
    fn code_assist_upstream_pins_cloudcode_pa_and_preserves_path_query() {
        let upstream = GEMINI_CODE_ASSIST_PROJECTOR.upstream;
        let (url, host) = upstream(
            &"/v1internal:streamGenerateContent?alt=sse"
                .parse::<http::Uri>()
                .unwrap(),
        );
        assert_eq!(host, "cloudcode-pa.googleapis.com");
        assert_eq!(
            url,
            "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
        );
        assert_eq!(host, gemini_code_assist_host());
    }

    #[test]
    fn code_assist_inject_oauth_bearer_strips_client_auth_and_sets_bearer() {
        let mut headers = hyper::HeaderMap::new();
        // The CLI signs client-side with google-auth-library; that Bearer must
        // be replaced, not pass through.
        headers.insert("authorization", "Bearer client-signed".parse().unwrap());
        headers.insert("x-api-key", "attacker".parse().unwrap());
        headers.insert("x-goog-api-key", "attacker".parse().unwrap());
        inject_oauth_bearer(&mut headers, BROKER_TOKEN).expect("inject");
        assert_eq!(
            headers.get("authorization").and_then(|v| v.to_str().ok()),
            Some(format!("Bearer {BROKER_TOKEN}").as_str()),
            "broker Bearer replaces the client's signed one"
        );
        assert!(headers.get("x-api-key").is_none());
        assert!(headers.get("x-goog-api-key").is_none());
    }

    #[test]
    fn code_assist_inject_trims_trailing_newline() {
        let mut headers = hyper::HeaderMap::new();
        inject_oauth_bearer(&mut headers, "ya29.tok\n").expect("inject");
        assert_eq!(
            headers.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer ya29.tok")
        );
    }

    #[tokio::test]
    async fn code_assist_fail_closed_no_session_authority() {
        let backend = StdArc::new(CodeAssistTestBackend::no_authority());
        let resp = handle_loopback_projector_request(
            &GEMINI_CODE_ASSIST_PROJECTOR,
            backend,
            req(hyper::Method::POST, GEN_PATH),
            "sess_unknown".into(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn code_assist_fail_closed_non_google_credential() {
        for cred in ["anthropic/oauth-token", "openai/session-key", "github/pat"] {
            let backend = StdArc::new(CodeAssistTestBackend::with_credential(cred));
            let resp = handle_loopback_projector_request(
                &GEMINI_CODE_ASSIST_PROJECTOR,
                backend,
                req(hyper::Method::POST, GEN_PATH),
                "sess_gca".into(),
            )
            .await
            .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "non-google credential {cred} must be refused"
            );
        }
    }

    #[tokio::test]
    async fn code_assist_budgeted_grant_blocks_streaming_before_token_read() {
        let backend = StdArc::new(CodeAssistTestBackend::with_budgeted_authority());
        let resp = handle_loopback_projector_request(
            &GEMINI_CODE_ASSIST_PROJECTOR,
            backend,
            req(hyper::Method::POST, "/v1internal:streamGenerateContent?alt=sse"),
            "sess_gca".into(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn code_assist_strict_gate_rejects_before_authority() {
        for (method, path) in [
            (hyper::Method::PUT, GEN_PATH),
            (hyper::Method::POST, "/v1beta/models/x:generateContent"),
            (hyper::Method::POST, "/v1internal:gen/erate"),
        ] {
            let backend = StdArc::new(CodeAssistTestBackend::with_authority());
            let resp = handle_loopback_projector_request(
                &GEMINI_CODE_ASSIST_PROJECTOR,
                backend,
                req(method.clone(), path),
                "sess_gca".into(),
            )
            .await
            .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{method} {path} must be rejected by the strict gate"
            );
        }
    }
}
