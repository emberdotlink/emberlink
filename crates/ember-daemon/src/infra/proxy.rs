use std::cell::RefCell;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::LengthLimitError;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Frame, SizeHint};
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, oneshot, watch};
use tokio::time::Sleep;
use zeroize::Zeroizing;

use async_trait::async_trait;
use core_proxy_forward::r#match::{
    MethodTier, effective_scope_uri, extract_github_branch, extract_host_from_url,
    git_echo_owner_repo, github_target_matches, glob_match_branch, host_matches_domain,
    is_git_smart_http_path, method_tier, request_to_action_resource, wildcard_match,
};
use core_proxy_forward::{EventError, EventSink, PolicyBackend, ThresholdAxis, ThresholdBand};
use hyper::http;

use crate::infra::events::GrantEvent;
use crate::infra::store::StoreError;
use crate::infra::vault::{VaultError, VaultScope};
use crate::pricing;

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
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

/// Upper bound on the bytes a streaming proxy response is allowed to
/// accumulate before we abort the downstream tee.
///
/// development milestone (2026-04-23): lowered from 16 MiB to 1 MiB. The tee exists
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
const MAX_STREAMING_RESPONSE_BYTES: usize = 1024 * 1024;

/// Maximum number of streaming proxy requests allowed in flight at once.
///
/// development milestone (2026-04-23): each in-flight streaming request owns a
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
const MAX_CONCURRENT_STREAMING: usize = 32;

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
static STREAMING_REQUESTS_INFLIGHT: AtomicUsize = AtomicUsize::new(0);

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
    fn try_acquire() -> Option<Self> {
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
    #[cfg(test)]
    fn inflight() -> usize {
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
    /// Anthropic streaming path () via `stream_response`.
    ///
    /// P69L.0b--GATE + P69L.0b--DROP-GUARD (2026-04-24): carries an
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
/// development milestone (P69L.0b--GATE + P69L.0b--DROP-GUARD 2026-04-24):
/// this mirrors `TeeBody`'s RAII-slot pattern but without accumulation —
/// the passthrough path does NOT need the tee buffer because git
/// smart-HTTP bodies are forwarded chunk-for-chunk to the client. The
/// slot + drop guard give us the same "every terminal path releases
/// resources exactly once" contract `TeeBody` has.
///
/// P69L.0b--ERROR-SIGNAL (2026-04-24): before emitting the terminal
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
/// event (P69L.0b--AUDIT) always uses the same string so log and wire
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
    bytes_forwarded: Arc<AtomicU64>,
    /// Stream outcome state machine. `0 = inflight`, `1 = complete`
    /// (clean EOF observed), `2 = partial` (upstream error or body
    /// dropped before EOF). Drop treats anything other than
    /// `complete` as `partial`.
    outcome: Arc<AtomicU8>,
    /// P69L.0b--TIMEOUTS: per-frame idle watchdog. When `Some`, the
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
    /// P69L.0b--ERROR-SIGNAL: tracks whether the trailer has been
    /// emitted yet. `false` = not yet (initial state); `true` = already
    /// emitted. Once the upstream reaches a terminal condition (clean EOF,
    /// upstream error, watchdog abort), `poll_frame` emits the
    /// `x-ember-stream-outcome` trailer frame and sets this to `true`.
    /// Subsequent polls skip straight to `Ready(None)`.
    trailer_emitted: bool,
    /// P69L.0b--AUDIT: correlating identifier threaded from
    /// `handle_git_echo` entry through to drop-time `proxy.stream`
    /// emission. `None` on code paths that don't participate in the
    /// git-echo audit trail (e.g., Anthropic SSE via `stream_response`).
    request_id: Option<Arc<str>>,
    /// Test-only deterministic hook. Set by unit tests so `Drop` can
    /// publish the final outcome without depending on a tracing
    /// subscriber. `None` in production — the `tracing::info!` call is
    /// the observable signal.
    #[cfg(test)]
    test_outcome_sink: Option<Arc<AtomicU8>>,
    /// Test-only bytes-forwarded hook — same rationale as
    /// `test_outcome_sink` but for the accumulated byte count, so a
    /// test can assert both invariants without log scraping.
    #[cfg(test)]
    test_bytes_sink: Option<Arc<AtomicU64>>,
}

/// Outcome constants for `PassthroughBody::outcome`. Kept as bare
/// integers (not an enum) because `AtomicU8` can't hold a repr-enum
/// and we want branch-free atomic updates on the hot path.
const PASSTHROUGH_INFLIGHT: u8 = 0;
const PASSTHROUGH_COMPLETE: u8 = 1;
const PASSTHROUGH_PARTIAL: u8 = 2;

/// The header name for the stream-outcome trailer emitted by
/// `PassthroughBody` (P69L.0b--ERROR-SIGNAL).
const STREAM_OUTCOME_TRAILER_NAME: &str = "x-ember-stream-outcome";

/// Build the `x-ember-stream-outcome` HTTP trailer `HeaderMap` for the
/// given outcome constant. `PASSTHROUGH_COMPLETE` → `"complete"`, any
/// other value → `"partial"`. Called by `PassthroughBody::poll_frame`
/// just before emitting the terminal `Ready(None)`.
fn build_outcome_trailer(outcome: u8) -> hyper::HeaderMap {
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
    fn new(inner: B, slot: Option<StreamingSlot>) -> Self {
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
            #[cfg(test)]
            test_outcome_sink: None,
            #[cfg(test)]
            test_bytes_sink: None,
        }
    }

    /// Attach a correlating `request_id` so the drop-time `proxy.stream`
    /// log line can be joined with the `credential.access` entry emitted
    /// at `handle_git_echo` entry. Called by `handle_git_echo` after
    /// acquiring the streaming slot; never called on the Anthropic SSE path.
    fn with_request_id(mut self, id: Arc<str>) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Enable the per-frame idle watchdog. When no data frame is observed
    /// from `inner` for at least `deadline`, `poll_frame` aborts the
    /// stream with `outcome=partial` and the drop-guard log line reports
    /// `reason=frame-idle-timeout`. Called by
    /// `stream_response_with_frame_idle` on the production path.
    fn with_frame_idle(mut self, deadline: Duration) -> Self {
        self.frame_idle_deadline = Some(deadline);
        self
    }

    /// Install deterministic test sinks so a unit test can observe the
    /// drop-time outcome + byte count without depending on a tracing
    /// subscriber. Called once at construction in tests; never in
    /// production (gated by `#[cfg(test)]`).
    #[cfg(test)]
    fn with_test_sinks(mut self, outcome_sink: Arc<AtomicU8>, bytes_sink: Arc<AtomicU64>) -> Self {
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

        // P69L.0b--ERROR-SIGNAL: once the trailer has been emitted,
        // every subsequent poll returns `Ready(None)` — the body is done.
        // Also covers the frame-idle-watchdog termination path: the
        // watchdog arm sets `trailer_emitted = true` before returning the
        // trailer frame, so repeat polls land here and end cleanly.
        if this.trailer_emitted {
            return Poll::Ready(None);
        }

        // P69L.0b--TIMEOUTS: frame_idle_fired is set by the watchdog arm
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
        // P69L.0b--AUDIT: emit `proxy.stream` with the correlating
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
        #[cfg(test)]
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

/// Wrap a buffered `Full<Bytes>` body in the proxy's unified response body
/// type. Used by every error/response helper so callers don't have to
/// thread the enum tag explicitly.
fn box_full(body: Full<Bytes>) -> ProxyBody {
    ProxyBody::Buffered(body)
}

/// Hop-by-hop headers per RFC 7230 §6.1. These MUST NOT be forwarded by a
/// proxy — they describe the single transport hop, not the end-to-end
/// message. `trailer` is the RFC-canonical spelling; we include `trailers`
/// (the plural commonly seen in the wild) defensively.
///
/// Stored lowercased because `HeaderName` comparison is case-insensitive
/// and the RFC tokens are ASCII.
const HOP_BY_HOP_HEADERS: &[&str] = &[
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
const ALLOWED_REQUEST_HEADERS: &[&str] = &[
    "accept",
    // `accept-encoding` deliberately omitted — implementation-note-45.
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
fn filter_request_headers(
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
fn strip_hop_by_hop_headers(headers: &mut hyper::HeaderMap) {
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
/// streaming path () — both need chunk-at-a-time forwarding without
/// the accumulation overhead of `TeeBody`.
///
/// `slot` is the acquired concurrency gate handle; it rides inside the
/// response body and is released automatically when the body is dropped
/// (clean EOF, upstream error, or client disconnect mid-stream). Callers
/// on the production path pass `Some(slot)` from `StreamingSlot::try_acquire`;
/// test callers may pass `None` to exercise the body shape without
/// touching the process-global gate.
#[allow(dead_code)]
pub(crate) fn stream_response(
    upstream: Response<Incoming>,
    slot: Option<StreamingSlot>,
) -> Response<ProxyBody> {
    // Preserved for the Anthropic streaming path () which does not
    // need a frame-idle watchdog (the SSE heartbeat serves that role).
    stream_response_with_frame_idle(upstream, slot, None)
}

/// Variant of `stream_response` that additionally enables the per-frame
/// idle watchdog (P69L.0b--TIMEOUTS). When `frame_idle` is `Some`, the
/// passthrough body will abort with `outcome=partial
/// reason=frame-idle-timeout` if no data frame arrives within the
/// specified deadline. `None` yields the same behaviour as
/// `stream_response`.
pub(crate) fn stream_response_with_frame_idle(
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

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("client error: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),
    #[error("http error: {0}")]
    Http(#[from] hyper::http::Error),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("vault error: {0}")]
    Vault(VaultError),
    #[error("vault unavailable")]
    VaultUnavailable,
    #[error("policy backend error: {0}")]
    PolicyBackend(core_proxy_forward::PolicyError),
}

impl From<VaultError> for ProxyError {
    fn from(e: VaultError) -> Self {
        ProxyError::Vault(e)
    }
}

pub struct ProxyConfig {
    pub bind_addr: std::net::SocketAddr,
}

pub struct ProxyState {
    pub store: crate::infra::store::DaemonStore,
    #[cfg(test)]
    pub vault: std::rc::Rc<crate::infra::vault::Vault>,
    /// Audit-log + broadcast sink, installed once during proxy spawn.
    ///
    /// implementation-note-273: the threshold-debounce set and the
    /// broadcast channel both moved INTO `DaemonEventSink`. `ProxyState`
    /// now holds a `OnceLock` pointer to the sink so the existing
    /// `state.sink_*` shim methods (and `emit_threshold_crossings` /
    /// `emit_debounced`) can reach the sink without re-threading every
    /// helper signature with `&dyn EventSink`. The `OnceLock` is required
    /// because of the circular construction: `DaemonEventSink::new` takes
    /// `Arc<ProxyState>`, but `ProxyState` must own a back-pointer to the
    /// sink. Callers install the sink immediately after construction with
    /// `state.event_sink.set(...)`.
    pub event_sink: OnceLock<Arc<DaemonEventSink>>,
}

impl ProxyState {
    pub fn new(store: crate::infra::store::DaemonStore) -> Self {
        Self {
            #[cfg(test)]
            vault: store
                .vault()
                .expect("ProxyState::new tests require a live vault attached to the store"),
            store,
            event_sink: OnceLock::new(),
        }
    }

    fn current_vault(&self) -> Result<std::rc::Rc<crate::infra::vault::Vault>, ProxyError> {
        crate::infra::interactive_unlock::current_live_vault(&self.store)
            .map_err(|_| ProxyError::VaultUnavailable)
    }

    /// Borrow the installed `DaemonEventSink`. Panics if the sink has not
    /// yet been installed — callers must `state.event_sink.set(sink)`
    /// immediately after `ProxyState::new`. The panic message names the
    /// invariant so a regression surfaces a structured failure rather
    /// than a generic `unwrap_or` silently dropping audit writes.
    pub(crate) fn sink(&self) -> &DaemonEventSink {
        self.event_sink
            .get()
            .expect("ProxyState::sink — event_sink must be installed via OnceLock::set immediately after ProxyState::new")
    }

    /// Sync shim around `DaemonEventSink::log_event_sync` so the existing
    /// 8 `state.store.log_event(...)` call sites can route through the
    /// `EventSink` surface without changing their helper signatures.
    pub(crate) fn sink_log_event(
        &self,
        persona_id: Option<&str>,
        event_kind: &str,
        credential_name: Option<&str>,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<(), EventError> {
        self.sink()
            .log_event_sync(persona_id, event_kind, credential_name, outcome, detail)
    }

    /// Sync shim around `DaemonEventSink::broadcast_sync` so
    /// `emit_debounced` can push a `GrantEvent` to subscribers without
    /// touching `state.events_tx` directly (which is now sink-owned).
    pub(crate) fn sink_broadcast(&self, event: GrantEvent) {
        self.sink().broadcast_sync(event);
    }

    /// Sync shim around `DaemonEventSink::record_threshold_crossing_sync`.
    /// Returns `true` if `(grant_id, statement_sid, axis, band)` was newly
    /// inserted, `false` if it had already been recorded.
    ///
    /// Currently unused by the in-place call sites — they reach for the
    /// `try_record_threshold_keys` variant which preserves the precise
    /// `"80"`/`"95"`/`"100"` band sub-labels carried on the wire. Kept
    /// here as the canonical enum-form shim for Slice C's remote backend
    /// (which round-trips `ThresholdAxis` / `ThresholdBand` over the UDS
    /// RPC and would project back to keys on the daemon side).
    #[allow(dead_code)]
    pub(crate) fn sink_record_threshold(
        &self,
        grant_id: &str,
        statement_sid: &str,
        axis: ThresholdAxis,
        band: ThresholdBand,
    ) -> bool {
        self.sink()
            .record_threshold_crossing_sync(grant_id, statement_sid, axis, band)
    }
}

/// Production `PolicyBackend` implementation for the ember daemon.
///
/// Wraps an `Arc<ProxyState>` and implements the five trait methods by
/// delegating to the daemon's `DaemonStore` and resolving the current live
/// vault at point of use.
///
/// All connections run on a single-threaded `LocalSet` (see `run_proxy`),
/// which is why `ProxyState` can hold the daemon's `!Send` store and reach
/// the sink's `RefCell` debounce set through `event_sink`. The
/// `unsafe impl Send + Sync` below acknowledges this invariant and matches
/// the existing `#[allow(clippy::arc_with_non_send_sync)]` usage throughout
/// the proxy infrastructure.
pub struct DaemonPolicyBackend {
    inner: Arc<ProxyState>,
}

impl DaemonPolicyBackend {
    pub fn new(state: Arc<ProxyState>) -> Self {
        Self { inner: state }
    }
}

// SAFETY: DaemonPolicyBackend is only ever used on the single-threaded
// LocalSet that `run_proxy` creates. The ProxyState it wraps reaches a
// `DaemonStore` (`rusqlite::Connection`, `!Send`) and a `DaemonEventSink`
// carrying a `RefCell` debounce set; neither is safe to share across
// threads in the general case, but the LocalSet invariant guarantees
// there is no concurrent access. This matches the existing
// `arc_with_non_send_sync` pattern used throughout the proxy infrastructure.
unsafe impl Send for DaemonPolicyBackend {}
unsafe impl Sync for DaemonPolicyBackend {}

#[async_trait]
impl PolicyBackend for DaemonPolicyBackend {
    async fn resolve_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
        pinned_grant_id: Option<&str>,
        effective_uri: &http::Uri,
        method: &str,
    ) -> Result<core_proxy_forward::ResolvedGrant, core_proxy_forward::PolicyError> {
        use core_proxy_forward::PolicyError;

        let grant = if let Some(gid) = pinned_grant_id {
            match self.inner.store.get_grant(gid) {
                Ok(g) => {
                    if g.persona_id != persona_id {
                        return Err(PolicyError::Forbidden(
                            "grant belongs to a different persona".into(),
                        ));
                    }
                    if g.credential_name != credential_name {
                        return Err(PolicyError::Forbidden(
                            "grant credential_name does not match X-Ember-Credential".into(),
                        ));
                    }
                    if g.status != "active" {
                        return Err(PolicyError::Forbidden(format!(
                            "grant is {} and cannot be used",
                            g.status
                        )));
                    }
                    g
                }
                Err(StoreError::NotFound) => {
                    return Err(PolicyError::NotFound(
                        "no active grant for X-Ember-Grant-Id".into(),
                    ));
                }
                Err(e) => return Err(PolicyError::Store(e.to_string())),
            }
        } else {
            match self.inner.store.evaluate_grant(persona_id, credential_name) {
                Ok(g) => g,
                Err(StoreError::NotFound) => {
                    return Err(PolicyError::NotFound(
                        "no active grant for persona/credential".into(),
                    ));
                }
                Err(e) => return Err(PolicyError::Store(e.to_string())),
            }
        };

        let access_grant = self
            .inner
            .store
            .get_access_grant(&grant.id)
            .map_err(|e| PolicyError::Store(e.to_string()))?;

        let hyper_method = method
            .parse::<hyper::Method>()
            .unwrap_or(hyper::Method::GET);
        let hyper_uri: hyper::Uri =
            effective_uri
                .to_string()
                .parse()
                .map_err(|e: hyper::http::uri::InvalidUri| {
                    PolicyError::Other(format!("invalid URI: {e}"))
                })?;

        let (resolved_sid, resolved_stmt) = if let Some((action, resource)) =
            request_to_action_resource(&hyper_method, &hyper_uri)
        {
            match resolve_statement_for_request_with_uri(
                &access_grant,
                &action,
                &resource,
                &hyper_uri,
            ) {
                ResolveOutcome::NoApplicable => {
                    if let Err(e) = self.inner.store.log_event(
                        Some(persona_id),
                        "credential.access",
                        Some(credential_name),
                        "denied_no_applicable_statement",
                        Some(&format!("action={action} resource={resource}")),
                    ) {
                        tracing::warn!(error = ?e, persona_id, credential = credential_name, "log_event failed in resolve_grant");
                    }
                    return Err(PolicyError::Forbidden("no_applicable_statement".into()));
                }
                ResolveOutcome::SubtargetMiss { subtarget_glob } => {
                    if let Err(e) = self.inner.store.log_event(
                        Some(persona_id),
                        "credential.access",
                        Some(credential_name),
                        "denied_subtarget_scope",
                        Some(&format!(
                            "action={action} resource={resource} subtarget_glob={subtarget_glob}"
                        )),
                    ) {
                        tracing::warn!(error = ?e, persona_id, credential = credential_name, "log_event failed in resolve_grant");
                    }
                    return Err(PolicyError::Forbidden("denied_subtarget_scope".into()));
                }
                ResolveOutcome::Match { index: _, stmt } => (stmt.sid.clone(), stmt.clone()),
            }
        } else {
            return Err(PolicyError::Forbidden("unsupported HTTP method".into()));
        };

        let revoked_sids = self
            .inner
            .store
            .get_revoked_sids(&grant.id)
            .map_err(|e| PolicyError::Store(e.to_string()))?;
        if revoked_sids.contains(&resolved_sid) {
            if let Err(e) = self.inner.store.log_event(
                Some(persona_id),
                "credential.access",
                Some(credential_name),
                "denied_statement_revoked",
                Some(&format!("grant_id={} sid={resolved_sid}", grant.id)),
            ) {
                tracing::warn!(error = ?e, grant_id = %grant.id, statement_sid = %resolved_sid, "log_event failed in resolve_grant");
            }
            // Beat 7 (SCION 2026-05-15 demo) — carry the sid through the
            // Forbidden(String) channel so handle_request can render a
            // structured JSON 403 with {persona_id, statement_id}. Format:
            // "statement_revoked:<sid>". Consumer parses out the sid; old
            // generic 403 string ("statement revoked", with space) is gone.
            return Err(PolicyError::Forbidden(format!(
                "statement_revoked:{resolved_sid}"
            )));
        }

        Ok(core_proxy_forward::ResolvedGrant {
            grant_id: grant.id.clone(),
            persona_id: grant.persona_id.clone(),
            credential_name: grant.credential_name.clone(),
            statement_sid: resolved_sid,
            statement: resolved_stmt,
            grant_scope: grant.scope.clone(),
            allowed_targets: grant.allowed_targets.clone(),
        })
    }

    async fn preflight_budget(
        &self,
        resolved: &core_proxy_forward::ResolvedGrant,
        body_bytes: &[u8],
    ) -> Result<core_proxy_forward::PreflightDecision, core_proxy_forward::PolicyError> {
        match preflight_budget_check(&resolved.statement, body_bytes) {
            PreflightDecision::Allowed => Ok(core_proxy_forward::PreflightDecision::Allowed),
            PreflightDecision::Rejected { axis, limit, used } => {
                Ok(core_proxy_forward::PreflightDecision::Rejected { axis, limit, used })
            }
        }
    }

    async fn get_credential(
        &self,
        credential_name: &str,
    ) -> Result<zeroize::Zeroizing<String>, core_proxy_forward::PolicyError> {
        let vault = self
            .inner
            .current_vault()
            .map_err(|e| core_proxy_forward::PolicyError::Vault(e.to_string()))?;
        match vault.get(VaultScope::Interactive, &self.inner.store, credential_name) {
            Ok(bytes) => {
                let s = String::from_utf8_lossy(&bytes).into_owned();
                Ok(zeroize::Zeroizing::new(s))
            }
            Err(VaultError::NotFound) => Err(core_proxy_forward::PolicyError::NotFound(format!(
                "credential not found in vault: {credential_name}"
            ))),
            Err(e) => Err(core_proxy_forward::PolicyError::Vault(e.to_string())),
        }
    }

    async fn post_flight(
        &self,
        resolved: &core_proxy_forward::ResolvedGrant,
        usage: Option<core_grant_types::Usage>,
    ) -> Result<(), core_proxy_forward::PolicyError> {
        let Some(delta) = usage else {
            return Ok(());
        };
        let credential_hash = hash_credential_name_for_audit(&resolved.credential_name);
        match self.inner.store.log_event(
            Some(&resolved.persona_id),
            "proxy.meter",
            Some(&credential_hash),
            "complete",
            Some(&format!(
                "grant_id={} sid={} tokens={} cents={}",
                resolved.grant_id, resolved.statement_sid, delta.tokens, delta.cents
            )),
        ) {
            Ok(_) => {}
            Err(e) => tracing::warn!(
                error = ?e,
                grant_id = %resolved.grant_id,
                sid = %resolved.statement_sid,
                "proxy.meter audit log_event failed"
            ),
        }
        match self.inner.store.increment_statement_usage(
            &resolved.grant_id,
            &resolved.statement_sid,
            delta,
        ) {
            Ok(usage_delta) => {
                if let Some(budget) = &resolved.statement.budget {
                    emit_threshold_crossings(
                        &self.inner,
                        &resolved.grant_id,
                        &resolved.statement_sid,
                        &resolved.persona_id,
                        &resolved.credential_name,
                        budget,
                        &usage_delta.prior,
                        &usage_delta.current,
                    );
                }
                let _ = self
                    .inner
                    .store
                    .mark_grant_exhausted_by_budget_if_terminal(&resolved.grant_id);
            }
            Err(e) => {
                tracing::warn!(
                    grant_id = %resolved.grant_id,
                    sid = %resolved.statement_sid,
                    error = ?e,
                    "DaemonPolicyBackend::post_flight: failed to increment statement usage"
                );
            }
        }
        Ok(())
    }

    // implementation-note-212: post_flight_meter is the trait-level entry
    // point for credential-grant metering after the upstream call completes.
    // Distinct from `post_flight` at the trait level so Slice C's remote
    // backend can route the two through different metering paths. The
    // in-process daemon implementation runs the same audit + increment
    // logic — they only diverge when Slice E lifts the proxy out-of-process.
    async fn post_flight_meter(
        &self,
        resolved: &core_proxy_forward::ResolvedGrant,
        usage: Option<core_grant_types::Usage>,
    ) -> Result<(), core_proxy_forward::PolicyError> {
        self.post_flight(resolved, usage).await
    }

    async fn log_event(
        &self,
        persona_id: &str,
        event_kind: &str,
        credential_name: Option<&str>,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<(), core_proxy_forward::PolicyError> {
        self.inner
            .store
            .log_event(
                Some(persona_id),
                event_kind,
                credential_name,
                outcome,
                detail,
            )
            .map(|_| ())
            .map_err(|e| core_proxy_forward::PolicyError::Store(e.to_string()))
    }
}

/// `EventSink` implementation for the ember daemon — landed in
/// implementation-note-212 and finished in B-2.
///
/// Wraps the daemon's `ProxyState` so the proxy pipeline can route audit
/// writes + grant-event broadcasts through the trait surface. This is the
/// in-process implementation; Slice C lands the remote variant
/// (`UdsEventSink`) that RPCs to the daemon over a unix socket.
///
/// **Migration status (B-2 — this slice):** the in-place
/// `state.store.log_event` / `state.events_tx.send` /
/// `state.threshold_emitted.insert` call sites now route through this
/// sink via `ProxyState`'s sync shim methods (`sink_log_event`,
/// `sink_broadcast`, `sink_record_threshold`). The fields previously held
/// directly on `ProxyState` (`threshold_emitted`, `events_tx`) live here
/// now; `ProxyState` owns a `OnceLock<Arc<DaemonEventSink>>` so the shim
/// methods can reach the sink without re-threading every helper signature
/// with `&dyn EventSink`.
///
/// SAFETY: like `DaemonPolicyBackend`, `DaemonEventSink` wraps
/// `Arc<ProxyState>`. `ProxyState` carries the daemon's `!Send` SQLite
/// store, and this struct itself owns a `RefCell` debounce set. Neither is
/// safe to share across threads in the general case, but the daemon only
/// ever uses these on a single-threaded `LocalSet`. The `unsafe impl Send +
/// Sync` below acknowledges this invariant and matches the existing pattern
/// on `DaemonPolicyBackend`. If a future refactor moves the proxy off the
/// LocalSet, this invariant has to be re-proved.
pub struct DaemonEventSink {
    inner: Arc<ProxyState>,
    /// Optional broadcast channel to push `budget.warning` /
    /// `budget.exhausted` notifications to connected socket clients (agent
    /// SDKs). `None` in unit tests that only exercise audit-log emission
    /// and in the git-echo proxy spawn, which does not yet broadcast.
    ///
    /// Moved here from `ProxyState` in implementation-note-273 so
    /// the broadcast path is fully owned by the sink.
    events_tx: Option<broadcast::Sender<GrantEvent>>,
    /// In-memory debounce set for threshold-crossing emissions. Entries
    /// are `(grant_id, statement_sid, axis, band)` — adding to this set
    /// before emission guarantees `budget.warning` is never logged twice
    /// for the same threshold. The set resets on daemon restart, which is
    /// acceptable: a restarted daemon re-emitting a warning is a
    /// defensive duplicate, not a missed alert.
    ///
    /// `RefCell` is safe here because proxy connections run on a
    /// `LocalSet` (see `run_proxy`) — the single-threaded runtime gives
    /// non-Sync interior mutability for free without a Mutex. Moved here
    /// from `ProxyState` in implementation-note-273.
    threshold_emitted: RefCell<HashSet<(String, String, &'static str, &'static str)>>,
}

impl DaemonEventSink {
    pub fn new(state: Arc<ProxyState>, events_tx: Option<broadcast::Sender<GrantEvent>>) -> Self {
        Self {
            inner: state,
            events_tx,
            threshold_emitted: RefCell::new(HashSet::new()),
        }
    }

    /// Sync inherent for audit-log writes — used by `ProxyState::sink_log_event`
    /// and by the async trait impl below. Keeping the implementation sync
    /// (the trait surface is async-by-fiat) avoids `block_on` inside the
    /// LocalSet, which would panic on a current-thread runtime.
    pub(crate) fn log_event_sync(
        &self,
        persona_id: Option<&str>,
        event_kind: &str,
        credential_name: Option<&str>,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<(), EventError> {
        self.inner
            .store
            .log_event(persona_id, event_kind, credential_name, outcome, detail)
            .map(|_| ())
            .map_err(|e| EventError::Log(e.to_string()))
    }

    /// Sync inherent for grant-event broadcast — used by
    /// `ProxyState::sink_broadcast` and by the async trait impl below.
    /// `send` returns Err only when there are no active subscribers —
    /// that's the expected state in unit tests and before any client
    /// connects; ignore the result.
    pub(crate) fn broadcast_sync(&self, event: GrantEvent) {
        if let Some(tx) = self.events_tx.as_ref() {
            let _ = tx.send(event);
        }
    }

    /// Sync inherent for threshold-crossing dedup — used by
    /// `ProxyState::sink_record_threshold` and by the async trait impl
    /// below. Returns `true` if the tuple was newly inserted (i.e. this
    /// is the first crossing for that (grant, sid, axis, band) since the
    /// daemon started), `false` if it had already been recorded.
    pub(crate) fn record_threshold_crossing_sync(
        &self,
        grant_id: &str,
        statement_sid: &str,
        axis: ThresholdAxis,
        band: ThresholdBand,
    ) -> bool {
        let (axis_str, band_str) = threshold_keys(axis, band);
        let key = (
            grant_id.to_string(),
            statement_sid.to_string(),
            axis_str,
            band_str,
        );
        self.threshold_emitted.borrow_mut().insert(key)
    }

    /// Direct insert into the debounce set using already-projected
    /// `(axis, band)` string keys — used by the existing in-place
    /// `emit_debounced` site which builds the keys from its
    /// `&'static str` band/axis arguments rather than the
    /// `ThresholdAxis`/`ThresholdBand` enums.
    ///
    /// Returns `true` on a fresh insert. Bypasses the enum projection so
    /// callers that already have the wire-format keys do not pay the
    /// round-trip cost.
    pub(crate) fn try_record_threshold_keys(
        &self,
        grant_id: &str,
        statement_sid: &str,
        axis: &'static str,
        band: &'static str,
    ) -> bool {
        let key = (grant_id.to_string(), statement_sid.to_string(), axis, band);
        self.threshold_emitted.borrow_mut().insert(key)
    }
}

/// Project the `ThresholdAxis` / `ThresholdBand` enums onto their wire
/// `&'static str` keys. Extracted as a free function so both the sync
/// `record_threshold_crossing_sync` and the async trait impl can share
/// the projection without duplicating the match.
fn threshold_keys(axis: ThresholdAxis, band: ThresholdBand) -> (&'static str, &'static str) {
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

// SAFETY: matches the `unsafe impl` pattern on `DaemonPolicyBackend`. The
// inner `ProxyState` is `!Send` because of its SQLite store, and this
// struct itself holds a `RefCell<HashSet>` debounce set, but the daemon
// only ever uses these on a single-threaded `LocalSet`. The trait bound
// `EventSink: Send + Sync + 'static` is satisfied by promise, not by
// structural means; if a future refactor moves `DaemonEventSink` off the
// LocalSet, this invariant has to be re-proved.
unsafe impl Send for DaemonEventSink {}
unsafe impl Sync for DaemonEventSink {}

#[async_trait]
impl EventSink for DaemonEventSink {
    async fn log_event(
        &self,
        persona_id: Option<&str>,
        event_kind: &str,
        credential_name: Option<&str>,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<(), EventError> {
        self.log_event_sync(persona_id, event_kind, credential_name, outcome, detail)
    }

    async fn broadcast(&self, event: GrantEvent) {
        self.broadcast_sync(event);
    }

    async fn record_threshold_crossing(
        &self,
        grant_id: &str,
        statement_sid: &str,
        axis: ThresholdAxis,
        band: ThresholdBand,
    ) -> bool {
        self.record_threshold_crossing_sync(grant_id, statement_sid, axis, band)
    }
}

/// Run the general LLM/HTTP credential-injection proxy until `shutdown`
/// flips to `true`.
///
/// Mirrors `run_git_echo_proxy`'s contract: when `bind_tx` is `Some`, the
/// bound `SocketAddr` is sent immediately after `TcpListener::bind`
/// completes (on success the actual local addr — important for
/// `127.0.0.1:0` callers reading the assigned port; on failure an
/// `std::io::Error`). Bind success/failure must not depend on whether the
/// receiver is still listening (silent-ignore on dropped rx).
///
/// implementation-note-173 — added `bind_tx` so the daemon runtime can
/// wait for bind, log the actual URL, and write the `proxy.url` sidecar
/// before entering the main accept loop, matching `run_git_echo_proxy`'s
/// startup discipline.
pub async fn run_proxy(
    config: ProxyConfig,
    state: Arc<ProxyState>,
    mut shutdown: watch::Receiver<bool>,
    bind_tx: Option<oneshot::Sender<Result<std::net::SocketAddr, std::io::Error>>>,
) -> Result<(), ProxyError> {
    let listener = match TcpListener::bind(config.bind_addr).await {
        Ok(l) => {
            let local_addr = l.local_addr().unwrap_or(config.bind_addr);
            if let Some(tx) = bind_tx {
                let _ = tx.send(Ok(local_addr));
            }
            l
        }
        Err(e) => {
            let annotated =
                crate::infra::socket::annotate_bind_error(e, &config.bind_addr.to_string());
            tracing::warn!(addr = %config.bind_addr, error = %annotated, "llm proxy failed to bind");
            if let Some(tx) = bind_tx {
                let kind = annotated.kind();
                let _ = tx.send(Err(std::io::Error::new(kind, annotated.to_string())));
            }
            return Err(ProxyError::from(annotated));
        }
    };

    // Wrap ProxyState in DaemonPolicyBackend so handle_request receives a
    // PolicyBackend rather than the raw state. DaemonPolicyBackend is
    // !Send (ProxyState carries the daemon store, and reaches the sink's
    // RefCell debounce set via event_sink), but is safe to use on the
    // single-threaded LocalSet below.
    #[allow(clippy::arc_with_non_send_sync)]
    let backend = Arc::new(DaemonPolicyBackend::new(state));

    // Use a LocalSet so that Arc<DaemonPolicyBackend> (which wraps
    // rusqlite's !Sync Connection via ProxyState) does not need to cross
    // thread boundaries.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, _addr)) => {
                                let backend = Arc::clone(&backend);
                                let io = TokioIo::new(stream);
                                tokio::task::spawn_local(async move {
                                    let svc = hyper::service::service_fn(move |req| {
                                        let backend = Arc::clone(&backend);
                                        async move { handle_request(backend, req).await }
                                    });
                                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                                        .serve_connection(io, svc)
                                        .await
                                    {
                                        tracing::warn!(error = %e, "proxy connection error");
                                    }
                                });
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

    Ok(())
}

pub async fn handle_request<B: PolicyBackend>(
    backend: Arc<B>,
    req: Request<Incoming>,
) -> Result<Response<ProxyBody>, ProxyError> {
    let headers = req.headers();

    let persona_id = match headers.get("x-ember-persona").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Ok(bad_request("missing X-Ember-Persona header")),
    };

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

    // implementation-note-271 — when the caller pins the grant
    // by id (composite-grant flow: a single grant authorizes multiple
    // credentials, so the persona+credential pair alone may match more than
    // one grant), look it up directly. The looked-up grant must still match
    // the `X-Ember-Persona` and `X-Ember-Credential` headers so a leaked
    // grant_id can't be used to read a different persona's credentials.
    let pinned_grant_id = headers
        .get("x-ember-grant-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

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
            pinned_grant_id.as_deref(),
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
            } else if msg == "denied_subtarget_scope" {
                return Ok(scope_violation_response());
            } else if let Some(sid) = msg.strip_prefix("statement_revoked:") {
                // Beat 7 (SCION 2026-05-15 demo) — structured 403 names which
                // statement was killed so the agent can self-recover or the
                // operator can correlate against the dashboard tile.
                return Ok(statement_revoked_response(&persona_id, sid));
            }
            return Ok(forbidden(&msg));
        }
        Err(e) => return Err(ProxyError::PolicyBackend(e)),
    };

    // Enforce grant.scope against request method + effective URI (C-1 fix).
    // Fail closed on any unknown or ambiguous scope format. Do NOT leak the
    // scope string to the client — log it internally and return a generic 403.
    if let Err(violation) = check_scope(&resolved.grant_scope, req.method(), &effective_uri) {
        tracing::warn!(
            grant_id = %resolved.grant_id,
            persona_id = %persona_id,
            credential = %credential_name,
            method = %req.method(),
            uri = %req.uri(),
            scope = %resolved.grant_scope,
            detail = %violation.message,
            "scope violation: denying request"
        );
        if let Err(e) = backend
            .log_event(
                &persona_id,
                "credential.access",
                Some(&credential_name),
                violation.audit_outcome(),
                Some(&violation.message),
            )
            .await
        {
            tracing::warn!(error = ?e, persona_id = %persona_id, credential = %credential_name, outcome = violation.audit_outcome(), "log_event failed");
        }
        return Ok(scope_violation_response());
    }

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
    if let Some(ref targets) = resolved.allowed_targets {
        let allowed: Vec<&str> = targets.split(',').map(|s| s.trim()).collect();
        let target_host = effective_uri.host();

        let is_allowed = match target_host {
            Some(host) => allowed.iter().any(|pattern| {
                if let Some(domain) = pattern.strip_prefix("*.") {
                    host_matches_domain(host, domain)
                } else {
                    host == *pattern
                }
            }),
            None => false,
        };

        if !is_allowed {
            return Ok(forbidden(&format!(
                "target {} not in allowed origins: {}",
                target_url, targets
            )));
        }
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
            return Err(ProxyError::PolicyBackend(e));
        }
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
            return Err(ProxyError::PolicyBackend(e));
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

    // Build an HTTPS-capable client using rustls with system WebPKI roots.
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

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
    //     401. implementation-note-173 — FINDING B from the brief: the
    //     prior unconditional Bearer injection broke every Beat 4 Anthropic
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
    // Resolved upstream host BEFORE the auth branch (was previously only
    // resolved later for metering). `host_matches_domain` rejects look-
    // alike hosts like `notanthropic.com`.
    let target_host_lower: String = extract_host_from_url(&target_url).unwrap_or_default();

    let mut outgoing_req = outgoing.body(Full::new(body_bytes_in)).map_err(|e| {
        tracing::warn!(error = %e, "failed to build outgoing request");
        ProxyError::Http(e)
    })?;

    let auth_scheme = match inject_provider_auth(
        outgoing_req.headers_mut(),
        &target_host_lower,
        is_git_transport,
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

    // implementation-note-45: force uncompressed responses upstream
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
        ProxyError::Client(e)
    })?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    // streaming detection. Anthropic's `/v1/messages` endpoint emits
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
        // development milestone: gate the streaming path on a per-process
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
        // T-implementation-note-272: capture the upstream
        // status's 2xx-ness for the meter callback. The closure runs
        // post-flight on the tee thread; `status` itself is moved into
        // the response builder below, so we snapshot the bool here.
        let meter_upstream_ok = status.is_success();
        // Beat 4 demo observability: snapshot per-call context for the
        // `proxy_call` event the meter callback emits. The closure runs
        // post-flight on the tee thread, so every field that travels in
        // the event must be owned (no borrows of `parts`, `effective_uri`,
        // `status`).
        let meter_persona_id = persona_id.clone();
        let meter_grant_id = resolved.grant_id.clone();
        let meter_method = parts.method.as_str().to_string();
        let meter_path = effective_uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| effective_uri.path().to_string());
        let meter_status_code = status.as_u16();
        let meter_cb = TeeMeterCallback::new(
            move |summary: pricing::UsageSummary, tee_outcome: StreamOutcome| {
                // development milestone: the SSE wire format itself tells
                // us whether `message_stop` arrived. With incremental
                // parsing the flag is already on `UsageSummary`, so we
                // can downgrade Complete → Partial without a second
                // pass over the bytes (which we no longer keep). The
                // downgrade only applies to Anthropic streams; non-SSE
                // bodies keep the tee-level outcome unchanged.
                let _outcome = if tee_outcome == StreamOutcome::Complete
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
                emit_proxy_call_event(
                    &meter_persona_id,
                    &meter_grant_id,
                    &meter_method,
                    &meter_path,
                    meter_status_code,
                    pu.input_tokens,
                    pu.output_tokens,
                );

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

    // Stream C post-flight meter. Resolve the upstream host and parse
    // the response for token + cent usage. If the target isn't an LLM
    // provider we have pricing for, `meter_response` returns `None` and
    // we skip the increment — the request still forwards unchanged.
    //
    // T-implementation-note-272: pass `status.is_success()`
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
    // — Receipt r-...`. Split input/output tokens via a fresh parse_usage
    // call — the buffered body is still in scope. Non-LLM hosts (GitHub
    // etc.) skip token reporting; we still emit a `proxy_call` event so the
    // call is visible in the stream.
    {
        let (tin, tout) = pricing::provider_for_host(&target_host)
            .and_then(|provider| pricing::parse_usage(provider, resp_body.as_ref()))
            .map(|pu| (pu.input_tokens, pu.output_tokens))
            .unwrap_or((0, 0));
        let path = effective_uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| effective_uri.path().to_string());
        emit_proxy_call_event(
            &persona_id,
            &resolved.grant_id,
            parts.method.as_str(),
            &path,
            status.as_u16(),
            tin,
            tout,
        );
    }

    let mut builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        builder = builder.header(name, value);
    }

    Ok(builder.body(box_full(Full::new(resp_body))).unwrap())
}

/// True when the upstream response should be forwarded chunk-by-chunk
/// rather than buffered. We treat SSE (`text/event-stream`) and raw
/// chunked transfer as streaming; everything else is assumed
/// JSON-complete-per-response and goes through the buffered meter path.
fn is_streaming_upstream(headers: &hyper::HeaderMap) -> bool {
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

/// How a streaming response terminated. : the receipt / audit trail
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

/// C44-implementation-note-274: short, stable hash of a credential alias for
/// emission into the audit log's `credential` column.
///
/// Returns `credname-<first 16 hex of sha256>` — enough entropy to avoid
/// collisions inside a single persona's credential set, short enough to
/// stay log-readable, and prefixed so a reader can tell at a glance the
/// column holds a derivative and not a raw alias. Raw aliases live in
/// `statement_usage`/grant rows; to join a specific call, hash the raw
/// alias and match prefixes.
fn hash_credential_name_for_audit(credential_name: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(credential_name.as_bytes());
    format!("credname-{}", hex::encode(&digest[..8]))
}

/// Beat 4 (SCION × Emberlink demo 2026-05-15) — emit a `proxy_call` event
/// into `.ember/runtime/events.jsonl` so the orchestrator status tail can
/// render one log line per upstream call:
///
/// ```text
///   [proxy <agent>] POST /v1/messages — 200 — 312 tokens — Receipt r-7a3f...
/// ```
///
/// The event sits alongside the existing `proxy.meter` audit row (which is
/// the authoritative billing record). This emission is for human-visible
/// observability during the demo and is best-effort: errors are swallowed
/// so an unwritable `.ember/runtime/` directory can never wedge the proxy.
///
/// Receipt ID is a demo-grade short hex derived from a sha256 over the
/// call's identifying fields. Beat 8 replaces this with a signed Receipt
/// minted by the receipt subsystem; until then the ID is stable per call
/// but not cryptographically bound. See implementation-note-275
/// (release-checklist) for the follow-up.
#[allow(clippy::too_many_arguments)]
fn emit_proxy_call_event(
    persona_id: &str,
    grant_id: &str,
    method: &str,
    path: &str,
    status: u16,
    tokens_in: u64,
    tokens_out: u64,
) {
    use sha2::{Digest, Sha256};
    // Resolve the primary worktree root via headless-runtime's git helper.
    // Fall back to cwd on failure — the daemon is typically launched from
    // the repo root; this is a best-effort observability path.
    let root =
        core_construct_runtime::layout::primary_worktree_root().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let events_path = root.join(core_construct_runtime::layout::ENGINE_EVENTS_FILE);

    // Receipt ID: short hex from sha256 of (persona, grant, method, path,
    // status, tokens, now_ns). Enough entropy to avoid collisions inside a
    // single agent run; not a substitute for a signed Receipt.
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(persona_id.as_bytes());
    hasher.update(b"|");
    hasher.update(grant_id.as_bytes());
    hasher.update(b"|");
    hasher.update(method.as_bytes());
    hasher.update(b"|");
    hasher.update(path.as_bytes());
    hasher.update(b"|");
    hasher.update(status.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(tokens_in.to_le_bytes());
    hasher.update(tokens_out.to_le_bytes());
    hasher.update(b"|");
    hasher.update(now_ns.to_le_bytes());
    let digest = hasher.finalize();
    let receipt_id = format!("r-{}", hex::encode(&digest[..6]));

    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let line = serde_json::json!({
        "event": "proxy_call",
        "ts": ts,
        "agent_id": persona_id,
        "persona_id": persona_id,
        "grant_id": grant_id,
        "method": method,
        "path": path,
        "status": status,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
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

/// Run the Stream C post-flight meter against the full accumulated upstream
/// response body. Shared between the buffered (`.collect()`) path and the
/// SSE tee path so both produce identical audit + usage state.
///
/// `outcome` tags the audit record `complete` vs `partial` so the Grant
/// Receipt generated downstream can reflect whether the recorded tokens
/// are the full call or a best-effort snapshot after an interruption.
///
/// `upstream_status_is_success` carries the upstream HTTP response's
/// 2xx-ness through to the meter so the `usage.requests` counter only
/// increments on upstream-confirmed responses. See
/// `record_upstream_request` (T-implementation-note-272).
///
/// WIP-FOR: T-implementation-note-272 — caller wiring in the
/// proxy streaming path is in flight; this function is the shared meter
/// the buffered + SSE-tee paths will both invoke once that task lands.
#[allow(clippy::too_many_arguments, dead_code)]
fn run_post_flight_meter(
    state: &ProxyState,
    grant_id: &str,
    statement_sid: &str,
    resolved_stmt: &core_grant_types::Statement,
    persona_id: &str,
    credential_name: &str,
    target_host: &str,
    body: &[u8],
    outcome: StreamOutcome,
    upstream_status_is_success: bool,
) {
    tracing::debug!(
        target: "proxy.meter",
        target_host = %target_host,
        grant_id = %grant_id,
        sid = %statement_sid,
        body_len = body.len(),
        outcome = %outcome.audit_tag(),
        upstream_ok = upstream_status_is_success,
        "run_post_flight_meter: entering buffered meter path"
    );
    let Some(mut delta) = meter_response(target_host, body) else {
        tracing::info!(
            target: "proxy.meter.skip",
            reason = "meter-response-none",
            target_host = %target_host,
            grant_id = %grant_id,
            sid = %statement_sid,
            "run_post_flight_meter: meter_response returned None — see preceding skip-reason for branch"
        );
        return;
    };
    // T-implementation-note-272: fold the upstream-confirmed
    // request count into the delta. `meter_response` no longer hardcodes
    // `requests: 1`; this is the single decision point that mints the
    // billable request against the grant. A successful upstream that
    // returned a parseable usage block counts as one request; a 5xx
    // (or any non-2xx) counts as zero, matching what providers
    // themselves bill.
    delta.requests = record_upstream_request(
        target_host,
        upstream_status_is_success,
        true, // we got a parseable usage block, by virtue of being past meter_response
    );
    // Emit a per-call metering audit event so the receipt + `ember audit`
    // can tell a `complete` stream from a `partial` one. The usage row in
    // `statement_usage` is identical for both cases; the audit record is
    // where the distinction lives.
    //
    // C44-implementation-note-274: the `credential` audit column stores a short
    // hash of the credential alias, not the raw alias. Raw aliases would
    // let anyone with audit-log read access correlate persona ↔ credential
    // across rows, breaking persona isolation. The raw alias still lives
    // in the `statement_usage`/grant rows (single source of truth); a
    // troubleshooter can join `credential_name_hash` against the hash of
    // the raw alias when a specific call needs to be traced.
    //
    // Subprocess-logging discipline (#424 class): never `let _ =
    // log_event(...)` a security event. A silent drop is an invisible
    // audit gap. Surface the error to tracing so the operator at least
    // sees it in the daemon log if the store fails.
    let credential_hash = hash_credential_name_for_audit(credential_name);
    // implementation-note-273: audit-log emission routes through the
    // sink shim. The store write itself is identical; only the
    // ownership of the call boundary moves.
    if let Err(e) = state.sink_log_event(
        Some(persona_id),
        "proxy.meter",
        Some(&credential_hash),
        outcome.audit_tag(),
        Some(&format!(
            "grant_id={grant_id} sid={statement_sid} tokens={} cents={}",
            delta.tokens, delta.cents
        )),
    ) {
        tracing::warn!(
            error = ?e,
            grant_id = %grant_id,
            sid = %statement_sid,
            "proxy.meter audit log_event failed"
        );
    }
    match state
        .store
        .increment_statement_usage(grant_id, statement_sid, delta)
    {
        Ok(delta) => {
            if let Some(budget) = &resolved_stmt.budget {
                emit_threshold_crossings(
                    state,
                    grant_id,
                    statement_sid,
                    persona_id,
                    credential_name,
                    budget,
                    &delta.prior,
                    &delta.current,
                );
            }
            // After the increment, check whether the grant is now
            // budget-terminal across all budget-bearing Statements
            // and flip status to `exhausted_by_budget` if so.
            let _ = state
                .store
                .mark_grant_exhausted_by_budget_if_terminal(grant_id);
        }
        Err(e) => {
            tracing::warn!(
                grant_id = %grant_id,
                sid = %statement_sid,
                error = ?e,
                "failed to increment statement usage (metering skipped)"
            );
        }
    }
}

/// Variant of `run_post_flight_meter` that consumes a structured
/// `UsageSummary` produced by the incremental SSE parser.
///
/// development milestone: with the streaming parser, `TeeBody` no longer
/// holds the raw response bytes. The meter must work from the parsed
/// summary directly. The non-streaming JSON path still uses the
/// byte-slice `run_post_flight_meter` because its body genuinely is
/// available as a single `Bytes`.
///
/// `upstream_status_is_success` mirrors the buffered path: only a 2xx
/// upstream response should count as one billable request via
/// `record_upstream_request`. SSE responses always start with a 2xx
/// status (Anthropic doesn't open an event stream on 5xx), but plumbing
/// the bit explicitly keeps both paths symmetric and audit-ready.
///
/// WIP-FOR: T-implementation-note-272 — pairs with
/// `run_post_flight_meter` above; the SSE-tee path will call this once
/// caller wiring lands.
#[allow(clippy::too_many_arguments, dead_code)]
fn run_post_flight_meter_from_summary(
    state: &ProxyState,
    grant_id: &str,
    statement_sid: &str,
    resolved_stmt: &core_grant_types::Statement,
    persona_id: &str,
    credential_name: &str,
    target_host: &str,
    summary: &pricing::UsageSummary,
    outcome: StreamOutcome,
    upstream_status_is_success: bool,
) {
    tracing::debug!(
        target: "proxy.meter",
        target_host = %target_host,
        grant_id = %grant_id,
        sid = %statement_sid,
        outcome = %outcome.audit_tag(),
        saw_any_usage = summary.saw_any_usage,
        saw_message_stop = summary.saw_message_stop,
        upstream_ok = upstream_status_is_success,
        "run_post_flight_meter_from_summary: entering streaming meter path"
    );
    let Some(mut delta) = usage_from_summary(target_host, summary) else {
        tracing::info!(
            target: "proxy.meter.skip",
            reason = "usage-from-summary-none",
            target_host = %target_host,
            grant_id = %grant_id,
            sid = %statement_sid,
            saw_any_usage = summary.saw_any_usage,
            "run_post_flight_meter_from_summary: usage_from_summary returned None (no provider match or no usage in stream)"
        );
        return;
    };
    // T-implementation-note-272: same fold as the buffered
    // path. `usage_from_summary` no longer hardcodes `requests: 1`; we
    // mint the billable request here once the upstream's confirmation
    // is known. A partial stream that observed any usage at all still
    // counts as one upstream-confirmed request — Anthropic accepted the
    // request and started responding, the cut-off is downstream of the
    // billable boundary.
    delta.requests = record_upstream_request(
        target_host,
        upstream_status_is_success,
        summary.saw_any_usage,
    );
    // The audit + increment paths below mirror `run_post_flight_meter`
    // verbatim — keep in sync if either evolves.
    let credential_hash = hash_credential_name_for_audit(credential_name);
    // implementation-note-273: sink shim — see sibling helper.
    if let Err(e) = state.sink_log_event(
        Some(persona_id),
        "proxy.meter",
        Some(&credential_hash),
        outcome.audit_tag(),
        Some(&format!(
            "grant_id={grant_id} sid={statement_sid} tokens={} cents={}",
            delta.tokens, delta.cents
        )),
    ) {
        tracing::warn!(
            error = ?e,
            grant_id = %grant_id,
            sid = %statement_sid,
            "proxy.meter audit log_event failed"
        );
    }
    match state
        .store
        .increment_statement_usage(grant_id, statement_sid, delta)
    {
        Ok(delta) => {
            if let Some(budget) = &resolved_stmt.budget {
                emit_threshold_crossings(
                    state,
                    grant_id,
                    statement_sid,
                    persona_id,
                    credential_name,
                    budget,
                    &delta.prior,
                    &delta.current,
                );
            }
            let _ = state
                .store
                .mark_grant_exhausted_by_budget_if_terminal(grant_id);
        }
        Err(e) => {
            tracing::warn!(
                grant_id = %grant_id,
                sid = %statement_sid,
                error = ?e,
                "failed to increment statement usage (metering skipped)"
            );
        }
    }
}

/// Returns `None` for non-LLM hosts or when the summary saw no usage at
/// all — matches the byte-slice `meter_response` semantics so the audit
/// trail and budget machinery behave identically across the two paths.
///
/// T-implementation-note-272: `requests` is left at 0 here.
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
    // implementation-note-45: micro-cent precision. See meter_response
    // for the full rationale; the SSE path mirrors the buffered path so
    // both metering routes accumulate budget identically.
    let cents_micro =
        pricing::cents_micro_for(&model, provider, folded.input_tokens, folded.output_tokens);
    Some(core_grant_types::Usage {
        tokens: folded.input_tokens.saturating_add(folded.output_tokens),
        cents: cents_micro / 1_000_000,
        cents_micro,
        // T-implementation-note-272: filled in by the caller
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

type TeeMeterFn = dyn FnOnce(pricing::UsageSummary, StreamOutcome);

/// Callback invoked by `TeeBody` when the upstream stream ends (cleanly or
/// via the size cap).
///
/// development milestone: the callback used to receive the full byte buffer
/// `(&[u8], StreamOutcome)`. That forced `TeeBody` to accumulate every
/// upstream byte up to a 1 MiB cap — N concurrent stalled streams was
/// `N * 1 MiB` of pinned RSS. The signature now takes a structured
/// `UsageSummary` produced by the incremental SSE parser, so per-stream
/// memory is bounded at `SSE_PARTIAL_FRAME_CAP_BYTES` (8 KiB) regardless
/// of stream length.
struct TeeMeterCallback {
    inner: Option<Box<TeeMeterFn>>,
}

impl TeeMeterCallback {
    fn new<F: FnOnce(pricing::UsageSummary, StreamOutcome) + 'static>(f: F) -> Self {
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
/// development milestone: this struct used to hold a `Vec<u8> accumulator`
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
    /// `Ready(None)`.
    cap_exceeded: bool,
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
    /// fires on drop. Guarded by `#[cfg(test)]` so the unit tests can
    /// drive a TeeBody without touching `STREAMING_REQUESTS_INFLIGHT`.
    #[cfg(test)]
    fn new(inner: B, cap_bytes: usize, meter: TeeMeterCallback) -> Self {
        Self::new_with_slot(inner, cap_bytes, meter, None)
    }

    fn new_with_slot(
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
    #[cfg(test)]
    fn buffered_bytes(&self) -> usize {
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

/// Extract the host from a URL string (e.g. `https://api.anthropic.com/v1`).
/// Returns `None` if the URL is malformed.
/// Provider-aware auth injection for the LLM/HTTP proxy.
///
/// Replaces any client-supplied `Authorization` / `x-api-key` header with a
/// vault-resolved credential in the format the upstream provider expects:
///
/// - **Anthropic** (`api.anthropic.com` and any subdomain): `x-api-key`
///   header. Anthropic rejects `Authorization: Bearer ...` with 401.
/// - **Git smart-HTTP**: `Authorization: Basic base64("x-access-token:{token}")`.
/// - **Anything else**: `Authorization: Bearer {token}`.
///
/// Returns `Ok(())` on success and `Err(())` if the credential value cannot
/// be turned into a `HeaderValue` (control chars, newlines, etc.). Callers
/// translate the error into a 500 — a credential the daemon can't even
/// transport upstream is an integrity failure of the vault, not a request
/// problem.
///
/// implementation-note-173 — FINDING B from the brief: prior code
/// unconditionally injected `Authorization: Bearer ...`, which broke every
/// Beat 4 Anthropic SDK call.
pub(crate) fn inject_provider_auth(
    headers: &mut hyper::HeaderMap,
    target_host_lower: &str,
    is_git_transport: bool,
    credential: &str,
) -> Result<AuthScheme, ()> {
    // Defence-in-depth: strip any client-supplied auth headers before
    // injecting our vault-resolved value. The request-header allowlist
    // already drops `authorization` and `x-api-key`, but `remove` is cheap
    // insurance against future allowlist drift.
    headers.remove("authorization");
    headers.remove("x-api-key");

    if host_matches_domain(target_host_lower, "anthropic.com") {
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

/// Auth scheme the proxy injected for an outbound request. Returned by
/// [`inject_provider_auth`] so `handle_request` can log + the test harness
/// can echo it back as a response header for assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthScheme {
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
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AuthScheme::Anthropic => "anthropic",
            AuthScheme::Basic => "basic",
            AuthScheme::Bearer => "bearer",
        }
    }
}

/// Category of scope violation, used to pick an audit outcome string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeViolationKind {
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
#[derive(Debug)]
pub(crate) struct ScopeViolation {
    pub(crate) message: String,
    pub(crate) kind: ScopeViolationKind,
}

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
    pub(crate) fn audit_outcome(&self) -> &'static str {
        match self.kind {
            ScopeViolationKind::General => "denied_scope",
            ScopeViolationKind::Subtarget => "denied_subtarget_scope",
        }
    }
}

/// Resolve the applicable `Statement` for a request (action, resource) pair
/// against a composite grant chain.
///
/// Walks every `(block_index, statement)` pair in chain order and returns
/// the first whose `applicable_to` predicate holds. When the chain has zero
/// applicable statements the caller MUST deny with
/// `no_applicable_statement_response()` — the authorization primitive never
/// falls back to grant-level enforcement. See design § "Allow-only" and
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
pub(crate) enum ResolveOutcome<'a> {
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
pub(crate) fn resolve_statement_for_request_with_uri<'a>(
    grant: &'a core_grant_types::AccessGrant,
    action: &str,
    resource: &str,
    uri: &hyper::Uri,
) -> ResolveOutcome<'a> {
    use core_grant_types::ResourceSelector;

    let mut subtarget_miss: Option<String> = None;

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

    match subtarget_miss {
        Some(sg) => ResolveOutcome::SubtargetMiss { subtarget_glob: sg },
        None => ResolveOutcome::NoApplicable,
    }
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
    // implementation-note-45: compare against the micro-cent
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

/// 429 denial body for a budget-exhausted pre-flight. The body names
/// `axis`, `limit`, and `used` so the agent can back off intelligently
/// without probing. Emitting a structured shape matches the `Error`
/// schema used by Stream D receipts; no secret is leaked because the
/// agent already knows the grant's budget (they've minted/received it).
pub(crate) fn budget_exhausted_response(
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
    // implementation-note-45: compute micro-cents (cents × 10⁶) and
    // derive whole cents from it. Without micro-cent precision, sub-cent
    // calls (~0.1¢ on Haiku-4.5) round to 0 per call and the budget cap
    // can never accumulate enough to trip.
    let cents_micro =
        pricing::cents_micro_for(&model, provider, parsed.input_tokens, parsed.output_tokens);
    Some(core_grant_types::Usage {
        tokens: parsed.input_tokens.saturating_add(parsed.output_tokens),
        cents: cents_micro / 1_000_000,
        cents_micro,
        // T-implementation-note-272: leave `requests` at 0
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
/// T-implementation-note-272: `usage.requests` historically
/// incremented by 1 for every proxy invocation that produced a parseable
/// usage block, regardless of whether the upstream's HTTP response was
/// itself a success. Per implementation-note-276 Decision 2 #2, the
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
pub(crate) fn record_upstream_request(
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

/// Emit threshold-crossing audit events for a metering update.
///
/// Looks at (prior, current, budget) on each axis (tokens, cents) and
/// emits a `budget.warning` at each band (80%, 95%) the update crossed
/// — never twice for the same (grant, sid, axis, band) in the lifetime
/// of the daemon process (debounce set on `ProxyState`). When `current`
/// meets or exceeds `budget`, emits a `budget.exhausted` audit record
/// (debounced the same way, band = `"100"`).
///
/// The caller is responsible for passing the Statement's current
/// resolved `budget` — this function does no read-back.
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_threshold_crossings(
    state: &ProxyState,
    grant_id: &str,
    statement_sid: &str,
    persona_id: &str,
    credential_name: &str,
    budget: &core_grant_types::Budget,
    prior: &core_grant_types::Usage,
    current: &core_grant_types::Usage,
) {
    // implementation-note-45: cents axis runs on micro-cents internally
    // so sub-cent calls accumulate honestly. Both the cap and the
    // before/after counters are scaled to micro-cents; the displayed
    // `used`/`limit` in the emitted audit/push payload are stepped back
    // down to whole cents so receipts and dashboards stay human-readable.
    let cents_cap_micro = budget.cents.map(|c| c.saturating_mul(1_000_000));
    let axes: [(&'static str, Option<u64>, u64, u64); 2] = [
        ("tokens", budget.tokens, prior.tokens, current.tokens),
        (
            "cents",
            cents_cap_micro,
            prior.cents_micro,
            current.cents_micro,
        ),
    ];
    for (axis, cap, before, after) in axes.iter() {
        let Some(cap) = cap else { continue };
        if *cap == 0 {
            continue;
        }
        // Display values: cents axis carries micro-cents internally; step
        // back down for the audit payload so receipts and dashboards show
        // human-readable cent counts instead of raw micro-cent integers.
        let display_divisor: u64 = if *axis == "cents" { 1_000_000 } else { 1 };
        let display_used = *after / display_divisor;
        let display_cap = *cap / display_divisor;
        for &(band_label, band_frac) in &[("80", 0.80f64), ("95", 0.95f64)] {
            let threshold = (*cap as f64 * band_frac) as u64;
            if *before < threshold && *after >= threshold {
                emit_debounced(
                    state,
                    grant_id,
                    statement_sid,
                    axis,
                    band_label,
                    persona_id,
                    credential_name,
                    "budget.warning",
                    &format!(
                        "axis={axis} used={display_used} limit={display_cap} percent={band_label}"
                    ),
                    Some(display_used),
                    Some(display_cap),
                );
            }
        }
        if *before < *cap && *after >= *cap {
            emit_debounced(
                state,
                grant_id,
                statement_sid,
                axis,
                "100",
                persona_id,
                credential_name,
                "budget.exhausted",
                &format!("axis={axis} used={display_used} limit={display_cap}"),
                Some(display_used),
                Some(display_cap),
            );
        }
    }
}

/// Write a single threshold crossing to the audit log AND broadcast a
/// structured push notification when a `broadcast::Sender<GrantEvent>` is
/// attached. The in-memory debounce set ensures both paths emit at most
/// once per `(grant_id, statement_sid, axis, band)` for the lifetime of
/// the daemon process — callers are free to re-run the meter without fear
/// of duplicate pushes.
#[allow(clippy::too_many_arguments)]
fn emit_debounced(
    state: &ProxyState,
    grant_id: &str,
    statement_sid: &str,
    axis: &'static str,
    band_label: &'static str,
    persona_id: &str,
    credential_name: &str,
    action: &str,
    details: &str,
    used: Option<u64>,
    budget: Option<u64>,
) {
    // implementation-note-273: debounce + audit + broadcast now route
    // through the `DaemonEventSink` reachable via `state.sink()`. The
    // sink owns the threshold-debounce set and the broadcast channel; the
    // sync shim methods on `ProxyState` keep this helper's signature
    // unchanged so callers do not have to thread `&dyn EventSink`.
    if !state
        .sink()
        .try_record_threshold_keys(grant_id, statement_sid, axis, band_label)
    {
        return;
    }
    if let Err(e) = state.sink_log_event(
        Some(persona_id),
        action,
        Some(credential_name),
        band_label,
        Some(details),
    ) {
        tracing::warn!(error = ?e, grant_id, statement_sid, axis, action, "log_event failed");
    }

    // Broadcast the structured event to connected socket clients so MCP/SDK
    // consumers receive `budget.warning`/`budget.exhausted` push
    // notifications in real time. The sink's `broadcast_sync` is a no-op
    // when no `events_tx` was installed (git-echo proxy, unit tests).
    if let (Some(used), Some(budget)) = (used, budget) {
        let event = if action == "budget.exhausted" {
            GrantEvent::BudgetExhausted {
                grant_id: grant_id.to_string(),
                statement_sid: statement_sid.to_string(),
                axis,
                used,
                budget,
            }
        } else {
            GrantEvent::BudgetWarning {
                grant_id: grant_id.to_string(),
                statement_sid: statement_sid.to_string(),
                axis,
                used,
                budget,
                percent: band_label,
            }
        };
        state.sink_broadcast(event);
    }
}

/// 403 denial when zero statements match a request. Never names the
/// statement set — same rationale as `scope_violation_response` (leaking
/// the selector shape is a probe vector). The cause is logged + audited.
pub(crate) fn no_applicable_statement_response() -> Response<ProxyBody> {
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
pub(crate) fn check_scope(
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
fn subtarget_matches(
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

/// Return a structured 403 when the matched statement has been revoked.
///
/// Beat 7 (SCION 2026-05-15 demo) — clients programmatically distinguish
/// "statement_revoked" from generic 403s so they can surface "your statement
/// was revoked by the operator" rather than a flat denial. Unlike
/// `scope_violation_response`, the persona_id and statement_id are NOT
/// information leaks here: the caller supplied the persona_id in the request
/// header (`X-Ember-Persona`) and already has access to the sid via the
/// grant detail page. Naming what was killed accelerates agent self-recovery.
fn statement_revoked_response(persona_id: &str, statement_id: &str) -> Response<ProxyBody> {
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

/// Return a generic 403 for scope violations. The body deliberately does
/// NOT include the grant's scope string — leaking it would let an attacker
/// probe for narrower scopes. The detail is in the daemon log and audit.
fn scope_violation_response() -> Response<ProxyBody> {
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

fn bad_request(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

fn forbidden(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

fn unauthorized(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

fn internal_error(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

/// HTTP 413 response used when a request or response body exceeds
/// `MAX_BODY_BYTES`. Signals to well-behaved clients that the
/// payload is too large to pass through the credential-injection layer.
fn payload_too_large(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

/// HTTP 503 response used when the per-process streaming-concurrency
/// cap is saturated (development milestone). A `Retry-After` header signals to
/// well-behaved clients that the condition is transient. Keep the body
/// short — it travels through hyper's small-buffer path and avoids
/// tickling the very accumulator we're protecting.
fn service_unavailable(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Retry-After", "1")
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

// ---------------------------------------------------------------------------
// P69L — git smart-HTTP echo proxy
//
// Mechanical forwarding path for `git push` / `git clone` before the
// grant-aware `handle_git_receive_pack` path lands. Isolated from
// `handle_request` — no grant lookup, no vault touch.
//
// Audit trail (-AUDIT):
//   `handle_git_echo` emits `credential.access` (tracing::info!) at entry
//   with `action="github.push.<owner/repo>"` and a `request_id`. The
//   `PassthroughBody::Drop` emits `proxy.stream` with the same `request_id`
//   so operators can correlate entry and exit for each streaming push.
//
// Streaming model (P69L.0b):
//   Request body streams as `Incoming` directly to the upstream client —
//   no intermediate buffer. Response body streams back via
//   `ProxyBody::Passthrough(PassthroughBody<Incoming>)`. Pack-objects from
//   large pushes never reside fully in daemon memory.
//
// Concurrency cap (-GATE, see `STREAMING_REQUESTS_INFLIGHT`):
//   `handle_git_echo` acquires a `StreamingSlot` before touching upstream.
//   When all `MAX_CONCURRENT_STREAMING` slots are held, the function
//   returns 503 + `Retry-After: 1` immediately without opening an upstream
//   connection. The slot is released on clean EOF, upstream error, or
//   client disconnect via `PassthroughBody`'s RAII field-drop order.
//
// Hop-by-hop header filtering (-HOPBYHOP, see `strip_hop_by_hop_headers`):
//   `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`,
//   `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, and any token listed in
//   the upstream `Connection:` header are stripped from the response before
//   forwarding (RFC 7230 §6.1).
//
// RAII drop guard (-DROP-GUARD, see `PassthroughBody`):
//   Byte counter increments per data frame. On drop: `outcome=complete` if
//   EOF was observed, `outcome=partial` + `bytes_forwarded` otherwise.
//
// Timeouts (post-#662, see `HEADERS_DEADLINE` + `FRAME_IDLE_DEADLINE`):
//   Lazy-static `Client` with bounded idle pool; `HEADERS_DEADLINE` aborts
//   before upstream headers arrive (returns 504); `FRAME_IDLE_DEADLINE`
//   watchdog fires mid-body and marks the drop guard `outcome=partial`.
//
// Usage (manual):
//   - Caller spawns `run_git_echo_proxy` with a bind addr + ProxyState.
//   - Client git is configured with
//     `url."http://127.0.0.1:PORT/github.com/".insteadOf "https://github.com/"`
//     so push requests arrive as plain HTTP with paths shaped
//     `/github.com/{owner}/{repo}.git/...`.
//   - The proxy reads `x-ember-persona` + `x-ember-credential` headers,
//     resolves an active grant for that persona/credential pair, checks the
//     composite-grant chain permits `github:push` on the target repo, fetches
//     the raw token from the vault, substitutes
//     `Basic base64("x-access-token:{token}")` for recognised git-transport
//     paths, rewrites `Host` to `github.com`, and forwards over HTTPS. The
//     upstream response streams back to the client.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// P69L.0b--TIMEOUTS — tunables for the git-echo upstream client.
// ---------------------------------------------------------------------------
//
// The git-echo path previously built a fresh `hyper_util` legacy Client (+
// HttpsConnector + rustls CryptoProvider wiring) on every request. That meant
// a TLS handshake per push, zero connection reuse, and no bound on the
// per-host idle pool. The constants below govern a single process-wide Client
// lazily initialised on first use.

/// Upper bound on how long an idle upstream TCP connection lingers in the
/// keep-alive pool before being closed. 90s matches a typical HTTPS
/// load-balancer idle timeout; longer and we'd pay reconnect cost on
/// half-closed sockets, shorter and we'd lose reuse during bursty pushes.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Maximum idle upstream sockets kept per `(scheme, host, port)` triple.
/// Bounds the FD footprint of the lazily-cached Client when many hosts are
/// touched (pathological case: a swarm of git origins); 8 is enough to
/// amortise handshakes across concurrent push fan-out without pinning file
/// descriptors indefinitely.
const POOL_MAX_IDLE_PER_HOST: usize = 8;

/// Maximum time we wait to receive response headers from the upstream after
/// dispatching a request. Covers TCP-connect + TLS handshake + request-line
/// transmission + upstream first-byte latency. 30s is aggressive enough to
/// surface dead/slow-loris upstreams long before a client-side git timeout
/// fires, and loose enough that a normal GitHub `git-receive-pack` handshake
/// (~100ms) is nowhere near the ceiling.
const HEADERS_DEADLINE: Duration = Duration::from_secs(30);

/// Maximum time we wait between body data frames once headers have flushed.
/// A well-behaved git/GitHub stream pushes frames continuously; going silent
/// for 30s is indistinguishable from a stalled upstream and abandoning the
/// stream is the correct behaviour. On elapse, `PassthroughBody` aborts with
/// `outcome=partial reason=frame-idle-timeout` so the partial drop-guard log
/// from P69L.0b--DROP-GUARD surfaces the root cause.
const FRAME_IDLE_DEADLINE: Duration = Duration::from_secs(30);

/// Process-wide lazily-initialised upstream client used by the git-echo path.
///
/// Initialised on first `git_echo_client()` call. Uses hyper-rustls with
/// system webpki roots so production pushes to github.com work, but accepts
/// plain HTTP upstreams too (`https_or_http`) so tests can mock without
/// spinning up a TLS certificate. Connection pooling + keep-alive are
/// governed by `POOL_IDLE_TIMEOUT` / `POOL_MAX_IDLE_PER_HOST`.
static GIT_ECHO_CLIENT: OnceLock<
    Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Incoming,
    >,
> = OnceLock::new();

/// Return the process-wide git-echo Client, initialising it on first call.
///
/// Safe to call from any async context; the underlying `OnceLock` handles
/// concurrent racers. The returned reference has `'static` lifetime, so it
/// can be borrowed freely across `.await` points without ownership ceremony.
fn git_echo_client() -> &'static Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Incoming,
> {
    GIT_ECHO_CLIENT.get_or_init(|| {
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        Client::builder(TokioExecutor::new())
            .pool_idle_timeout(POOL_IDLE_TIMEOUT)
            .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
            .build(https)
    })
}

/// URL scheme for the upstream connection used by [`GitEchoConfig`].
///
/// A typed alternative to the stringly-typed `"http"` / `"https"` that
/// previously lived in the config struct. Using the enum prevents typos such
/// as `"htps"` from silently producing a broken target URL at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scheme::Http => f.write_str("http"),
            Scheme::Https => f.write_str("https"),
        }
    }
}

impl std::str::FromStr for Scheme {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "http" => Ok(Scheme::Http),
            "https" => Ok(Scheme::Https),
            other => Err(format!(
                "unknown scheme {:?}; expected \"http\" or \"https\"",
                other
            )),
        }
    }
}

/// Runtime configuration for the grant-aware git smart-HTTP echo proxy.
///
/// `state` carries the vault + grant store used for per-request credential
/// resolution: the proxy reads `x-ember-persona` + `x-ember-credential`
/// headers, resolves an active grant, verifies the composite-grant chain
/// permits `github:push` on the target repo, then fetches the raw token
/// from the vault. The caller never sees the token — Emberlink mediates.
#[derive(Clone)]
pub struct GitEchoConfig {
    pub bind_addr: std::net::SocketAddr,
    /// Upstream host we forward to (always `github.com` in production).
    pub upstream_host: String,
    /// Vault + grant store used for per-request credential resolution.
    /// Carries persona grants and the encrypted credential bytes.
    pub state: Arc<ProxyState>,
    /// URL scheme for the upstream connection. Production callers use
    /// [`Scheme::Https`]; tests can set [`Scheme::Http`] to forward to a
    /// plain-HTTP mock upstream without needing a TLS certificate.
    pub upstream_scheme: Scheme,
}

/// Run the Day-1 echo proxy until `shutdown` flips to `true`.
///
/// This is the mechanical sibling of `run_proxy` — same listener + LocalSet
/// pattern, but dispatches to `handle_git_echo` instead of `handle_request`.
/// Exposed `pub` so a separate test binary or an `#[ignore]`-d integration
/// test can spawn it without reaching into daemon state.
///
/// `bind_tx` (implementation-note-172): when `Some`, the bound `SocketAddr` is sent
/// exactly once immediately after `TcpListener::bind` succeeds. Bind errors
/// are sent as `Err` and the function returns. The receiver gets the actual
/// local addr (so `127.0.0.1:0` callers can read the assigned port). If the
/// caller has dropped the receiver the send is silently ignored — bind
/// success/failure must not depend on whether anyone is listening for it.
pub async fn run_git_echo_proxy(
    config: GitEchoConfig,
    mut shutdown: watch::Receiver<bool>,
    bind_tx: Option<oneshot::Sender<Result<std::net::SocketAddr, std::io::Error>>>,
) -> Result<(), ProxyError> {
    let listener = match TcpListener::bind(config.bind_addr).await {
        Ok(l) => {
            let local_addr = l.local_addr().unwrap_or(config.bind_addr);
            if let Some(tx) = bind_tx {
                let _ = tx.send(Ok(local_addr));
            }
            l
        }
        Err(e) => {
            // Mirror dashboard's "best effort to surface, then propagate"
            // pattern. We deliver the error to `bind_tx` if present, then
            // return ProxyError so the spawning task records a non-zero exit.
            //
            // P69E.8b: annotate `AddrInUse` failures with `lsof -i :<port>` +
            // daemon-stop hints so operators have an actionable path forward
            // instead of an opaque "Address already in use" log line.
            let annotated =
                crate::infra::socket::annotate_bind_error(e, &config.bind_addr.to_string());
            tracing::warn!(addr = %config.bind_addr, error = %annotated, "git echo proxy failed to bind");
            if let Some(tx) = bind_tx {
                let kind = annotated.kind();
                let _ = tx.send(Err(std::io::Error::new(kind, annotated.to_string())));
            }
            return Err(ProxyError::from(annotated));
        }
    };
    // `GitEchoConfig` embeds `Arc<ProxyState>` which is `!Sync` (RefCell inside).
    // This is intentional: the proxy runs on a `LocalSet` (single-threaded) so
    // `Send + Sync` are not required. The same pattern is used by `run_proxy`.
    #[allow(clippy::arc_with_non_send_sync)]
    let config = Arc::new(config);
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, _addr)) => {
                                let config = Arc::clone(&config);
                                let io = TokioIo::new(stream);
                                tokio::task::spawn_local(async move {
                                    let svc = hyper::service::service_fn(move |req| {
                                        let config = Arc::clone(&config);
                                        async move { handle_git_echo(config, req).await }
                                    });
                                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                                        .serve_connection(io, svc)
                                        .await
                                    {
                                        tracing::warn!(error = %e, "git echo connection error");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "git echo accept error");
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
    Ok(())
}

/// Per-request handler for the Day-1 echo proxy.
///
/// Accepts the `insteadOf`-rewritten shape `/{upstream_host}/{rest...}` and
/// forwards `/{rest...}` to `https://{upstream_host}/{rest...}` with the
/// client's `Authorization` replaced by a grant-backed Basic-auth header. The
/// caller must supply `x-ember-persona` and `x-ember-credential` headers; the
/// proxy resolves the active grant, verifies the composite-grant chain permits
/// `github:push` on the target repo, fetches the raw token from the vault, and
/// synthesises `Basic base64("x-access-token:{token}")`. If the path does NOT
/// look like a git smart-HTTP request we fail closed with a 400 — the echo is
/// intentionally narrow.
pub async fn handle_git_echo(
    config: Arc<GitEchoConfig>,
    req: Request<Incoming>,
) -> Result<Response<ProxyBody>, ProxyError> {
    // development milestone (P69L.0b--GATE): acquire a streaming slot BEFORE we
    // commit to building the upstream request. The passthrough body
    // holds this slot for the lifetime of the response; once we hit the
    // per-process `MAX_CONCURRENT_STREAMING` cap, fail-closed with 503 +
    // Retry-After so well-behaved clients back off rather than piling
    // up stalled streams that pin unbounded upstream sockets on the
    // daemon. We do this at function entry (not inside `stream_response`)
    // so we spend zero upstream bandwidth when the gate is saturated.
    let Some(streaming_slot) = StreamingSlot::try_acquire() else {
        tracing::warn!(
            inflight = STREAMING_REQUESTS_INFLIGHT.load(Ordering::Acquire),
            cap = MAX_CONCURRENT_STREAMING,
            "git echo: streaming concurrency cap reached — rejecting"
        );
        return Ok(service_unavailable("streaming-saturated"));
    };

    // P69L.0b--AUDIT: mint a per-request correlating id so the
    // `credential.access` entry (below) and the `proxy.stream` entry
    // (from PassthroughBody::Drop) can be joined in the audit log.
    let request_id: Arc<str> = Arc::from(format!("req-{}", uuid::Uuid::new_v4()).as_str());

    // P69L.0c: resolve persona + credential from request headers.
    // Missing either header → 401 (the git client must be configured to
    // forward them; without both we cannot look up the grant).
    let headers = req.headers();
    let persona_id = match headers.get("x-ember-persona").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Ok(unauthorized("missing X-Ember-Persona header")),
    };
    let credential_name = match headers
        .get("x-ember-credential")
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.to_string(),
        None => return Ok(unauthorized("missing X-Ember-Credential header")),
    };

    let method = req.method().clone();
    let uri = req.uri().clone();

    // Parse the `insteadOf`-rewritten path: `/github.com/owner/repo.git/...`.
    // The leading segment MUST match `config.upstream_host` — anything else
    // is a routing mistake on the client and we refuse rather than silently
    // forwarding to an unexpected host.
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let expected_prefix = format!("/{}/", config.upstream_host);
    let upstream_path_and_query = match path_and_query.strip_prefix(&expected_prefix) {
        Some(rest) => format!("/{rest}"),
        None => {
            tracing::warn!(
                path = %path_and_query,
                expected_prefix = %expected_prefix,
                "git echo: path does not start with expected upstream prefix"
            );
            return Ok(bad_request(
                "git echo: path must start with /<upstream_host>/",
            ));
        }
    };

    // Detect git-transport shape so we only Basic-inject on the right paths.
    // Both phases of a push are recognised:
    //   - GET  /{owner}/{repo}.git/info/refs?service=git-receive-pack
    //   - POST /{owner}/{repo}.git/git-receive-pack
    // The read-side (git-upload-pack) is also tagged as git-transport because
    // `insteadOf` rewrites affect clone/fetch too and we want a consistent
    // credential substitution across every phase.
    let is_git_transport = is_git_smart_http_path(&upstream_path_and_query);

    // P69L.0c: grant-backed credential resolution.
    //
    // 1. Look up the active grant for (persona, credential). No active grant →
    //    403 (policy denies).
    // 2. Load and verify the composite AccessGrant chain from the store.
    // 3. Derive (action, resource) from the upstream path:
    //    action   = "github:push"  (receive-pack) or "github:read" (upload-pack)
    //    resource = "owner/repo"   extracted by git_echo_owner_repo
    // 4. Resolve the matching Statement. No match → 403.
    // 5. Fetch the raw credential bytes from the vault. Not found → 500.
    let push_target = git_echo_owner_repo(&upstream_path_and_query)
        .unwrap_or_else(|| upstream_path_and_query.trim_start_matches('/').to_string());

    let grant = match config
        .state
        .store
        .evaluate_grant(&persona_id, &credential_name)
    {
        Ok(g) => g,
        Err(StoreError::NotFound) => {
            tracing::warn!(
                persona_id = %persona_id,
                credential = %credential_name,
                "git echo: no active grant for persona/credential"
            );
            // implementation-note-273: route through sink shim.
            if let Err(e) = config.state.sink_log_event(
                Some(&persona_id),
                "credential.access",
                Some(&credential_name),
                "denied_no_grant",
                Some(&format!("push_target={push_target}")),
            ) {
                tracing::warn!(error = ?e, "git echo: log_event(denied_no_grant) failed");
            }
            return Ok(forbidden("no active grant for persona/credential"));
        }
        Err(e) => return Err(ProxyError::Store(e)),
    };

    let access_grant = match config.state.store.get_access_grant(&grant.id) {
        Ok(ag) => ag,
        Err(e) => return Err(ProxyError::Store(e)),
    };

    // Classify the request: receive-pack = push, upload-pack = read.
    let git_action = if upstream_path_and_query.contains("git-receive-pack") {
        "github:push"
    } else {
        "github:read"
    };
    let resource = push_target.clone();

    if resolve_statement_for_request(&access_grant, git_action, &resource).is_none() {
        tracing::warn!(
            grant_id = %grant.id,
            persona_id = %persona_id,
            credential = %credential_name,
            action = %git_action,
            resource = %resource,
            "git echo: no applicable statement for request — denying"
        );
        // implementation-note-273: route through sink shim.
        if let Err(e) = config.state.sink_log_event(
            Some(&persona_id),
            "credential.access",
            Some(&credential_name),
            "denied_no_applicable_statement",
            Some(&format!("action={git_action} resource={resource}")),
        ) {
            tracing::warn!(error = ?e, "git echo: log_event(denied_no_applicable_statement) failed");
        }
        return Ok(forbidden("no applicable statement for git push"));
    }

    // Fetch the raw credential from the vault. Not in vault → 500 + audit.
    // Wrap in Zeroizing so the raw key bytes are wiped on drop.
    let vault = config.state.current_vault()?;
    let credential_bytes: Zeroizing<Vec<u8>> = match vault.get(
        VaultScope::Interactive,
        &config.state.store,
        &credential_name,
    ) {
        Ok(b) => Zeroizing::new(b),
        Err(VaultError::NotFound) => {
            tracing::warn!(
                credential = %credential_name,
                "git echo: credential not found in vault"
            );
            // implementation-note-273: route through sink shim.
            if let Err(e) = config.state.sink_log_event(
                Some(&persona_id),
                "credential.access",
                Some(&credential_name),
                "error_vault_not_found",
                Some(&format!("push_target={push_target}")),
            ) {
                tracing::warn!(error = ?e, "git echo: log_event(error_vault_not_found) failed");
            }
            return Ok(internal_error("credential not found in vault"));
        }
        Err(e) => return Err(ProxyError::Vault(e)),
    };
    let credential_value: Zeroizing<String> =
        Zeroizing::new(String::from_utf8_lossy(&credential_bytes).into_owned());

    // P69L.0b--AUDIT: emit `credential.access` so operators can see
    // that a credential substitution occurred and which repo was targeted.
    // `action` mirrors the shape from C44-implementation-note-274: "github.push.<owner/repo>".
    tracing::info!(
        event = "credential.access",
        allowed = true,
        action = %format!("github.push.{push_target}"),
        credential_name = %credential_name,
        persona_id = %persona_id,
        request_id = %request_id,
        "git echo: credential access"
    );
    // implementation-note-273: route through sink shim.
    if let Err(e) = config.state.sink_log_event(
        Some(&persona_id),
        "credential.access",
        Some(&credential_name),
        "allowed",
        Some(&format!(
            "push_target={push_target} request_id={request_id}"
        )),
    ) {
        tracing::warn!(error = ?e, "git echo: log_event(allowed) failed");
    }

    // Split the request into parts + streaming body. The body is forwarded
    // as a stream — no collection into memory — so pack-objects flows on
    // git push without ever fully residing in the daemon process.
    let (parts, incoming_body) = req.into_parts();

    // P69L.0b--TIMEOUTS: reuse the process-wide client so we don't pay a
    // TLS handshake per request. The pool bounds live on the Client itself
    // (see `git_echo_client()` / POOL_* constants).
    let client = git_echo_client();

    let target_url = format!(
        "{scheme}://{host}{path}",
        scheme = config.upstream_scheme,
        host = config.upstream_host,
        path = upstream_path_and_query,
    );
    let mut outgoing = Request::builder().method(method.clone()).uri(&target_url);

    // Forward every header except the ones we MUST control.
    //
    // - `authorization`: stripped unconditionally. Upstream must see only the
    //   header WE inject, never a header the client happened to send. This
    //   is the core product guarantee of the whole spike.
    // - `host`: rewritten to `upstream_host` so github.com's vhost routing
    //   matches. Hyper will also regenerate this from the URI, but being
    //   explicit prevents surprises if a client sends a bogus Host.
    // - `x-ember-*`: never appeared on the way in from git, but strip
    //   defensively in case a non-git client ever hits this endpoint.
    for (name, value) in &parts.headers {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "authorization" || lower == "host" || lower.starts_with("x-ember-") {
            continue;
        }
        outgoing = outgoing.header(name, value);
    }
    outgoing = outgoing.header("host", &config.upstream_host);

    // Inject Basic auth only for git-transport paths. Non-git paths get no
    // credential injected — they shouldn't be hitting this echo at all, and
    // we'd rather upstream reject with 401 than accidentally gate REST calls.
    if is_git_transport {
        let basic = build_github_basic_auth(&credential_value);
        outgoing = outgoing.header("authorization", basic);
    }

    // Pass the request body as a stream — `incoming_body` is `Incoming` and
    // implements `Body` directly. No intermediate buffer allocation.
    let outgoing_req = outgoing.body(incoming_body).map_err(|e| {
        tracing::warn!(error = %e, "git echo: failed to build outgoing request");
        ProxyError::Http(e)
    })?;

    tracing::info!(
        method = %method,
        upstream = %target_url,
        is_git_transport,
        "git echo forwarding"
    );

    // P69L.0b--TIMEOUTS: cap the headers-received phase with
    // `HEADERS_DEADLINE`. `tokio::time::timeout` drops the inner future on
    // elapse, which cancels any in-flight TCP/TLS/request work and closes
    // the upstream socket — no leaked futures, no pinned sockets. On
    // timeout we return 504 to the client; `streaming_slot` is dropped at
    // function return so the concurrency counter is released.
    let upstream_resp =
        match tokio::time::timeout(HEADERS_DEADLINE, client.request(outgoing_req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "git echo: upstream request failed");
                return Err(ProxyError::Client(e));
            }
            Err(_elapsed) => {
                tracing::warn!(
                    upstream = %target_url,
                    deadline_secs = HEADERS_DEADLINE.as_secs(),
                    "git echo: upstream headers deadline exceeded — returning 504"
                );
                return Ok(gateway_timeout("upstream-headers-timeout"));
            }
        };

    // Stream the upstream response back to the client via `stream_response`.
    // Status, headers, and body frames flow through without accumulation —
    // P69L.0b streaming fix. (Anthropic) can reuse `stream_response`
    // for the same pattern.
    //
    // The `streaming_slot` acquired at function entry rides inside the
    // returned `PassthroughBody`; hyper will drop the body once the
    // response is fully written (clean EOF) or the client disconnects
    // mid-stream, releasing the slot in both cases.
    //
    // P69L.0b--TIMEOUTS: wire a per-frame idle watchdog into the
    // passthrough body. If no data frame arrives within
    // `FRAME_IDLE_DEADLINE`, the stream aborts and drop emits
    // `outcome=partial reason=frame-idle-timeout`.
    //
    // P69L.0b--AUDIT: thread the correlating `request_id` into the
    // passthrough body so Drop can emit `proxy.stream { request_id, ... }`
    // joinable with the `credential.access` entry above.
    let (resp_parts, resp_body) = stream_response_with_frame_idle(
        upstream_resp,
        Some(streaming_slot),
        Some(FRAME_IDLE_DEADLINE),
    )
    .into_parts();
    let resp_body = match resp_body {
        ProxyBody::Passthrough(pb) => ProxyBody::Passthrough(pb.with_request_id(request_id)),
        other => other,
    };
    Ok(Response::from_parts(resp_parts, resp_body))
}

/// HTTP 504 response used when the upstream fails to send response headers
/// within `HEADERS_DEADLINE`, or when a mid-stream frame-idle watchdog
/// fires before any body bytes have flushed downstream. Short body keeps
/// the response cheap to emit; diagnostic detail lives in the daemon log.
fn gateway_timeout(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::GATEWAY_TIMEOUT)
        .header("content-type", "text/plain; charset=utf-8")
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

/// Build the `Authorization: Basic ...` value GitHub expects for smart-HTTP
/// over HTTPS with a PAT.
///
/// GitHub's convention for token-based Basic auth is
/// `x-access-token:{pat}` as the `user:password` pair. Any non-empty
/// username works, but `x-access-token` is the documented form for PATs and
/// installation tokens, and keeps audit logs legible.
fn build_github_basic_auth(token: &str) -> String {
    let raw = format!("x-access-token:{token}");
    format!("Basic {}", base64_std_encode(raw.as_bytes()))
}

/// Minimal RFC 4648 §4 standard-base64 encoder (padded, no URL-safe
/// substitutions). Kept local to avoid pulling in the `base64` crate for a
/// one-off echo prototype; Day 2's production path will either reuse an
/// existing dep or we'll add one in a scoped PR.
fn base64_std_encode(input: &[u8]) -> String {
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
mod tests;
