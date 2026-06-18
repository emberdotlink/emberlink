//! CLASSIFICATION: PUBLIC
//!
//! Token + cost metering for the credential proxy (69K.2, ADR 072).
//!
//! The proxy parses LLM response bodies for a `usage` field, maps the
//! `(provider, model)` pair to `TokenPricing`, and converts input + output
//! tokens into integer cents. Those cents feed the post-flight budget check
//! and audit-event emission in `proxy.rs`.
//!
//! Prices are as of Q1 2026 (see references below). An unknown model maps to
//! `TokenPricing::UNKNOWN`, which returns zero cents and emits a debug log —
//! we do not block unknown-model traffic.
//!
//! References (current as of 2026-04-22):
//!   * Anthropic: <https://www.anthropic.com/pricing>
//!   * OpenAI: <https://openai.com/api/pricing/>

/// Integer cents-per-million-tokens pricing for an LLM input/output token pair.
/// Kept as integer cents per million so downstream integer math stays exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenPricing {
    /// Input cost in cents per million input tokens.
    pub input_cents_per_million: u64,
    /// Output cost in cents per million output tokens.
    pub output_cents_per_million: u64,
}

impl TokenPricing {
    /// Fallback pricing — zero cost. Emitted for unknown models so metering
    /// never blocks traffic we don't have a price table for.
    pub const UNKNOWN: Self = Self {
        input_cents_per_million: 0,
        output_cents_per_million: 0,
    };

    /// Cost in integer cents for this call. Derived from `cents_micro_for`
    /// by floor-dividing micro-cents to whole cents — kept for callers and
    /// tests that only need the human-readable cent value. Use
    /// `cents_micro_for` when the value will be summed across calls or
    /// compared to a budget cap (DEMO-MAY3-WEDGE-METER-WIRE: per-side
    /// truncation zeroed every sub-cent call, making the cap unreachable).
    pub fn cents_for(&self, input_tokens: u64, output_tokens: u64) -> u64 {
        self.cents_micro_for(input_tokens, output_tokens) / 1_000_000
    }

    /// Cost in micro-cents (cents × 10⁶) for this call. Computed without
    /// per-side rounding so sub-cent calls accumulate honestly.
    /// `input_cents_per_million` × tokens already lives in cents-per-million
    /// units, which is the same as micro-cents-per-token, so no extra scale
    /// is needed.
    pub fn cents_micro_for(&self, input_tokens: u64, output_tokens: u64) -> u64 {
        let in_micros = input_tokens.saturating_mul(self.input_cents_per_million);
        let out_micros = output_tokens.saturating_mul(self.output_cents_per_million);
        in_micros.saturating_add(out_micros)
    }
}

/// Strip a trailing `-YYYYMMDD` (8 contiguous digits) date suffix from a
/// model name. Anthropic publishes date-pinned aliases that bill at the
/// family/version rate — e.g. `claude-haiku-4-5-20251001` is the same
/// price as `claude-haiku-4-5`. Without this, the pricing match falls
/// through to `UNKNOWN { 0, 0 }` every time Anthropic rolls a new
/// date-pinned alias and budget enforcement silently breaks at the wire
/// (DEMO-MAY3-WEDGE-METER-WIRE: shipped on `claude-haiku-4-5-20251001`).
///
/// Only matches Anthropic's `-YYYYMMDD` shape (8 digits, no separators).
/// OpenAI's `-YYYY-MM-DD` form has internal hyphens and falls through
/// untouched, so the explicit OpenAI date-aliases below still apply.
fn strip_anthropic_date_suffix(model: &str) -> Option<&str> {
    if model.len() < 9 {
        return None;
    }
    let (head, tail) = model.split_at(model.len() - 9);
    let bytes = tail.as_bytes();
    if bytes[0] == b'-' && bytes[1..].iter().all(|b| b.is_ascii_digit()) {
        Some(head)
    } else {
        None
    }
}

/// Look up pricing for a `(provider, model)` pair. Provider is derived from the
/// target host in `proxy.rs` (`api.anthropic.com` → `"anthropic"`, etc.).
///
/// The table is small and literal on purpose: agents run against a tightly
/// bounded set of model names, and keeping this static avoids a config
/// dependency for the metering hot path.
pub fn pricing_for(provider: &str, model: &str) -> TokenPricing {
    let exact = pricing_for_exact(provider, model);
    if !matches!(
        exact,
        TokenPricing {
            input_cents_per_million: 0,
            output_cents_per_million: 0
        }
    ) {
        return exact;
    }
    // Fallback: strip a `-YYYYMMDD` Anthropic date suffix and retry once
    // against the family/version rate. Order matters — exact match wins,
    // so legacy date-only-named models like `claude-3-haiku-20240307`
    // (no bare-name parent) still resolve correctly.
    if let Some(stripped) = strip_anthropic_date_suffix(model) {
        let retry = pricing_for_exact(provider, stripped);
        if !matches!(
            retry,
            TokenPricing {
                input_cents_per_million: 0,
                output_cents_per_million: 0
            }
        ) {
            return retry;
        }
    }
    tracing::info!(
        target: "proxy.meter.skip",
        reason = "unknown-model",
        provider = %provider,
        model = %model,
        "pricing_for: model not in pricing table (exact or date-suffix-stripped), using TokenPricing::UNKNOWN (0 cents)"
    );
    TokenPricing::UNKNOWN
}

fn pricing_for_exact(provider: &str, model: &str) -> TokenPricing {
    match (provider, model) {
        // --- Anthropic ---
        // Opus (4.5): $15/MTok input, $75/MTok output = 1500 / 7500 cents.
        ("anthropic", "claude-opus-4-5") | ("anthropic", "claude-opus-4-5-20250514") => {
            TokenPricing {
                input_cents_per_million: 1_500,
                output_cents_per_million: 7_500,
            }
        }
        // Opus 4.6 / 4.7 — successive generations retain the 4.5 price point
        // until Anthropic publishes revised rates. When they do, swap the
        // constants here; callers don't need to change.
        ("anthropic", "claude-opus-4-6")
        | ("anthropic", "claude-opus-4-6-20260101")
        | ("anthropic", "claude-opus-4-7")
        | ("anthropic", "claude-opus-4-7-20260401")
        | ("anthropic", "claude-opus-4-7[1m]") => TokenPricing {
            input_cents_per_million: 1_500,
            output_cents_per_million: 7_500,
        },
        // Sonnet 4.5 / 4.6: $3/MTok input, $15/MTok output = 300 / 1500 cents.
        ("anthropic", "claude-sonnet-4-5")
        | ("anthropic", "claude-sonnet-4-5-20250514")
        | ("anthropic", "claude-sonnet-4-6")
        | ("anthropic", "claude-sonnet-4-6-20260101") => TokenPricing {
            input_cents_per_million: 300,
            output_cents_per_million: 1_500,
        },
        // Haiku 4.5: $1/MTok input, $5/MTok output = 100 / 500 cents.
        ("anthropic", "claude-haiku-4-5") | ("anthropic", "claude-haiku-4-5-20250514") => {
            TokenPricing {
                input_cents_per_million: 100,
                output_cents_per_million: 500,
            }
        }
        // Haiku 3 (legacy): $0.25/MTok input, $1.25/MTok output = 25 / 125 cents.
        // Used by the May 3 YC composite-grant demo runner — without an entry
        // here the pricing lookup falls through to UNKNOWN { 0, 0 } and the
        // cents budget never increments, silently breaking Beat 4.
        ("anthropic", "claude-3-haiku-20240307") => TokenPricing {
            input_cents_per_million: 25,
            output_cents_per_million: 125,
        },

        // --- OpenAI ---
        // gpt-4 classic: $30/MTok in, $60/MTok out.
        ("openai", "gpt-4") | ("openai", "gpt-4-0613") => TokenPricing {
            input_cents_per_million: 3_000,
            output_cents_per_million: 6_000,
        },
        // gpt-4o: $2.50/MTok in, $10/MTok out.
        ("openai", "gpt-4o") | ("openai", "gpt-4o-2024-08-06") => TokenPricing {
            input_cents_per_million: 250,
            output_cents_per_million: 1_000,
        },
        // gpt-4o-mini: $0.15/MTok in, $0.60/MTok out → 15 / 60 cents.
        ("openai", "gpt-4o-mini") | ("openai", "gpt-4o-mini-2024-07-18") => TokenPricing {
            input_cents_per_million: 15,
            output_cents_per_million: 60,
        },
        // gpt-4.1: $3/MTok in, $12/MTok out (Q1 2026 published rates).
        ("openai", "gpt-4.1") | ("openai", "gpt-4.1-2025-04-14") => TokenPricing {
            input_cents_per_million: 300,
            output_cents_per_million: 1_200,
        },

        // --- Unknown ---
        // No log here — pricing_for() handles the fallback retry then logs
        // the final unknown verdict so we don't double-log when the exact
        // pass is just the first half of a two-pass lookup.
        _ => TokenPricing::UNKNOWN,
    }
}

/// Compute the cost in cents for a metered LLM call.
///
/// Convenience wrapper around `pricing_for` + `TokenPricing::cents_for` so
/// callers don't have to thread the intermediate `TokenPricing` value.
pub fn cents_for(model: &str, provider: &str, input_tokens: u64, output_tokens: u64) -> u64 {
    pricing_for(provider, model).cents_for(input_tokens, output_tokens)
}

/// Compute the cost in micro-cents (cents × 10⁶) for a metered LLM call.
/// Sister to [`cents_for`]; use this when the value will be summed across
/// calls or compared against a budget cap. See `Usage::cents_micro` for
/// the load-bearing rationale.
pub fn cents_micro_for(model: &str, provider: &str, input_tokens: u64, output_tokens: u64) -> u64 {
    pricing_for(provider, model).cents_micro_for(input_tokens, output_tokens)
}

/// Provider identifiers we understand. Derived from the request's target host.
pub const PROVIDER_ANTHROPIC: &str = "anthropic";
pub const PROVIDER_OPENAI: &str = "openai";

/// Map a target URL host to a provider we know how to meter. Returns `None`
/// for anything else (e.g. GitHub API), in which case metering is skipped.
pub fn provider_for_host(host: &str) -> Option<&'static str> {
    // Normalize case since the Host header / URL host are case-insensitive per
    // RFC 3986 but the match arms are literal.
    let lower = host.to_ascii_lowercase();
    // Trim a trailing dot that can appear in FQDNs (e.g. "api.anthropic.com.").
    let lower = lower.trim_end_matches('.');
    match lower {
        "api.anthropic.com" => Some(PROVIDER_ANTHROPIC),
        "api.openai.com" => Some(PROVIDER_OPENAI),
        // ChatGPT plan/subscription backend (codex GPT-plan lane, P22-S2). The
        // `/backend-api/codex/responses` body is the same OpenAI Responses
        // usage shape, so it meters under the OpenAI provider.
        "chatgpt.com" => Some(PROVIDER_OPENAI),
        _ => None,
    }
}

/// Parsed token counts from an LLM response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Parse token usage from an LLM response body. `provider` selects the
/// parser. Returns `None` if the body doesn't contain a recognizable usage
/// block — callers should silently skip metering in that case.
///
/// Handles both JSON-complete bodies (legacy non-streaming path) and
/// Anthropic/OpenAI SSE streams. Detection is by-content: bodies whose first
/// non-whitespace byte is `{` or `[` are treated as JSON; anything else is
/// attempted as provider-specific SSE. The caller does not need to distinguish
/// — `meter_response` will get the same `ParsedUsage` back either way.
pub fn parse_usage(provider: &str, body: &[u8]) -> Option<ParsedUsage> {
    if looks_like_json(body) {
        let value: serde_json::Value = serde_json::from_slice(body).ok()?;
        let usage = value.get("usage")?;
        return match provider {
            PROVIDER_ANTHROPIC => parse_anthropic_usage(usage),
            PROVIDER_OPENAI => parse_openai_usage(usage),
            _ => None,
        };
    }
    // P69L.1: Anthropic SSE streams (text/event-stream). Parse frame-by-frame
    // and accumulate usage from `message_start` + `message_delta` events.
    if provider == PROVIDER_ANTHROPIC {
        return parse_anthropic_sse_usage(body).map(|p| p.usage);
    }
    // P22-S2: OpenAI Responses-API SSE (codex GPT-plan lane). The buffered
    // codex response is an SSE stream; pull usage from `response.completed`.
    if provider == PROVIDER_OPENAI {
        return parse_openai_responses_sse_usage(body);
    }
    None
}

/// True when the first non-whitespace byte suggests a JSON document. SSE
/// streams always start with an `event:` or `data:` line — never `{` — so
/// this is a robust cheap check.
fn looks_like_json(body: &[u8]) -> bool {
    for b in body {
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            b'{' | b'[' => return true,
            _ => return false,
        }
    }
    false
}

fn parse_anthropic_usage(usage: &serde_json::Value) -> Option<ParsedUsage> {
    // Anthropic: { "input_tokens": N, "output_tokens": N,
    //              "cache_creation_input_tokens": N?, "cache_read_input_tokens": N? }
    // Cache-related tokens fold into input_tokens for billing purposes — they
    // are still tokens the model processed against the grant's budget.
    let input = usage.get("input_tokens")?.as_u64()?;
    let output = usage.get("output_tokens")?.as_u64()?;
    let cache_create = usage
        .get("cache_creation_input_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cache_read = usage
        .get("cache_read_input_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    Some(ParsedUsage {
        input_tokens: input
            .saturating_add(cache_create)
            .saturating_add(cache_read),
        output_tokens: output,
    })
}

fn parse_openai_usage(usage: &serde_json::Value) -> Option<ParsedUsage> {
    // Two OpenAI usage shapes:
    //   Chat Completions: { "prompt_tokens": N, "completion_tokens": N, ... }
    //   Responses API:    { "input_tokens": N,  "output_tokens": N,     ... }
    // The codex GPT-plan lane (chatgpt.com/backend-api/codex/responses) uses the
    // Responses shape (P22-S2). Accept either.
    let input = usage
        .get("input_tokens")
        .or_else(|| usage.get("prompt_tokens"))?
        .as_u64()?;
    let output = usage
        .get("output_tokens")
        .or_else(|| usage.get("completion_tokens"))?
        .as_u64()?;
    Some(ParsedUsage {
        input_tokens: input,
        output_tokens: output,
    })
}

/// Parse usage out of an OpenAI **Responses-API SSE** body (the codex GPT-plan
/// lane). The stream ends with a `response.completed` event whose
/// `data:` JSON carries `response.usage = { input_tokens, output_tokens, ... }`.
/// We scan `data:` payloads and take the usage from the terminal
/// `response.completed` event (falling back to any event carrying
/// `response.usage`). Returns `None` if no usage block is present.
fn parse_openai_responses_sse_usage(body: &[u8]) -> Option<ParsedUsage> {
    let text = std::str::from_utf8(body).ok()?;
    let mut found: Option<ParsedUsage> = None;
    for line in text.lines() {
        let payload = match line.strip_prefix("data:") {
            Some(p) => p.trim(),
            None => continue,
        };
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
            continue;
        };
        // Responses SSE nests usage under `.response.usage`; some events carry
        // a top-level `.usage`. Prefer the `response.completed` event.
        let usage = value
            .get("response")
            .and_then(|r| r.get("usage"))
            .or_else(|| value.get("usage"));
        if let Some(usage) = usage
            && let Some(parsed) = parse_openai_usage(usage)
        {
            let is_completed =
                value.get("type").and_then(|t| t.as_str()) == Some("response.completed");
            if is_completed {
                return Some(parsed);
            }
            found = Some(parsed);
        }
    }
    found
}

fn parse_openai_responses_sse_model(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let mut found: Option<String> = None;
    for line in text.lines() {
        let payload = match line.strip_prefix("data:") {
            Some(p) => p.trim(),
            None => continue,
        };
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
            continue;
        };
        let model = value
            .get("response")
            .and_then(|r| r.get("model"))
            .or_else(|| value.get("model"))
            .and_then(|m| m.as_str());
        let Some(model) = model else {
            continue;
        };
        let is_completed = value.get("type").and_then(|t| t.as_str()) == Some("response.completed");
        if is_completed {
            return Some(model.to_string());
        }
        found = Some(model.to_string());
    }
    found
}

/// Shape of the Anthropic SSE aggregation — `usage` is the accumulated
/// token counts, `model` is the `message_start.message.model` if seen
/// (returned as a convenience so the proxy can skip a second pass for
/// pricing lookup), and `saw_message_stop` records whether the stream
/// ended cleanly. The caller — `proxy.rs::run_post_flight_meter` — uses
/// `saw_message_stop` to tag the audit record `complete` vs `partial`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnthropicSseSummary {
    pub usage: ParsedUsage,
    pub model: Option<String>,
    pub saw_message_stop: bool,
}

/// Incremental SSE parsing summary — drop-in replacement for the raw
/// `Vec<u8>` accumulator that `TeeBody` historically held.
///
/// C44-TEE-INCR-PARSE: the streaming proxy used to accumulate every
/// upstream byte into a `Vec<u8>` capped at `MAX_STREAMING_RESPONSE_BYTES`
/// (1 MiB). For metering we only need the integer token counts plus the
/// model string — a struct that is bytes, not megabytes. `UsageSummary`
/// is what `AnthropicSseStreamParser::summary()` produces and what the
/// `TeeMeterCallback` consumes; the raw byte buffer is gone from the
/// streaming path. The parser handles Anthropic Messages SSE and OpenAI
/// Responses SSE usage events.
///
/// Cache tokens are kept separate from `input_tokens` until the final
/// fold-into-Usage step so a partial summary can record the message_start
/// counts even when no `message_delta` arrived. The fold mirrors the
/// non-streaming JSON path's behaviour exactly (ADR 072 §metering).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageSummary {
    /// Authoritative `input_tokens` (from `message_start.message.usage`).
    pub input_tokens: u64,
    /// Cumulative output high-water mark (max across `message_delta` events).
    pub output_tokens: u64,
    /// Cache-creation tokens (from `message_start.message.usage`).
    pub cache_creation_input_tokens: u64,
    /// Cache-read tokens (from `message_start.message.usage`).
    pub cache_read_input_tokens: u64,
    /// Model identifier from the provider's stream metadata.
    pub model: Option<String>,
    /// `true` once a `message_stop` event has been observed.
    pub saw_message_stop: bool,
    /// `true` once any usage field has been observed (matches the
    /// `Option<AnthropicSseSummary>` semantics of the byte-slice parser:
    /// callers can skip metering when nothing was seen).
    pub saw_any_usage: bool,
}

impl UsageSummary {
    /// Equivalent of the historical `parse_anthropic_sse_usage` return —
    /// folds cache tokens into `input_tokens` so the `ParsedUsage` shape
    /// matches the non-streaming JSON path. Use this when a downstream
    /// consumer needs the legacy `(input, output)` pair.
    pub fn folded_usage(&self) -> ParsedUsage {
        ParsedUsage {
            input_tokens: self
                .input_tokens
                .saturating_add(self.cache_creation_input_tokens)
                .saturating_add(self.cache_read_input_tokens),
            output_tokens: self.output_tokens,
        }
    }
}

/// Maximum bytes the streaming SSE parser will buffer between frames.
///
/// SSE frames are separated by a blank line. When a chunk arrives that
/// doesn't end on a frame boundary, the trailing partial frame is held
/// here until the next chunk completes it. 8 KiB is comfortably above
/// the largest legitimate Anthropic frame (a `message_start` carrying
/// model, usage, and headers is ≈ 500 bytes; `message_delta` is under
/// 200) while keeping per-stream memory bounded regardless of length.
///
/// A hostile upstream that emits a single >8 KiB frame without a
/// trailing blank line would otherwise let us pin unbounded RSS. When
/// the buffer would grow past this cap we drop the oldest bytes and
/// keep parsing — the `saw_message_stop` flag stays accurate as long as
/// the stop frame itself fits in the cap.
pub const SSE_PARTIAL_FRAME_CAP_BYTES: usize = 8 * 1024;

/// Incremental LLM SSE parser.
///
/// C44-TEE-INCR-PARSE: replaces the raw-byte accumulator that `TeeBody`
/// historically held. Bytes arrive in chunks (`feed`) split on arbitrary
/// boundaries — including mid-frame and mid-line. The parser owns a
/// bounded partial-frame buffer (see `SSE_PARTIAL_FRAME_CAP_BYTES`),
/// extracts complete frames as they form, and updates the running
/// `UsageSummary` exactly the way the byte-slice parser would have for
/// supported provider streams.
///
/// Frame extraction respects both LF-LF and CRLF-CRLF separators; the
/// CRLF case is normalised to LF on the fly so the same scan logic
/// handles both. The cap is enforced at frame-buffer level (single
/// in-flight frame), not at total-bytes-seen level — total bytes streamed
/// can be arbitrarily large.
#[derive(Debug, Default)]
pub struct AnthropicSseStreamParser {
    /// In-flight bytes that have not yet completed a frame. Capped at
    /// `SSE_PARTIAL_FRAME_CAP_BYTES`.
    partial: Vec<u8>,
    /// Running summary updated as each complete frame is parsed.
    summary: UsageSummary,
}

impl AnthropicSseStreamParser {
    /// Construct an empty parser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a chunk of upstream bytes. Returns `()` — the running
    /// summary is observable via `summary()` after each call. Frames
    /// that complete inside this chunk update the summary synchronously;
    /// trailing partial bytes are buffered for the next chunk.
    pub fn feed(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }

        // Append to the partial buffer, capped. If the partial buffer
        // would overflow the cap, drop the oldest bytes — keeping the
        // newest is correct because frame separators (`\n\n`) only
        // become valid at the end of a frame, so we want the trailing
        // tail of the buffer to stay intact.
        self.append_capped(chunk);

        // Extract every complete frame currently in the buffer, leaving
        // the trailing partial (if any) in `self.partial`.
        // Normalize CRLF → LF in-place inside a borrowed working slice
        // so both wire shapes parse identically.
        let normalized: Vec<u8>;
        let working: &[u8] = if self.partial.contains(&b'\r') {
            normalized = normalize_crlf(&self.partial);
            &normalized
        } else {
            &self.partial
        };

        // Walk the working slice for frame separators (`\n\n`). Collect
        // owned frames + the trailing tail BEFORE releasing the borrow,
        // then mutate `self`.
        let (frames, tail): (Vec<Vec<u8>>, Option<Vec<u8>>) = {
            let mut frames: Vec<Vec<u8>> = Vec::new();
            let mut start: usize = 0;
            let mut last_consumed: usize = 0;
            while let Some(pos) = find_frame_separator(working, start) {
                frames.push(working[start..pos].to_vec());
                start = pos + 2;
                last_consumed = start;
            }
            let tail = if last_consumed > 0 {
                Some(working[last_consumed..].to_vec())
            } else {
                None
            };
            (frames, tail)
        };

        for frame in &frames {
            self.process_frame(frame);
        }
        if let Some(tail) = tail {
            self.partial = tail;
        }
    }

    /// Borrow the running summary.
    pub fn summary(&self) -> &UsageSummary {
        &self.summary
    }

    /// Take the running summary by value, leaving the parser at default.
    /// Used by `TeeBody::poll_frame` when firing the meter callback so
    /// the summary doesn't need to be cloned.
    pub fn take_summary(&mut self) -> UsageSummary {
        std::mem::take(&mut self.summary)
    }

    /// Bytes currently held in the partial-frame buffer. Test-only —
    /// used to verify the per-stream memory cap stays bounded.
    ///
    /// Gated on `test-support` (not bare `#[cfg(test)]`) so ember-daemon's
    /// in-tree `TeeBody::buffered_bytes` test accessor can reach it through
    /// the `proxy-forward-runtime/test-support` dev-dependency feature.
    #[cfg(any(test, feature = "test-support"))]
    pub fn buffered_bytes(&self) -> usize {
        self.partial.len()
    }

    fn append_capped(&mut self, chunk: &[u8]) {
        let new_len = self.partial.len().saturating_add(chunk.len());
        if new_len <= SSE_PARTIAL_FRAME_CAP_BYTES {
            self.partial.extend_from_slice(chunk);
            return;
        }
        // Compute how much of the existing buffer to keep so the result
        // fits exactly under the cap with the new chunk appended.
        if chunk.len() >= SSE_PARTIAL_FRAME_CAP_BYTES {
            // The chunk alone already saturates the cap; keep only the
            // trailing cap bytes of the chunk.
            self.partial.clear();
            let start = chunk.len() - SSE_PARTIAL_FRAME_CAP_BYTES;
            self.partial.extend_from_slice(&chunk[start..]);
            return;
        }
        // Drop the oldest bytes from the existing partial.
        let keep_existing = SSE_PARTIAL_FRAME_CAP_BYTES - chunk.len();
        let drop_n = self.partial.len().saturating_sub(keep_existing);
        self.partial.drain(..drop_n);
        self.partial.extend_from_slice(chunk);
    }

    fn process_frame(&mut self, frame: &[u8]) {
        // Decode lossily — SSE is UTF-8 spec'd but a malformed byte
        // inside a JSON string should not abort the whole parse.
        let frame_text = String::from_utf8_lossy(frame);
        let mut event_name: Option<&str> = None;
        let mut data_lines: Vec<&str> = Vec::new();
        for line in frame_text.lines() {
            if line.starts_with(':') || line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("event:") {
                event_name = Some(rest.trim());
            } else if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.trim_start());
            }
        }
        let data = if data_lines.is_empty() {
            return;
        } else if data_lines.len() == 1 {
            data_lines[0].to_string()
        } else {
            data_lines.join("\n")
        };

        let Ok(value) = serde_json::from_str::<serde_json::Value>(&data) else {
            return;
        };

        let event_type = event_name
            .or_else(|| value.get("type").and_then(|v| v.as_str()))
            .unwrap_or("");

        match event_type {
            "message_start" => {
                if let Some(msg) = value.get("message") {
                    if let Some(m) = msg.get("model").and_then(|v| v.as_str()) {
                        self.summary.model = Some(m.to_string());
                    }
                    if let Some(usage) = msg.get("usage") {
                        self.summary.saw_any_usage = true;
                        if let Some(n) = usage.get("input_tokens").and_then(|v| v.as_u64()) {
                            self.summary.input_tokens = self.summary.input_tokens.max(n);
                        }
                        if let Some(n) = usage
                            .get("cache_creation_input_tokens")
                            .and_then(|v| v.as_u64())
                        {
                            self.summary.cache_creation_input_tokens =
                                self.summary.cache_creation_input_tokens.max(n);
                        }
                        if let Some(n) = usage
                            .get("cache_read_input_tokens")
                            .and_then(|v| v.as_u64())
                        {
                            self.summary.cache_read_input_tokens =
                                self.summary.cache_read_input_tokens.max(n);
                        }
                        // c44 MSG-START-POISON: deliberately skip
                        // `output_tokens` here — see the byte-slice
                        // parser for the full rationale.
                    }
                }
            }
            "message_delta" => {
                if let Some(usage) = value.get("usage") {
                    self.summary.saw_any_usage = true;
                    // c44 Phase E HIGH: only output_tokens from delta;
                    // ignore any input_tokens / cache_* injection.
                    if let Some(n) = usage.get("output_tokens").and_then(|v| v.as_u64()) {
                        self.summary.output_tokens = self.summary.output_tokens.max(n);
                    }
                }
            }
            "message_stop" => {
                self.summary.saw_message_stop = true;
            }
            "response.completed" => {
                let model = value
                    .get("response")
                    .and_then(|r| r.get("model"))
                    .or_else(|| value.get("model"))
                    .and_then(|m| m.as_str());
                if let Some(model) = model {
                    self.summary.model = Some(model.to_string());
                }
                let usage = value
                    .get("response")
                    .and_then(|r| r.get("usage"))
                    .or_else(|| value.get("usage"));
                if let Some(usage) = usage
                    && let Some(parsed) = parse_openai_usage(usage)
                {
                    self.summary.saw_any_usage = true;
                    self.summary.input_tokens = self.summary.input_tokens.max(parsed.input_tokens);
                    self.summary.output_tokens =
                        self.summary.output_tokens.max(parsed.output_tokens);
                }
                // OpenAI Responses streams carry usage on the terminal
                // `response.completed` event. Treat it as the streaming
                // stop signal so complete streams do not look partial to
                // downstream summary consumers.
                self.summary.saw_message_stop = true;
            }
            _ => {}
        }
    }
}

/// Normalize CRLF → LF. Allocates only when `\r` is present (fast path
/// in the streaming parser is byte-identical to LF input).
fn normalize_crlf(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\r' && i + 1 < input.len() && input[i + 1] == b'\n' {
            out.push(b'\n');
            i += 2;
        } else if input[i] == b'\r' {
            // Bare CR — drop it (matches `\r\n` → `\n` semantics for
            // the SSE-frame finder; spec only allows LF or CRLF).
            i += 1;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

/// Find the next `\n\n` in `input` starting at `from`. Returns the index
/// of the first `\n` of the pair.
fn find_frame_separator(input: &[u8], from: usize) -> Option<usize> {
    if from >= input.len() {
        return None;
    }
    let mut i = from;
    while i + 1 < input.len() {
        if input[i] == b'\n' && input[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Parse an Anthropic Messages-API SSE stream and accumulate usage
/// tokens. The wire format is documented at
/// <https://docs.anthropic.com/en/docs/build-with-claude/streaming>.
///
/// Behaviour:
///   * `message_start.message.usage.input_tokens` (plus cache_creation /
///     cache_read variants) is taken as the authoritative input-token
///     count — this event fires at most once per stream.
///   * `message_delta.usage.output_tokens` is cumulative in the real
///     Anthropic wire format (the final delta carries the total). We
///     track the **max** value seen so partial streams record what was
///     produced up to the interruption and full streams match the
///     non-streaming path exactly.
///   * `message_stop` marks a clean termination. Its absence (upstream
///     disconnect, tee size-cap abort, client hang-up) flips the summary
///     to `saw_message_stop: false` so the meter can distinguish
///     `complete` from `partial`.
///
/// Returns `None` only when no usage field was seen at all (body was
/// empty or upstream died before `message_start`). In every other case
/// we emit the partial usage so the audit record captures what the
/// agent actually consumed.
pub fn parse_anthropic_sse_usage(body: &[u8]) -> Option<AnthropicSseSummary> {
    // Parse UTF-8 lossily — SSE is spec'd as UTF-8 but a malformed byte
    // inside a JSON string would abort the whole parse if we were strict.
    let text = String::from_utf8_lossy(body);

    // c44 SSE-CRLF: the SSE spec (WHATWG / RFC 8895-ish) permits either LF-LF
    // or CRLF-CRLF as the frame separator. Anthropic ships LF today, but some
    // TLS-terminating intermediaries rewrite line endings — a CRLF-framed
    // response would otherwise collapse into a single unsplit parse unit and
    // metering would silently degrade to None. Normalize once at entry so the
    // existing `\n\n` split and `.lines()` scans stay unchanged. The 1 MiB
    // tee cap on upstream bodies bounds the allocation; the `contains('\r')`
    // fast-path skips the reallocation entirely for LF-only streams (the
    // overwhelming common case).
    let normalized: String;
    let text: &str = if text.contains('\r') {
        normalized = text.replace("\r\n", "\n");
        &normalized
    } else {
        text.as_ref()
    };

    let mut input_tokens: u64 = 0;
    let mut cache_create: u64 = 0;
    let mut cache_read: u64 = 0;
    let mut output_tokens_max: u64 = 0;
    let mut model: Option<String> = None;
    let mut saw_message_stop = false;
    let mut saw_any_usage = false;
    let mut saw_message_start = false;

    // SSE frames are separated by a blank line. Parse each frame and
    // extract its `event:` name + `data:` JSON payload. We deliberately
    // ignore `id:` / `retry:` fields — Anthropic does not use them and
    // strict ignoring lets us stay robust to future additions.
    for frame in text.split("\n\n") {
        let mut event_name: Option<&str> = None;
        let mut data_lines: Vec<&str> = Vec::new();
        for line in frame.lines() {
            // RFC 8895-ish: a line starting with `:` is a comment, skip.
            if line.starts_with(':') || line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("event:") {
                event_name = Some(rest.trim());
            } else if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.trim_start());
            }
        }
        let data = if data_lines.is_empty() {
            continue;
        } else if data_lines.len() == 1 {
            data_lines[0].to_string()
        } else {
            // Multi-line `data:` fields are concatenated with `\n` per
            // the SSE spec — rare in Anthropic's stream but tolerated.
            data_lines.join("\n")
        };

        // Parse the data payload as JSON. Skip frames that don't parse —
        // a malformed frame should not tank the entire accumulator.
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&data) else {
            continue;
        };

        // Resolve the event type: prefer the `event:` SSE line, fall
        // back to the `"type"` JSON field (Anthropic sets both for
        // message_start / message_delta / message_stop).
        let event_type = event_name
            .or_else(|| value.get("type").and_then(|v| v.as_str()))
            .unwrap_or("");

        match event_type {
            "message_start" => {
                saw_message_start = true;
                if let Some(msg) = value.get("message") {
                    if let Some(m) = msg.get("model").and_then(|v| v.as_str()) {
                        model = Some(m.to_string());
                    }
                    if let Some(usage) = msg.get("usage") {
                        saw_any_usage = true;
                        if let Some(n) = usage.get("input_tokens").and_then(|v| v.as_u64()) {
                            // Take the max across any repeated message_start
                            // (defensive; Anthropic fires this exactly once).
                            input_tokens = input_tokens.max(n);
                        }
                        if let Some(n) = usage
                            .get("cache_creation_input_tokens")
                            .and_then(|v| v.as_u64())
                        {
                            cache_create = cache_create.max(n);
                        }
                        if let Some(n) = usage
                            .get("cache_read_input_tokens")
                            .and_then(|v| v.as_u64())
                        {
                            cache_read = cache_read.max(n);
                        }
                        // c44 MSG-START-POISON: deliberately do NOT read
                        // `output_tokens` from `message_start`. Per Anthropic's
                        // streaming spec it is always 0 at this point — the
                        // stream hasn't produced any output yet. Reading it
                        // here would let a hostile upstream set e.g.
                        // `output_tokens: u64::MAX` and poison the high-water
                        // mark for the rest of the stream, since the
                        // `message_delta` path max-merges. Mirrors the
                        // input_tokens discipline enforced in the delta arm.
                    }
                }
            }
            "message_delta" => {
                if let Some(usage) = value.get("usage") {
                    saw_any_usage = true;
                    // Only output_tokens is read from message_delta. Per
                    // Anthropic's streaming spec, input_tokens / cache_*
                    // counts are authoritative at message_start and do NOT
                    // update during the stream. A hostile upstream (MITM,
                    // rogue relay, compromised endpoint) could otherwise
                    // inject a single delta with inflated input_tokens to
                    // exhaust the grant's budget — c44 Phase E HIGH.
                    if let Some(n) = usage.get("output_tokens").and_then(|v| v.as_u64()) {
                        output_tokens_max = output_tokens_max.max(n);
                    }
                }
            }
            "message_stop" => {
                saw_message_stop = true;
            }
            _ => {} // content_block_start / _delta / _stop / ping / error — no usage.
        }
    }

    if !saw_any_usage && !saw_message_start {
        return None;
    }

    Some(AnthropicSseSummary {
        usage: ParsedUsage {
            input_tokens: input_tokens
                .saturating_add(cache_create)
                .saturating_add(cache_read),
            output_tokens: output_tokens_max,
        },
        model,
        saw_message_stop,
    })
}

/// Extract the model name from an LLM response body. Optional — used only so
/// the pricing table sees the actual model the server responded with.
///
/// Handles JSON bodies (legacy), Anthropic SSE streams (P69L.1), and OpenAI
/// Responses SSE streams. The SSE paths read the provider's model field so
/// budget cents are priced against the same model the server returned.
pub fn extract_model(provider: &str, body: &[u8]) -> Option<String> {
    if looks_like_json(body) {
        let value: serde_json::Value = serde_json::from_slice(body).ok()?;
        return match provider {
            PROVIDER_ANTHROPIC | PROVIDER_OPENAI => value
                .get("model")
                .and_then(|v| v.as_str())
                .map(String::from),
            _ => None,
        };
    }
    if provider == PROVIDER_ANTHROPIC {
        return parse_anthropic_sse_usage(body).and_then(|s| s.model);
    }
    if provider == PROVIDER_OPENAI {
        return parse_openai_responses_sse_model(body);
    }
    None
}

/// Estimate the worst-case input/output tokens for a pre-flight budget check.
///
/// Strategy: parse the request body as JSON, count bytes divided by 4 as
/// an upper-bound proxy for input tokens (real tokenization is tighter but
/// this biases conservative). Read `max_tokens` or `max_completion_tokens`
/// as the output bound; default 4000 if absent. Returns the total of
/// `(input_est + output_est)` so callers can compare to remaining budget
/// directly.
pub fn estimate_call_tokens(body: &[u8]) -> u64 {
    let (input_est, output_est) = estimate_call_tokens_split(body);
    input_est.saturating_add(output_est)
}

/// Same as `estimate_call_tokens`, but returns the (input, output) split so
/// callers that want to log or test either piece can do so.
pub fn estimate_call_tokens_split(body: &[u8]) -> (u64, u64) {
    const DEFAULT_MAX_OUTPUT: u64 = 4_000;
    // Fallback: if the body isn't valid JSON, use the raw byte length / 4 as
    // input estimate and default output.
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        let input_est = (body.len() as u64) / 4;
        return (input_est, DEFAULT_MAX_OUTPUT);
    };

    // Input estimate: total serialized JSON length / 4. The byte length is a
    // generous upper bound because tokenizers compress structured tokens.
    let input_est = (body.len() as u64) / 4;

    // Output estimate: prefer max_completion_tokens (new OpenAI param), then
    // max_tokens (Anthropic + legacy OpenAI). Anything else defaults to 4k.
    let output_est = value
        .get("max_completion_tokens")
        .and_then(|v| v.as_u64())
        .or_else(|| value.get("max_tokens").and_then(|v| v.as_u64()))
        .unwrap_or(DEFAULT_MAX_OUTPUT);

    (input_est, output_est)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_usage_openai_responses_json_shape() {
        // Responses API complete-JSON body uses input_tokens/output_tokens.
        let body = br#"{"usage":{"input_tokens":120,"output_tokens":45,"total_tokens":165}}"#;
        let u = parse_usage(PROVIDER_OPENAI, body).expect("responses json usage");
        assert_eq!(u.input_tokens, 120);
        assert_eq!(u.output_tokens, 45);
    }

    #[test]
    fn parse_usage_openai_chat_shape_still_works() {
        let body = br#"{"usage":{"prompt_tokens":10,"completion_tokens":7}}"#;
        let u = parse_usage(PROVIDER_OPENAI, body).expect("chat usage");
        assert_eq!(u.input_tokens, 10);
        assert_eq!(u.output_tokens, 7);
    }

    #[test]
    fn parse_usage_openai_responses_sse_completed_event() {
        // codex GPT-plan lane: buffered SSE; usage rides response.completed.
        let body = b"event: response.created\n\
data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-4o-mini\"}}\n\
\n\
event: response.completed\n\
data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-4o-mini\",\"usage\":{\"input_tokens\":2000,\"output_tokens\":754,\"total_tokens\":2754}}}\n\
\n";
        let u = parse_usage(PROVIDER_OPENAI, body).expect("responses sse usage");
        assert_eq!(u.input_tokens, 2000);
        assert_eq!(u.output_tokens, 754);
        assert_eq!(
            extract_model(PROVIDER_OPENAI, body).as_deref(),
            Some("gpt-4o-mini")
        );
    }

    #[test]
    fn incremental_sse_parser_extracts_openai_responses_completed_usage() {
        let body = b"event: response.created\n\
data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-4o-mini\"}}\n\
\n\
event: response.output_text.delta\n\
data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\
\n\
event: response.completed\n\
data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-4o-mini\",\"usage\":{\"input_tokens\":2000,\"output_tokens\":754,\"total_tokens\":2754}}}\n\
\n";

        let mut parser = AnthropicSseStreamParser::new();
        let split = body.len() / 2;
        parser.feed(&body[..split]);
        parser.feed(&body[split..]);

        let summary = parser.summary();
        assert!(summary.saw_any_usage);
        assert!(summary.saw_message_stop);
        assert_eq!(summary.model.as_deref(), Some("gpt-4o-mini"));
        assert_eq!(
            summary.folded_usage(),
            ParsedUsage {
                input_tokens: 2000,
                output_tokens: 754
            }
        );
    }

    #[test]
    fn parse_usage_openai_sse_without_usage_is_none() {
        let body = b"event: response.created\n\
data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}\n\n";
        assert!(parse_usage(PROVIDER_OPENAI, body).is_none());
    }

    #[test]
    fn provider_for_host_maps_chatgpt_to_openai() {
        assert_eq!(provider_for_host("chatgpt.com"), Some(PROVIDER_OPENAI));
    }

    #[test]
    fn pricing_cents_for_known_anthropic_models() {
        // Opus 4.5: 1500/7500 per MTok. 1M in + 1M out = 1500 + 7500 = 9000 cents ($90).
        assert_eq!(
            cents_for("claude-opus-4-5", "anthropic", 1_000_000, 1_000_000),
            9_000
        );
        // Opus 4.6 / 4.7 alias the same rate.
        assert_eq!(
            cents_for("claude-opus-4-6", "anthropic", 1_000_000, 1_000_000),
            9_000
        );
        assert_eq!(
            cents_for("claude-opus-4-7", "anthropic", 1_000_000, 1_000_000),
            9_000
        );

        // Sonnet 4.5: 300/1500 per MTok. 1M+1M = 300 + 1500 = 1800 cents.
        assert_eq!(
            cents_for("claude-sonnet-4-5", "anthropic", 1_000_000, 1_000_000),
            1_800
        );
        // Sonnet 4.6 aliases the same rate.
        assert_eq!(
            cents_for("claude-sonnet-4-6", "anthropic", 1_000_000, 1_000_000),
            1_800
        );

        // Haiku 4.5: 100/500 per MTok. 1M+1M = 600 cents.
        assert_eq!(
            cents_for("claude-haiku-4-5", "anthropic", 1_000_000, 1_000_000),
            600
        );

        // Haiku 3 (legacy, used by May-3 demo runner): 25/125 per MTok.
        // 1M+1M = 150 cents. Regression guard against the bug where this
        // model fell through to UNKNOWN { 0, 0 } and the cents budget
        // never incremented. (DEMO-MAY3-BUDGET-MATH-REAL)
        assert_eq!(
            cents_for("claude-3-haiku-20240307", "anthropic", 1_000_000, 1_000_000),
            150
        );
    }

    #[test]
    fn pricing_cents_for_known_openai_models() {
        // GPT-4: 3000/6000 per MTok. 1M+1M = 9000 cents ($90).
        assert_eq!(cents_for("gpt-4", "openai", 1_000_000, 1_000_000), 9_000);

        // GPT-4o: 250/1000. 1M+1M = 1250 cents.
        assert_eq!(cents_for("gpt-4o", "openai", 1_000_000, 1_000_000), 1_250);

        // GPT-4o-mini: 15/60. 1M+1M = 75 cents.
        assert_eq!(cents_for("gpt-4o-mini", "openai", 1_000_000, 1_000_000), 75);

        // GPT-4.1: 300/1200. 1M+1M = 1500 cents.
        assert_eq!(cents_for("gpt-4.1", "openai", 1_000_000, 1_000_000), 1_500);
    }

    /// DEMO-MAY3-WEDGE-METER-WIRE regression: a date-pinned Anthropic
    /// model alias must bill at the same rate as its bare-name parent.
    /// Before the fix the pricing match fell through to UNKNOWN { 0, 0 }
    /// and budget enforcement silently broke at the wire — every Anthropic
    /// call on `claude-haiku-4-5-20251001` returned cents=0 and the 5¢
    /// cap never tripped. The strip_anthropic_date_suffix normalizer
    /// catches every `-YYYYMMDD` shape generically so future date bumps
    /// don't re-break the demo.
    #[test]
    fn pricing_date_pinned_anthropic_aliases_match_family_rate() {
        // Haiku 4.5 — May 3 demo runner ships against this date alias.
        assert_eq!(
            cents_for(
                "claude-haiku-4-5-20251001",
                "anthropic",
                1_000_000,
                1_000_000
            ),
            600,
        );
        // Hypothetical future date pin must also match without a table edit.
        assert_eq!(
            cents_for(
                "claude-haiku-4-5-20260315",
                "anthropic",
                1_000_000,
                1_000_000
            ),
            600,
        );
        // Sonnet 4.6 with a future date pin.
        assert_eq!(
            cents_for(
                "claude-sonnet-4-6-20260101",
                "anthropic",
                1_000_000,
                1_000_000
            ),
            1_800,
        );
        // Strip helper itself.
        assert_eq!(
            strip_anthropic_date_suffix("claude-haiku-4-5-20251001"),
            Some("claude-haiku-4-5"),
        );
        assert_eq!(strip_anthropic_date_suffix("claude-haiku-4-5"), None);
        // OpenAI's hyphenated date form must NOT be stripped.
        assert_eq!(strip_anthropic_date_suffix("gpt-4o-2024-08-06"), None);
        // Too short to have a valid suffix.
        assert_eq!(strip_anthropic_date_suffix("abc"), None);
    }

    #[test]
    fn pricing_unknown_model_returns_zero() {
        // The debug log is emitted via `tracing::debug!` — we don't capture it
        // here; the contract is simply that unknown models return 0 cents.
        assert_eq!(
            cents_for("totally-unknown-model", "anthropic", 1_000_000, 1_000_000),
            0
        );
        assert_eq!(
            cents_for("claude-opus-4-5", "unknown-provider", 1_000, 1_000),
            0
        );
    }

    #[test]
    fn parse_anthropic_usage_simple() {
        let body = br#"{
            "id": "msg_123",
            "model": "claude-opus-4-5",
            "usage": {"input_tokens": 100, "output_tokens": 200}
        }"#;
        let parsed = parse_usage(PROVIDER_ANTHROPIC, body).expect("usage present");
        assert_eq!(parsed.input_tokens, 100);
        assert_eq!(parsed.output_tokens, 200);
    }

    #[test]
    fn parse_anthropic_usage_with_cache() {
        // cache_creation_input_tokens and cache_read_input_tokens fold into
        // input_tokens.
        let body = br#"{
            "usage": {
                "input_tokens": 100,
                "output_tokens": 200,
                "cache_creation_input_tokens": 50,
                "cache_read_input_tokens": 25
            }
        }"#;
        let parsed = parse_usage(PROVIDER_ANTHROPIC, body).expect("usage present");
        assert_eq!(parsed.input_tokens, 175);
        assert_eq!(parsed.output_tokens, 200);
    }

    #[test]
    fn parse_openai_usage() {
        let body = br#"{
            "id": "chatcmpl-abc",
            "model": "gpt-4o",
            "usage": {"prompt_tokens": 50, "completion_tokens": 75, "total_tokens": 125}
        }"#;
        let parsed = parse_usage(PROVIDER_OPENAI, body).expect("usage present");
        assert_eq!(parsed.input_tokens, 50);
        assert_eq!(parsed.output_tokens, 75);
    }

    #[test]
    fn parse_no_usage_returns_none() {
        let body = br#"{"id": "x", "content": "hello"}"#;
        assert_eq!(parse_usage(PROVIDER_ANTHROPIC, body), None);
        assert_eq!(parse_usage(PROVIDER_OPENAI, body), None);
        // Non-JSON body.
        assert_eq!(parse_usage(PROVIDER_ANTHROPIC, b"not json"), None);
        assert_eq!(parse_usage(PROVIDER_OPENAI, b""), None);
        // Unknown provider.
        let body_ok = br#"{"usage": {"input_tokens": 1, "output_tokens": 2}}"#;
        assert_eq!(parse_usage("github", body_ok), None);
    }

    #[test]
    fn provider_for_host_mapping() {
        assert_eq!(
            provider_for_host("api.anthropic.com"),
            Some(PROVIDER_ANTHROPIC)
        );
        assert_eq!(
            provider_for_host("API.ANTHROPIC.COM"),
            Some(PROVIDER_ANTHROPIC)
        );
        assert_eq!(provider_for_host("api.openai.com"), Some(PROVIDER_OPENAI));
        assert_eq!(provider_for_host("api.github.com"), None);
        assert_eq!(provider_for_host(""), None);
    }

    #[test]
    fn estimate_call_tokens_uses_max_tokens_from_body() {
        let body = br#"{"model": "claude-opus-4-5", "max_tokens": 2048, "messages": []}"#;
        let (_, output_est) = estimate_call_tokens_split(body);
        assert_eq!(output_est, 2_048);

        // Same through the sum helper.
        let total = estimate_call_tokens(body);
        let input_est = (body.len() as u64) / 4;
        assert_eq!(total, input_est + 2_048);
    }

    #[test]
    fn estimate_call_tokens_uses_max_completion_tokens() {
        let body = br#"{"model": "gpt-4o", "max_completion_tokens": 512, "messages": []}"#;
        let (_, output_est) = estimate_call_tokens_split(body);
        assert_eq!(output_est, 512);
    }

    #[test]
    fn estimate_call_tokens_defaults_output_4000() {
        let body = br#"{"model": "foo", "messages": []}"#;
        let (_, output_est) = estimate_call_tokens_split(body);
        assert_eq!(output_est, 4_000);
    }

    #[test]
    fn estimate_call_tokens_input_is_body_len_div_4_on_non_json() {
        let body = b"0123456789012345"; // 16 bytes, not JSON
        let (input_est, output_est) = estimate_call_tokens_split(body);
        assert_eq!(input_est, 4);
        assert_eq!(output_est, 4_000); // default
    }

    #[test]
    fn extract_model_works_for_known_providers() {
        let anth =
            br#"{"model": "claude-opus-4-5", "usage": {"input_tokens": 1, "output_tokens": 2}}"#;
        assert_eq!(
            extract_model(PROVIDER_ANTHROPIC, anth).as_deref(),
            Some("claude-opus-4-5")
        );
        let oai = br#"{"model": "gpt-4o", "usage": {"prompt_tokens": 1, "completion_tokens": 2}}"#;
        assert_eq!(
            extract_model(PROVIDER_OPENAI, oai).as_deref(),
            Some("gpt-4o")
        );
        // Missing model
        let no_model = br#"{"usage": {"input_tokens": 1, "output_tokens": 2}}"#;
        assert_eq!(extract_model(PROVIDER_ANTHROPIC, no_model), None);
    }

    // P69L.1 — Anthropic SSE parser unit tests.

    #[test]
    fn parse_sse_usage_minimal_stream() {
        let body = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"model\":\"claude-opus-4-5\",\"usage\":{\"input_tokens\":42,\"output_tokens\":0}}}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":18}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";
        let summary = parse_anthropic_sse_usage(body.as_bytes()).expect("parses");
        assert_eq!(summary.usage.input_tokens, 42);
        assert_eq!(summary.usage.output_tokens, 18);
        assert!(summary.saw_message_stop);
        assert_eq!(summary.model.as_deref(), Some("claude-opus-4-5"));
    }

    #[test]
    fn parse_sse_usage_folds_cache_tokens() {
        let body = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-5\",\"usage\":{\"input_tokens\":10,\"cache_creation_input_tokens\":5,\"cache_read_input_tokens\":7,\"output_tokens\":0}}}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":4}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";
        let summary = parse_anthropic_sse_usage(body.as_bytes()).expect("parses");
        // 10 + 5 + 7 = 22
        assert_eq!(summary.usage.input_tokens, 22);
        assert_eq!(summary.usage.output_tokens, 4);
    }

    #[test]
    fn parse_sse_usage_no_message_stop_is_partial() {
        let body = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-5\",\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}\n\
\n";
        let summary = parse_anthropic_sse_usage(body.as_bytes()).expect("parses");
        assert_eq!(summary.usage.output_tokens, 9);
        assert!(!summary.saw_message_stop);
    }

    #[test]
    fn parse_sse_usage_multiple_deltas_takes_max() {
        // Cumulative output_tokens stream (real Anthropic shape).
        let body = "event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":12}}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":30}}\n\
\n";
        let summary = parse_anthropic_sse_usage(body.as_bytes()).expect("parses");
        assert_eq!(summary.usage.output_tokens, 30);
    }

    #[test]
    fn parse_sse_usage_skips_malformed_frames() {
        // One bad frame sandwiched between two good ones.
        let body = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-5\",\"usage\":{\"input_tokens\":8,\"output_tokens\":0}}}\n\
\n\
event: message_delta\n\
data: {not valid json\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":6}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";
        let summary = parse_anthropic_sse_usage(body.as_bytes()).expect("parses");
        assert_eq!(summary.usage.input_tokens, 8);
        assert_eq!(summary.usage.output_tokens, 6);
        assert!(summary.saw_message_stop);
    }

    #[test]
    fn parse_sse_usage_empty_body_returns_none() {
        assert_eq!(parse_anthropic_sse_usage(b""), None);
    }

    /// c44 Phase E HIGH: a hostile upstream that injects `input_tokens` in a
    /// `message_delta` must NOT inflate billing. Only `message_start` is
    /// authoritative for input/cache counts.
    #[test]
    fn parse_sse_usage_ignores_input_tokens_in_message_delta() {
        let body = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-5\",\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":9999999,\"cache_creation_input_tokens\":9999999,\"cache_read_input_tokens\":9999999,\"output_tokens\":5}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";
        let summary = parse_anthropic_sse_usage(body.as_bytes()).expect("parses");
        assert_eq!(
            summary.usage.input_tokens, 10,
            "input_tokens must come from message_start only, not message_delta"
        );
        assert_eq!(summary.usage.output_tokens, 5);
    }

    /// c44 SSE-CRLF: CRLF-framed SSE (some enterprise TLS intermediaries
    /// rewrite line endings) must parse identically to LF-framed SSE.
    /// Without entry-point normalization, `text.split("\n\n")` would see
    /// a single unsplit blob and metering would degrade to None.
    #[test]
    fn parse_sse_usage_accepts_crlf_frames() {
        let lf_body = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"model\":\"claude-opus-4-5\",\"usage\":{\"input_tokens\":42,\"output_tokens\":0}}}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":18}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";
        let crlf_body = lf_body.replace('\n', "\r\n");
        let lf_summary = parse_anthropic_sse_usage(lf_body.as_bytes()).expect("lf parses");
        let crlf_summary = parse_anthropic_sse_usage(crlf_body.as_bytes()).expect("crlf parses");
        assert_eq!(
            lf_summary, crlf_summary,
            "CRLF-framed SSE must parse identically to LF-framed"
        );
        assert_eq!(crlf_summary.usage.input_tokens, 42);
        assert_eq!(crlf_summary.usage.output_tokens, 18);
        assert!(crlf_summary.saw_message_stop);
        assert_eq!(crlf_summary.model.as_deref(), Some("claude-opus-4-5"));
    }

    /// c44 MSG-START-POISON: a hostile upstream that sets `output_tokens`
    /// in `message_start` must NOT raise the output high-water mark. Per
    /// Anthropic's spec, `message_start.usage.output_tokens` is always 0
    /// (no output has streamed yet); reading it would let MITM inflate
    /// billing by setting it to u64::MAX, which would then stick via the
    /// max-merge in the `message_delta` arm.
    #[test]
    fn parse_sse_usage_ignores_output_tokens_in_message_start() {
        let body = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-5\",\"usage\":{\"input_tokens\":10,\"output_tokens\":9999999}}}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";
        let summary = parse_anthropic_sse_usage(body.as_bytes()).expect("parses");
        assert_eq!(summary.usage.input_tokens, 10);
        assert_eq!(
            summary.usage.output_tokens, 5,
            "output_tokens must come from message_delta only, not message_start"
        );
    }

    #[test]
    fn parse_usage_routes_sse_to_sse_parser() {
        // Confirm the top-level `parse_usage` dispatches SSE bodies to
        // the SSE parser instead of returning None.
        let body = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-5\",\"usage\":{\"input_tokens\":50,\"output_tokens\":0}}}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":25}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";
        let parsed = parse_usage(PROVIDER_ANTHROPIC, body.as_bytes()).expect("parsed");
        assert_eq!(parsed.input_tokens, 50);
        assert_eq!(parsed.output_tokens, 25);
    }

    /// c44 MSG-START-POISON regression: `message_start.usage.output_tokens`
    /// set to `u64::MAX` by a hostile upstream must NOT raise the running
    /// high-water mark. The delta arm max-merges, so a poisoned message_start
    /// would otherwise lock `output_tokens_max` at `u64::MAX` for every
    /// subsequent delta. The fix is to never read `output_tokens` from
    /// `message_start` at all — it is always 0 per Anthropic's spec.
    #[test]
    fn message_start_output_tokens_clamped_to_zero() {
        // Stream with a hostile message_start carrying u64::MAX output_tokens,
        // followed by a normal delta (output = 7) and a stop.
        let body = format!(
            "event: message_start\n\
data: {{\"type\":\"message_start\",\"message\":{{\"model\":\"claude-opus-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":{}}}}}}}\n\
\n\
event: message_delta\n\
data: {{\"type\":\"message_delta\",\"usage\":{{\"output_tokens\":7}}}}\n\
\n\
event: message_stop\n\
data: {{\"type\":\"message_stop\"}}\n\
\n",
            u64::MAX
        );
        let summary = parse_anthropic_sse_usage(body.as_bytes()).expect("parses");
        assert_eq!(summary.usage.input_tokens, 10);
        assert_eq!(
            summary.usage.output_tokens, 7,
            "output_tokens high-water mark must be 7 (from message_delta), \
             not u64::MAX (from poisoned message_start)"
        );
        assert!(summary.saw_message_stop);

        // Edge case: no delta at all — output stays at 0.
        let body_no_delta = format!(
            "event: message_start\n\
data: {{\"type\":\"message_start\",\"message\":{{\"model\":\"claude-opus-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":{}}}}}}}\n\
\n\
event: message_stop\n\
data: {{\"type\":\"message_stop\"}}\n\
\n",
            u64::MAX
        );
        let summary2 = parse_anthropic_sse_usage(body_no_delta.as_bytes()).expect("parses");
        assert_eq!(
            summary2.usage.output_tokens, 0,
            "output_tokens must stay 0 when only a poisoned message_start is present"
        );
    }

    #[test]
    fn looks_like_json_matches_only_json_bodies() {
        assert!(looks_like_json(b"{\"k\":1}"));
        assert!(looks_like_json(b"  \n\t{"));
        assert!(looks_like_json(b"[1,2,3]"));
        assert!(!looks_like_json(b"event: message_start\n"));
        assert!(!looks_like_json(b"data: {\"k\":1}\n"));
        assert!(!looks_like_json(b""));
    }
}
