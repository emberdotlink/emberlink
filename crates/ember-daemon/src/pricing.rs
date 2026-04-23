//! Token + cost metering for the credential proxy (69K.2, design).
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

    /// Cost in integer cents for this call, rounding per-side then summing.
    /// Integer division truncates, which biases under; for the demo-critical
    /// "exhausted at 100%" path that's acceptable because the budget check
    /// is inclusive (`usage + delta > budget` rejects).
    pub fn cents_for(&self, input_tokens: u64, output_tokens: u64) -> u64 {
        let in_cost = input_tokens.saturating_mul(self.input_cents_per_million) / 1_000_000;
        let out_cost = output_tokens.saturating_mul(self.output_cents_per_million) / 1_000_000;
        in_cost.saturating_add(out_cost)
    }
}

/// Look up pricing for a `(provider, model)` pair. Provider is derived from the
/// target host in `proxy.rs` (`api.anthropic.com` → `"anthropic"`, etc.).
///
/// The table is small and literal on purpose: agents run against a tightly
/// bounded set of model names, and keeping this static avoids a config
/// dependency for the metering hot path.
pub fn pricing_for(provider: &str, model: &str) -> TokenPricing {
    match (provider, model) {
        // --- Anthropic ---
        // Opus (4.5): $15/MTok input, $75/MTok output = 1500 / 7500 cents.
        ("anthropic", "claude-opus-4-5")
        | ("anthropic", "claude-opus-4-5-20250514") => TokenPricing {
            input_cents_per_million: 1_500,
            output_cents_per_million: 7_500,
        },
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
        ("anthropic", "claude-haiku-4-5")
        | ("anthropic", "claude-haiku-4-5-20250514") => TokenPricing {
            input_cents_per_million: 100,
            output_cents_per_million: 500,
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
        _ => {
            tracing::debug!(
                provider = %provider,
                model = %model,
                "unknown model pricing, using TokenPricing::UNKNOWN (0 cents)",
            );
            TokenPricing::UNKNOWN
        }
    }
}

/// Compute the cost in cents for a metered LLM call.
///
/// Convenience wrapper around `pricing_for` + `TokenPricing::cents_for` so
/// callers don't have to thread the intermediate `TokenPricing` value.
pub fn cents_for(model: &str, provider: &str, input_tokens: u64, output_tokens: u64) -> u64 {
    pricing_for(provider, model).cents_for(input_tokens, output_tokens)
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
pub fn parse_usage(provider: &str, body: &[u8]) -> Option<ParsedUsage> {
    // Only parse JSON bodies; streaming responses (SSE) are out of scope for
    // this pass — the daemon forwards them through without parsing.
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = value.get("usage")?;
    match provider {
        PROVIDER_ANTHROPIC => parse_anthropic_usage(usage),
        PROVIDER_OPENAI => parse_openai_usage(usage),
        _ => None,
    }
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
        input_tokens: input.saturating_add(cache_create).saturating_add(cache_read),
        output_tokens: output,
    })
}

fn parse_openai_usage(usage: &serde_json::Value) -> Option<ParsedUsage> {
    // OpenAI: { "prompt_tokens": N, "completion_tokens": N, "total_tokens": N }
    let input = usage.get("prompt_tokens")?.as_u64()?;
    let output = usage.get("completion_tokens")?.as_u64()?;
    Some(ParsedUsage {
        input_tokens: input,
        output_tokens: output,
    })
}

/// Extract the model name from an LLM response body. Optional — used only so
/// the pricing table sees the actual model the server responded with.
pub fn extract_model(provider: &str, body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    match provider {
        PROVIDER_ANTHROPIC | PROVIDER_OPENAI => {
            value.get("model").and_then(|v| v.as_str()).map(String::from)
        }
        _ => None,
    }
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
        let anth = br#"{"model": "claude-opus-4-5", "usage": {"input_tokens": 1, "output_tokens": 2}}"#;
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
}
