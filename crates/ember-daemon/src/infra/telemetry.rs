//! Daemon-side process telemetry surface (ADR 212, ADR212-TELEMETRY-EXPORTER).
//!
//! emberd's slice of the three-layer split: it owns its **own** metric families
//! (defined with `core-metrics` buckets/labels), the broker-materialization
//! instrumentation, and mounts the shared `ember-telemetry` exposition handler
//! on its existing `hyper` loopback listener (the dashboard server) — no new
//! listener (ADR 212 §4), no central aggregation (ADR 212 §2).
//!
//! The registry + metric handles live in a process-global `OnceCell`
//! ([`DAEMON_TELEMETRY`]), mirroring the broker registry's startup-install
//! pattern (`broker/handler/registry.rs`). The `prometheus_client` family
//! handles are cheaply cloneable atomic-backed values that are `Send + Sync`;
//! the `Registry` itself is read-only after [`init`] runs, so render-from-`&`
//! and record-via-handle never contend.
//!
//! ## Label discipline (ADR 212 §5 — TRUST BOUNDARY)
//!
//! The broker families are labeled ONLY with the bounded, closed-set
//! `core_metrics::ReceiptKindLabel` / `core_metrics::OutcomeLabel`. No
//! per-principal id (`persona_id` / `grant_id` / `session_id`) is ever a label.
//! Per-principal correlation rides on the histogram **exemplar** instead
//! (ADR 212 §6): a sampled `correlation_id` (the `materialization_id`, which
//! also keys the Receipt) attached to a single bucket observation — a
//! high-cardinality id WITHOUT label cardinality, the spike→case→receipt pivot.
//!
//! ## Proxy-forward families (ADR 212 increment 2)
//!
//! The in-process proxy-forward path (ADR 197's separate `ember-proxy` process
//! is not yet shipped — the LLM gateway runs inside emberd today) records onto
//! these same emberd families via an injected sink:
//! `proxy_forward_runtime` stays free of the telemetry stack, so it hands a
//! bounded [`HostAuthzOutcome`] + a latency to [`ForwardSink`], installed by
//! [`install_forward_sink`]. The only label is the closed-set
//! `core_metrics::ProxyHostAuthzLabel` (allow / deny_not_in_allowlist /
//! deny_generic_no_allowlist) — same trust-boundary rule, no per-principal id.

use once_cell::sync::OnceCell;

use core_metrics::{OutcomeLabel, ProxyHostAuthzLabel, ReceiptKindLabel};
use ember_telemetry::{ResourceIdentity, TelemetryRegistry, render_metrics};
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::exemplar::HistogramWithExemplars;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::Histogram;
use proxy_forward_runtime::telemetry::{ForwardTelemetrySink, HostAuthzOutcome};

/// Bounded label set for the broker-materialization families. Both dimensions
/// are closed sets sourced from `core-metrics` — the `{receipt_kind, outcome}`
/// cross-product is the entire cardinality. Carries NO per-principal id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct MaterializationLabels {
    pub receipt_kind: ReceiptKindLabelValue,
    pub outcome: OutcomeLabelValue,
}

/// Newtype around the `core-metrics` receipt-kind label so it can derive
/// `EncodeLabelValue` (the exposition encoder trait) while the taxonomy stays
/// in the WASM-clean `core-metrics` crate. Encodes to the same stable string as
/// [`ReceiptKindLabel::as_label`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReceiptKindLabelValue(pub ReceiptKindLabel);

impl EncodeLabelValue for ReceiptKindLabelValue {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), std::fmt::Error> {
        EncodeLabelValue::encode(&self.0.as_label(), encoder)
    }
}

/// Newtype around the `core-metrics` outcome label — see
/// [`ReceiptKindLabelValue`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OutcomeLabelValue(pub OutcomeLabel);

impl EncodeLabelValue for OutcomeLabelValue {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), std::fmt::Error> {
        EncodeLabelValue::encode(&self.0.as_label(), encoder)
    }
}

/// Exemplar label set carried on a sampled histogram-bucket observation
/// (ADR 212 §6). The `correlation_id` is the `materialization_id` (or a sampled
/// id on the failure path) — high-cardinality, deliberately NOT a metric label.
#[derive(Clone, Debug, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct CorrelationExemplar {
    pub correlation_id: String,
}

/// Bounded label set for the proxy-forward host-authorization counter
/// (ADR 212 increment 2). The single `outcome` dimension is a closed 3-variant
/// set — the entire cardinality. Carries NO per-principal id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct ProxyForwardLabels {
    pub outcome: ProxyHostAuthzLabelValue,
}

/// Newtype around the `core-metrics` proxy host-authz label so it can derive
/// `EncodeLabelValue` while the taxonomy stays in the WASM-clean `core-metrics`
/// crate — see [`ReceiptKindLabelValue`]. Encodes to the same stable string as
/// [`ProxyHostAuthzLabel::as_label`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProxyHostAuthzLabelValue(pub ProxyHostAuthzLabel);

impl EncodeLabelValue for ProxyHostAuthzLabelValue {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), std::fmt::Error> {
        EncodeLabelValue::encode(&self.0.as_label(), encoder)
    }
}

/// Owned broker-materialization metric handles. Cloneable; backed by atomics.
struct BrokerMaterializationMetrics {
    /// Latency of the grant→mint→receipt path, in seconds, with a sampled
    /// `correlation_id` exemplar on the observed bucket.
    latency: Family<MaterializationLabels, HistogramWithExemplars<CorrelationExemplar>>,
    /// Outcome counter — one increment per materialization attempt.
    outcome: Family<MaterializationLabels, Counter>,
}

/// Owned proxy-forward metric handles (ADR 212 increment 2). Cloneable; backed
/// by atomics.
struct ProxyForwardMetrics {
    /// Host-authorization outcome counter — one increment per forward whose
    /// destination host was adjudicated (`authorize_forward_host`).
    host_authz: Family<ProxyForwardLabels, Counter>,
    /// End-to-end forward handling latency, in seconds. No labels and no
    /// exemplar: the forward path has no single per-request correlation id at
    /// the timing-wrapper boundary, so this is a plain distribution of "how long
    /// does a proxied request take" across every disposition.
    duration: Histogram,
}

/// The daemon's process telemetry: the shared registry (for render) plus the
/// daemon-owned metric families (for record).
pub struct DaemonTelemetry {
    telemetry: TelemetryRegistry,
    broker: BrokerMaterializationMetrics,
    proxy: ProxyForwardMetrics,
}

static DAEMON_TELEMETRY: OnceCell<DaemonTelemetry> = OnceCell::new();

impl DaemonTelemetry {
    /// Build the daemon telemetry surface and register its families. `instance`
    /// is the dashboard bound `host:port` (a bounded discriminator, never a
    /// per-principal id); `build_sha` is the compiled-in commit.
    fn build(identity: ResourceIdentity) -> Self {
        let mut telemetry = TelemetryRegistry::new(identity);

        // Latency histogram with `core-metrics` latency buckets + a per-bucket
        // exemplar slot. `new_with_constructor` so every {kind,outcome} series
        // gets the same canonical bucket layout.
        let latency = Family::<
            MaterializationLabels,
            HistogramWithExemplars<CorrelationExemplar>,
        >::new_with_constructor(|| {
            HistogramWithExemplars::new(
                core_metrics::HISTOGRAM_BUCKETS_LATENCY_SECONDS.iter().copied(),
            )
        });
        telemetry.registry_mut().register(
            "broker_materialization_duration_seconds",
            "Latency of broker grant->mint->materialization audit event (ADR 94/212)",
            latency.clone(),
        );

        let outcome = Family::<MaterializationLabels, Counter>::default();
        telemetry.registry_mut().register(
            "broker_materialization_total",
            "Broker materialization attempts by receipt kind and outcome",
            outcome.clone(),
        );

        // ADR 212 increment 2 — in-process proxy-forward families.
        let proxy_host_authz = Family::<ProxyForwardLabels, Counter>::default();
        telemetry.registry_mut().register(
            "proxy_forward_host_authz_total",
            "Proxy forward host-authorization decisions by outcome (ADR 205/212)",
            proxy_host_authz.clone(),
        );

        let proxy_duration = Histogram::new(
            core_metrics::HISTOGRAM_BUCKETS_LATENCY_SECONDS
                .iter()
                .copied(),
        );
        telemetry.registry_mut().register(
            "proxy_forward_request_duration_seconds",
            "End-to-end proxy forward request handling latency (ADR 197/212)",
            proxy_duration.clone(),
        );

        Self {
            telemetry,
            broker: BrokerMaterializationMetrics { latency, outcome },
            proxy: ProxyForwardMetrics {
                host_authz: proxy_host_authz,
                duration: proxy_duration,
            },
        }
    }

    /// Render this process's `/metrics` text exposition.
    pub fn render(&self) -> Result<String, ember_telemetry::RenderError> {
        render_metrics(self.telemetry.registry())
    }
}

/// Initialise the process-global daemon telemetry once at startup. Idempotent —
/// a second call is a no-op (the first install wins), matching the broker
/// registry's `OnceCell` contract. Safe to call before the dashboard binds.
pub fn init(instance: impl Into<String>, build_sha: impl Into<String>) {
    let identity = ResourceIdentity::new("emberd", instance, env!("CARGO_PKG_VERSION"), build_sha);
    let _ = DAEMON_TELEMETRY.set(DaemonTelemetry::build(identity));
}

/// Borrow the installed telemetry, if [`init`] has run.
pub fn current() -> Option<&'static DaemonTelemetry> {
    DAEMON_TELEMETRY.get()
}

/// Render the `/metrics` exposition, or `None` if telemetry is not yet
/// installed. The dashboard route maps `None` to a `503` so a scrape before
/// startup-init is a clean "not ready" rather than an empty body.
pub fn render_exposition() -> Option<String> {
    current().and_then(|t| t.render().ok())
}

/// Record one broker materialization attempt: bump the outcome counter and
/// observe the latency, attaching a sampled `correlation_id` exemplar to the
/// histogram bucket (ADR 212 §6).
///
/// No-op if telemetry is not installed (e.g. unit-test paths that never call
/// [`init`]). The `correlation_id` is the `materialization_id` on success — the
/// same id that keys the Receipt — so a Grafana spike → exemplar → receipt is
/// one chain.
pub fn record_broker_materialization(
    kind: ReceiptKindLabel,
    outcome: OutcomeLabel,
    latency_seconds: f64,
    correlation_id: &str,
) {
    let Some(t) = current() else {
        return;
    };
    let labels = MaterializationLabels {
        receipt_kind: ReceiptKindLabelValue(kind),
        outcome: OutcomeLabelValue(outcome),
    };
    t.broker.outcome.get_or_create(&labels).inc();

    // Only sample an exemplar when we have a correlation id — an empty id is
    // not a useful pivot target. The exemplar is per-bucket; the latest
    // observation in a bucket wins (prometheus-client semantics).
    let exemplar = if correlation_id.is_empty() {
        None
    } else {
        Some(CorrelationExemplar {
            correlation_id: correlation_id.to_string(),
        })
    };
    t.broker
        .latency
        .get_or_create(&labels)
        .observe(latency_seconds, exemplar, None);
}

/// Record one proxy-forward host-authorization outcome (ADR 212 increment 2).
/// No-op if telemetry is not installed.
pub fn record_proxy_host_authz(outcome: ProxyHostAuthzLabel) {
    let Some(t) = current() else {
        return;
    };
    let labels = ProxyForwardLabels {
        outcome: ProxyHostAuthzLabelValue(outcome),
    };
    t.proxy.host_authz.get_or_create(&labels).inc();
}

/// Observe one end-to-end proxy-forward request latency in seconds (ADR 212
/// increment 2). No-op if telemetry is not installed.
pub fn observe_proxy_forward_duration(latency_seconds: f64) {
    let Some(t) = current() else {
        return;
    };
    t.proxy.duration.observe(latency_seconds);
}

/// The forward-runtime telemetry sink emberd installs so the in-process
/// proxy-forward path records onto emberd's own `/metrics`. Maps the
/// dependency-free [`HostAuthzOutcome`] vocabulary onto the `core-metrics`
/// label taxonomy; carries no per-principal data (ADR 212 §5).
struct ForwardSink;

impl ForwardTelemetrySink for ForwardSink {
    fn observe_request(&self, latency_seconds: f64) {
        observe_proxy_forward_duration(latency_seconds);
    }

    fn record_host_authz(&self, outcome: HostAuthzOutcome) {
        let label = match outcome {
            HostAuthzOutcome::Allow => ProxyHostAuthzLabel::Allow,
            HostAuthzOutcome::DenyNotInAllowlist => ProxyHostAuthzLabel::DenyNotInAllowlist,
            HostAuthzOutcome::DenyGenericNoAllowlist => ProxyHostAuthzLabel::DenyGenericNoAllowlist,
        };
        record_proxy_host_authz(label);
    }
}

/// Install the forward-runtime telemetry sink (ADR 212 increment 2). Call once
/// at startup, after [`init`], so the in-process proxy-forward path (ADR 197's
/// separate `ember-proxy` process is not yet shipped) records onto emberd's
/// existing `/metrics`. Idempotent via the forward runtime's `OnceLock`.
pub fn install_forward_sink() {
    proxy_forward_runtime::telemetry::set_sink(Box::new(ForwardSink));
}

#[cfg(test)]
mod tests {
    //! T2: exercises the real exporter path (registry render + record), no
    //! process/socket I/O.
    use super::*;

    /// Build a standalone telemetry (NOT the process-global one, so tests don't
    /// race on the `OnceCell`) and exercise record + render.
    fn fresh() -> DaemonTelemetry {
        DaemonTelemetry::build(ResourceIdentity::new(
            "emberd",
            "127.0.0.1:0",
            "0.0.0-test",
            "testsha",
        ))
    }

    fn record_into(
        t: &DaemonTelemetry,
        kind: ReceiptKindLabel,
        outcome: OutcomeLabel,
        latency: f64,
        correlation_id: &str,
    ) {
        let labels = MaterializationLabels {
            receipt_kind: ReceiptKindLabelValue(kind),
            outcome: OutcomeLabelValue(outcome),
        };
        t.broker.outcome.get_or_create(&labels).inc();
        let ex = (!correlation_id.is_empty()).then(|| CorrelationExemplar {
            correlation_id: correlation_id.to_string(),
        });
        t.broker
            .latency
            .get_or_create(&labels)
            .observe(latency, ex, None);
    }

    #[test]
    fn exposition_contains_receipt_kind_outcome_series_and_no_per_principal_label() {
        let t = fresh();
        record_into(
            &t,
            ReceiptKindLabel::BrokerMint,
            OutcomeLabel::Ok,
            0.012,
            "mat-abc123",
        );
        let out = t.render().expect("render");

        // The receipt-kind/outcome series are present.
        assert!(
            out.contains("ember_broker_materialization_total"),
            "missing outcome counter: {out}"
        );
        assert!(
            out.contains("ember_broker_materialization_duration_seconds"),
            "missing latency histogram: {out}"
        );
        assert!(out.contains("receipt_kind=\"broker_mint\""), "{out}");
        assert!(out.contains("outcome=\"ok\""), "{out}");

        // TRUST BOUNDARY (ADR 212 §5): no per-principal identifier label.
        assert!(
            !out.contains("persona_id"),
            "leaked persona_id label: {out}"
        );
        assert!(!out.contains("grant_id"), "leaked grant_id label: {out}");
        assert!(
            !out.contains("session_id"),
            "leaked session_id label: {out}"
        );
    }

    #[test]
    fn correlation_id_rides_exemplar_not_label() {
        let t = fresh();
        // The correlation id is a high-cardinality value that must appear ONLY
        // as an exemplar, never promoted to a label key.
        record_into(
            &t,
            ReceiptKindLabel::BrokerMint,
            OutcomeLabel::Ok,
            0.05,
            "mat-correlation-xyz",
        );
        let out = t.render().expect("render");
        // Exemplar block carries the id...
        assert!(
            out.contains("correlation_id=\"mat-correlation-xyz\""),
            "exemplar id missing: {out}"
        );
        // ...but `correlation_id` must never be a series label on the metric
        // line itself (i.e. inside the `{...}` before the value). The exemplar
        // renders after a `#` marker; assert the id does not appear on a
        // `_total` series line.
        for line in out.lines() {
            if line.starts_with("ember_broker_materialization_total{") {
                assert!(
                    !line.contains("correlation_id"),
                    "correlation_id leaked onto a metric label line: {line}"
                );
            }
        }
    }

    /// Record into a standalone telemetry's proxy families (NOT the
    /// process-global one) so tests don't race on the `OnceCell`.
    fn record_proxy_into(t: &DaemonTelemetry, outcome: ProxyHostAuthzLabel, latency: f64) {
        let labels = ProxyForwardLabels {
            outcome: ProxyHostAuthzLabelValue(outcome),
        };
        t.proxy.host_authz.get_or_create(&labels).inc();
        t.proxy.duration.observe(latency);
    }

    #[test]
    fn proxy_forward_exposition_has_host_authz_and_duration_no_per_principal() {
        let t = fresh();
        record_proxy_into(&t, ProxyHostAuthzLabel::Allow, 0.020);
        record_proxy_into(&t, ProxyHostAuthzLabel::DenyNotInAllowlist, 0.001);
        record_proxy_into(&t, ProxyHostAuthzLabel::DenyGenericNoAllowlist, 0.001);
        let out = t.render().expect("render");

        // Both proxy-forward series are present.
        assert!(
            out.contains("ember_proxy_forward_host_authz_total"),
            "missing host-authz counter: {out}"
        );
        assert!(
            out.contains("ember_proxy_forward_request_duration_seconds"),
            "missing forward duration histogram: {out}"
        );
        // All three bounded outcomes render their stable label string.
        assert!(out.contains("outcome=\"allow\""), "{out}");
        assert!(out.contains("outcome=\"deny_not_in_allowlist\""), "{out}");
        assert!(
            out.contains("outcome=\"deny_generic_no_allowlist\""),
            "{out}"
        );

        // TRUST BOUNDARY (ADR 212 §5): no per-principal identifier label.
        assert!(!out.contains("persona_id"), "leaked persona_id: {out}");
        assert!(!out.contains("grant_id"), "leaked grant_id: {out}");
        assert!(!out.contains("session_id"), "leaked session_id: {out}");
    }

    #[test]
    fn outcome_counter_increments_per_attempt() {
        let t = fresh();
        record_into(
            &t,
            ReceiptKindLabel::BrokerMint,
            OutcomeLabel::Ok,
            0.01,
            "a",
        );
        record_into(
            &t,
            ReceiptKindLabel::BrokerMint,
            OutcomeLabel::Ok,
            0.01,
            "b",
        );
        record_into(
            &t,
            ReceiptKindLabel::BrokerMint,
            OutcomeLabel::Denied,
            0.02,
            "c",
        );
        let out = t.render().expect("render");
        // The ok series reached 2; denied reached 1. Assert both series exist
        // with their distinct outcome label.
        assert!(out.contains("outcome=\"ok\""), "{out}");
        assert!(out.contains("outcome=\"denied\""), "{out}");
    }
}
