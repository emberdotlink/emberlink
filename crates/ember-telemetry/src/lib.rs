//! `ember-telemetry` — the per-process Prometheus telemetry substrate.
//!
//! ADR212-TELEMETRY-EXPORTER — increment 1 of the process telemetry surface
//! (ADR 212). This crate is the **shared substrate** in the three-layer split:
//!
//! - `core-metrics` (WASM, no I/O) — the *taxonomy*: bucket constants,
//!   [`core_metrics::ReceiptKindLabel`] / [`core_metrics::OutcomeLabel`]
//!   newtypes, the [`core_metrics::forbidden_label_value`] gate.
//! - `ember-telemetry` (this crate, non-WASM, shared) — the *substrate*: a
//!   [`prometheus_client::registry::Registry`], a text-exposition `/metrics`
//!   handler ([`render_metrics`]), and the standard **resource-identity** label
//!   set ([`ResourceIdentity`]) carried by every process's `/metrics` output.
//! - each process (`emberd`, proxy, …) — its *own* metric families (defined
//!   with `core-metrics` buckets/labels), the instrumentation call-sites, and
//!   wiring [`render_metrics`] onto its existing HTTP listener.
//!
//! There is **no central aggregation hub and no federation** (ADR 212 §2): each
//! process exposes its own `/metrics`, scraped independently. This crate
//! deliberately does not stand up a listener — it produces the exposition bytes
//! and the registry the owning process holds; the process mounts the route on
//! the listener it already runs.
//!
//! ## Label discipline is a TRUST BOUNDARY (ADR 212 §5)
//!
//! Metric **labels** carry only low-cardinality, non-sensitive dimensions:
//! `process` / `instance` / `version` / build-SHA, plus the already-bounded
//! [`core_metrics::ReceiptKindLabel`] / [`core_metrics::OutcomeLabel`]. **No
//! per-principal identifier (`persona_id`, `grant_id`, `session_id`) is ever a
//! metric label** — both for unbounded cardinality and because labels are the
//! always-on, fully-enumerable scrape dimension (an authority-graph leak onto a
//! weaker surface than the receipt store). [`guard_label_value`] wraps
//! [`core_metrics::forbidden_label_value`] so a dynamic label value that looks
//! like a credential / key / grants.toml fragment trips loudly at the
//! instrumentation site instead of leaking onto the scrape surface.
//!
//! Per-principal correlation is served by the *right* plane (ADR 212 §6):
//! Receipts for the authoritative record, and OpenMetrics **exemplars** (a
//! sampled `correlation_id` / `grant_id` on a specific histogram-bucket
//! observation — high-cardinality ID **without** label cardinality) for
//! spike→case click-through.

use std::fmt::Write as _;

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;

/// Standard resource-identity label set carried by every process's `/metrics`
/// exposition (ADR 212 §1). This is the identity future traces and structured
/// logs will also carry, which is why the surface is named for *telemetry* and
/// not metrics: defining it once avoids refactoring a `metrics`-named silo when
/// those join.
///
/// All four dimensions are **bounded and non-sensitive** — per ADR 212 §5 a
/// resource identity is exactly the kind of low-cardinality dimension labels
/// are for. Construct it via [`ResourceIdentity::new`] so the build-SHA is read
/// from the compiled-in value rather than re-derived per call-site.
#[derive(Clone, Debug, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct ResourceIdentity {
    /// The process role, e.g. `emberd` / `proxy-forward-runtime`. Bounded by
    /// the (small, fixed) set of constellation processes.
    pub process: String,
    /// A stable instance discriminator for this process on this host (e.g. the
    /// bound `host:port` or a pod name). Bounded per host/fleet, never a
    /// per-principal id.
    pub instance: String,
    /// The semver of the running binary (`CARGO_PKG_VERSION`).
    pub version: String,
    /// The build commit SHA (short or full). Bounded — one value per build.
    pub build_sha: String,
}

impl ResourceIdentity {
    /// Construct a resource identity for the owning process.
    ///
    /// `build_sha` is caller-supplied (read from `env!("VERGEN_GIT_SHA")` or an
    /// equivalent compile-time constant by the owning process) so this crate
    /// stays free of build-script coupling; `"unknown"` is the documented
    /// fallback when no SHA is compiled in.
    pub fn new(
        process: impl Into<String>,
        instance: impl Into<String>,
        version: impl Into<String>,
        build_sha: impl Into<String>,
    ) -> Self {
        Self {
            process: process.into(),
            instance: instance.into(),
            version: version.into(),
            build_sha: build_sha.into(),
        }
    }
}

/// A registry plus the owning process's resource identity.
///
/// The process holds one of these for its lifetime, registers its metric
/// families into [`registry_mut`](TelemetryRegistry::registry_mut) at startup,
/// and serves [`render`](TelemetryRegistry::render) from its `/metrics` route.
/// The resource identity is exposed as a process-level constant gauge series
/// (`ember_build_info`) so a scraper can join on it the same way it joins on a
/// Prometheus `*_build_info` metric, without paying the cost of stamping it as
/// a label on every family.
pub struct TelemetryRegistry {
    registry: Registry,
    identity: ResourceIdentity,
}

impl TelemetryRegistry {
    /// Build a telemetry registry for the owning process. Registers the
    /// `ember_build_info` constant-`1` gauge carrying the resource identity as
    /// labels, then returns the registry for the process to register its own
    /// families into.
    pub fn new(identity: ResourceIdentity) -> Self {
        // `ember` prefix → every series is `ember_*`, matching the product
        // namespace convention so a multi-tenant Prometheus disambiguates ours.
        let mut registry = <Registry>::with_prefix("ember");

        // `ember_build_info{process,instance,version,build_sha} 1` — the
        // idiomatic Prometheus build-info join target. Carrying identity here
        // (once) rather than as a label on every family keeps the per-family
        // cardinality minimal while still letting a scraper join on identity.
        let build_info = prometheus_client::metrics::family::Family::<
            ResourceIdentity,
            prometheus_client::metrics::gauge::Gauge,
        >::default();
        build_info.get_or_create(&identity).set(1);
        registry.register(
            "build_info",
            "Build/resource identity of this process (constant 1)",
            build_info,
        );

        Self { registry, identity }
    }

    /// Mutable access to the registry so the owning process can register its
    /// own metric families at startup.
    pub fn registry_mut(&mut self) -> &mut Registry {
        &mut self.registry
    }

    /// Shared access to the registry (e.g. for rendering).
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// This process's resource identity.
    pub fn identity(&self) -> &ResourceIdentity {
        &self.identity
    }

    /// Render the OpenMetrics text exposition for this process's `/metrics`
    /// route. Equivalent to [`render_metrics`] against the held registry.
    pub fn render(&self) -> Result<String, RenderError> {
        render_metrics(&self.registry)
    }
}

/// Error rendering the text exposition. Wraps a formatting failure, which is
/// effectively unreachable for an in-memory `String` sink but surfaced rather
/// than panicked so a `/metrics` handler can return `500` instead of aborting.
#[derive(Debug)]
pub struct RenderError(std::fmt::Error);

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "metrics exposition encode failed: {}", self.0)
    }
}

impl std::error::Error for RenderError {}

/// The OpenMetrics text-exposition content type, for the `Content-Type` header
/// of a `/metrics` HTTP response. Prometheus negotiates this version.
pub const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Render the registry to the OpenMetrics text exposition — the body of a
/// `/metrics` response. This is the small `/metrics`-handler helper every
/// process uses: bind the result to a `200 OK` with [`METRICS_CONTENT_TYPE`].
pub fn render_metrics(registry: &Registry) -> Result<String, RenderError> {
    let mut buf = String::new();
    encode(&mut buf, registry).map_err(RenderError)?;
    Ok(buf)
}

/// The trust-boundary guard (ADR 212 §5). Wraps
/// [`core_metrics::forbidden_label_value`] so every **dynamic** label value
/// passed to a metric on this exporter path is screened before it can reach the
/// registry. Returns `Ok(value)` when the value is safe to use as a label, or
/// `Err(reason)` naming the leak class when it matches a forbidden shape.
///
/// Instrumentation sites MUST route dynamic label values through this gate.
/// Closed-set labels (`ReceiptKindLabel`/`OutcomeLabel`) are already bounded at
/// the type level and need no runtime screening, but anything assembled from a
/// string (an operation target, a provider id read off the wire) does.
pub fn guard_label_value(value: &str) -> Result<&str, &'static str> {
    match core_metrics::forbidden_label_value(value) {
        Some(reason) => Err(reason),
        None => Ok(value),
    }
}

/// Append a single forbidden-class diagnostic line to a buffer. Small helper so
/// instrumentation sites can log *why* a value was rejected without re-deriving
/// the reason string. Returns the reason so callers can also branch on it.
pub fn note_forbidden(buf: &mut String, value: &str) -> Option<&'static str> {
    let reason = core_metrics::forbidden_label_value(value)?;
    let _ = write!(buf, "rejected label value (class={reason})");
    Some(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::metrics::counter::Counter;
    use prometheus_client::metrics::family::Family;

    fn test_identity() -> ResourceIdentity {
        ResourceIdentity::new("emberd", "127.0.0.1:3141", "0.3.0", "deadbeef")
    }

    #[test]
    fn build_info_series_carries_resource_identity() {
        let reg = TelemetryRegistry::new(test_identity());
        let out = reg.render().expect("render");
        // The build-info join target is present and carries all four identity
        // dimensions as labels (these ARE bounded + non-sensitive).
        assert!(
            out.contains("ember_build_info"),
            "missing build_info: {out}"
        );
        assert!(out.contains("process=\"emberd\""), "{out}");
        assert!(out.contains("version=\"0.3.0\""), "{out}");
        assert!(out.contains("build_sha=\"deadbeef\""), "{out}");
    }

    #[test]
    fn registered_family_renders_in_exposition() {
        let mut reg = TelemetryRegistry::new(test_identity());
        let fam = Family::<Vec<(&'static str, &'static str)>, Counter>::default();
        fam.get_or_create(&vec![("outcome", "ok")]).inc();
        reg.registry_mut()
            .register("widgets_total", "Test widgets", fam);
        let out = reg.render().expect("render");
        assert!(out.contains("ember_widgets_total"), "{out}");
        assert!(out.contains("outcome=\"ok\""), "{out}");
    }

    #[test]
    fn guard_passes_safe_values_and_rejects_credentials() {
        assert_eq!(guard_label_value("broker_mint"), Ok("broker_mint"));
        assert_eq!(guard_label_value("ok"), Ok("ok"));
        assert_eq!(
            guard_label_value("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Err("github_token_prefix")
        );
        assert_eq!(
            guard_label_value("scope = \"vault.read\""),
            Err("grants_toml_fragment")
        );
    }

    #[test]
    fn note_forbidden_writes_reason() {
        let mut buf = String::new();
        let reason = note_forbidden(&mut buf, "hvs.AAA");
        assert_eq!(reason, Some("vault_token_prefix"));
        assert!(buf.contains("vault_token_prefix"), "{buf}");

        let mut clean = String::new();
        assert_eq!(note_forbidden(&mut clean, "broker_mint"), None);
        assert!(clean.is_empty());
    }

    #[test]
    fn content_type_is_openmetrics() {
        assert!(METRICS_CONTENT_TYPE.contains("openmetrics-text"));
    }
}
