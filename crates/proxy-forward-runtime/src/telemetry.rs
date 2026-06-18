//! CLASSIFICATION: PUBLIC
//!
//! Telemetry seam for the forwarding core (ADR 212 increment 2,
//! ADR212-TELEMETRY-EXPORTER).
//!
//! `proxy-forward-runtime` is deliberately free of daemon types AND of the
//! telemetry stack (`prometheus_client` / `core-metrics` / `ember-telemetry`) —
//! the same layering that lets it stay "linkable without emberd's vault". So
//! the forward path does NOT record metrics directly; it hands a bounded
//! outcome + a latency to an injected [`ForwardTelemetrySink`]. emberd installs
//! a sink ([`set_sink`]) that maps these into its process-global registry
//! (`ember-daemon/src/infra/telemetry.rs`) and onto its existing `/metrics`
//! listener. Absent a sink — every consumer that links this crate without
//! telemetry, and all unit tests — the helpers no-op, mirroring the daemon
//! recorder's "no-op if telemetry uninstalled" contract.
//!
//! The proxy's *own* per-process `/metrics` endpoint is gated on ADR 197 (the
//! separate `ember-proxy` process is not yet shipped — today the forward path
//! runs in-process inside emberd). This seam is what lets that endpoint drop in
//! unchanged when ADR 197 lands: a second process installs a different sink.
//!
//! ## Label discipline (ADR 212 §5 — TRUST BOUNDARY)
//!
//! The only datum that crosses this seam as a metric dimension is
//! [`HostAuthzOutcome`], a closed 3-variant set. No persona / grant / session id
//! ever rides a label — per-principal correlation belongs in the Receipt, not on
//! the weaker-protected scrape surface.

use std::sync::OnceLock;

/// Bounded host-authorization outcome of a forward attempt — the
/// `authorize_forward_host` decision projected to a closed set safe to use as a
/// Prometheus label (cardinality 3, no per-principal data). Mirrors the private
/// `forward::HostAuthz` arms; kept separate so the sink's wire vocabulary is
/// independent of the internal control-flow enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostAuthzOutcome {
    /// Forward permitted to the destination host.
    Allow,
    /// Refused: destination host is not in the grant's `allowed_targets`.
    DenyNotInAllowlist,
    /// Refused: a generic-lane credential with no `allowed_targets` allowlist,
    /// so the destination host would be unconstrained.
    DenyGenericNoAllowlist,
}

/// Sink the host process (emberd) installs to receive forward-path telemetry.
///
/// `Send + Sync` because it lives in a process-global accessible from the
/// forward accept loop's per-connection `spawn_local` tasks (whose `'static`
/// futures the borrow checker treats as cross-thread-capable even though they
/// run on a single-threaded `LocalSet`).
pub trait ForwardTelemetrySink: Send + Sync + 'static {
    /// One forward request finished (any disposition, including transport
    /// error); observe its end-to-end wall-clock latency in seconds.
    fn observe_request(&self, latency_seconds: f64);

    /// A host-authorization decision was reached for a forward; count it by
    /// bounded outcome.
    fn record_host_authz(&self, outcome: HostAuthzOutcome);
}

static SINK: OnceLock<Box<dyn ForwardTelemetrySink>> = OnceLock::new();

/// Install the process-global forward-telemetry sink. Idempotent — the first
/// install wins (matches the daemon telemetry `OnceCell` contract). Call once at
/// host startup.
pub fn set_sink(sink: Box<dyn ForwardTelemetrySink>) {
    let _ = SINK.set(sink);
}

/// Observe an end-to-end forward latency, if a sink is installed; otherwise a
/// no-op.
pub(crate) fn observe_request(latency_seconds: f64) {
    if let Some(sink) = SINK.get() {
        sink.observe_request(latency_seconds);
    }
}

/// Record a host-authorization outcome, if a sink is installed; otherwise a
/// no-op.
pub(crate) fn record_host_authz(outcome: HostAuthzOutcome) {
    if let Some(sink) = SINK.get() {
        sink.record_host_authz(outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    #[derive(Default)]
    struct CountingSink {
        observed_calls: AtomicUsize,
        last_latency_micros: AtomicU64,
        allow: AtomicUsize,
        deny_not_in_allowlist: AtomicUsize,
        deny_generic: AtomicUsize,
    }

    impl ForwardTelemetrySink for Arc<CountingSink> {
        fn observe_request(&self, latency_seconds: f64) {
            self.observed_calls.fetch_add(1, Ordering::Relaxed);
            self.last_latency_micros
                .store((latency_seconds * 1_000_000.0) as u64, Ordering::Relaxed);
        }
        fn record_host_authz(&self, outcome: HostAuthzOutcome) {
            match outcome {
                HostAuthzOutcome::Allow => &self.allow,
                HostAuthzOutcome::DenyNotInAllowlist => &self.deny_not_in_allowlist,
                HostAuthzOutcome::DenyGenericNoAllowlist => &self.deny_generic,
            }
            .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The only test in this crate that installs a sink, so it wins the
    /// `OnceLock` deterministically. Exercises both helper paths end-to-end.
    #[test]
    fn installed_sink_receives_forward_telemetry() {
        let sink = Arc::new(CountingSink::default());
        set_sink(Box::new(Arc::clone(&sink)));

        observe_request(0.010);
        record_host_authz(HostAuthzOutcome::Allow);
        record_host_authz(HostAuthzOutcome::DenyNotInAllowlist);
        record_host_authz(HostAuthzOutcome::DenyGenericNoAllowlist);

        assert_eq!(sink.observed_calls.load(Ordering::Relaxed), 1);
        assert!(sink.last_latency_micros.load(Ordering::Relaxed) >= 9_000);
        assert_eq!(sink.allow.load(Ordering::Relaxed), 1);
        assert_eq!(sink.deny_not_in_allowlist.load(Ordering::Relaxed), 1);
        assert_eq!(sink.deny_generic.load(Ordering::Relaxed), 1);
    }
}
