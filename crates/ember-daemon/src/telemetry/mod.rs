//! CLASSIFICATION: PUBLIC
//!
//! Daemon-side **empirical-sample telemetry** for the v0.3.0 friendly-drop
//! window. It collects workload-distribution, JIT-latency, and
//! audit-write-throughput data before retuning any cohort defaults in v0.3.1.
//!
//! This module is **distinct from `infra::telemetry`** (the ADR 212 Prometheus
//! exposition surface). `infra::telemetry` is a steady-state operator surface;
//! `telemetry::measurement` is a time-bounded data-collection module whose
//! output feeds the v0.3.1 retune decisions, then sunsets.
//!
//! See [`measurement`] for the recording API.

pub mod measurement;
