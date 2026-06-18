//! CLASSIFICATION: PUBLIC
//! core-proxy-forward — HTTP CONNECT / forward-proxy primitives.
//!
//! Skeleton substrate landed in SCION-PROXY-CRATE-RENAME-A-SKELETON; the
//! actual forward-proxy logic migrates in a follow-up slice (SCION-PROXY-
//! CRATE-RENAME-C-MIGRATE, filed separately when needed).

pub mod policy_backend;
pub use policy_backend::{
    ChatgptPlanAuth, ColocatedBackend, GrantRecord, PolicyBackend, PolicyError, PreflightDecision,
    ProxyCallReceiptRequest, ProxyState, ResolvedAttachmentAuthority, ResolvedGrant,
    SessionGatewayAuthority,
};

pub mod event_sink;
pub use event_sink::{EventError, EventSink, GrantEvent, ThresholdAxis, ThresholdBand};

// `match` is a reserved word; the raw identifier `r#match` is the canonical
// module name. Callers spell it `core_proxy_forward::r#match::...`.
pub mod r#match;

// SSRF / metadata-IP destination classifier (ADR 205 §4) — pure, shared by the
// proxy's pre-flight literal check and its connect-time resolver guard.
pub mod ssrf;

// Outbound/inbound credential-leak (DLP) scanning primitives (ADR 205 §4) —
// pure, stateless pattern detection wired into the forward path.
pub mod outbound_leak;

// One canonical storage+parse encoding for grant `allowed_targets` (ADR 207
// SEAM-8B follow-up). Storage at the `create_grant` write site is a JSON
// array of host patterns; every reader (proxy forward gate, standing-grant
// matcher, dashboard UI) routes through the same parser here. A bare
// single-entry string (no leading `[`) is treated as one entry — required
// by the existing forward.rs unit tests and the raw-SQL test fixtures.
// Comma-separated multi-entry strings are NOT recognised: writing the
// canonical encoding is enforced at the write site, and the brief
// explicitly retires the legacy comma form (no production callers).
//
// anchor: allowed_targets_storage_and_parse_one_encoding
pub mod allowed_targets;
pub use allowed_targets::{parse_allowed_targets, validate_allowed_target_entry};
