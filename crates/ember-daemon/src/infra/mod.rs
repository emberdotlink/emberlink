pub mod anomaly;
pub(crate) mod attachment;
pub mod attested_device;
pub mod audit;
pub mod audit_explain;
pub mod binary_pin;
pub mod bridge_frame;
pub mod claim_journal;
pub mod codex_oauth;
pub mod config;
pub mod credential_store;
pub mod cursor_egress_proxy;
pub mod gemini_oauth;
pub mod daemon_wrap_key;
pub mod dashboard;
pub mod delegation_template;
// `endpoint_gate_framework` — ADR 215 slice 3 (per-session endpoint gate +
// admission policy enum). Pure decision logic; lane integrations call into it
// instead of running bespoke gates.
pub mod endpoint_gate;
pub mod events;
pub mod handler;
pub mod handlers;
pub(crate) mod headless_scope;
pub mod identity_substrate;
pub mod image_registry;
pub mod init_first_grant;
pub mod interactive_unlock;
pub mod kms;
pub mod kms_edge;
// `loopback_proxy` — ADR 215 §2: one per-session loopback-TCP credential-
// injection registry shared by the codex GPT-plan and gemini Code Assist OAuth
// lanes (each `Open` carries its own `&'static LoopbackProjector`).
pub mod loopback_proxy;
pub mod notification;
pub mod notify;
pub mod operator_identity;
pub mod persona;
pub mod pid;
pub mod pidfd;
pub mod presence_seal;
pub mod process_hardening;
pub mod prompt_intent;
pub mod proxy;
pub mod rate_limit;
pub mod receipt;
pub mod receipt_tree;
pub mod rpc_error;
pub mod rpc_listener;
pub mod runtime;
pub mod sandbox;
pub mod session_proxy;
pub mod socket;
pub mod status;
pub mod store;
pub mod tailnet;
// ADR212-TELEMETRY-EXPORTER — per-process Prometheus telemetry surface.
pub mod telemetry;
pub mod template_snapshot;
pub mod unlock_pin;
pub mod vault;
pub mod vault_rotate;

#[cfg(target_os = "macos")]
pub mod vault_macos;

#[cfg(target_os = "macos")]
pub mod vault_macos_se;
