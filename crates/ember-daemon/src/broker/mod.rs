pub mod anthropic_config;
pub mod aws_sts_config;
pub mod azure_config;
// implementation-note-87 — daemon-controlled credential-target
// allowlist. CRUD over `credential_bindings` is consumed by the
// admin verb (`ember bind …`) and (in a follow-up) by the broker's
// per-request authorization gate.
pub mod bindings;
// implementation-note-77 Phase 1 — Linux memfd-sealed
// credential surface that callers can swap for raw env-var injection.
// Non-Linux targets compile a stub that returns `NotImplemented`.
pub mod exec_env;
pub mod fly_config;
pub mod gcp_config;
pub mod github_config;
pub mod handler;
pub mod hashivault_config;
pub mod okta_config;
pub mod vercel_config;
pub mod gitconfig_reader;
pub mod tofu;
pub mod working_tree_id;
