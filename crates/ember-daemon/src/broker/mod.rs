pub mod anthropic_config;
pub mod authority;
pub mod aws_sts_config;
pub mod azure_config;
// META-ARCH-DCC-1-BINDINGS-STORE — daemon-controlled credential-target
// allowlist. CRUD over `credential_bindings` is consumed by the
// admin verb (`ember bind …`) and (in a follow-up) by the broker's
// per-request authorization gate.
pub mod bindings;
// META-BROKER-EXEC-ENV-LEAK-VIA-PROC Phase 1 — Linux memfd-sealed
// credential surface that callers can swap for raw env-var injection.
// Non-Linux targets compile a stub that returns `NotImplemented`.
pub mod exec_env;
pub mod fly_config;
pub mod gcp_config;
pub mod github_config;
pub mod handler;
pub mod hashivault_config;
// META-DEV-PROD-PARITY-MOCK-BROKER-EXPLICIT (ADR 157 §Component 2) —
// parser for `EMBER_ALLOW_MOCK_BROKERS`. MockBroker registration is now
// an explicit opt-in: missing creds fail-loud unless the operator named
// the provider in this env. Anchor: `dev_prod_parity_mock_broker_explicit_landed`.
pub mod mock_allowlist;
pub mod okta_config;
pub mod runners;
// META-BROKER-EXEC-PER-SPAWN-UID — per-spawn ephemeral uid pool that
// fork+execve drops into before running the child. Closes Finding 14
// (refuse spawning child as daemon uid) and the cross-spawn
// `/proc/<pid>/environ` side-channel. See uid_alloc.rs for the pool;
// see ADR 167 for the allocation-strategy rationale (amendment to
// ADR 131).
pub mod uid_alloc;
// ADR 155 Components 2 + 3 + MACOS-PRIMITIVES Decision 5 — daemon-side
// client for the privileged spawn-helper sibling daemon. Used by
// `handler::handle_broker_exec` on macOS (always) and hardened Linux
// (sysctl-detected) to route the setuid + chroot + sandbox/seccomp
// chain through the helper's UDS rather than executing it in-process.
pub mod gitconfig_reader;
pub mod spawn_helper_client;
pub mod tofu;
pub mod vercel_config;
pub mod working_tree_id;
