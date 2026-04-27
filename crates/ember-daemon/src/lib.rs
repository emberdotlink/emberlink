pub mod anomaly;
pub mod approval;
pub mod attenuation;
pub mod audit;
pub mod broker_handler;
pub mod config;
pub mod dashboard;
pub mod events;
pub mod grant;
pub mod handler;
pub mod image_registry;
pub mod notification;
pub mod notify;
pub mod outbound_leak;
pub mod persona;
pub mod pid;
pub mod policy;
pub mod presence;
pub mod pricing;
pub mod proxy;
pub mod rate_limit;
pub mod receipt;
pub mod runtime;
pub mod sandbox;
pub mod socket;
pub mod standing_grant;
pub mod store;
pub mod tailnet;
pub mod vault;

/// macOS-only Keychain shim that wraps the vault MEK passphrase with
/// `kSecAttrAccessControl` (user-presence / Touch ID / device passcode).
/// See security check. The `keyring` crate doesn't expose this attribute, so the
/// production-keychain read path on macOS routes through here directly.
#[cfg(target_os = "macos")]
pub mod vault_macos;
