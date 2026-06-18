//! OS-level presence invalidation transports.
//!
//! This module owns the platform-specific event sources that force the
//! daemon's interactive lane to hard-lock when the host OS crosses a
//! presence boundary such as screen lock or system sleep.

#[cfg(target_os = "linux")]
pub mod invalidation_linux;
#[cfg(target_os = "macos")]
pub mod invalidation_macos;
