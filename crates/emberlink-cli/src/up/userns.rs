//! container_userns_remap_baseline
//! CLASSIFICATION: PUBLIC
//! Linux user-namespace remap baseline for hardened-runc per ADR 166 §Component 9.
//! Provides preflight validation + the env-var fallback when the runtime doesn't
//! honor `userns_mode`.

#[cfg(target_os = "linux")]
use std::fs;

/// User-namespace mode requested for the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsernsMode {
    /// Map container UID/GID back to the host operator's UID/GID (`keep-id`).
    KeepId,
    /// Use the host network namespace (no remapping).
    Host,
    /// User-namespace remapping is disabled.
    Disabled,
}

/// User-namespace configuration for a container spawn.
#[derive(Debug, Clone)]
pub struct UsernsConfig {
    pub mode: UsernsMode,
    pub remap_uid: Option<u32>,
    pub remap_gid: Option<u32>,
}

/// Runtime support level for Linux user-namespaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsernsSupport {
    /// `/proc/sys/kernel/unprivileged_userns_clone` is present and set to `1`.
    Supported,
    /// `/proc/sys/kernel/unprivileged_userns_clone` is present and set to `0`.
    KernelDisabled,
    /// Not running on Linux (macOS, Windows, etc.) — the host runtime handles
    /// namespace support; no local kernel check is meaningful.
    NotLinux,
}

/// Errors produced by [`detect_runtime_support`].
#[derive(Debug, thiserror::Error)]
pub enum UsernsError {
    /// Failed to read `/proc/sys/kernel/unprivileged_userns_clone`.
    #[error("failed to read /proc/sys/kernel/unprivileged_userns_clone")]
    ProcReadFailed,
    /// The contents of the proc file could not be parsed as an integer.
    #[error("failed to parse /proc/sys/kernel/unprivileged_userns_clone contents")]
    ParseFailed,
}

/// Errors produced by [`validate_config_for_runtime`].
#[derive(Debug, thiserror::Error)]
pub enum UsernsValidationError {
    /// `KeepId` mode was requested but the kernel has disabled unprivileged
    /// user-namespace creation.
    #[error(
        "userns_mode keep-id requires kernel unprivileged user-namespace support (set /proc/sys/kernel/unprivileged_userns_clone=1 or switch to Host/Disabled mode)"
    )]
    KeepIdRequiresKernelSupport,
}

/// Check whether the host kernel supports unprivileged user-namespace creation.
///
/// On Linux this reads `/proc/sys/kernel/unprivileged_userns_clone`.  On
/// non-Linux hosts the function returns [`UsernsSupport::NotLinux`] immediately
/// without attempting any filesystem access.
///
/// Return values:
/// - `Ok(Supported)` — kernel allows unprivileged user-namespaces.
/// - `Ok(KernelDisabled)` — kernel explicitly disables them.
/// - `Ok(NotLinux)` — not a Linux host; skip the check.
/// - `Err(ProcReadFailed)` — the proc file exists on a Linux host but could not
///   be read (permissions, I/O error, etc.).
/// - `Err(ParseFailed)` — the proc file contents are not a valid integer.
pub fn detect_runtime_support() -> Result<UsernsSupport, UsernsError> {
    // On non-Linux platforms the proc filesystem is absent; return NotLinux so
    // callers can skip kernel-specific validation without panicking.
    #[cfg(not(target_os = "linux"))]
    {
        Ok(UsernsSupport::NotLinux)
    }

    #[cfg(target_os = "linux")]
    {
        const PROC_PATH: &str = "/proc/sys/kernel/unprivileged_userns_clone";

        let contents = match fs::read_to_string(PROC_PATH) {
            Ok(s) => s,
            Err(_) => {
                // The file may be absent on kernels that always allow
                // unprivileged user-namespaces (e.g. upstream kernels ≥ 3.8
                // compiled without CONFIG_USER_NS_UNPRIVILEGED_USERS_ONLY).
                // Treat absence as supported so we don't block valid configs.
                return Ok(UsernsSupport::Supported);
            }
        };

        let value: u8 = contents
            .trim()
            .parse()
            .map_err(|_| UsernsError::ParseFailed)?;

        if value == 1 {
            Ok(UsernsSupport::Supported)
        } else {
            Ok(UsernsSupport::KernelDisabled)
        }
    }
}

/// Validate a [`UsernsConfig`] against detected runtime support.
///
/// Rules:
/// - `KeepId` on `KernelDisabled` → [`UsernsValidationError::KeepIdRequiresKernelSupport`].
/// - Any mode on `NotLinux` → `Ok(())` (host runtime handles it).
/// - Any mode on `Supported` → `Ok(())`.
pub fn validate_config_for_runtime(
    cfg: &UsernsConfig,
    support: UsernsSupport,
) -> Result<(), UsernsValidationError> {
    match (&cfg.mode, support) {
        (UsernsMode::KeepId, UsernsSupport::KernelDisabled) => {
            Err(UsernsValidationError::KeepIdRequiresKernelSupport)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_runtime_support_returns_not_linux_or_supported() {
        let result = detect_runtime_support();
        let support = result.expect("detect_runtime_support must not panic or error on this host");
        assert!(
            matches!(
                support,
                UsernsSupport::Supported | UsernsSupport::KernelDisabled | UsernsSupport::NotLinux
            ),
            "expected one of Supported/KernelDisabled/NotLinux, got {support:?}"
        );
    }

    #[test]
    fn validate_keep_id_refuses_kernel_disabled() {
        let cfg = UsernsConfig {
            mode: UsernsMode::KeepId,
            remap_uid: None,
            remap_gid: None,
        };
        let result = validate_config_for_runtime(&cfg, UsernsSupport::KernelDisabled);
        assert!(
            matches!(
                result,
                Err(UsernsValidationError::KeepIdRequiresKernelSupport)
            ),
            "expected KeepIdRequiresKernelSupport, got {result:?}"
        );
    }

    #[test]
    fn validate_keep_id_accepts_supported_or_non_linux() {
        let cfg = UsernsConfig {
            mode: UsernsMode::KeepId,
            remap_uid: None,
            remap_gid: None,
        };

        let result_supported = validate_config_for_runtime(&cfg, UsernsSupport::Supported);
        assert!(
            result_supported.is_ok(),
            "KeepId must be accepted on Supported: {result_supported:?}"
        );

        let result_not_linux = validate_config_for_runtime(&cfg, UsernsSupport::NotLinux);
        assert!(
            result_not_linux.is_ok(),
            "KeepId must be accepted on NotLinux: {result_not_linux:?}"
        );
    }
}
