//! Founder console-login monitoring for the authority daemon.
//!
//! A console login is intentionally different from an unlocked screen. macOS keeps the
//! console user installed while the display is locked or asleep, so those states preserve
//! an active founder login. Logout hands the console to `loginwindow` (or removes the console
//! user), which makes the founder inactive.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConsoleSessionActivity {
    FounderActive,
    Inactive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConsoleSessionError {
    /// This target has no implementation backed by an authoritative OS session source.
    #[cfg(not(target_os = "macos"))]
    UnsupportedPlatform,
    /// The system session source could not produce an observation.
    #[cfg(target_os = "macos")]
    SourceUnavailable,
    /// The system source returned an identity that is not safe to classify.
    MalformedIdentity,
    /// The console identity changed between samples, so no single identity was established.
    IdentityChanged,
}

/// Checks whether the configured founder owns the active macOS console login.
///
/// Callers must treat every error as inactive. In particular, this interface does not infer
/// login state from processes, screen-lock state, or GUI authentication.
pub(crate) struct ConsoleSessionMonitor {
    founder_uid: u32,
}

impl ConsoleSessionMonitor {
    pub(crate) const fn new(founder_uid: u32) -> Self {
        Self { founder_uid }
    }

    pub(crate) fn check(&self) -> Result<ConsoleSessionActivity, ConsoleSessionError> {
        let observations = [
            platform::copy_console_identity()?,
            platform::copy_console_identity()?,
        ];
        classify_observations(self.founder_uid, &observations)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConsoleIdentity {
    None,
    User { uid: u32, name: String },
}
fn classify_observations(
    founder_uid: u32,
    observations: &[ConsoleIdentity],
) -> Result<ConsoleSessionActivity, ConsoleSessionError> {
    let [first, second] = observations else {
        return Err(ConsoleSessionError::IdentityChanged);
    };
    if first != second {
        return Err(ConsoleSessionError::IdentityChanged);
    }
    classify(founder_uid, first)
}

fn classify(
    founder_uid: u32,
    identity: &ConsoleIdentity,
) -> Result<ConsoleSessionActivity, ConsoleSessionError> {
    let ConsoleIdentity::User { uid, name } = identity else {
        return Ok(ConsoleSessionActivity::Inactive);
    };

    if name.is_empty()
        || name.trim() != name
        || name.chars().any(char::is_control)
        || name.contains('/')
        || name.contains(':')
    {
        return Err(ConsoleSessionError::MalformedIdentity);
    }

    // These system-owned pseudo-users represent setup/login UI, not a logged-in founder.
    if matches!(name.as_str(), "loginwindow" | "_mbsetupuser") {
        return Ok(ConsoleSessionActivity::Inactive);
    }

    Ok(if *uid == founder_uid {
        ConsoleSessionActivity::FounderActive
    } else {
        ConsoleSessionActivity::Inactive
    })
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{ConsoleIdentity, ConsoleSessionError};
    use core_foundation::base::TCFType;
    use core_foundation::string::{CFString, CFStringRef};
    use std::ffi::c_void;
    use std::ptr;

    #[link(name = "SystemConfiguration", kind = "framework")]
    unsafe extern "C" {
        fn SCDynamicStoreCopyConsoleUser(
            store: *const c_void,
            uid: *mut libc::uid_t,
            gid: *mut libc::gid_t,
        ) -> CFStringRef;
    }

    pub(super) fn copy_console_identity() -> Result<ConsoleIdentity, ConsoleSessionError> {
        let mut uid = libc::uid_t::MAX;
        let mut gid = libc::gid_t::MAX;

        // SAFETY: SystemConfiguration documents a null store as selecting the default dynamic
        // store. Both output pointers refer to initialized, correctly typed local values. A
        // non-null result follows Core Foundation's Create Rule and is immediately placed in a
        // retaining Rust wrapper so it is released exactly once.
        let raw_name = unsafe { SCDynamicStoreCopyConsoleUser(ptr::null(), &mut uid, &mut gid) };
        if raw_name.is_null() {
            return Ok(ConsoleIdentity::None);
        }

        // SAFETY: `SCDynamicStoreCopyConsoleUser` returns an owned CFString on success.
        let name = unsafe { CFString::wrap_under_create_rule(raw_name) }.to_string();
        if uid == libc::uid_t::MAX || gid == libc::gid_t::MAX {
            return Err(ConsoleSessionError::SourceUnavailable);
        }

        Ok(ConsoleIdentity::User { uid, name })
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::{ConsoleIdentity, ConsoleSessionError};

    pub(super) fn copy_console_identity() -> Result<ConsoleIdentity, ConsoleSessionError> {
        Err(ConsoleSessionError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOUNDER_UID: u32 = 501;

    fn user(uid: u32, name: &str) -> ConsoleIdentity {
        ConsoleIdentity::User {
            uid,
            name: name.to_owned(),
        }
    }

    #[test]
    fn founder_console_user_is_active() {
        assert_eq!(
            classify(FOUNDER_UID, &user(FOUNDER_UID, "founder")),
            Ok(ConsoleSessionActivity::FounderActive)
        );
    }

    #[test]
    fn different_console_user_is_inactive() {
        assert_eq!(
            classify(FOUNDER_UID, &user(502, "someone-else")),
            Ok(ConsoleSessionActivity::Inactive)
        );
    }

    #[test]
    fn loginwindow_is_inactive_even_if_uid_matches() {
        assert_eq!(
            classify(FOUNDER_UID, &user(FOUNDER_UID, "loginwindow")),
            Ok(ConsoleSessionActivity::Inactive)
        );
    }

    #[test]
    fn no_console_user_is_inactive() {
        assert_eq!(
            classify(FOUNDER_UID, &ConsoleIdentity::None),
            Ok(ConsoleSessionActivity::Inactive)
        );
    }

    #[test]
    fn screen_lock_preserves_founder_activity_when_console_identity_is_preserved() {
        let identity_reported_before_lock = user(FOUNDER_UID, "founder");
        let identity_reported_during_lock = identity_reported_before_lock.clone();

        assert_eq!(
            classify(FOUNDER_UID, &identity_reported_during_lock),
            Ok(ConsoleSessionActivity::FounderActive)
        );
    }

    #[test]
    fn malformed_identity_fails_closed() {
        assert_eq!(
            classify(FOUNDER_UID, &user(FOUNDER_UID, "founder\0loginwindow")),
            Err(ConsoleSessionError::MalformedIdentity)
        );
    }

    #[test]
    fn changing_or_multiple_identity_fails_closed() {
        let observations = [user(FOUNDER_UID, "founder"), user(502, "someone-else")];

        assert_eq!(
            classify_observations(FOUNDER_UID, &observations),
            Err(ConsoleSessionError::IdentityChanged)
        );
    }
}
