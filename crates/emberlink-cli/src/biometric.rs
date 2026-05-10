//! implementation-note-81 — biometric (Touch ID / device passcode) gate for high-risk
//! CLI operations like `ember approval approve <id>`.
//!
//! ## Goal
//!
//! When a human operator approves an outstanding agent approval request from
//! the terminal, we want the OS-native biometric prompt to fire. The platform
//! bind is the visible trust signal: a non-biometric "press a button" beat
//! looks identical to clicking through a dialog; a Touch ID prompt is the
//! demo-grade evidence that real human presence is being attested.
//!
//! ## Implementation
//!
//! On macOS we link against `LocalAuthentication.framework` directly via a
//! tiny FFI block, using the Objective-C runtime (`objc_msgSend`) to call
//! `+[LAContext alloc]` / `-[LAContext canEvaluatePolicy:error:]` /
//! `-[LAContext evaluatePolicy:localizedReason:error:]` synchronously.
//!
//! Following Apple Silicon ABI, every distinct `objc_msgSend` signature is
//! declared as a SEPARATE `extern "C"` symbol via `#[link_name = "objc_msgSend"]`
//! rather than transmuting a single variadic shim — the variadic+typed
//! transmute approach miscompiles on aarch64-apple-darwin in release builds.
//!
//! ## Test gates
//!
//! Three independent axes can short-circuit the prompt:
//!
//! - `--no-biometric` flag on the CLI command itself
//! - `EMBER_DISABLE_BIO=1` environment variable
//! - `cfg!(test)` or `is_cargo_test_binary()` (cargo-built test binaries
//!   detected via `current_exe`) — mirrors the security check vault gate so
//!   `cargo test` never fires a real LocalAuthentication prompt
//!
//! Any one of these returning true makes [`require_biometric`] short-circuit
//! to `Ok(BiometricOutcome::Skipped)` — the caller treats this as an approved
//! biometric for audit purposes (`biometric=false`, `credential_id=None`).
//!
//! ## Non-darwin platforms
//!
//! On Linux / Windows the entire FFI block is feature-gated out and
//! [`require_biometric`] returns `Ok(BiometricOutcome::Skipped)` unconditionally.
//! Distro-specific biometric integrations (fprintd / Windows Hello) are
//! out-of-scope for the May 3 demo.

/// Outcome of a biometric check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BiometricOutcome {
    /// The user successfully authenticated. `credential_id` carries an
    /// opaque, OS-supplied label identifying the credential that verified
    /// (e.g. Touch ID enrollment label) — surfaced into the audit log.
    Verified { credential_id: Option<String> },
    /// Skipped because of a test gate, the `--no-biometric` flag,
    /// `EMBER_DISABLE_BIO=1`, or non-darwin platform. Caller treats as
    /// approved for refusal-control purposes (i.e. does NOT block) but
    /// audits as `biometric=false`.
    Skipped,
}

#[derive(Debug, thiserror::Error)]
pub enum BiometricError {
    /// User cancelled the prompt or biometric verification declined.
    #[error("biometric refused: {0}")]
    Refused(String),
    /// LocalAuthentication framework reported an internal error
    /// (no enrolled biometrics, hardware fault, etc).
    #[error("biometric unavailable: {0}")]
    Unavailable(String),
}

/// True when the cargo test harness is the active process. Same heuristic
/// as `ember-daemon::vault::is_cargo_test_binary`.
fn is_cargo_test_binary() -> bool {
    match std::env::current_exe() {
        Ok(p) => {
            let s = p.to_string_lossy();
            s.contains("/target/") && s.contains("/deps/")
        }
        Err(_) => false,
    }
}

/// Whether the current invocation should bypass the biometric prompt.
fn bypass_active(no_biometric_flag: bool) -> bool {
    no_biometric_flag
        || std::env::var("EMBER_DISABLE_BIO").is_ok()
        || cfg!(test)
        || is_cargo_test_binary()
}

/// Require the operator to authenticate via the platform biometric (Touch ID
/// or device passcode on macOS). Returns `Ok(Verified)` on success, `Err`
/// when the user actively refuses, and `Ok(Skipped)` when any test gate or
/// the `--no-biometric` flag is active.
///
/// `reason` is shown in the OS-native prompt (e.g. "Approve grant request
/// for Stripe API key"). Keep it short, factual, and free of jargon.
pub fn require_biometric(
    reason: &str,
    no_biometric_flag: bool,
) -> Result<BiometricOutcome, BiometricError> {
    if bypass_active(no_biometric_flag) {
        return Ok(BiometricOutcome::Skipped);
    }
    require_biometric_platform(reason)
}

#[cfg(target_os = "macos")]
fn require_biometric_platform(reason: &str) -> Result<BiometricOutcome, BiometricError> {
    macos::evaluate_policy(reason)
}

#[cfg(not(target_os = "macos"))]
fn require_biometric_platform(_reason: &str) -> Result<BiometricOutcome, BiometricError> {
    // No supported platform binding on Linux/Windows for the May 3 demo —
    // skip silently. Audit log records biometric=false.
    Ok(BiometricOutcome::Skipped)
}

#[cfg(target_os = "macos")]
#[allow(clashing_extern_declarations)]
mod macos {
    //! macOS-only LocalAuthentication.framework binding.
    //!
    //! Constants per Apple's `LAContext.h`:
    //!   `LAPolicyDeviceOwnerAuthentication = 2` (Touch ID OR passcode fallback)
    //!
    //! Policy 2 (and not 1 = biometric-only) is intentional: dev machines
    //! without enrolled Touch ID — e.g. Apple Silicon laptop wired through
    //! an external display — still authenticate via the device passcode
    //! fallback, keeping the gate intact for demo recordings.

    use std::ffi::{CStr, CString, c_void};
    use std::os::raw::{c_char, c_long, c_uchar};

    use super::{BiometricError, BiometricOutcome};

    type Id = *mut c_void;
    type Sel = *const c_void;

    #[link(name = "LocalAuthentication", kind = "framework")]
    unsafe extern "C" {}

    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {}

    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Sel;
    }

    // Distinct typed `objc_msgSend` symbols. Apple Silicon's variadic ABI
    // miscompiles a single transmuted dispatcher; the workaround is to
    // declare each call shape as its own extern symbol with
    // `#[link_name = "objc_msgSend"]` in a SEPARATE `extern "C"` block so
    // the compiler doesn't warn about signature redeclaration.
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn msg_send_id(receiver: Id, sel: Sel) -> Id;
    }
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn msg_send_id_id(receiver: Id, sel: Sel, arg0: Id) -> Id;
    }
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn msg_send_id_cstr(receiver: Id, sel: Sel, arg0: *const c_char) -> Id;
    }
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn msg_send_void(receiver: Id, sel: Sel);
    }
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn msg_send_bool_long_outerr(
            receiver: Id,
            sel: Sel,
            policy: c_long,
            err_out: *mut Id,
        ) -> c_uchar;
    }
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn msg_send_bool_long_id_outerr(
            receiver: Id,
            sel: Sel,
            policy: c_long,
            reason: Id,
            err_out: *mut Id,
        ) -> c_uchar;
    }
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn msg_send_cstr(receiver: Id, sel: Sel) -> *const c_char;
    }

    const LA_POLICY_DEVICE_OWNER_AUTHENTICATION: c_long = 2;

    /// Synchronous wrapper for `-[LAContext evaluatePolicy:localizedReason:error:]`.
    ///
    /// Returns `Ok(Verified)` on success, `Err(Refused)` on user-decline,
    /// and `Err(Unavailable)` if the framework cannot evaluate (no
    /// enrollment, etc).
    pub fn evaluate_policy(reason: &str) -> Result<BiometricOutcome, BiometricError> {
        unsafe {
            let context = create_la_context();
            if context.is_null() {
                return Err(BiometricError::Unavailable(
                    "LAContext alloc returned nil".into(),
                ));
            }

            // Pre-flight: canEvaluatePolicy:error:. If the device has no
            // biometric enrollment AND no passcode, the policy is genuinely
            // unavailable and we should error rather than block.
            let can_eval = can_evaluate_policy(context, LA_POLICY_DEVICE_OWNER_AUTHENTICATION);
            if !can_eval {
                release_object(context);
                return Err(BiometricError::Unavailable(
                    "LocalAuthentication policy not available on this device \
                     (no Touch ID enrollment and no device passcode set)"
                        .into(),
                ));
            }

            let outcome = run_evaluate_policy(
                context,
                LA_POLICY_DEVICE_OWNER_AUTHENTICATION,
                reason,
            );
            release_object(context);

            match outcome {
                EvalResult::Success => Ok(BiometricOutcome::Verified {
                    credential_id: Some("LocalAuthentication:device-owner".into()),
                }),
                EvalResult::Refused(msg) => Err(BiometricError::Refused(msg)),
            }
        }
    }

    enum EvalResult {
        Success,
        Refused(String),
    }

    unsafe fn create_la_context() -> Id {
        unsafe {
            let cls_name = CString::new("LAContext").unwrap();
            let cls = objc_getClass(cls_name.as_ptr());
            if cls.is_null() {
                return std::ptr::null_mut();
            }
            let alloc_sel = sel_registerName(CString::new("alloc").unwrap().as_ptr());
            let init_sel = sel_registerName(CString::new("init").unwrap().as_ptr());
            let allocated = msg_send_id(cls, alloc_sel);
            if allocated.is_null() {
                return std::ptr::null_mut();
            }
            msg_send_id(allocated, init_sel)
        }
    }

    unsafe fn release_object(obj: Id) {
        if obj.is_null() {
            return;
        }
        unsafe {
            let release_sel = sel_registerName(CString::new("release").unwrap().as_ptr());
            msg_send_void(obj, release_sel);
        }
    }

    unsafe fn can_evaluate_policy(ctx: Id, policy: c_long) -> bool {
        unsafe {
            let sel = sel_registerName(
                CString::new("canEvaluatePolicy:error:").unwrap().as_ptr(),
            );
            let mut err: Id = std::ptr::null_mut();
            msg_send_bool_long_outerr(ctx, sel, policy, &mut err) != 0
        }
    }

    /// Invoke `-[LAContext evaluatePolicy:localizedReason:error:]` —
    /// the *synchronous* variant. This blocks the current thread, raises
    /// the system biometric sheet, and returns a BOOL after the user
    /// taps the sensor or cancels.
    ///
    /// Note: this selector is technically deprecated since macOS 11 in
    /// favour of the async `:reply:` block-based variant, but the synchronous
    /// shape is retained for backwards compat and simplifies our pure-Rust
    /// FFI (no ObjC block synthesis required).
    unsafe fn run_evaluate_policy(ctx: Id, policy: c_long, reason: &str) -> EvalResult {
        unsafe {
            let reason_ns = nsstring_from_str(reason);
            let sel = sel_registerName(
                CString::new("evaluatePolicy:localizedReason:error:")
                    .unwrap()
                    .as_ptr(),
            );
            let mut err: Id = std::ptr::null_mut();
            let ok = msg_send_bool_long_id_outerr(ctx, sel, policy, reason_ns, &mut err) != 0;
            release_object(reason_ns);

            if ok {
                EvalResult::Success
            } else {
                let desc = if err.is_null() {
                    "biometric verification declined".to_string()
                } else {
                    let desc_sel = sel_registerName(
                        CString::new("localizedDescription").unwrap().as_ptr(),
                    );
                    let ns_desc = msg_send_id(err, desc_sel);
                    nsstring_to_string(ns_desc)
                        .unwrap_or_else(|| "biometric verification declined".to_string())
                };
                EvalResult::Refused(desc)
            }
        }
    }

    unsafe fn nsstring_from_str(s: &str) -> Id {
        unsafe {
            let cls_name = CString::new("NSString").unwrap();
            let cls = objc_getClass(cls_name.as_ptr());
            if cls.is_null() {
                return std::ptr::null_mut();
            }
            let sel = sel_registerName(
                CString::new("stringWithUTF8String:").unwrap().as_ptr(),
            );
            let cstr = CString::new(s).unwrap_or_else(|_| CString::new("").unwrap());
            msg_send_id_cstr(cls, sel, cstr.as_ptr())
        }
    }

    unsafe fn nsstring_to_string(s: Id) -> Option<String> {
        unsafe {
            if s.is_null() {
                return None;
            }
            let sel = sel_registerName(CString::new("UTF8String").unwrap().as_ptr());
            let raw = msg_send_cstr(s, sel);
            if raw.is_null() {
                return None;
            }
            Some(CStr::from_ptr(raw).to_string_lossy().into_owned())
        }
    }

    // Suppress unused warnings for the msg_send_id_id symbol — declared for
    // future caller shapes that take a single Id arg.
    #[allow(dead_code)]
    fn _force_link() {
        let _ = msg_send_id_id;
    }

    #[cfg(test)]
    mod tests {
        use super::super::*;

        #[test]
        fn cargo_test_short_circuits() {
            // Under cargo test, is_cargo_test_binary() returns true and
            // bypass_active() returns true regardless of flag. This must
            // never block on a real biometric prompt.
            let outcome = require_biometric("test-reason", false).unwrap();
            assert_eq!(outcome, BiometricOutcome::Skipped);
        }

        #[test]
        fn no_biometric_flag_short_circuits() {
            let outcome = require_biometric("test-reason", true).unwrap();
            assert_eq!(outcome, BiometricOutcome::Skipped);
        }
    }
}

#[cfg(not(target_os = "macos"))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_darwin_short_circuits() {
        let outcome = require_biometric("test-reason", false).unwrap();
        assert_eq!(outcome, BiometricOutcome::Skipped);
    }
}
