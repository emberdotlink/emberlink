//! Biometric (Touch ID / device passcode) gate for high-risk operations —
//! `ember approval approve <id>` from the CLI, and the autopilot engine's
//! session-runtime presence acquisition from `internal-automation`.
//!
//! Originally `DEMO-MAY3-BIO` inside `emberlink-cli`; moved here so the
//! LocalAuthentication FFI lives in one audited place shared by both callers.
//!
//! CLASSIFICATION: PUBLIC
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
//! The managed-daemon unlock lane uses the same substrate with two explicit
//! policies:
//!
//! - `Recoverable` -> `deviceOwnerAuthentication` (Touch ID or passcode)
//! - `StrictBiometric` -> `deviceOwnerAuthenticationWithBiometrics`
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
//!   detected via `current_exe`) — mirrors the vault user-presence gate so
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

use core_crypto::presence::PresencePromptPolicy;

/// Outcome of a biometric check.
///
/// On macOS the `Verified` variant is constructed by the macOS-only
/// `mod macos` block; on Linux/Windows the platform-bind shim short-
/// circuits to `Skipped`. Suppress the dead-code lint on non-macOS so
/// the cross-platform API contract doesn't emit spurious warnings on
/// the Linux build (which is the autopilot host).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

/// Errors a biometric check can surface.
///
/// Both variants are returned only from the macOS LocalAuthentication
/// path; on non-macOS the bind is `Skipped` (no error path). Same
/// `cfg_attr(allow(dead_code))` rationale as `BiometricOutcome`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
    require_biometric_with_policy(
        reason,
        no_biometric_flag,
        &PresencePromptPolicy::Recoverable,
    )
}

/// Same as [`require_biometric`], but lets callers choose whether
/// LocalAuthentication may fall back to the device passcode (`Recoverable`)
/// or must stay biometric-only (`StrictBiometric`).
pub fn require_biometric_with_policy(
    reason: &str,
    no_biometric_flag: bool,
    prompt_policy: &PresencePromptPolicy,
) -> Result<BiometricOutcome, BiometricError> {
    if bypass_active(no_biometric_flag) {
        return Ok(BiometricOutcome::Skipped);
    }
    require_biometric_platform(reason, prompt_policy)
}

#[cfg(target_os = "macos")]
fn require_biometric_platform(
    reason: &str,
    prompt_policy: &PresencePromptPolicy,
) -> Result<BiometricOutcome, BiometricError> {
    macos::evaluate_policy(reason, prompt_policy)
}

#[cfg(not(target_os = "macos"))]
fn require_biometric_platform(
    _reason: &str,
    _prompt_policy: &PresencePromptPolicy,
) -> Result<BiometricOutcome, BiometricError> {
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
    //!   `LAPolicyDeviceOwnerAuthenticationWithBiometrics = 1`
    //!   `LAPolicyDeviceOwnerAuthentication = 2` (Touch ID OR passcode fallback)
    //!
    //! Policy 2 is the default managed unlock lane because it preserves the
    //! recoverable Apple-native fallback. Policy 1 remains available for the
    //! explicit strict-biometric opt-in lane.

    use std::ffi::{CStr, CString, c_void};
    use std::os::raw::{c_char, c_long, c_uchar};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use super::{BiometricError, BiometricOutcome, PresencePromptPolicy};
    use block2::{Block, RcBlock};

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
        fn msg_send_void_long_id_block(
            receiver: Id,
            sel: Sel,
            policy: c_long,
            reason: Id,
            reply: &Block<dyn Fn(c_uchar, Id)>,
        );
    }
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn msg_send_cstr(receiver: Id, sel: Sel) -> *const c_char;
    }

    const LA_POLICY_DEVICE_OWNER_AUTHENTICATION_WITH_BIOMETRICS: c_long = 1;
    const LA_POLICY_DEVICE_OWNER_AUTHENTICATION: c_long = 2;
    const LOCAL_AUTH_REPLY_TIMEOUT_SECS: u64 = 30;
    const LOCAL_AUTH_INVALIDATE_GRACE_MILLIS: u64 = 750;

    fn local_auth_policy(prompt_policy: &PresencePromptPolicy) -> c_long {
        match prompt_policy {
            PresencePromptPolicy::Recoverable => LA_POLICY_DEVICE_OWNER_AUTHENTICATION,
            PresencePromptPolicy::StrictBiometric => {
                LA_POLICY_DEVICE_OWNER_AUTHENTICATION_WITH_BIOMETRICS
            }
        }
    }

    fn credential_id_for_policy(prompt_policy: &PresencePromptPolicy) -> String {
        match prompt_policy {
            PresencePromptPolicy::Recoverable => "LocalAuthentication:device-owner".into(),
            PresencePromptPolicy::StrictBiometric => "LocalAuthentication:biometric-only".into(),
        }
    }

    fn unavailable_message_for_policy(prompt_policy: &PresencePromptPolicy) -> &'static str {
        match prompt_policy {
            PresencePromptPolicy::Recoverable => {
                "LocalAuthentication policy not available on this device \
                 (no Touch ID enrollment and no device passcode set)"
            }
            PresencePromptPolicy::StrictBiometric => {
                "LocalAuthentication biometric-only policy not available on this device \
                 (no enrolled biometrics or biometrics are unavailable)"
            }
        }
    }

    fn local_auth_reply_timeout() -> Duration {
        Duration::from_secs(LOCAL_AUTH_REPLY_TIMEOUT_SECS)
    }

    fn local_auth_invalidate_grace() -> Duration {
        Duration::from_millis(LOCAL_AUTH_INVALIDATE_GRACE_MILLIS)
    }

    fn local_auth_timeout_message(timeout: Duration) -> String {
        format!(
            "LocalAuthentication prompt timed out after {}s waiting for an OS reply",
            timeout.as_secs()
        )
    }

    /// Synchronous wrapper for `-[LAContext evaluatePolicy:localizedReason:error:]`.
    ///
    /// Returns `Ok(Verified)` on success, `Err(Refused)` on user-decline,
    /// and `Err(Unavailable)` if the framework cannot evaluate (no
    /// enrollment, etc).
    pub fn evaluate_policy(
        reason: &str,
        prompt_policy: &PresencePromptPolicy,
    ) -> Result<BiometricOutcome, BiometricError> {
        unsafe {
            let context = create_la_context();
            if context.is_null() {
                return Err(BiometricError::Unavailable(
                    "LAContext alloc returned nil".into(),
                ));
            }
            let local_auth_policy = local_auth_policy(prompt_policy);

            // Pre-flight: canEvaluatePolicy:error:. If the device has no
            // biometric enrollment AND no passcode, the policy is genuinely
            // unavailable and we should error rather than block.
            let can_eval = can_evaluate_policy(context, local_auth_policy);
            if !can_eval {
                release_object(context);
                return Err(BiometricError::Unavailable(
                    unavailable_message_for_policy(prompt_policy).into(),
                ));
            }

            let outcome = run_evaluate_policy(context, local_auth_policy, reason);
            release_object(context);

            match outcome {
                EvalResult::Success => Ok(BiometricOutcome::Verified {
                    credential_id: Some(credential_id_for_policy(prompt_policy)),
                }),
                EvalResult::Refused(msg) => Err(BiometricError::Refused(msg)),
                EvalResult::Unavailable(msg) => Err(BiometricError::Unavailable(msg)),
            }
        }
    }

    #[derive(Debug)]
    enum EvalResult {
        Success,
        Refused(String),
        Unavailable(String),
    }

    #[derive(Debug)]
    struct EvalWaitState {
        outcome: Option<EvalResult>,
        timed_out: bool,
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
            let sel = sel_registerName(CString::new("canEvaluatePolicy:error:").unwrap().as_ptr());
            let mut err: Id = std::ptr::null_mut();
            msg_send_bool_long_outerr(ctx, sel, policy, &mut err) != 0
        }
    }

    unsafe fn invalidate_context(ctx: Id) {
        if ctx.is_null() {
            return;
        }
        unsafe {
            let sel = sel_registerName(CString::new("invalidate").unwrap().as_ptr());
            msg_send_void(ctx, sel);
        }
    }

    fn eval_outcome_from_reply(
        ok: bool,
        err_desc: Option<String>,
        timed_out: bool,
        timeout_message: &str,
    ) -> EvalResult {
        if ok {
            EvalResult::Success
        } else if timed_out {
            EvalResult::Unavailable(timeout_message.to_string())
        } else {
            EvalResult::Refused(
                err_desc.unwrap_or_else(|| "biometric verification declined".to_string()),
            )
        }
    }

    fn wait_for_eval_outcome(
        shared: &Arc<(Mutex<EvalWaitState>, Condvar)>,
        timeout: Duration,
    ) -> Option<EvalResult> {
        let (lock, cv) = &**shared;
        let deadline = Instant::now() + timeout;
        let mut guard = lock.lock().expect("lock biometric waiter state");
        loop {
            if let Some(outcome) = guard.outcome.take() {
                return Some(outcome);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_guard, wait_result) = cv
                .wait_timeout(guard, remaining)
                .expect("wait for biometric callback");
            guard = next_guard;
            if wait_result.timed_out() && guard.outcome.is_none() {
                return None;
            }
        }
    }

    /// Invoke `-[LAContext evaluatePolicy:localizedReason:reply:]` and block
    /// the current thread until the reply callback arrives.
    ///
    /// The previously attempted `...error:` selector is not a documented
    /// LocalAuthentication API, and on live operator hosts it raised an
    /// Objective-C exception that Rust aborted on as a foreign unwind.
    unsafe fn run_evaluate_policy(ctx: Id, policy: c_long, reason: &str) -> EvalResult {
        unsafe {
            let reason_ns = nsstring_from_str(reason);
            let timeout = local_auth_reply_timeout();
            let timeout_message = local_auth_timeout_message(timeout);
            let shared = Arc::new((
                Mutex::new(EvalWaitState {
                    outcome: None,
                    timed_out: false,
                }),
                Condvar::new(),
            ));
            let shared_for_block = Arc::clone(&shared);
            let timeout_message_for_block = timeout_message.clone();
            let reply_block = RcBlock::new(move |ok: c_uchar, err: Id| {
                let (lock, cv) = &*shared_for_block;
                let mut state = lock.lock().expect("lock biometric callback state");
                let desc = if err.is_null() {
                    None
                } else {
                    let desc_sel =
                        sel_registerName(CString::new("localizedDescription").unwrap().as_ptr());
                    let ns_desc = msg_send_id(err, desc_sel);
                    nsstring_to_string(ns_desc)
                };
                state.outcome = Some(eval_outcome_from_reply(
                    ok != 0,
                    desc,
                    state.timed_out,
                    &timeout_message_for_block,
                ));
                cv.notify_one();
            });
            let sel = sel_registerName(
                CString::new("evaluatePolicy:localizedReason:reply:")
                    .unwrap()
                    .as_ptr(),
            );
            msg_send_void_long_id_block(ctx, sel, policy, reason_ns, &reply_block);

            if let Some(outcome) = wait_for_eval_outcome(&shared, timeout) {
                return outcome;
            }

            {
                let (lock, _) = &*shared;
                let mut state = lock.lock().expect("lock biometric timeout state");
                if let Some(outcome) = state.outcome.take() {
                    return outcome;
                }
                state.timed_out = true;
            }

            invalidate_context(ctx);
            if let Some(outcome) = wait_for_eval_outcome(&shared, local_auth_invalidate_grace()) {
                return outcome;
            }

            // The framework did not answer even after `invalidate`. Leak the
            // reply block on this pathological path so a late callback cannot
            // race a drop of its captured state.
            let _ = RcBlock::into_raw(reply_block);
            EvalResult::Unavailable(timeout_message)
        }
    }

    unsafe fn nsstring_from_str(s: &str) -> Id {
        unsafe {
            let cls_name = CString::new("NSString").unwrap();
            let cls = objc_getClass(cls_name.as_ptr());
            if cls.is_null() {
                return std::ptr::null_mut();
            }
            let sel = sel_registerName(CString::new("stringWithUTF8String:").unwrap().as_ptr());
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
        use super::*;

        #[test]
        fn eval_outcome_from_reply_marks_timed_out_replies_unavailable() {
            let outcome = eval_outcome_from_reply(
                false,
                Some("Caller invalidated LAContext".to_string()),
                true,
                "timeout",
            );
            match outcome {
                EvalResult::Unavailable(msg) => assert_eq!(msg, "timeout"),
                other => panic!("expected timeout-unavailable, got {other:?}"),
            }
        }

        #[test]
        fn wait_for_eval_outcome_times_out_without_reply() {
            let shared = Arc::new((
                Mutex::new(EvalWaitState {
                    outcome: None,
                    timed_out: false,
                }),
                Condvar::new(),
            ));
            assert!(
                wait_for_eval_outcome(&shared, Duration::from_millis(5)).is_none(),
                "missing LocalAuthentication reply should time out"
            );
        }

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
