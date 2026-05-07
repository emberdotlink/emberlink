//! Per-Construct runtime: env-detect → classify → broker.resolve → broker.exec.
//!
//! See crate-level docs for the lifecycle. This module currently stubs
//! `broker.resolve` / `broker.exec` (mirroring the daemon's `-32001 NotSupported`
//! response in `crates/ember-daemon/src/broker_handler.rs`); real wiring lands
//! in T-CONSTRUCT-FIRST-REFERENCE-EMBER-GH-WIRE.

use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

use crate::ClassifyArgv;

/// Inputs for one `run_construct` invocation.
///
/// Each Construct binary builds one of these in `main()` and hands it to
/// [`run_construct`]. The fields capture the construct-specific bits
/// (classifier, manifest bytes, wrapped binary path) while the runtime
/// owns the lifecycle (env detect, broker calls, exit handling).
pub struct ConstructSpec<'a, C: ClassifyArgv> {
    /// Argv passed to this Construct (already stripped of argv[0]).
    pub argv: &'a [String],
    /// Construct-specific classifier (turns argv into an ActionKey).
    pub classifier: &'a C,
    /// Embedded `Construct.toml` bytes (for future broker.resolve payload).
    pub construct_toml_bytes: &'static [u8],
    /// Env var that signals we're inside an ember session — typically
    /// `"EMBER_SESSION_ID"`. If absent, we exec the wrapped binary directly.
    pub session_id_env: &'static str,
    /// Absolute path to the real tool, e.g. `"/usr/bin/gh"`.
    pub wrapped_binary: &'static str,
}

/// Single entry point for every Construct shim.
///
/// Returns the `ExitCode` to surface from `main`. See module docs for the
/// lifecycle stages and exit codes.
pub fn run_construct<C: ClassifyArgv>(spec: ConstructSpec<C>) -> ExitCode {
    // 1. env-detect: no session → passthrough exec the real tool.
    if std::env::var_os(spec.session_id_env).is_none() {
        let err = Command::new(spec.wrapped_binary).args(spec.argv).exec();
        // exec only returns on failure.
        eprintln!(
            "core-construct-runtime: failed to exec passthrough binary {:?}: {err}",
            spec.wrapped_binary
        );
        return ExitCode::from(126);
    }

    // 2. classify argv → ActionKey.
    let action_key = match spec.classifier.classify(spec.argv) {
        Some(k) => k,
        None => {
            eprintln!(
                "core-construct-runtime: classify failed for argv {:?}",
                spec.argv
            );
            return ExitCode::from(2);
        }
    };

    // 3. broker.resolve — STUB. Mirrors daemon's `-32001 NotSupported`
    //    in `crates/ember-daemon/src/broker_handler.rs::resolve_with_registry`.
    //    TODO: wire to daemon broker.resolve RPC,
    //    pass `spec.construct_toml_bytes` + `action_key` in the request.
    let _ = spec.construct_toml_bytes;
    eprintln!(
        "core-construct-runtime: broker.resolve not yet implemented \
         (implementation-note-9); action_key={action_key}"
    );

    // 4. broker.exec — STUB, unreachable while step 3 short-circuits.
    //    TODO: once broker.resolve returns a lease,
    //    spawn `spec.wrapped_binary` with the lease envelope and forward
    //    its exit status. Until then, step 3's `64` is what callers see.

    ExitCode::from(64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ActionKey;

    struct MockClassifier {
        result: Option<ActionKey>,
    }

    impl ClassifyArgv for MockClassifier {
        fn classify(&self, _argv: &[String]) -> Option<ActionKey> {
            self.result.clone()
        }
    }

    // These tests mutate process-global env vars, so they must run on the
    // same thread to avoid stomping each other. Cargo runs tests in parallel
    // by default; we serialize via a mutex.
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const TEST_ENV: &str = "EMBER_SESSION_ID_CCR_TEST";

    #[test]
    fn env_absent_attempts_passthrough_exec() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK; remove_var is sound here.
        unsafe {
            std::env::remove_var(TEST_ENV);
        }

        let classifier = MockClassifier {
            result: Some(ActionKey("test.action".to_string())),
        };
        let argv: Vec<String> = vec!["--help".to_string()];
        let spec = ConstructSpec {
            argv: &argv,
            classifier: &classifier,
            construct_toml_bytes: b"",
            session_id_env: TEST_ENV,
            // A path that definitely does not exist → exec fails → 126.
            wrapped_binary: "/usr/bin/false-fake-ccr-test-nonexistent",
        };

        let code = run_construct(spec);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(126)));
    }

    #[test]
    fn env_present_classify_some_returns_stub_64() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(TEST_ENV, "session-abc");
        }

        let classifier = MockClassifier {
            result: Some(ActionKey("test.action".to_string())),
        };
        let argv: Vec<String> = vec!["pr".to_string(), "create".to_string()];
        let spec = ConstructSpec {
            argv: &argv,
            classifier: &classifier,
            construct_toml_bytes: b"",
            session_id_env: TEST_ENV,
            wrapped_binary: "/usr/bin/false-fake-ccr-test-nonexistent",
        };

        let code = run_construct(spec);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(TEST_ENV);
        }

        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(64)));
    }

    #[test]
    fn env_present_classify_none_returns_2() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(TEST_ENV, "session-abc");
        }

        let classifier = MockClassifier { result: None };
        let argv: Vec<String> = vec!["weird".to_string()];
        let spec = ConstructSpec {
            argv: &argv,
            classifier: &classifier,
            construct_toml_bytes: b"",
            session_id_env: TEST_ENV,
            wrapped_binary: "/usr/bin/false-fake-ccr-test-nonexistent",
        };

        let code = run_construct(spec);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(TEST_ENV);
        }

        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(2)));
    }
}
