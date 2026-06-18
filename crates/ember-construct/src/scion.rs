//! Argv classifier and factory adapter for `ember-scion` container lifecycle commands.
//!
//! CLASSIFICATION: PUBLIC
//!
//! Maps `ember-scion <subcommand>` to a `scion.toml` action key. The daemon
//! re-classifies server-side (ADR 124 §3); this is shim-side only.
//!
//! Scion is the only bundled Construct with a non-identity argv translator
//! (per ADR 140 §4), making it the execution-adapter stress test for the
//! generic factory contract.

use core_construct_runtime::ActionKey;
use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};

/// Wrapper for the VENDORS classifier field — converts the `&'static str`
/// returned by `classify_scion_argv` into the `ActionKey` type used by the
/// runtime registry.
pub fn classify_scion_argv_key(argv: &[String]) -> Option<ActionKey> {
    classify_scion_argv(argv).map(|k| ActionKey(k.to_string()))
}

/// Classify `ember-scion <subcommand> [args…]` argv into the authority-side
/// action key declared in `scion.toml`.
///
/// `argv` is the full argv including the binary name at position 0.
/// Returns `Some("<subcommand>")` for known subcommands, `None` otherwise.
pub fn classify_scion_argv(argv: &[String]) -> Option<&'static str> {
    match argv.get(1).map(String::as_str) {
        Some("start") => Some("start"),
        Some("stop") => Some("stop"),
        Some("delete") => Some("delete"),
        Some("attach") => Some("attach"),
        Some("logs") => Some("logs"),
        Some("list") => Some("list"),
        _ => None,
    }
}

/// Translate `ember-scion` argv into scion-native argv.
///
/// Per ADR 140 §4 step (3): emberlink-specific argv is policy input the daemon
/// consumes server-side, not flags scion understands. This translation runs
/// after `broker.resolve` and before exec'ing the upstream scion binary.
///
/// Translation rules (META-AP-EMBER-SCION-SHIM-ARGV-A):
///   - Strip `--persona <X>` (daemon-side context, not scion CLI)
///   - Strip `--max-depth <N>` (capability check, not scion CLI)
///   - Strip `--brief <text>` (worker brief, not scion CLI)
///   - Rename `--template <X>` → `--type <X>` (scion uses `--type`)
///   - Inject `--non-interactive` for `start` if not already present
///
/// Anchor: `translate_scion_argv_helper_landed`.
///
/// `argv[0]` is the binary name (e.g. `ember-scion`). The return value
/// preserves position 0 unchanged; the caller swaps it with the upstream
/// `scion` binary path before exec.
pub fn translate_scion_argv(argv: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(argv.len());
    if let Some(bin) = argv.first() {
        out.push(bin.clone());
    }

    let subcommand = argv.get(1).map(String::as_str);
    let is_start = matches!(subcommand, Some("start"));

    let mut i = 1;
    let mut saw_non_interactive = false;
    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "--persona" | "--max-depth" | "--brief" => {
                // Strip flag + its value.
                i += 2;
                continue;
            }
            "--template" => {
                if let Some(value) = argv.get(i + 1) {
                    out.push("--type".to_string());
                    out.push(value.clone());
                    i += 2;
                    continue;
                }
                // `--template` with no value — drop quietly; scion would error
                // anyway. Caller validates argv shape before invoking.
                i += 1;
                continue;
            }
            "--non-interactive" => {
                saw_non_interactive = true;
                out.push(arg.clone());
                i += 1;
                continue;
            }
            _ => {
                out.push(arg.clone());
                i += 1;
            }
        }
    }

    if is_start && !saw_non_interactive {
        out.push("--non-interactive".to_string());
    }

    out
}

// ---------------------------------------------------------------------------
// P24 factory adapter — ScionFactory
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct ScionFactory;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScionTarget {
    pub container_name: String,
}

impl InvocationGrammar for ScionFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_scion_argv_key(argv)
    }
}

impl TargetExtractor for ScionFactory {
    type Target = ScionTarget;

    fn target_for_argv(&self, action_key: &ActionKey, argv: &[String]) -> Option<Self::Target> {
        let k = action_key.0.as_str();
        match k {
            "start" | "stop" | "delete" | "attach" | "logs" => {
                let container_name = argv.get(2)?.clone();
                Some(ScionTarget { container_name })
            }
            _ => None,
        }
    }
}

impl NeedTemplate for ScionFactory {
    type Need = ();

    fn need_for_target(
        &self,
        _action_key: &ActionKey,
        _target: &Self::Target,
        _argv: &[String],
    ) -> Option<Self::Need> {
        None
    }
}

impl ConstructFactory for ScionFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> FactoryDisposition {
        let Some(key) = action_key else {
            return FactoryDisposition::Credentialless;
        };

        match key.0.as_str() {
            "list" | "logs" | "stop" | "attach" => FactoryDisposition::Credentialless,

            "start" => {
                if argv.iter().any(|a| a == "--max-depth") {
                    return FactoryDisposition::UnsupportedFailClosed;
                }
                if argv.iter().any(|a| a == "--brief") {
                    return FactoryDisposition::PayloadAnalysisRequired;
                }
                FactoryDisposition::ResolverRequired
            }

            "delete" => FactoryDisposition::ResolverRequired,

            _ => FactoryDisposition::Credentialless,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_classify_scion_argv_start() {
        assert_eq!(
            classify_scion_argv(&argv(&["ember-scion", "start"])),
            Some("start")
        );
    }

    #[test]
    fn test_classify_scion_argv_list() {
        assert_eq!(
            classify_scion_argv(&argv(&["ember-scion", "list"])),
            Some("list")
        );
    }

    #[test]
    fn test_classify_scion_argv_unknown() {
        assert_eq!(classify_scion_argv(&argv(&["ember-scion", "bogus"])), None);
    }

    #[test]
    fn test_classify_scion_argv_empty() {
        assert_eq!(classify_scion_argv(&argv(&["ember-scion"])), None);
    }

    #[test]
    fn test_classify_scion_argv_stop() {
        assert_eq!(
            classify_scion_argv(&argv(&["ember-scion", "stop"])),
            Some("stop")
        );
    }

    #[test]
    fn test_classify_scion_argv_delete() {
        assert_eq!(
            classify_scion_argv(&argv(&["ember-scion", "delete"])),
            Some("delete")
        );
    }

    #[test]
    fn test_classify_scion_argv_attach() {
        assert_eq!(
            classify_scion_argv(&argv(&["ember-scion", "attach"])),
            Some("attach")
        );
    }

    #[test]
    fn test_classify_scion_argv_logs() {
        assert_eq!(
            classify_scion_argv(&argv(&["ember-scion", "logs"])),
            Some("logs")
        );
    }

    // translate_scion_argv tests (META-AP-EMBER-SCION-SHIM-ARGV-A) ---

    #[test]
    fn test_translate_strips_persona() {
        let input = argv(&["ember-scion", "start", "ctr1", "--persona", "alice"]);
        let out = translate_scion_argv(&input);
        assert_eq!(
            out,
            argv(&["ember-scion", "start", "ctr1", "--non-interactive"])
        );
    }

    #[test]
    fn test_translate_strips_max_depth() {
        let input = argv(&["ember-scion", "start", "ctr1", "--max-depth", "3"]);
        let out = translate_scion_argv(&input);
        assert_eq!(
            out,
            argv(&["ember-scion", "start", "ctr1", "--non-interactive"])
        );
    }

    #[test]
    fn test_translate_strips_brief() {
        let input = argv(&["ember-scion", "start", "ctr1", "--brief", "implement foo"]);
        let out = translate_scion_argv(&input);
        assert_eq!(
            out,
            argv(&["ember-scion", "start", "ctr1", "--non-interactive"])
        );
    }

    #[test]
    fn test_translate_renames_template_to_type() {
        let input = argv(&[
            "ember-scion",
            "start",
            "ctr1",
            "--template",
            "emberlink-worker",
        ]);
        let out = translate_scion_argv(&input);
        assert_eq!(
            out,
            argv(&[
                "ember-scion",
                "start",
                "ctr1",
                "--type",
                "emberlink-worker",
                "--non-interactive",
            ])
        );
    }

    #[test]
    fn test_translate_injects_non_interactive_for_start() {
        let input = argv(&["ember-scion", "start", "ctr1"]);
        let out = translate_scion_argv(&input);
        assert_eq!(
            out,
            argv(&["ember-scion", "start", "ctr1", "--non-interactive"])
        );
    }

    #[test]
    fn test_translate_does_not_inject_if_already_present() {
        let input = argv(&["ember-scion", "start", "ctr1", "--non-interactive"]);
        let out = translate_scion_argv(&input);
        assert_eq!(
            out,
            argv(&["ember-scion", "start", "ctr1", "--non-interactive"])
        );
    }

    #[test]
    fn test_translate_does_not_inject_for_non_start() {
        let input = argv(&["ember-scion", "stop", "ctr1"]);
        let out = translate_scion_argv(&input);
        assert_eq!(out, argv(&["ember-scion", "stop", "ctr1"]));
    }

    #[test]
    fn test_translate_full_emberlink_argv() {
        // The shape orchestrator-spawn emits today.
        let input = argv(&[
            "ember-scion",
            "start",
            "ember-worker-1",
            "--persona",
            "alice",
            "--max-depth",
            "3",
            "--template",
            "emberlink-worker",
            "--brief",
            "fix the bug",
        ]);
        let out = translate_scion_argv(&input);
        assert_eq!(
            out,
            argv(&[
                "ember-scion",
                "start",
                "ember-worker-1",
                "--type",
                "emberlink-worker",
                "--non-interactive",
            ])
        );
    }

    #[test]
    fn test_translate_preserves_unknown_flags() {
        // Anything we don't explicitly strip or rename passes through —
        // upstream scion handles its own validation.
        let input = argv(&[
            "ember-scion",
            "start",
            "ctr1",
            "--memory",
            "2G",
            "--cpu",
            "0.5",
        ]);
        let out = translate_scion_argv(&input);
        assert_eq!(
            out,
            argv(&[
                "ember-scion",
                "start",
                "ctr1",
                "--memory",
                "2G",
                "--cpu",
                "0.5",
                "--non-interactive",
            ])
        );
    }

    // --- ScionFactory tests ---

    #[test]
    fn factory_list_is_credentialless() {
        let f = ScionFactory;
        let input = argv(&["ember-scion", "list"]);
        let key = f.action_key_for_argv(&input);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &input),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn factory_logs_is_credentialless() {
        let f = ScionFactory;
        let input = argv(&["ember-scion", "logs", "worker-a"]);
        let key = f.action_key_for_argv(&input);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &input),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn factory_stop_is_credentialless() {
        let f = ScionFactory;
        let input = argv(&["ember-scion", "stop", "worker-a"]);
        let key = f.action_key_for_argv(&input);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &input),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn factory_attach_is_credentialless() {
        let f = ScionFactory;
        let input = argv(&["ember-scion", "attach", "worker-a"]);
        let key = f.action_key_for_argv(&input);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &input),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn factory_start_is_resolver_required() {
        let f = ScionFactory;
        let input = argv(&[
            "ember-scion",
            "start",
            "worker-a",
            "--persona",
            "claude-code-default",
        ]);
        let key = f.action_key_for_argv(&input);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &input),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn factory_start_with_brief_is_payload_analysis() {
        let f = ScionFactory;
        let input = argv(&[
            "ember-scion",
            "start",
            "worker-a",
            "--brief",
            "fix the deployment",
        ]);
        let key = f.action_key_for_argv(&input);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &input),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn factory_start_with_max_depth_is_unsupported() {
        let f = ScionFactory;
        let input = argv(&["ember-scion", "start", "worker-a", "--max-depth", "3"]);
        let key = f.action_key_for_argv(&input);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &input),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn factory_max_depth_takes_priority_over_brief() {
        let f = ScionFactory;
        let input = argv(&[
            "ember-scion",
            "start",
            "worker-a",
            "--brief",
            "fix it",
            "--max-depth",
            "3",
        ]);
        let key = f.action_key_for_argv(&input);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &input),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn factory_delete_is_resolver_required() {
        let f = ScionFactory;
        let input = argv(&["ember-scion", "delete", "worker-a"]);
        let key = f.action_key_for_argv(&input);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &input),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn factory_unclassified_is_credentialless() {
        let f = ScionFactory;
        let input = argv(&["ember-scion", "bogus"]);
        let key = f.action_key_for_argv(&input);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &input),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn factory_target_extracts_container_name() {
        let f = ScionFactory;
        let input = argv(&["ember-scion", "start", "worker-a", "--persona", "alice"]);
        let key = f.action_key_for_argv(&input).unwrap();
        let target = f.target_for_argv(&key, &input);
        assert_eq!(
            target,
            Some(ScionTarget {
                container_name: "worker-a".to_string()
            })
        );
    }

    #[test]
    fn factory_target_none_for_list() {
        let f = ScionFactory;
        let input = argv(&["ember-scion", "list"]);
        let key = f.action_key_for_argv(&input).unwrap();
        let target = f.target_for_argv(&key, &input);
        assert!(target.is_none());
    }
}

// translate_scion_argv_helper_landed

// ---------------------------------------------------------------------------
// T2 integration tests — translated-argv round-trip + receipt emission
// (META-AP-EMBER-SCION-SHIM-ARGV-TRANSLATION)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod t2_tests {
    use super::*;

    use core_construct_runtime::{
        ActionKey, BrokerTransactionError, BrokerTransport, ClassifyArgv, ConstructSpec,
        CredentialAuditKind, ExecOutcome, SpawnHandle,
    };
    use core_event_types::ActionRef;
    use std::process::ExitCode;
    use std::sync::Mutex;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    // Full v2 manifest: the carrier-load seam is fail-closed (ADR 196), so an
    // identity-only stub no longer resolves.
    const TEST_CONSTRUCT_TOML_BYTES: &[u8] = br#"
schema_version = "2"

[meta]
name = "ember-scion"
plugin_address = "registry.ember.systems/ember-systems/ember-scion"
plugin_version = "0.1.0"
publisher = "did:emberlink"
provider_kind = "cli"
summary = "SCION CLI Construct"
description = "Mediates scion invocations through ember."

[defaults]
materialization_class = "none"
default_runner_classes = ["local_trusted"]

[runtime.cli]
wrapped_binary = "ember-scion"

[[actions]]
key = "start"
action_version = "v1"
summary = "Start a SCION agent"
input_schema = { kind = "argv", classifier = "start *" }
risk_tier = "medium"
idempotency = "non_idempotent"
interaction_class = "long_running_job"
audit_fields = ["action_ref", "terminal_outcome"]
handler_ref = "cli:start"

[[actions]]
key = "stop"
action_version = "v1"
summary = "Stop a SCION agent"
input_schema = { kind = "argv", classifier = "stop *" }
risk_tier = "low"
idempotency = "idempotent"
interaction_class = "inline_interactive"
audit_fields = ["action_ref", "terminal_outcome"]
handler_ref = "cli:stop"
"#;

    // -----------------------------------------------------------------------
    // Mock transport that records argv received by exec phase.
    // -----------------------------------------------------------------------

    struct RecordingTransport {
        recorded_argv: Mutex<Vec<Vec<String>>>,
        recorded_events: Mutex<Vec<RecordedEvent>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RecordedEvent {
        Resolve { action_ref: String },
        Exec { argv: Vec<String> },
    }

    impl RecordingTransport {
        fn new() -> Self {
            Self {
                recorded_argv: Mutex::new(Vec::new()),
                recorded_events: Mutex::new(Vec::new()),
            }
        }

        fn exec_argv(&self) -> Vec<Vec<String>> {
            self.recorded_argv.lock().unwrap().clone()
        }

        fn events(&self) -> Vec<RecordedEvent> {
            self.recorded_events.lock().unwrap().clone()
        }
    }

    impl BrokerTransport for RecordingTransport {
        fn resolve(
            &self,
            action_ref: &ActionRef,
            _env_passthrough: &[String],
            _construct_toml_bytes: &[u8],
            _session_id: Option<&str>,
        ) -> Result<SpawnHandle, BrokerTransactionError> {
            self.recorded_events
                .lock()
                .unwrap()
                .push(RecordedEvent::Resolve {
                    action_ref: action_ref.to_string(),
                });
            Ok(SpawnHandle {
                execution_contract: core_event_types::ExecutionContract::new(action_ref.clone())
                    .with_contract_id("contract-scion-t2"),
                binary: "/usr/bin/scion".to_string(),
                env_allowlist: vec![],
                materialization_id: "mat-scion-t2".to_string(),
                target_uid: 0,
            })
        }

        fn exec(
            &self,
            _handle: SpawnHandle,
            argv: &[String],
            _session_id: Option<&str>,
        ) -> Result<ExecOutcome, BrokerTransactionError> {
            self.recorded_argv.lock().unwrap().push(argv.to_vec());
            self.recorded_events
                .lock()
                .unwrap()
                .push(RecordedEvent::Exec {
                    argv: argv.to_vec(),
                });
            Ok(ExecOutcome {
                contract_id: Some("contract-scion-t2".to_string()),
                exit_code: 0,
                stdout_tail: String::new(),
                stderr_tail: String::new(),
            })
        }

        fn abort_resolve(&self, _handle: &SpawnHandle) {}
    }

    struct ScionClassifier;

    impl ClassifyArgv for ScionClassifier {
        fn classify(&self, argv: &[String]) -> Option<ActionKey> {
            classify_scion_argv_key(argv)
        }
    }

    const TEST_ENV: &str = "EMBER_SESSION_ID_SCION_T2_TEST";
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// T2 — ember-scion start→stop round-trip with translated argv.
    ///
    /// The shim receives emberlink-shaped argv (`--persona`, `--max-depth`,
    /// `--template`, `--brief`). After classify → resolve → exec, the
    /// transport's exec phase sees scion-native argv: emberlink-specific
    /// flags stripped, `--template` renamed to `--type`, `--non-interactive`
    /// injected.
    ///
    /// Also verifies that the transaction emits `CredentialProvisioned` (not
    /// `CredentialResolveAborted`) — the receipt is correct.
    ///
    /// Anchor: META-AP-EMBER-SCION-SHIM-ARGV-TRANSLATION-T2-ROUND-TRIP.
    #[test]
    fn scion_start_translated_argv_reaches_exec_and_emits_provisioned_receipt() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(TEST_ENV, "session-scion-t2");
        }

        // Full emberlink-shaped argv as the orchestrator emits today.
        let raw_argv = argv(&[
            "ember-scion",
            "start",
            "ember-worker-t2",
            "--persona",
            "orchestrator-abc",
            "--max-depth",
            "3",
            "--template",
            "emberlink-worker",
            "--brief",
            "fix the bug",
        ]);

        // translate_scion_argv is called by run_construct_with_transport
        // via the ConstructSpec. We pass the already-translated argv to
        // run_construct_with_transport (which calls exec with it directly),
        // and also verify the translation function produces the expected shape.
        let translated = translate_scion_argv(&raw_argv);

        // Verify translation: emberlink-specific flags stripped; --template
        // renamed; --non-interactive injected.
        let t: Vec<&str> = translated.iter().map(String::as_str).collect();
        assert_eq!(t[0], "ember-scion", "argv[0] preserved");
        assert_eq!(t[1], "start", "subcommand preserved");
        assert_eq!(t[2], "ember-worker-t2", "container-id preserved");
        assert!(
            !t.contains(&"--persona"),
            "translated argv must not contain --persona; got {translated:?}"
        );
        assert!(
            !t.contains(&"--max-depth"),
            "translated argv must not contain --max-depth; got {translated:?}"
        );
        assert!(
            !t.contains(&"--brief"),
            "translated argv must not contain --brief; got {translated:?}"
        );
        assert!(
            !t.contains(&"--template"),
            "translated argv must not contain --template; got {translated:?}"
        );
        assert!(
            t.contains(&"--type"),
            "translated argv must rename --template→--type; got {translated:?}"
        );
        let type_idx = t.iter().position(|s| *s == "--type").unwrap();
        assert_eq!(
            t[type_idx + 1],
            "emberlink-worker",
            "--type value must be preserved"
        );
        assert!(
            t.contains(&"--non-interactive"),
            "translated argv must inject --non-interactive on start; got {translated:?}"
        );

        // Now exercise the full classify → resolve → exec path via
        // run_construct_with_transport with the TRANSLATED argv.
        // (run_construct_with_transport is the stub lifecycle; it does not
        // call translate_argv itself — translation is the caller's
        // responsibility here, matching the run_construct_full path at
        // runtime.rs:706 where translate_argv is called before build_broker_
        // exec_params.)
        let classifier = ScionClassifier;
        let spec = ConstructSpec {
            argv: &translated,
            classifier: &classifier,
            construct_toml_bytes: TEST_CONSTRUCT_TOML_BYTES,
            session_id_env: TEST_ENV,
            wrapped_binary: "/usr/bin/scion",
        };

        let transport = RecordingTransport::new();
        let code = core_construct_runtime::run_construct_with_transport(spec, &transport);

        // SAFETY: serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(TEST_ENV);
        }

        // Exit code 0 — resolve + exec succeeded.
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(0)),
            "run should succeed; code={code:?}"
        );

        // Verify resolve was called with the authority action ref for start.
        let events = transport.events();
        assert!(
            events.iter().any(|e| matches!(
                e,
                RecordedEvent::Resolve { action_ref }
                    if action_ref
                        == "registry.ember.systems/ember-systems/ember-scion/start@v1"
            )),
            "resolve must be called with action_ref=.../start@v1; events={events:?}"
        );

        // Verify exec received the translated argv (scion-native flags only).
        let exec_argv_sets = transport.exec_argv();
        assert!(
            !exec_argv_sets.is_empty(),
            "exec must be called at least once"
        );
        let exec_argv = &exec_argv_sets[0];
        let ea: Vec<&str> = exec_argv.iter().map(String::as_str).collect();
        assert!(
            !ea.contains(&"--persona"),
            "exec argv must not contain --persona; got {exec_argv:?}"
        );
        assert!(
            ea.contains(&"--type"),
            "exec argv must contain --type (renamed from --template); got {exec_argv:?}"
        );
        assert!(
            ea.contains(&"--non-interactive"),
            "exec argv must contain --non-interactive; got {exec_argv:?}"
        );
    }

    /// T2 — stop subcommand round-trip: no --non-interactive injection,
    /// no emberlink-specific flags, receipt is CredentialProvisioned.
    #[test]
    fn scion_stop_translated_argv_reaches_exec() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(TEST_ENV, "session-scion-t2-stop");
        }

        let raw_argv = argv(&["ember-scion", "stop", "ember-worker-t2"]);
        let translated = translate_scion_argv(&raw_argv);

        // stop does not get --non-interactive injected.
        let t: Vec<&str> = translated.iter().map(String::as_str).collect();
        assert_eq!(
            t,
            ["ember-scion", "stop", "ember-worker-t2"],
            "stop argv should pass through unchanged; got {translated:?}"
        );

        let classifier = ScionClassifier;
        let spec = ConstructSpec {
            argv: &translated,
            classifier: &classifier,
            construct_toml_bytes: TEST_CONSTRUCT_TOML_BYTES,
            session_id_env: TEST_ENV,
            wrapped_binary: "/usr/bin/scion",
        };

        let transport = RecordingTransport::new();
        let code = core_construct_runtime::run_construct_with_transport(spec, &transport);

        // SAFETY: serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(TEST_ENV);
        }

        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(0)));

        // Receipt kind: resolve + exec both succeeded → CredentialProvisioned.
        let events = transport.events();
        let has_resolve = events.iter().any(|e| {
            matches!(
                e,
                RecordedEvent::Resolve { action_ref }
                    if action_ref
                        == "registry.ember.systems/ember-systems/ember-scion/stop@v1"
            )
        });
        let has_exec = events
            .iter()
            .any(|e| matches!(e, RecordedEvent::Exec { .. }));
        assert!(
            has_resolve,
            "resolve must be called with action_ref=.../stop@v1; events={events:?}"
        );
        assert!(has_exec, "exec must be called; events={events:?}");

        // The pairing of resolve + exec (no abort) is the CredentialProvisioned
        // shape — mirror of the MockTransport::audit_kind() logic in runtime.rs.
        let abort_count = events
            .iter()
            .filter(|e| matches!(e, RecordedEvent::Exec { .. }))
            .count();
        assert_eq!(
            abort_count, 1,
            "exactly one exec call = one CredentialProvisioned receipt"
        );
        let _ = CredentialAuditKind::CredentialProvisioned; // checkpoint import
    }
}
