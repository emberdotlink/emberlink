//! Argv classifier for `ember-scion` container lifecycle commands.
//!
//!
//! Maps `ember-scion <subcommand>` to a `scion.toml` action key. The daemon
//! re-classifies server-side (design §3); this is shim-side only.

use core_construct_runtime::ActionKey;

/// Wrapper for the VENDORS classifier field — converts the `&'static str`
/// returned by `classify_scion_argv` into the `ActionKey` type used by the
/// runtime registry.
pub fn classify_scion_argv_key(argv: &[String]) -> Option<ActionKey> {
    classify_scion_argv(argv).map(|k| ActionKey(k.to_string()))
}

/// Classify `ember-scion <subcommand> [args…]` argv into an action key.
///
/// `argv` is the full argv including the binary name at position 0.
/// Returns `Some("scion.<subcommand>")` for known subcommands, `None` otherwise.
pub fn classify_scion_argv(argv: &[String]) -> Option<&'static str> {
    match argv.get(1).map(String::as_str) {
        Some("start") => Some("scion.start"),
        Some("stop") => Some("scion.stop"),
        Some("delete") => Some("scion.delete"),
        Some("attach") => Some("scion.attach"),
        Some("logs") => Some("scion.logs"),
        Some("list") => Some("scion.list"),
        _ => None,
    }
}

/// Translate `ember-scion` argv into scion-native argv.
///
/// Per design §4 step (3): emberlink-specific argv is policy input the daemon
/// consumes server-side, not flags scion understands. This translation runs
/// after `broker.resolve` and before exec'ing the upstream scion binary.
///
/// Translation rules (implementation-note-70):
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
            Some("scion.start")
        );
    }

    #[test]
    fn test_classify_scion_argv_list() {
        assert_eq!(
            classify_scion_argv(&argv(&["ember-scion", "list"])),
            Some("scion.list")
        );
    }

    #[test]
    fn test_classify_scion_argv_unknown() {
        assert_eq!(
            classify_scion_argv(&argv(&["ember-scion", "bogus"])),
            None
        );
    }

    #[test]
    fn test_classify_scion_argv_empty() {
        assert_eq!(classify_scion_argv(&argv(&["ember-scion"])), None);
    }

    #[test]
    fn test_classify_scion_argv_stop() {
        assert_eq!(
            classify_scion_argv(&argv(&["ember-scion", "stop"])),
            Some("scion.stop")
        );
    }

    #[test]
    fn test_classify_scion_argv_delete() {
        assert_eq!(
            classify_scion_argv(&argv(&["ember-scion", "delete"])),
            Some("scion.delete")
        );
    }

    #[test]
    fn test_classify_scion_argv_attach() {
        assert_eq!(
            classify_scion_argv(&argv(&["ember-scion", "attach"])),
            Some("scion.attach")
        );
    }

    #[test]
    fn test_classify_scion_argv_logs() {
        assert_eq!(
            classify_scion_argv(&argv(&["ember-scion", "logs"])),
            Some("scion.logs")
        );
    }

    // translate_scion_argv tests (implementation-note-70) ---

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
        let input = argv(&[
            "ember-scion",
            "start",
            "ctr1",
            "--brief",
            "implement foo",
        ]);
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
        let input = argv(&[
            "ember-scion",
            "start",
            "ctr1",
            "--non-interactive",
        ]);
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
}

// translate_scion_argv_helper_landed

