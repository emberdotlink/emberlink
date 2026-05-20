use std::env;
use std::io::{self, Write};
use std::path::PathBuf;

use clap::Parser;
use emberlink_cli::{Args, Cmd, DemoApp, default_data_dir, output};

fn main() {
    let raw: Vec<String> = env::args().skip(1).collect();
    let options = resolve_launch_options(raw);
    let mut app = if options.no_demo {
        let path = options
            .state_file
            .unwrap_or_else(|| default_data_dir().join("local-state.enc"));
        eprintln!(
            "Starting without demo data. Run `init --name <your name>` to create an identity."
        );
        DemoApp::with_state_file(path)
    } else {
        match options.state_file {
            Some(path) => DemoApp::with_state_file(path),
            None => DemoApp::seeded(),
        }
    };
    // DRY-10: honor --json / --quiet / --color for handlers that have
    // migrated to the typed `Output` abstraction. Un-migrated handlers
    // ignore this and emit the legacy human shape.
    app.set_output_mode(options.output_mode);

    if let Some(screen) = options.command.first() {
        print!("{}", render_screen(&mut app, screen, &options.command[1..]));
        return;
    }

    println!("Emberlink shell. Run `help` for commands.");
    interactive_loop(&mut app);
}

/// Resolve launch options from argv.
///
/// DRY-9: clap-derive is the primary path — gives us `--help` per subcommand
/// and structured top-level discovery. Two escape hatches keep the legacy
/// freeform tokenizer reachable:
///
/// * `--legacy` flag anywhere in argv.
/// * `EMBER_CLI_LEGACY=1` environment variable.
///
/// If clap parsing itself fails (e.g. because someone passed a freeform
/// string that doesn't fit the global-flag shape), we also fall back rather
/// than refuse the input — `handle_command` is the source of truth for what
/// the demo shell accepts.
fn resolve_launch_options(args: Vec<String>) -> LaunchOptions {
    let legacy_env = env::var("EMBER_CLI_LEGACY")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    let legacy_flag = args.iter().any(|a| a == "--legacy");

    if legacy_env || legacy_flag {
        return parse_launch_args(args);
    }

    // Prepend a synthetic argv[0] so clap's parser recognizes its program name.
    let mut argv: Vec<String> = Vec::with_capacity(args.len() + 1);
    argv.push("emberlink-cli".to_string());
    argv.extend(args.iter().cloned());

    match Args::try_parse_from(&argv) {
        Ok(parsed) => LaunchOptions::from_clap(parsed),
        Err(err) => {
            // `--help` / `--version` print and exit through clap.
            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp
                    | clap::error::ErrorKind::DisplayVersion
                    | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) {
                err.exit();
            }
            // Anything else: fall back to the legacy tokenizer rather than
            // refuse a shape the legacy shell would have accepted. The shell
            // is a demo playground — robustness over strictness.
            parse_launch_args(args)
        }
    }
}

fn interactive_loop(app: &mut DemoApp) {
    loop {
        print!("emberlink> ");
        io::stdout().flush().expect("flush prompt");

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("Failed to read input");
            return;
        }

        let command = input.trim();
        if command.is_empty() {
            continue;
        }

        let output = app.handle_command(command);
        if output == "EXIT" {
            break;
        }
        print!("{output}");
    }
}

fn render_screen(app: &mut DemoApp, screen: &str, rest: &[String]) -> String {
    match screen {
        "home" => app.render_home(),
        "broker" => {
            if rest.iter().any(|arg| arg == "--disclose-links") {
                app.render_broker(true)
            } else {
                app.render_broker(false)
            }
        }
        "trust" => {
            if rest.is_empty() {
                app.render_trust()
            } else {
                let mut full = vec![screen.to_string()];
                full.extend(rest.iter().cloned());
                app.handle_command(&full.join(" "))
            }
        }
        "messages" => app.render_messages(),
        "disclosures" => app.render_disclosures(),
        "message" => {
            if rest.is_empty() {
                app.render_messages()
            } else {
                let mut full = vec![screen.to_string()];
                full.extend(rest.iter().cloned());
                app.handle_command(&full.join(" "))
            }
        }
        "content" => {
            if rest.is_empty() {
                app.render_content()
            } else {
                let mut full = vec![screen.to_string()];
                full.extend(rest.iter().cloned());
                app.handle_command(&full.join(" "))
            }
        }
        "recovery" => {
            if rest.is_empty() {
                app.render_recovery()
            } else {
                let mut full = vec![screen.to_string()];
                full.extend(rest.iter().cloned());
                app.handle_command(&full.join(" "))
            }
        }
        "vault" => {
            if rest.is_empty() {
                app.render_vault(None)
            } else {
                let mut full = vec![screen.to_string()];
                full.extend(rest.iter().cloned());
                app.handle_command(&full.join(" "))
            }
        }
        "storage" => {
            if rest.is_empty() {
                app.render_storage()
            } else {
                let mut full = vec![screen.to_string()];
                full.extend(rest.iter().cloned());
                app.handle_command(&full.join(" "))
            }
        }
        "sync" => {
            if rest.is_empty() {
                app.render_sync()
            } else {
                let mut full = vec![screen.to_string()];
                full.extend(rest.iter().cloned());
                app.handle_command(&full.join(" "))
            }
        }
        "state" => app.render_state(),
        "roots" => app.render_roots(),
        "devices" => app.render_devices(),
        "personas" => app.render_personas(),
        "all" => app.render_all(),
        "help" | "reset" | "show" | "list" | "root" | "device" | "persona" | "create-root"
        | "create-persona" | "inspect" | "compare" | "disclosure" | "init" | "disclose"
        | "status" => {
            let mut full = vec![screen.to_string()];
            full.extend(rest.iter().cloned());
            app.handle_command(&full.join(" "))
        }
        other => format!("Unknown command: {other}\n"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LaunchOptions {
    state_file: Option<PathBuf>,
    no_demo: bool,
    command: Vec<String>,
    /// DRY-10: resolved output renderer mode (Human/Json/Quiet).
    output_mode: output::Mode,
}

impl LaunchOptions {
    fn from_clap(args: Args) -> Self {
        let output_mode = args.output_mode();
        let command = match args.command {
            Some(Cmd::Legacy(tokens)) => tokens,
            Some(other) => other
                .to_legacy_string()
                .split_whitespace()
                .map(|s| s.to_string())
                .collect(),
            None => Vec::new(),
        };
        Self {
            state_file: args.state,
            no_demo: args.no_demo,
            command,
            output_mode,
        }
    }
}

fn parse_launch_args(args: Vec<String>) -> LaunchOptions {
    let mut state_file = None;
    let mut no_demo = false;
    let mut command = Vec::new();
    let mut i = 0;

    while i < args.len() {
        if !command.is_empty() {
            // Once a command word is seen, all remaining args belong to it
            command.push(args[i].clone());
            i += 1;
            continue;
        }
        match args[i].as_str() {
            "--state" if i + 1 < args.len() => {
                state_file = Some(PathBuf::from(args[i + 1].clone()));
                i += 2;
            }
            "--no-demo" => {
                no_demo = true;
                i += 1;
            }
            "--legacy" => {
                // Checkpoint consumed by `resolve_launch_options`; ignore here.
                i += 1;
            }
            other => {
                command.push(other.to_string());
                i += 1;
            }
        }
    }

    LaunchOptions {
        state_file,
        no_demo,
        command,
        // DRY-10: legacy tokenizer doesn't parse --json/--quiet/--color, so
        // fall back to the default human (no color) shape. Anyone who needs
        // structured output goes through clap.
        output_mode: output::Mode::Human { color: false },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_launch_args_supports_named_state_file() {
        let options = parse_launch_args(vec![
            "--state".into(),
            "/tmp/emberlink-client-a.tsv".into(),
            "show".into(),
            "state".into(),
        ]);

        assert_eq!(
            options.state_file,
            Some(PathBuf::from("/tmp/emberlink-client-a.tsv"))
        );
        assert_eq!(
            options.command,
            vec!["show".to_string(), "state".to_string()]
        );
        assert!(!options.no_demo);
    }

    #[test]
    fn parse_launch_args_defaults_to_seeded_state() {
        let options = parse_launch_args(vec!["show".into(), "broker".into()]);

        assert_eq!(options.state_file, None);
        assert_eq!(
            options.command,
            vec!["show".to_string(), "broker".to_string()]
        );
        assert!(!options.no_demo);
    }

    #[test]
    fn parse_launch_args_supports_no_demo_flag() {
        let options = parse_launch_args(vec!["--no-demo".into()]);

        assert!(options.no_demo);
        assert_eq!(options.state_file, None);
        assert!(options.command.is_empty());
    }

    #[test]
    fn parse_launch_args_stops_consuming_flags_after_command() {
        let options = parse_launch_args(vec![
            "--state".into(),
            "/tmp/alice.tsv".into(),
            "sync".into(),
            "apply".into(),
            "--state".into(),
            "/tmp/bob.tsv".into(),
        ]);

        assert_eq!(options.state_file, Some(PathBuf::from("/tmp/alice.tsv")));
        assert_eq!(
            options.command,
            vec![
                "sync".to_string(),
                "apply".to_string(),
                "--state".to_string(),
                "/tmp/bob.tsv".to_string(),
            ]
        );
    }

    #[test]
    fn launch_options_from_clap_show_state() {
        let args =
            Args::try_parse_from(["emberlink-cli", "--state", "/tmp/x.tsv", "show", "state"])
                .unwrap();
        let options = LaunchOptions::from_clap(args);
        assert_eq!(options.state_file, Some(PathBuf::from("/tmp/x.tsv")));
        assert_eq!(
            options.command,
            vec!["show".to_string(), "state".to_string()]
        );
        assert!(!options.no_demo);
    }

    #[test]
    fn launch_options_from_clap_legacy_passthrough() {
        let args =
            Args::try_parse_from(["emberlink-cli", "totally-unknown", "foo", "bar"]).unwrap();
        let options = LaunchOptions::from_clap(args);
        assert_eq!(
            options.command,
            vec![
                "totally-unknown".to_string(),
                "foo".to_string(),
                "bar".to_string()
            ]
        );
    }

    #[test]
    fn launch_options_from_clap_propagates_json_mode() {
        let args = Args::try_parse_from(["emberlink-cli", "--json", "grant", "list"]).unwrap();
        let options = LaunchOptions::from_clap(args);
        assert_eq!(options.output_mode, output::Mode::Json);
    }

    #[test]
    fn launch_options_from_clap_propagates_quiet_mode() {
        let args = Args::try_parse_from(["emberlink-cli", "--quiet", "grant", "list"]).unwrap();
        let options = LaunchOptions::from_clap(args);
        assert_eq!(options.output_mode, output::Mode::Quiet);
    }

    #[test]
    fn grant_list_json_flag_emits_ndjson_through_demo_app() {
        // End-to-end: --json flag flows through Args -> LaunchOptions ->
        // DemoApp::set_output_mode -> handle_command("grant list").
        let mut app = DemoApp::ephemeral();
        app.set_output_mode(output::Mode::Json);
        // Seed a grant.
        let _ = app.handle_command(
            "grant create --persona persona-professional --recipient agent-jx \
             --kind peer --profile agent --mode standing --label dry10-e2e \
             --cap read_credential:obj-jx",
        );
        let listed = app.handle_command("grant list");
        // Each non-empty line is parseable JSON.
        for line in listed.lines().filter(|l| !l.is_empty()) {
            let v: serde_json::Value = serde_json::from_str(line).expect("ndjson line parses");
            assert!(v.get("id").is_some());
        }
        // No human heading.
        assert!(!listed.contains("Active grants"));
    }

    #[test]
    fn render_screen_supports_sync_view() {
        let mut app = DemoApp::ephemeral();

        let output = render_screen(&mut app, "sync", &[]);

        assert!(output.contains("Sync And Relay"));
        assert!(output.contains("Payload semantics: hidden from relay"));
    }

    #[test]
    fn render_screen_passes_through_trust_subcommands() {
        let mut app = DemoApp::ephemeral();

        let output = render_screen(
            &mut app,
            "trust",
            &["--recipient".to_string(), "peer-demo".to_string()],
        );

        assert!(output.contains("Audience: peer-demo"));
        assert!(output.contains("Normalized score: 0.77"));
    }

    #[test]
    fn render_screen_supports_messages_view() {
        let mut app = DemoApp::ephemeral();

        let output = render_screen(&mut app, "messages", &[]);

        assert!(output.contains("Messages"));
    }

    #[test]
    fn render_screen_passes_through_content_publish() {
        let mut app = DemoApp::ephemeral();

        let output = render_screen(
            &mut app,
            "content",
            &[
                "publish".to_string(),
                "--from".to_string(),
                "persona-professional".to_string(),
                "--type".to_string(),
                "post".to_string(),
                "--payload".to_string(),
                "cafefood".to_string(),
                "--visibility".to_string(),
                "public".to_string(),
            ],
        );

        assert!(output.contains("published content\tcontent-"));
    }

    #[test]
    fn grant_create_list_show_revoke_lifecycle() {
        let mut app = DemoApp::ephemeral();

        // Create a grant
        let output = app.handle_command(
            "grant create --persona persona-professional --recipient agent-123 \
             --kind peer --profile agent --mode standing --label test-grant \
             --cap read_credential:obj-abc",
        );
        assert!(output.contains("created grant\tgrant-"));

        // Extract grant ID from output
        let grant_id = output.split('\t').nth(1).unwrap().trim();

        // List grants — should include it
        let output = app.handle_command("grant list");
        assert!(output.contains("Active grants"));
        assert!(output.contains("standing"));

        // Show grant detail
        let output = app.handle_command(&format!("grant show {grant_id}"));
        assert!(output.contains(&format!("Grant {grant_id}")));
        assert!(output.contains("standing"));
        assert!(output.contains("agent"));
        assert!(output.contains("test-grant"));
        // Composite-grant shape (design): `grant show` walks blocks/statements
        // directly and prints `[sid] <resource_type> actions=[...] resource=<...>`.
        assert!(output.contains("actions=[credential:read]"));
        assert!(output.contains("resource=obj-abc"));
        assert!(output.contains("v1 created at"));

        // Edit grant label
        let output = app.handle_command(&format!("grant edit {grant_id} --label renamed-grant"));
        assert!(output.contains("edited grant"));

        // Show updated label
        let output = app.handle_command(&format!("grant show {grant_id}"));
        assert!(output.contains("renamed-grant"));

        // Revoke grant (reason flag is accepted but not stored — revoke_grant
        // mirrors DaemonStore::revoke_grant which does not persist a reason text)
        let output = app.handle_command(&format!("grant revoke {grant_id}"));
        assert!(output.contains("revoked grant"));

        // Show revoked state
        let output = app.handle_command(&format!("grant show {grant_id}"));
        assert!(output.contains("revoked"));

        // List should now be empty (only active)
        let output = app.handle_command("grant list");
        assert!(output.contains("No active grants"));
    }

    #[test]
    fn grant_renew_requires_renewable_mode() {
        let mut app = DemoApp::ephemeral();

        // Create a renewable grant
        let output = app.handle_command(
            "grant create --persona persona-professional --recipient svc-1 --kind service --profile service --mode renewable --expires-in 3600 --cap read_credential:obj-1",
        );
        let grant_id = output.split('\t').nth(1).unwrap().trim();

        // Renew it
        let output = app.handle_command(&format!("grant renew {grant_id} --expires-in 7200"));
        assert!(output.contains("renewed grant"));

        // Create a standing grant — renew should fail
        let output2 = app.handle_command(
            "grant create --persona persona-professional --recipient svc-2 --kind service --profile service --mode standing --cap read_credential:obj-2",
        );
        let standing_id = output2.split('\t').nth(1).unwrap().trim();

        let output = app.handle_command(&format!("grant renew {standing_id} --expires-in 7200"));
        assert!(output.contains("Failed to renew grant"));
    }

    #[test]
    fn grant_recipient_shows_all_grants_for_recipient() {
        let mut app = DemoApp::ephemeral();

        // Create two grants for the same recipient
        let output1 = app.handle_command(
            "grant create --persona persona-professional --recipient agent-x \
             --kind peer --profile agent --mode standing --label first-grant \
             --cap read_credential:obj-1",
        );
        let grant_id1 = output1.split('\t').nth(1).unwrap().trim().to_string();

        app.handle_command(
            "grant create --persona persona-professional --recipient agent-x \
             --kind peer --profile agent --mode renewable --expires-in 3600 \
             --label second-grant --cap read_credential:obj-2",
        );

        // Revoke the first grant
        app.handle_command(&format!("grant revoke {grant_id1} --reason done"));

        // Recipient detail should show both (active + revoked)
        let output = app.handle_command("grant recipient --kind peer --id agent-x");
        assert!(output.contains("Recipient agent-x (peer)"));
        assert!(output.contains("revoked"));
        assert!(output.contains("renewable"));

        // Empty recipient should show no grants
        let output = app.handle_command("grant recipient --kind service --id nonexistent");
        assert!(output.contains("No grants for this recipient"));
    }

    #[test]
    fn grant_history_shows_timeline() {
        let mut app = DemoApp::ephemeral();

        // Create a grant
        let output = app.handle_command(
            "grant create --persona persona-professional --recipient svc-hist \
             --kind service --profile service --mode standing --cap read_credential:obj-h1",
        );
        let grant_id = output.split('\t').nth(1).unwrap().trim().to_string();

        // Edit it
        app.handle_command(&format!("grant edit {grant_id} --label updated-label"));

        // History should show both events
        let output = app.handle_command("grant history");
        assert!(output.contains("Grant history"));
        assert!(output.contains("created"));
        assert!(output.contains("edited"));

        // History filtered by persona
        let output = app.handle_command("grant history --persona persona-professional");
        assert!(output.contains("created"));

        // History with limit
        let output = app.handle_command("grant history --limit 1");
        // Should have header + column header + 1 data line = 3 lines
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 3);
    }
}
