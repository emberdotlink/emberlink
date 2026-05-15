//! Clap-derive surface for the `emberlink-cli` demo shell.
//!
//! DRY-9: the legacy entry point [`crate::DemoApp::handle_command`] is a
//! string-tokenizer with ~70 subcommand handlers and ~380 in-tree test sites
//! that drive it via raw strings (`app.handle_command("grant create ...")`).
//! A wholesale clap migration of every handler would be a multi-thousand-line
//! rewrite and a test-suite earthquake, neither of which is the goal here.
//!
//! Instead this module wraps the argv-parsing surface in a thin clap-derive
//! shell so that:
//!
//! * `emberlink-cli --help` enumerates the top-level commands with help text.
//! * `emberlink-cli <subcommand> --help` works per top-level subcommand.
//! * The body of every variant is just `Vec<String>` of trailing tokens that
//!   we re-join and feed to the legacy `handle_command(&str)` path. The 380
//!   test sites keep working unchanged.
//! * Anything we have not enumerated falls through `Cmd::Legacy` (clap's
//!   `external_subcommand`), preserving the long tail of niche commands.
//!
//! `EMBER_CLI_LEGACY=1` (or `--legacy`) skips clap entirely and runs the raw
//! tokenizer — escape hatch for anyone who depended on freeform string parsing
//! that clap-derive's stricter shape would reject.
use std::io::IsTerminal;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::output;

/// Top-level `emberlink-cli` argv.
#[derive(Debug, Parser)]
#[command(
    name = "emberlink-cli",
    about = "Emberlink demo shell — interactive identity playground",
    long_about = "Emberlink demo shell — interactive identity playground.\n\n\
        Run with no subcommand for an interactive REPL. Pass a subcommand to \
        execute one command and exit. The production `ember` binary lives in \
        `src/bin/ember.rs` and has its own clap surface."
)]
pub struct Args {
    /// Override the on-disk state file (defaults to seeded demo state).
    #[arg(long, global = true)]
    pub state: Option<PathBuf>,

    /// Skip the seeded demo identity. Run `init --name <name>` after.
    #[arg(long, global = true)]
    pub no_demo: bool,

    /// Skip clap-derive parsing and run the raw tokenizer (legacy path).
    #[arg(long, global = true)]
    pub legacy: bool,

    /// Emit machine-readable NDJSON instead of human-formatted text (DRY-10).
    /// Suppresses headings and success blurbs; data rows become JSON arrays,
    /// objects become JSON lines. Mutually exclusive with `--quiet` (Json wins).
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress headings and success messages — emit only data rows and
    /// warnings/errors. Designed for shell pipelines (DRY-10).
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Color output policy (DRY-10). `auto` (default) enables ANSI when stdout
    /// is a TTY and `NO_COLOR` is unset; `always` forces on; `never` forces off.
    #[arg(long, global = true, value_enum, default_value_t = ColorMode::Auto)]
    pub color: ColorMode,

    #[command(subcommand)]
    pub command: Option<Cmd>,
}

/// `--color` policy. See [`Args::output_mode`] for resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

impl Args {
    /// Resolve the active output renderer mode from `--json` / `--quiet` /
    /// `--color`. Precedence:
    ///
    /// 1. `--json` always wins.
    /// 2. `--quiet` wins over Human.
    /// 3. Otherwise Human, with `color` resolved by `--color` + TTY +
    ///    `NO_COLOR`.
    pub fn output_mode(&self) -> output::Mode {
        if self.json {
            return output::Mode::Json;
        }
        if self.quiet {
            return output::Mode::Quiet;
        }
        let color = match self.color {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => detect_color_auto(),
        };
        output::Mode::Human { color }
    }
}

/// Auto-detect color: stdout-is-tty AND `NO_COLOR` is unset.
/// See <https://no-color.org>.
fn detect_color_auto() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stdout().is_terminal()
}

/// Top-level subcommands. Each variant captures its trailing tokens verbatim
/// and re-joins them for the legacy string-based [`crate::DemoApp::handle_command`].
///
/// The variant set is the union of the match arms in
/// `commands.rs::handle_command` plus the structured arms in
/// `commands.rs::handle_structured_command`. We do NOT enumerate every nested
/// flag — the goal is `--help` discoverability, not a full type-safe surface.
#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Show identity overview (also: `whoami`).
    Status {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Print the in-shell help text (catalog of every legacy command).
    #[command(name = "shell-help")]
    ShellHelp {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Initialize a new identity (root + persona + device).
    Init {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Create or accept an invite.
    Invite {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Reset on-disk demo state.
    Reset {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Inspect raw events / state shape (debug aid).
    Inspect {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Compare two state snapshots.
    Compare {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Render a view (broker, trust, messages, ...). Use `show <topic>`.
    Show {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// List entities (`list roots`, `list devices`, `list personas`, ...).
    List {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Render the broker scoreboard.
    Broker {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Render trust attestations / scoring.
    Trust {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Send / list messages.
    Message {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// List recent messages (alias for `message list`).
    Messages {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Inspect disclosures.
    Disclosures {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Inspect a specific disclosure message.
    Disclosure {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Issue a disclosure.
    Disclose {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Publish / list content.
    Content {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Recovery flows (request / approve / contest / reject / execute).
    Recovery {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Claim a delegated grant.
    Claim {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Service-binding workflows.
    Service {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Passkey workflows.
    Passkey {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Import an event log / invite / portable batch.
    Import {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Vault namespace management.
    Vault {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Grant lifecycle (create / list / show / revoke / renew / edit / claim / ...).
    Grant {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Grants manifest workflows (validate <file>).
    Grants {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Approve or deny a pending approval (implementation-note-156).
    Approval {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Render the badge UI (display / verify).
    Badge {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Credential vault helpers (issue / show / use).
    Credential {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Storage manifest workflows.
    Storage {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Sync / relay workflows (preview / apply / send / drain / ...).
    Sync {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Show event-store state.
    State {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Show local key material.
    Keys {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Root identity (`root create`, `root rotate-key`, `root show <ref>`, `root list`).
    Root {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Roots list (alias for `list roots`).
    Roots {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Device commands (add / revoke / rotate-key / show / list).
    Device {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Devices list (alias for `list devices`).
    Devices {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Persona commands (create / revoke / rotate-key / grant-device / show / list).
    Persona {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Personas list (alias for `list personas`).
    Personas {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Render every view in sequence (debug aid).
    All {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Legacy `create-root <name>` shorthand.
    #[command(name = "create-root")]
    CreateRoot {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Legacy `create-persona <root> <template> <label>` shorthand.
    #[command(name = "create-persona")]
    CreatePersona {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Export the event log.
    #[command(name = "export-events")]
    ExportEvents {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Import an event log.
    #[command(name = "import-events")]
    ImportEvents {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Query the receipts audit log (EMBER-implementation-note-172).
    ///
    /// Subcommand::Audit — dispatches to the receipt-query handler.
    /// Filters: --since <duration|ISO>, --actor <persona-id>,
    /// --kind <grant|kms_wrap|kms_unwrap>, --grant-id <id>,
    /// --resource <pattern>, --limit <N>, --format <table|json|jsonl>.
    Audit {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Manage content-hash-pinned binaries (install / list / update / remove).
    ///
    /// `ember binary install <tool>@<version> --from-path <path>` registers a
    /// binary with its blake3 content hash in `~/.ember/binaries/manifest.toml`.
    Binary {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Construct binary signing (sign, verify).
    ///
    /// `ember construct sign` produces a JSON sidecar at `<binary>.sig` with
    /// a blake3 content hash + Ed25519 publisher signature per
    /// `docs/construct-signing-pipeline.md`.
    Construct {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Quit the interactive shell.
    #[command(alias = "exit", alias = "q")]
    Quit,
    /// Anything not enumerated above. Falls through to the legacy tokenizer.
    #[command(external_subcommand)]
    Legacy(Vec<String>),
}

impl Cmd {
    /// Re-serialize this variant back into the space-separated string shape
    /// that [`crate::DemoApp::handle_command`] expects.
    pub fn to_legacy_string(&self) -> String {
        let (head, rest): (&str, &[String]) = match self {
            Cmd::Status { rest } => ("status", rest),
            Cmd::ShellHelp { rest } => ("help", rest),
            Cmd::Init { rest } => ("init", rest),
            Cmd::Invite { rest } => ("invite", rest),
            Cmd::Reset { rest } => ("reset", rest),
            Cmd::Inspect { rest } => ("inspect", rest),
            Cmd::Compare { rest } => ("compare", rest),
            Cmd::Show { rest } => ("show", rest),
            Cmd::List { rest } => ("list", rest),
            Cmd::Broker { rest } => ("broker", rest),
            Cmd::Trust { rest } => ("trust", rest),
            Cmd::Message { rest } => ("message", rest),
            Cmd::Messages { rest } => ("messages", rest),
            Cmd::Disclosures { rest } => ("disclosures", rest),
            Cmd::Disclosure { rest } => ("disclosure", rest),
            Cmd::Disclose { rest } => ("disclose", rest),
            Cmd::Content { rest } => ("content", rest),
            Cmd::Recovery { rest } => ("recovery", rest),
            Cmd::Claim { rest } => ("claim", rest),
            Cmd::Service { rest } => ("service", rest),
            Cmd::Passkey { rest } => ("passkey", rest),
            Cmd::Import { rest } => ("import", rest),
            Cmd::Vault { rest } => ("vault", rest),
            Cmd::Grant { rest } => ("grant", rest),
            Cmd::Grants { rest } => ("grants", rest),
            Cmd::Approval { rest } => ("approval", rest),
            Cmd::Badge { rest } => ("badge", rest),
            Cmd::Credential { rest } => ("credential", rest),
            Cmd::Storage { rest } => ("storage", rest),
            Cmd::Sync { rest } => ("sync", rest),
            Cmd::State { rest } => ("state", rest),
            Cmd::Keys { rest } => ("keys", rest),
            Cmd::Root { rest } => ("root", rest),
            Cmd::Roots { rest } => ("roots", rest),
            Cmd::Device { rest } => ("device", rest),
            Cmd::Devices { rest } => ("devices", rest),
            Cmd::Persona { rest } => ("persona", rest),
            Cmd::Personas { rest } => ("personas", rest),
            Cmd::All { rest } => ("all", rest),
            Cmd::CreateRoot { rest } => ("create-root", rest),
            Cmd::CreatePersona { rest } => ("create-persona", rest),
            Cmd::ExportEvents { rest } => ("export-events", rest),
            Cmd::ImportEvents { rest } => ("import-events", rest),
            Cmd::Audit { rest } => ("audit", rest),
            Cmd::Binary { rest } => ("binary", rest),
            Cmd::Construct { rest } => ("construct", rest),
            Cmd::Quit => return "quit".to_string(),
            Cmd::Legacy(tokens) => {
                return tokens.join(" ");
            }
        };
        if rest.is_empty() {
            head.to_string()
        } else {
            format!("{} {}", head, rest.join(" "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn args_parses_top_level_help() {
        // `--help` aborts with `0`, so we use `try_parse_from` to inspect the error kind.
        let err = Args::try_parse_from(["emberlink-cli", "--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn args_parses_subcommand_help() {
        let err = Args::try_parse_from(["emberlink-cli", "approval", "--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn approval_round_trips_to_legacy_string() {
        let args = Args::try_parse_from([
            "emberlink-cli",
            "approval",
            "approve",
            "appr-1",
            "--no-biometric",
        ])
        .unwrap();
        let cmd = args.command.expect("subcommand");
        assert_eq!(cmd.to_legacy_string(), "approval approve appr-1 --no-biometric");
    }

    #[test]
    fn grant_create_round_trips_to_legacy_string() {
        let args = Args::try_parse_from([
            "emberlink-cli",
            "grant",
            "create",
            "--persona",
            "persona-professional",
            "--recipient",
            "agent-x",
            "--kind",
            "peer",
            "--profile",
            "agent",
            "--mode",
            "standing",
            "--cap",
            "read_credential:obj-1",
        ])
        .unwrap();
        let cmd = args.command.expect("subcommand");
        let expected = "grant create --persona persona-professional --recipient agent-x \
                        --kind peer --profile agent --mode standing --cap read_credential:obj-1";
        assert_eq!(cmd.to_legacy_string(), expected);
    }

    #[test]
    fn list_devices_round_trips() {
        let args = Args::try_parse_from(["emberlink-cli", "list", "devices"]).unwrap();
        let cmd = args.command.expect("subcommand");
        assert_eq!(cmd.to_legacy_string(), "list devices");
    }

    #[test]
    fn show_broker_disclose_links_round_trips() {
        let args =
            Args::try_parse_from(["emberlink-cli", "show", "broker", "--disclose-links"]).unwrap();
        let cmd = args.command.expect("subcommand");
        assert_eq!(cmd.to_legacy_string(), "show broker --disclose-links");
    }

    #[test]
    fn unknown_subcommand_falls_through_to_legacy() {
        let args = Args::try_parse_from(["emberlink-cli", "totally-unknown", "foo", "bar"]).unwrap();
        let cmd = args.command.expect("subcommand");
        assert_eq!(cmd.to_legacy_string(), "totally-unknown foo bar");
    }

    #[test]
    fn quit_serializes() {
        let args = Args::try_parse_from(["emberlink-cli", "quit"]).unwrap();
        let cmd = args.command.expect("subcommand");
        assert_eq!(cmd.to_legacy_string(), "quit");
    }

    #[test]
    fn no_subcommand_means_repl() {
        let args = Args::try_parse_from(["emberlink-cli"]).unwrap();
        assert!(args.command.is_none());
    }

    #[test]
    fn no_demo_flag_is_global() {
        let args = Args::try_parse_from(["emberlink-cli", "--no-demo"]).unwrap();
        assert!(args.no_demo);
        assert!(args.command.is_none());
    }

    #[test]
    fn state_flag_is_global() {
        let args = Args::try_parse_from([
            "emberlink-cli",
            "--state",
            "/tmp/x.tsv",
            "show",
            "broker",
        ])
        .unwrap();
        assert_eq!(args.state, Some(PathBuf::from("/tmp/x.tsv")));
        let cmd = args.command.expect("subcommand");
        assert_eq!(cmd.to_legacy_string(), "show broker");
    }

    #[test]
    fn args_command_factory_is_well_formed() {
        // Compile-time-ish assertion: clap can build the command graph.
        let _ = Args::command();
    }

    #[test]
    fn json_flag_selects_json_mode() {
        let args =
            Args::try_parse_from(["emberlink-cli", "--json", "grant", "list"]).unwrap();
        assert!(args.json);
        assert_eq!(args.output_mode(), output::Mode::Json);
    }

    #[test]
    fn quiet_flag_selects_quiet_mode() {
        let args =
            Args::try_parse_from(["emberlink-cli", "--quiet", "grant", "list"]).unwrap();
        assert!(args.quiet);
        assert_eq!(args.output_mode(), output::Mode::Quiet);
    }

    #[test]
    fn json_wins_over_quiet() {
        let args = Args::try_parse_from([
            "emberlink-cli",
            "--json",
            "--quiet",
            "grant",
            "list",
        ])
        .unwrap();
        assert_eq!(args.output_mode(), output::Mode::Json);
    }

    #[test]
    fn color_never_disables_ansi() {
        let args = Args::try_parse_from([
            "emberlink-cli",
            "--color",
            "never",
            "grant",
            "list",
        ])
        .unwrap();
        assert_eq!(args.output_mode(), output::Mode::Human { color: false });
    }

    #[test]
    fn color_always_enables_ansi() {
        let args = Args::try_parse_from([
            "emberlink-cli",
            "--color",
            "always",
            "grant",
            "list",
        ])
        .unwrap();
        assert_eq!(args.output_mode(), output::Mode::Human { color: true });
    }

    #[test]
    fn color_default_is_auto() {
        let args = Args::try_parse_from(["emberlink-cli", "grant", "list"]).unwrap();
        assert_eq!(args.color, ColorMode::Auto);
    }
}
