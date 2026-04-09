use std::env;
use std::io::{self, Write};
use std::path::PathBuf;

use emberlink_cli::DemoApp;

fn main() {
    let options = parse_launch_args(env::args().skip(1).collect());
    let mut app = if options.no_demo {
        let path = options
            .state_file
            .unwrap_or_else(|| PathBuf::from(".emberlink/local-state.tsv"));
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

    if let Some(screen) = options.command.first() {
        print!("{}", render_screen(&mut app, screen, &options.command[1..]));
        return;
    }

    println!("Emberlink shell. Run `help` for commands.");
    interactive_loop(&mut app);
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
}
