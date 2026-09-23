//! ProductBase authority daemon entrypoint.

use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut state_dir = default_state_dir();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--state-dir" => {
                let Some(value) = args.next() else {
                    fail("--state-dir requires a path");
                };
                state_dir = PathBuf::from(value);
            }
            "--help" | "-h" => {
                println!("usage: emberd [--state-dir <path>]");
                return;
            }
            _ => fail(&format!("unknown argument: {argument}")),
        }
    }
    if let Err(error) = ember_daemon::productbase_s4::run(&state_dir) {
        fail(&error);
    }
}

fn default_state_dir() -> PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(ember_authority::AUTHORITY_STATE_DIRECTORY)
}

fn fail(message: &str) -> ! {
    eprintln!("emberd: {message}");
    std::process::exit(1)
}
