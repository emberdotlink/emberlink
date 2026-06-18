//! `ember demo wedge` — 60-second canned fallback demo for friendly devs.
//!
//! Per ADR 120 §8 (Day-2 ask Touch 1 fallback): thin wrapper around
//! `qember.sh demo up/down`. Does NOT reimplement demo machinery.

use std::process::Command;

/// Run the demo wedge fallback scenario (or tear it down).
///
/// `teardown = false`: shells `qember.sh demo up`, then prints friendly-dev
/// next-step instructions.
///
/// `teardown = true`: shells `qember.sh demo down` and prints a confirmation.
///
/// Non-zero exit from `qember.sh` surfaces stderr and returns an error.
pub fn cmd_demo_wedge(teardown: bool) -> Result<(), Box<dyn std::error::Error>> {
    let script = locate_qember_sh()?;

    if teardown {
        run_qember(&script, &["demo", "down"])?;
        println!("ember demo wedge: demo environment torn down.");
    } else {
        run_qember(&script, &["demo", "up"])?;
        println!();
        println!("Demo environment is ready. Next steps:");
        println!();
        println!("  1. Open Claude Code in a new terminal.");
        println!("  2. Attempt a `git push` on the seeded project repo.");
        println!("     (The ember proxy intercepts it and raises an approval request.)");
        println!("  3. Open the ember dashboard — the approval popup fires automatically.");
        println!("  4. Approve the request in the dashboard; watch the Grant Receipt issued.");
        println!();
        println!("Run `ember demo wedge --teardown` to clean up when done.");
    }

    Ok(())
}

/// Locate `qember.sh` relative to the repository root, or fall back to the
/// path the script installs itself into when running inside the repo tree.
///
/// Resolution order:
///   1. `$EMBER_REPO_ROOT/.claude/scripts/qember.sh` (set by the harness or CI)
///   2. Walk from `argv[0]` up until we find `.claude/scripts/qember.sh`
///   3. Hard-coded repo-relative path used by autopilot workers
fn locate_qember_sh() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    // 1. Explicit override.
    if let Ok(root) = std::env::var("EMBER_REPO_ROOT") {
        let candidate = std::path::PathBuf::from(root)
            .join(".claude")
            .join("scripts")
            .join("qember.sh");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // 2. Walk from cwd upward.
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = cwd.as_path();
        loop {
            let candidate = dir.join(".claude").join("scripts").join("qember.sh");
            if candidate.exists() {
                return Ok(candidate);
            }
            match dir.parent() {
                Some(p) => dir = p,
                None => break,
            }
        }
    }

    Err("could not locate .claude/scripts/qember.sh — set EMBER_REPO_ROOT to the repo root".into())
}

fn run_qember(script: &std::path::Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("bash")
        .arg(script)
        .args(args)
        .output()
        .map_err(|e| format!("failed to spawn qember.sh: {e}"))?;

    // Mirror stdout + stderr to our own streams so the caller sees live output.
    if !output.stdout.is_empty() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "qember.sh {} exited with status {}",
            args.join(" "),
            output.status
        )
        .into())
    }
}
