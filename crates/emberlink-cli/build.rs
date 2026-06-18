//! Emit `EMBERLINK_GIT_SHA` + `EMBERLINK_BUILD_TIMESTAMP` env vars for `env!()`
//! consumption in the `ember` binary.
//!
//! CLI-VERSION-FLAG: `ember --version` and the daemon startup log line both
//! source these so a stale binary is identifiable in seconds.
//!
//! - Git SHA is read via `git rev-parse --short HEAD`. Any failure (e.g.
//!   release tarball without `.git/`, missing git binary) falls back to the
//!   literal `(no-git)` so the build never breaks on environments without
//!   a working repo.
//! - Build timestamp is `SystemTime::now()` rendered as RFC 3339.
//! - `cargo:rerun-if-changed=.git/HEAD` triggers a rebuild when the SHA
//!   changes (commit, checkout). Without this the env var would stick at
//!   the value baked into the cached build script output.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "(no-git)".to_string());

    println!("cargo:rustc-env=EMBERLINK_GIT_SHA={sha}");
    println!(
        "cargo:rustc-env=EMBERLINK_BUILD_TIMESTAMP={}",
        iso8601_now()
    );

    // Rebuild when HEAD or the active branch ref moves. Both files must be
    // listed: `.git/HEAD` is the symbolic-ref pointer, and the file it points
    // to is what actually changes on a `git commit`.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
}

/// Render the current wall-clock time as RFC 3339 in UTC.
///
/// We avoid pulling `chrono` into `[build-dependencies]` for this single
/// formatting need — the CLI already depends on `chrono` at runtime, but
/// adding it to the build deps would slow cold-build by ~hundreds of ms.
fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_iso8601(secs)
}

/// Convert seconds since the Unix epoch to `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Hand-rolled because pulling `chrono` into build-deps for this is overkill.
/// Algorithm: standard civil-from-days (Howard Hinnant) — exact for any
/// 64-bit unix timestamp without leap-second handling. Good enough for a
/// build-time stamp that's only consumed by humans grepping logs.
fn format_iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day / 60) % 60;
    let second = secs_of_day % 60;

    // Civil-from-days. `z` is days since 1970-01-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}
