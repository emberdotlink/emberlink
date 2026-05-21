//! Emit `EMBERLINK_GIT_SHA` + `EMBERLINK_BUILD_TIMESTAMP` env vars for `env!()`
//! consumption in `runtime.rs`.
//!
//! CLI-VERSION-FLAG: the daemon startup log line records both so a stale
//! binary running against a newer codebase (the implementation-note-116
//! root cause) is identifiable in seconds.
//!
//! See `crates/emberlink-cli/build.rs` for the same algorithm — duplicated
//! verbatim because rust workspace build scripts cannot share code without
//! a separate helper crate. The duplication is small enough that diverging
//! is cheaper than introducing a `core-buildinfo` crate.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // implementation-note-5 (Cluster D D1, design review 20260513-122447):
    // refuse to compile a release-binary build that also enabled the
    // qa-mock feature. The intent is "qa-mock exposes test substrate;
    // release artifacts must never carry it." Operators who want a
    // staging build with test helpers should set qa-mock and OMIT
    // EMBER_RELEASE; production-shipping pipelines set EMBER_RELEASE=1
    // and the daemon's CI gate refuses any binary that came in via
    // the qa-mock path. Production checkpoint approaches were rejected
    // (runtime-deletable); the build.rs panic is the structural gate.
    let qa_mock_on = std::env::var_os("CARGO_FEATURE_QA_MOCK").is_some();
    let ember_release = std::env::var("EMBER_RELEASE").as_deref() == Ok("1");
    if qa_mock_on && ember_release {
        panic!(
            "implementation-note-5: refusing to build ember-daemon with \
             `qa-mock` feature enabled AND EMBER_RELEASE=1. The qa-mock \
             feature exposes test substrate (MockBroker, mock fixtures, \
             test helpers) that MUST NOT ship in release artifacts. Either \
             drop the qa-mock feature for the release build, or unset \
             EMBER_RELEASE for a staging build."
        );
    }
    println!("cargo:rerun-if-env-changed=EMBER_RELEASE");

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

    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
}

fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_iso8601(secs)
}

fn format_iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day / 60) % 60;
    let second = secs_of_day % 60;

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
