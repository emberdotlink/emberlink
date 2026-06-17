//! Emit `EMBERLINK_GIT_SHA` + `EMBERLINK_BUILD_TIMESTAMP` env vars for `env!()`
//! consumption in `runtime.rs`, plus enforce compile-time gates against
//! test-substrate leaking into release artifacts.
//!
//! CLI-VERSION-FLAG: the daemon startup log line records both so a stale
//! binary running against a newer codebase (the implementation-note-117
//! root cause) is identifiable in seconds.
//!
//! See `crates/emberlink-cli/build.rs` for the same algorithm — duplicated
//! verbatim because rust workspace build scripts cannot share code without
//! a separate helper crate. The duplication is small enough that diverging
//! is cheaper than introducing a `core-buildinfo` crate.
//!
//! ## Compile-time release-profile gates
//!
//! 1. **`implementation-note-7`** (Cluster D D1, design review
//!    20260513-122447) — refuses a release build with the `qa-mock`
//!    feature enabled. `qa-mock` exposes test substrate (MockBroker,
//!    mock fixtures, test helpers) that must never ship in release
//!    artifacts. Triggered when `CARGO_FEATURE_QA_MOCK` is set AND
//!    `EMBER_RELEASE=1`.
//!
//! 2. **`implementation-note-118`** (Tier A §A3,
//!    audit 2026-06-14) — refuses a release build whose source
//!    tree still carries live (i.e. not-`cfg(test)`-gated, not-doc,
//!    not-deprecation-warn) runtime checks for the test-mode env vars
//!    `EMBER_VAULT_MOCK` / `EMBER_VAULT_DEV_MODE`. An attacker who
//!    controls the operator shell environment can otherwise flip a
//!    release daemon into mock-vault behaviour by setting those
//!    variables. The gate is triggered when `EMBER_BUILD_PROFILE=release`.
//!    Mirrors the qa-mock precedent above (compile-time refuse, not a
//!    runtime checkpoint — runtime sentinels are deletable, build.rs
//!    panics are structural).
//!
//!    The gate also emits `--cfg=ember_release` so follow-up cleanup
//!    PRs can add `#[cfg(not(ember_release))]` attributes to gate the
//!    runtime checks out of the release binary entirely. Today the
//!    gate's role is purely refusal: any new unguarded test-mode
//!    env-var check added in the future will fail the release build.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // === implementation-note-7 ============================================
    // Refuse to compile a release-binary build that also enabled the qa-mock
    // feature. The intent is "qa-mock exposes test substrate; release
    // artifacts must never carry it." Operators who want a staging build with
    // test helpers should set qa-mock and OMIT EMBER_RELEASE; production-
    // shipping pipelines set EMBER_RELEASE=1 and the daemon's CI gate refuses
    // any binary that came in via the qa-mock path. Production checkpoint
    // approaches were rejected (runtime-deletable); the build.rs panic is the
    // structural gate.
    let qa_mock_on = std::env::var_os("CARGO_FEATURE_QA_MOCK").is_some();
    let ember_release = std::env::var("EMBER_RELEASE").as_deref() == Ok("1");
    if qa_mock_on && ember_release {
        panic!(
            "implementation-note-7: refusing to build ember-daemon with \
             `qa-mock` feature enabled AND EMBER_RELEASE=1. The qa-mock \
             feature exposes test substrate (MockBroker, mock fixtures, \
             test helpers) that MUST NOT ship in release artifacts. Either \
             drop the qa-mock feature for the release build, or unset \
             EMBER_RELEASE for a staging build."
        );
    }
    println!("cargo:rerun-if-env-changed=EMBER_RELEASE");

    // === implementation-note-118 ==========================
    // Anchor: EMBER_BUILD_PROFILE. Closes Tier A §A3.
    //
    // Refuses a release build whose source tree still carries live runtime
    // checks for the test-mode env vars EMBER_VAULT_MOCK / EMBER_VAULT_DEV_MODE.
    // "Live" means: not inside a `#[cfg(test)]` block, not in a doc comment,
    // not inside a `tracing::warn!(` deprecation arm, not in a `tests/`
    // subdirectory. Mirrors the qa-mock precedent above.
    //
    // Also emits `--cfg=ember_release` so follow-up cleanup PRs can layer
    // `#[cfg(not(ember_release))]` over the runtime checks, dropping them
    // from the release binary entirely. Per ADR doctrine "no placeholder
    // crypto/no runtime sentinels for security gates" — the panic is the
    // structural gate.
    println!("cargo:rerun-if-env-changed=EMBER_BUILD_PROFILE");
    println!("cargo:rustc-check-cfg=cfg(ember_release)");
    let build_profile = std::env::var("EMBER_BUILD_PROFILE").unwrap_or_default();
    if build_profile == "release" {
        println!("cargo:rustc-cfg=ember_release");

        let crate_src = PathBuf::from(env_or("CARGO_MANIFEST_DIR", ".")).join("src");
        let violations = scan_for_unguarded_test_mode_env_vars(&crate_src);
        if !violations.is_empty() {
            let mut msg = String::from(
                "implementation-note-118: refusing to \
                 build ember-daemon with EMBER_BUILD_PROFILE=release while \
                 the source tree still carries live runtime checks for the \
                 test-mode env vars EMBER_VAULT_MOCK / EMBER_VAULT_DEV_MODE.\n\
                 \n\
                 Tier A §A3 of the audit (2026-06-14) requires these \
                 checks to be structurally absent from release artifacts so \
                 an attacker who controls the operator shell environment \
                 cannot flip the daemon into mock-vault behaviour.\n\
                 \n\
                 Gate the offending check with `#[cfg(not(ember_release))]` \
                 (the `ember_release` cfg flag is set by this build.rs only \
                 under EMBER_BUILD_PROFILE=release) or move it inside an \
                 existing `#[cfg(test)]` block.\n\
                 \n\
                 Offending lines:\n",
            );
            for v in &violations {
                msg.push_str(&format!("  - {}:{}: {}\n", v.path, v.line, v.snippet));
            }
            panic!("{msg}");
        }
    }

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
    println!("cargo:rerun-if-changed=src");
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// One unguarded test-mode env-var reference detected by the scanner.
#[derive(Debug, PartialEq, Eq)]
struct Violation {
    path: String,
    line: usize,
    snippet: String,
}

/// The forbidden env-var literals. Lifted into a constant so the
/// constants themselves can be matched without the scanner triggering on
/// its own definition (the constant strings are split below).
const FORBIDDEN_NEEDLES: &[&str] = &[
    // Strings constructed at runtime via concat!() so they don't appear as
    // contiguous literals in this build script's own source — keeps the
    // scanner from matching itself when the source tree is scanned by
    // anything else.
    concat!("EMBER", "_VAULT_MOCK"),
    concat!("EMBER", "_VAULT_DEV_MODE"),
];

/// Recursively scan `dir` for `*.rs` files that contain `env::var("FOO")`
/// where FOO is one of the forbidden test-mode env vars and the surrounding
/// context is not one of the allowed safe contexts (doc comments,
/// `#[cfg(test)]` blocks, `tracing::warn!` deprecation arms, or test
/// modules nested under a `mod tests` heading).
fn scan_for_unguarded_test_mode_env_vars(dir: &Path) -> Vec<Violation> {
    let mut out = Vec::new();
    let files = collect_rs_files(dir);
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let rel = path
            .strip_prefix(dir)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path.display().to_string());
        scan_file(&rel, &text, &mut out);
    }
    out
}

fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(read) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in read.flatten() {
        let p = entry.path();
        if p.is_dir() {
            out.extend(collect_rs_files(&p));
        } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(p);
        }
    }
    out
}

fn scan_file(rel_path: &str, text: &str, out: &mut Vec<Violation>) {
    // Track whether we're currently inside a `#[cfg(test)]`-gated module
    // by counting brace depth from the most recent cfg(test) attribute on
    // a `mod` declaration. A precise Rust parser is overkill here — the
    // scanner is allowed false-negatives (missing a violation in obscure
    // syntax) but should not false-positive on the well-understood
    // patterns currently in the ember-daemon source tree.
    let lines: Vec<&str> = text.lines().collect();
    let cfg_test_depths = compute_cfg_test_module_depths(&lines);
    let warn_arm_ranges = compute_tracing_warn_ranges(&lines);

    for (idx, raw_line) in lines.iter().enumerate() {
        let line = *raw_line;
        let trimmed = line.trim_start();
        // Skip pure doc / comment lines.
        if trimmed.starts_with("//") {
            continue;
        }
        let Some(needle) = FORBIDDEN_NEEDLES.iter().find(|n| line.contains(**n)) else {
            continue;
        };
        // Require the match to be the *argument of an env::var call* rather
        // than a free-floating mention (e.g. in a string used for a
        // tracing::warn! message). The shape we care about is the
        // syntactic `env::var("EMBER_VAULT_MOCK"`-style call site.
        if !line.contains("env::var") {
            continue;
        }
        // Allow `cfg!(test)`-gated test modules.
        if cfg_test_depths[idx] {
            continue;
        }
        // Allow `tracing::warn!` deprecation arms (the v0.3 deprecation
        // warnings in `runtime.rs` mention the env-var name but do not
        // act on the value — they fire as soon as the var is set, with
        // no behaviour change).
        if warn_arm_ranges[idx] {
            continue;
        }
        // Allow `is_cargo_test_binary()` companion checks within a
        // `cfg!(test)` short-circuit on the same line — these are the
        // existing in-tree gates that always disable themselves in a
        // release binary (no `cfg!(test)` and no cargo-test binary path).
        // We still flag the env::var match because the env-var read is
        // reachable in release.
        let _ = needle;
        out.push(Violation {
            path: rel_path.to_string(),
            line: idx + 1,
            snippet: line.trim().to_string(),
        });
    }
}

/// For each line, return `true` if that line sits inside a module that
/// was declared with `#[cfg(test)]` (or nested under one).
fn compute_cfg_test_module_depths(lines: &[&str]) -> Vec<bool> {
    let mut out = vec![false; lines.len()];
    // Stack of (open_depth_at_entry, is_cfg_test). Track brace depth as we
    // go; when we see `#[cfg(test)]` immediately above a `mod NAME {`, mark
    // the enclosing scope as cfg(test) until its matching close brace.
    let mut depth: i32 = 0;
    let mut active: Vec<(i32, bool)> = Vec::new();
    let mut pending_cfg_test = false;
    for (idx, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        // Detect `#[cfg(test)]` attribute on its own line — the standard
        // form across the ember-daemon source tree.
        if line.starts_with("#[cfg(test)") || line == "#[cfg(test)]" {
            pending_cfg_test = true;
        }
        // Walk the characters to update brace depth and detect module-open.
        // Heuristic: a line like `mod tests {` with pending_cfg_test=true
        // pushes a new cfg(test) scope.
        let opens = raw.chars().filter(|c| *c == '{').count() as i32;
        let closes = raw.chars().filter(|c| *c == '}').count() as i32;
        let line_starts_module = line.starts_with("mod ") || line.starts_with("pub mod ");
        // Determine whether this line is inside any active cfg(test) scope.
        let inside_cfg_test = active.iter().any(|(_d, t)| *t);
        out[idx] = inside_cfg_test;

        // Apply opens then closes for this line.
        for _ in 0..opens {
            depth += 1;
            // Each opening brace on this line corresponds to a new scope.
            // Only the FIRST opening brace on the line counts as the
            // candidate "mod {" if line_starts_module is true.
            let is_cfg_test_scope = line_starts_module && pending_cfg_test;
            active.push((depth, is_cfg_test_scope));
            if line_starts_module && pending_cfg_test {
                // Once consumed, drop the pending flag.
                pending_cfg_test = false;
            }
        }
        for _ in 0..closes {
            if let Some((open_depth, _)) = active.last()
                && *open_depth == depth
            {
                active.pop();
            }
            depth -= 1;
        }
        // Clear pending cfg(test) if the next line wasn't a `mod`.
        // (cfg(test) only carries forward one logical line.)
        if !line_starts_module
            && !line.starts_with("#[cfg(test)")
            && line != "#[cfg(test)]"
            && !line.is_empty()
        {
            // Allow blank lines between attribute and mod declaration —
            // but if a non-attribute, non-blank line intervenes, drop the
            // pending flag.
            if !line.starts_with('#') {
                pending_cfg_test = false;
            }
        }
    }
    out
}

/// Mark lines that fall inside the body of a `tracing::warn!(...)` macro
/// call (or `tracing::error!`, etc. — any `tracing::warn!(` opener that
/// runs to a closing `);`). The deprecation arms in `runtime.rs` look
/// like:
///
/// ```ignore
/// if std::env::var("EMBER_VAULT_MOCK").is_ok() {
///     tracing::warn!(
///         "deprecated: EMBER_VAULT_MOCK is replaced by ..."
///     );
/// }
/// ```
///
/// We allow the `env::var` line because the deprecation is a no-op WARN
/// (the value is not consumed for behaviour). The classifier marks the
/// `if std::env::var(...)` line as "warn-arm" when the immediately
/// following non-blank, non-comment line opens a `tracing::warn!` /
/// `tracing::error!` macro inside the if-body. design deprecation
/// pattern.
fn compute_tracing_warn_ranges(lines: &[&str]) -> Vec<bool> {
    let mut out = vec![false; lines.len()];
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !trimmed.contains("env::var") {
            continue;
        }
        // Peek ahead to the first non-blank, non-comment line. If it
        // opens a `tracing::warn!` / `tracing::error!` / `tracing::debug!`
        // / `tracing::info!` macro, classify as a deprecation warn arm.
        let mut j = idx + 1;
        while j < lines.len() {
            let next = lines[j].trim();
            j += 1;
            if next.is_empty() || next.starts_with("//") {
                continue;
            }
            if next.starts_with("tracing::warn!")
                || next.starts_with("tracing::error!")
                || next.starts_with("tracing::debug!")
                || next.starts_with("tracing::info!")
            {
                // Confirm this is a deprecation-style warn arm: the macro
                // body must mention "deprecated" within the next ~6 lines.
                let mut k = j;
                let mut found_deprecated = false;
                let mut span = 0;
                while k < lines.len() && span < 8 {
                    if lines[k].contains("deprecated") {
                        found_deprecated = true;
                        break;
                    }
                    if lines[k].contains(");") {
                        break;
                    }
                    k += 1;
                    span += 1;
                }
                if found_deprecated {
                    out[idx] = true;
                }
                break;
            }
            // First non-blank/non-comment line is not a tracing macro:
            // the env::var call drives behaviour. Not a deprecation arm.
            break;
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_flags_unguarded_env_var_check() {
        let src = "fn foo() {\n    if std::env::var(\"EMBER_VAULT_MOCK\").is_ok() {\n        do_thing();\n    }\n}\n";
        let mut out = Vec::new();
        scan_file("test.rs", src, &mut out);
        assert_eq!(out.len(), 1, "expected one violation, got {out:?}");
        assert_eq!(out[0].line, 2);
    }

    #[test]
    fn scanner_skips_doc_comment_mentions() {
        let src = "/// EMBER_VAULT_MOCK is the legacy env var.\nfn foo() {}\n";
        let mut out = Vec::new();
        scan_file("test.rs", src, &mut out);
        assert!(out.is_empty(), "doc comment should not trigger: {out:?}");
    }

    #[test]
    fn scanner_skips_cfg_test_module() {
        let src = "#[cfg(test)]\nmod tests {\n    fn bar() {\n        std::env::var(\"EMBER_VAULT_MOCK\").ok();\n    }\n}\n";
        let mut out = Vec::new();
        scan_file("test.rs", src, &mut out);
        assert!(out.is_empty(), "cfg(test) mod should not trigger: {out:?}");
    }

    #[test]
    fn scanner_skips_tracing_warn_deprecation_arm() {
        let src = "fn foo() {\n    if std::env::var(\"EMBER_VAULT_MOCK\").is_ok() {\n        tracing::warn!(\n            \"deprecated: EMBER_VAULT_MOCK is replaced by EMBER_TRUST_ROOTS\"\n        );\n    }\n}\n";
        let mut out = Vec::new();
        scan_file("test.rs", src, &mut out);
        assert!(
            out.is_empty(),
            "tracing::warn! deprecation arm should not trigger: {out:?}"
        );
    }

    #[test]
    fn scanner_flags_dev_mode_too() {
        let src = "fn foo() {\n    let v = std::env::var(\"EMBER_VAULT_DEV_MODE\").ok();\n    let _ = v;\n}\n";
        let mut out = Vec::new();
        scan_file("test.rs", src, &mut out);
        assert_eq!(out.len(), 1);
    }
}
