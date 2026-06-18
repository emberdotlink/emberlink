//! CLASSIFICATION: PUBLIC
//!
//! Delegation template listing + interactive selector (META-PREGRANT-LAUNCHER-PROMPT-UX-B).
//!
//! `ember claude` is the canonical launcher (ADR 157 §Component 6;
//! ADR 158 §Component 1). When the operator runs the launcher without an
//! explicit workflow-template override, this module lists every bundled and
//! overlay delegation template, prints a numbered menu of
//! `name — description (TTL, scopes summary)`, and reads a stdin selection.
//! The selected `TemplateMeta` is what the launcher uses to drive the
//! daemon's session-open: per ADR 205 §6 the template's authority is
//! lowered into the runtime persona's `StandingGrant` (Touch ID + atomic
//! session-open lands in subtask C; this slice is just the list-and-pick UX).
//!
//! Templates live in two roots:
//!
//! - **Bundled** — `<install_root>/delegation-templates/*.toml`. Prod
//!   `install_root` is `/usr/local/lib/ember/`; dev is
//!   `/usr/local/lib/ember-dev/` (per ADR 157 §Component 3). In dev /
//!   worktree builds the bundled set ships from
//!   `crates/emberlink-cli/delegation-templates/`.
//! - **Overlay** — `~/.config/emberlink/delegation-templates/*.toml`. Operator
//!   overrides; an overlay entry whose `name` matches a bundled entry
//!   replaces the bundled one.
//!
//! The selector pre-selects the operator's last-used workflow when one is
//! cached at `~/.config/emberlink/last-delegation.toml`. The cache is
//! best-effort UX polish — missing or corrupt entries degrade to the first
//! template in the list (alphabetical), so a launch never fails on cache
//! state.
//!
//! Sentinels: `pregrant_delegation_prompt_landed`,
//! `pregrant_last_used_cache_landed`.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use core_event_types::ActionRefPattern;
use serde::Deserialize;
use thiserror::Error;

/// Maximum number of scopes rendered in the selector preview before the
/// remainder collapse to a `+N more` indicator.
const SCOPE_PREVIEW_MAX: usize = 5;

/// Display struct produced by [`list_templates`]. Carries only the bits the
/// selector renders — the launcher re-loads the full TOML once the operator
/// picks one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateMeta {
    /// Workflow name (matches the `name` key in the TOML). Used as the
    /// Explicit workflow-template name and persisted as the delegation grant's
    /// `template_name`.
    pub name: String,
    /// Operator-facing one-liner from the TOML `description` field.
    pub title: String,
    /// TTL ceiling in seconds parsed from the TOML `ttl` field.
    pub ttl_secs: u64,
    /// Comma-joined preview of the first [`SCOPE_PREVIEW_MAX`] scopes; the
    /// remainder collapse to `+N more`. Empty string when the template has
    /// no scopes (currently impossible per cohort A template authoring).
    pub scope_summary: String,
}

/// Errors surfaced by listing + parsing template files.
#[derive(Debug, Error)]
pub enum DelegationPromptError {
    #[error("template I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("template parse error at {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error(
        "unparseable ttl `{value}` in template `{name}` — expected forms `Nh`, `Nm`, `Nd`, `Ns`"
    )]
    Ttl { name: String, value: String },
    #[error("no delegated-authority templates found under {install_root} or operator overlay")]
    NoTemplates { install_root: PathBuf },
    #[error("interactive prompt unavailable (stdin closed or non-interactive)")]
    NotInteractive,
    #[error("operator selection `{input}` is not a valid choice (expected 1..{max})")]
    BadSelection { input: String, max: usize },
}

/// Raw TOML shape — kept private so callers depend only on [`TemplateMeta`].
/// pregrant_delegation_prompt_landed: this anchors the parser checkpoint inside
/// a code path the production reader executes.
#[derive(Deserialize)]
struct TemplateToml {
    name: String,
    #[serde(default)]
    description: Option<String>,
    ttl: String,
    #[serde(default)]
    scopes: Vec<String>,
}

/// Pure parser — accepts the TOML text + a context path for error reporting.
/// Factored out so [`list_templates`] can defer all I/O to one block while
/// the parse-and-validate logic stays unit-testable from in-memory fixtures
/// (no tempdir, no filesystem).
pub fn parse_template(
    toml_str: &str,
    context_path: &Path,
) -> Result<TemplateMeta, DelegationPromptError> {
    let parsed: TemplateToml =
        toml::from_str(toml_str).map_err(|e| DelegationPromptError::Parse {
            path: context_path.to_path_buf(),
            source: e,
        })?;
    let ttl_secs = parse_ttl(&parsed.name, &parsed.ttl)?;
    let scope_summary = render_scope_summary(&parsed.scopes);
    let title = parsed.description.unwrap_or_else(|| parsed.name.clone());
    Ok(TemplateMeta {
        name: parsed.name,
        title,
        ttl_secs,
        scope_summary,
    })
}

fn parse_ttl(name: &str, ttl: &str) -> Result<u64, DelegationPromptError> {
    let trimmed = ttl.trim();
    if trimmed.is_empty() {
        return Err(DelegationPromptError::Ttl {
            name: name.to_string(),
            value: ttl.to_string(),
        });
    }
    let (num_part, unit) = trimmed.split_at(trimmed.len() - 1);
    let n: u64 = num_part.parse().map_err(|_| DelegationPromptError::Ttl {
        name: name.to_string(),
        value: ttl.to_string(),
    })?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => {
            return Err(DelegationPromptError::Ttl {
                name: name.to_string(),
                value: ttl.to_string(),
            });
        }
    };
    Ok(secs)
}

fn render_scope_summary(scopes: &[String]) -> String {
    if scopes.is_empty() {
        return String::new();
    }
    let preview: Vec<String> = scopes
        .iter()
        .take(SCOPE_PREVIEW_MAX)
        .map(|scope| compact_scope_string(scope))
        .collect();
    let joined = preview.join(", ");
    if scopes.len() > SCOPE_PREVIEW_MAX {
        format!("{joined} +{} more", scopes.len() - SCOPE_PREVIEW_MAX)
    } else {
        joined
    }
}

fn compact_scope_string(scope: &str) -> String {
    let Ok(pattern) = ActionRefPattern::parse(scope) else {
        return scope.to_string();
    };
    let Some(tool) = pattern
        .plugin_address
        .strip_prefix("registry.ember.systems/ember-systems/ember-")
    else {
        return scope.to_string();
    };
    if pattern.action_key == "*" {
        return format!("{tool}.*");
    }
    format!("{tool}.{}", pattern.action_key)
}

/// Read every `*.toml` file under `dir` and return the [`TemplateMeta`] for
/// each. Files that fail to parse are surfaced as errors immediately — a
/// silently-skipped malformed template is a configuration-leak class bug
/// (the operator would not see their override take effect).
fn read_template_dir(dir: &Path) -> Result<Vec<TemplateMeta>, DelegationPromptError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => {
            return Err(DelegationPromptError::Io {
                path: dir.to_path_buf(),
                source: e,
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|e| DelegationPromptError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let contents = std::fs::read_to_string(&path).map_err(|e| DelegationPromptError::Io {
            path: path.clone(),
            source: e,
        })?;
        out.push(parse_template(&contents, &path)?);
    }
    Ok(out)
}

/// List every available template — bundled (from `<install_root>/delegation-templates/`)
/// merged with operator overlay (from `~/.config/emberlink/delegation-templates/`).
/// Overlay entries whose `name` matches a bundled entry REPLACE the bundled
/// version. The returned vector is sorted by name for stable rendering.
pub fn list_templates(install_root: &Path) -> Result<Vec<TemplateMeta>, DelegationPromptError> {
    let bundled_dir = install_root.join("delegation-templates");
    let overlay_dir = overlay_template_dir();

    let mut by_name: BTreeMap<String, TemplateMeta> = BTreeMap::new();
    for tmpl in read_template_dir(&bundled_dir)? {
        by_name.insert(tmpl.name.clone(), tmpl);
    }
    if let Some(overlay_dir) = overlay_dir {
        for tmpl in read_template_dir(&overlay_dir)? {
            by_name.insert(tmpl.name.clone(), tmpl);
        }
    }
    if by_name.is_empty() {
        return Err(DelegationPromptError::NoTemplates {
            install_root: install_root.to_path_buf(),
        });
    }
    Ok(by_name.into_values().collect())
}

fn overlay_template_dir() -> Option<PathBuf> {
    dirs_next::config_dir().map(|c| c.join("emberlink").join("delegation-templates"))
}

/// Format the menu the operator sees. Pure so the test suite can snapshot
/// the rendering without a TTY. Each template appears as:
///
///   N) <name> — <title> (TTL <human>, scopes: <scope_summary>)
///
/// where `N` starts at 1 and `<human>` is a compact form of `ttl_secs`
/// (matches the cohort A template wording: 4h / 2h / 1h / 8h).
pub fn render_menu(templates: &[TemplateMeta], default: Option<&str>) -> String {
    let mut s = String::new();
    s.push_str("Choose delegated authority template:\n");
    for (i, t) in templates.iter().enumerate() {
        let marker = match default {
            Some(d) if d == t.name => "* ",
            _ => "  ",
        };
        let n = i + 1;
        let scope_part = if t.scope_summary.is_empty() {
            String::new()
        } else {
            format!(", scopes: {}", t.scope_summary)
        };
        s.push_str(&format!(
            "{marker}{n}) {name} — {title} (TTL {ttl}{scope_part})\n",
            name = t.name,
            title = t.title,
            ttl = render_ttl(t.ttl_secs),
        ));
    }
    if let Some(d) = default {
        s.push_str(&format!("\nDefault template: {d} (press Enter)\n"));
    }
    s
}

fn render_ttl(secs: u64) -> String {
    if secs.is_multiple_of(86_400) {
        format!("{}d", secs / 86_400)
    } else if secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

/// Interactive selection helper used by the launcher (subtask D). Prints the
/// menu via [`render_menu`] to stderr, reads one line of stdin, returns the
/// chosen [`TemplateMeta`]. Empty input with a non-None `default` returns
/// the default. The `Result<TemplateMeta>` return shape (owned, cloned) is
/// intentional — borrow-with-lifetime against the input slice complicated
/// downstream call sites with no real benefit since the launcher only needs
/// one selection per session.
pub fn prompt_for_template(
    templates: &[TemplateMeta],
    default: Option<&str>,
) -> Result<TemplateMeta, DelegationPromptError> {
    if templates.is_empty() {
        return Err(DelegationPromptError::NoTemplates {
            install_root: PathBuf::from("<unknown>"),
        });
    }
    let menu = render_menu(templates, default);
    let stderr = io::stderr();
    let mut handle = stderr.lock();
    let _ = handle.write_all(menu.as_bytes());
    let _ = handle.write_all(b"Selection: ");
    let _ = handle.flush();

    let stdin = io::stdin();
    let mut line = String::new();
    let n = stdin
        .lock()
        .read_line(&mut line)
        .map_err(|_| DelegationPromptError::NotInteractive)?;
    if n == 0 {
        return Err(DelegationPromptError::NotInteractive);
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        if let Some(d) = default
            && let Some(t) = templates.iter().find(|t| t.name == d)
        {
            return Ok(t.clone());
        }
        return Err(DelegationPromptError::BadSelection {
            input: trimmed.to_string(),
            max: templates.len(),
        });
    }
    let idx: usize = trimmed
        .parse()
        .map_err(|_| DelegationPromptError::BadSelection {
            input: trimmed.to_string(),
            max: templates.len(),
        })?;
    if idx == 0 || idx > templates.len() {
        return Err(DelegationPromptError::BadSelection {
            input: trimmed.to_string(),
            max: templates.len(),
        });
    }
    Ok(templates[idx - 1].clone())
}

/// Path to the last-used workflow cache file
/// (`~/.config/emberlink/last-delegation.toml`). Returns `None` when the
/// process has no resolvable config directory (rare — headless container
/// with no `HOME`).
fn last_delegation_cache_path() -> Option<PathBuf> {
    dirs_next::config_dir().map(|c| c.join("emberlink").join("last-delegation.toml"))
}

/// Internal: read the cached workflow name from an explicit path. Factored
/// out so the test suite can exercise corrupt-file + missing-file paths
/// against a tempdir without touching the operator's real config dir.
fn load_last_delegation_from(path: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    #[derive(Deserialize)]
    struct LastUsed {
        name: String,
    }
    let parsed: LastUsed = toml::from_str(&contents).ok()?;
    Some(parsed.name)
}

/// Read the operator's last-selected workflow name from
/// `~/.config/emberlink/last-delegation.toml`. Returns `None` if the file is
/// missing, unreadable, or contains malformed TOML — the cache is
/// best-effort UX polish, never a hard gate. pregrant_last_used_cache_landed.
pub fn load_last_delegation() -> Option<String> {
    let path = last_delegation_cache_path()?;
    load_last_delegation_from(&path)
}

/// Internal: write `name` as the cached workflow at an explicit path using
/// an atomic create-temp-then-rename pattern. `std::fs::rename` is atomic
/// on POSIX when source + destination share a filesystem, so the cache file
/// is either the previous good value or the new value — never a half-written
/// partial. Factored out so the test suite can verify atomicity and
/// idempotency against a tempdir.
fn save_last_delegation_to(path: &Path, name: &str) -> Result<(), DelegationPromptError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| DelegationPromptError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let mut tmp_os = path.as_os_str().to_owned();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);
    let body = format!("name = {:?}\n", name);
    std::fs::write(&tmp_path, body.as_bytes()).map_err(|e| DelegationPromptError::Io {
        path: tmp_path.clone(),
        source: e,
    })?;
    std::fs::rename(&tmp_path, path).map_err(|e| DelegationPromptError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

/// Persist `name` to `~/.config/emberlink/last-delegation.toml`. Silently
/// skips when no config dir is resolvable (headless / no `HOME`). Atomic
/// — a crash mid-write leaves either the previous good cache or no cache
/// file at all. pregrant_last_used_cache_landed.
pub fn save_last_delegation(name: &str) -> Result<(), DelegationPromptError> {
    let Some(path) = last_delegation_cache_path() else {
        return Ok(());
    };
    save_last_delegation_to(&path, name)
}

/// Resolve the menu default: cached name if it still maps to a current
/// template, else the first template alphabetically. Returns `None` only
/// when `templates` is empty (callers already reject that earlier in
/// `prompt_for_template`).
fn resolve_default_name(templates: &[TemplateMeta], cached: Option<String>) -> Option<String> {
    if let Some(name) = cached
        && templates.iter().any(|t| t.name == name)
    {
        return Some(name);
    }
    templates.first().map(|t| t.name.clone())
}

/// Cache-aware wrapper around [`prompt_for_template`]. Pre-selects the
/// operator's last-used workflow (or the first list item if no cache
/// exists or the cached name no longer maps to a template), runs the
/// selector, then persists the chosen template name. Save failures are
/// surfaced as a stderr warning — they never abort the launch.
pub fn prompt_for_template_with_cache(
    templates: &[TemplateMeta],
) -> Result<TemplateMeta, DelegationPromptError> {
    let default = resolve_default_name(templates, load_last_delegation());
    let chosen = prompt_for_template(templates, default.as_deref())?;
    if let Err(e) = save_last_delegation(&chosen.name) {
        let _ = writeln!(
            io::stderr(),
            "warning: failed to persist delegated-authority template cache ({e}); next launch falls back to first-list-item default"
        );
    }
    Ok(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMBERD_DEV: &str = r#"
name = "emberd-development"
description = "Daily emberd development — git, gh, cargo, kubectl, npm"
ttl = "4h"
scopes = [
    "registry.ember.systems/ember-systems/ember-git/*@v1",
    "registry.ember.systems/ember-systems/ember-gh/*@v1",
    "registry.ember.systems/ember-systems/ember-cargo/*@v1",
    "registry.ember.systems/ember-systems/ember-kubectl/*@v1",
    "registry.ember.systems/ember-systems/ember-npm/*@v1",
]
"#;

    const READ_ONLY: &str = r#"
name = "read-only"
description = "Read-only — fetch, log, status, diff"
ttl = "8h"
scopes = [
    "registry.ember.systems/ember-systems/ember-git/fetch@v1",
    "registry.ember.systems/ember-systems/ember-git/log@v1",
    "registry.ember.systems/ember-systems/ember-git/status@v1",
    "registry.ember.systems/ember-systems/ember-git/diff@v1",
]
"#;

    const BAD_TTL: &str = r#"
name = "bogus"
description = "bogus"
ttl = "forever"
scopes = []
"#;

    #[test]
    fn parse_template_emberd_development_in_memory() {
        let m =
            parse_template(EMBERD_DEV, Path::new("/in-memory/emberd-development.toml")).unwrap();
        assert_eq!(m.name, "emberd-development");
        assert_eq!(
            m.title,
            "Daily emberd development — git, gh, cargo, kubectl, npm"
        );
        assert_eq!(m.ttl_secs, 4 * 3600);
        assert_eq!(m.scope_summary, "git.*, gh.*, cargo.*, kubectl.*, npm.*");
    }

    #[test]
    fn parse_template_read_only_4_scopes_no_more_marker() {
        let m = parse_template(READ_ONLY, Path::new("/in-memory/read-only.toml")).unwrap();
        assert_eq!(m.ttl_secs, 8 * 3600);
        assert!(!m.scope_summary.contains("more"));
        assert_eq!(m.scope_summary, "git.fetch, git.log, git.status, git.diff");
    }

    #[test]
    fn parse_template_bad_ttl_returns_ttl_error() {
        let err = parse_template(BAD_TTL, Path::new("/in-memory/bogus.toml")).unwrap_err();
        match err {
            DelegationPromptError::Ttl { name, value } => {
                assert_eq!(name, "bogus");
                assert_eq!(value, "forever");
            }
            other => panic!("expected Ttl error, got {other:?}"),
        }
    }

    #[test]
    fn ttl_parses_each_supported_unit() {
        assert_eq!(parse_ttl("t", "30s").unwrap(), 30);
        assert_eq!(parse_ttl("t", "5m").unwrap(), 300);
        assert_eq!(parse_ttl("t", "2h").unwrap(), 7200);
        assert_eq!(parse_ttl("t", "1d").unwrap(), 86_400);
        assert!(parse_ttl("t", "5x").is_err());
        assert!(parse_ttl("t", "").is_err());
    }

    #[test]
    fn scope_summary_collapses_over_preview_max() {
        let lots: Vec<String> = (0..(SCOPE_PREVIEW_MAX + 3))
            .map(|i| format!("scope.{i}"))
            .collect();
        let s = render_scope_summary(&lots);
        assert!(s.ends_with(&format!("+{} more", 3)));
    }

    #[test]
    fn render_menu_marks_default_with_star() {
        let templates = vec![
            parse_template(EMBERD_DEV, Path::new("/in-memory/a.toml")).unwrap(),
            parse_template(READ_ONLY, Path::new("/in-memory/b.toml")).unwrap(),
        ];
        let menu = render_menu(&templates, Some("read-only"));
        // pregrant_delegation_prompt_landed — checkpoint anchor in test body to
        // keep grep-based verification working even if the doc-comment shifts.
        assert!(menu.contains("* 2) read-only"));
        assert!(menu.contains("Default template: read-only"));
    }

    #[test]
    fn render_menu_no_default_no_star() {
        let templates = vec![parse_template(EMBERD_DEV, Path::new("/x.toml")).unwrap()];
        let menu = render_menu(&templates, None);
        // The scope summary itself contains `*` (e.g. `git.*`), so we cannot
        // assert the absence of `*` outright. Instead assert that no line is
        // prefixed with the "* N)" default marker.
        assert!(!menu.contains("* 1)"));
        assert!(!menu.contains("Default template:"));
    }

    #[test]
    fn render_ttl_picks_largest_clean_unit() {
        assert_eq!(render_ttl(86_400), "1d");
        assert_eq!(render_ttl(7200), "2h");
        assert_eq!(render_ttl(300), "5m");
        assert_eq!(render_ttl(45), "45s");
    }

    #[test]
    fn last_delegation_round_trips_through_explicit_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("last-delegation.toml");
        save_last_delegation_to(&path, "emberd-development").unwrap();
        let loaded = load_last_delegation_from(&path).unwrap();
        assert_eq!(loaded, "emberd-development");
    }

    #[test]
    fn last_delegation_missing_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never-written.toml");
        assert!(load_last_delegation_from(&path).is_none());
    }

    #[test]
    fn last_delegation_corrupt_toml_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.toml");
        std::fs::write(&path, b"this is not valid TOML = = =\n").unwrap();
        assert!(load_last_delegation_from(&path).is_none());
    }

    #[test]
    fn save_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir
            .path()
            .join("does")
            .join("not")
            .join("exist")
            .join("last-delegation.toml");
        save_last_delegation_to(&nested, "infra-iteration").unwrap();
        assert_eq!(
            load_last_delegation_from(&nested).unwrap(),
            "infra-iteration"
        );
    }

    #[test]
    fn save_overwrites_previous_value_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("last-delegation.toml");
        save_last_delegation_to(&path, "read-only").unwrap();
        save_last_delegation_to(&path, "emberd-development").unwrap();
        // pregrant_last_used_cache_landed — checkpoint mirrored in test body
        // to keep grep-based verification working from this file even if
        // module-level docs shift.
        assert_eq!(
            load_last_delegation_from(&path).unwrap(),
            "emberd-development"
        );
        // No leftover `.tmp` file.
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftover.is_empty(), "atomic-rename left a .tmp file behind");
    }

    #[test]
    fn resolve_default_prefers_cached_when_in_list() {
        let templates = vec![
            parse_template(EMBERD_DEV, Path::new("/a.toml")).unwrap(),
            parse_template(READ_ONLY, Path::new("/b.toml")).unwrap(),
        ];
        let default = resolve_default_name(&templates, Some("read-only".to_string()));
        assert_eq!(default.as_deref(), Some("read-only"));
    }

    #[test]
    fn resolve_default_falls_back_to_first_when_cached_unknown() {
        let templates = vec![
            parse_template(EMBERD_DEV, Path::new("/a.toml")).unwrap(),
            parse_template(READ_ONLY, Path::new("/b.toml")).unwrap(),
        ];
        // Cached entry refers to a workflow no longer present (e.g. operator
        // removed the overlay file). Selector must degrade to the first
        // alphabetical template, never error out.
        let default = resolve_default_name(&templates, Some("gone-since-last-launch".to_string()));
        assert_eq!(default.as_deref(), Some("emberd-development"));
    }

    #[test]
    fn resolve_default_falls_back_to_first_when_no_cache() {
        let templates = vec![
            parse_template(EMBERD_DEV, Path::new("/a.toml")).unwrap(),
            parse_template(READ_ONLY, Path::new("/b.toml")).unwrap(),
        ];
        let default = resolve_default_name(&templates, None);
        assert_eq!(default.as_deref(), Some("emberd-development"));
    }

    #[test]
    fn resolve_default_returns_none_for_empty_list() {
        let templates: Vec<TemplateMeta> = Vec::new();
        assert!(resolve_default_name(&templates, Some("anything".to_string())).is_none());
        assert!(resolve_default_name(&templates, None).is_none());
    }
}
