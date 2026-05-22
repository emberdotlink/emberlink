//!
//! Daemon-side workflow template loader (design §Component 1).
//!
//! The launcher passes a `workflow_template` name to `register_session`; the
//! daemon resolves that name to a TOML file under the bundled
//! `<install_root>/workflow-templates/` directory (with optional operator
//! overlay at `<config_dir>/emberlink/workflow-templates/`), parses the
//! template, and issues a [`WorkflowGrant`] via
//! [`crate::infra::workflow_grant::save_if_absent`] at session-open.
//!
//! Mirrors the CLI-side `emberlink_cli::workflow_prompt` parser shape so the
//! launcher and the daemon agree on TTL parsing and scope-key validation;
//! the daemon does NOT depend on the CLI crate (`emberlink-cli` → `ember-daemon`
//! is the existing dependency direction, so the reverse would be a cycle).
//!
//! Anchor: `workflow_template_loader_landed`.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

/// Workflow template loaded from disk. Contains everything needed to mint a
/// `WorkflowGrant` (via the constructor in `core-grants`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowTemplate {
    /// Template name (matches the `name` key in the TOML).
    pub name: String,
    /// Operator-facing description.
    pub description: Option<String>,
    /// TTL ceiling in seconds parsed from the TOML `ttl` field.
    pub ttl_secs: i64,
    /// Action keys / namespace globs admitted by this template.
    pub scopes: Vec<String>,
    /// Action keys / namespace globs explicitly forbidden by this template.
    pub excludes: Vec<String>,
}

/// Errors surfaced by template lookup + parsing.
#[derive(Debug, Error)]
pub enum WorkflowTemplateError {
    #[error("workflow template '{name}' not found under {bundled_dir:?} or operator overlay")]
    NotFound {
        name: String,
        bundled_dir: PathBuf,
    },
    #[error("workflow template I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("workflow template parse error at {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error(
        "unparseable ttl `{value}` in workflow template `{name}` — expected forms `Nh`, `Nm`, `Nd`, `Ns`"
    )]
    Ttl { name: String, value: String },
}

#[derive(Deserialize)]
struct TemplateToml {
    name: String,
    #[serde(default)]
    description: Option<String>,
    ttl: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    excludes: Vec<String>,
}

/// Adversarial HIGH-4 fix (2026-05-22) — daemon-side gate that
/// mirrors the launcher's `is_safe_template_name`. Refuses template
/// names that could path-traverse out of the workflow-templates dir.
fn is_safe_template_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return false;
    }
    let p = std::path::Path::new(name);
    let mut comps = p.components();
    let only = comps.next();
    if comps.next().is_some() {
        return false;
    }
    matches!(only, Some(std::path::Component::Normal(_)))
}

fn parse_ttl(name: &str, ttl: &str) -> Result<i64, WorkflowTemplateError> {
    let trimmed = ttl.trim();
    if trimmed.is_empty() {
        return Err(WorkflowTemplateError::Ttl {
            name: name.to_string(),
            value: ttl.to_string(),
        });
    }
    let (num_part, unit) = trimmed.split_at(trimmed.len() - 1);
    let n: i64 = num_part.parse().map_err(|_| WorkflowTemplateError::Ttl {
        name: name.to_string(),
        value: ttl.to_string(),
    })?;
    let secs = match unit {
        "s" => n,
        "m" => n.checked_mul(60).ok_or_else(|| WorkflowTemplateError::Ttl {
            name: name.to_string(),
            value: ttl.to_string(),
        })?,
        "h" => n
            .checked_mul(3600)
            .ok_or_else(|| WorkflowTemplateError::Ttl {
                name: name.to_string(),
                value: ttl.to_string(),
            })?,
        "d" => n
            .checked_mul(86_400)
            .ok_or_else(|| WorkflowTemplateError::Ttl {
                name: name.to_string(),
                value: ttl.to_string(),
            })?,
        _ => {
            return Err(WorkflowTemplateError::Ttl {
                name: name.to_string(),
                value: ttl.to_string(),
            });
        }
    };
    if secs <= 0 {
        return Err(WorkflowTemplateError::Ttl {
            name: name.to_string(),
            value: ttl.to_string(),
        });
    }
    Ok(secs)
}

/// Parse a TOML template string. Factored so the test suite can drive
/// parse-and-validate behavior without touching disk.
pub fn parse_template(
    toml_str: &str,
    context_path: &Path,
) -> Result<WorkflowTemplate, WorkflowTemplateError> {
    let parsed: TemplateToml =
        toml::from_str(toml_str).map_err(|e| WorkflowTemplateError::Parse {
            path: context_path.to_path_buf(),
            source: e,
        })?;
    let ttl_secs = parse_ttl(&parsed.name, &parsed.ttl)?;
    Ok(WorkflowTemplate {
        name: parsed.name,
        description: parsed.description,
        ttl_secs,
        scopes: parsed.scopes,
        excludes: parsed.excludes,
    })
}

/// Resolve a workflow template by name, checking the operator overlay first,
/// then the bundled directory.
///
/// `bundled_dir`: `<install_root>/workflow-templates/` (e.g.
/// `/usr/local/lib/ember/workflow-templates/`).
/// `overlay_dir`: optional `<config_dir>/emberlink/workflow-templates/`.
pub fn load_template(
    name: &str,
    bundled_dir: &Path,
    overlay_dir: Option<&Path>,
) -> Result<WorkflowTemplate, WorkflowTemplateError> {
    // 1. Overlay first — operator overrides bundled.
    if let Some(overlay) = overlay_dir
        && let Some(template) = try_load_template_from_dir(overlay, name)?
    {
        return Ok(template);
    }

    // 2. Bundled.
    if let Some(template) = try_load_template_from_dir(bundled_dir, name)? {
        return Ok(template);
    }

    Err(WorkflowTemplateError::NotFound {
        name: name.to_string(),
        bundled_dir: bundled_dir.to_path_buf(),
    })
}

/// Try loading `<dir>/<name>.toml` and verify the inner `name` matches
/// `expected_name`. Returns `Ok(None)` when the file does not exist.
///
/// Adversarial HIGH-4 fix (2026-05-22): refuse template names that
/// could traverse out of `dir`. Pre-fix `dir.join(format!("{name}.toml"))`
/// happily accepted `../`, absolute paths, etc. The launcher's
/// `is_safe_template_name` is a defense-in-depth gate on
/// `EMBER_WORKFLOW_TEMPLATE`; this is the daemon-side belt to that
/// suspenders. We reject ANY `expected_name` that doesn't parse as a
/// single `Component::Normal` path component, even if the launcher
/// forgot to validate (or if a future RPC caller bypasses the
/// launcher).
fn try_load_template_from_dir(
    dir: &Path,
    expected_name: &str,
) -> Result<Option<WorkflowTemplate>, WorkflowTemplateError> {
    if !is_safe_template_name(expected_name) {
        // Treat as "not found" — same as legitimate missing template —
        // so the fall-through-to-bundled chain in the resolver still
        // works, but with the attacker-supplied name silently ignored.
        return Ok(None);
    }
    let path = dir.join(format!("{expected_name}.toml"));
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let template = parse_template(&contents, &path)?;
            if template.name != expected_name {
                // Filename-vs-content mismatch — defense in depth against
                // an overlay file lying about its name.
                return Ok(None);
            }
            Ok(Some(template))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(WorkflowTemplateError::Io {
            path: path.clone(),
            source: e,
        }),
    }
}

/// Checkpoint anchor. Presence of this test proves the loader ships with the
/// load-bearing properties: name-mismatch refusal, overlay precedence,
/// invalid-TTL refusal.
#[cfg(test)]
#[allow(dead_code)]
fn workflow_template_loader_landed() {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const EMBERD_DEV: &str = r#"
name = "emberd-development"
description = "Daily emberd development"
ttl = "4h"
scopes = ["git.*", "gh.*"]
excludes = ["gh.repo_delete"]
"#;

    const READ_ONLY: &str = r#"
name = "read-only"
description = "Read-only"
ttl = "8h"
scopes = ["git.fetch", "git.log"]
"#;

    const BAD_TTL: &str = r#"
name = "bad"
description = "bad"
ttl = "forever"
scopes = []
"#;

    #[test]
    fn parse_template_round_trips_known_fields() {
        let t =
            parse_template(EMBERD_DEV, Path::new("/in-memory/emberd-development.toml")).unwrap();
        assert_eq!(t.name, "emberd-development");
        assert_eq!(t.ttl_secs, 4 * 3600);
        assert_eq!(
            t.scopes,
            vec!["git.*".to_string(), "gh.*".to_string()]
        );
        assert_eq!(t.excludes, vec!["gh.repo_delete".to_string()]);
    }

    #[test]
    fn parse_template_rejects_bad_ttl() {
        let err = parse_template(BAD_TTL, Path::new("/in-memory/bad.toml")).unwrap_err();
        match err {
            WorkflowTemplateError::Ttl { name, value } => {
                assert_eq!(name, "bad");
                assert_eq!(value, "forever");
            }
            other => panic!("expected Ttl error, got {other:?}"),
        }
    }

    #[test]
    fn load_template_finds_bundled() {
        let dir = TempDir::new().unwrap();
        let bundled = dir.path().join("workflow-templates");
        std::fs::create_dir_all(&bundled).unwrap();
        std::fs::write(bundled.join("read-only.toml"), READ_ONLY).unwrap();

        let t = load_template("read-only", &bundled, None).unwrap();
        assert_eq!(t.name, "read-only");
        assert_eq!(t.ttl_secs, 8 * 3600);
    }

    #[test]
    fn load_template_overlay_precedes_bundled() {
        let dir = TempDir::new().unwrap();
        let bundled = dir.path().join("workflow-templates");
        let overlay = dir.path().join("overlay");
        std::fs::create_dir_all(&bundled).unwrap();
        std::fs::create_dir_all(&overlay).unwrap();
        // Bundled emberd-development has TTL 4h; overlay overrides to 1h.
        std::fs::write(bundled.join("emberd-development.toml"), EMBERD_DEV).unwrap();
        let overlay_toml = r#"
name = "emberd-development"
description = "Operator-overridden — tighter TTL"
ttl = "1h"
scopes = ["git.fetch"]
"#;
        std::fs::write(overlay.join("emberd-development.toml"), overlay_toml).unwrap();

        let t =
            load_template("emberd-development", &bundled, Some(&overlay)).unwrap();
        assert_eq!(t.ttl_secs, 3600, "overlay must override bundled");
        assert_eq!(t.scopes, vec!["git.fetch".to_string()]);
    }

    #[test]
    fn load_template_not_found_returns_structured_error() {
        let dir = TempDir::new().unwrap();
        let bundled = dir.path().join("workflow-templates");
        std::fs::create_dir_all(&bundled).unwrap();

        let err = load_template("missing", &bundled, None).unwrap_err();
        assert!(matches!(err, WorkflowTemplateError::NotFound { .. }));
    }

    #[test]
    fn load_template_refuses_name_mismatch() {
        // Overlay file claims a different inner name than its filename. The
        // loader must not silently return the wrong template.
        let dir = TempDir::new().unwrap();
        let bundled = dir.path().join("workflow-templates");
        std::fs::create_dir_all(&bundled).unwrap();
        // File named `read-only.toml` but inner name is `emberd-development`.
        std::fs::write(bundled.join("read-only.toml"), EMBERD_DEV).unwrap();

        let err = load_template("read-only", &bundled, None).unwrap_err();
        assert!(matches!(err, WorkflowTemplateError::NotFound { .. }));
    }
}
