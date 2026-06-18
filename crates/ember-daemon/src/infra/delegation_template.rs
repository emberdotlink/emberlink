//! CLASSIFICATION: PUBLIC
//!
//! Daemon-side delegation template loader (ADR 158 §Component 1).
//!
//! The launcher passes a `delegation_template` name to `register_session`; the
//! daemon resolves that name to a TOML file under the bundled
//! `<install_root>/delegation-templates/` directory (with optional operator
//! overlay at `<config_dir>/emberlink/delegation-templates/`), parses the
//! template, and lowers it into the runtime persona's `StandingGrant` at
//! session-open (per ADR 205 §6 — the legacy delegation sidecar lane is
//! retired).
//!
//! Mirrors the CLI-side `emberlink_cli::delegation_prompt` parser shape so the
//! launcher and the daemon agree on TTL parsing and scope-key validation;
//! the daemon does NOT depend on the CLI crate (`emberlink-cli` → `ember-daemon`
//! is the existing dependency direction, so the reverse would be a cycle).
//!
//! Anchor: `delegation_template_loader_landed`.

use std::path::{Path, PathBuf};

use core_event_types::ActionRefPattern;
use serde::Deserialize;
use thiserror::Error;

/// Delegation template loaded from disk. Contains everything needed to lower
/// the template's authority into the runtime persona's `StandingGrant` (per
/// ADR 205 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationTemplate {
    /// Template name (matches the `name` key in the TOML).
    pub name: String,
    /// Operator-facing description.
    pub description: Option<String>,
    /// TTL ceiling in seconds parsed from the TOML `ttl` field.
    pub ttl_secs: i64,
    /// Structured action-ref patterns admitted by this template.
    pub scopes: Vec<ActionRefPattern>,
    /// Structured action-ref patterns explicitly forbidden by this template.
    pub excludes: Vec<ActionRefPattern>,
}

/// Errors surfaced by template lookup + parsing.
#[derive(Debug, Error)]
pub enum DelegationTemplateError {
    #[error(
        "delegated-authority template '{name}' not found under {bundled_dir:?} or operator overlay"
    )]
    NotFound { name: String, bundled_dir: PathBuf },
    #[error("delegated-authority template I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("delegated-authority template parse error at {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error(
        "unparseable ttl `{value}` in delegated-authority template `{name}` — expected forms `Nh`, `Nm`, `Nd`, `Ns`"
    )]
    Ttl { name: String, value: String },
    #[error("failed to serialize delegated-authority template `{name}`: {source}")]
    Serialize {
        name: String,
        #[source]
        source: toml::ser::Error,
    },
}

#[derive(Deserialize)]
struct TemplateToml {
    name: String,
    #[serde(default)]
    description: Option<String>,
    ttl: String,
    #[serde(default)]
    scopes: Vec<ActionRefPattern>,
    #[serde(default)]
    excludes: Vec<ActionRefPattern>,
}

/// Adversarial HIGH-4 fix (2026-05-22) — daemon-side gate that
/// mirrors the launcher's `is_safe_template_name`. Refuses template
/// names that could path-traverse out of the delegation-templates dir.
pub(crate) fn is_safe_template_name(name: &str) -> bool {
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

fn parse_ttl(name: &str, ttl: &str) -> Result<i64, DelegationTemplateError> {
    let trimmed = ttl.trim();
    if trimmed.is_empty() {
        return Err(DelegationTemplateError::Ttl {
            name: name.to_string(),
            value: ttl.to_string(),
        });
    }
    let (num_part, unit) = trimmed.split_at(trimmed.len() - 1);
    let n: i64 = num_part.parse().map_err(|_| DelegationTemplateError::Ttl {
        name: name.to_string(),
        value: ttl.to_string(),
    })?;
    let secs = match unit {
        "s" => n,
        "m" => n
            .checked_mul(60)
            .ok_or_else(|| DelegationTemplateError::Ttl {
                name: name.to_string(),
                value: ttl.to_string(),
            })?,
        "h" => n
            .checked_mul(3600)
            .ok_or_else(|| DelegationTemplateError::Ttl {
                name: name.to_string(),
                value: ttl.to_string(),
            })?,
        "d" => n
            .checked_mul(86_400)
            .ok_or_else(|| DelegationTemplateError::Ttl {
                name: name.to_string(),
                value: ttl.to_string(),
            })?,
        _ => {
            return Err(DelegationTemplateError::Ttl {
                name: name.to_string(),
                value: ttl.to_string(),
            });
        }
    };
    if secs <= 0 {
        return Err(DelegationTemplateError::Ttl {
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
) -> Result<DelegationTemplate, DelegationTemplateError> {
    let parsed: TemplateToml =
        toml::from_str(toml_str).map_err(|e| DelegationTemplateError::Parse {
            path: context_path.to_path_buf(),
            source: e,
        })?;
    let ttl_secs = parse_ttl(&parsed.name, &parsed.ttl)?;
    Ok(DelegationTemplate {
        name: parsed.name,
        description: parsed.description,
        ttl_secs,
        scopes: parsed.scopes,
        excludes: parsed.excludes,
    })
}

/// Serializable form used by the planner's save path (ADR 194 §5 output 3).
/// Mirrors [`TemplateToml`] but owns the data so we can emit canonical TOML.
#[derive(serde::Serialize)]
struct TemplateTomlOut<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    ttl: &'a str,
    scopes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    excludes: Vec<String>,
}

/// Render a workflow-template TOML document from planner inputs and validate
/// that it round-trips through [`parse_template`] — so we never persist an
/// unloadable template. `scopes`/`excludes` are structured action-ref strings
/// (`<plugin_address>/<action_key>@<version>`); each must parse as an
/// `ActionRefPattern` or the round-trip fails. Returns the canonical TOML text.
///
/// The planner's saved artifact is a "reusable consequence" of the plan (ADR
/// 194 §9); this is the assembly side of that. The authority decision still
/// happens at launch via `register_session`, not here.
pub(crate) fn render_validated_template_toml(
    name: &str,
    description: Option<&str>,
    ttl: &str,
    scopes: &[String],
    excludes: &[String],
) -> Result<String, DelegationTemplateError> {
    let out = TemplateTomlOut {
        name,
        description,
        ttl,
        scopes: scopes.to_vec(),
        excludes: excludes.to_vec(),
    };
    let toml_str =
        toml::to_string_pretty(&out).map_err(|source| DelegationTemplateError::Serialize {
            name: name.to_string(),
            source,
        })?;
    // Round-trip: prove it parses, the TTL is valid, and every scope string is
    // a well-formed action-ref pattern before we hand it to the writer.
    let context_path = PathBuf::from(format!("<rendered>/{name}.toml"));
    let parsed = parse_template(&toml_str, &context_path)?;
    debug_assert_eq!(parsed.name, name);
    Ok(toml_str)
}

/// Resolve a delegation template by name, checking the operator overlay first,
/// then the bundled directory.
///
/// `bundled_dir`: `<install_root>/delegation-templates/` (e.g.
/// `/usr/local/lib/ember/delegation-templates/`).
/// `overlay_dir`: optional `<config_dir>/emberlink/delegation-templates/`.
pub fn load_template(
    name: &str,
    bundled_dir: &Path,
    overlay_dir: Option<&Path>,
) -> Result<DelegationTemplate, DelegationTemplateError> {
    let mut unreadable_overlay = None;

    // 1. Overlay first — operator overrides bundled.
    if let Some(overlay) = overlay_dir {
        match try_load_template_from_dir(overlay, name) {
            Ok(Some(template)) => return Ok(template),
            Ok(None) => {}
            Err(err) => {
                // A separate-uid daemon may be unable to read an operator-home
                // overlay even when the bundled template is valid. Fall back
                // to bundled for this template name, but preserve the overlay
                // error when there is no bundled twin.
                if matches!(
                    &err,
                    DelegationTemplateError::Io { source, .. }
                        if source.kind() == std::io::ErrorKind::PermissionDenied
                ) {
                    unreadable_overlay = Some(err);
                } else {
                    return Err(err);
                }
            }
        }
    }

    // 2. Bundled.
    if let Some(template) = try_load_template_from_dir(bundled_dir, name)? {
        if let Some(DelegationTemplateError::Io { path, .. }) = unreadable_overlay.as_ref() {
            tracing::warn!(
                template_name = %name,
                overlay_path = %path.display(),
                "delegated-authority template overlay unreadable; falling back to bundled template",
            );
        }
        return Ok(template);
    }

    if let Some(err) = unreadable_overlay {
        return Err(err);
    }

    // Keep the canonical bundle in-process so delegation-grant issuance still
    // works when the managed install omitted delegation-templates/ on disk.
    if let Some(template) = try_load_embedded_template(name)? {
        return Ok(template);
    }

    Err(DelegationTemplateError::NotFound {
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
/// `EMBER_DELEGATION_TEMPLATE`; this is the daemon-side belt to that
/// suspenders. We reject ANY `expected_name` that doesn't parse as a
/// single `Component::Normal` path component, even if the launcher
/// forgot to validate (or if a future RPC caller bypasses the
/// launcher).
fn try_load_template_from_dir(
    dir: &Path,
    expected_name: &str,
) -> Result<Option<DelegationTemplate>, DelegationTemplateError> {
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
        Err(e) => Err(DelegationTemplateError::Io {
            path: path.clone(),
            source: e,
        }),
    }
}

fn try_load_embedded_template(
    expected_name: &str,
) -> Result<Option<DelegationTemplate>, DelegationTemplateError> {
    let Some(toml) = ember_construct::delegation_template_schema::bundled_delegation_template_toml(
        expected_name,
    ) else {
        return Ok(None);
    };
    let context_path = PathBuf::from(format!("<embedded>/{expected_name}.toml"));
    let template = parse_template(toml, &context_path)?;
    if template.name != expected_name {
        return Ok(None);
    }
    Ok(Some(template))
}

/// Checkpoint anchor. Presence of this test proves the loader ships with the
/// load-bearing properties: name-mismatch refusal, overlay precedence,
/// invalid-TTL refusal.
#[cfg(test)]
#[allow(dead_code)]
fn delegation_template_loader_landed() {}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    const EMBERD_DEV: &str = r#"
name = "emberd-development"
description = "Daily emberd development"
ttl = "4h"
scopes = [
    "registry.ember.systems/ember-systems/ember-git/*@v1",
    "registry.ember.systems/ember-systems/ember-gh/*@v1",
]
excludes = ["registry.ember.systems/ember-systems/ember-gh/repo_delete@v1"]
"#;

    const READ_ONLY: &str = r#"
name = "read-only"
description = "Read-only"
ttl = "8h"
scopes = [
    "registry.ember.systems/ember-systems/ember-git/fetch@v1",
    "registry.ember.systems/ember-systems/ember-git/log@v1",
]
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
            vec![
                ActionRefPattern::new("registry.ember.systems/ember-systems/ember-git", "*", "v1"),
                ActionRefPattern::new("registry.ember.systems/ember-systems/ember-gh", "*", "v1"),
            ]
        );
        assert_eq!(
            t.excludes,
            vec![ActionRefPattern::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "repo_delete",
                "v1"
            )]
        );
    }

    #[test]
    fn parse_template_rejects_bad_ttl() {
        let err = parse_template(BAD_TTL, Path::new("/in-memory/bad.toml")).unwrap_err();
        match err {
            DelegationTemplateError::Ttl { name, value } => {
                assert_eq!(name, "bad");
                assert_eq!(value, "forever");
            }
            other => panic!("expected Ttl error, got {other:?}"),
        }
    }

    #[test]
    fn load_template_finds_bundled() {
        let dir = TempDir::new().unwrap();
        let bundled = dir.path().join("delegation-templates");
        std::fs::create_dir_all(&bundled).unwrap();
        std::fs::write(bundled.join("read-only.toml"), READ_ONLY).unwrap();

        let t = load_template("read-only", &bundled, None).unwrap();
        assert_eq!(t.name, "read-only");
        assert_eq!(t.ttl_secs, 8 * 3600);
    }

    #[test]
    fn load_template_overlay_precedes_bundled() {
        let dir = TempDir::new().unwrap();
        let bundled = dir.path().join("delegation-templates");
        let overlay = dir.path().join("overlay");
        std::fs::create_dir_all(&bundled).unwrap();
        std::fs::create_dir_all(&overlay).unwrap();
        // Bundled emberd-development has TTL 4h; overlay overrides to 1h.
        std::fs::write(bundled.join("emberd-development.toml"), EMBERD_DEV).unwrap();
        let overlay_toml = r#"
name = "emberd-development"
description = "Operator-overridden — tighter TTL"
ttl = "1h"
scopes = ["registry.ember.systems/ember-systems/ember-git/fetch@v1"]
"#;
        std::fs::write(overlay.join("emberd-development.toml"), overlay_toml).unwrap();

        let t = load_template("emberd-development", &bundled, Some(&overlay)).unwrap();
        assert_eq!(t.ttl_secs, 3600, "overlay must override bundled");
        assert_eq!(
            t.scopes,
            vec![ActionRefPattern::new(
                "registry.ember.systems/ember-systems/ember-git",
                "fetch",
                "v1"
            )]
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_template_unreadable_overlay_falls_back_to_bundled() {
        let dir = TempDir::new().unwrap();
        let bundled = dir.path().join("delegation-templates");
        let overlay = dir.path().join("overlay");
        std::fs::create_dir_all(&bundled).unwrap();
        std::fs::create_dir_all(&overlay).unwrap();
        std::fs::write(
            bundled.join("autopilot.toml"),
            READ_ONLY.replace("read-only", "autopilot"),
        )
        .unwrap();

        let overlay_path = overlay.join("autopilot.toml");
        std::fs::write(&overlay_path, READ_ONLY.replace("read-only", "autopilot")).unwrap();
        std::fs::set_permissions(&overlay_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let t = load_template("autopilot", &bundled, Some(&overlay)).unwrap();
        assert_eq!(t.name, "autopilot");
        assert_eq!(t.ttl_secs, 8 * 3600);
    }

    #[cfg(unix)]
    #[test]
    fn load_template_unreadable_overlay_without_bundled_still_errors() {
        let dir = TempDir::new().unwrap();
        let bundled = dir.path().join("delegation-templates");
        let overlay = dir.path().join("overlay");
        std::fs::create_dir_all(&bundled).unwrap();
        std::fs::create_dir_all(&overlay).unwrap();

        let overlay_path = overlay.join("autopilot.toml");
        std::fs::write(&overlay_path, READ_ONLY.replace("read-only", "autopilot")).unwrap();
        std::fs::set_permissions(&overlay_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let err = load_template("autopilot", &bundled, Some(&overlay)).unwrap_err();
        match err {
            DelegationTemplateError::Io { path, source } => {
                assert_eq!(path, overlay_path);
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected unreadable overlay I/O error, got {other:?}"),
        }
    }

    #[test]
    fn load_template_not_found_returns_structured_error() {
        let dir = TempDir::new().unwrap();
        let bundled = dir.path().join("delegation-templates");
        std::fs::create_dir_all(&bundled).unwrap();

        let err = load_template("missing", &bundled, None).unwrap_err();
        assert!(matches!(err, DelegationTemplateError::NotFound { .. }));
        assert!(
            err.to_string()
                .contains("delegated-authority template 'missing' not found"),
            "error should use delegated-authority wording: {err}"
        );
    }

    #[test]
    fn load_template_refuses_name_mismatch() {
        // Overlay file claims a different inner name than its filename. The
        // loader must not silently return the wrong template; it should fall
        // back to the embedded canonical bundle instead.
        let dir = TempDir::new().unwrap();
        let bundled = dir.path().join("delegation-templates");
        std::fs::create_dir_all(&bundled).unwrap();
        // File named `read-only.toml` but inner name is `emberd-development`.
        std::fs::write(bundled.join("read-only.toml"), EMBERD_DEV).unwrap();

        let template = load_template("read-only", &bundled, None).unwrap();
        assert_eq!(template.name, "read-only");
        assert_eq!(template.ttl_secs, 8 * 3600);
    }

    #[test]
    fn render_validated_template_toml_round_trips_through_parse() {
        let scopes = vec![
            "registry.ember.systems/ember-systems/ember-git/push@v1".to_string(),
            "registry.ember.systems/ember-systems/ember-gh/pr_create@v1".to_string(),
        ];
        let toml_str = render_validated_template_toml(
            "release-proof",
            Some("Saved by ember catalog plan (bounded)"),
            "4h",
            &scopes,
            &[],
        )
        .expect("render should succeed");
        // The rendered text must load back as the same template.
        let parsed = parse_template(&toml_str, Path::new("/in-memory/release-proof.toml")).unwrap();
        assert_eq!(parsed.name, "release-proof");
        assert_eq!(parsed.ttl_secs, 4 * 3600);
        assert_eq!(parsed.scopes.len(), 2);
        assert_eq!(
            parsed.scopes[1],
            ActionRefPattern::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_create",
                "v1"
            )
        );
    }

    #[test]
    fn render_validated_template_toml_rejects_bad_ttl() {
        let scopes = vec!["registry.ember.systems/ember-systems/ember-git/push@v1".to_string()];
        let err = render_validated_template_toml("x", None, "forever", &scopes, &[]).unwrap_err();
        assert!(matches!(err, DelegationTemplateError::Ttl { .. }));
    }

    #[test]
    fn render_validated_template_toml_rejects_malformed_scope() {
        // A scope string with no `@version` is not a valid action-ref pattern;
        // the round-trip through parse_template must reject it.
        let scopes = vec!["not-a-valid-action-ref".to_string()];
        let err = render_validated_template_toml("x", None, "4h", &scopes, &[]).unwrap_err();
        assert!(matches!(err, DelegationTemplateError::Parse { .. }));
    }

    #[test]
    fn load_template_falls_back_to_embedded_bundle_when_disk_bundle_missing() {
        let dir = TempDir::new().unwrap();
        let bundled = dir.path().join("delegation-templates");

        let template = load_template("read-only", &bundled, None).unwrap();
        assert_eq!(template.name, "read-only");
        assert_eq!(template.ttl_secs, 8 * 3600);
    }
}
