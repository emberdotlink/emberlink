//! Argv classifier: maps `vercel <group> [<verb>] [args]` to a
//! `construct.toml` action_key. Per ADR 124 §3 — this lives shim-side
//! BUT the daemon re-classifies the argv server-side (untrusts the shim).
//!
//! Vercel CLI argv shape:
//!
//! ```text
//! vercel [global-flags...] [<group> [<verb>]] [verb-args...]
//! ```
//!
//! The bare `vercel` invocation (with no group) is shorthand for `deploy`,
//! so an empty post-strip argv classifies to `vercel.deploy`. Likewise
//! `vercel deploy` is the explicit form.
//!
//! Global flags (`--token`, `--scope`, `--cwd`, `--yes`, `--debug`,
//! `--no-color`) may appear before, between, or after the group/verb
//! tokens. We strip them — including their values for the flags that take
//! one — before pattern-matching, so classification is stable under flag
//! reordering. `--project` is included because a stale shim may still pass
//! it; vercel removed it from the canonical CLI but agents and CI scripts
//! continue to use it as a project-name override.
//!
//! Coverage (mutating verbs are gated; read-only verbs passthrough as `None`):
//!
//! | argv prefix                                 | action_key                     |
//! |---------------------------------------------|--------------------------------|
//! | `<empty>` or `deploy`                       | `vercel.deploy`                |
//! | `env {add,remove,pull,push}`                | `vercel.env.<verb>`            |
//! | `projects {add,remove}`                     | `vercel.projects.<verb>`       |
//! | `domains {add,remove,transfer-in,transfer-out,buy}` | `vercel.domains.<verb>` |
//! | `dns {add,remove}`                          | `vercel.dns.<verb>`            |
//! | `certs {add,remove,renew}`                  | `vercel.certs.<verb>`          |
//! | `alias {set,remove}`                        | `vercel.alias.<verb>`          |
//! | `teams {create,invite,remove}`              | `vercel.teams.<verb>`          |
//! | `tokens {create,revoke}`                    | `vercel.tokens.<verb>`         |
//! | `secrets {add,remove,rename}`               | `vercel.secrets.<verb>`        |
//! | `integration {add,remove}`                  | `vercel.integration.<verb>`    |
//! | `rollback`                                  | `vercel.rollback`              |
//! | `promote`                                   | `vercel.promote`               |
//! | `git disconnect`                            | `vercel.git.disconnect`        |
//! | `list \| ls \| inspect \| logs \| bisect \| whoami \| link \| pull \| git connect` | `None` (passthrough) |

use core_construct_runtime::ActionKey;
use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};

/// Vercel CLI global flags that take a value as the *next* argv token.
/// When stripping, both the flag and its value are removed.
const VALUE_BEARING_GLOBAL_FLAGS: &[&str] =
    &["--token", "-t", "--scope", "-S", "--project", "--cwd"];

/// Vercel CLI global flags that are valueless (boolean toggles).
const BOOLEAN_GLOBAL_FLAGS: &[&str] = &["--debug", "-d", "--no-color", "--yes", "-y"];

/// Strip global flags (and their values, where applicable) from `argv`.
///
/// Recognizes both `--flag value` and `--flag=value` forms for the
/// value-bearing flags, plus the boolean toggles in
/// [`BOOLEAN_GLOBAL_FLAGS`]. Non-flag tokens and unknown flags pass
/// through unchanged (the daemon re-classifies anyway).
pub(crate) fn strip_global_flags(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];

        // `--flag=value` form — drop in one step regardless of whether
        // it's a value-bearing or boolean global flag (boolean flags
        // shouldn't have `=value` but accept it tolerantly).
        if let Some(eq) = tok.find('=') {
            let name = &tok[..eq];
            if VALUE_BEARING_GLOBAL_FLAGS.contains(&name) || BOOLEAN_GLOBAL_FLAGS.contains(&name) {
                i += 1;
                continue;
            }
        }

        // `--flag value` form for value-bearing globals.
        if VALUE_BEARING_GLOBAL_FLAGS.contains(&tok.as_str()) {
            // Skip the flag and (if present) its value.
            i += 1;
            if i < argv.len() {
                i += 1;
            }
            continue;
        }

        // Boolean global flags — skip just the flag itself.
        if BOOLEAN_GLOBAL_FLAGS.contains(&tok.as_str()) {
            i += 1;
            continue;
        }

        out.push(tok.clone());
        i += 1;
    }
    out
}

/// Returns `true` if `verb` looks like a top-level read-only Vercel CLI verb.
fn is_read_only_top_verb(verb: &str) -> bool {
    matches!(
        verb,
        "list"
            | "ls"
            | "inspect"
            | "logs"
            | "bisect"
            | "whoami"
            | "link"
            | "help"
            | "version"
            | "login"
            | "logout"
    )
}

/// Classify `vercel <group> [<verb>] ...` argv into an action_key.
///
/// Returns `None` for read-only / unrecognized shapes — the runtime
/// treats `None` as passthrough (no broker mediation).
pub fn classify_vercel_argv(argv: &[String]) -> Option<ActionKey> {
    let stripped = strip_global_flags(argv);

    // Bare `vercel` (no positional args) is shorthand for `deploy`.
    if stripped.is_empty() {
        return Some(ActionKey("vercel.deploy".to_string()));
    }

    let g0 = stripped.first()?.as_str();

    // Top-level read-only verbs.
    if is_read_only_top_verb(g0) {
        return None;
    }

    // Top-level mutating verbs (no further verb token required).
    match g0 {
        "deploy" => return Some(ActionKey("vercel.deploy".to_string())),
        "rollback" => return Some(ActionKey("vercel.rollback".to_string())),
        "promote" => return Some(ActionKey("vercel.promote".to_string())),
        // Top-level `pull` is read-only (downloads env + project metadata
        // for local dev). Mutating env transfer is `env push` / `env pull`
        // under the env subgroup.
        "pull" => return None,
        _ => {}
    }

    let g1 = stripped.get(1).map(|s| s.as_str())?;

    match g0 {
        // env <verb> — list / ls passthrough; mutating verbs gated.
        "env" => match g1 {
            "add" | "remove" | "rm" | "pull" | "push" => {
                // Normalize `rm` → `remove` so the action_key matches the
                // canonical construct.toml entry.
                let v = if g1 == "rm" { "remove" } else { g1 };
                Some(ActionKey(format!("vercel.env.{v}")))
            }
            _ => None,
        },

        // projects <verb> — list / ls passthrough; mutating verbs gated.
        "projects" => match g1 {
            "add" | "remove" | "rm" => {
                let v = if g1 == "rm" { "remove" } else { g1 };
                Some(ActionKey(format!("vercel.projects.{v}")))
            }
            _ => None,
        },

        // domains <verb> — ls / inspect passthrough; mutating verbs gated.
        "domains" => match g1 {
            "add" | "remove" | "rm" | "transfer-in" | "transfer-out" | "buy" => {
                let v = if g1 == "rm" { "remove" } else { g1 };
                Some(ActionKey(format!("vercel.domains.{v}")))
            }
            _ => None,
        },

        // dns <verb> — ls passthrough; mutating verbs gated.
        "dns" => match g1 {
            "add" | "remove" | "rm" => {
                let v = if g1 == "rm" { "remove" } else { g1 };
                Some(ActionKey(format!("vercel.dns.{v}")))
            }
            _ => None,
        },

        // certs <verb> — ls / issue (read) passthrough; mutating verbs gated.
        "certs" => match g1 {
            "add" | "remove" | "rm" | "renew" => {
                let v = if g1 == "rm" { "remove" } else { g1 };
                Some(ActionKey(format!("vercel.certs.{v}")))
            }
            _ => None,
        },

        // alias <verb> — bare `alias` is a read-only list when no verb is
        // present; with `set` / `remove` it mutates routing.
        "alias" => match g1 {
            "set" => Some(ActionKey("vercel.alias.set".to_string())),
            "remove" | "rm" => Some(ActionKey("vercel.alias.remove".to_string())),
            _ => None,
        },

        // teams <verb> — ls / switch passthrough; mutating verbs gated.
        "teams" => match g1 {
            "create" | "invite" => Some(ActionKey(format!("vercel.teams.{g1}"))),
            "remove" | "rm" => Some(ActionKey("vercel.teams.remove".to_string())),
            _ => None,
        },

        // tokens <verb> — ls passthrough; mutating verbs gated.
        "tokens" => match g1 {
            "create" | "revoke" => Some(ActionKey(format!("vercel.tokens.{g1}"))),
            _ => None,
        },

        // secrets <verb> — ls passthrough; mutating verbs gated.
        "secrets" => match g1 {
            "add" | "rename" => Some(ActionKey(format!("vercel.secrets.{g1}"))),
            "remove" | "rm" => Some(ActionKey("vercel.secrets.remove".to_string())),
            _ => None,
        },

        // integration <verb> — ls passthrough; mutating verbs gated.
        "integration" => match g1 {
            "add" | "remove" | "rm" => {
                let v = if g1 == "rm" { "remove" } else { g1 };
                Some(ActionKey(format!("vercel.integration.{v}")))
            }
            _ => None,
        },

        // git <verb> — `connect` is read-only-ish (just associates a repo);
        // `disconnect` is mutation that breaks deploy hooks.
        "git" => match g1 {
            "disconnect" => Some(ActionKey("vercel.git.disconnect".to_string())),
            _ => None,
        },

        // Unknown group → passthrough; daemon re-classifies.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// VercelFactory — P24 construct-factory contract for the vercel construct
// ---------------------------------------------------------------------------

/// Parsed vercel.toml action manifest, initialised once at first access.
static VERCEL_MANIFEST: std::sync::LazyLock<core_events::construct_toml::ParsedActionManifest> =
    std::sync::LazyLock::new(|| {
        core_events::construct_toml::parse_action_manifest(include_str!("../construct/vercel.toml"))
            .expect("bundled vercel.toml must be valid")
    });

/// Look up the `need` atoms for an action key from the bundled manifest.
/// Returns `None` if the action is absent from the manifest or has an empty
/// `need` list.
fn manifest_need_for_action(action_key: &str) -> Option<Vec<String>> {
    let suffix = action_key.strip_prefix("vercel.")?;
    VERCEL_MANIFEST
        .manifest
        .actions
        .iter()
        .find(|a| a.key == action_key || a.key == format!("vercel.{suffix}"))
        .and_then(|a| {
            let need = &a.need;
            if need.is_empty() {
                None
            } else {
                Some(need.clone())
            }
        })
}

/// Returns `true` when `action_key` (full form, e.g. `"vercel.deploy"`) has an
/// entry in the bundled manifest (regardless of whether it carries a `need`).
fn action_in_manifest(action_key: &str) -> bool {
    VERCEL_MANIFEST.manifest.actions.iter().any(|a| {
        a.key == action_key
            || action_key
                .strip_prefix("vercel.")
                .is_some_and(|suffix| a.key == format!("vercel.{suffix}"))
    })
}

/// Returns `true` when the raw argv contains `--token` or `-t` (the Vercel
/// credential-selection flags). Checks both the `--flag value` and
/// `--flag=value` forms.
fn has_token_flag(argv: &[String]) -> bool {
    argv.iter().any(|tok| {
        tok == "--token" || tok == "-t" || tok.starts_with("--token=") || tok.starts_with("-t=")
    })
}

/// Returns `true` when the stripped argv's first positional token is `login`.
fn is_login_argv(argv: &[String]) -> bool {
    let stripped = strip_global_flags(argv);
    stripped.first().is_some_and(|v| v == "login")
}

/// Extract `--scope`/`-S` value from raw argv (both `--scope value` and
/// `--scope=value` forms).
fn extract_scope_flag(argv: &[String]) -> Option<String> {
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];
        // --scope=value / -S=value
        for prefix in &["--scope=", "-S="] {
            if let Some(value) = tok.strip_prefix(prefix)
                && !value.is_empty()
            {
                return Some(value.to_string());
            }
        }
        // --scope value / -S value
        if (tok == "--scope" || tok == "-S") && i + 1 < argv.len() {
            let value = &argv[i + 1];
            if !value.starts_with('-') {
                return Some(value.clone());
            }
        }
        i += 1;
    }
    None
}

/// P24 factory implementation for the `vercel` construct.
#[derive(Debug, Default, Clone)]
pub struct VercelFactory;

/// Provider-specific target extracted from a `vercel` argv invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VercelFactoryTarget {
    pub provider: &'static str,
    /// Team/org scope as supplied via `--scope` / `-S`.
    pub scope: Option<String>,
    /// Project name (not currently extractable from argv alone; requires
    /// vercel config / linked project resolution).
    pub project: Option<String>,
}

/// Need atoms derived from the bundled manifest for one `vercel` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VercelFactoryNeed(pub Vec<String>);

impl InvocationGrammar for VercelFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_vercel_argv(argv)
    }
}

impl TargetExtractor for VercelFactory {
    type Target = VercelFactoryTarget;

    fn target_for_argv(&self, _action_key: &ActionKey, argv: &[String]) -> Option<Self::Target> {
        // Vercel target always requires project resolution from vercel config
        // / linked project (not present in argv). We can extract scope if
        // supplied, but project is always None from argv alone.
        let scope = extract_scope_flag(argv);
        Some(VercelFactoryTarget {
            provider: "vercel",
            scope,
            project: None,
        })
    }
}

impl NeedTemplate for VercelFactory {
    type Need = VercelFactoryNeed;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        _target: &Self::Target,
        _argv: &[String],
    ) -> Option<Self::Need> {
        manifest_need_for_action(&action_key.0).map(VercelFactoryNeed)
    }
}

impl ConstructFactory for VercelFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> FactoryDisposition {
        // --token / -t in raw argv selects credential material — always fail
        // closed regardless of what the classifier returns.
        if has_token_flag(argv) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // `vercel login` is classified as None by the argv classifier (it's in
        // the read-only passthrough list) but is a credential-bypass vector.
        if is_login_argv(argv) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        let Some(key) = action_key else {
            // Unclassified argv — no known mutating action (reads, version,
            // whoami, etc.). Credentialless passthrough.
            return FactoryDisposition::Credentialless;
        };

        // env.pull downloads environment material — authority-bearing payload
        // that needs analysis before materialization.
        if key.0 == "vercel.env.pull" {
            return FactoryDisposition::PayloadAnalysisRequired;
        }

        // Action not in the manifest at all — no bounded authority declared.
        if !action_in_manifest(&key.0) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // Action is in the manifest. If it has no `need`, authority is
        // unbounded — but for Vercel, project/team/scope must always be
        // resolved from vercel config/linked project before mediation.
        // All classified Vercel actions require resolver.
        FactoryDisposition::ResolverRequired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // --- bare deploy ---

    #[test]
    fn bare_vercel_classifies_as_deploy() {
        let r = classify_vercel_argv(&args(&[])).unwrap();
        assert_eq!(r.0, "vercel.deploy");
    }

    #[test]
    fn explicit_deploy_classified() {
        let r = classify_vercel_argv(&args(&["deploy"])).unwrap();
        assert_eq!(r.0, "vercel.deploy");
    }

    #[test]
    fn deploy_with_args_classified() {
        let r = classify_vercel_argv(&args(&["deploy", "--prod"])).unwrap();
        assert_eq!(r.0, "vercel.deploy");
    }

    // --- env ---

    #[test]
    fn env_add_classified() {
        let r = classify_vercel_argv(&args(&["env", "add", "FOO", "production"])).unwrap();
        assert_eq!(r.0, "vercel.env.add");
    }

    #[test]
    fn env_remove_classified() {
        let r = classify_vercel_argv(&args(&["env", "remove", "FOO"])).unwrap();
        assert_eq!(r.0, "vercel.env.remove");
    }

    #[test]
    fn env_rm_alias_classified_as_remove() {
        let r = classify_vercel_argv(&args(&["env", "rm", "FOO"])).unwrap();
        assert_eq!(r.0, "vercel.env.remove");
    }

    #[test]
    fn env_pull_classified() {
        let r = classify_vercel_argv(&args(&["env", "pull", ".env"])).unwrap();
        assert_eq!(r.0, "vercel.env.pull");
    }

    #[test]
    fn env_push_classified() {
        let r = classify_vercel_argv(&args(&["env", "push"])).unwrap();
        assert_eq!(r.0, "vercel.env.push");
    }

    #[test]
    fn env_list_passthrough() {
        assert!(classify_vercel_argv(&args(&["env", "list"])).is_none());
    }

    // --- projects ---

    #[test]
    fn projects_add_classified() {
        let r = classify_vercel_argv(&args(&["projects", "add", "myproj"])).unwrap();
        assert_eq!(r.0, "vercel.projects.add");
    }

    #[test]
    fn projects_remove_classified() {
        let r = classify_vercel_argv(&args(&["projects", "remove", "myproj"])).unwrap();
        assert_eq!(r.0, "vercel.projects.remove");
    }

    #[test]
    fn projects_rm_alias_classified_as_remove() {
        let r = classify_vercel_argv(&args(&["projects", "rm", "myproj"])).unwrap();
        assert_eq!(r.0, "vercel.projects.remove");
    }

    #[test]
    fn projects_ls_passthrough() {
        assert!(classify_vercel_argv(&args(&["projects", "ls"])).is_none());
    }

    // --- domains ---

    #[test]
    fn domains_add_classified() {
        let r = classify_vercel_argv(&args(&["domains", "add", "example.com"])).unwrap();
        assert_eq!(r.0, "vercel.domains.add");
    }

    #[test]
    fn domains_remove_classified() {
        let r = classify_vercel_argv(&args(&["domains", "remove", "example.com"])).unwrap();
        assert_eq!(r.0, "vercel.domains.remove");
    }

    #[test]
    fn domains_transfer_in_classified() {
        let r = classify_vercel_argv(&args(&["domains", "transfer-in", "example.com"])).unwrap();
        assert_eq!(r.0, "vercel.domains.transfer-in");
    }

    #[test]
    fn domains_transfer_out_classified() {
        let r = classify_vercel_argv(&args(&["domains", "transfer-out", "example.com"])).unwrap();
        assert_eq!(r.0, "vercel.domains.transfer-out");
    }

    #[test]
    fn domains_buy_classified() {
        let r = classify_vercel_argv(&args(&["domains", "buy", "example.com"])).unwrap();
        assert_eq!(r.0, "vercel.domains.buy");
    }

    #[test]
    fn domains_inspect_passthrough() {
        assert!(classify_vercel_argv(&args(&["domains", "inspect", "example.com"])).is_none());
    }

    // --- dns ---

    #[test]
    fn dns_add_classified() {
        let r =
            classify_vercel_argv(&args(&["dns", "add", "example.com", "A", "1.2.3.4"])).unwrap();
        assert_eq!(r.0, "vercel.dns.add");
    }

    #[test]
    fn dns_remove_classified() {
        let r = classify_vercel_argv(&args(&["dns", "remove", "rec_id"])).unwrap();
        assert_eq!(r.0, "vercel.dns.remove");
    }

    #[test]
    fn dns_ls_passthrough() {
        assert!(classify_vercel_argv(&args(&["dns", "ls", "example.com"])).is_none());
    }

    // --- certs ---

    #[test]
    fn certs_add_classified() {
        let r = classify_vercel_argv(&args(&["certs", "add", "example.com"])).unwrap();
        assert_eq!(r.0, "vercel.certs.add");
    }

    #[test]
    fn certs_remove_classified() {
        let r = classify_vercel_argv(&args(&["certs", "remove", "cert_id"])).unwrap();
        assert_eq!(r.0, "vercel.certs.remove");
    }

    #[test]
    fn certs_renew_classified() {
        let r = classify_vercel_argv(&args(&["certs", "renew", "example.com"])).unwrap();
        assert_eq!(r.0, "vercel.certs.renew");
    }

    // --- alias ---

    #[test]
    fn alias_set_classified() {
        let r = classify_vercel_argv(&args(&["alias", "set", "deployment", "alias.com"])).unwrap();
        assert_eq!(r.0, "vercel.alias.set");
    }

    #[test]
    fn alias_remove_classified() {
        let r = classify_vercel_argv(&args(&["alias", "remove", "alias.com"])).unwrap();
        assert_eq!(r.0, "vercel.alias.remove");
    }

    #[test]
    fn alias_rm_alias_classified_as_remove() {
        let r = classify_vercel_argv(&args(&["alias", "rm", "alias.com"])).unwrap();
        assert_eq!(r.0, "vercel.alias.remove");
    }

    // --- teams ---

    #[test]
    fn teams_create_classified() {
        let r = classify_vercel_argv(&args(&["teams", "create", "myteam"])).unwrap();
        assert_eq!(r.0, "vercel.teams.create");
    }

    #[test]
    fn teams_invite_classified() {
        let r = classify_vercel_argv(&args(&["teams", "invite", "user@example.com"])).unwrap();
        assert_eq!(r.0, "vercel.teams.invite");
    }

    #[test]
    fn teams_remove_classified() {
        let r = classify_vercel_argv(&args(&["teams", "remove", "myteam"])).unwrap();
        assert_eq!(r.0, "vercel.teams.remove");
    }

    #[test]
    fn teams_ls_passthrough() {
        assert!(classify_vercel_argv(&args(&["teams", "ls"])).is_none());
    }

    // --- tokens ---

    #[test]
    fn tokens_create_classified() {
        let r = classify_vercel_argv(&args(&["tokens", "create"])).unwrap();
        assert_eq!(r.0, "vercel.tokens.create");
    }

    #[test]
    fn tokens_revoke_classified() {
        let r = classify_vercel_argv(&args(&["tokens", "revoke", "tok_id"])).unwrap();
        assert_eq!(r.0, "vercel.tokens.revoke");
    }

    #[test]
    fn tokens_ls_passthrough() {
        assert!(classify_vercel_argv(&args(&["tokens", "ls"])).is_none());
    }

    // --- secrets ---

    #[test]
    fn secrets_add_classified() {
        let r = classify_vercel_argv(&args(&["secrets", "add", "name", "value"])).unwrap();
        assert_eq!(r.0, "vercel.secrets.add");
    }

    #[test]
    fn secrets_remove_classified() {
        let r = classify_vercel_argv(&args(&["secrets", "remove", "name"])).unwrap();
        assert_eq!(r.0, "vercel.secrets.remove");
    }

    #[test]
    fn secrets_rename_classified() {
        let r = classify_vercel_argv(&args(&["secrets", "rename", "old", "new"])).unwrap();
        assert_eq!(r.0, "vercel.secrets.rename");
    }

    #[test]
    fn secrets_ls_passthrough() {
        assert!(classify_vercel_argv(&args(&["secrets", "ls"])).is_none());
    }

    // --- integration ---

    #[test]
    fn integration_add_classified() {
        let r = classify_vercel_argv(&args(&["integration", "add", "name"])).unwrap();
        assert_eq!(r.0, "vercel.integration.add");
    }

    #[test]
    fn integration_remove_classified() {
        let r = classify_vercel_argv(&args(&["integration", "remove", "name"])).unwrap();
        assert_eq!(r.0, "vercel.integration.remove");
    }

    // --- top-level rollback / promote ---

    #[test]
    fn rollback_classified() {
        let r = classify_vercel_argv(&args(&["rollback", "deployment"])).unwrap();
        assert_eq!(r.0, "vercel.rollback");
    }

    #[test]
    fn promote_classified() {
        let r = classify_vercel_argv(&args(&["promote", "deployment"])).unwrap();
        assert_eq!(r.0, "vercel.promote");
    }

    // --- git ---

    #[test]
    fn git_disconnect_classified() {
        let r = classify_vercel_argv(&args(&["git", "disconnect"])).unwrap();
        assert_eq!(r.0, "vercel.git.disconnect");
    }

    #[test]
    fn git_connect_passthrough() {
        // git connect is read-only-ish per spec: associates repo, no
        // mutation of deploy infrastructure.
        assert!(classify_vercel_argv(&args(&["git", "connect", "url"])).is_none());
    }

    // --- read-only top-level passthroughs ---

    #[test]
    fn list_top_passthrough() {
        assert!(classify_vercel_argv(&args(&["list"])).is_none());
    }

    #[test]
    fn ls_top_passthrough() {
        assert!(classify_vercel_argv(&args(&["ls"])).is_none());
    }

    #[test]
    fn inspect_top_passthrough() {
        assert!(classify_vercel_argv(&args(&["inspect", "deployment"])).is_none());
    }

    #[test]
    fn logs_top_passthrough() {
        assert!(classify_vercel_argv(&args(&["logs", "deployment"])).is_none());
    }

    #[test]
    fn bisect_top_passthrough() {
        assert!(classify_vercel_argv(&args(&["bisect"])).is_none());
    }

    #[test]
    fn whoami_top_passthrough() {
        assert!(classify_vercel_argv(&args(&["whoami"])).is_none());
    }

    #[test]
    fn link_top_passthrough() {
        assert!(classify_vercel_argv(&args(&["link"])).is_none());
    }

    #[test]
    fn pull_top_passthrough() {
        // Top-level `vercel pull` downloads env + project metadata for
        // local dev — read-only.
        assert!(classify_vercel_argv(&args(&["pull"])).is_none());
    }

    // --- global flag stripping ---

    #[test]
    fn token_flag_before_group_stripped() {
        let r = classify_vercel_argv(&args(&["--token", "vc_secret", "projects", "remove", "p"]))
            .unwrap();
        assert_eq!(r.0, "vercel.projects.remove");
    }

    #[test]
    fn scope_flag_between_group_and_verb_stripped() {
        let r = classify_vercel_argv(&args(&[
            "domains",
            "--scope",
            "myteam",
            "remove",
            "example.com",
        ]))
        .unwrap();
        assert_eq!(r.0, "vercel.domains.remove");
    }

    #[test]
    fn project_flag_after_verb_stripped() {
        let r =
            classify_vercel_argv(&args(&["env", "remove", "FOO", "--project", "myproj"])).unwrap();
        assert_eq!(r.0, "vercel.env.remove");
    }

    #[test]
    fn cwd_flag_stripped() {
        let r = classify_vercel_argv(&args(&["--cwd", "/tmp/proj", "deploy"])).unwrap();
        assert_eq!(r.0, "vercel.deploy");
    }

    #[test]
    fn debug_boolean_flag_stripped() {
        let r = classify_vercel_argv(&args(&["--debug", "secrets", "remove", "name"])).unwrap();
        assert_eq!(r.0, "vercel.secrets.remove");
    }

    #[test]
    fn no_color_boolean_flag_stripped() {
        let r = classify_vercel_argv(&args(&["--no-color", "rollback", "deployment"])).unwrap();
        assert_eq!(r.0, "vercel.rollback");
    }

    #[test]
    fn yes_boolean_flag_stripped() {
        let r = classify_vercel_argv(&args(&["--yes", "alias", "remove", "alias.com"])).unwrap();
        assert_eq!(r.0, "vercel.alias.remove");
    }

    #[test]
    fn equals_form_token_flag_stripped() {
        let r =
            classify_vercel_argv(&args(&["--token=vc_secret", "tokens", "revoke", "tok"])).unwrap();
        assert_eq!(r.0, "vercel.tokens.revoke");
    }

    #[test]
    fn equals_form_scope_flag_stripped() {
        let r = classify_vercel_argv(&args(&["domains", "--scope=myteam", "buy", "example.com"]))
            .unwrap();
        assert_eq!(r.0, "vercel.domains.buy");
    }

    #[test]
    fn equals_form_project_flag_stripped() {
        let r = classify_vercel_argv(&args(&["env", "--project=myproj", "push"])).unwrap();
        assert_eq!(r.0, "vercel.env.push");
    }

    #[test]
    fn short_token_flag_stripped() {
        let r =
            classify_vercel_argv(&args(&["-t", "vc_secret", "projects", "remove", "p"])).unwrap();
        assert_eq!(r.0, "vercel.projects.remove");
    }

    #[test]
    fn short_scope_flag_stripped() {
        let r = classify_vercel_argv(&args(&["-S", "myteam", "rollback", "deployment"])).unwrap();
        assert_eq!(r.0, "vercel.rollback");
    }

    #[test]
    fn multiple_global_flags_stripped() {
        let r = classify_vercel_argv(&args(&[
            "--token",
            "tok",
            "--scope",
            "myteam",
            "--debug",
            "--no-color",
            "domains",
            "remove",
            "example.com",
        ]))
        .unwrap();
        assert_eq!(r.0, "vercel.domains.remove");
    }

    #[test]
    fn flags_reordered_classification_stable() {
        let a = classify_vercel_argv(&args(&[
            "domains",
            "remove",
            "example.com",
            "--scope",
            "myteam",
        ]))
        .unwrap();
        let b = classify_vercel_argv(&args(&[
            "--scope",
            "myteam",
            "domains",
            "remove",
            "example.com",
        ]))
        .unwrap();
        let c = classify_vercel_argv(&args(&[
            "domains",
            "--scope",
            "myteam",
            "remove",
            "example.com",
        ]))
        .unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(b.0, c.0);
    }

    #[test]
    fn only_global_flags_classifies_as_deploy() {
        // Bare invocation with only stripped flags is still `vercel`,
        // which is shorthand for `deploy`.
        let r = classify_vercel_argv(&args(&["--token", "vc_secret", "--debug"])).unwrap();
        assert_eq!(r.0, "vercel.deploy");
    }

    // --- unknown / corner cases ---

    #[test]
    fn unknown_group_passthrough() {
        assert!(classify_vercel_argv(&args(&["wireguard", "list"])).is_none());
    }

    #[test]
    fn group_without_verb_passthrough() {
        // Groups that need a verb (`env`, `projects`, etc.) without one
        // should passthrough, NOT classify as deploy.
        assert!(classify_vercel_argv(&args(&["env"])).is_none());
        assert!(classify_vercel_argv(&args(&["projects"])).is_none());
        assert!(classify_vercel_argv(&args(&["domains"])).is_none());
    }

    #[test]
    fn env_unknown_verb_passthrough() {
        assert!(classify_vercel_argv(&args(&["env", "foo"])).is_none());
    }

    #[test]
    fn teams_switch_passthrough() {
        // teams switch is not in the mutating-verb set; passthrough.
        assert!(classify_vercel_argv(&args(&["teams", "switch", "myteam"])).is_none());
    }

    // --- T1: unit on flag extraction ---

    #[test]
    fn strip_global_flags_token_and_scope() {
        let argv = args(&["--token", "secret", "--scope", "myteam", "deploy"]);
        let stripped = strip_global_flags(&argv);
        assert_eq!(stripped, vec!["deploy".to_string()]);
    }

    #[test]
    fn strip_global_flags_equals_form() {
        let argv = args(&["--token=secret", "--project=myproj", "env", "push"]);
        let stripped = strip_global_flags(&argv);
        assert_eq!(stripped, vec!["env".to_string(), "push".to_string()]);
    }

    #[test]
    fn strip_global_flags_preserves_unknown() {
        // Unknown flags pass through; the daemon re-classifies anyway.
        let argv = args(&["--unknown", "value", "deploy"]);
        let stripped = strip_global_flags(&argv);
        assert_eq!(
            stripped,
            vec![
                "--unknown".to_string(),
                "value".to_string(),
                "deploy".to_string(),
            ]
        );
    }

    #[test]
    fn strip_global_flags_value_at_end_no_panic() {
        // Trailing value-bearing flag with no value — must not panic.
        let argv = args(&["deploy", "--token"]);
        let stripped = strip_global_flags(&argv);
        assert_eq!(stripped, vec!["deploy".to_string()]);
    }

    // --- proptest: argv fuzzer; no panics; flag-insertion preserves classification ---

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 256,
            ..proptest::test_runner::Config::default()
        })]

        /// Fuzz arbitrary argv shapes — must never panic.
        #[test]
        fn fuzz_classify_no_panic(
            argv in proptest::collection::vec("[a-zA-Z0-9_:.-]{0,16}", 0..8usize)
        ) {
            // We only care that no panic escapes.
            let _ = classify_vercel_argv(&argv);
        }

        /// Inserting a recognized value-bearing global flag (with value) into a
        /// known-classified argv must not change the classification.
        #[test]
        fn fuzz_token_flag_insertion_stable(
            insert_at in 0usize..6,
            tok in "[a-zA-Z0-9]{8,16}"
        ) {
            let base = vec![
                "domains".to_string(),
                "remove".to_string(),
                "example.com".to_string(),
            ];
            let base_class = classify_vercel_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, tok.clone());
            with_flag.insert(pos, "--token".to_string());

            let class2 = classify_vercel_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }

        /// Inserting a boolean global flag at any position into a known
        /// classified argv must not change the classification.
        #[test]
        fn fuzz_boolean_flag_insertion_stable(insert_at in 0usize..6) {
            let base = vec![
                "secrets".to_string(),
                "remove".to_string(),
                "name".to_string(),
            ];
            let base_class = classify_vercel_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, "--debug".to_string());

            let class2 = classify_vercel_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }
    }

    // --- T2: integration with MockBroker for BrokerProvider::Vercel ---
    //
    // The full broker_exec lifecycle lives in the daemon; here we cover the
    // contract slice this Construct depends on: the broker registry can
    // hold a `MockBroker::new(BrokerProvider::Vercel)`, and a request that
    // declares `provider = Vercel` round-trips through issue → revoke
    // without panicking. Real Vercel impl is BROKER-VERCEL-IMPL (separate task).

    use core_broker::{Broker, BrokerError, BrokerProvider, BrokerRequest, MockBroker};
    use std::time::Duration;

    fn vercel_request(ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::Vercel,
            scope: serde_json::json!({
                "team": "ember-systems",
                "project": "ember-warden",
                "actions": ["deploy", "env:write"],
            }),
            ttl: Duration::from_secs(ttl_secs),
            contract_id: None,
            action_ref: None,
            workspace_ref: None,
            subject_ref: None,
            coordination_ref: None,
            caller_ref: None,
            authority_ref: None,
            reason: "ember-vercel integration test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    #[tokio::test]
    async fn mock_broker_vercel_issue_revoke_roundtrip() {
        let broker = MockBroker::new(BrokerProvider::Vercel);
        assert_eq!(broker.provider(), BrokerProvider::Vercel);

        let creds = broker
            .issue(vercel_request(900))
            .await
            .expect("issue should succeed for matching provider");
        assert_eq!(creds.materialization_id, "mock-1");

        broker
            .revoke(&creds.materialization_id)
            .await
            .expect("revoke of issued materialization should succeed");

        assert_eq!(broker.active_count(), 0);
        assert_eq!(broker.revoke_calls(), vec![creds.materialization_id]);
    }

    #[tokio::test]
    async fn mock_broker_vercel_rejects_wrong_provider() {
        let broker = MockBroker::new(BrokerProvider::Vercel);
        let mut req = vercel_request(900);
        req.provider = BrokerProvider::Cloudflare;

        let err = broker.issue(req).await.expect_err("provider mismatch");
        match err {
            BrokerError::InvalidScope(_) => {}
            other => panic!("expected InvalidScope, got {other:?}"),
        }
    }

    #[test]
    fn vercel_provider_as_str() {
        assert_eq!(BrokerProvider::Vercel.as_str(), "vercel");
    }

    // --- VercelFactory tests ---

    #[test]
    fn vercel_factory_deploy_is_resolver_required() {
        let f = VercelFactory;
        let a = args(&["deploy", "--prod"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn vercel_factory_env_pull_is_payload_analysis() {
        let f = VercelFactory;
        let a = args(&["env", "pull", ".env.local"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn vercel_factory_token_flag_fails_closed() {
        let f = VercelFactory;
        let a = args(&["--token", "vercel-token", "deploy", "--prod"]);
        let key = f.action_key_for_argv(&a);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn vercel_factory_short_token_flag_fails_closed() {
        let f = VercelFactory;
        let a = args(&["-t", "vercel-token", "deploy"]);
        let key = f.action_key_for_argv(&a);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn vercel_factory_token_equals_fails_closed() {
        let f = VercelFactory;
        let a = args(&["--token=vercel-token", "deploy"]);
        let key = f.action_key_for_argv(&a);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn vercel_factory_login_fails_closed() {
        let f = VercelFactory;
        let a = args(&["login"]);
        let key = f.action_key_for_argv(&a);
        // Classifier returns None for login (read-only passthrough), but
        // factory intercepts raw argv.
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn vercel_factory_whoami_is_credentialless() {
        let f = VercelFactory;
        let a = args(&["whoami"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn vercel_factory_version_flag_is_credentialless() {
        let f = VercelFactory;
        let a = args(&["--version"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn vercel_factory_env_add_is_resolver_required() {
        let f = VercelFactory;
        let a = args(&["env", "add", "FOO", "production"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn vercel_factory_target_extraction_with_scope() {
        let f = VercelFactory;
        let a = args(&["--scope", "myteam", "deploy", "--prod"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.provider, "vercel");
        assert_eq!(target.scope, Some("myteam".to_string()));
        assert_eq!(target.project, None);
    }

    #[test]
    fn vercel_factory_target_extraction_short_scope() {
        let f = VercelFactory;
        let a = args(&["-S", "myteam", "deploy"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.scope, Some("myteam".to_string()));
    }

    #[test]
    fn vercel_factory_target_extraction_scope_equals() {
        let f = VercelFactory;
        let a = args(&["--scope=myteam", "deploy"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.scope, Some("myteam".to_string()));
    }

    #[test]
    fn vercel_factory_target_extraction_no_scope() {
        let f = VercelFactory;
        let a = args(&["deploy", "--prod"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.provider, "vercel");
        assert_eq!(target.scope, None);
        assert_eq!(target.project, None);
    }

    #[test]
    fn vercel_factory_contract_runs_conformance_corpus() {
        let corpus = core_construct_runtime::factory::parse_factory_fixture_corpus(include_str!(
            "../conformance/vercel/factory-fixtures.toml"
        ))
        .expect("fixture corpus parses");
        let validation_errors =
            core_construct_runtime::factory::validate_factory_fixture_corpus(&corpus);
        assert!(validation_errors.is_empty(), "{validation_errors:#?}");

        let carrier = core_construct_runtime::factory::ActionManifestV2Carrier::parse(
            include_str!("../construct/vercel.toml"),
        )
        .expect("valid vercel manifest");
        let report = core_construct_runtime::factory::run_factory_fixtures(
            &VercelFactory,
            Some(&carrier),
            &corpus,
        );
        assert!(report.is_clean(), "{:#?}", report.failures);
    }
}
