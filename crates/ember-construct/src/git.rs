//! Argv classifier: maps `git <verb> [flags…]` to a `construct.toml` action_key.
//! Per ADR 124 §3 — this lives shim-side BUT the daemon re-classifies the argv
//! server-side (untrusts the shim).
//!
//! Returns `None` for read-only and safe-write verbs (passthrough — no broker
//! mediation). Returns `Some(ActionKey)` for anything gated.
//!
//! Critical distinctions:
//!   `push`                      → git.push (permit)
//!   `push --force`              → git.push.force (biometric)
//!   `push --force-with-lease`   → git.push.force (biometric)
//!   `push --force-with-lease=<ref>` → git.push.force (biometric)
//!   `push -f`                   → git.push.force (biometric)
//!   `push --tags`               → git.push.tags (permit)
//!   `push --follow-tags`        → git.push.tags (permit)
//!   `commit`                    → None (passthrough)
//!   `commit --amend`            → git.commit.amend (gated)
//!   `rebase HEAD~3`             → None (passthrough)
//!   `rebase -i HEAD~3`          → git.rebase.interactive (gated)
//!   `rebase --interactive`      → git.rebase.interactive (gated)
//!   `reset --soft`              → None (passthrough)
//!   `reset --hard`              → git.reset.hard (biometric + budget 3/session)
//!   `clean -f`                  → git.clean.force (biometric + budget 3/session)
//!   `clean -fd`                 → git.clean.force
//!   `branch -d feature`         → None (passthrough — soft delete)
//!   `branch -D feature`         → git.branch.force_delete (biometric)
//!   `branch --delete --force`   → git.branch.force_delete
//!   `tag v1.0`                  → None (passthrough — create)
//!   `tag -d v1.0`               → git.tag.delete (gated)
//!   `tag --delete v1.0`         → git.tag.delete (gated)
//!   `gc --aggressive`           → git.gc.destructive (gated)
//!   `gc --prune=now`            → git.gc.destructive (gated)

use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};
use core_construct_runtime::{ActionKey, ClassifyArgv};

/// Struct wrapper for daemon-side classify calls (ADR 124 §3).
#[derive(Debug, Default, Clone)]
pub struct GitClassifier;

impl ClassifyArgv for GitClassifier {
    fn classify(&self, argv: &[String]) -> Option<ActionKey> {
        classify_git_argv(argv)
    }
}

/// Classify `git <verb> [flags…]` argv into an action_key.
///
/// `argv` is the slice AFTER the `git` binary name (i.e. `argv[0]` is the
/// subcommand). Skips leading `-c key=value`, `-C path`, and embedded-value
/// long flags (`--git-dir=...`, `--work-tree=...`, etc.) — per `git`'s own
/// argv parser. Returns `None` for passthrough (read-only / safe writes).
pub fn classify_git_argv(argv: &[String]) -> Option<ActionKey> {
    let verb_idx = first_verb_index(argv)?;
    let verb = argv[verb_idx].as_str();
    let rest = &argv[verb_idx + 1..];

    match verb {
        // Read-only verbs — always passthrough.
        "status" | "log" | "diff" | "show" | "remote" | "config" | "rev-parse" | "ls-files"
        | "ls-tree" | "blame" | "bisect" | "stash" | "worktree" | "reflog" | "shortlog"
        | "describe" | "grep" | "archive" | "format-patch" | "count-objects" | "fsck" => None,

        // Verbs that have both passthrough and gated forms depending on flags.
        "commit" => classify_commit(rest),
        "push" => classify_push(rest),
        "rebase" => classify_rebase(rest),
        "reset" => classify_reset(rest),
        "clean" => classify_clean(rest),
        "branch" => classify_branch(rest),
        "tag" => classify_tag(rest),
        "gc" => classify_gc(rest),

        // Safe write verbs that have no gated variant in cohort-A scope.
        "add" | "rm" | "mv" | "checkout" | "switch" | "restore" | "merge" | "pull" | "fetch"
        | "clone" | "init" | "cherry-pick" | "revert" | "apply" | "am" | "notes" | "submodule"
        | "subtree" | "bundle" | "request-pull" | "send-email" | "instaweb" => None,

        // Catch-all: unknown verbs are passthrough (daemon will re-classify).
        _ => None,
    }
}

/// `git tag` — create is passthrough; `-d` / `--delete` is gated.
fn classify_tag(rest: &[String]) -> Option<ActionKey> {
    if has_flag(rest, &["-d", "--delete"]) {
        Some(ActionKey("git.tag.delete".to_string()))
    } else {
        None
    }
}

/// `git branch` — soft `-d` is passthrough; `-D` / `--delete --force` is gated.
fn classify_branch(rest: &[String]) -> Option<ActionKey> {
    let has_force = has_flag(rest, &["-D"])
        || (has_flag(rest, &["--delete", "-d"]) && has_flag(rest, &["--force", "-f"]));
    if has_force {
        Some(ActionKey("git.branch.force_delete".to_string()))
    } else {
        None
    }
}

/// `git commit` — plain commit is passthrough; `--amend` is gated.
fn classify_commit(rest: &[String]) -> Option<ActionKey> {
    if has_flag(rest, &["--amend"]) {
        Some(ActionKey("git.commit.amend".to_string()))
    } else {
        None
    }
}

/// `git push` — plain push is `git.push`; force variants upgrade to `git.push.force`;
/// `--tags` / `--follow-tags` (without force) route to `git.push.tags`.
fn classify_push(rest: &[String]) -> Option<ActionKey> {
    if is_force_push(rest) {
        Some(ActionKey("git.push.force".to_string()))
    } else if has_flag(rest, &["--tags", "--follow-tags"]) {
        Some(ActionKey("git.push.tags".to_string()))
    } else {
        Some(ActionKey("git.push".to_string()))
    }
}

/// Returns true if any token in `args` signals a force-push variant.
///
/// Handles:
///   `--force`, `-f`, `--force-with-lease` (standalone flag)
///   `--force-with-lease=<refspec>` (value form — starts-with check)
fn is_force_push(args: &[String]) -> bool {
    args.iter().any(|a| {
        matches!(a.as_str(), "--force" | "-f" | "--force-with-lease")
            || a.starts_with("--force-with-lease=")
    })
}

/// `git rebase` — plain rebase is passthrough; `-i` / `--interactive` is gated.
fn classify_rebase(rest: &[String]) -> Option<ActionKey> {
    if has_flag(rest, &["-i", "--interactive"]) {
        Some(ActionKey("git.rebase.interactive".to_string()))
    } else {
        None
    }
}

/// `git reset` — `--hard` is gated (budget 3/session); all others passthrough.
fn classify_reset(rest: &[String]) -> Option<ActionKey> {
    if has_flag(rest, &["--hard"]) {
        Some(ActionKey("git.reset.hard".to_string()))
    } else {
        None
    }
}

/// `git clean` — any `-f` / `--force` variant is gated; passthrough otherwise.
fn classify_clean(rest: &[String]) -> Option<ActionKey> {
    // `-f`, `-fd`, `-fX`, `-fx`, etc. — any token containing 'f' after a leading '-'.
    // We check for explicit `-f` / `--force` flags, plus combined short flags like `-fd`.
    let force = rest.iter().any(|a| {
        if a == "--force" {
            return true;
        }
        // Combined short flags: `-fd`, `-df`, `-fX`, etc.
        if let Some(flags) = a.strip_prefix('-')
            && !flags.starts_with('-')
        {
            return flags.contains('f');
        }
        false
    });

    if force {
        Some(ActionKey("git.clean.force".to_string()))
    } else {
        None
    }
}

/// `git gc` — `--aggressive` / `--prune=now` are gated; plain `gc` is passthrough.
fn classify_gc(rest: &[String]) -> Option<ActionKey> {
    let destructive = has_flag(rest, &["--aggressive"]) || rest.iter().any(|a| a == "--prune=now");

    if destructive {
        Some(ActionKey("git.gc.destructive".to_string()))
    } else {
        None
    }
}

/// Index of the first non-flag argv element — i.e. the subcommand verb.
/// Skips leading `git`-style global flag pairs:
///
///   - `-c key=value` (next arg is `key=value` — skip 2)
///   - `-C path` (next arg is path — skip 2)
///   - `--git-dir=...`, `--work-tree=...`, `--exec-path[=...]`,
///     `--namespace=...`, `--literal-pathspecs`, `--no-replace-objects`,
///     `--bare`, `--no-pager` (single arg with embedded value — skip 1)
///
/// Returns `None` when argv is empty, consists entirely of flag pairs,
/// or contains an unrecognized leading `-`-prefixed flag the parser
/// can't safely skip past (conservative — let the wrapped binary error
/// rather than guess a verb past an unknown flag).
fn first_verb_index(argv: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        if arg == "-c" || arg == "-C" {
            i += 2;
            continue;
        }
        if arg.starts_with("--git-dir")
            || arg.starts_with("--work-tree")
            || arg.starts_with("--exec-path")
            || arg.starts_with("--namespace")
            || arg.starts_with("--literal-pathspecs")
            || arg.starts_with("--no-replace-objects")
            || arg.starts_with("--bare")
            || arg.starts_with("--no-pager")
        {
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            return None;
        }
        return Some(i);
    }
    None
}

/// Returns true if `flags` contains any of `needles`.
fn has_flag(flags: &[String], needles: &[&str]) -> bool {
    flags.iter().any(|f| needles.contains(&f.as_str()))
}

/// Extract the remote-name positional from a git verb's argv tail.
///
/// For verbs in `{"push", "fetch", "pull", "clone"}`, returns the first
/// positional argument (after skipping flags). For `git push origin main`
/// the result is `Some("origin")`. For bare `git push` the result is `None`
/// (caller falls back to upstream resolution or refuses).
///
/// For `clone`, returns the first positional which is the URL itself (since
/// clone doesn't reference a configured remote — caller may distinguish).
///
/// Returns `None` for verbs that don't have a remote-name positional
/// (commit, status, log, etc.) and for malformed argv.
pub fn extract_git_remote_name(verb: &str, rest: &[String]) -> Option<String> {
    match verb {
        "push" | "fetch" | "pull" | "clone" => {}
        _ => return None,
    }
    // Skip leading flags (tokens starting with '-') to find first positional.
    rest.iter().find(|a| !a.starts_with('-')).cloned()
}

/// Classification of a git remote URL for least-privilege GitHub token minting
/// (ADR 204 BKR-2). Lets the mint path bound a GitHub installation token to the
/// concrete repo, while **degrading gracefully** — never refusing a push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubRemote {
    /// A `github.com` remote with a concrete `owner/repo` — bind the mint to it.
    Repo(String),
    /// A `github.com` remote whose `owner/repo` could not be extracted (a
    /// malformed/exotic URL). The mint should fall back to the action's declared
    /// (unbounded) scope rather than refuse — this is the rare safety valve.
    GithubUnparseable,
    /// Not a `github.com` remote (GitLab, internal git, a non-URL, …). A GitHub
    /// installation token is useless here, so the mint should be **skipped**
    /// entirely; the operation proceeds with its own auth.
    NotGithub,
}

/// Parse the host + path out of a git remote URL. Handles `scheme://[user@]host[:port]/path`
/// and scp-like `[user@]host:path`. Returns `(host, path)`.
fn split_remote_host_path(url: &str) -> Option<(&str, String)> {
    let url = url.trim();
    if let Some((_scheme, rest)) = url.split_once("://") {
        // URL form: [userinfo@]host[:port]/path
        let rest = rest.split_once('@').map(|(_, r)| r).unwrap_or(rest);
        let (host, path) = rest.split_once('/')?;
        Some((host.split(':').next().unwrap_or(host), path.to_string()))
    } else if let Some((hostpart, path)) = url.split_once(':') {
        // scp-like form: [user@]host:path
        let host = hostpart.split('@').next_back().unwrap_or(hostpart);
        Some((host, path.to_string()))
    } else {
        None
    }
}

/// Classify a git remote URL for GitHub least-privilege minting. The host must
/// be **exactly** `github.com` (lookalikes like `github.company.com` and
/// `evil.com/github.com/...` are `NotGithub`). See [`GithubRemote`].
pub fn classify_github_remote(url: &str) -> GithubRemote {
    let Some((host, path)) = split_remote_host_path(url) else {
        return GithubRemote::NotGithub;
    };
    if host != "github.com" {
        return GithubRemote::NotGithub;
    }
    let mut segs = path.trim_start_matches('/').split('/');
    let (Some(owner), Some(repo)) = (segs.next(), segs.next()) else {
        return GithubRemote::GithubUnparseable;
    };
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if owner.is_empty() || repo.is_empty() || owner.contains('*') || repo.contains('*') {
        return GithubRemote::GithubUnparseable;
    }
    GithubRemote::Repo(format!("{owner}/{repo}"))
}

/// Concrete `owner/repo` of a `github.com` remote, or `None` for any other host
/// / malformed URL. Thin wrapper over [`classify_github_remote`].
pub fn owner_repo_from_remote_url(url: &str) -> Option<String> {
    match classify_github_remote(url) {
        GithubRemote::Repo(r) => Some(r),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// GitFactory — P24 construct-factory contract for the git construct
// ---------------------------------------------------------------------------

static GIT_MANIFEST: std::sync::LazyLock<core_events::construct_toml::ParsedActionManifest> =
    std::sync::LazyLock::new(|| {
        core_events::construct_toml::parse_action_manifest(include_str!("../construct/git.toml"))
            .expect("bundled git.toml must be valid")
    });

fn manifest_need_for_action(action_key: &str) -> Option<Vec<String>> {
    GIT_MANIFEST
        .manifest
        .actions
        .iter()
        .find(|a| action_key.ends_with(&a.key))
        .and_then(|a| {
            let need = &a.need;
            if need.is_empty() {
                None
            } else {
                Some(need.clone())
            }
        })
}

fn action_in_manifest(action_key: &str) -> bool {
    GIT_MANIFEST
        .manifest
        .actions
        .iter()
        .any(|a| action_key.ends_with(&a.key))
}

/// P24 factory implementation for the `git` construct.
#[derive(Debug, Default, Clone)]
pub struct GitFactory;

/// Provider-specific target extracted from a `git` argv invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitFactoryTarget {
    pub provider: &'static str,
    pub host: String,
    pub repo: String,
    pub refspec: Option<String>,
}

/// Need atoms derived from the bundled manifest for one `git` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitFactoryNeed(pub Vec<String>);

impl InvocationGrammar for GitFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_git_argv(argv)
    }
}

impl TargetExtractor for GitFactory {
    type Target = GitFactoryTarget;

    fn target_for_argv(&self, _action_key: &ActionKey, argv: &[String]) -> Option<Self::Target> {
        let verb_idx = first_verb_index(argv)?;
        let verb = argv[verb_idx].as_str();
        let rest = &argv[verb_idx + 1..];

        match verb {
            "push" | "fetch" | "pull" | "clone" => {}
            _ => return None,
        }

        let remote = rest.iter().find(|a| !a.starts_with('-'))?.as_str();

        if !remote.contains("://") && !remote.contains(':') {
            return None;
        }

        let (host, path) = split_remote_host_path(remote)?;
        if host != "github.com" {
            return None;
        }

        let mut segs = path.trim_start_matches('/').split('/');
        let (owner, repo_raw) = (segs.next()?, segs.next()?);
        let repo = repo_raw.strip_suffix(".git").unwrap_or(repo_raw);
        if owner.is_empty() || repo.is_empty() {
            return None;
        }

        let refspec = rest.iter().filter(|a| !a.starts_with('-')).nth(1).cloned();

        Some(GitFactoryTarget {
            provider: "github",
            host: host.to_string(),
            repo: format!("{owner}/{repo}"),
            refspec,
        })
    }
}

impl NeedTemplate for GitFactory {
    type Need = GitFactoryNeed;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        _target: &Self::Target,
        _argv: &[String],
    ) -> Option<Self::Need> {
        manifest_need_for_action(&action_key.0).map(GitFactoryNeed)
    }
}

/// Returns `true` when `argv` contains `--mirror` (unbounded ref mutation).
fn has_mirror_flag(argv: &[String]) -> bool {
    argv.iter().any(|a| a == "--mirror")
}

impl ConstructFactory for GitFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> FactoryDisposition {
        let Some(key) = action_key else {
            return FactoryDisposition::Credentialless;
        };

        if has_mirror_flag(argv) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        if !action_in_manifest(&key.0) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        if manifest_need_for_action(&key.0).is_none() {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        let verb_idx = first_verb_index(argv);
        let has_url_remote = verb_idx
            .and_then(|i| {
                let rest = &argv[i + 1..];
                rest.iter().find(|a| !a.starts_with('-'))
            })
            .is_some_and(|remote| remote.contains("://") || remote.contains(':'));

        if has_url_remote {
            FactoryDisposition::Mediated
        } else {
            FactoryDisposition::ResolverRequired
        }
    }

    /// Trusted resolver: derive the github origin URL from cwd's
    /// `.git/config`, then synthesize the argv by replacing the
    /// remote-alias positional (e.g. `origin`) with the URL — or
    /// appending the URL when argv has no remote positional. The
    /// resulting argv has the URL inline, so the existing
    /// `disposition_for_argv` flips ResolverRequired → Mediated and the
    /// daemon's existing `target ⊆ grant.resource` clamp gates the
    /// derived target.
    ///
    /// Skipped for `clone` (its argv already requires a URL positional)
    /// and when the first positional is already URL-shaped.
    fn resolve_target_from_environment(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
        cwd: &std::path::Path,
    ) -> Option<Vec<String>> {
        let _key = action_key?;
        let verb_idx = first_verb_index(argv)?;
        let verb = argv[verb_idx].as_str();
        // `clone` always carries the URL inline; no env-derive applies.
        if verb == "clone" {
            return None;
        }
        let rest_start = verb_idx + 1;
        let alias_pos = argv[rest_start..]
            .iter()
            .position(|a| !a.starts_with('-'))
            .map(|p| rest_start + p);
        // If a positional is already URL-shaped, don't derive.
        if let Some(pos) = alias_pos {
            let candidate = argv[pos].as_str();
            if candidate.contains("://") || candidate.contains(':') {
                return None;
            }
        }

        let url = crate::env_derive::cwd_git_remote_origin_url(cwd)?;
        // Synthesize only when the derived URL is a github URL — the
        // existing GitFactory disposition flips to Mediated only on
        // github URLs (`target_for_argv` is github-only), so a non-github
        // origin won't unlock the Mediated path. Fall through to the
        // existing refusal in that case rather than emit confusing argv.
        if !matches!(classify_github_remote(&url), GithubRemote::Repo(_)) {
            return None;
        }

        let mut synthesized = argv.to_vec();
        match alias_pos {
            Some(pos) => {
                // Replace alias (e.g. `origin`) with the derived URL.
                synthesized[pos] = url;
            }
            None => {
                // No positional — append URL at the canonical
                // post-options position for `git push [options] [repo]`.
                synthesized.push(url);
            }
        }
        Some(synthesized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    fn key(strs: &[&str]) -> Option<String> {
        classify_git_argv(&args(strs)).map(|k| k.0)
    }

    // --- github remote classification (ADR 204 BKR-2) ---

    #[test]
    fn owner_repo_from_https_with_and_without_dot_git() {
        assert_eq!(
            owner_repo_from_remote_url("https://github.com/emberdotlink/emberlink-dev.git")
                .as_deref(),
            Some("emberdotlink/emberlink-dev")
        );
        assert_eq!(
            owner_repo_from_remote_url("https://github.com/emberdotlink/emberlink-dev").as_deref(),
            Some("emberdotlink/emberlink-dev")
        );
    }

    #[test]
    fn owner_repo_from_embedded_token_and_port() {
        let token_remote = format!(
            "https://{}@github.com/acme/widgets.git",
            "x-access-token:example-token"
        );
        assert_eq!(
            owner_repo_from_remote_url(&token_remote).as_deref(),
            Some("acme/widgets")
        );
        assert_eq!(
            owner_repo_from_remote_url("https://github.com:443/acme/widgets").as_deref(),
            Some("acme/widgets")
        );
    }

    #[test]
    fn owner_repo_from_scp_and_ssh_forms() {
        assert_eq!(
            owner_repo_from_remote_url("git@github.com:acme/widgets.git").as_deref(),
            Some("acme/widgets")
        );
        assert_eq!(
            owner_repo_from_remote_url("ssh://git@github.com/acme/widgets.git").as_deref(),
            Some("acme/widgets")
        );
    }

    #[test]
    fn classify_non_github_host_is_not_github_not_unparseable() {
        // The hot-path-safety distinction: a real non-github remote must be
        // NotGithub (skip the mint), NOT GithubUnparseable (which would
        // unbounded-fallback). A non-URL is also NotGithub.
        for url in [
            "https://gitlab.com/a/b.git",
            "https://evil.com/github.com/a/b", // host is evil.com
            "https://github.company.com/a/b",  // lookalike host
            "git@gitlab.com:a/b.git",
            "not a url",
        ] {
            assert_eq!(
                classify_github_remote(url),
                GithubRemote::NotGithub,
                "{url}"
            );
            assert_eq!(owner_repo_from_remote_url(url), None, "{url}");
        }
    }

    #[test]
    fn classify_github_host_but_malformed_is_unparseable() {
        // github.com host but no concrete owner/repo → unbounded-fallback, not skip.
        for url in [
            "https://github.com/owner",   // missing repo segment
            "https://github.com/owner/*", // wildcard repo
            "https://github.com//",       // empty segments
        ] {
            assert_eq!(
                classify_github_remote(url),
                GithubRemote::GithubUnparseable,
                "{url}"
            );
            assert_eq!(owner_repo_from_remote_url(url), None, "{url}");
        }
    }

    #[test]
    fn classify_github_repo_form() {
        assert_eq!(
            classify_github_remote("https://github.com/acme/widgets.git"),
            GithubRemote::Repo("acme/widgets".to_string())
        );
    }

    // --- push ---

    #[test]
    fn push_plain_is_git_push() {
        assert_eq!(key(&["push"]), Some("git.push".to_string()));
    }

    #[test]
    fn push_with_remote_is_git_push() {
        assert_eq!(
            key(&["push", "origin", "main"]),
            Some("git.push".to_string())
        );
    }

    #[test]
    fn push_force_long_flag() {
        assert_eq!(
            key(&["push", "--force"]),
            Some("git.push.force".to_string())
        );
    }

    #[test]
    fn push_force_short_flag() {
        assert_eq!(key(&["push", "-f"]), Some("git.push.force".to_string()));
    }

    #[test]
    fn push_force_with_lease_standalone() {
        assert_eq!(
            key(&["push", "--force-with-lease"]),
            Some("git.push.force".to_string())
        );
    }

    #[test]
    fn push_force_with_lease_value_form() {
        // --force-with-lease=<ref> — the =value form is a single argv element.
        assert_eq!(
            key(&["push", "--force-with-lease=origin/main"]),
            Some("git.push.force".to_string())
        );
    }

    #[test]
    fn push_force_with_lease_value_form_branch() {
        assert_eq!(
            key(&["push", "origin", "--force-with-lease=refs/heads/feat"]),
            Some("git.push.force".to_string())
        );
    }

    #[test]
    fn push_tags_only() {
        assert_eq!(key(&["push", "--tags"]), Some("git.push.tags".to_string()));
    }

    #[test]
    fn push_follow_tags() {
        assert_eq!(
            key(&["push", "--follow-tags"]),
            Some("git.push.tags".to_string())
        );
    }

    #[test]
    fn push_force_beats_tags() {
        // Force takes priority over --tags when both are present.
        assert_eq!(
            key(&["push", "--force", "--tags"]),
            Some("git.push.force".to_string())
        );
    }

    // --- commit ---

    #[test]
    fn commit_plain_is_passthrough() {
        assert_eq!(key(&["commit", "-m", "msg"]), None);
    }

    #[test]
    fn commit_amend_is_gated() {
        assert_eq!(
            key(&["commit", "--amend"]),
            Some("git.commit.amend".to_string())
        );
    }

    #[test]
    fn commit_amend_with_message() {
        assert_eq!(
            key(&["commit", "--amend", "-m", "updated"]),
            Some("git.commit.amend".to_string())
        );
    }

    // --- rebase ---

    #[test]
    fn rebase_plain_is_passthrough() {
        assert_eq!(key(&["rebase", "HEAD~3"]), None);
    }

    #[test]
    fn rebase_onto_is_passthrough() {
        assert_eq!(key(&["rebase", "--onto", "main", "feat~3"]), None);
    }

    #[test]
    fn rebase_interactive_short() {
        assert_eq!(
            key(&["rebase", "-i", "HEAD~3"]),
            Some("git.rebase.interactive".to_string())
        );
    }

    #[test]
    fn rebase_interactive_long() {
        assert_eq!(
            key(&["rebase", "--interactive", "HEAD~5"]),
            Some("git.rebase.interactive".to_string())
        );
    }

    // --- reset ---

    #[test]
    fn reset_soft_is_passthrough() {
        assert_eq!(key(&["reset", "--soft", "HEAD~1"]), None);
    }

    #[test]
    fn reset_mixed_is_passthrough() {
        assert_eq!(key(&["reset", "--mixed", "HEAD"]), None);
    }

    #[test]
    fn reset_hard_is_gated() {
        assert_eq!(
            key(&["reset", "--hard"]),
            Some("git.reset.hard".to_string())
        );
    }

    #[test]
    fn reset_hard_with_ref() {
        assert_eq!(
            key(&["reset", "--hard", "origin/main"]),
            Some("git.reset.hard".to_string())
        );
    }

    // --- clean ---

    #[test]
    fn clean_dry_run_is_passthrough() {
        assert_eq!(key(&["clean", "-n"]), None);
    }

    #[test]
    fn clean_force_short() {
        assert_eq!(key(&["clean", "-f"]), Some("git.clean.force".to_string()));
    }

    #[test]
    fn clean_force_long() {
        assert_eq!(
            key(&["clean", "--force"]),
            Some("git.clean.force".to_string())
        );
    }

    #[test]
    fn clean_fd_combined() {
        // `-fd` is a combined short flag — force + directories.
        assert_eq!(key(&["clean", "-fd"]), Some("git.clean.force".to_string()));
    }

    #[test]
    fn clean_dfx_combined() {
        // `-dfx` contains 'f' → gated.
        assert_eq!(key(&["clean", "-dfx"]), Some("git.clean.force".to_string()));
    }

    // --- branch ---

    #[test]
    fn branch_list_is_passthrough() {
        assert_eq!(key(&["branch"]), None);
    }

    #[test]
    fn branch_soft_delete_is_passthrough() {
        assert_eq!(key(&["branch", "-d", "feature"]), None);
    }

    #[test]
    fn branch_force_delete_uppercase_d() {
        assert_eq!(
            key(&["branch", "-D", "feature"]),
            Some("git.branch.force_delete".to_string())
        );
    }

    #[test]
    fn branch_delete_force_long_flags() {
        assert_eq!(
            key(&["branch", "--delete", "--force", "feature"]),
            Some("git.branch.force_delete".to_string())
        );
    }

    // --- tag ---

    #[test]
    fn tag_create_is_passthrough() {
        assert_eq!(key(&["tag", "v1.0"]), None);
    }

    #[test]
    fn tag_list_is_passthrough() {
        assert_eq!(key(&["tag"]), None);
    }

    #[test]
    fn tag_delete_short() {
        assert_eq!(
            key(&["tag", "-d", "v1.0"]),
            Some("git.tag.delete".to_string())
        );
    }

    #[test]
    fn tag_delete_long() {
        assert_eq!(
            key(&["tag", "--delete", "v1.0"]),
            Some("git.tag.delete".to_string())
        );
    }

    // --- gc ---

    #[test]
    fn gc_plain_is_passthrough() {
        assert_eq!(key(&["gc"]), None);
    }

    #[test]
    fn gc_aggressive_is_gated() {
        assert_eq!(
            key(&["gc", "--aggressive"]),
            Some("git.gc.destructive".to_string())
        );
    }

    #[test]
    fn gc_prune_now_is_gated() {
        assert_eq!(
            key(&["gc", "--prune=now"]),
            Some("git.gc.destructive".to_string())
        );
    }

    // --- read-only passthrough verbs ---

    #[test]
    fn read_only_verbs_are_passthrough() {
        for verb in &[
            "status",
            "log",
            "diff",
            "show",
            "remote",
            "config",
            "rev-parse",
            "ls-files",
            "blame",
            "reflog",
        ] {
            assert!(
                classify_git_argv(&args(&[verb])).is_none(),
                "{verb} should be passthrough"
            );
        }
    }

    #[test]
    fn safe_write_verbs_are_passthrough() {
        for verb in &[
            "add",
            "rm",
            "mv",
            "checkout",
            "switch",
            "merge",
            "pull",
            "fetch",
            "clone",
            "init",
            "cherry-pick",
            "revert",
        ] {
            assert!(
                classify_git_argv(&args(&[verb])).is_none(),
                "{verb} should be passthrough"
            );
        }
    }

    #[test]
    fn empty_argv_is_passthrough() {
        assert!(classify_git_argv(&[]).is_none());
    }

    // --- extract_git_remote_name ---

    #[test]
    fn extract_remote_name_push_with_origin() {
        let argv: Vec<String> = vec!["push".into(), "origin".into(), "main".into()];
        assert_eq!(
            extract_git_remote_name("push", &argv[1..]),
            Some("origin".into())
        );
    }

    #[test]
    fn extract_remote_name_push_bare() {
        let argv: Vec<String> = vec!["push".into()];
        assert_eq!(extract_git_remote_name("push", &argv[1..]), None);
    }

    #[test]
    fn extract_remote_name_push_with_upstream_flag() {
        // git push -u origin feature/foo
        let argv: Vec<String> = vec![
            "push".into(),
            "-u".into(),
            "origin".into(),
            "feature/foo".into(),
        ];
        assert_eq!(
            extract_git_remote_name("push", &argv[1..]),
            Some("origin".into())
        );
    }

    #[test]
    fn extract_remote_name_push_with_force_flag() {
        let argv: Vec<String> = vec!["push".into(), "--force".into(), "upstream".into()];
        assert_eq!(
            extract_git_remote_name("push", &argv[1..]),
            Some("upstream".into())
        );
    }

    #[test]
    fn extract_remote_name_fetch_with_remote() {
        let argv: Vec<String> = vec!["fetch".into(), "upstream".into()];
        assert_eq!(
            extract_git_remote_name("fetch", &argv[1..]),
            Some("upstream".into())
        );
    }

    #[test]
    fn extract_remote_name_unrelated_verb_returns_none() {
        assert_eq!(
            extract_git_remote_name("commit", &["-m".into(), "msg".into()]),
            None
        );
    }

    // --- GitFactory tests ---

    #[test]
    fn git_factory_push_exact_https_is_mediated() {
        let f = GitFactory;
        let a = args(&[
            "push",
            "https://github.com/emberdotlink/emberlink-dev.git",
            "HEAD:main",
        ]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::Mediated
        );
    }

    #[test]
    fn git_factory_push_origin_is_resolver_required() {
        let f = GitFactory;
        let a = args(&["push", "origin", "main"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn git_factory_push_mirror_is_unsupported() {
        let f = GitFactory;
        let a = args(&["push", "--mirror", "origin"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn git_factory_force_push_no_need_is_unsupported() {
        let f = GitFactory;
        let a = args(&["push", "--force", "origin", "main"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn git_factory_push_bare_is_resolver_required() {
        let f = GitFactory;
        let a = args(&["push"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn git_factory_reset_hard_is_unsupported() {
        let f = GitFactory;
        let a = args(&["reset", "--hard", "HEAD~1"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn git_factory_commit_passthrough_is_credentialless() {
        let f = GitFactory;
        let a = args(&["commit", "-m", "msg"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn git_factory_target_extraction_https() {
        let f = GitFactory;
        let a = args(&[
            "push",
            "https://github.com/emberdotlink/emberlink-dev.git",
            "HEAD:main",
        ]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.provider, "github");
        assert_eq!(target.host, "github.com");
        assert_eq!(target.repo, "emberdotlink/emberlink-dev");
        assert_eq!(target.refspec, Some("HEAD:main".to_string()));
    }

    #[test]
    fn git_factory_target_extraction_scp() {
        let f = GitFactory;
        let a = args(&["push", "git@github.com:acme/widgets.git", "main"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.repo, "acme/widgets");
        assert_eq!(target.refspec, Some("main".to_string()));
    }

    #[test]
    fn git_factory_target_alias_returns_none() {
        let f = GitFactory;
        let a = args(&["push", "origin", "main"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert!(f.target_for_argv(&key, &a).is_none());
    }

    #[test]
    fn git_factory_target_non_github_returns_none() {
        let f = GitFactory;
        let a = args(&["push", "https://gitlab.com/acme/widgets.git", "main"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert!(f.target_for_argv(&key, &a).is_none());
    }

    #[test]
    fn git_factory_need_resolution_push() {
        let f = GitFactory;
        let a = args(&["push", "https://github.com/acme/widgets.git", "main"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target");
        let need = f.need_for_target(&key, &target, &a).expect("need resolved");
        assert_eq!(
            need.0,
            vec!["github:metadata:read", "github:contents:write"]
        );
    }

    #[test]
    fn git_factory_push_ssh_url_is_mediated() {
        let f = GitFactory;
        let a = args(&["push", "ssh://git@github.com/acme/widgets.git", "HEAD:main"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::Mediated
        );
    }

    #[test]
    fn git_factory_contract_runs_conformance_corpus() {
        let corpus = core_construct_runtime::factory::parse_factory_fixture_corpus(include_str!(
            "../conformance/git/factory-fixtures.toml"
        ))
        .expect("fixture corpus parses");
        let validation_errors =
            core_construct_runtime::factory::validate_factory_fixture_corpus(&corpus);
        assert!(validation_errors.is_empty(), "{validation_errors:#?}");

        let carrier = core_construct_runtime::factory::ActionManifestV2Carrier::parse(
            include_str!("../construct/git.toml"),
        )
        .expect("git manifest carrier parses");
        let report = core_construct_runtime::factory::run_factory_fixtures(
            &GitFactory,
            Some(&carrier),
            &corpus,
        );
        assert!(report.is_clean(), "{:#?}", report.failures);
    }

    // -----------------------------------------------------------------------
    // V030-FACTORY-RESOLVER-COHORT-A: GitFactory::resolve_target_from_environment
    //
    // AC: derive github origin URL from cwd, replace remote-alias positional
    //     (e.g. `origin`) with the derived URL, or append URL on bare push.
    //     Non-github origins return None. Already-URL argv returns None.
    //     `clone` returns None (URL is always explicit).
    // -----------------------------------------------------------------------

    use std::process::Command;
    use std::sync::Mutex;

    static GIT_RESOLVER_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn make_git_repo_with_origin(remote_url: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cwd = tmp.path();
        let init = Command::new(crate::env_derive::SYSTEM_GIT_BINARY)
            .args(["init", "--quiet"])
            .current_dir(cwd)
            .output()
            .expect("git init");
        assert!(init.status.success(), "git init failed: {init:?}");
        let remote = Command::new(crate::env_derive::SYSTEM_GIT_BINARY)
            .args(["remote", "add", "origin", remote_url])
            .current_dir(cwd)
            .output()
            .expect("git remote add");
        assert!(remote.status.success(), "git remote add failed: {remote:?}");
        tmp
    }

    fn skip_if_no_system_git() -> bool {
        if !std::path::Path::new(crate::env_derive::SYSTEM_GIT_BINARY).exists() {
            eprintln!(
                "skipping: {} not present on this host",
                crate::env_derive::SYSTEM_GIT_BINARY
            );
            return true;
        }
        false
    }

    /// Happy path: `git push origin main` with origin → github URL.
    /// Synthesised argv replaces `origin` with the URL.
    #[test]
    fn git_factory_resolver_replaces_origin_alias_with_derived_url() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GIT_RESOLVER_TEST_LOCK.lock().unwrap();
        let repo = make_git_repo_with_origin("https://github.com/acme/widgets.git");

        let f = GitFactory;
        let argv = args(&["push", "origin", "main"]);
        let key = f.action_key_for_argv(&argv).expect("classified");
        let synthesized = f
            .resolve_target_from_environment(Some(&key), &argv, repo.path())
            .expect("resolver derived target");

        assert_eq!(
            synthesized,
            vec![
                "push".to_string(),
                "https://github.com/acme/widgets.git".to_string(),
                "main".to_string()
            ]
        );

        // Synthesised argv flips disposition to Mediated.
        assert_eq!(
            f.disposition_for_argv(Some(&key), &synthesized),
            FactoryDisposition::Mediated
        );
    }

    /// Bare `git push` (no positional) → append URL at end.
    #[test]
    fn git_factory_resolver_appends_url_on_bare_push() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GIT_RESOLVER_TEST_LOCK.lock().unwrap();
        let repo = make_git_repo_with_origin("https://github.com/acme/widgets.git");

        let f = GitFactory;
        let argv = args(&["push"]);
        let key = f.action_key_for_argv(&argv).expect("classified");
        let synthesized = f
            .resolve_target_from_environment(Some(&key), &argv, repo.path())
            .expect("resolver derived target");
        assert_eq!(
            synthesized,
            vec![
                "push".to_string(),
                "https://github.com/acme/widgets.git".to_string()
            ]
        );
        assert_eq!(
            f.disposition_for_argv(Some(&key), &synthesized),
            FactoryDisposition::Mediated
        );
    }

    /// `git push -u origin main` → preserve `-u` flag, replace alias.
    #[test]
    fn git_factory_resolver_preserves_flags_when_replacing_alias() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GIT_RESOLVER_TEST_LOCK.lock().unwrap();
        let repo = make_git_repo_with_origin("https://github.com/acme/widgets.git");

        let f = GitFactory;
        let argv = args(&["push", "-u", "origin", "feature/x"]);
        let key = f.action_key_for_argv(&argv).expect("classified");
        let synthesized = f
            .resolve_target_from_environment(Some(&key), &argv, repo.path())
            .expect("resolver derived target");
        assert_eq!(
            synthesized,
            vec![
                "push".to_string(),
                "-u".to_string(),
                "https://github.com/acme/widgets.git".to_string(),
                "feature/x".to_string()
            ]
        );
    }

    /// Argv already URL-shaped → resolver is a no-op (returns None).
    #[test]
    fn git_factory_resolver_no_op_when_argv_already_has_url() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GIT_RESOLVER_TEST_LOCK.lock().unwrap();
        let repo = make_git_repo_with_origin("https://github.com/acme/widgets.git");

        let f = GitFactory;
        let argv = args(&["push", "https://github.com/explicit/target.git", "main"]);
        let key = f.action_key_for_argv(&argv).expect("classified");
        let synthesized = f.resolve_target_from_environment(Some(&key), &argv, repo.path());
        assert_eq!(synthesized, None);
    }

    /// `clone` always carries its URL inline; resolver returns None.
    #[test]
    fn git_factory_resolver_skips_clone() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GIT_RESOLVER_TEST_LOCK.lock().unwrap();
        let repo = make_git_repo_with_origin("https://github.com/acme/widgets.git");

        let f = GitFactory;
        // `clone` is classified as None (passthrough) — but if the
        // hook is ever called for clone, it must still return None.
        let argv = args(&["clone"]);
        // For this test we synthesise an action_key since the
        // classifier would return None for `clone`.
        let synthesized = f.resolve_target_from_environment(
            Some(&ActionKey("git.clone".to_string())),
            &argv,
            repo.path(),
        );
        assert_eq!(synthesized, None);
    }

    /// Non-github origin → resolver returns None (won't unlock Mediated).
    #[test]
    fn git_factory_resolver_returns_none_for_non_github_origin() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GIT_RESOLVER_TEST_LOCK.lock().unwrap();
        let repo = make_git_repo_with_origin("https://gitlab.com/acme/widgets.git");

        let f = GitFactory;
        let argv = args(&["push", "origin", "main"]);
        let key = f.action_key_for_argv(&argv).expect("classified");
        let synthesized = f.resolve_target_from_environment(Some(&key), &argv, repo.path());
        assert_eq!(synthesized, None);
    }

    /// Outside any git repo → resolver returns None.
    #[test]
    fn git_factory_resolver_outside_git_repo_returns_none() {
        if skip_if_no_system_git() {
            return;
        }
        let _guard = GIT_RESOLVER_TEST_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().expect("tempdir");

        let f = GitFactory;
        let argv = args(&["push", "origin"]);
        let key = f.action_key_for_argv(&argv).expect("classified");
        let synthesized = f.resolve_target_from_environment(Some(&key), &argv, tmp.path());
        assert_eq!(synthesized, None);
    }
}
