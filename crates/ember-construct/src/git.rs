//! Argv classifier: maps `git <verb> [flags…]` to a `construct.toml` action_key.
//! Per design §3 — this lives shim-side BUT the daemon re-classifies the argv
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

use core_construct_runtime::{ActionKey, ClassifyArgv};

/// Struct wrapper for daemon-side classify calls (design §3).
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
        "status"
        | "log"
        | "diff"
        | "show"
        | "remote"
        | "config"
        | "rev-parse"
        | "ls-files"
        | "ls-tree"
        | "blame"
        | "bisect"
        | "stash"
        | "worktree"
        | "reflog"
        | "shortlog"
        | "describe"
        | "grep"
        | "archive"
        | "format-patch"
        | "count-objects"
        | "fsck" => None,

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
        "add"
        | "rm"
        | "mv"
        | "checkout"
        | "switch"
        | "restore"
        | "merge"
        | "pull"
        | "fetch"
        | "clone"
        | "init"
        | "cherry-pick"
        | "revert"
        | "apply"
        | "am"
        | "notes"
        | "submodule"
        | "subtree"
        | "bundle"
        | "request-pull"
        | "send-email"
        | "instaweb" => None,

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
    let destructive = has_flag(rest, &["--aggressive"])
        || rest.iter().any(|a| a == "--prune=now");

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
    rest.iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
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

    // --- push ---

    #[test]
    fn push_plain_is_git_push() {
        assert_eq!(key(&["push"]), Some("git.push".to_string()));
    }

    #[test]
    fn push_with_remote_is_git_push() {
        assert_eq!(key(&["push", "origin", "main"]), Some("git.push".to_string()));
    }

    #[test]
    fn push_force_long_flag() {
        assert_eq!(key(&["push", "--force"]), Some("git.push.force".to_string()));
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
        assert_eq!(
            key(&["clean", "-f"]),
            Some("git.clean.force".to_string())
        );
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
        assert_eq!(
            key(&["clean", "-fd"]),
            Some("git.clean.force".to_string())
        );
    }

    #[test]
    fn clean_dfx_combined() {
        // `-dfx` contains 'f' → gated.
        assert_eq!(
            key(&["clean", "-dfx"]),
            Some("git.clean.force".to_string())
        );
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
            "status", "log", "diff", "show", "remote", "config",
            "rev-parse", "ls-files", "blame", "reflog",
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
            "add", "rm", "mv", "checkout", "switch", "merge", "pull",
            "fetch", "clone", "init", "cherry-pick", "revert",
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
        assert_eq!(extract_git_remote_name("push", &argv[1..]), Some("origin".into()));
    }

    #[test]
    fn extract_remote_name_push_bare() {
        let argv: Vec<String> = vec!["push".into()];
        assert_eq!(extract_git_remote_name("push", &argv[1..]), None);
    }

    #[test]
    fn extract_remote_name_push_with_upstream_flag() {
        // git push -u origin feature/foo
        let argv: Vec<String> = vec!["push".into(), "-u".into(), "origin".into(), "feature/foo".into()];
        assert_eq!(extract_git_remote_name("push", &argv[1..]), Some("origin".into()));
    }

    #[test]
    fn extract_remote_name_push_with_force_flag() {
        let argv: Vec<String> = vec!["push".into(), "--force".into(), "upstream".into()];
        assert_eq!(extract_git_remote_name("push", &argv[1..]), Some("upstream".into()));
    }

    #[test]
    fn extract_remote_name_fetch_with_remote() {
        let argv: Vec<String> = vec!["fetch".into(), "upstream".into()];
        assert_eq!(extract_git_remote_name("fetch", &argv[1..]), Some("upstream".into()));
    }

    #[test]
    fn extract_remote_name_unrelated_verb_returns_none() {
        assert_eq!(extract_git_remote_name("commit", &["-m".into(), "msg".into()]), None);
    }
}
