//! Argv classifier: maps `flyctl <group> [<subgroup> ...] <verb> [args]` to
//! a `construct.toml` action_key. Per design §3 — this lives shim-side BUT
//! the daemon re-classifies the argv server-side (untrusts the shim).
//!
//! Fly.io CLI argv shape:
//!
//! ```text
//! flyctl [global-flags...] <group> [<subgroup> ...] <verb> [verb-args...]
//! ```
//!
//! Global flags (`--access-token`, `--app`, `--config`, `--region`,
//! `--json`, `--debug`, `--verbose`) may appear before, between, or after
//! the group/verb tokens. We strip them — including their values for the
//! flags that take one — before pattern-matching, so classification is
//! stable under flag reordering.
//!
//! Coverage (mutating verbs are gated; read-only verbs passthrough as `None`):
//!
//! | argv prefix                                              | action_key                          |
//! |----------------------------------------------------------|-------------------------------------|
//! | `apps {create,destroy,restart,scale,deploy}`             | `fly.apps.<verb>`                   |
//! | `apps releases rollback`                                 | `fly.apps.releases.rollback`        |
//! | `machine {run,stop,start,restart,destroy,exec,clone,update}` | `fly.machine.<verb>`            |
//! | `volumes {create,destroy,extend,fork}`                   | `fly.volumes.<verb>`                |
//! | `secrets {set,unset,import,deploy}`                      | `fly.secrets.<verb>`                |
//! | `deploy` (top-level)                                     | `fly.deploy`                        |
//! | `scale {count,vm,memory,show}`                           | `fly.scale.<verb>`                  |
//! | `regions {add,remove,set,backup}`                        | `fly.regions.<verb>`                |
//! | `postgres {create,destroy,attach,detach,connect}`        | `fly.postgres.<verb>`               |
//! | `redis {create,destroy,update}`                          | `fly.redis.<verb>`                  |
//! | `certs {add,remove,check}`                               | `fly.certs.<verb>`                  |
//! | `ips {allocate-v4,allocate-v6,release}`                  | `fly.ips.<verb>`                    |
//! | `tokens {create,revoke}`                                 | `fly.tokens.<verb>`                 |
//! | `orgs revoke`                                            | `fly.orgs.revoke`                   |
//! | `ssh {issue,console}`                                    | `fly.ssh.<verb>`                    |
//! | `status \| list \| info \| logs \| version \| dashboard` | `None` (passthrough)                |
//! | `apps list \| machine list \| regions list \| tokens list` | `None` (passthrough)              |

use core_construct_runtime::ActionKey;

/// Fly CLI global flags that take a value as the *next* argv token.
/// When stripping, both the flag and its value are removed.
const VALUE_BEARING_GLOBAL_FLAGS: &[&str] = &[
    "--access-token",
    "-t",
    "--app",
    "-a",
    "--config",
    "-c",
    "--region",
    "-r",
];

/// Fly CLI global flags that are valueless (boolean toggles).
const BOOLEAN_GLOBAL_FLAGS: &[&str] = &["--json", "--debug", "--verbose"];

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
            if VALUE_BEARING_GLOBAL_FLAGS.contains(&name)
                || BOOLEAN_GLOBAL_FLAGS.contains(&name)
            {
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

/// Returns `true` if `verb` looks like a read-only Fly CLI verb.
///
/// Read-only verbs include `list`, `status`, `info`, `logs`, `version`,
/// `dashboard`, `show`, plus the help shape.
fn is_read_only_verb(verb: &str) -> bool {
    matches!(
        verb,
        "list" | "status" | "info" | "logs" | "version" | "dashboard" | "show" | "help"
    )
}

/// Classify `flyctl <group> [<subgroup> ...] <verb> ...` argv into an
/// action_key.
///
/// Returns `None` for read-only / unrecognized shapes — the runtime
/// treats `None` as passthrough (no broker mediation).
pub fn classify_flyctl_argv(argv: &[String]) -> Option<ActionKey> {
    let stripped = strip_global_flags(argv);

    let g0 = stripped.first()?.as_str();

    // Top-level `deploy` shorthand (no group/verb split).
    if g0 == "deploy" {
        return Some(ActionKey("fly.deploy".to_string()));
    }

    // Top-level read-only verbs (e.g., `fly status`, `fly version`).
    if is_read_only_verb(g0) {
        return None;
    }

    let g1 = stripped.get(1).map(|s| s.as_str())?;

    // Read-only second-token verbs (e.g., `fly apps list`,
    // `fly machine list`, `fly regions list`, `fly tokens list`).
    if is_read_only_verb(g1) {
        return None;
    }

    match g0 {
        // apps <verb> | apps releases rollback
        "apps" => match g1 {
            "create" | "destroy" | "restart" | "scale" | "deploy" => {
                Some(ActionKey(format!("fly.apps.{g1}")))
            }
            "releases" => {
                let g2 = stripped.get(2).map(|s| s.as_str())?;
                if g2 == "rollback" {
                    Some(ActionKey("fly.apps.releases.rollback".to_string()))
                } else {
                    None
                }
            }
            _ => None,
        },

        // machine <verb> (singular per spec).
        "machine" => match g1 {
            "run" | "stop" | "start" | "restart" | "destroy" | "exec" | "clone"
            | "update" => Some(ActionKey(format!("fly.machine.{g1}"))),
            _ => None,
        },

        // volumes <verb>
        "volumes" => match g1 {
            "create" | "destroy" | "extend" | "fork" => {
                Some(ActionKey(format!("fly.volumes.{g1}")))
            }
            _ => None,
        },

        // secrets <verb>
        "secrets" => match g1 {
            "set" | "unset" | "import" | "deploy" => {
                Some(ActionKey(format!("fly.secrets.{g1}")))
            }
            _ => None,
        },

        // scale <verb> — write subcommands. `show` is read-only and
        // returns None via the second-token read-only check above.
        "scale" => match g1 {
            "count" | "vm" | "memory" => {
                Some(ActionKey(format!("fly.scale.{g1}")))
            }
            _ => None,
        },

        // regions <verb> — list is read-only (handled above).
        "regions" => match g1 {
            "add" | "remove" | "set" | "backup" => {
                Some(ActionKey(format!("fly.regions.{g1}")))
            }
            _ => None,
        },

        // postgres <verb>
        "postgres" => match g1 {
            "create" | "destroy" | "attach" | "detach" | "connect" => {
                Some(ActionKey(format!("fly.postgres.{g1}")))
            }
            _ => None,
        },

        // redis <verb>
        "redis" => match g1 {
            "create" | "destroy" | "update" => {
                Some(ActionKey(format!("fly.redis.{g1}")))
            }
            _ => None,
        },

        // certs <verb>
        "certs" => match g1 {
            "add" | "remove" | "check" => {
                Some(ActionKey(format!("fly.certs.{g1}")))
            }
            _ => None,
        },

        // ips <verb>
        "ips" => match g1 {
            "allocate-v4" | "allocate-v6" | "release" => {
                Some(ActionKey(format!("fly.ips.{g1}")))
            }
            _ => None,
        },

        // tokens <verb> — list is read-only (handled above).
        "tokens" => match g1 {
            "create" | "revoke" => Some(ActionKey(format!("fly.tokens.{g1}"))),
            _ => None,
        },

        // orgs revoke (only privilege-removal verb classified).
        "orgs" => match g1 {
            "revoke" => Some(ActionKey("fly.orgs.revoke".to_string())),
            _ => None,
        },

        // ssh <verb>
        "ssh" => match g1 {
            "issue" | "console" => Some(ActionKey(format!("fly.ssh.{g1}"))),
            _ => None,
        },

        // Unknown group → passthrough; daemon re-classifies.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // --- apps ---

    #[test]
    fn apps_create_classified() {
        let r = classify_flyctl_argv(&args(&["apps", "create", "myapp"])).unwrap();
        assert_eq!(r.0, "fly.apps.create");
    }

    #[test]
    fn apps_destroy_classified() {
        let r = classify_flyctl_argv(&args(&["apps", "destroy", "myapp"])).unwrap();
        assert_eq!(r.0, "fly.apps.destroy");
    }

    #[test]
    fn apps_restart_classified() {
        let r = classify_flyctl_argv(&args(&["apps", "restart", "myapp"])).unwrap();
        assert_eq!(r.0, "fly.apps.restart");
    }

    #[test]
    fn apps_scale_classified() {
        let r = classify_flyctl_argv(&args(&["apps", "scale"])).unwrap();
        assert_eq!(r.0, "fly.apps.scale");
    }

    #[test]
    fn apps_deploy_classified() {
        let r = classify_flyctl_argv(&args(&["apps", "deploy"])).unwrap();
        assert_eq!(r.0, "fly.apps.deploy");
    }

    #[test]
    fn apps_releases_rollback_classified() {
        let r = classify_flyctl_argv(&args(&["apps", "releases", "rollback", "v1"])).unwrap();
        assert_eq!(r.0, "fly.apps.releases.rollback");
    }

    #[test]
    fn apps_list_passthrough() {
        assert!(classify_flyctl_argv(&args(&["apps", "list"])).is_none());
    }

    // --- machine ---

    #[test]
    fn machine_run_classified() {
        let r = classify_flyctl_argv(&args(&["machine", "run", "image"])).unwrap();
        assert_eq!(r.0, "fly.machine.run");
    }

    #[test]
    fn machine_stop_classified() {
        let r = classify_flyctl_argv(&args(&["machine", "stop", "id"])).unwrap();
        assert_eq!(r.0, "fly.machine.stop");
    }

    #[test]
    fn machine_start_classified() {
        let r = classify_flyctl_argv(&args(&["machine", "start", "id"])).unwrap();
        assert_eq!(r.0, "fly.machine.start");
    }

    #[test]
    fn machine_restart_classified() {
        let r = classify_flyctl_argv(&args(&["machine", "restart", "id"])).unwrap();
        assert_eq!(r.0, "fly.machine.restart");
    }

    #[test]
    fn machine_destroy_classified() {
        let r = classify_flyctl_argv(&args(&["machine", "destroy", "id"])).unwrap();
        assert_eq!(r.0, "fly.machine.destroy");
    }

    #[test]
    fn machine_exec_classified() {
        let r = classify_flyctl_argv(&args(&["machine", "exec", "id", "ls"])).unwrap();
        assert_eq!(r.0, "fly.machine.exec");
    }

    #[test]
    fn machine_clone_classified() {
        let r = classify_flyctl_argv(&args(&["machine", "clone", "id"])).unwrap();
        assert_eq!(r.0, "fly.machine.clone");
    }

    #[test]
    fn machine_update_classified() {
        let r = classify_flyctl_argv(&args(&["machine", "update", "id"])).unwrap();
        assert_eq!(r.0, "fly.machine.update");
    }

    #[test]
    fn machine_list_passthrough() {
        assert!(classify_flyctl_argv(&args(&["machine", "list"])).is_none());
    }

    // --- volumes ---

    #[test]
    fn volumes_create_classified() {
        let r = classify_flyctl_argv(&args(&["volumes", "create", "data"])).unwrap();
        assert_eq!(r.0, "fly.volumes.create");
    }

    #[test]
    fn volumes_destroy_classified() {
        let r = classify_flyctl_argv(&args(&["volumes", "destroy", "vol_id"])).unwrap();
        assert_eq!(r.0, "fly.volumes.destroy");
    }

    #[test]
    fn volumes_extend_classified() {
        let r = classify_flyctl_argv(&args(&["volumes", "extend", "vol_id"])).unwrap();
        assert_eq!(r.0, "fly.volumes.extend");
    }

    #[test]
    fn volumes_fork_classified() {
        let r = classify_flyctl_argv(&args(&["volumes", "fork", "vol_id"])).unwrap();
        assert_eq!(r.0, "fly.volumes.fork");
    }

    // --- secrets ---

    #[test]
    fn secrets_set_classified() {
        let r = classify_flyctl_argv(&args(&["secrets", "set", "K=V"])).unwrap();
        assert_eq!(r.0, "fly.secrets.set");
    }

    #[test]
    fn secrets_unset_classified() {
        let r = classify_flyctl_argv(&args(&["secrets", "unset", "K"])).unwrap();
        assert_eq!(r.0, "fly.secrets.unset");
    }

    #[test]
    fn secrets_import_classified() {
        let r = classify_flyctl_argv(&args(&["secrets", "import"])).unwrap();
        assert_eq!(r.0, "fly.secrets.import");
    }

    #[test]
    fn secrets_deploy_classified() {
        let r = classify_flyctl_argv(&args(&["secrets", "deploy"])).unwrap();
        assert_eq!(r.0, "fly.secrets.deploy");
    }

    #[test]
    fn secrets_list_passthrough() {
        assert!(classify_flyctl_argv(&args(&["secrets", "list"])).is_none());
    }

    // --- top-level deploy ---

    #[test]
    fn top_level_deploy_classified() {
        let r = classify_flyctl_argv(&args(&["deploy"])).unwrap();
        assert_eq!(r.0, "fly.deploy");
    }

    #[test]
    fn top_level_deploy_with_app_flag_classified() {
        let r = classify_flyctl_argv(&args(&["deploy", "--app", "myapp"])).unwrap();
        assert_eq!(r.0, "fly.deploy");
    }

    // --- scale ---

    #[test]
    fn scale_count_classified() {
        let r = classify_flyctl_argv(&args(&["scale", "count", "3"])).unwrap();
        assert_eq!(r.0, "fly.scale.count");
    }

    #[test]
    fn scale_vm_classified() {
        let r = classify_flyctl_argv(&args(&["scale", "vm", "shared-cpu-1x"])).unwrap();
        assert_eq!(r.0, "fly.scale.vm");
    }

    #[test]
    fn scale_memory_classified() {
        let r = classify_flyctl_argv(&args(&["scale", "memory", "512"])).unwrap();
        assert_eq!(r.0, "fly.scale.memory");
    }

    #[test]
    fn scale_show_passthrough() {
        // `show` is read-only, returns None via the second-token check.
        assert!(classify_flyctl_argv(&args(&["scale", "show"])).is_none());
    }

    // --- regions ---

    #[test]
    fn regions_add_classified() {
        let r = classify_flyctl_argv(&args(&["regions", "add", "iad"])).unwrap();
        assert_eq!(r.0, "fly.regions.add");
    }

    #[test]
    fn regions_remove_classified() {
        let r = classify_flyctl_argv(&args(&["regions", "remove", "iad"])).unwrap();
        assert_eq!(r.0, "fly.regions.remove");
    }

    #[test]
    fn regions_set_classified() {
        let r = classify_flyctl_argv(&args(&["regions", "set", "iad,sea"])).unwrap();
        assert_eq!(r.0, "fly.regions.set");
    }

    #[test]
    fn regions_backup_classified() {
        let r = classify_flyctl_argv(&args(&["regions", "backup", "iad"])).unwrap();
        assert_eq!(r.0, "fly.regions.backup");
    }

    #[test]
    fn regions_list_passthrough() {
        assert!(classify_flyctl_argv(&args(&["regions", "list"])).is_none());
    }

    // --- postgres ---

    #[test]
    fn postgres_create_classified() {
        let r = classify_flyctl_argv(&args(&["postgres", "create"])).unwrap();
        assert_eq!(r.0, "fly.postgres.create");
    }

    #[test]
    fn postgres_destroy_classified() {
        let r = classify_flyctl_argv(&args(&["postgres", "destroy", "pg-app"])).unwrap();
        assert_eq!(r.0, "fly.postgres.destroy");
    }

    #[test]
    fn postgres_attach_classified() {
        let r = classify_flyctl_argv(&args(&["postgres", "attach"])).unwrap();
        assert_eq!(r.0, "fly.postgres.attach");
    }

    #[test]
    fn postgres_detach_classified() {
        let r = classify_flyctl_argv(&args(&["postgres", "detach"])).unwrap();
        assert_eq!(r.0, "fly.postgres.detach");
    }

    #[test]
    fn postgres_connect_classified() {
        let r = classify_flyctl_argv(&args(&["postgres", "connect"])).unwrap();
        assert_eq!(r.0, "fly.postgres.connect");
    }

    // --- redis ---

    #[test]
    fn redis_create_classified() {
        let r = classify_flyctl_argv(&args(&["redis", "create"])).unwrap();
        assert_eq!(r.0, "fly.redis.create");
    }

    #[test]
    fn redis_destroy_classified() {
        let r = classify_flyctl_argv(&args(&["redis", "destroy", "id"])).unwrap();
        assert_eq!(r.0, "fly.redis.destroy");
    }

    #[test]
    fn redis_update_classified() {
        let r = classify_flyctl_argv(&args(&["redis", "update", "id"])).unwrap();
        assert_eq!(r.0, "fly.redis.update");
    }

    // --- certs ---

    #[test]
    fn certs_add_classified() {
        let r = classify_flyctl_argv(&args(&["certs", "add", "example.com"])).unwrap();
        assert_eq!(r.0, "fly.certs.add");
    }

    #[test]
    fn certs_remove_classified() {
        let r = classify_flyctl_argv(&args(&["certs", "remove", "example.com"])).unwrap();
        assert_eq!(r.0, "fly.certs.remove");
    }

    #[test]
    fn certs_check_classified() {
        let r = classify_flyctl_argv(&args(&["certs", "check", "example.com"])).unwrap();
        assert_eq!(r.0, "fly.certs.check");
    }

    // --- ips ---

    #[test]
    fn ips_allocate_v4_classified() {
        let r = classify_flyctl_argv(&args(&["ips", "allocate-v4"])).unwrap();
        assert_eq!(r.0, "fly.ips.allocate-v4");
    }

    #[test]
    fn ips_allocate_v6_classified() {
        let r = classify_flyctl_argv(&args(&["ips", "allocate-v6"])).unwrap();
        assert_eq!(r.0, "fly.ips.allocate-v6");
    }

    #[test]
    fn ips_release_classified() {
        let r = classify_flyctl_argv(&args(&["ips", "release", "1.2.3.4"])).unwrap();
        assert_eq!(r.0, "fly.ips.release");
    }

    // --- tokens ---

    #[test]
    fn tokens_create_classified() {
        let r = classify_flyctl_argv(&args(&["tokens", "create"])).unwrap();
        assert_eq!(r.0, "fly.tokens.create");
    }

    #[test]
    fn tokens_revoke_classified() {
        let r = classify_flyctl_argv(&args(&["tokens", "revoke", "tok"])).unwrap();
        assert_eq!(r.0, "fly.tokens.revoke");
    }

    #[test]
    fn tokens_list_passthrough() {
        assert!(classify_flyctl_argv(&args(&["tokens", "list"])).is_none());
    }

    // --- orgs ---

    #[test]
    fn orgs_revoke_classified() {
        let r = classify_flyctl_argv(&args(&["orgs", "revoke"])).unwrap();
        assert_eq!(r.0, "fly.orgs.revoke");
    }

    // --- ssh ---

    #[test]
    fn ssh_issue_classified() {
        let r = classify_flyctl_argv(&args(&["ssh", "issue"])).unwrap();
        assert_eq!(r.0, "fly.ssh.issue");
    }

    #[test]
    fn ssh_console_classified() {
        let r = classify_flyctl_argv(&args(&["ssh", "console"])).unwrap();
        assert_eq!(r.0, "fly.ssh.console");
    }

    // --- read-only top-level passthroughs ---

    #[test]
    fn top_status_passthrough() {
        assert!(classify_flyctl_argv(&args(&["status"])).is_none());
    }

    #[test]
    fn top_info_passthrough() {
        assert!(classify_flyctl_argv(&args(&["info"])).is_none());
    }

    #[test]
    fn top_logs_passthrough() {
        assert!(classify_flyctl_argv(&args(&["logs"])).is_none());
    }

    #[test]
    fn top_version_passthrough() {
        assert!(classify_flyctl_argv(&args(&["version"])).is_none());
    }

    #[test]
    fn top_dashboard_passthrough() {
        assert!(classify_flyctl_argv(&args(&["dashboard"])).is_none());
    }

    // --- global flag stripping ---

    #[test]
    fn access_token_flag_before_group_stripped() {
        let r = classify_flyctl_argv(&args(&[
            "--access-token",
            "fo1_xxx",
            "apps",
            "destroy",
            "myapp",
        ]))
        .unwrap();
        assert_eq!(r.0, "fly.apps.destroy");
    }

    #[test]
    fn app_flag_between_group_and_verb_stripped() {
        let r = classify_flyctl_argv(&args(&[
            "machine",
            "--app",
            "myapp",
            "destroy",
            "id",
        ]))
        .unwrap();
        assert_eq!(r.0, "fly.machine.destroy");
    }

    #[test]
    fn config_flag_after_verb_stripped() {
        let r = classify_flyctl_argv(&args(&[
            "deploy",
            "--config",
            "fly.toml",
        ]))
        .unwrap();
        assert_eq!(r.0, "fly.deploy");
    }

    #[test]
    fn region_flag_stripped() {
        let r = classify_flyctl_argv(&args(&[
            "--region",
            "iad",
            "machine",
            "run",
            "image",
        ]))
        .unwrap();
        assert_eq!(r.0, "fly.machine.run");
    }

    #[test]
    fn json_boolean_flag_stripped() {
        let r = classify_flyctl_argv(&args(&["--json", "apps", "destroy", "x"])).unwrap();
        assert_eq!(r.0, "fly.apps.destroy");
    }

    #[test]
    fn debug_boolean_flag_stripped() {
        let r =
            classify_flyctl_argv(&args(&["--debug", "secrets", "unset", "K"])).unwrap();
        assert_eq!(r.0, "fly.secrets.unset");
    }

    #[test]
    fn verbose_boolean_flag_stripped() {
        let r =
            classify_flyctl_argv(&args(&["--verbose", "ssh", "console"])).unwrap();
        assert_eq!(r.0, "fly.ssh.console");
    }

    #[test]
    fn equals_form_app_flag_stripped() {
        let r =
            classify_flyctl_argv(&args(&["--app=myapp", "machine", "destroy", "id"]))
                .unwrap();
        assert_eq!(r.0, "fly.machine.destroy");
    }

    #[test]
    fn equals_form_region_flag_stripped() {
        let r = classify_flyctl_argv(&args(&[
            "--region=iad",
            "ips",
            "allocate-v4",
        ]))
        .unwrap();
        assert_eq!(r.0, "fly.ips.allocate-v4");
    }

    #[test]
    fn equals_form_access_token_flag_stripped() {
        let r = classify_flyctl_argv(&args(&[
            "--access-token=fo1_secret",
            "tokens",
            "revoke",
            "tok",
        ]))
        .unwrap();
        assert_eq!(r.0, "fly.tokens.revoke");
    }

    #[test]
    fn short_app_flag_stripped() {
        let r = classify_flyctl_argv(&args(&[
            "-a",
            "myapp",
            "machine",
            "destroy",
            "id",
        ]))
        .unwrap();
        assert_eq!(r.0, "fly.machine.destroy");
    }

    #[test]
    fn multiple_global_flags_stripped() {
        let r = classify_flyctl_argv(&args(&[
            "--access-token",
            "tok",
            "--app",
            "myapp",
            "--json",
            "--debug",
            "postgres",
            "destroy",
            "pg",
        ]))
        .unwrap();
        assert_eq!(r.0, "fly.postgres.destroy");
    }

    #[test]
    fn flags_reordered_classification_stable() {
        let a = classify_flyctl_argv(&args(&[
            "machine", "destroy", "id", "--app", "myapp",
        ]))
        .unwrap();
        let b = classify_flyctl_argv(&args(&[
            "--app", "myapp", "machine", "destroy", "id",
        ]))
        .unwrap();
        let c = classify_flyctl_argv(&args(&[
            "machine", "--app", "myapp", "destroy", "id",
        ]))
        .unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(b.0, c.0);
    }

    // --- unknown / empty / corner cases ---

    #[test]
    fn empty_argv_passthrough() {
        assert!(classify_flyctl_argv(&[]).is_none());
    }

    #[test]
    fn only_global_flags_passthrough() {
        assert!(classify_flyctl_argv(&args(&["--app", "myapp", "--json"])).is_none());
    }

    #[test]
    fn unknown_group_passthrough() {
        assert!(classify_flyctl_argv(&args(&["wireguard", "list"])).is_none());
    }

    #[test]
    fn group_without_verb_passthrough() {
        assert!(classify_flyctl_argv(&args(&["apps"])).is_none());
    }

    #[test]
    fn apps_unknown_verb_passthrough() {
        assert!(classify_flyctl_argv(&args(&["apps", "open"])).is_none());
    }

    #[test]
    fn apps_releases_without_rollback_passthrough() {
        assert!(classify_flyctl_argv(&args(&["apps", "releases"])).is_none());
    }

    #[test]
    fn orgs_unknown_verb_passthrough() {
        assert!(classify_flyctl_argv(&args(&["orgs", "create"])).is_none());
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
            let _ = classify_flyctl_argv(&argv);
        }

        /// Inserting a recognized value-bearing global flag (with value) into a
        /// known-classified argv must not change the classification.
        #[test]
        fn fuzz_app_flag_insertion_stable(
            insert_at in 0usize..6,
            app in "[a-z][a-z0-9-]{0,15}"
        ) {
            let base = vec![
                "machine".to_string(),
                "destroy".to_string(),
                "id".to_string(),
            ];
            let base_class = classify_flyctl_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, app.clone());
            with_flag.insert(pos, "--app".to_string());

            let class2 = classify_flyctl_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }

        /// Inserting a boolean global flag at any position into a known
        /// classified argv must not change the classification.
        #[test]
        fn fuzz_boolean_flag_insertion_stable(insert_at in 0usize..6) {
            let base = vec![
                "secrets".to_string(),
                "unset".to_string(),
                "K".to_string(),
            ];
            let base_class = classify_flyctl_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, "--debug".to_string());

            let class2 = classify_flyctl_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }
    }

    // --- T2: integration with MockBroker for BrokerProvider::FlyIo ---
    //
    // The full broker_exec lifecycle lives in the daemon; here we cover the
    // contract slice this Construct depends on: the broker registry can
    // hold a `MockBroker::new(BrokerProvider::FlyIo)`, and a request that
    // declares `provider = FlyIo` round-trips through issue → revoke
    // without panicking. Real FlyIo impl is implementation-note-33 (separate task).

    use core_broker::{
        Broker, BrokerError, BrokerProvider, BrokerRequest, MockBroker,
    };
    use std::time::Duration;

    fn fly_request(ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::FlyIo,
            scope: serde_json::json!({
                "org": "ember-systems",
                "app": "ember-warden",
                "actions": ["apps:deploy", "machine:run"],
            }),
            ttl: Duration::from_secs(ttl_secs),
            reason: "ember-flyctl integration test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    #[tokio::test]
    async fn mock_broker_fly_issue_revoke_roundtrip() {
        let broker = MockBroker::new(BrokerProvider::FlyIo);
        assert_eq!(broker.provider(), BrokerProvider::FlyIo);

        let creds = broker
            .issue(fly_request(900))
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
    async fn mock_broker_fly_rejects_wrong_provider() {
        let broker = MockBroker::new(BrokerProvider::FlyIo);
        let mut req = fly_request(900);
        req.provider = BrokerProvider::Cloudflare;

        let err = broker.issue(req).await.expect_err("provider mismatch");
        match err {
            BrokerError::InvalidScope(_) => {}
            other => panic!("expected InvalidScope, got {other:?}"),
        }
    }

    #[test]
    fn fly_io_provider_as_str() {
        assert_eq!(BrokerProvider::FlyIo.as_str(), "fly_io");
    }
}
