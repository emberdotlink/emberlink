//! Argv classifier: maps `vault <verb> ...` (or `vault <subsystem> <verb> ...`)
//! to a `construct.toml` action_key. Per ADR 124 §3 — this lives shim-side
//! BUT the daemon re-classifies the argv server-side (untrusts the shim).
//!
//! Vault CLI argv shape:
//!
//! ```text
//! vault [global-flags...] <verb> [global-flags...] [verb-args...]
//! vault [global-flags...] <subsystem> <verb> [global-flags...] [verb-args...]
//! ```
//!
//! Global flags (e.g. `-address=`, `-namespace=`, `-tls-skip-verify`,
//! `-format=`, `-ca-cert=`, `-client-cert=`, `-output-curl-string`,
//! `-non-interactive`, `-no-print`) may appear before, between, or after
//! the subsystem/verb tokens. We strip them — including their values for
//! the flags that take one — before pattern-matching, so classification
//! is stable under flag reordering. Vault uses single-dash long flags
//! (`-address=...`); double-dash forms (`--address=...`) are also accepted
//! for forward compatibility.
//!
//! Coverage (mutating verbs are gated; strict read-only verbs passthrough as `None`):
//!
//! | argv prefix                                 | action_key                                        |
//! |---------------------------------------------|---------------------------------------------------|
//! | `write <path>`                              | `vault.write`                                     |
//! | `delete <path>`                             | `vault.delete`                                    |
//! | `read <path>` (SPECIAL — gated for audit)   | `vault.read`                                      |
//! | `kv put\|delete\|destroy\|patch\|undelete`  | `vault.kv.{put,delete,destroy,patch,undelete}`    |
//! | `kv get` (SPECIAL — gated for audit)        | `vault.kv.get`                                    |
//! | `policy write\|delete`                      | `vault.policy.{write,delete}`                     |
//! | `auth enable\|disable\|tune`                | `vault.auth.{enable,disable,tune}`                |
//! | `secrets enable\|disable\|tune`             | `vault.secrets.{enable,disable,tune}`             |
//! | `token create\|revoke\|renew`               | `vault.token.{create,revoke,renew}`               |
//! | `lease revoke\|revoke-prefix`               | `vault.lease.{revoke,revoke-prefix}`              |
//! | `audit enable\|disable`                     | `vault.audit.{enable,disable}`                    |
//! | `status\|version\|list\|path-help`          | `None` (passthrough)                              |
//!
//! Notes:
//!   - `read` and `kv get` are SPECIAL: Vault's `read` is technically a
//!     "read" but it reveals secrets, so every invocation is auditable.
//!     They classify to `mode=gate` in `construct.toml`, NOT passthrough.
//!     The daemon emits a Receipt for each secret reveal.
//!   - `policy read`/`policy list`, `auth list`, `secrets list`,
//!     `token lookup`, `lease lookup`, `audit list` are strict read-only
//!     (no secret reveal) and passthrough as `None`.

use core_construct_runtime::ActionKey;

/// Vault CLI global flags that take a value as the *next* argv token
/// (the space-separated form, e.g. `-address https://vault.example`).
///
/// Vault CLI primarily uses the `-flag=value` form; the space form is
/// less common but supported for many flags. We list the common ones
/// here so reordering is robust.
const VALUE_BEARING_GLOBAL_FLAGS: &[&str] = &[
    "-address",
    "-namespace",
    "-format",
    "-ca-cert",
    "-ca-path",
    "-client-cert",
    "-client-key",
    "-tls-server-name",
    "-wrap-ttl",
    "-mfa",
    "-header",
    "-policy-override",
    // Double-dash forward-compat aliases.
    "--address",
    "--namespace",
    "--format",
    "--ca-cert",
    "--ca-path",
    "--client-cert",
    "--client-key",
    "--tls-server-name",
    "--wrap-ttl",
    "--mfa",
    "--header",
    "--policy-override",
];

/// Vault CLI global flags that are valueless (boolean toggles).
const BOOLEAN_GLOBAL_FLAGS: &[&str] = &[
    "-tls-skip-verify",
    "-output-curl-string",
    "-output-policy",
    "-no-print",
    "-non-interactive",
    // Double-dash forward-compat aliases.
    "--tls-skip-verify",
    "--output-curl-string",
    "--output-policy",
    "--no-print",
    "--non-interactive",
];

/// Strip global flags (and their values, where applicable) from `argv`.
///
/// Recognizes both `-flag=value` / `--flag=value` and `-flag value` /
/// `--flag value` forms for the value-bearing flags, plus the boolean
/// toggles in [`BOOLEAN_GLOBAL_FLAGS`]. Non-flag tokens and unknown
/// flags pass through unchanged (the daemon re-classifies anyway).
pub(crate) fn strip_global_flags(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];

        // `-flag=value` / `--flag=value` form — drop in one step regardless
        // of whether it's a value-bearing or boolean global flag (boolean
        // flags shouldn't have `=value` but we accept it tolerantly).
        if let Some(eq) = tok.find('=') {
            let name = &tok[..eq];
            if VALUE_BEARING_GLOBAL_FLAGS.contains(&name) || BOOLEAN_GLOBAL_FLAGS.contains(&name) {
                i += 1;
                continue;
            }
        }

        // `-flag value` / `--flag value` form for value-bearing globals.
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

/// Returns `true` if `verb` is a strict read-only top-level Vault verb.
///
/// These are verbs that never reveal secrets and never mutate state:
/// `status`, `version`, `list`, `path-help`. Note that `read` and
/// `kv get` are NOT in this set — they reveal secrets and must be
/// audited.
fn is_strict_read_only(verb: &str) -> bool {
    matches!(verb, "status" | "version" | "list" | "path-help" | "help")
}

/// Extract the KV v2 mount + secret path from argv for `kv` subsystem
/// commands.
///
/// Vault's KV v2 stores secrets under `<mount>/data/<path>`; the CLI
/// presents them as `<mount>/<path>`. This helper extracts the
/// (mount, path) pair from the first non-flag token following the
/// kv verb. Returns `None` if the path is missing or starts with `-`.
///
/// WIP-FOR: daemon-side scope-check consumer (no specific task ID
/// yet; tracked under the VAULT-SCOPE-SPLIT-MEK + ember-vault Construct
/// gating series). The classifier itself does not consume the path;
/// this helper is provided so the future daemon-side authorization
/// path can validate `kv` operations against the persona's vault scope
/// without re-implementing argv parsing. Tests below cover the contract.
#[allow(dead_code)]
pub fn extract_kv_path(argv_after_verb: &[String]) -> Option<(&str, &str)> {
    for tok in argv_after_verb {
        if tok.starts_with('-') {
            continue;
        }
        // Split on the first `/` — left half is the mount, right is the
        // KV path. A path like `secret/foo/bar` becomes
        // (`secret`, `foo/bar`).
        let (mount, rest) = tok.split_once('/')?;
        if mount.is_empty() || rest.is_empty() {
            return None;
        }
        return Some((mount, rest));
    }
    None
}

/// Classify `vault <verb> ...` (or `vault <subsystem> <verb> ...`) argv
/// into an action_key.
///
/// Returns `None` for strict read-only / unrecognized shapes — the
/// runtime treats `None` as passthrough (no broker mediation).
pub fn classify_vault_argv(argv: &[String]) -> Option<ActionKey> {
    let stripped = strip_global_flags(argv);

    let head = stripped.first()?.as_str();

    // Strict read-only top-level verbs — never reach broker.
    if is_strict_read_only(head) {
        return None;
    }

    match head {
        // Top-level mutation verbs.
        "write" => Some(ActionKey("vault.write".to_string())),
        "delete" => Some(ActionKey("vault.delete".to_string())),
        // SPECIAL: `read` reveals secrets — gated for audit, NOT passthrough.
        "read" => Some(ActionKey("vault.read".to_string())),

        // kv subsystem — KV v2 secret CRUD.
        "kv" => {
            let verb = stripped.get(1).map(|s| s.as_str())?;
            match verb {
                "put" | "delete" | "destroy" | "patch" | "undelete" => {
                    Some(ActionKey(format!("vault.kv.{verb}")))
                }
                // SPECIAL: `kv get` reveals secrets — gated for audit.
                "get" => Some(ActionKey("vault.kv.get".to_string())),
                // `kv list`, `kv metadata`, etc. — passthrough.
                _ => None,
            }
        }

        // policy subsystem.
        "policy" => {
            let verb = stripped.get(1).map(|s| s.as_str())?;
            match verb {
                "write" | "delete" => Some(ActionKey(format!("vault.policy.{verb}"))),
                // `policy read`, `policy list` — passthrough.
                _ => None,
            }
        }

        // auth subsystem (auth-method backends).
        "auth" => {
            let verb = stripped.get(1).map(|s| s.as_str())?;
            match verb {
                "enable" | "disable" | "tune" => Some(ActionKey(format!("vault.auth.{verb}"))),
                // `auth list`, `auth help`, login flows — passthrough.
                _ => None,
            }
        }

        // secrets subsystem (secrets-engine backends).
        "secrets" => {
            let verb = stripped.get(1).map(|s| s.as_str())?;
            match verb {
                "enable" | "disable" | "tune" => Some(ActionKey(format!("vault.secrets.{verb}"))),
                // `secrets list` — passthrough.
                _ => None,
            }
        }

        // token subsystem.
        "token" => {
            let verb = stripped.get(1).map(|s| s.as_str())?;
            match verb {
                "create" | "revoke" | "renew" => Some(ActionKey(format!("vault.token.{verb}"))),
                // `token lookup`, `token capabilities` — passthrough.
                _ => None,
            }
        }

        // lease subsystem.
        "lease" => {
            let verb = stripped.get(1).map(|s| s.as_str())?;
            match verb {
                "revoke" | "revoke-prefix" => Some(ActionKey(format!("vault.lease.{verb}"))),
                // `lease lookup`, `lease renew` — passthrough.
                _ => None,
            }
        }

        // audit subsystem.
        "audit" => {
            let verb = stripped.get(1).map(|s| s.as_str())?;
            match verb {
                "enable" | "disable" => Some(ActionKey(format!("vault.audit.{verb}"))),
                // `audit list` — passthrough.
                _ => None,
            }
        }

        // Unknown verb / subsystem → passthrough; daemon re-classifies.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // --- top-level mutation verbs ---

    #[test]
    fn write_classified() {
        let r = classify_vault_argv(&args(&["write", "secret/foo", "value=bar"])).unwrap();
        assert_eq!(r.0, "vault.write");
    }

    #[test]
    fn delete_classified() {
        let r = classify_vault_argv(&args(&["delete", "secret/foo"])).unwrap();
        assert_eq!(r.0, "vault.delete");
    }

    #[test]
    fn read_classified_as_mutation_for_audit() {
        // SPECIAL: vault read reveals secrets and is auditable.
        let r = classify_vault_argv(&args(&["read", "secret/foo"])).unwrap();
        assert_eq!(r.0, "vault.read");
    }

    // --- strict read-only top-level verbs (passthrough) ---

    #[test]
    fn status_passthrough() {
        assert!(classify_vault_argv(&args(&["status"])).is_none());
    }

    #[test]
    fn version_passthrough() {
        assert!(classify_vault_argv(&args(&["version"])).is_none());
    }

    #[test]
    fn list_passthrough() {
        assert!(classify_vault_argv(&args(&["list", "secret/"])).is_none());
    }

    #[test]
    fn path_help_passthrough() {
        assert!(classify_vault_argv(&args(&["path-help", "sys/policy"])).is_none());
    }

    // --- kv subsystem ---

    #[test]
    fn kv_put_classified() {
        let r = classify_vault_argv(&args(&["kv", "put", "secret/foo", "k=v"])).unwrap();
        assert_eq!(r.0, "vault.kv.put");
    }

    #[test]
    fn kv_get_classified_as_mutation_for_audit() {
        // SPECIAL: kv get reveals secrets and is auditable.
        let r = classify_vault_argv(&args(&["kv", "get", "secret/foo"])).unwrap();
        assert_eq!(r.0, "vault.kv.get");
    }

    #[test]
    fn kv_delete_classified() {
        let r = classify_vault_argv(&args(&["kv", "delete", "secret/foo"])).unwrap();
        assert_eq!(r.0, "vault.kv.delete");
    }

    #[test]
    fn kv_destroy_classified() {
        let r =
            classify_vault_argv(&args(&["kv", "destroy", "-versions=1", "secret/foo"])).unwrap();
        assert_eq!(r.0, "vault.kv.destroy");
    }

    #[test]
    fn kv_patch_classified() {
        let r = classify_vault_argv(&args(&["kv", "patch", "secret/foo", "k=v"])).unwrap();
        assert_eq!(r.0, "vault.kv.patch");
    }

    #[test]
    fn kv_undelete_classified() {
        let r =
            classify_vault_argv(&args(&["kv", "undelete", "-versions=1", "secret/foo"])).unwrap();
        assert_eq!(r.0, "vault.kv.undelete");
    }

    #[test]
    fn kv_list_passthrough() {
        assert!(classify_vault_argv(&args(&["kv", "list", "secret/"])).is_none());
    }

    #[test]
    fn kv_metadata_passthrough() {
        assert!(classify_vault_argv(&args(&["kv", "metadata", "get", "secret/foo"])).is_none());
    }

    // --- policy subsystem ---

    #[test]
    fn policy_write_classified() {
        let r = classify_vault_argv(&args(&["policy", "write", "my-policy", "-"])).unwrap();
        assert_eq!(r.0, "vault.policy.write");
    }

    #[test]
    fn policy_delete_classified() {
        let r = classify_vault_argv(&args(&["policy", "delete", "my-policy"])).unwrap();
        assert_eq!(r.0, "vault.policy.delete");
    }

    #[test]
    fn policy_read_passthrough() {
        assert!(classify_vault_argv(&args(&["policy", "read", "my-policy"])).is_none());
    }

    #[test]
    fn policy_list_passthrough() {
        assert!(classify_vault_argv(&args(&["policy", "list"])).is_none());
    }

    // --- auth subsystem ---

    #[test]
    fn auth_enable_classified() {
        let r = classify_vault_argv(&args(&["auth", "enable", "userpass"])).unwrap();
        assert_eq!(r.0, "vault.auth.enable");
    }

    #[test]
    fn auth_disable_classified() {
        let r = classify_vault_argv(&args(&["auth", "disable", "userpass/"])).unwrap();
        assert_eq!(r.0, "vault.auth.disable");
    }

    #[test]
    fn auth_tune_classified() {
        let r = classify_vault_argv(&args(&[
            "auth",
            "tune",
            "-default-lease-ttl=1h",
            "userpass/",
        ]))
        .unwrap();
        assert_eq!(r.0, "vault.auth.tune");
    }

    #[test]
    fn auth_list_passthrough() {
        assert!(classify_vault_argv(&args(&["auth", "list"])).is_none());
    }

    // --- secrets subsystem ---

    #[test]
    fn secrets_enable_classified() {
        let r = classify_vault_argv(&args(&["secrets", "enable", "-path=kv2", "kv-v2"])).unwrap();
        assert_eq!(r.0, "vault.secrets.enable");
    }

    #[test]
    fn secrets_disable_classified() {
        let r = classify_vault_argv(&args(&["secrets", "disable", "kv2/"])).unwrap();
        assert_eq!(r.0, "vault.secrets.disable");
    }

    #[test]
    fn secrets_tune_classified() {
        let r = classify_vault_argv(&args(&["secrets", "tune", "-default-lease-ttl=4h", "kv2/"]))
            .unwrap();
        assert_eq!(r.0, "vault.secrets.tune");
    }

    #[test]
    fn secrets_list_passthrough() {
        assert!(classify_vault_argv(&args(&["secrets", "list"])).is_none());
    }

    // --- token subsystem ---

    #[test]
    fn token_create_classified() {
        let r = classify_vault_argv(&args(&["token", "create", "-policy=my-policy"])).unwrap();
        assert_eq!(r.0, "vault.token.create");
    }

    #[test]
    fn token_revoke_classified() {
        let r = classify_vault_argv(&args(&["token", "revoke", "s.abc123"])).unwrap();
        assert_eq!(r.0, "vault.token.revoke");
    }

    #[test]
    fn token_renew_classified() {
        let r = classify_vault_argv(&args(&["token", "renew", "s.abc123"])).unwrap();
        assert_eq!(r.0, "vault.token.renew");
    }

    #[test]
    fn token_lookup_passthrough() {
        assert!(classify_vault_argv(&args(&["token", "lookup"])).is_none());
    }

    // --- lease subsystem ---

    #[test]
    fn lease_revoke_classified() {
        let r = classify_vault_argv(&args(&["lease", "revoke", "kv/lease-id"])).unwrap();
        assert_eq!(r.0, "vault.lease.revoke");
    }

    #[test]
    fn lease_revoke_prefix_classified() {
        let r = classify_vault_argv(&args(&["lease", "revoke-prefix", "kv/creds/"])).unwrap();
        assert_eq!(r.0, "vault.lease.revoke-prefix");
    }

    #[test]
    fn lease_lookup_passthrough() {
        assert!(classify_vault_argv(&args(&["lease", "lookup", "lease-id"])).is_none());
    }

    // --- audit subsystem ---

    #[test]
    fn audit_enable_classified() {
        let r = classify_vault_argv(&args(&[
            "audit",
            "enable",
            "file",
            "file_path=/var/log/vault.log",
        ]))
        .unwrap();
        assert_eq!(r.0, "vault.audit.enable");
    }

    #[test]
    fn audit_disable_classified() {
        let r = classify_vault_argv(&args(&["audit", "disable", "file/"])).unwrap();
        assert_eq!(r.0, "vault.audit.disable");
    }

    #[test]
    fn audit_list_passthrough() {
        assert!(classify_vault_argv(&args(&["audit", "list"])).is_none());
    }

    // --- global flag stripping (single-dash, equals form) ---

    #[test]
    fn address_eq_flag_before_verb_stripped() {
        let r = classify_vault_argv(&args(&[
            "-address=https://vault.example",
            "kv",
            "put",
            "secret/foo",
            "k=v",
        ]))
        .unwrap();
        assert_eq!(r.0, "vault.kv.put");
    }

    #[test]
    fn namespace_eq_flag_between_subsystem_and_verb_stripped() {
        let r =
            classify_vault_argv(&args(&["kv", "-namespace=team-a", "put", "secret/foo"])).unwrap();
        assert_eq!(r.0, "vault.kv.put");
    }

    #[test]
    fn format_flag_after_verb_stripped() {
        let r = classify_vault_argv(&args(&["kv", "get", "-format=json", "secret/foo"])).unwrap();
        assert_eq!(r.0, "vault.kv.get");
    }

    #[test]
    fn tls_skip_verify_boolean_flag_stripped() {
        let r = classify_vault_argv(&args(&["-tls-skip-verify", "policy", "delete", "p"])).unwrap();
        assert_eq!(r.0, "vault.policy.delete");
    }

    #[test]
    fn output_curl_string_boolean_flag_stripped() {
        let r =
            classify_vault_argv(&args(&["-output-curl-string", "auth", "disable", "u/"])).unwrap();
        assert_eq!(r.0, "vault.auth.disable");
    }

    // --- global flag stripping (single-dash, space form) ---

    #[test]
    fn address_space_flag_stripped() {
        let r = classify_vault_argv(&args(&[
            "-address",
            "https://vault.example",
            "audit",
            "disable",
            "file/",
        ]))
        .unwrap();
        assert_eq!(r.0, "vault.audit.disable");
    }

    #[test]
    fn namespace_space_flag_stripped() {
        let r = classify_vault_argv(&args(&[
            "-namespace",
            "team-a",
            "lease",
            "revoke-prefix",
            "kv/creds/",
        ]))
        .unwrap();
        assert_eq!(r.0, "vault.lease.revoke-prefix");
    }

    // --- double-dash forward-compat aliases ---

    #[test]
    fn double_dash_address_eq_stripped() {
        let r = classify_vault_argv(&args(&[
            "--address=https://vault.example",
            "token",
            "revoke",
            "s.abc",
        ]))
        .unwrap();
        assert_eq!(r.0, "vault.token.revoke");
    }

    #[test]
    fn double_dash_tls_skip_verify_stripped() {
        let r = classify_vault_argv(&args(&["--tls-skip-verify", "delete", "secret/foo"])).unwrap();
        assert_eq!(r.0, "vault.delete");
    }

    #[test]
    fn multiple_global_flags_stripped() {
        let r = classify_vault_argv(&args(&[
            "-address=https://vault.example",
            "-namespace=team-a",
            "-tls-skip-verify",
            "-format=json",
            "kv",
            "destroy",
            "-versions=1",
            "secret/foo",
        ]))
        .unwrap();
        assert_eq!(r.0, "vault.kv.destroy");
    }

    #[test]
    fn flags_reordered_classification_stable() {
        let a = classify_vault_argv(&args(&["kv", "put", "secret/foo", "-namespace=ns", "k=v"]))
            .unwrap();
        let b = classify_vault_argv(&args(&["-namespace=ns", "kv", "put", "secret/foo", "k=v"]))
            .unwrap();
        let c = classify_vault_argv(&args(&["kv", "-namespace=ns", "put", "secret/foo", "k=v"]))
            .unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(b.0, c.0);
    }

    // --- corner cases ---

    #[test]
    fn empty_argv_passthrough() {
        assert!(classify_vault_argv(&[]).is_none());
    }

    #[test]
    fn only_global_flags_passthrough() {
        assert!(
            classify_vault_argv(&args(&[
                "-address=https://vault.example",
                "-tls-skip-verify"
            ]))
            .is_none()
        );
    }

    #[test]
    fn unknown_subsystem_passthrough() {
        assert!(classify_vault_argv(&args(&["operator", "init"])).is_none());
    }

    #[test]
    fn kv_without_verb_passthrough() {
        assert!(classify_vault_argv(&args(&["kv"])).is_none());
    }

    #[test]
    fn policy_without_verb_passthrough() {
        assert!(classify_vault_argv(&args(&["policy"])).is_none());
    }

    // --- KV path extraction ---

    #[test]
    fn extract_kv_path_simple() {
        let argv = vec!["secret/foo".to_string()];
        let (mount, path) = extract_kv_path(&argv).unwrap();
        assert_eq!(mount, "secret");
        assert_eq!(path, "foo");
    }

    #[test]
    fn extract_kv_path_nested() {
        let argv = vec!["kv/data/team-a/db-creds".to_string()];
        let (mount, path) = extract_kv_path(&argv).unwrap();
        assert_eq!(mount, "kv");
        assert_eq!(path, "data/team-a/db-creds");
    }

    #[test]
    fn extract_kv_path_skips_flags() {
        let argv = vec![
            "-versions=2".to_string(),
            "-format=json".to_string(),
            "secret/foo".to_string(),
        ];
        let (mount, path) = extract_kv_path(&argv).unwrap();
        assert_eq!(mount, "secret");
        assert_eq!(path, "foo");
    }

    #[test]
    fn extract_kv_path_no_path_returns_none() {
        let argv: Vec<String> = vec!["-versions=1".to_string()];
        assert!(extract_kv_path(&argv).is_none());
    }

    #[test]
    fn extract_kv_path_no_slash_returns_none() {
        // A bare token without `/` is not a valid kv mount/path.
        let argv = vec!["secret".to_string()];
        assert!(extract_kv_path(&argv).is_none());
    }

    #[test]
    fn extract_kv_path_empty_segment_returns_none() {
        // `/foo` and `secret/` are malformed.
        let argv1 = vec!["/foo".to_string()];
        assert!(extract_kv_path(&argv1).is_none());
        let argv2 = vec!["secret/".to_string()];
        assert!(extract_kv_path(&argv2).is_none());
    }

    // --- proptest: argv fuzzer; no panics; passthrough is a fixed point ---

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 256,
            ..proptest::test_runner::Config::default()
        })]

        /// Fuzz arbitrary argv shapes — must never panic.
        #[test]
        fn fuzz_classify_no_panic(
            argv in proptest::collection::vec("[a-zA-Z0-9_:./=-]{0,16}", 0..8usize)
        ) {
            // We only care that no panic escapes.
            let _ = classify_vault_argv(&argv);
        }

        /// Inserting a recognized value-bearing global flag (with value) at
        /// any position into a known classified argv must not change the
        /// classification.
        #[test]
        fn fuzz_namespace_flag_insertion_stable(
            insert_at in 0usize..6,
            ns in "[a-z][a-z0-9-]{0,8}"
        ) {
            let base = vec![
                "kv".to_string(),
                "put".to_string(),
                "secret/foo".to_string(),
            ];
            let base_class = classify_vault_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, ns.clone());
            with_flag.insert(pos, "-namespace".to_string());

            let class2 = classify_vault_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }

        /// Inserting a boolean global flag at any position into a known
        /// classified argv must not change the classification.
        #[test]
        fn fuzz_boolean_flag_insertion_stable(insert_at in 0usize..6) {
            let base = vec![
                "policy".to_string(),
                "delete".to_string(),
                "my-policy".to_string(),
            ];
            let base_class = classify_vault_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, "-tls-skip-verify".to_string());

            let class2 = classify_vault_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }

        /// Inserting an `-address=` equals-form flag at any position into
        /// a known classified argv must not change the classification.
        #[test]
        fn fuzz_address_eq_flag_insertion_stable(insert_at in 0usize..6) {
            let base = vec![
                "audit".to_string(),
                "disable".to_string(),
                "file/".to_string(),
            ];
            let base_class = classify_vault_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, "-address=https://vault.example".to_string());

            let class2 = classify_vault_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }
    }

    // --- T2: integration with MockBroker for BrokerProvider::HashiVault ---
    //
    // The full broker_exec lifecycle lives in the daemon; here we cover the
    // contract slice this Construct depends on: the broker registry can
    // hold a `MockBroker::new(BrokerProvider::HashiVault)`, and a request
    // that declares `provider = HashiVault` round-trips through issue →
    // revoke without panicking. Real HashiVault impl is
    // BROKER-HASHIVAULT-IMPL (separate task).

    use core_broker::{Broker, BrokerError, BrokerProvider, BrokerRequest, MockBroker};
    use std::time::Duration;

    fn vault_request(ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::HashiVault,
            scope: serde_json::json!({
                "policies": ["read-secret-foo"],
                "paths": ["secret/data/foo"],
                "namespace": "team-a",
            }),
            ttl: Duration::from_secs(ttl_secs),
            contract_id: None,
            action_ref: None,
            workspace_ref: None,
            subject_ref: None,
            coordination_ref: None,
            caller_ref: None,
            authority_ref: None,
            reason: "ember-vault integration test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    #[tokio::test]
    async fn mock_broker_hashi_vault_issue_revoke_roundtrip() {
        let broker = MockBroker::new(BrokerProvider::HashiVault);
        assert_eq!(broker.provider(), BrokerProvider::HashiVault);

        let creds = broker
            .issue(vault_request(900))
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
    async fn mock_broker_hashi_vault_rejects_wrong_provider() {
        let broker = MockBroker::new(BrokerProvider::HashiVault);
        let mut req = vault_request(900);
        req.provider = BrokerProvider::Cloudflare;

        let err = broker.issue(req).await.expect_err("provider mismatch");
        match err {
            BrokerError::InvalidScope(_) => {}
            other => panic!("expected InvalidScope, got {other:?}"),
        }
    }
}
