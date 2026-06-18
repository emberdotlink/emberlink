//! ember-vault — Construct shim for `vault` (HashiCorp Vault CLI) per ADR 124 §1.
//!
//! Lifecycle (env-detect → classify → broker_exec RPC → PTY bridge → exit)
//! is owned by `core-construct-runtime::run_construct_full`. This file wires
//! the vault-specific classifier and config onto that entry point.
//!
//! Wire format details (TAG_DATA, TAG_WINSIZE, TAG_SIGINT/TERM/TSTP/CONT)
//! live in `core-construct-runtime::pty_bridge`.
//!
//! Credential injection: the broker (`BrokerProvider::HashiVault`) issues a
//! scoped Vault child token (minted from a parent token via policy/path
//! scope), and the daemon materializes it into `VAULT_TOKEN` and
//! `VAULT_ADDR`. The daemon zeroizes on child exit and additionally calls
//! Vault's `auth/token/revoke` to enforce TTL-bound exposure even if broker
//! bookkeeping fails.
//!
//! EMBER_VAULT_WIRE_DONE

mod classify;

use std::env;
use std::process::ExitCode;

use core_construct_runtime::{ActionKey, ClassifyArgv, ConstructConfig};

const CONSTRUCT_TOML: &[u8] = include_bytes!("../construct.toml");

struct VaultConfig;

impl ClassifyArgv for VaultConfig {
    fn classify(&self, argv: &[String]) -> Option<ActionKey> {
        classify::classify_vault_argv(argv)
    }
}

impl ConstructConfig for VaultConfig {
    fn session_id_env(&self) -> &'static str {
        "EMBER_SESSION_ID"
    }

    fn construct_toml_bytes(&self) -> &'static [u8] {
        CONSTRUCT_TOML
    }

    fn resolve_binary(&self) -> String {
        env::var("EMBER_VAULT_BINARY").unwrap_or_else(|_| {
            env::var("PATH")
                .unwrap_or_default()
                .split(':')
                .map(|dir| format!("{dir}/vault"))
                .find(|p| std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false))
                .unwrap_or_else(|| "vault".to_string())
        })
    }

    fn env_passthrough(&self) -> &'static [&'static str] {
        &["VAULT_TOKEN", "VAULT_ADDR"]
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    let argv: Vec<String> = env::args().skip(1).collect();
    core_construct_runtime::run_construct_full(&argv, &VaultConfig)
}
