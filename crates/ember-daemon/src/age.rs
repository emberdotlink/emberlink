//! Age keypair generation + storage in the daemon vault.
//!
//! Phase 1 of the SOPS+emberd integration (pulumi-gitops.md / ADR 100).
//! Each persona has an age keypair. Public key gets exported to
//! `.sops.yaml` creation_rules; private key stays in the daemon vault
//! and is released only via the blessed `sops-as-bot.sh` wrapper
//! (TZ-SOPS-1-WRAPPER follow-up).

#[cfg_attr(feature = "age", allow(unused_imports))]
use anyhow::Context;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// One age keypair.
///
/// `public_key` is the `age1...` recipient string (publishable in
/// `.sops.yaml`). `private_key` is the `AGE-SECRET-KEY-1...` plaintext —
/// never log or persist outside the daemon's encrypted vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgeKeypair {
    pub public_key: String,
    /// Plaintext private key. Treat as Secret. Stored only in the daemon vault.
    pub private_key: String,
}

/// Generate a fresh age keypair using the `age` crate.
///
/// Real impl: `age::x25519::Identity::generate()`. The `age` crate is
/// already in the broader Rust ecosystem; pulling it in is mechanical.
/// For now, gate the dep with a `#[cfg]` to keep this task PR-sized.
///
/// TODO: orchestrator-only follow-up ships
/// `.claude/scripts/sops-as-bot.sh` which is the only blessed path that
/// actually releases this private key out of the vault.
pub fn generate_age_keypair() -> Result<AgeKeypair> {
    #[cfg(feature = "age")]
    {
        use age::secrecy::ExposeSecret;
        let identity = age::x25519::Identity::generate();
        let public = identity.to_public().to_string();
        let private = identity.to_string().expose_secret().to_string();
        Ok(AgeKeypair {
            public_key: public,
            private_key: private,
        })
    }
    #[cfg(not(feature = "age"))]
    {
        Err(anyhow::anyhow!(
            "age feature not enabled; build with --features age (TZ-SOPS-1-WIRE-DEP follow-up)"
        ))
        .context("generate_age_keypair stub — feature gate not yet flipped")
    }
}

/// Compose a vault entry name for a persona's age private key.
/// Per ADR 097 grammar: lowercase + hyphens + slashes only.
pub fn vault_path_for_persona(persona: &str) -> String {
    format!("age/persona/{}/private-key", persona)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_path_format() {
        assert_eq!(
            vault_path_for_persona("orchestrator"),
            "age/persona/orchestrator/private-key"
        );
    }

    #[test]
    #[cfg(feature = "age")]
    fn generate_returns_distinct_keypairs() {
        let a = generate_age_keypair().unwrap();
        let b = generate_age_keypair().unwrap();
        assert_ne!(a.public_key, b.public_key);
        assert!(a.public_key.starts_with("age1"));
        assert!(a.private_key.starts_with("AGE-SECRET-KEY-1"));
    }

    #[test]
    #[cfg(not(feature = "age"))]
    fn generate_errors_without_feature() {
        assert!(generate_age_keypair().is_err());
    }
}
