use std::collections::HashMap;

use core_crypto::LocalKeyPair;
use core_crypto::grant_chain::PubkeyNextKeyPair;
use core_principals::KeyAlgorithm;
use zeroize::Zeroize;

/// A signing key held locally for one owner (root, persona, or device).
pub struct LocalKeyEntry {
    pub owner_kind: String,
    pub key_pair: LocalKeyPair,
}

/// An ephemeral private key held for an outstanding grant offer.
/// Discarded once the offer is claimed or expires.
pub struct EphemeralKeyEntry {
    pub offer_id: String,
    pub private_key_age: String,
    pub expires_at: u64,
}

/// The `pubkey_next` secret for a grant chain's tail (M-3). Persisted so
/// that later delegation / attenuation blocks can be signed after a daemon
/// restart. Drop clears the secret from memory.
///
/// Stored as hex — same encoding as `LocalKeyEntry.private_key`, sharing
/// the same keystore (`local-state.enc` encrypted under the vault master
/// key). No separate on-disk location; the whole `LocalState` is
/// encrypted as a single blob.
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct GrantChainSecret {
    pub grant_id: String,
    pub public_hex: String,
    pub secret_hex: String,
}

impl GrantChainSecret {
    pub fn to_pubkey_next_keypair(&self) -> Option<PubkeyNextKeyPair> {
        PubkeyNextKeyPair::from_hex(self.public_hex.clone(), self.secret_hex.clone()).ok()
    }
}

/// In-memory local state: signing keys plus any lines the app doesn't parse
/// (peer_identity, linkages, recovery sessions, manifest keys). The passthrough
/// lines are preserved verbatim so CLI and GUI can share `local-state.enc`
/// without data loss.
pub struct LocalState {
    /// Signing keys keyed by owner_id.
    pub keys: HashMap<String, LocalKeyEntry>,
    /// Ephemeral keys for outstanding grant offers, keyed by offer_id.
    pub ephemeral_keys: HashMap<String, EphemeralKeyEntry>,
    /// Grant-chain `pubkey_next` secrets keyed by grant_id (M-3). See
    /// `core_crypto::grant_chain::PubkeyNextKeyPair`.
    pub chain_secrets: HashMap<String, GrantChainSecret>,
    /// Lines that this layer doesn't interpret — preserved on roundtrip.
    pub passthrough_lines: Vec<String>,
}

impl LocalState {
    pub fn empty() -> Self {
        Self {
            keys: HashMap::new(),
            ephemeral_keys: HashMap::new(),
            chain_secrets: HashMap::new(),
            passthrough_lines: Vec::new(),
        }
    }

    /// Store the `pubkey_next` secret for a grant chain's tail. See
    /// `core_crypto::grant_chain::sign_block_zero`.
    pub fn store_chain_secret(&mut self, grant_id: impl Into<String>, secret: PubkeyNextKeyPair) {
        let grant_id = grant_id.into();
        self.chain_secrets.insert(
            grant_id.clone(),
            GrantChainSecret {
                grant_id,
                public_hex: secret.public_hex.clone(),
                secret_hex: secret.secret_hex.clone(),
            },
        );
    }

    /// Load the `pubkey_next` secret for extending a grant chain.
    pub fn load_chain_secret(&self, grant_id: &str) -> Option<PubkeyNextKeyPair> {
        self.chain_secrets
            .get(grant_id)
            .and_then(|s| s.to_pubkey_next_keypair())
    }
}

impl Default for LocalState {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// TSV serialization — must stay byte-for-byte compatible with the CLI format
// ---------------------------------------------------------------------------

pub fn serialize(state: &LocalState) -> String {
    let mut lines = Vec::new();

    for line in &state.passthrough_lines {
        lines.push(line.clone());
    }

    for (owner_id, entry) in &state.keys {
        lines.push(format!(
            "local_key\t{}\t{}\t{}\t{}\t{}",
            entry.owner_kind,
            owner_id,
            entry.key_pair.key_id,
            entry.key_pair.public_key,
            entry.key_pair.private_key,
        ));
    }

    for (offer_id, entry) in &state.ephemeral_keys {
        lines.push(format!(
            "ephemeral_key\t{}\t{}\t{}",
            offer_id, entry.private_key_age, entry.expires_at,
        ));
    }

    for (grant_id, entry) in &state.chain_secrets {
        lines.push(format!(
            "chain_secret\t{}\t{}\t{}",
            grant_id, entry.public_hex, entry.secret_hex,
        ));
    }

    lines.join("\n")
}

pub fn deserialize(data: &str) -> Result<LocalState, String> {
    let mut keys = HashMap::new();
    let mut ephemeral_keys = HashMap::new();
    let mut chain_secrets = HashMap::new();
    let mut passthrough_lines = Vec::new();

    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        match parts.first() {
            Some(&"local_key") => match parts.as_slice() {
                [
                    "local_key",
                    owner_kind,
                    owner_id,
                    key_id,
                    public_key,
                    private_key,
                ] => {
                    let algorithm = key_algorithm_from_public_key(public_key)?;
                    keys.insert(
                        owner_id.to_string(),
                        LocalKeyEntry {
                            owner_kind: owner_kind.to_string(),
                            key_pair: LocalKeyPair {
                                key_id: key_id.to_string(),
                                algorithm,
                                public_key: public_key.to_string(),
                                private_key: private_key.to_string(),
                            },
                        },
                    );
                }
                _ => return Err(format!("malformed local_key line: {line}")),
            },
            Some(&"ephemeral_key") => match parts.as_slice() {
                ["ephemeral_key", offer_id, private_key_age, expires_at] => {
                    let expires_at = expires_at
                        .parse::<u64>()
                        .map_err(|_| format!("malformed ephemeral_key expires_at: {line}"))?;
                    ephemeral_keys.insert(
                        offer_id.to_string(),
                        EphemeralKeyEntry {
                            offer_id: offer_id.to_string(),
                            private_key_age: private_key_age.to_string(),
                            expires_at,
                        },
                    );
                }
                _ => return Err(format!("malformed ephemeral_key line: {line}")),
            },
            Some(&"chain_secret") => match parts.as_slice() {
                ["chain_secret", grant_id, public_hex, secret_hex] => {
                    chain_secrets.insert(
                        grant_id.to_string(),
                        GrantChainSecret {
                            grant_id: grant_id.to_string(),
                            public_hex: public_hex.to_string(),
                            secret_hex: secret_hex.to_string(),
                        },
                    );
                }
                _ => return Err(format!("malformed chain_secret line: {line}")),
            },
            _ => {
                passthrough_lines.push(line.to_string());
            }
        }
    }

    Ok(LocalState {
        keys,
        ephemeral_keys,
        chain_secrets,
        passthrough_lines,
    })
}

fn key_algorithm_from_public_key(public_key: &str) -> Result<KeyAlgorithm, String> {
    if public_key.starts_with("ed25519:") {
        Ok(KeyAlgorithm::Ed25519)
    } else if public_key.starts_with("age1") {
        Ok(KeyAlgorithm::AgeX25519)
    } else {
        Err(format!("unsupported public key encoding: {public_key}"))
    }
}
