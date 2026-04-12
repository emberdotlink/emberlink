use std::collections::HashMap;

use core_crypto::LocalKeyPair;
use core_types::KeyAlgorithm;

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

/// In-memory local state: signing keys plus any lines the app doesn't parse
/// (peer_identity, linkages, recovery sessions, manifest keys). The passthrough
/// lines are preserved verbatim so CLI and GUI can share `local-state.enc`
/// without data loss.
pub struct LocalState {
    /// Signing keys keyed by owner_id.
    pub keys: HashMap<String, LocalKeyEntry>,
    /// Ephemeral keys for outstanding grant offers, keyed by offer_id.
    pub ephemeral_keys: HashMap<String, EphemeralKeyEntry>,
    /// Lines that this layer doesn't interpret — preserved on roundtrip.
    pub passthrough_lines: Vec<String>,
}

impl LocalState {
    pub fn empty() -> Self {
        Self {
            keys: HashMap::new(),
            ephemeral_keys: HashMap::new(),
            passthrough_lines: Vec::new(),
        }
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

    lines.join("\n")
}

pub fn deserialize(data: &str) -> Result<LocalState, String> {
    let mut keys = HashMap::new();
    let mut ephemeral_keys = HashMap::new();
    let mut passthrough_lines = Vec::new();

    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        match parts.first() {
            Some(&"local_key") => match parts.as_slice() {
                ["local_key", owner_kind, owner_id, key_id, public_key, private_key] => {
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
            _ => {
                passthrough_lines.push(line.to_string());
            }
        }
    }

    Ok(LocalState {
        keys,
        ephemeral_keys,
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
