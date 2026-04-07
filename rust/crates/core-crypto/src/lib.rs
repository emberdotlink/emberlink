use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub String);

pub trait Signer {
    fn sign(&self, payload: &[u8]) -> Signature;
    fn public_key(&self) -> PublicKey;
}

pub trait Verifier {
    fn verify(&self, public_key: &PublicKey, payload: &[u8], signature: &Signature) -> bool;
}

#[derive(Debug, Clone)]
pub struct FixtureSigner {
    key_id: String,
}

impl FixtureSigner {
    pub fn new(key_id: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
        }
    }

    fn digest(&self, payload: &[u8]) -> String {
        let mut hasher = DefaultHasher::new();
        self.key_id.hash(&mut hasher);
        payload.hash(&mut hasher);
        format!("fixture:{:016x}", hasher.finish())
    }
}

impl Signer for FixtureSigner {
    fn sign(&self, payload: &[u8]) -> Signature {
        Signature(self.digest(payload))
    }

    fn public_key(&self) -> PublicKey {
        PublicKey(self.key_id.clone())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FixtureVerifier;

impl Verifier for FixtureVerifier {
    fn verify(&self, public_key: &PublicKey, payload: &[u8], signature: &Signature) -> bool {
        let signer = FixtureSigner::new(public_key.0.clone());
        signer.sign(payload) == *signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_signatures_are_deterministic() {
        let signer = FixtureSigner::new("fixture_signer");
        let signature = signer.sign(b"root_created");
        let verifier = FixtureVerifier;

        assert!(verifier.verify(&signer.public_key(), b"root_created", &signature));
    }
}

