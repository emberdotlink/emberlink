use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedImage {
    pub name: String,
    pub digest: String,
    pub source: String,
    pub first_seen: String,
    pub last_verified: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ImageRegistry {
    #[serde(default)]
    pub images: HashMap<String, TrustedImage>,
}

impl ImageRegistry {
    pub fn load(path: &Path) -> Result<Self, ImageRegistryError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path)?;
        let registry: ImageRegistry = toml::from_str(&contents)?;
        Ok(registry)
    }

    pub fn save(&self, path: &Path) -> Result<(), ImageRegistryError> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Record a pulled image. Returns true if this is a new image or digest changed.
    pub fn record(&mut self, name: &str, digest: &str, source: &str) -> bool {
        let now = chrono::Utc::now().to_rfc3339();
        match self.images.get(name) {
            Some(existing) if existing.digest == digest => {
                // Same digest — just update last_verified
                if let Some(img) = self.images.get_mut(name) {
                    img.last_verified = now;
                }
                false
            }
            Some(_existing) => {
                // DIGEST CHANGED — tag mutation detected
                tracing::warn!(
                    image = name,
                    old_digest = self.images[name].digest,
                    new_digest = digest,
                    "image digest changed — possible tag mutation"
                );
                self.images.insert(
                    name.to_string(),
                    TrustedImage {
                        name: name.to_string(),
                        digest: digest.to_string(),
                        source: source.to_string(),
                        first_seen: now.clone(),
                        last_verified: now,
                    },
                );
                true
            }
            None => {
                self.images.insert(
                    name.to_string(),
                    TrustedImage {
                        name: name.to_string(),
                        digest: digest.to_string(),
                        source: source.to_string(),
                        first_seen: now.clone(),
                        last_verified: now,
                    },
                );
                true
            }
        }
    }

    /// Check if an image name matches a trusted digest
    pub fn verify(&self, name: &str, digest: &str) -> bool {
        self.images
            .get(name)
            .is_some_and(|img| img.digest == digest)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ImageRegistryError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("serialize: {0}")]
    Serialize(#[from] toml::ser::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn record_new_image() {
        let mut registry = ImageRegistry::default();
        let changed = registry.record("alpine:latest", "sha256:abc123", "docker.io");
        assert!(changed);
        assert!(registry.images.contains_key("alpine:latest"));
    }

    #[test]
    fn record_same_digest_returns_false() {
        let mut registry = ImageRegistry::default();
        registry.record("alpine:latest", "sha256:abc123", "docker.io");
        let changed = registry.record("alpine:latest", "sha256:abc123", "docker.io");
        assert!(!changed);
    }

    #[test]
    fn record_changed_digest_returns_true() {
        let mut registry = ImageRegistry::default();
        registry.record("alpine:latest", "sha256:abc123", "docker.io");
        let changed = registry.record("alpine:latest", "sha256:def456", "docker.io");
        assert!(changed);
        assert_eq!(registry.images["alpine:latest"].digest, "sha256:def456");
    }

    #[test]
    fn verify_known_image() {
        let mut registry = ImageRegistry::default();
        registry.record("alpine:latest", "sha256:abc123", "docker.io");
        assert!(registry.verify("alpine:latest", "sha256:abc123"));
    }

    #[test]
    fn verify_unknown_image() {
        let registry = ImageRegistry::default();
        assert!(!registry.verify("alpine:latest", "sha256:abc123"));
    }

    #[test]
    fn load_save_roundtrip() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();

        let mut registry = ImageRegistry::default();
        registry.record("alpine:latest", "sha256:abc123", "docker.io");
        registry.record("ubuntu:22.04", "sha256:def456", "docker.io");
        registry.save(path).unwrap();

        let loaded = ImageRegistry::load(path).unwrap();
        assert_eq!(loaded.images.len(), 2);
        assert_eq!(loaded.images["alpine:latest"].digest, "sha256:abc123");
        assert_eq!(loaded.images["ubuntu:22.04"].source, "docker.io");
    }
}
