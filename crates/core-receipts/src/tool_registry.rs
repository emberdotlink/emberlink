//! Registry of known ember-X tools (TZ-RECEIPT-V2-CLI).
//!
//! Receipts reference tools by id (e.g. `ember-aws`); the registry tells
//! the verifier whether a tool is recognized and what credential provider
//! it expects. Source of truth: the `package.name` field in each
//! `crates/ember-*/Cargo.toml` for shipped tool-shim Constructs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// One row in the tool registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolEntry {
    /// Crate name and CLI id, e.g. `"ember-aws"`.
    pub id: String,
    /// Human-readable display name, e.g. `"AWS CLI"`.
    pub display_name: String,
    /// Argv prefix the shim wraps, e.g. `"aws"`.
    pub argv_prefix: String,
    /// Credential-provider hint used by the broker, e.g. `"aws_sts"`.
    pub credential_provider: String,
}

/// Lookup table from tool id to [`ToolEntry`]. Built once via
/// [`ToolRegistry::new_default`] and reused per verify call.
#[derive(Debug, Clone, Default)]
pub struct ToolRegistry {
    entries: HashMap<String, ToolEntry>,
}

impl ToolRegistry {
    /// Empty registry. Tests use this; production callers want
    /// [`ToolRegistry::new_default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-populated registry with every ember-X tool currently shipped as a
    /// tool-shim Construct in `crates/ember-*`.
    pub fn new_default() -> Self {
        let mut entries = HashMap::new();
        for entry in default_entries() {
            entries.insert(entry.id.clone(), entry);
        }
        Self { entries }
    }

    /// Register a tool entry, overwriting any existing entry with the same id.
    pub fn register(&mut self, entry: ToolEntry) {
        self.entries.insert(entry.id.clone(), entry);
    }

    /// Look up a tool by id. Returns `None` if unknown.
    pub fn lookup(&self, id: &str) -> Option<&ToolEntry> {
        self.entries.get(id)
    }

    /// Iterate over all known tools (order is unspecified).
    pub fn known_tools(&self) -> impl Iterator<Item = &ToolEntry> {
        self.entries.values()
    }

    /// Number of registered tools.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn default_entries() -> Vec<ToolEntry> {
    vec![
        ToolEntry {
            id: "ember-aws".into(),
            display_name: "AWS CLI".into(),
            argv_prefix: "aws".into(),
            credential_provider: "aws_sts".into(),
        },
        ToolEntry {
            id: "ember-az".into(),
            display_name: "Azure CLI".into(),
            argv_prefix: "az".into(),
            credential_provider: "azure".into(),
        },
        ToolEntry {
            id: "ember-gcloud".into(),
            display_name: "Google Cloud CLI".into(),
            argv_prefix: "gcloud".into(),
            credential_provider: "gcp".into(),
        },
        ToolEntry {
            id: "ember-vault".into(),
            display_name: "HashiCorp Vault CLI".into(),
            argv_prefix: "vault".into(),
            credential_provider: "vault_token".into(),
        },
        ToolEntry {
            id: "ember-kubectl".into(),
            display_name: "Kubernetes kubectl".into(),
            argv_prefix: "kubectl".into(),
            credential_provider: "kubeconfig".into(),
        },
        ToolEntry {
            id: "ember-wrangler".into(),
            display_name: "Cloudflare Wrangler".into(),
            argv_prefix: "wrangler".into(),
            credential_provider: "cloudflare_api_token".into(),
        },
        ToolEntry {
            id: "ember-gh".into(),
            display_name: "GitHub CLI".into(),
            argv_prefix: "gh".into(),
            credential_provider: "github_token".into(),
        },
        ToolEntry {
            id: "ember-git".into(),
            display_name: "git".into(),
            argv_prefix: "git".into(),
            credential_provider: "git_credentials".into(),
        },
        ToolEntry {
            id: "ember-docker".into(),
            display_name: "Docker CLI".into(),
            argv_prefix: "docker".into(),
            credential_provider: "docker_config".into(),
        },
        ToolEntry {
            id: "ember-pulumi".into(),
            display_name: "Pulumi CLI".into(),
            argv_prefix: "pulumi".into(),
            credential_provider: "pulumi_access_token".into(),
        },
        ToolEntry {
            id: "ember-npm".into(),
            display_name: "npm".into(),
            argv_prefix: "npm".into(),
            credential_provider: "npm_token".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_includes_all_shipped_tools() {
        let r = ToolRegistry::new_default();
        // Every ember-X tool-shim crate currently in the workspace must be
        // present so v2 verify recognises receipts that reference them.
        let must_have = [
            "ember-aws",
            "ember-az",
            "ember-gcloud",
            "ember-vault",
            "ember-kubectl",
            "ember-wrangler",
            "ember-gh",
            "ember-git",
            "ember-docker",
            "ember-pulumi",
            "ember-npm",
        ];
        for id in must_have {
            assert!(r.lookup(id).is_some(), "default registry missing {id}");
        }
    }

    #[test]
    fn lookup_returns_entry() {
        let r = ToolRegistry::new_default();
        let entry = r.lookup("ember-aws").expect("ember-aws must be registered");
        assert_eq!(entry.argv_prefix, "aws");
        assert_eq!(entry.credential_provider, "aws_sts");
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let r = ToolRegistry::new_default();
        assert!(r.lookup("ember-bogus").is_none());
    }

    #[test]
    fn register_inserts_custom_entry() {
        let mut r = ToolRegistry::new();
        assert!(r.is_empty());
        r.register(ToolEntry {
            id: "ember-fake".into(),
            display_name: "Fake".into(),
            argv_prefix: "fake".into(),
            credential_provider: "none".into(),
        });
        assert_eq!(r.len(), 1);
        assert_eq!(r.lookup("ember-fake").unwrap().argv_prefix, "fake");
    }

    #[test]
    fn known_tools_iterates_all_entries() {
        let r = ToolRegistry::new_default();
        let count = r.known_tools().count();
        assert_eq!(count, r.len());
        assert!(count >= 11);
    }
}
