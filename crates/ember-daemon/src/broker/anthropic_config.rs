//! Anthropic workspace credential discovery for the daemon's broker
//! registry. Mirrors the shape of `github_config.rs` and
//! `aws_sts_config.rs` so wireup is homogeneous across providers.
//!
//! Reads ADR-099-grammar vault paths under `anthropic/workspace/<tier>/`
//! for the Anthropic Admin-API workspace key id + API key the daemon
//! hands to the (forthcoming) `ember_broker::AnthropicBroker`. Tiers
//! are arbitrary lowercase-hyphen identifiers per ADR 096 (e.g.
//! `default`, `agents-autopilot`, `prod`); the caller chooses which
//! tier to resolve at registration time.
//!
//! Behaviour contract:
//!
//! - Both leaves present → `Ok(Some(creds))`. Daemon registers the
//!   Anthropic broker for that tier and emits a
//!   `bot-identity-source { provider="anthropic", source="vault", tier }`
//!   tracing event.
//! - Both leaves absent → `Ok(None)`. Daemon falls back to the env
//!   loader (when one exists) or `MockBroker` for development hosts.
//! - One leaf present, the other absent → `Err(StoreError::Other)`.
//!   A partial triple is an operator misconfiguration and we surface
//!   it loudly rather than silently picking up the env fallback.
//!
//! This file exists for ARCH-BROKER-VAULT-CUTOVER-PR4A-CONFIG-READERS;
//! the runtime wireup that consumes it lands in PR4B alongside the
//! `EMBER_VAULT_FIRST` flag.

use secrecy::SecretString;

/// Anthropic workspace credentials minted from a vault entry.
///
/// `api_key` is wrapped in `SecretString` so it never lands in
/// `Debug` / `Display` output. `key_id` is the Anthropic-assigned
/// workspace-key identifier (non-secret — used in audit and broker
/// metrics so the operator can correlate a request with a specific
/// key when rotation lands).
pub struct AnthropicWorkspaceCredentials {
    /// The actual Anthropic API key (`sk-ant-…`).
    pub api_key: SecretString,
    /// The non-secret workspace-key identifier paired with `api_key`.
    pub key_id: String,
}

/// Store-key prefix for ADR-099-grammar Anthropic workspace
/// credentials. Entries live under
/// `anthropic/workspace/<tier>/<purpose>` where `<purpose>` ∈ {
/// `api-key`, `key-id` }.
const STORE_PREFIX_ANTHROPIC_WORKSPACE: &str = "anthropic/workspace";

/// Per-purpose leaf names beneath
/// `anthropic/workspace/<tier>/`.
const PURPOSE_API_KEY: &str = "api-key";
const PURPOSE_KEY_ID: &str = "key-id";

/// `CredentialStore`-backed reader for Anthropic workspace
/// credentials at the given `tier`.
///
/// Returns:
/// - `Ok(Some(creds))` when both `api-key` and `key-id` leaves are
///   present.
/// - `Ok(None)` when the tier has no entries at all (the daemon
///   falls back to env / mock per the wireup in `runtime.rs`).
/// - `Err(StoreError::Other(_))` when exactly one of the two leaves
///   is present — partial credentials are a misconfiguration we
///   surface loudly rather than silently falling back from.
///
/// On `Ok(Some(_))` the function emits a structured
/// `bot-identity-source` event via `tracing::info!` with fields
/// `provider="anthropic"`, `source="vault"`, and `tier=<tier>`.
pub async fn anthropic_config_from_store(
    store: &dyn crate::infra::credential_store::CredentialStore,
    tier: &str,
) -> Result<Option<AnthropicWorkspaceCredentials>, crate::infra::credential_store::StoreError> {
    use crate::infra::credential_store::StoreError;

    async fn get_opt(
        store: &dyn crate::infra::credential_store::CredentialStore,
        key: &str,
    ) -> Result<Option<String>, StoreError> {
        match store.get(key).await {
            Ok(bytes) => {
                Ok(Some(String::from_utf8(bytes).map_err(|e| {
                    StoreError::Other(format!("non-utf8 in {}: {e}", key))
                })?))
            }
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(other) => Err(other),
        }
    }

    let api_key_path = format!("{STORE_PREFIX_ANTHROPIC_WORKSPACE}/{tier}/{PURPOSE_API_KEY}");
    let key_id_path = format!("{STORE_PREFIX_ANTHROPIC_WORKSPACE}/{tier}/{PURPOSE_KEY_ID}");

    let api_key = get_opt(store, &api_key_path).await?;
    let key_id = get_opt(store, &key_id_path).await?;

    let (api_key, key_id) = match (api_key, key_id) {
        (Some(a), Some(k)) => (a, k),
        (None, None) => return Ok(None),
        (Some(_), None) => {
            return Err(StoreError::Other(format!(
                "{api_key_path}: present but {key_id_path}: missing — \
                 both leaves of an Anthropic workspace credential must \
                 be present together"
            )));
        }
        (None, Some(_)) => {
            return Err(StoreError::Other(format!(
                "{key_id_path}: present but {api_key_path}: missing — \
                 both leaves of an Anthropic workspace credential must \
                 be present together"
            )));
        }
    };

    if api_key.trim().is_empty() {
        return Err(StoreError::Other(format!(
            "{api_key_path}: empty value — expected Anthropic API key"
        )));
    }

    tracing::info!(
        event = "bot-identity-source",
        provider = "anthropic",
        source = "vault",
        tier = %tier,
        "broker config reader resolved Anthropic workspace credentials from vault"
    );

    Ok(Some(AnthropicWorkspaceCredentials {
        api_key: SecretString::from(api_key),
        key_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    /// Seed an in-memory store with the ADR-099 path grammar for a
    /// single tier and assert the reader returns the credential.
    /// Covers the PR4A acceptance criterion
    /// "reads anthropic/workspace/<tier>/{api-key,key-id}".
    #[tokio::test]
    async fn anthropic_config_from_store_reads_tier() {
        use crate::infra::credential_store::CredentialStore;
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(
            "anthropic/workspace/default/api-key",
            b"sk-ant-fake-key-value",
        )
        .await
        .unwrap();
        mock.put(
            "anthropic/workspace/default/key-id",
            b"workspace-key-abc123",
        )
        .await
        .unwrap();

        let result = anthropic_config_from_store(&mock, "default").await.unwrap();
        let creds = result.expect("credentials should be present");
        assert_eq!(creds.key_id, "workspace-key-abc123");
        assert_eq!(creds.api_key.expose_secret(), "sk-ant-fake-key-value");
    }

    /// When the requested tier has no entries the reader returns
    /// `Ok(None)` so the daemon wireup falls back to env / mock.
    #[tokio::test]
    async fn anthropic_config_from_store_absent_tier_returns_ok_none() {
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        let result = anthropic_config_from_store(&mock, "absent-tier")
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "missing tier must return Ok(None) so file-fallback engages"
        );
    }

    /// A tier with `api-key` present but `key-id` missing is a
    /// misconfiguration and must surface as `Err`.
    #[tokio::test]
    async fn anthropic_config_from_store_partial_pair_is_err() {
        use crate::infra::credential_store::CredentialStore;
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(
            "anthropic/workspace/default/api-key",
            b"sk-ant-fake-key-value",
        )
        .await
        .unwrap();
        // Note: no key-id leaf.

        let err = match anthropic_config_from_store(&mock, "default").await {
            Err(e) => e,
            Ok(_) => panic!("partial pair must surface as Err, got Ok"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("both leaves"),
            "error must call out the partial state: {msg}"
        );
    }

    /// Tiers are independent — populating one tier must not surface
    /// credentials for a different tier.
    #[tokio::test]
    async fn anthropic_config_from_store_tier_isolation() {
        use crate::infra::credential_store::CredentialStore;
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(
            "anthropic/workspace/agents-autopilot/api-key",
            b"sk-ant-fake-autopilot",
        )
        .await
        .unwrap();
        mock.put(
            "anthropic/workspace/agents-autopilot/key-id",
            b"autopilot-key-id",
        )
        .await
        .unwrap();

        // The "default" tier is empty even though "agents-autopilot" is populated.
        let result = anthropic_config_from_store(&mock, "default").await.unwrap();
        assert!(result.is_none(), "default tier must be empty");

        // The "agents-autopilot" tier resolves cleanly.
        let creds = anthropic_config_from_store(&mock, "agents-autopilot")
            .await
            .unwrap()
            .expect("autopilot tier must resolve");
        assert_eq!(creds.key_id, "autopilot-key-id");
    }
}
