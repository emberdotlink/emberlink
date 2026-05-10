//! GitHub App `Broker` implementation — issues short-lived installation
//! tokens scoped to caller-supplied repos + permissions, returns them as
//! [`BrokeredCredential`] so the daemon's broker registry can route
//! `(provider=github, scope=...)` requests through a single trait shape.
//!
//! Wraps [`crate::github_app::mint_installation_token`] (prior change) and
//! exposes it through `core_broker::Broker`. Companion to the daemon-side
//! registration in `ember-daemon::infra::runtime::run` — this struct
//! holds the [`GhAppCredentials`] (loaded from disk at daemon startup)
//! and one entry per outstanding materialization.
//!
//! ## Revocation
//!
//! GitHub App installation tokens are TTL-bounded (1 hour fixed) and
//! cannot be revoked through a public API: `DELETE /installation/token`
//! requires the token itself as auth and is one-shot. The daemon's
//! `revoke()` therefore drops the bookkeeping entry but does not call
//! upstream — the credential remains valid until its `expires_at`. This
//! is acceptable because broker_exec issues + uses + drops within
//! seconds-to-minutes, well inside the 1-hour bound. A separate task
//! (T-CONSTRUCT-GH-INSTALLATION-TOKEN-REVOKE-UPSTREAM) can wire the
//! upstream DELETE call when shorter-than-TTL exposure windows matter.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::Arc;
use std::time::SystemTime;

use core_broker::{
    Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::github_app::{
    mint_installation_token_with_client, GhAppCredentials, GhAppError, HttpClient,
    ReqwestClient,
};

/// Provider-specific scope payload for the GitHub broker.
///
/// Deserialized from the opaque `BrokerRequest::scope` (`serde_json::Value`)
/// inside `issue()`. Both fields are optional:
///
/// - Empty `repositories` → token has the GitHub App's full installation
///   scope (every repo the App is installed on).
/// - Empty `permissions` → token inherits the App's installation-level
///   permissions verbatim.
///
/// Callers SHOULD set both for least-privilege; the broker will pass an
/// unscoped request through to GitHub if both are omitted, which produces
/// a token with the App's full installation power.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GithubScope {
    /// Repository names (without owner prefix) the token is restricted to.
    /// Example: `["emberlink-dev"]` (assuming the App is installed on the
    /// `emberdotlink` org).
    #[serde(default)]
    pub repositories: Vec<String>,

    /// Fine-grained permission pairs. Example:
    /// `[("contents", "write"), ("pull_requests", "write")]`.
    #[serde(default)]
    pub permissions: Vec<(String, String)>,
}

/// `Broker` impl backed by `ember_broker::github_app`.
///
/// Construct with [`GitHubBroker::new`] for production (uses
/// [`ReqwestClient`]) or [`GitHubBroker::with_client`] for tests
/// (any `dyn HttpClient` implementation).
pub struct GitHubBroker {
    creds: GhAppCredentials,
    client: Arc<dyn HttpClient>,
    /// `materialization_id` → `expires_at`. Populated on `issue()`,
    /// drained on `revoke()`. The broker holds nothing else per
    /// outstanding token — the plaintext is captured by the daemon's
    /// `BrokerRegistry::record_plaintext` immediately after `issue()`
    /// returns, so the broker never persists secret material itself.
    state: Mutex<HashMap<String, SystemTime>>,
}

impl GitHubBroker {
    /// Production constructor — uses [`ReqwestClient`] for the
    /// `POST /app/installations/<id>/access_tokens` call.
    pub fn new(creds: GhAppCredentials) -> Self {
        Self {
            creds,
            client: Arc::new(
                ReqwestClient::new()
                    .expect("reqwest client construction must not fail in production"),
            ),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Test constructor — accepts an arbitrary [`HttpClient`] so unit
    /// tests can inject [`crate::github_app::MockHttpClient`].
    pub fn with_client(creds: GhAppCredentials, client: Arc<dyn HttpClient>) -> Self {
        Self {
            creds,
            client,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Number of materializations the broker currently tracks. Used by
    /// tests to assert state transitions across `issue`/`revoke` calls.
    pub fn active_count(&self) -> usize {
        self.state.lock().expect("github broker state mutex").len()
    }
}

impl Broker for GitHubBroker {
    fn provider(&self) -> BrokerProvider {
        BrokerProvider::Github
    }

    async fn issue(&self, req: BrokerRequest) -> Result<BrokeredCredential, BrokerError> {
        if req.provider != BrokerProvider::Github {
            return Err(BrokerError::InvalidScope(format!(
                "GitHubBroker received request for {}",
                req.provider.as_str()
            )));
        }

        let scope: GithubScope = serde_json::from_value(req.scope)
            .map_err(|e| BrokerError::InvalidScope(format!("scope deserialize: {e}")))?;

        let token = mint_installation_token_with_client(
            &self.creds,
            &scope.repositories,
            &scope.permissions,
            self.client.as_ref(),
        )
        .await
        .map_err(|e| match e {
            GhAppError::NotConfigured(m) => BrokerError::PolicyRejected(m),
            GhAppError::JwtSigning(m) => BrokerError::Other(format!("jwt signing: {m}")),
            other => BrokerError::Upstream(other.to_string()),
        })?;

        let expires_at = SystemTime::from(token.expires_at);

        // Materialization ID format: `gh-app-<expires_at_unix>-<token_prefix>`.
        // The token prefix is the first 12 chars of the GH installation
        // token (which always starts with `ghs_`); enough to uniquely
        // identify the materialization within a daemon process lifetime
        // without echoing the bearer in logs / receipts. Falls back to a
        // time-only ID if the token is shorter than expected.
        let token_prefix: String = token.token.chars().take(12).collect();
        let materialization_id = format!(
            "gh-app-{}-{}",
            token.expires_at.timestamp(),
            token_prefix,
        );

        self.state
            .lock()
            .expect("github broker state mutex")
            .insert(materialization_id.clone(), expires_at);

        Ok(BrokeredCredential {
            token: SecretString::from(token.token),
            expires_at,
            materialization_id,
        })
    }

    async fn revoke(&self, materialization_id: &str) -> Result<(), BrokerError> {
        // GitHub App installation tokens have no public revoke API. We
        // drop bookkeeping; the credential remains valid until its
        // 1-hour TTL. See module docs.
        let mut st = self.state.lock().expect("github broker state mutex");
        if st.remove(materialization_id).is_none() {
            return Err(BrokerError::UnknownMaterialization(
                materialization_id.to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_app::MockHttpClient;
    use secrecy::ExposeSecret;
    use std::sync::Arc;
    use std::time::Duration;

    // RSA fixture key, copied from github_app.rs tests so this module is
    // self-contained for the construct-runtime + broker-trait paths.
    // Generated with `openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt`.
    // Not a real credential — only used to verify JWT signing.
    const FIXTURE_RSA_PEM: &str = "\x2d----BEGIN PRIVATE KEY-----\n\
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD1K64WSvEo+7zd\n\
        kxJ7BgiSw+lW2KP6u++JuE4iwip73SQc9/OmZK2aHjeBo8+4gAOMyTsUZb01b3Fp\n\
        awm2wORt5fDil72t3EdxZxiCC+nCJmZhRA7KPlTzzWHllVZPb9rjqORnyejIBc5i\n\
        pMGTdd3nxRuait4lbdqwn5D3mCKsH+ziLk9UJ3AZscEUGwb6/mVdzxxmDLWdtHio\n\
        jC4spDa3ABUJIfSbLdW+5F2MsJQQ/CxORVuAP6XHYqK9WB8e/pKIbBWMT+KtKP73\n\
        LzOybKow4P/Louos9DGAGjiqmSUXN91j7S+6hV7LM+AdipaaVK+J9EZxfC+VxcV7\n\
        juP260jRAgMBAAECggEADVMr7LgMmZK6n5V91Ip6tQG8pCs1fyWiuoRci5gSkTvV\n\
        Wbu1Ytt0i5YaPZhtH25zT74KHeAvsE1K+sgSzy6pqG1t/t3xAbEhf7QMowv86Iy7\n\
        IlmXSJeqeO7plxd1CVYF4NS0YUDm8j20JPlZls2gdP3QZvRZzlGSDrWfCxqzwh4F\n\
        pYQIyYxYqzRcIYkAZNYcuJDHYV52jX9nbAu/jZfQP7CqkQHeLbOk5H8bAISzZOVO\n\
        NP720ldXRR2muWs70WE24uAIERFYbQ7c3+HAhkg1+U0Nfc2Q2Ys/JBLL1nVxUXW7\n\
        FqrEkyuPM64ea1xLUq8VgZ2HSbXWVSDyC+ccpXYUdwKBgQD9y/3XTXiqCQ1rOW43\n\
        c88uaEhPl6xIXyYtyVjlhjZTMqYnXdjOTP5IimW390ouCfsbBO7TKWCTdUL8J0wS\n\
        9LXfJ23BKn4L1cQkwz6y1X5W1HRY1nGGLt3VNPLN9MO2eT55MxYfdgRl4XElp71Z\n\
        V+X7gyovKs4Uw/XXhosN5zQtCwKBgQD3TITArOI7jqrAPw5U02zw805FA/JeMn3e\n\
        TH9yRKDqKF5lDqGwgKq2IDv1BZAXJ9IilCbCFoF3CazlvBsuWoWg+v++E6auQVHA\n\
        8aZ16/MZ4I0yPcH6eD9+arXO8E2EX1siK2cMZBbG0M/+9Jb2grFFhD0zUymTzcKe\n\
        4zNym3BzEwKBgQDir1lC/QdRmFRL+Tfgf6gFo08zCB3xZksLilPEbmQHW63ca45C\n\
        dbKJyFOiRVYUWQXX1Egcg1CnZI03+0GPjNMFRopZhkKe/4f57goKYXY+x/RDhQZQ\n\
        +3tX+7sDCiPkz9ZlGqQf5aF3/iy5nWEac9APHdCH4IvBMGZc4udAu8l2kQKBgEYF\n\
        /60DBwgwLH9FG4y/VSCg9C+sn2s2xtc0N/4mGp5TEe9xhi0RMcViOTf2/EbiOqkZ\n\
        5COe9ce8EJ34doXYke/0QogSzmaXDkwg4K6RQgO4xqJMRGnktK3aD2LqPjjWO1rg\n\
        iUxD5wMiy1J49WoVtZZmjGHFEYfNgmc1FDNGej/LAoGAGSmHZlLs1wGSAx4LMtbJ\n\
        E0wjpNL7h2RbLOLDG/zftxny+3bE20PUi+xWQ1dYFvy66etJVxM6Xv/pK1CmaPR0\n\
        NxoLOtrjuytHHZvofQ8oHwvMe8S34U8+/G6NKyNocyfu+CqqUI4xedXJUyerN8p7\n\
        CCLSxCxNhsab6ORMb8ZOf5E=\n\
        -----END PRIVATE KEY-----";

    fn fixture_creds() -> GhAppCredentials {
        GhAppCredentials {
            app_id: "12345".to_string(),
            installation_id: "67890".to_string(),
            private_key_pem: FIXTURE_RSA_PEM.to_string(),
        }
    }

    fn gh_request(scope: serde_json::Value, ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::Github,
            scope,
            ttl: Duration::from_secs(ttl_secs),
            reason: "test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    fn ok_token_body() -> String {
        serde_json::json!({
            "token": "ghs_test_token_xyz_extra_chars_for_prefix",
            "expires_at": "2099-01-01T00:00:00Z",
        })
        .to_string()
    }

    #[test]
    fn provider_returns_github() {
        let broker = GitHubBroker::with_client(
            fixture_creds(),
            Arc::new(MockHttpClient {
                status: 201,
                body: ok_token_body(),
            }),
        );
        assert_eq!(broker.provider(), BrokerProvider::Github);
    }

    #[tokio::test]
    async fn issue_returns_credential_and_records_state() {
        let broker = GitHubBroker::with_client(
            fixture_creds(),
            Arc::new(MockHttpClient {
                status: 201,
                body: ok_token_body(),
            }),
        );
        let req = gh_request(
            serde_json::json!({
                "repositories": ["emberlink-dev"],
                "permissions": [["contents", "write"], ["pull_requests", "write"]],
            }),
            3600,
        );

        let cred = Broker::issue(&broker, req).await.expect("issue must succeed");
        assert!(cred.materialization_id.starts_with("gh-app-"));
        assert!(cred.token.expose_secret().starts_with("ghs_test_token_xyz"));
        assert_eq!(broker.active_count(), 1);
    }

    #[tokio::test]
    async fn issue_with_empty_scope_succeeds() {
        let broker = GitHubBroker::with_client(
            fixture_creds(),
            Arc::new(MockHttpClient {
                status: 201,
                body: ok_token_body(),
            }),
        );
        let req = gh_request(serde_json::json!({}), 3600);
        Broker::issue(&broker, req).await.expect("empty scope must succeed");
    }

    #[tokio::test]
    async fn issue_with_invalid_scope_returns_invalid_scope_error() {
        let broker = GitHubBroker::with_client(
            fixture_creds(),
            Arc::new(MockHttpClient {
                status: 201,
                body: ok_token_body(),
            }),
        );
        let req = gh_request(
            serde_json::json!({"repositories": "not-a-list"}),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::InvalidScope(_)),
            "expected InvalidScope, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_with_wrong_provider_in_request_is_rejected() {
        let broker = GitHubBroker::with_client(
            fixture_creds(),
            Arc::new(MockHttpClient {
                status: 201,
                body: ok_token_body(),
            }),
        );
        let mut req = gh_request(serde_json::json!({}), 3600);
        req.provider = BrokerProvider::Cloudflare;
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn issue_upstream_failure_maps_to_broker_error() {
        let broker = GitHubBroker::with_client(
            fixture_creds(),
            Arc::new(MockHttpClient {
                status: 401,
                body: r#"{"message":"Bad credentials"}"#.to_string(),
            }),
        );
        let req = gh_request(serde_json::json!({}), 3600);
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream, got {err:?}"
        );
    }

    #[tokio::test]
    async fn revoke_drops_state_and_returns_ok() {
        let broker = GitHubBroker::with_client(
            fixture_creds(),
            Arc::new(MockHttpClient {
                status: 201,
                body: ok_token_body(),
            }),
        );
        let cred = Broker::issue(&broker, gh_request(serde_json::json!({}), 3600))
            .await
            .expect("issue");
        assert_eq!(broker.active_count(), 1);
        Broker::revoke(&broker, &cred.materialization_id)
            .await
            .expect("revoke must succeed");
        assert_eq!(broker.active_count(), 0);
    }

    #[tokio::test]
    async fn revoke_unknown_id_returns_unknown_materialization() {
        let broker = GitHubBroker::with_client(
            fixture_creds(),
            Arc::new(MockHttpClient {
                status: 201,
                body: ok_token_body(),
            }),
        );
        let err = Broker::revoke(&broker, "does-not-exist").await.unwrap_err();
        assert!(matches!(err, BrokerError::UnknownMaterialization(_)));
    }

    #[test]
    fn github_scope_round_trips_through_json() {
        let scope = GithubScope {
            repositories: vec!["a".to_string(), "b".to_string()],
            permissions: vec![("contents".to_string(), "write".to_string())],
        };
        let s = serde_json::to_string(&scope).expect("serialize");
        let parsed: GithubScope = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(parsed.repositories, scope.repositories);
        assert_eq!(parsed.permissions, scope.permissions);
    }
}
