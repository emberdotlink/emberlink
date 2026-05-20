//! Broker trait, request/response types, and an in-memory `MockBroker`
//! implementation suitable for tests.
//!
//! See design (Emberlink credential broker) §5 and design (Anthropic
//! broker) §6 for the design rationale and the canonical trait shape.
//!
//! Provider-specific scopes (Cloudflare, Anthropic, GitHub, AWS STS, GCP,
//! Tailscale) are represented at the trait boundary as opaque
//! `serde_json::Value` payloads. Each provider implementation deserializes
//! this into its own typed struct (see `implementation-note-10` and
//! sibling tasks). The trait stays provider-agnostic so a single
//! `Box<dyn Broker>` can be stored in the daemon's broker registry.
//!
//! The trait uses native `async fn` (stable in Rust 1.75+, no
//! `async-trait` macro dependency). The crate compiles to
//! `wasm32-unknown-unknown` (workspace CI invariant) and pulls in no
//! runtime — callers (the daemon) own the executor.

#![forbid(unsafe_code)]

// `anthropic` ships the real Anthropic Admin-API broker. ureq does not
// compile to `wasm32-unknown-unknown`, so the module is also gated off
// for that target. Feature-gated per implementation-note-11: the trait
// crate compiles with --no-default-features to trait + types + MockBroker
// only; provider impls require explicit opt-in.
#[cfg(all(not(target_arch = "wasm32"), feature = "anthropic"))]
pub mod anthropic;

#[cfg(all(not(target_arch = "wasm32"), feature = "anthropic"))]
pub use anthropic::AnthropicBroker;

// `cloudflare` ships the Cloudflare API token broker (POST /user/tokens +
// DELETE /user/tokens/:id). Same gate shape as `anthropic`.
#[cfg(all(not(target_arch = "wasm32"), feature = "cloudflare"))]
pub mod cloudflare;

#[cfg(all(not(target_arch = "wasm32"), feature = "cloudflare"))]
pub use cloudflare::CloudflareBroker;

// Opaque `SecretRef` contract — agents hold the opaque id, never the
// plaintext (implementation-note-12). The trust boundary for
// resolving `SecretRef` → plaintext is ember-proxy / ember-tools, which
// emits a per-resolution Receipt.
pub mod secret_ref;
pub use secret_ref::SecretRef;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Identifies which upstream provider the broker is talking to.
///
/// Extensible — additions go behind their own ADR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerProvider {
    Cloudflare,
    Anthropic,
    Github,
    AwsSts,
    AzureCli,
    FlyIo,
    Gcp,
    HashiVault,
    Okta,
    Tailscale,
    Vercel,
}

impl BrokerProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            BrokerProvider::Cloudflare => "cloudflare",
            BrokerProvider::Anthropic => "anthropic",
            BrokerProvider::Github => "github",
            BrokerProvider::AwsSts => "aws_sts",
            BrokerProvider::AzureCli => "azure_cli",
            BrokerProvider::FlyIo => "fly_io",
            BrokerProvider::Gcp => "gcp",
            BrokerProvider::HashiVault => "hashi_vault",
            BrokerProvider::Okta => "okta",
            BrokerProvider::Tailscale => "tailscale",
            BrokerProvider::Vercel => "vercel",
        }
    }
}

/// Provider-specific scope payload.
///
/// At the trait boundary the scope is opaque (`serde_json::Value`).
/// Each provider implementation deserializes this into its own typed
/// struct — e.g., `CloudflareScope { zone, permissions }` for the
/// Cloudflare broker, or `AnthropicScope { tier }` for the Anthropic
/// broker. Keeping the scope opaque here lets the daemon hold a
/// heterogeneous registry of `Box<dyn Broker>` without leaking
/// provider details into the core type.
pub type BrokerScope = serde_json::Value;

/// Materialization request — what a caller asks for.
///
/// Mirrors design §5b. The daemon constructs this from the policy
/// engine + caller identity + a per-stack `scope.toml` declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerRequest {
    pub provider: BrokerProvider,
    pub scope: BrokerScope,
    /// Time-to-live for the materialized credential. The broker may
    /// clamp this downward to a provider-imposed maximum.
    #[serde(with = "duration_as_secs")]
    pub ttl: Duration,
    /// Free-form audit reason — recorded in the Grant Receipt.
    pub reason: String,
    /// Persona on whose behalf this credential is being issued.
    /// None for legacy callers that pre-date the grant-scope gate.
    #[serde(default)]
    pub caller_persona: Option<String>,
    /// SHA-256 hex of the grants file content when issued via
    /// `ember broker issue --grants-file`. Propagated into the BrokerReceipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants_file_rev: Option<String>,
    /// Credential name from the grants file entry that produced this request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants_file_credential_name: Option<String>,
}

/// Successful materialization — what the broker returns.
///
/// `token` is `SecretString` so it cannot be accidentally logged or
/// `Debug`-printed. Callers must call `expose_secret()` explicitly.
#[derive(Debug)]
pub struct BrokeredCredential {
    pub token: SecretString,
    pub expires_at: SystemTime,
    /// Upstream provider's identifier for the materialized credential
    /// (e.g., a Cloudflare API token ID, an Anthropic API key ID).
    /// Used by `revoke()` to actively cancel the credential before
    /// its TTL expires.
    pub materialization_id: String,
}

/// Errors a broker implementation may surface.
///
/// Variants are deliberately coarse — provider-specific failures are
/// flattened into `Upstream` with a free-form message. The daemon
/// maps these into Receipt events without leaking provider details
/// into the core type.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// The scope payload could not be deserialized into the
    /// provider-specific shape.
    #[error("invalid scope: {0}")]
    InvalidScope(String),

    /// The request was syntactically valid but rejected by policy
    /// (e.g., scope exceeded the caller's grant).
    #[error("policy rejected request: {0}")]
    PolicyRejected(String),

    /// Upstream provider returned an error (network / API / quota).
    #[error("upstream error: {0}")]
    Upstream(String),

    /// The materialization ID is unknown to the broker — typically
    /// because it was never issued or has already been revoked.
    #[error("unknown materialization id: {0}")]
    UnknownMaterialization(String),

    /// The operation is not supported by this broker implementation.
    /// Default return value for optional trait methods (e.g.,
    /// `reconcile_usage`) on providers that have no usage API.
    #[error("operation not supported by this broker")]
    NotSupported,

    /// Catch-all for unanticipated failures.
    #[error("broker error: {0}")]
    Other(String),
}

/// Usage metrics returned by [`Broker::reconcile_usage`].
///
/// Token counts mirror the Anthropic Usage & Cost API response fields.
/// The `cost_cents_estimate` is a best-effort approximation computed
/// from public pricing; the authoritative cost figure lives in the
/// upstream billing dashboard.
///
/// Defined unconditionally so the `Broker` trait can reference it on
/// all targets including `wasm32-unknown-unknown`. Only `AnthropicBroker`
/// (a native-only type) produces non-default values; WASM consumers of
/// `core-broker` see the trait shape but calls return `NotSupported`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrokerUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub cache_creation_input_tokens: u64,
    /// Estimated cost in US cents (integer, rounded up). Derived from
    /// public Anthropic pricing at the time of the call; not guaranteed
    /// to match the actual invoice.
    pub cost_cents_estimate: u64,
    pub period_start: std::time::SystemTime,
    pub period_end: std::time::SystemTime,
}

/// Time window for a usage reconciliation query.
///
/// Both bounds are Unix timestamps (seconds since epoch) expressed as
/// `SystemTime` for consistency with `BrokeredCredential::expires_at`.
/// The broker converts them to the ISO-8601 strings the upstream API
/// expects.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct UsagePeriod {
    pub start: std::time::SystemTime,
    pub end: std::time::SystemTime,
}

/// The trait every provider implementation honors.
///
/// Mirrors design §5b verbatim:
/// - `provider()` — identifies the upstream the broker mints against.
/// - `issue()` — synchronously talks to the upstream and returns a
///   short-lived credential.
/// - `revoke()` — cancels a previously-issued credential before TTL
///   expiry. Idempotent in spirit: revoking an already-revoked
///   materialization should not panic, though it may surface
///   `BrokerError::UnknownMaterialization` if the broker has dropped
///   the bookkeeping.
/// - `reconcile_usage()` — optional; queries the upstream provider's
///   usage API for the given materialization and time window. Providers
///   that do not support a usage API return
///   `Err(BrokerError::NotSupported)` from the default impl.
///
/// Uses native async fn in trait (stable since Rust 1.75). This is
/// `Send + Sync` so the daemon can hold a `Box<dyn Broker>` across
/// `.await` points; concrete impls must honor that bound.
pub trait Broker: Send + Sync {
    fn provider(&self) -> BrokerProvider;

    fn issue(
        &self,
        req: BrokerRequest,
    ) -> impl std::future::Future<Output = Result<BrokeredCredential, BrokerError>> + Send;

    fn revoke(
        &self,
        materialization_id: &str,
    ) -> impl std::future::Future<Output = Result<(), BrokerError>> + Send;

    /// Fetch post-task usage for the given materialization over
    /// `period`.  Returns `Err(BrokerError::NotSupported)` by default;
    /// only providers with a usage API (currently: Anthropic) override
    /// this.
    ///
    /// The `materialization_id` is the upstream key/token ID returned
    /// in `BrokeredCredential::materialization_id` at issuance time.
    /// Providers that reuse the same key across multiple tasks
    /// (Anthropic shared-mode tiers) filter by key ID + time window;
    /// attribution is approximate when tasks overlap.
    ///
    /// Gated on `not(target_arch = "wasm32")` in concrete impls —
    /// declared here without the cfg so the trait is uniform across
    /// targets.
    fn reconcile_usage(
        &self,
        _materialization_id: &str,
        _period: UsagePeriod,
    ) -> impl std::future::Future<Output = Result<BrokerUsage, BrokerError>> + Send
    where
        Self: Sized,
    {
        std::future::ready(Err(BrokerError::NotSupported))
    }
}

/// In-memory broker for tests.
///
/// `issue()` returns a deterministic canary credential. The
/// materialization ID is `mock-<n>` where `n` is the number of prior
/// `issue()` calls. `revoke()` records the materialization ID in an
/// internal log and returns `Ok(())` if the ID was previously issued,
/// or `BrokerError::UnknownMaterialization` otherwise.
pub struct MockBroker {
    provider: BrokerProvider,
    state: Mutex<MockState>,
}

struct MockState {
    /// Map of materialization ID to TTL. Pruned on revoke.
    active: HashMap<String, Duration>,
    /// Append-only log of revoke calls.
    revoke_log: Vec<String>,
    /// Issuance counter for deterministic ID generation.
    issue_count: u64,
}

impl MockBroker {
    pub fn new(provider: BrokerProvider) -> Self {
        Self {
            provider,
            state: Mutex::new(MockState {
                active: HashMap::new(),
                revoke_log: Vec::new(),
                issue_count: 0,
            }),
        }
    }

    /// Returns the recorded revoke calls, in call order.
    pub fn revoke_calls(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("mock broker mutex")
            .revoke_log
            .clone()
    }

    /// Number of materializations still active.
    pub fn active_count(&self) -> usize {
        self.state.lock().expect("mock broker mutex").active.len()
    }
}

impl Broker for MockBroker {
    fn provider(&self) -> BrokerProvider {
        self.provider
    }

    async fn issue(&self, req: BrokerRequest) -> Result<BrokeredCredential, BrokerError> {
        if req.provider != self.provider {
            return Err(BrokerError::InvalidScope(format!(
                "mock broker is {} but request asked for {}",
                self.provider.as_str(),
                req.provider.as_str()
            )));
        }
        let mut st = self.state.lock().expect("mock broker mutex");
        st.issue_count += 1;
        let id = format!("mock-{}", st.issue_count);
        st.active.insert(id.clone(), req.ttl);
        Ok(BrokeredCredential {
            token: SecretString::from(format!("canary-token-{}", id)),
            expires_at: SystemTime::now() + req.ttl,
            materialization_id: id,
        })
    }

    async fn revoke(&self, materialization_id: &str) -> Result<(), BrokerError> {
        let mut st = self.state.lock().expect("mock broker mutex");
        st.revoke_log.push(materialization_id.to_string());
        if st.active.remove(materialization_id).is_none() {
            return Err(BrokerError::UnknownMaterialization(
                materialization_id.to_string(),
            ));
        }
        Ok(())
    }
}

/// Serde adapter — `Duration` as integer seconds.
mod duration_as_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn cf_request(ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::Cloudflare,
            scope: serde_json::json!({
                "zone": "emberlink.dev",
                "permissions": ["dns:edit"],
            }),
            ttl: Duration::from_secs(ttl_secs),
            reason: "unit test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    /// Naive blocking executor for the trait's async methods.
    ///
    /// The crate has no tokio dep, but futures returned by the
    /// trait's async fns are guaranteed to be `Send` and produce a
    /// terminal value without yielding (the mock impls are
    /// non-async-IO). This is sufficient for unit tests; production
    /// callers (the daemon) will run them on tokio.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        use std::pin::pin;
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }
        let waker: Waker = Arc::new(NoopWaker).into();
        let mut ctx = Context::from_waker(&waker);
        let mut pinned = pin!(f);
        loop {
            if let Poll::Ready(v) = pinned.as_mut().poll(&mut ctx) {
                return v;
            }
        }
    }

    #[test]
    fn trait_object_safe_via_concrete_use() {
        // Sanity check: MockBroker satisfies the Broker trait
        // (Send + Sync + provider/issue/revoke), and provider() is
        // accessible without entering an async context.
        let mock = MockBroker::new(BrokerProvider::Cloudflare);
        assert_eq!(mock.provider(), BrokerProvider::Cloudflare);
        assert_eq!(BrokerProvider::Cloudflare.as_str(), "cloudflare");
    }

    #[test]
    fn issue_round_trip_returns_canary_with_ttl() {
        let mock = MockBroker::new(BrokerProvider::Cloudflare);
        let cred = block_on(mock.issue(cf_request(900))).expect("issue");
        assert_eq!(cred.materialization_id, "mock-1");
        assert!(cred.token.expose_secret().contains("canary-token-mock-1"));
        let now = SystemTime::now();
        let ttl_lower = now + Duration::from_secs(800);
        assert!(
            cred.expires_at >= ttl_lower,
            "expires_at must reflect the requested TTL"
        );
        assert_eq!(mock.active_count(), 1);
    }

    #[test]
    fn revoke_records_call_and_clears_active() {
        let mock = MockBroker::new(BrokerProvider::Cloudflare);
        let cred = block_on(mock.issue(cf_request(60))).expect("issue");
        assert_eq!(mock.active_count(), 1);
        block_on(mock.revoke(&cred.materialization_id)).expect("revoke");
        assert_eq!(mock.active_count(), 0);
        assert_eq!(mock.revoke_calls(), vec![cred.materialization_id]);
    }

    #[test]
    fn revoke_unknown_id_maps_to_unknown_materialization_error() {
        let mock = MockBroker::new(BrokerProvider::Cloudflare);
        let err = block_on(mock.revoke("does-not-exist")).expect_err("revoke must fail");
        match err {
            BrokerError::UnknownMaterialization(id) => assert_eq!(id, "does-not-exist"),
            other => panic!("expected UnknownMaterialization, got {other:?}"),
        }
        // Even a failed revoke is recorded in the call log so tests
        // can assert call count separately from success.
        assert_eq!(mock.revoke_calls(), vec!["does-not-exist".to_string()]);
    }

    #[test]
    fn provider_mismatch_fails_with_invalid_scope() {
        let mock = MockBroker::new(BrokerProvider::Cloudflare);
        let mut req = cf_request(60);
        req.provider = BrokerProvider::Anthropic;
        let err = block_on(mock.issue(req)).expect_err("issue must fail");
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[test]
    fn broker_request_round_trips_through_json() {
        let req = cf_request(900);
        let s = serde_json::to_string(&req).expect("serialize");
        let parsed: BrokerRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(parsed.provider, BrokerProvider::Cloudflare);
        assert_eq!(parsed.ttl, Duration::from_secs(900));
        assert_eq!(parsed.reason, "unit test");
    }
}
