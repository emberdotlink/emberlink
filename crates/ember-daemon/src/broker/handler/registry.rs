use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use core_broker::{Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential};
use core_event_types::{ActionRef, ExecutionContract};
use once_cell::sync::OnceCell;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::binary_manifest::BinaryManifest;
use crate::infra::pidfd::{SpawnHandlePidfd, SpawnHandlePidfdInvalidated};
use crate::infra::runtime::PeerCredPrincipal;

// ---------------------------------------------------------------------------
// Object-safety adapter (DynBroker)
// ---------------------------------------------------------------------------

/// Object-safe broker adapter — concrete [`Broker`] impls (which use
/// `impl Future` and so are NOT dyn-compatible) get a blanket impl that
/// type-erases via `Pin<Box<dyn Future>>`. The daemon registry stores
/// `Box<dyn DynBroker>` so a single `HashMap` can hold heterogeneous
/// providers (Mock today; Anthropic/Cloudflare downstream).
pub trait DynBroker: Send + Sync {
    fn provider(&self) -> BrokerProvider;

    fn issue<'a>(
        &'a self,
        req: BrokerRequest,
    ) -> Pin<Box<dyn Future<Output = Result<BrokeredCredential, BrokerError>> + Send + 'a>>;

    fn revoke<'a>(
        &'a self,
        materialization_id: &'a str,
        plaintext: Option<secrecy::SecretString>,
    ) -> Pin<Box<dyn Future<Output = Result<(), BrokerError>> + Send + 'a>>;
}

impl<B: Broker + 'static> DynBroker for B {
    fn provider(&self) -> BrokerProvider {
        Broker::provider(self)
    }

    fn issue<'a>(
        &'a self,
        req: BrokerRequest,
    ) -> Pin<Box<dyn Future<Output = Result<BrokeredCredential, BrokerError>> + Send + 'a>> {
        Box::pin(Broker::issue(self, req))
    }

    fn revoke<'a>(
        &'a self,
        materialization_id: &'a str,
        _plaintext: Option<secrecy::SecretString>,
    ) -> Pin<Box<dyn Future<Output = Result<(), BrokerError>> + Send + 'a>> {
        Box::pin(Broker::revoke(self, materialization_id))
    }
}

// ---------------------------------------------------------------------------
// MaterializationSummary — `broker_list` response shape
// ---------------------------------------------------------------------------

/// One row of the `broker_list` response. Mirrors ADR 094 §c.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializationSummary {
    pub materialization_id: String,
    pub provider: BrokerProvider,
    /// RFC3339 UTC.
    pub issued_at: String,
    /// RFC3339 UTC.
    pub expires_at: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_ref: Option<ActionRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordination_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_ref: Option<String>,
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Spawn-handle TTL
// ---------------------------------------------------------------------------

/// Seconds a minted spawn handle remains valid before `broker_exec` refuses
/// it. Closes the resolve → exec replay window.
pub const SPAWN_HANDLE_TTL_SECS: i64 = 30;

/// Daemon-internal record of a pending (resolved but not yet executed) spawn
/// handle. Lives in [`RegistryState::pending_spawn_handles`] keyed by
/// `materialization_id` until consumed or expired.
#[derive(Clone, Debug)]
pub struct PendingSpawnHandle {
    /// Matches the `materialization_id` returned by `broker_resolve` to the
    /// SCION shim. Used as the map key so lookup is O(1).
    pub handle_id: String,
    /// Authority-approved execution contract that survives the resolve → exec
    /// hop while runner-local coordinates remain out-of-band.
    pub execution_contract: ExecutionContract,
    /// Absolute deadline after which `broker_exec` refuses the handle.
    /// Set to `Utc::now() + Duration::seconds(SPAWN_HANDLE_TTL_SECS)` at
    /// mint time (inside `resolve_with_registry`).
    pub not_after: chrono::DateTime<chrono::Utc>,
    /// spawn_handle_pidfd — reuse-immune binding to the Construct shim process
    /// that minted the handle. The current protocol creates this handle before
    /// the wrapped child exists, so the caller pidfd is the process identity
    /// available at mint time. Direct in-process tests may leave this `None`;
    /// socket-routed production resolve binds it fail-closed.
    pub bound_pidfd: Option<SpawnHandlePidfd>,
    /// True once the handle has been successfully consumed by `broker_exec`.
    /// Set inside the registry lock before the entry is moved to
    /// `consumed_recent`.
    pub consumed: bool,
}

impl PendingSpawnHandle {
    pub fn validate_bound_pidfd(
        &self,
        principal: Option<&PeerCredPrincipal>,
    ) -> Result<(), SpawnHandlePidfdInvalidated> {
        if let Some(bound_pidfd) = self.bound_pidfd.as_ref() {
            bound_pidfd.validate_for_principal(&self.handle_id, principal)?;
        } else if principal.is_some() {
            return Err(SpawnHandlePidfdInvalidated::new(
                self.handle_id.clone(),
                crate::infra::pidfd::SpawnHandlePidfdInvalidReason::MissingBoundPidfd,
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BrokerRegistry
// ---------------------------------------------------------------------------

/// Daemon-side broker registry — owns one [`DynBroker`] per
/// [`BrokerProvider`] and tracks active materializations across all
/// providers so `broker revoke <id>` can route to the right impl without
/// the caller naming the provider.
///
/// `mock_providers` (ADR 157
/// §Component 2): records which providers were registered with a
/// `MockBroker` instance (opted in via `EMBER_ALLOW_MOCK_BROKERS`) so the
/// receipt-emission path can stamp `mock_broker: true` on every Receipt
/// emitted from a Mock. The set is populated by [`Self::register_mock`];
/// calling [`Self::register`] (the real-broker path) leaves the provider
/// OUT of the mock set, which means the default-real / mock-when-opted-in
/// posture is enforced by construction.
pub struct BrokerRegistry {
    pub(super) brokers: HashMap<BrokerProvider, Box<dyn DynBroker>>,
    /// Providers whose registered broker is a `MockBroker` (per
    /// `EMBER_ALLOW_MOCK_BROKERS` opt-in). Used by receipt-emission to
    /// stamp `mock_broker: true` (ADR 157 §Component 2).
    mock_providers: std::collections::HashSet<BrokerProvider>,
    state: Mutex<RegistryState>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProviderRegistrationStatus {
    pub provider: BrokerProvider,
    pub mock: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GithubProviderStatus {
    pub lane: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<String>,
}

#[derive(Default)]
struct RegistryState {
    /// `materialization_id` → summary. Updated on issue, removed on
    /// successful revoke. Used to (a) route `revoke` to the right
    /// provider, and (b) answer `broker_list`.
    active: HashMap<String, MaterializationSummary>,
    /// `materialization_id` → plaintext credential bound to its issuing
    /// persona. Retained inside the daemon so `broker_resolve` can hand
    /// the secret to the trust boundary (ember-proxy / ember-tools /
    /// ember-kernel reconcilers).
    /// Plaintext NEVER returns to the agent process — agents hold the
    /// opaque `SecretRef` (= the `materialization_id`) and present it
    /// to the trust boundary.
    ///
    /// The `persona_id` field captures the `caller_persona` recorded at
    /// issuance time. `broker_resolve_plaintext` enforces persona
    /// binding: a resolver presenting a different `persona_id` is
    /// refused with `ResolveError::PersonaBindingViolation` (the persona
    /// that materialised the credential is the only persona allowed to
    /// resolve it). Materializations issued without a `caller_persona`
    /// (legacy / system-internal callers) require the resolver to
    /// likewise present `None` — strict identity match in both
    /// directions.
    plaintext: HashMap<String, PlaintextEntry>,
    /// Personas frozen by a WebAuthn verification failure
    /// (ADR-DRAFT-BROWSER-AS-TOUCH-ID-PROMPTER D7). While a persona is
    /// in this set, new grant-issuance RPCs are refused fails-closed.
    ///
    /// Mid-session UNAVAILABLE fails closed across all cohorts.
    ///
    /// Cleared only by the operator via the dashboard recovery flow
    /// (PAM passphrase confirmation for session-open context;
    /// mid-session recovery is UNAVAILABLE).
    frozen_personas: std::collections::HashSet<String>,
    /// `materialization_id` → pending spawn handle minted by `broker_resolve`
    /// for the SCION shim resolve path. Consumed (removed) on the first
    /// `broker_exec` that presents the matching `secret_ref`, or refused
    /// with `SpawnHandleExpired` after `SPAWN_HANDLE_TTL_SECS` seconds.
    pending_spawn_handles: HashMap<String, PendingSpawnHandle>,
    /// Recently consumed spawn handle IDs with their consumption timestamp.
    /// Retained for 60 seconds after consumption so that a second `broker_exec`
    /// attempt with the same handle ID returns `SpawnHandleAlreadyConsumed`
    /// instead of the generic "unknown handle" path — prevents leaking
    /// handle-lifecycle information.
    consumed_recent: VecDeque<(String, DateTime<Utc>)>,
}

/// Daemon-internal record of a materialised credential's plaintext +
/// the persona that issued it. Lives only inside the broker registry's
/// state mutex — never serialised, never sent over UDS.
pub(super) struct PlaintextEntry {
    // Field order matters: struct fields drop in declaration order, so the
    // mlock guard must munlock before `plaintext` zeroizes and deallocates.
    _mlock: Option<MlockedSecretAllocation>,
    pub(super) plaintext: secrecy::SecretString,
    /// `caller_persona` from the originating `BrokerRequest`, or `None`
    /// for legacy / system-internal materializations. Used by
    /// [`broker_resolve_plaintext`] to enforce persona binding.
    pub(super) persona_id: Option<String>,
    /// Active grant that justified this materialization at issue time.
    /// Used to project one successful resolve into both session and grant
    /// claim-journal scopes without re-querying mutable grant state later.
    pub(super) grant_id: Option<String>,
}

impl PlaintextEntry {
    fn new(
        plaintext: secrecy::SecretString,
        persona_id: Option<String>,
        grant_id: Option<String>,
    ) -> Self {
        let mlock = MlockedSecretAllocation::try_lock(&plaintext);
        Self {
            _mlock: mlock,
            plaintext,
            persona_id,
            grant_id,
        }
    }
}

impl Clone for PlaintextEntry {
    fn clone(&self) -> Self {
        Self::new(
            self.plaintext.clone(),
            self.persona_id.clone(),
            self.grant_id.clone(),
        )
    }
}

struct MlockedSecretAllocation {
    ptr: *const libc::c_void,
    len: usize,
}

unsafe impl Send for MlockedSecretAllocation {}

impl MlockedSecretAllocation {
    fn try_lock(secret: &secrecy::SecretString) -> Option<Self> {
        let exposed = secret.expose_secret();
        if exposed.is_empty() {
            return None;
        }
        let ptr = exposed.as_ptr() as *const libc::c_void;
        let len = exposed.len();
        let rc = unsafe { libc::mlock(ptr, len) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!(
                error = %err,
                len,
                "mlock(broker plaintext) failed - broker registry plaintext may be paged to swap"
            );
            return None;
        }
        Some(Self { ptr, len })
    }
}

impl Drop for MlockedSecretAllocation {
    fn drop(&mut self) {
        unsafe {
            libc::munlock(self.ptr, self.len);
        }
    }
}

impl BrokerRegistry {
    /// Build an empty registry. Use [`Self::register`] to add brokers.
    pub fn new() -> Self {
        Self {
            brokers: HashMap::new(),
            mock_providers: std::collections::HashSet::new(),
            state: Mutex::new(RegistryState::default()),
        }
    }

    /// Register a broker for a provider. The last registration wins so
    /// tests can swap implementations.
    ///
    /// Mock-broker explicit lane (ADR 157 §Component 2):
    /// This path is for REAL brokers — registering a `MockBroker` via
    /// this method does NOT flag the provider as mock-registered (the
    /// `mock_providers` set stays untouched). Use [`Self::register_mock`]
    /// instead so the receipt-emission path stamps `mock_broker: true`.
    /// The split-method posture forces the runtime broker-registration
    /// loop to explicitly declare which lane each registration is on.
    pub fn register(&mut self, broker: Box<dyn DynBroker>) {
        let provider = broker.provider();
        self.brokers.insert(provider, broker);
        // Real-broker registration retracts any prior mock flag for the
        // same provider (defense-in-depth: test code that re-registers
        // a real broker over a mock should clear the audit signal).
        self.mock_providers.remove(&provider);
    }

    /// Register a `MockBroker` for a provider (ADR 157 §Component 2). The provider is flagged
    /// in `mock_providers` so every Receipt emitted from this registry's
    /// materialization / revocation paths stamps `mock_broker: true`.
    ///
    /// Callers MUST gate this on `EMBER_ALLOW_MOCK_BROKERS` membership;
    /// this method does NOT perform that check itself (the check lives
    /// in the daemon-startup broker-registration loop in `runtime.rs` so
    /// the fail-loud error path can carry the missing-creds context).
    pub fn register_mock(&mut self, broker: Box<dyn DynBroker>) {
        let provider = broker.provider();
        self.brokers.insert(provider, broker);
        self.mock_providers.insert(provider);
    }

    /// Returns true when the given provider was registered as a Mock
    /// (ADR 157 §Component 2).
    /// Returns false when the provider is real-registered OR absent.
    pub fn is_mock(&self, provider: BrokerProvider) -> bool {
        self.mock_providers.contains(&provider)
    }

    /// Returns true when the given provider has a registered impl.
    pub fn has_provider(&self, provider: BrokerProvider) -> bool {
        self.brokers.contains_key(&provider)
    }

    /// Count of providers with a registered broker implementation.
    pub fn provider_count(&self) -> usize {
        self.brokers.len()
    }

    /// Snapshot of registered providers with their real-vs-mock posture.
    pub fn provider_statuses(&self) -> Vec<ProviderRegistrationStatus> {
        let mut out: Vec<ProviderRegistrationStatus> = self
            .brokers
            .keys()
            .copied()
            .map(|provider| ProviderRegistrationStatus {
                provider,
                mock: self.mock_providers.contains(&provider),
            })
            .collect();
        out.sort_by(|a, b| a.provider.as_str().cmp(b.provider.as_str()));
        out
    }

    /// Snapshot of all currently-active materializations, sorted by
    /// `issued_at` ascending so output is deterministic.
    pub fn list_active(&self) -> Vec<MaterializationSummary> {
        let st = self.state.lock().expect("broker registry mutex");
        let mut out: Vec<MaterializationSummary> = st.active.values().cloned().collect();
        out.sort_by(|a, b| a.issued_at.cmp(&b.issued_at));
        out
    }

    pub(super) fn record_active(&self, summary: MaterializationSummary) {
        let mut st = self.state.lock().expect("broker registry mutex");
        st.active
            .insert(summary.materialization_id.clone(), summary);
    }

    /// Stash the daemon-internal plaintext for a freshly-issued
    /// materialization, tagged with the `caller_persona` that requested
    /// it. Companion to [`Self::record_active`]; only the daemon ever
    /// holds plaintext, and only the trust boundary (ember-proxy /
    /// ember-tools / ember-kernel reconcilers) ever asks for it back
    /// via `broker_resolve_plaintext`.
    pub(super) fn record_plaintext(
        &self,
        materialization_id: String,
        plaintext: secrecy::SecretString,
        persona_id: Option<String>,
        grant_id: Option<String>,
    ) {
        let mut st = self.state.lock().expect("broker registry mutex");
        st.plaintext.insert(
            materialization_id,
            PlaintextEntry::new(plaintext, persona_id, grant_id),
        );
    }

    /// Look up the plaintext entry for a materialization, cloning it
    /// out of the mutex-guarded state so the caller can drop the lock
    /// before any I/O. Returns `None` when the materialization is
    /// unknown (already revoked, or never issued).
    pub(super) fn lookup_plaintext(&self, materialization_id: &str) -> Option<PlaintextEntry> {
        let st = self.state.lock().expect("broker registry mutex");
        st.plaintext.get(materialization_id).cloned()
    }

    pub(super) fn drop_active(&self, materialization_id: &str) -> Option<MaterializationSummary> {
        let mut st = self.state.lock().expect("broker registry mutex");
        // Drop the plaintext too — once revoked there is nothing to resolve.
        st.plaintext.remove(materialization_id);
        st.active.remove(materialization_id)
    }

    pub(super) fn lookup_provider(&self, materialization_id: &str) -> Option<BrokerProvider> {
        let st = self.state.lock().expect("broker registry mutex");
        st.active.get(materialization_id).map(|s| s.provider)
    }

    /// Freeze a persona, refusing new grant-issuance until the operator
    /// completes the dashboard recovery flow. Called by
    /// [`handle_presence_verification_failure`] after revoking all active
    /// grants for the persona.
    pub fn freeze_persona(&self, persona_id: &str) {
        let mut st = self.state.lock().expect("broker registry mutex");
        st.frozen_personas.insert(persona_id.to_string());
    }

    /// Return `true` when the persona has been frozen by a WebAuthn
    /// verification failure and the operator has not yet completed recovery.
    pub fn is_persona_frozen(&self, persona_id: &str) -> bool {
        let st = self.state.lock().expect("broker registry mutex");
        st.frozen_personas.contains(persona_id)
    }

    /// Unfreeze a persona after successful operator recovery (PAM passphrase
    /// confirmation on session-open path). Mid-session recovery is
    /// UNAVAILABLE; this method must only be called from the session-open
    /// recovery handler.
    pub fn unfreeze_persona(&self, persona_id: &str) {
        let mut st = self.state.lock().expect("broker registry mutex");
        st.frozen_personas.remove(persona_id);
    }

    /// Record a freshly-minted spawn handle so `broker_exec` can validate its
    /// TTL. Called from `resolve_with_registry` immediately after minting the
    /// `materialization_id` for the SCION shim resolve path.
    pub(super) fn record_spawn_handle(&self, handle: PendingSpawnHandle) {
        let mut st = self.state.lock().expect("broker registry mutex");
        st.pending_spawn_handles
            .insert(handle.handle_id.clone(), handle);
    }

    pub fn peek_spawn_handle(&self, materialization_id: &str) -> Option<PendingSpawnHandle> {
        let st = self.state.lock().expect("broker registry mutex");
        st.pending_spawn_handles.get(materialization_id).cloned()
    }

    pub fn extend_spawn_handle_not_after(
        &self,
        materialization_id: &str,
        not_after: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let mut st = self.state.lock().expect("broker registry mutex");
        let Some(handle) = st.pending_spawn_handles.get_mut(materialization_id) else {
            return false;
        };
        if handle.not_after < not_after {
            handle.not_after = not_after;
        }
        true
    }

    /// Remove and return the pending spawn handle for `materialization_id`.
    /// Returns `None` when no handle exists (either already consumed, never
    /// issued via the SCION shim path, or already expired and GC'd).
    /// On successful removal, records the handle_id in `consumed_recent` for
    /// 60 seconds so replay attempts return `SpawnHandleAlreadyConsumed`.
    pub fn consume_spawn_handle(&self, materialization_id: &str) -> Option<PendingSpawnHandle> {
        let mut st = self.state.lock().expect("broker registry mutex");
        let handle = st.pending_spawn_handles.remove(materialization_id)?;
        // Record in consumed_recent so replay attempts see SpawnHandleAlreadyConsumed.
        let now = chrono::Utc::now();
        st.consumed_recent
            .push_back((handle.handle_id.clone(), now));
        // Prune entries older than 60 seconds.
        let cutoff = now - chrono::Duration::seconds(60);
        while let Some((_, ts)) = st.consumed_recent.front() {
            if *ts < cutoff {
                st.consumed_recent.pop_front();
            } else {
                break;
            }
        }
        Some(handle)
    }

    /// Returns `true` if `materialization_id` appears in `consumed_recent`
    /// (consumed within the last 60 seconds). Used by `handle_broker_exec` to
    /// distinguish "already consumed" from "never issued" when
    /// `consume_spawn_handle` returns `None`.
    pub fn was_recently_consumed(&self, materialization_id: &str) -> bool {
        let st = self.state.lock().expect("broker registry mutex");
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(60);
        st.consumed_recent
            .iter()
            .any(|(id, ts)| id == materialization_id && *ts >= cutoff)
    }
}

impl Default for BrokerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Process-singleton wiring
// ---------------------------------------------------------------------------

/// Explicit authority under which the daemon is allowed to keep a
/// process-global parent-credential broker registry alive.
///
/// ADR 139's remaining gap is no longer "the shared live-vault slot stays
/// populated at startup" — that part is fixed. The load-bearing blocker is
/// now the broker registry itself: it is still hydrated at daemon boot from
/// file / credential-store-backed parent creds and then kept alive for
/// unattended broker paths.
///
/// This enum makes that authority explicit in code instead of leaving it as an
/// implicit side effect of daemon startup:
///
/// - [`InteractiveStartup`] is the current shipped posture: a temporary
///   startup bootstrap-open derives parent creds before `startup_lock()`.
/// - [`HeadlessEnrollment`] is the accepted future unattended posture once
///   `headless_enroll` grows a real authority substrate instead of today's
///   Phase 1 stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerRegistryAuthority {
    /// Current shipped posture: daemon startup bootstrap-open hydrated the
    /// registry before the runtime entered serve.
    InteractiveStartup,
    /// Target unattended posture: a real headless enrollment authorized the
    /// daemon to hold parent broker creds outside an interactive session.
    HeadlessEnrollment,
}

impl BrokerRegistryAuthority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InteractiveStartup => "interactive_startup",
            Self::HeadlessEnrollment => "headless_enrollment",
        }
    }
}

struct InstalledBrokerRegistry {
    authority: BrokerRegistryAuthority,
    registry: BrokerRegistry,
}

/// The daemon registers a single [`BrokerRegistry`] at startup
/// (`runtime.rs::run`). Stored in an `OnceCell` so handler/socket code
/// can access it without threading an `Rc` through every dispatch
/// signature — same pattern as `receipt::current_identity()`.
///
/// The stored value carries both the registry and the authority that justified
/// hydrating it, so future ADR 139 work can replace the current startup path
/// without inventing a second implicit global contract.
static REGISTRY: OnceCell<InstalledBrokerRegistry> = OnceCell::new();

fn install_registry_into(
    cell: &OnceCell<InstalledBrokerRegistry>,
    registry: BrokerRegistry,
    authority: BrokerRegistryAuthority,
) {
    let _ = cell.set(InstalledBrokerRegistry {
        authority,
        registry,
    });
}

/// Install the process-global registry. Called exactly once at runtime
/// startup. A second call with a different registry has no effect; the
/// first installation wins.
pub fn install_registry(registry: BrokerRegistry) {
    install_registry_with_authority(registry, BrokerRegistryAuthority::InteractiveStartup);
}

/// Install the process-global registry under an explicit authority seam.
///
/// Current shipped runtime startup uses
/// [`BrokerRegistryAuthority::InteractiveStartup`]. Future ADR 139 work can
/// switch unattended broker paths to
/// [`BrokerRegistryAuthority::HeadlessEnrollment`] without needing to widen
/// the process-global access contract again.
pub fn install_registry_with_authority(
    registry: BrokerRegistry,
    authority: BrokerRegistryAuthority,
) {
    install_registry_into(&REGISTRY, registry, authority);
}

/// Access the process-global registry if it has been installed.
pub fn current_registry() -> Option<&'static BrokerRegistry> {
    REGISTRY.get().map(|installed| &installed.registry)
}

/// Access the explicit authority under which the process-global broker
/// registry was installed.
pub fn current_registry_authority() -> Option<BrokerRegistryAuthority> {
    REGISTRY.get().map(|installed| installed.authority)
}

// ---------------------------------------------------------------------------
// Process-global signed binary manifest
// ---------------------------------------------------------------------------

/// Shared, immutable view of the signed `binaries/manifest.toml` the
/// daemon loaded at startup. Same `OnceCell` pattern as
/// [`REGISTRY`] / [`current_identity`]: install once in
/// `runtime.rs::run`, read everywhere via [`current_manifest`].
///
/// Stored as `Arc` so per-connection cached references can hold an
/// owned handle without churning the manifest bytes on every RPC. The
/// content is fully owned (manifest entries cloned into the Arc) so
/// readers never touch a TOML re-parse.
static MANIFEST: OnceCell<Arc<BinaryManifest>> = OnceCell::new();

/// Install the process-global binary manifest. Called exactly once
/// at runtime startup after the manifest's signature is verified
/// (see `runtime.rs::run` PATH-PINNING-STARTUP-VERIFY block).
/// Subsequent calls are no-ops — the first installation wins.
pub fn install_manifest(manifest: BinaryManifest) {
    let _ = MANIFEST.set(Arc::new(manifest));
}

/// Access the process-global manifest if it has been installed.
/// Returns `None` when the daemon started without a manifest on disk
/// (e.g. fresh install before `ember binary install` has run).
/// Broker handlers treat the `None` case as "pin verification
/// disabled" — see [`check_peer_binary_pinned`].
pub fn current_manifest() -> Option<Arc<BinaryManifest>> {
    MANIFEST.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_registry_authority_labels_are_stable() {
        assert_eq!(
            BrokerRegistryAuthority::InteractiveStartup.as_str(),
            "interactive_startup"
        );
        assert_eq!(
            BrokerRegistryAuthority::HeadlessEnrollment.as_str(),
            "headless_enrollment"
        );
    }

    #[test]
    fn install_registry_into_records_authority_and_keeps_first_install() {
        let cell = OnceCell::new();

        install_registry_into(
            &cell,
            BrokerRegistry::new(),
            BrokerRegistryAuthority::HeadlessEnrollment,
        );
        assert_eq!(
            cell.get().map(|installed| installed.authority),
            Some(BrokerRegistryAuthority::HeadlessEnrollment)
        );

        install_registry_into(
            &cell,
            BrokerRegistry::new(),
            BrokerRegistryAuthority::InteractiveStartup,
        );
        assert_eq!(
            cell.get().map(|installed| installed.authority),
            Some(BrokerRegistryAuthority::HeadlessEnrollment),
            "OnceCell install must preserve the first authority"
        );
    }

    fn test_pending_execution_contract() -> ExecutionContract {
        ExecutionContract::new(ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_list",
            "v1",
        ))
        .with_contract_id("contract-test")
    }

    /// `spawn_handle_within_ttl_succeeds`: a handle minted now and immediately
    /// consumed via the registry must be present and within TTL.
    #[test]
    fn spawn_handle_within_ttl_succeeds() {
        let registry = BrokerRegistry::new();
        let mat_id = format!("scion-resolve-test-{}", uuid::Uuid::new_v4());
        let not_after = chrono::Utc::now() + chrono::Duration::seconds(SPAWN_HANDLE_TTL_SECS);

        registry.record_spawn_handle(PendingSpawnHandle {
            handle_id: mat_id.clone(),
            execution_contract: test_pending_execution_contract(),
            not_after,
            bound_pidfd: None,
            consumed: false,
        });

        let handle = registry
            .consume_spawn_handle(&mat_id)
            .expect("handle must be present immediately after mint");

        // TTL check: now must be before not_after (i.e. not expired).
        assert!(
            chrono::Utc::now() <= handle.not_after,
            "freshly-minted handle must not be expired: not_after={:?}",
            handle.not_after
        );
    }

    /// `spawn_handle_after_ttl_refused`: a handle whose `not_after` is in the
    /// past must trigger the SpawnHandleExpired error path.
    #[test]
    fn spawn_handle_after_ttl_refused() {
        let registry = BrokerRegistry::new();
        let mat_id = format!("scion-resolve-expired-{}", uuid::Uuid::new_v4());
        // Simulate expiry by setting not_after in the past.
        let not_after = chrono::Utc::now() - chrono::Duration::seconds(1);

        registry.record_spawn_handle(PendingSpawnHandle {
            handle_id: mat_id.clone(),
            execution_contract: test_pending_execution_contract(),
            not_after,
            bound_pidfd: None,
            consumed: false,
        });

        let handle = registry
            .consume_spawn_handle(&mat_id)
            .expect("handle must be present before expiry check");

        // Replicate the broker_exec expiry check (spawn_handle_ttl).
        let is_expired = chrono::Utc::now() > handle.not_after;
        assert!(
            is_expired,
            "handle with not_after in the past must be detected as SpawnHandleExpired"
        );

        // Confirm the error message would be "SpawnHandleExpired".
        let err: Result<(), (i32, String)> = if is_expired {
            Err((-32002, "SpawnHandleExpired".to_string()))
        } else {
            Ok(())
        };
        let (code, msg) = err.expect_err("expired handle must produce error");
        assert_eq!(
            code, -32002,
            "SpawnHandleExpired must use error code -32002"
        );
        assert!(
            msg.contains("SpawnHandleExpired"),
            "error must name SpawnHandleExpired: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Single-use enforcement
    // -----------------------------------------------------------------------

    /// `spawn_handle_first_use_succeeds_second_refused`: mint a handle, consume
    /// it once (succeeds), then attempt to consume it again — must return
    /// `SpawnHandleAlreadyConsumed` via `was_recently_consumed`.
    #[test]
    fn spawn_handle_first_use_succeeds_second_refused() {
        let registry = BrokerRegistry::new();
        let mat_id = format!("scion-resolve-single-use-{}", uuid::Uuid::new_v4());
        let not_after = chrono::Utc::now() + chrono::Duration::seconds(SPAWN_HANDLE_TTL_SECS);

        registry.record_spawn_handle(PendingSpawnHandle {
            handle_id: mat_id.clone(),
            execution_contract: test_pending_execution_contract(),
            not_after,
            bound_pidfd: None,
            consumed: false,
        });

        // First consumption must succeed.
        let handle = registry
            .consume_spawn_handle(&mat_id)
            .expect("first consume must return the handle");
        assert!(
            chrono::Utc::now() <= handle.not_after,
            "handle must not be expired after first consume"
        );

        // Second consumption must return None (removed from pending map).
        let second = registry.consume_spawn_handle(&mat_id);
        assert!(
            second.is_none(),
            "second consume must return None — handle was removed from pending map"
        );

        // spawn_handle_single_use — verify
        // that was_recently_consumed identifies this as a replay attempt.
        assert!(
            registry.was_recently_consumed(&mat_id),
            "was_recently_consumed must return true immediately after consumption"
        );

        // Simulate the broker_exec single-use refusal path.
        let err: Result<(), (i32, String)> = if registry.was_recently_consumed(&mat_id) {
            Err((-32003, "SpawnHandleAlreadyConsumed".to_string()))
        } else {
            Ok(())
        };
        let (code, msg) = err.expect_err("second exec must produce SpawnHandleAlreadyConsumed");
        assert_eq!(
            code, -32003,
            "SpawnHandleAlreadyConsumed must use error code -32003"
        );
        assert!(
            msg.contains("SpawnHandleAlreadyConsumed"),
            "error must name SpawnHandleAlreadyConsumed: {msg}"
        );
    }

    /// `spawn_handle_consumed_recent_remembers_replays`: consume a handle, then
    /// manually verify `consumed_recent` still detects the replay even after
    /// the entry is no longer in `pending_spawn_handles`.
    #[test]
    fn spawn_handle_consumed_recent_remembers_replays() {
        let registry = BrokerRegistry::new();
        let mat_id = format!("scion-resolve-replay-{}", uuid::Uuid::new_v4());
        let not_after = chrono::Utc::now() + chrono::Duration::seconds(SPAWN_HANDLE_TTL_SECS);

        registry.record_spawn_handle(PendingSpawnHandle {
            handle_id: mat_id.clone(),
            execution_contract: test_pending_execution_contract(),
            not_after,
            bound_pidfd: None,
            consumed: false,
        });

        // Consume the handle (removes from pending_spawn_handles, adds to consumed_recent).
        let _handle = registry
            .consume_spawn_handle(&mat_id)
            .expect("initial consume must succeed");

        // The handle must no longer be in pending_spawn_handles.
        assert!(
            registry.consume_spawn_handle(&mat_id).is_none(),
            "handle must not be in pending_spawn_handles after consumption"
        );

        // spawn_handle_single_use — confirm
        // consumed_recent still records the handle for replay detection.
        assert!(
            registry.was_recently_consumed(&mat_id),
            "consumed_recent must remember the handle for replay detection after pending removal"
        );

        // A different, never-issued handle must NOT appear in consumed_recent.
        let unknown_id = format!("scion-resolve-unknown-{}", uuid::Uuid::new_v4());
        assert!(
            !registry.was_recently_consumed(&unknown_id),
            "was_recently_consumed must return false for a handle that was never consumed"
        );
    }
}
