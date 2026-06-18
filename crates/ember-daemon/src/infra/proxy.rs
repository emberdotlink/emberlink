use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, oneshot, watch};
use zeroize::{Zeroize, Zeroizing};

use async_trait::async_trait;
use core_proxy_forward::r#match::{
    git_echo_owner_repo, is_git_smart_http_path, request_to_action_resource,
};
use core_proxy_forward::{EventError, EventSink, PolicyBackend, ThresholdAxis, ThresholdBand};
use hyper::http;

// P22-S2 — the generic LLM/HTTP forwarding core moved into
// `proxy-forward-runtime`. Re-export every moved item so this module's
// public surface is unchanged for callers (runtime.rs, the examples binary)
// AND so `proxy::tests`' `use super::*;` keeps resolving the moved
// constants/types/functions exactly as before the extraction. The
// daemon-specific code below (ProxyState, DaemonPolicyBackend,
// DaemonEventSink, run_post_flight_meter*, emit_threshold_crossings,
// emit_debounced, hash_credential_name_for_audit, the git-echo lane) stays
// here because it touches DaemonStore / Vault / ProxyState / the sink.
pub use proxy_forward_runtime::forward::*;

use crate::infra::endpoint_gate::AdmissionPolicy;
use crate::infra::events::GrantEvent;
use crate::infra::store::StoreError;
use crate::infra::vault::{VaultError, VaultScope};
use crate::pricing;

fn secret_utf8(
    bytes: Zeroizing<Vec<u8>>,
    context: &str,
) -> Result<Zeroizing<String>, core_proxy_forward::PolicyError> {
    match String::from_utf8(bytes.to_vec()) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(err) => {
            let mut bytes = err.into_bytes();
            bytes.zeroize();
            Err(core_proxy_forward::PolicyError::Vault(format!(
                "{context}: credential is not valid UTF-8"
            )))
        }
    }
}

// P22-S2 — imports the in-tree `proxy::tests` module reaches via `use
// super::*;`. Before the forwarding core moved to `proxy-forward-runtime`,
// `proxy.rs` imported these at module scope and the test glob picked them
// up; the stay-code below no longer references them, so they are gated on
// `#[cfg(test)]` to avoid unused-import warnings in the production build.
#[cfg(test)]
use core_proxy_forward::r#match::{
    effective_scope_uri, extract_host_from_url, host_matches_domain,
};
#[cfg(test)]
use http_body_util::{LengthLimitError, Limited};
#[cfg(test)]
use hyper::body::{Body, Frame, SizeHint};
#[cfg(test)]
use std::pin::Pin;
#[cfg(test)]
use std::sync::atomic::{AtomicU8, AtomicU64};
#[cfg(test)]
use std::task::{Context, Poll};

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("client error: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),
    #[error("http error: {0}")]
    Http(#[from] hyper::http::Error),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("vault error: {0}")]
    Vault(VaultError),
    #[error("vault unavailable")]
    VaultUnavailable,
    #[error("policy backend error: {0}")]
    PolicyBackend(core_proxy_forward::PolicyError),
    /// P22-S2 — bridge for surfacing an error from the moved generic
    /// forwarding core (`proxy_forward_runtime::ForwardError`) as a daemon
    /// `ProxyError`. The current accept loop (`run_forward_accept_loop`) logs
    /// per-connection forward errors itself and does not propagate them, so
    /// this `#[from]` is not exercised yet; it's the conversion the daemon
    /// wrapper will use once it propagates forward-core failures (PR22-S4).
    #[error("forward runtime error: {0}")]
    Forward(#[from] proxy_forward_runtime::ForwardError),
}

impl From<VaultError> for ProxyError {
    fn from(e: VaultError) -> Self {
        ProxyError::Vault(e)
    }
}

// ===== kept from proxy.rs lines 786-1388 =====
pub struct ProxyState {
    pub store: crate::infra::store::DaemonStore,
    pub sessions_dir: Option<std::path::PathBuf>,
    /// Per-credential single-flight locks for daemon-owned OAuth token refresh,
    /// shared by the codex GPT-plan lane (`resolve_chatgpt_plan_auth`) and the
    /// gemini Code Assist lane (`resolve_oauth_bearer`). ChatGPT refresh tokens
    /// ROTATE (single-use), so two concurrent requests must NOT both POST a
    /// refresh with the same token — the second would get `refresh_token_reused`
    /// and brick the credential; Google's don't rotate but the single-flight
    /// still avoids a thundering herd of refreshes. The first caller to find the
    /// access token near-expiry holds the per-credential lock across the refresh
    /// + vault write-back; concurrent callers await it, then re-read the
    /// freshly-refreshed token instead of refreshing again. Keyed by
    /// `credential_name`, so the codex (`openai/…`) and gemini (`google/…`) lanes
    /// never collide. `RefCell<HashMap<..>>` because all proxy work runs on one
    /// `LocalSet` thread (see `DaemonPolicyBackend`'s `unsafe impl Send`).
    pub oauth_refresh_locks:
        RefCell<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    #[cfg(test)]
    pub vault: std::rc::Rc<crate::infra::vault::Vault>,
    /// Audit-log + broadcast sink, installed once during proxy spawn.
    ///
    /// The threshold-debounce set and the
    /// broadcast channel both moved INTO `DaemonEventSink`. `ProxyState`
    /// now holds a `OnceLock` pointer to the sink so the existing
    /// `state.sink_*` shim methods (and `emit_threshold_crossings` /
    /// `emit_debounced`) can reach the sink without re-threading every
    /// helper signature with `&dyn EventSink`. The `OnceLock` is required
    /// because of the circular construction: `DaemonEventSink::new` takes
    /// `Arc<ProxyState>`, but `ProxyState` must own a back-pointer to the
    /// sink. Callers install the sink immediately after construction with
    /// `state.event_sink.set(...)`.
    pub event_sink: OnceLock<Arc<DaemonEventSink>>,
}

impl ProxyState {
    pub fn new(
        store: crate::infra::store::DaemonStore,
        sessions_dir: Option<std::path::PathBuf>,
    ) -> Self {
        let sessions_dir = sessions_dir.or_else(|| {
            store
                .data_dir()
                .map(crate::session_watcher::sessions_dir_from_data)
        });
        Self {
            #[cfg(test)]
            vault: store
                .vault()
                .expect("ProxyState::new tests require a live vault attached to the store"),
            store,
            sessions_dir,
            oauth_refresh_locks: RefCell::new(std::collections::HashMap::new()),
            event_sink: OnceLock::new(),
        }
    }

    fn current_vault(&self) -> Result<std::rc::Rc<crate::infra::vault::Vault>, ProxyError> {
        crate::infra::interactive_unlock::current_live_vault(&self.store)
            .map_err(|_| ProxyError::VaultUnavailable)
    }

    /// Borrow the installed `DaemonEventSink`. Panics if the sink has not
    /// yet been installed — callers must `state.event_sink.set(sink)`
    /// immediately after `ProxyState::new`. The panic message names the
    /// invariant so a regression surfaces a structured failure rather
    /// than a generic `unwrap_or` silently dropping audit writes.
    pub(crate) fn sink(&self) -> &DaemonEventSink {
        self.event_sink
            .get()
            .expect("ProxyState::sink — event_sink must be installed via OnceLock::set immediately after ProxyState::new")
    }

    /// Sync shim around `DaemonEventSink::log_event_sync` so the existing
    /// 8 `state.store.log_event(...)` call sites can route through the
    /// `EventSink` surface without changing their helper signatures.
    pub(crate) fn sink_log_event(
        &self,
        persona_id: Option<&str>,
        event_kind: &str,
        credential_name: Option<&str>,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<(), EventError> {
        self.sink()
            .log_event_sync(persona_id, event_kind, credential_name, outcome, detail)
    }

    /// Sync shim around `DaemonEventSink::broadcast_sync` so
    /// `emit_debounced` can push a `GrantEvent` to subscribers without
    /// touching `state.events_tx` directly (which is now sink-owned).
    pub(crate) fn sink_broadcast(&self, event: GrantEvent) {
        self.sink().broadcast_sync(event);
    }

    /// Sync shim around `DaemonEventSink::record_threshold_crossing_sync`.
    /// Returns `true` if `(grant_id, statement_sid, axis, band)` was newly
    /// inserted, `false` if it had already been recorded.
    ///
    /// Currently unused by the in-place call sites — they reach for the
    /// `try_record_threshold_keys` variant which preserves the precise
    /// `"80"`/`"95"`/`"100"` band sub-labels carried on the wire. Kept
    /// here as the canonical enum-form shim for Slice C's remote backend
    /// (which round-trips `ThresholdAxis` / `ThresholdBand` over the UDS
    /// RPC and would project back to keys on the daemon side).
    #[allow(dead_code)]
    pub(crate) fn sink_record_threshold(
        &self,
        grant_id: &str,
        statement_sid: &str,
        axis: ThresholdAxis,
        band: ThresholdBand,
    ) -> bool {
        self.sink()
            .record_threshold_crossing_sync(grant_id, statement_sid, axis, band)
    }
}

/// Production `PolicyBackend` implementation for the ember daemon.
///
/// Wraps an `Arc<ProxyState>` and implements the five trait methods by
/// delegating to the daemon's `DaemonStore` and resolving the current live
/// vault at point of use.
///
/// All connections run on a single-threaded `LocalSet` (see `run_proxy`),
/// which is why `ProxyState` can hold the daemon's `!Send` store and reach
/// the sink's `RefCell` debounce set through `event_sink`. The
/// `unsafe impl Send + Sync` below acknowledges this invariant and matches
/// the existing `#[allow(clippy::arc_with_non_send_sync)]` usage throughout
/// the proxy infrastructure.
pub struct DaemonPolicyBackend {
    inner: Arc<ProxyState>,
}

impl DaemonPolicyBackend {
    pub fn new(state: Arc<ProxyState>) -> Self {
        Self { inner: state }
    }

    /// Audit a loopback-TCP connection admitted without kernel peer
    /// attestation. The `lane` (the projector's name — `codex`,
    /// `gemini-code-assist`, …) is woven into the event kind so each loopback
    /// lane logs under its own `<lane>-loopback-no-kernel-attestation` kind
    /// rather than every lane masquerading as codex (ADR 215 §2). The codex
    /// lane therefore still emits `codex-loopback-no-kernel-attestation`,
    /// byte-for-byte as before.
    pub(crate) fn log_loopback_no_kernel_attestation(
        &self,
        lane: &str,
        session_id: &str,
        bound_uid: u32,
        admission_policy: &AdmissionPolicy,
    ) -> Result<(), StoreError> {
        self.inner
            .store
            .log_event(
                None,
                &format!("{lane}-loopback-no-kernel-attestation"),
                None,
                "warn",
                Some(&format!(
                    "lane={lane} session={session_id} policy={admission_policy} bound_uid={bound_uid} reason=loopback-tcp-no-kernel-peercred"
                )),
            )
            .map(|_| ())
    }

    fn ensure_live_lease_for_resolved(
        &self,
        resolved: &core_proxy_forward::ResolvedGrant,
        stage: &str,
    ) -> Result<(), core_proxy_forward::PolicyError> {
        if self
            .inner
            .store
            .leases()
            .has_live_lease(&resolved.grant_id, chrono::Utc::now())
        {
            return Ok(());
        }

        if let Err(e) = self.inner.store.log_event(
            Some(&resolved.persona_id),
            "credential.access",
            Some(&resolved.credential_name),
            "denied_no_live_lease",
            Some(&format!("grant_id={} stage={stage}", resolved.grant_id)),
        ) {
            tracing::warn!(
                error = ?e,
                persona_id = %resolved.persona_id,
                credential = %resolved.credential_name,
                stage,
                "log_event failed in proxy live-lease recheck"
            );
        }

        Err(core_proxy_forward::PolicyError::Forbidden(format!(
            "grant_inactive:no_live_lease:{}",
            resolved.grant_id
        )))
    }

    /// Read + parse the codex token blob from the vault (SYNCHRONOUS — holds
    /// the `!Send` `Rc<Vault>` only within this fn, never across an await).
    fn read_codex_token_blob(
        &self,
        credential_name: &str,
    ) -> Result<crate::infra::codex_oauth::CodexTokenBlob, core_proxy_forward::PolicyError> {
        let vault = self
            .inner
            .current_vault()
            .map_err(|e| core_proxy_forward::PolicyError::Vault(e.to_string()))?;
        let bytes = match vault.get(VaultScope::Interactive, &self.inner.store, credential_name) {
            Ok(b) => b,
            Err(VaultError::NotFound) => {
                return Err(core_proxy_forward::PolicyError::NotFound(format!(
                    "credential not found in vault: {credential_name}"
                )));
            }
            Err(e) => return Err(core_proxy_forward::PolicyError::Vault(e.to_string())),
        };
        crate::infra::codex_oauth::parse_token_blob(&bytes).map_err(|e| {
            core_proxy_forward::PolicyError::Vault(format!("codex token blob parse: {e}"))
        })
    }

    /// Persist a (refreshed/rotated) codex token blob back to the vault in-place
    /// (SYNCHRONOUS — same `!Send`-not-across-await discipline as the read).
    fn write_codex_token_blob(
        &self,
        credential_name: &str,
        blob: &crate::infra::codex_oauth::CodexTokenBlob,
    ) -> Result<(), core_proxy_forward::PolicyError> {
        let vault = self
            .inner
            .current_vault()
            .map_err(|e| core_proxy_forward::PolicyError::Vault(e.to_string()))?;
        let bytes = crate::infra::codex_oauth::serialize_token_blob(blob);
        vault
            .replace(
                VaultScope::Interactive,
                &self.inner.store,
                credential_name,
                &bytes,
                None,
            )
            .map(|_| ())
            .map_err(|e| core_proxy_forward::PolicyError::Vault(e.to_string()))
    }

    /// Read + parse the gemini Code Assist `oauth_creds` blob from the vault
    /// (SYNCHRONOUS — holds the `!Send` `Rc<Vault>` only within this fn, never
    /// across an await). Sibling of [`read_codex_token_blob`].
    fn read_gemini_oauth_blob(
        &self,
        credential_name: &str,
    ) -> Result<crate::infra::gemini_oauth::GeminiOAuthBlob, core_proxy_forward::PolicyError> {
        let vault = self
            .inner
            .current_vault()
            .map_err(|e| core_proxy_forward::PolicyError::Vault(e.to_string()))?;
        let bytes = match vault.get(VaultScope::Interactive, &self.inner.store, credential_name) {
            Ok(b) => b,
            Err(VaultError::NotFound) => {
                return Err(core_proxy_forward::PolicyError::NotFound(format!(
                    "credential not found in vault: {credential_name}"
                )));
            }
            Err(e) => return Err(core_proxy_forward::PolicyError::Vault(e.to_string())),
        };
        crate::infra::gemini_oauth::parse_oauth_blob(&bytes).map_err(|e| {
            core_proxy_forward::PolicyError::Vault(format!("gemini oauth blob parse: {e}"))
        })
    }

    /// Persist a (refreshed) gemini `oauth_creds` blob back to the vault in-place
    /// (SYNCHRONOUS — same `!Send`-not-across-await discipline as the read).
    fn write_gemini_oauth_blob(
        &self,
        credential_name: &str,
        blob: &crate::infra::gemini_oauth::GeminiOAuthBlob,
    ) -> Result<(), core_proxy_forward::PolicyError> {
        let vault = self
            .inner
            .current_vault()
            .map_err(|e| core_proxy_forward::PolicyError::Vault(e.to_string()))?;
        let bytes = crate::infra::gemini_oauth::serialize_oauth_blob(blob);
        vault
            .replace(
                VaultScope::Interactive,
                &self.inner.store,
                credential_name,
                &bytes,
                None,
            )
            .map(|_| ())
            .map_err(|e| core_proxy_forward::PolicyError::Vault(e.to_string()))
    }
}

/// `endpoint_gate_egress_default_composed` — ADR 215 slice 3 composition hook
/// for the default agent-egress gating policy.
///
/// The shipped in-process `run_proxy` listener is still the plain host LLM
/// proxy; the future egress-default/`ember-proxy` mTLS listener is not present
/// on `origin/main`. Its bind path should construct this policy from the
/// session's bound `(persona, container)` pair, extract the peer client cert
/// DER after mTLS, and call `evaluate_admission` with
/// `PeerIdentity::cert_san(cert_der)`.
#[allow(dead_code)]
pub(crate) fn egress_default_cert_san_policy(
    persona_id: &str,
    container_id: &str,
) -> AdmissionPolicy {
    AdmissionPolicy::CertSan {
        expected_san: format!("{persona_id}|{container_id}"),
    }
}

/// Build the proxy-injected [`core_proxy_forward::ChatgptPlanAuth`] from a token
/// blob — access token + account id + fedramp flag ONLY. The `refresh_token`
/// is deliberately not carried across this boundary.
fn plan_auth_from_blob(
    blob: &crate::infra::codex_oauth::CodexTokenBlob,
) -> core_proxy_forward::ChatgptPlanAuth {
    core_proxy_forward::ChatgptPlanAuth {
        access_token: Zeroizing::new(blob.access_token.clone()),
        account_id: crate::infra::codex_oauth::account_id(blob),
        is_fedramp: crate::infra::codex_oauth::is_fedramp(blob),
    }
}

fn policy_error_for_post_flight_metering_failure(
    err: &StoreError,
    grant_id: &str,
) -> Option<core_proxy_forward::PolicyError> {
    if let StoreError::InvalidInput(reason) = err
        && (reason.contains("live leased authority") || reason.contains("grant-scoped lease"))
    {
        return Some(core_proxy_forward::PolicyError::Forbidden(format!(
            "grant_inactive:no_live_lease:{grant_id}"
        )));
    }
    None
}

// SAFETY: DaemonPolicyBackend is only ever used on the single-threaded
// LocalSet that `run_proxy` creates. The ProxyState it wraps reaches a
// `DaemonStore` (`rusqlite::Connection`, `!Send`) and a `DaemonEventSink`
// carrying a `RefCell` debounce set; neither is safe to share across
// threads in the general case, but the LocalSet invariant guarantees
// there is no concurrent access. This matches the existing
// `arc_with_non_send_sync` pattern used throughout the proxy infrastructure.
unsafe impl Send for DaemonPolicyBackend {}
unsafe impl Sync for DaemonPolicyBackend {}

#[async_trait]
impl PolicyBackend for DaemonPolicyBackend {
    async fn resolve_attachment_authority(
        &self,
        attachment_id: &str,
        endpoint_token: &str,
    ) -> Result<
        Option<core_proxy_forward::ResolvedAttachmentAuthority>,
        core_proxy_forward::PolicyError,
    > {
        let Some(sessions_dir) = self.inner.sessions_dir.as_deref() else {
            return Ok(None);
        };
        let resolved = crate::infra::attachment::resolve_attachment_authority(
            sessions_dir,
            attachment_id,
            endpoint_token,
        )
        .await
        .map_err(|(code, message)| {
            if code == -32004 {
                core_proxy_forward::PolicyError::NotFound(message)
            } else {
                core_proxy_forward::PolicyError::Forbidden(message)
            }
        })?;
        Ok(Some(core_proxy_forward::ResolvedAttachmentAuthority {
            session_id: resolved.session_id,
            attachment_id: resolved.attachment_id,
            runtime_persona_id: resolved.runtime_persona_id,
            caller_binding_id: resolved.caller_binding_id,
            grant_id: resolved.grant_id,
            state: resolved.state,
            authority_strict: resolved.authority_strict,
        }))
    }

    async fn resolve_attachment_for_session(
        &self,
        session_id: &str,
    ) -> Result<
        Option<core_proxy_forward::ResolvedAttachmentAuthority>,
        core_proxy_forward::PolicyError,
    > {
        // P22-S2 (ADR 197 §2): the per-session UDS was already kernel-attested
        // by the accept-time gate (peercred uid + liveness + launcher pid-tree
        // + binary attestation), so the socket binding is authoritative for
        // *which* session is asking. We read the session's OWN attachment
        // endpoint from our trusted store and resolve via the existing
        // authority resolver using that internally-held token — no
        // caller-supplied bearer is consulted (the bearer is superseded). This
        // preserves every downstream check (active-state, posture) while
        // closing the replayable-token surface.
        let Some(sessions_dir) = self.inner.sessions_dir.as_deref() else {
            return Ok(None);
        };
        let store = core_state::SessionStore::new(sessions_dir.to_path_buf());
        let endpoint = match store.read_attachment_endpoint(session_id) {
            Ok(Some(ep)) => ep,
            Ok(None) => return Ok(None),
            Err(e) => {
                return Err(core_proxy_forward::PolicyError::NotFound(format!(
                    "session attachment endpoint unreadable: {e}"
                )));
            }
        };
        let resolved = crate::infra::attachment::resolve_attachment_authority(
            sessions_dir,
            &endpoint.attachment_id,
            &endpoint.endpoint_token,
        )
        .await
        .map_err(|(code, message)| {
            if code == -32004 {
                core_proxy_forward::PolicyError::NotFound(message)
            } else {
                core_proxy_forward::PolicyError::Forbidden(message)
            }
        })?;
        Ok(Some(core_proxy_forward::ResolvedAttachmentAuthority {
            session_id: resolved.session_id,
            attachment_id: resolved.attachment_id,
            runtime_persona_id: resolved.runtime_persona_id,
            caller_binding_id: resolved.caller_binding_id,
            grant_id: resolved.grant_id,
            state: resolved.state,
            authority_strict: resolved.authority_strict,
        }))
    }

    async fn resolve_session_authority(
        &self,
        session_id: &str,
    ) -> Result<Option<core_proxy_forward::SessionGatewayAuthority>, core_proxy_forward::PolicyError>
    {
        // Codex responses lane (P22-S2 / ADR 197 codex): resolve persona +
        // grant + credential_name entirely from the daemon-minted session id,
        // because codex sends no `X-Ember-*` headers. The session metadata
        // carries the runtime persona + the runtime grant id; the grant row
        // carries the credential_name. This is the same trusted store the
        // header-driven Anthropic lane consults, just keyed by session.
        let Some(sessions_dir) = self.inner.sessions_dir.as_deref() else {
            return Ok(None);
        };
        let session_store = core_state::SessionStore::new(sessions_dir.to_path_buf());
        let meta = match session_store.read(session_id) {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(None),
            Err(e) => {
                return Err(core_proxy_forward::PolicyError::Store(format!(
                    "read session {session_id}: {e}"
                )));
            }
        };
        let grant = match self.inner.store.get_grant(&meta.grant_id) {
            Ok(g) => g,
            Err(StoreError::NotFound) => return Ok(None),
            Err(e) => return Err(core_proxy_forward::PolicyError::Store(e.to_string())),
        };
        Ok(Some(core_proxy_forward::SessionGatewayAuthority {
            session_id: session_id.to_string(),
            persona_id: meta.persona,
            grant_id: grant.id,
            credential_name: grant.credential_name,
        }))
    }

    async fn resolve_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
        resolved_grant_id: Option<&str>,
        effective_uri: &http::Uri,
        method: &str,
    ) -> Result<core_proxy_forward::ResolvedGrant, core_proxy_forward::PolicyError> {
        use core_proxy_forward::PolicyError;

        let grant = if let Some(gid) = resolved_grant_id {
            match self.inner.store.get_grant(gid) {
                Ok(g) => {
                    if g.persona_id != persona_id {
                        return Err(PolicyError::Forbidden(
                            "grant belongs to a different persona".into(),
                        ));
                    }
                    if g.credential_name != credential_name {
                        return Err(PolicyError::Forbidden(
                            "grant credential_name does not match X-Ember-Credential".into(),
                        ));
                    }
                    if g.status != "active" {
                        // ADR 190 §4 / ADR 197 §2: the credential grant has
                        // gone non-active mid-session (`expired`, `revoked`,
                        // `parent_cascade_revoked`, or `exhausted_by_budget`).
                        // A *delegation* expiring would leave the grant
                        // `active` (only the posture detaches), so every
                        // status that reaches here is genuine credential
                        // death — we must NOT inject it. But the caller turns
                        // the parseable `grant_inactive:{status}:{grant_id}`
                        // contract into a posture-aware *recoverable*
                        // response (V030-REVOKE-ERROR-MESSAGE: the trailing
                        // grant_id lets the proxy surface the offending
                        // grant id + the canonical abandon-and-reopen
                        // recovery action — exit the current `claude`/`codex`
                        // process and re-open via `ember claude` / `ember
                        // codex` — instead of a fatal 403, so a live
                        // `ember claude` turn degrades gracefully rather
                        // than bricking. The session-resume path is NOT
                        // recommended: it re-attaches to the existing
                        // session meta and inherits the dead grant.
                        if let Err(e) = self.inner.store.log_event(
                            Some(persona_id),
                            "credential.access",
                            Some(credential_name),
                            "denied_grant_inactive",
                            Some(&format!("status={} grant_id={}", g.status, g.id)),
                        ) {
                            tracing::warn!(
                                error = ?e,
                                persona_id,
                                credential = credential_name,
                                "log_event failed in resolve_grant"
                            );
                        }
                        return Err(PolicyError::Forbidden(format!(
                            "grant_inactive:{}:{}",
                            g.status, g.id
                        )));
                    }
                    if !self
                        .inner
                        .store
                        .leases()
                        .has_live_lease(&g.id, chrono::Utc::now())
                    {
                        // ADR 211 §1/AC-2: an active grant row without a live
                        // grant-scoped lease is an inert identity. Refuse at
                        // the proxy resolver before any upstream traffic or
                        // metering/signing side effect can occur.
                        if let Err(e) = self.inner.store.log_event(
                            Some(persona_id),
                            "credential.access",
                            Some(credential_name),
                            "denied_no_live_lease",
                            Some(&format!("grant_id={}", g.id)),
                        ) {
                            tracing::warn!(
                                error = ?e,
                                persona_id,
                                credential = credential_name,
                                "log_event failed in resolve_grant"
                            );
                        }
                        return Err(PolicyError::Forbidden(format!(
                            "grant_inactive:no_live_lease:{}",
                            g.id
                        )));
                    }
                    g
                }
                Err(StoreError::NotFound) => {
                    return Err(PolicyError::NotFound(
                        "attachment resolved to a non-active grant".into(),
                    ));
                }
                Err(e) => return Err(PolicyError::Store(e.to_string())),
            }
        } else {
            match self.inner.store.evaluate_grant(persona_id, credential_name) {
                Ok(g) => {
                    if !self
                        .inner
                        .store
                        .leases()
                        .has_live_lease(&g.id, chrono::Utc::now())
                    {
                        // ADR 211 §1/AC-2: evaluate_grant proves only the
                        // durable row is active. Authority-to-act additionally
                        // requires the live in-memory grant-scoped lease.
                        if let Err(e) = self.inner.store.log_event(
                            Some(persona_id),
                            "credential.access",
                            Some(credential_name),
                            "denied_no_live_lease",
                            Some(&format!("grant_id={}", g.id)),
                        ) {
                            tracing::warn!(
                                error = ?e,
                                persona_id,
                                credential = credential_name,
                                "log_event failed in resolve_grant"
                            );
                        }
                        return Err(PolicyError::Forbidden(format!(
                            "grant_inactive:no_live_lease:{}",
                            g.id
                        )));
                    }
                    g
                }
                Err(StoreError::NotFound) => {
                    return Err(PolicyError::NotFound(
                        "no active grant for persona/credential".into(),
                    ));
                }
                Err(e) => return Err(PolicyError::Store(e.to_string())),
            }
        };

        let access_grant = self
            .inner
            .store
            .get_access_grant(&grant.id)
            .map_err(|e| PolicyError::Store(e.to_string()))?;

        // BKR-4b (ADR 205 §A.6 step 3): root-authorize + chain-verify the grant
        // on the SAME composed seams the broker mints use (#5708 broker_exec,
        // #5718 broker_issue), so the LLM proxy resolves authority through the
        // one live lookup (Reconciliation Q3: "LLM and broker/tool resolve
        // authority through the same live lookup"). The proxy already runs the
        // §A.4 ancestor-revocation walk (below) + the per-request statement
        // match; this folds in verifier parts (1) root-id and (2)
        // chain-integrity, which the audit found ran at NO use-time grant
        // boundary. Composition order matches `verify_grant_for_use`: (1)+(2)
        // gate BEFORE per-request resolution, so a forged/unrooted grant is
        // refused before any statement-match, vault read, or upstream traffic.
        //
        // (1) The issuing persona's root must be authorized by the apex
        //     device-set (`PersonaRootAuthority`). Today that seam is the
        //     transitional dev0 daemon-stored root (ADR 205 §A.5/§9 honest
        //     limit) — consistent with the chain `get_access_grant` just
        //     verified, so in dev0 the only net-new refusal is an unsigned
        //     legacy-orphan grant whose persona no longer resolves a root. It
        //     becomes load-bearing with NO caller change when ADR 206 steps 1–2
        //     anchor the root in the presence device-set (a persona the set does
        //     not authorize then yields `None` here).
        // (2) The block chain must verify against that root.
        // Fail-closed; oracle-safe (the Forbidden reason names only the failing
        // layer, like the SID/ancestor contracts).
        {
            use crate::trust::use_time_verify::PersonaRootAuthority;
            let Some(root) = self
                .inner
                .store
                .authorized_root_pubkey(&access_grant.issuing_persona_id)
            else {
                if let Err(e) = self.inner.store.log_event(
                    Some(persona_id),
                    "credential.access",
                    Some(credential_name),
                    "denied_root_unauthorized",
                    Some(&format!(
                        "grant_id={} issuer={}",
                        grant.id, access_grant.issuing_persona_id
                    )),
                ) {
                    tracing::warn!(error = ?e, persona_id, credential = credential_name, "log_event failed in resolve_grant");
                }
                return Err(PolicyError::Forbidden("root_unauthorized".into()));
            };
            if core_crypto::grant_chain::verify_chain(&access_grant.blocks, &root).is_err() {
                if let Err(e) = self.inner.store.log_event(
                    Some(persona_id),
                    "credential.access",
                    Some(credential_name),
                    "denied_chain_invalid",
                    Some(&format!("grant_id={}", grant.id)),
                ) {
                    tracing::warn!(error = ?e, persona_id, credential = credential_name, "log_event failed in resolve_grant");
                }
                return Err(PolicyError::Forbidden("chain_invalid".into()));
            }
        }

        let hyper_method = method
            .parse::<hyper::Method>()
            .unwrap_or(hyper::Method::GET);
        let hyper_uri: hyper::Uri =
            effective_uri
                .to_string()
                .parse()
                .map_err(|e: hyper::http::uri::InvalidUri| {
                    PolicyError::Other(format!("invalid URI: {e}"))
                })?;

        let (resolved_sid, resolved_stmt) = if let Some((action, resource)) =
            request_to_action_resource(&hyper_method, &hyper_uri)
        {
            match resolve_statement_for_request_with_uri(
                &access_grant,
                &action,
                &resource,
                &hyper_uri,
            ) {
                ResolveOutcome::NoApplicable => {
                    if let Err(e) = self.inner.store.log_event(
                        Some(persona_id),
                        "credential.access",
                        Some(credential_name),
                        "denied_no_applicable_statement",
                        Some(&format!("action={action} resource={resource}")),
                    ) {
                        tracing::warn!(error = ?e, persona_id, credential = credential_name, "log_event failed in resolve_grant");
                    }
                    return Err(PolicyError::Forbidden("no_applicable_statement".into()));
                }
                ResolveOutcome::SubtargetMiss { subtarget_glob } => {
                    if let Err(e) = self.inner.store.log_event(
                        Some(persona_id),
                        "credential.access",
                        Some(credential_name),
                        "denied_subtarget_scope",
                        Some(&format!(
                            "action={action} resource={resource} subtarget_glob={subtarget_glob}"
                        )),
                    ) {
                        tracing::warn!(error = ?e, persona_id, credential = credential_name, "log_event failed in resolve_grant");
                    }
                    return Err(PolicyError::Forbidden("denied_subtarget_scope".into()));
                }
                ResolveOutcome::UnevaluableCondition { conditions } => {
                    // ADR 207 seam 8B: the only applicable statement(s) carry
                    // conditions the proxy forward path cannot evaluate, so we
                    // fail closed rather than silently authorize past an
                    // unevaluated target clamp (e.g. `UrlPattern`/`Subpath`).
                    if let Err(e) = self.inner.store.log_event(
                        Some(persona_id),
                        "credential.access",
                        Some(credential_name),
                        "denied_unevaluable_condition",
                        Some(&format!(
                            "action={action} resource={resource} conditions={conditions}"
                        )),
                    ) {
                        tracing::warn!(error = ?e, persona_id, credential = credential_name, "log_event failed in resolve_grant");
                    }
                    return Err(PolicyError::Forbidden("unevaluable_condition".into()));
                }
                ResolveOutcome::Match { index: _, stmt } => (stmt.sid.clone(), stmt.clone()),
            }
        } else {
            return Err(PolicyError::Forbidden("unsupported HTTP method".into()));
        };

        let revoked_sids = self
            .inner
            .store
            .get_revoked_sids(&grant.id)
            .map_err(|e| PolicyError::Store(e.to_string()))?;
        if revoked_sids.contains(&resolved_sid) {
            if let Err(e) = self.inner.store.log_event(
                Some(persona_id),
                "credential.access",
                Some(credential_name),
                "denied_statement_revoked",
                Some(&format!("grant_id={} sid={resolved_sid}", grant.id)),
            ) {
                tracing::warn!(error = ?e, grant_id = %grant.id, statement_sid = %resolved_sid, "log_event failed in resolve_grant");
            }
            // Beat 7 (SCION 2026-05-15 demo) — carry the sid through the
            // Forbidden(String) channel so handle_request can render a
            // structured JSON 403 with {persona_id, statement_id}. Format:
            // "statement_revoked:<sid>". Consumer parses out the sid; old
            // generic 403 string ("statement revoked", with space) is gone.
            return Err(PolicyError::Forbidden(format!(
                "statement_revoked:{resolved_sid}"
            )));
        }

        // ADR 205 §A.4 — online grant-ancestry revocation walk. The leaf grant
        // is `active` (checked above) and the matched statement is not
        // SID-revoked, but an ANCESTOR in its `parent_grant_id` lineage may have
        // been revoked without the eager `cascade_revoke_children` write
        // reaching this leaf (crash mid-cascade, a race, or a presented
        // embed-chain the daemon's column never cascaded). Refuse the proxied
        // request if so — the same boundary-agnostic grant-cascade check the
        // construct mint applies (§A.3/§7). Orthogonal to, and stacked on, the
        // per-statement-SID revocation above.
        if let Some(revoked) = self.inner.store.first_revoked_grant_ancestor(&grant.id) {
            if let Err(e) = self.inner.store.log_event(
                Some(persona_id),
                "credential.access",
                Some(credential_name),
                "denied_ancestor_revoked",
                Some(&format!(
                    "grant_id={} ancestor={} reason={}",
                    grant.id, revoked.grant_id, revoked.reason
                )),
            ) {
                tracing::warn!(error = ?e, grant_id = %grant.id, ancestor = %revoked.grant_id, "log_event failed in resolve_grant");
            }
            // A revoked ancestor is genuine authority death (like a revoked
            // leaf grant) — a fatal 403, not a posture-recoverable signal.
            return Err(PolicyError::Forbidden(format!(
                "ancestor_revoked:{}",
                revoked.grant_id
            )));
        }

        Ok(core_proxy_forward::ResolvedGrant {
            grant_id: grant.id.clone(),
            persona_id: grant.persona_id.clone(),
            credential_name: grant.credential_name.clone(),
            statement_sid: resolved_sid,
            statement: resolved_stmt,
            grant_scope: grant.scope.clone(),
            allowed_targets: grant.allowed_targets.clone(),
        })
    }

    async fn preflight_budget(
        &self,
        resolved: &core_proxy_forward::ResolvedGrant,
        body_bytes: &[u8],
    ) -> Result<core_proxy_forward::PreflightDecision, core_proxy_forward::PolicyError> {
        self.ensure_live_lease_for_resolved(resolved, "preflight_budget")?;
        match preflight_budget_check(&resolved.statement, body_bytes) {
            PreflightDecision::Allowed => Ok(core_proxy_forward::PreflightDecision::Allowed),
            PreflightDecision::Rejected { axis, limit, used } => {
                Ok(core_proxy_forward::PreflightDecision::Rejected { axis, limit, used })
            }
        }
    }

    async fn get_credential(
        &self,
        credential_name: &str,
    ) -> Result<zeroize::Zeroizing<String>, core_proxy_forward::PolicyError> {
        let vault = self
            .inner
            .current_vault()
            .map_err(|e| core_proxy_forward::PolicyError::Vault(e.to_string()))?;
        match vault.get(VaultScope::Interactive, &self.inner.store, credential_name) {
            Ok(bytes) => secret_utf8(bytes, "proxy credential"),
            Err(VaultError::NotFound) => Err(core_proxy_forward::PolicyError::NotFound(format!(
                "credential not found in vault: {credential_name}"
            ))),
            Err(e) => Err(core_proxy_forward::PolicyError::Vault(e.to_string())),
        }
    }

    /// Resolve the structured ChatGPT plan auth for the codex GPT-plan lane,
    /// refreshing the short-window access token daemon-side when near expiry.
    ///
    /// AWAIT-SEND DISCIPLINE: the daemon's `!Send` vault/store must never be
    /// held across the refresh `.await` (the `#[async_trait]` future is
    /// `Send`). The synchronous reads/writes are scoped to helper fns
    /// (`read_codex_token_blob` / `write_codex_token_blob`); only owned
    /// `String`s + the `Send` refresh future + the `Send` mutex guard cross the
    /// await. The `refresh_token` never leaves the daemon — only the injected
    /// fields are returned to the proxy.
    async fn resolve_chatgpt_plan_auth(
        &self,
        credential_name: &str,
    ) -> Result<core_proxy_forward::ChatgptPlanAuth, core_proxy_forward::PolicyError> {
        use crate::infra::codex_oauth;

        // 1. Read + parse the stored token blob (sync — no await held).
        let blob = self.read_codex_token_blob(credential_name)?;

        // 2. Fast path: token comfortably valid → inject as-is, no refresh.
        if !codex_oauth::needs_refresh(&blob, chrono::Utc::now()) {
            return Ok(plan_auth_from_blob(&blob));
        }

        // 3. Refresh needed → single-flight on a per-credential lock so two
        //    concurrent requests can't both spend the (rotating) refresh token.
        let lock = {
            let mut locks = self.inner.oauth_refresh_locks.borrow_mut();
            Arc::clone(
                locks
                    .entry(credential_name.to_string())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        let _guard = lock.lock().await;

        // 4. Re-read after acquiring the lock — another task may have just
        //    refreshed + rotated the token while we waited.
        let blob = self.read_codex_token_blob(credential_name)?;
        if !codex_oauth::needs_refresh(&blob, chrono::Utc::now()) {
            return Ok(plan_auth_from_blob(&blob));
        }

        let Some(refresh_token) = blob.refresh_token.clone() else {
            return Err(core_proxy_forward::PolicyError::Forbidden(
                "no_refresh_token".into(),
            ));
        };

        // 5. Refresh against the OAuth endpoint (await — NO vault/store held).
        let outcome = match codex_oauth::refresh_access_token(&refresh_token).await {
            Ok(o) => o,
            Err(codex_oauth::RefreshError::Permanent(reason)) => {
                tracing::warn!(credential_name = %credential_name, reason = %reason, "codex GPT-plan: refresh token unusable — re-auth required");
                return Err(core_proxy_forward::PolicyError::Forbidden(format!(
                    "refresh_{reason}"
                )));
            }
            Err(codex_oauth::RefreshError::Transient(msg)) => {
                tracing::warn!(credential_name = %credential_name, error = %msg, "codex GPT-plan: transient refresh failure");
                // If the token has not HARD-expired yet, fall back to it rather
                // than failing the request on a transient blip.
                if !codex_oauth::is_hard_expired(&blob, chrono::Utc::now()) {
                    return Ok(plan_auth_from_blob(&blob));
                }
                return Err(core_proxy_forward::PolicyError::Other(format!(
                    "refresh failed: {msg}"
                )));
            }
        };

        // 6. Merge rotated tokens + persist back to vault (sync — no await).
        let mut new_blob = blob;
        codex_oauth::apply_refresh(&mut new_blob, outcome);
        self.write_codex_token_blob(credential_name, &new_blob)?;
        tracing::info!(credential_name = %credential_name, "codex GPT-plan: access token refreshed + rotation persisted");

        Ok(plan_auth_from_blob(&new_blob))
    }

    async fn resolve_oauth_bearer(
        &self,
        credential_name: &str,
    ) -> Result<zeroize::Zeroizing<String>, core_proxy_forward::PolicyError> {
        use crate::infra::gemini_oauth;

        // Structurally mirrors `resolve_chatgpt_plan_auth` (shared single-flight
        // discipline + the `!Send`-not-across-await rule), but for the gemini
        // Code Assist OAuth blob; returns ONLY the access token (no account-id).

        // 1. Read + parse the stored token blob (sync — no await held).
        let blob = self.read_gemini_oauth_blob(credential_name)?;

        // 2. Fast path: token comfortably valid → return as-is, no refresh.
        if !gemini_oauth::needs_refresh(&blob, chrono::Utc::now()) {
            return Ok(zeroize::Zeroizing::new(blob.access_token));
        }

        // 3. Refresh needed → single-flight on the shared per-credential lock so
        //    concurrent requests don't stampede the token endpoint.
        let lock = {
            let mut locks = self.inner.oauth_refresh_locks.borrow_mut();
            Arc::clone(
                locks
                    .entry(credential_name.to_string())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        let _guard = lock.lock().await;

        // 4. Re-read after acquiring the lock — another task may have just
        //    refreshed while we waited.
        let blob = self.read_gemini_oauth_blob(credential_name)?;
        if !gemini_oauth::needs_refresh(&blob, chrono::Utc::now()) {
            return Ok(zeroize::Zeroizing::new(blob.access_token));
        }

        let Some(refresh_token) = blob.refresh_token.clone() else {
            return Err(core_proxy_forward::PolicyError::Forbidden(
                "no_refresh_token".into(),
            ));
        };

        // 5. Refresh against Google's token endpoint (await — NO vault/store held).
        let outcome = match gemini_oauth::refresh_access_token(&refresh_token).await {
            Ok(o) => o,
            Err(gemini_oauth::RefreshError::Config(msg)) => {
                tracing::warn!(credential_name = %credential_name, error = %msg, "gemini Code Assist: OAuth client configuration missing");
                return Err(core_proxy_forward::PolicyError::Other(format!(
                    "Gemini OAuth client configuration missing: {msg}"
                )));
            }
            Err(gemini_oauth::RefreshError::Permanent(reason)) => {
                tracing::warn!(credential_name = %credential_name, reason = %reason, "gemini Code Assist: refresh token unusable — re-auth required");
                return Err(core_proxy_forward::PolicyError::Forbidden(format!(
                    "refresh_{reason}"
                )));
            }
            Err(gemini_oauth::RefreshError::Transient(msg)) => {
                tracing::warn!(credential_name = %credential_name, error = %msg, "gemini Code Assist: transient refresh failure");
                // Not hard-expired yet → fall back to the stored token rather
                // than failing the request on a transient blip.
                if !gemini_oauth::is_hard_expired(&blob, chrono::Utc::now()) {
                    return Ok(zeroize::Zeroizing::new(blob.access_token));
                }
                return Err(core_proxy_forward::PolicyError::Other(format!(
                    "refresh failed: {msg}"
                )));
            }
        };

        // 6. Merge refreshed token + persist back to vault (sync — no await).
        let mut new_blob = blob;
        gemini_oauth::apply_refresh(&mut new_blob, outcome, chrono::Utc::now());
        self.write_gemini_oauth_blob(credential_name, &new_blob)?;
        tracing::info!(credential_name = %credential_name, "gemini Code Assist: access token refreshed + persisted");

        Ok(zeroize::Zeroizing::new(new_blob.access_token))
    }

    async fn post_flight(
        &self,
        resolved: &core_proxy_forward::ResolvedGrant,
        usage: Option<core_grant_types::Usage>,
    ) -> Result<(), core_proxy_forward::PolicyError> {
        let Some(delta) = usage else {
            return Ok(());
        };
        let credential_hash = hash_credential_name_for_audit(&resolved.credential_name);
        match self.inner.store.log_event(
            Some(&resolved.persona_id),
            "proxy.meter",
            Some(&credential_hash),
            "complete",
            Some(&format!(
                "grant_id={} sid={} tokens={} cents={}",
                resolved.grant_id, resolved.statement_sid, delta.tokens, delta.cents
            )),
        ) {
            Ok(_) => {}
            Err(e) => tracing::warn!(
                error = ?e,
                grant_id = %resolved.grant_id,
                sid = %resolved.statement_sid,
                "proxy.meter audit log_event failed"
            ),
        }
        match self.inner.store.increment_statement_usage(
            &resolved.grant_id,
            &resolved.statement_sid,
            delta,
        ) {
            Ok(usage_delta) => {
                if let Some(budget) = &resolved.statement.budget {
                    emit_threshold_crossings(
                        &self.inner,
                        &resolved.grant_id,
                        &resolved.statement_sid,
                        &resolved.persona_id,
                        &resolved.credential_name,
                        budget,
                        &usage_delta.prior,
                        &usage_delta.current,
                    );
                }
                let _ = self
                    .inner
                    .store
                    .mark_grant_exhausted_by_budget_if_terminal(&resolved.grant_id);
            }
            Err(e) => {
                tracing::warn!(
                    grant_id = %resolved.grant_id,
                    sid = %resolved.statement_sid,
                    error = ?e,
                    "DaemonPolicyBackend::post_flight: failed to increment statement usage"
                );
                if let Some(policy_error) =
                    policy_error_for_post_flight_metering_failure(&e, &resolved.grant_id)
                {
                    return Err(policy_error);
                }
            }
        }
        Ok(())
    }

    // post_flight_meter is the trait-level entry
    // point for credential-grant metering after the upstream call completes.
    // Distinct from `post_flight` at the trait level so Slice C's remote
    // backend can route the two through different metering paths. The
    // in-process daemon implementation runs the same audit + increment
    // logic — they only diverge when Slice E lifts the proxy out-of-process.
    async fn post_flight_meter(
        &self,
        resolved: &core_proxy_forward::ResolvedGrant,
        usage: Option<core_grant_types::Usage>,
    ) -> Result<(), core_proxy_forward::PolicyError> {
        self.post_flight(resolved, usage).await
    }

    async fn issue_proxy_call_receipt(
        &self,
        resolved: &core_proxy_forward::ResolvedGrant,
        call: &core_proxy_forward::ProxyCallReceiptRequest,
    ) -> Result<Option<String>, core_proxy_forward::PolicyError> {
        let body = core_events::receipt::ProxyCallBody {
            persona_id: resolved.persona_id.clone(),
            grant_id: resolved.grant_id.clone(),
            statement_sid: resolved.statement_sid.clone(),
            method: call.method.clone(),
            path: call.path.clone(),
            status: call.status,
            tokens_in: call.tokens_in,
            tokens_out: call.tokens_out,
            tokens_total: call.tokens_in.saturating_add(call.tokens_out),
            outcome: call.outcome.clone(),
            observed_at: chrono::Utc::now().to_rfc3339(),
        };
        // proxy_call_receipt_id_is_signed: the forwarding runtime receives
        // this canonical ReceiptEnvelope id and never derives a demo hash at
        // the event emit site.
        Ok(crate::infra::receipt::emit_proxy_call_receipt_current(
            &self.inner.store,
            &resolved.grant_id,
            &resolved.persona_id,
            &body,
        ))
    }

    async fn log_event(
        &self,
        persona_id: &str,
        event_kind: &str,
        credential_name: Option<&str>,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<(), core_proxy_forward::PolicyError> {
        self.inner
            .store
            .log_event(
                Some(persona_id),
                event_kind,
                credential_name,
                outcome,
                detail,
            )
            .map(|_| ())
            .map_err(|e| core_proxy_forward::PolicyError::Store(e.to_string()))
    }
}

/// `EventSink` implementation for the ember daemon.
///
/// Wraps the daemon's `ProxyState` so the proxy pipeline can route audit
/// writes + grant-event broadcasts through the trait surface. This is the
/// in-process implementation; Slice C lands the remote variant
/// (`UdsEventSink`) that RPCs to the daemon over a unix socket.
///
/// **Migration status (B-2 — this slice):** the in-place
/// `state.store.log_event` / `state.events_tx.send` /
/// `state.threshold_emitted.insert` call sites now route through this
/// sink via `ProxyState`'s sync shim methods (`sink_log_event`,
/// `sink_broadcast`, `sink_record_threshold`). The fields previously held
/// directly on `ProxyState` (`threshold_emitted`, `events_tx`) live here
/// now; `ProxyState` owns a `OnceLock<Arc<DaemonEventSink>>` so the shim
/// methods can reach the sink without re-threading every helper signature
/// with `&dyn EventSink`.
///
/// SAFETY: like `DaemonPolicyBackend`, `DaemonEventSink` wraps
/// `Arc<ProxyState>`. `ProxyState` carries the daemon's `!Send` SQLite
/// store, and this struct itself owns a `RefCell` debounce set. Neither is
/// safe to share across threads in the general case, but the daemon only
/// ever uses these on a single-threaded `LocalSet`. The `unsafe impl Send +
/// Sync` below acknowledges this invariant and matches the existing pattern
/// on `DaemonPolicyBackend`. If a future refactor moves the proxy off the
/// LocalSet, this invariant has to be re-proved.
pub struct DaemonEventSink {
    inner: Arc<ProxyState>,
    /// Optional broadcast channel to push `budget.warning` /
    /// `budget.exhausted` notifications to connected socket clients (agent
    /// SDKs). `None` in unit tests that only exercise audit-log emission
    /// and in the git-echo proxy spawn, which does not yet broadcast.
    ///
    /// Moved here from `ProxyState` so
    /// the broadcast path is fully owned by the sink.
    events_tx: Option<broadcast::Sender<GrantEvent>>,
    /// In-memory debounce set for threshold-crossing emissions. Entries
    /// are `(grant_id, statement_sid, axis, band)` — adding to this set
    /// before emission guarantees `budget.warning` is never logged twice
    /// for the same threshold. The set resets on daemon restart, which is
    /// acceptable: a restarted daemon re-emitting a warning is a
    /// defensive duplicate, not a missed alert.
    ///
    /// `RefCell` is safe here because proxy connections run on a
    /// `LocalSet` (see `run_proxy`) — the single-threaded runtime gives
    /// non-Sync interior mutability for free without a Mutex. Moved here
    /// from `ProxyState`.
    threshold_emitted: RefCell<HashSet<(String, String, &'static str, &'static str)>>,
}

impl DaemonEventSink {
    pub fn new(state: Arc<ProxyState>, events_tx: Option<broadcast::Sender<GrantEvent>>) -> Self {
        Self {
            inner: state,
            events_tx,
            threshold_emitted: RefCell::new(HashSet::new()),
        }
    }

    /// Sync inherent for audit-log writes — used by `ProxyState::sink_log_event`
    /// and by the async trait impl below. Keeping the implementation sync
    /// (the trait surface is async-by-fiat) avoids `block_on` inside the
    /// LocalSet, which would panic on a current-thread runtime.
    pub(crate) fn log_event_sync(
        &self,
        persona_id: Option<&str>,
        event_kind: &str,
        credential_name: Option<&str>,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<(), EventError> {
        self.inner
            .store
            .log_event(persona_id, event_kind, credential_name, outcome, detail)
            .map(|_| ())
            .map_err(|e| EventError::Log(e.to_string()))
    }

    /// Sync inherent for grant-event broadcast — used by
    /// `ProxyState::sink_broadcast` and by the async trait impl below.
    /// `send` returns Err only when there are no active subscribers —
    /// that's the expected state in unit tests and before any client
    /// connects; ignore the result.
    pub(crate) fn broadcast_sync(&self, event: GrantEvent) {
        if let Some(tx) = self.events_tx.as_ref() {
            let _ = tx.send(event);
        }
    }

    /// Sync inherent for threshold-crossing dedup — used by
    /// `ProxyState::sink_record_threshold` and by the async trait impl
    /// below. Returns `true` if the tuple was newly inserted (i.e. this
    /// is the first crossing for that (grant, sid, axis, band) since the
    /// daemon started), `false` if it had already been recorded.
    pub(crate) fn record_threshold_crossing_sync(
        &self,
        grant_id: &str,
        statement_sid: &str,
        axis: ThresholdAxis,
        band: ThresholdBand,
    ) -> bool {
        let (axis_str, band_str) = threshold_keys(axis, band);
        let key = (
            grant_id.to_string(),
            statement_sid.to_string(),
            axis_str,
            band_str,
        );
        self.threshold_emitted.borrow_mut().insert(key)
    }

    /// Direct insert into the debounce set using already-projected
    /// `(axis, band)` string keys — used by the existing in-place
    /// `emit_debounced` site which builds the keys from its
    /// `&'static str` band/axis arguments rather than the
    /// `ThresholdAxis`/`ThresholdBand` enums.
    ///
    /// Returns `true` on a fresh insert. Bypasses the enum projection so
    /// callers that already have the wire-format keys do not pay the
    /// round-trip cost.
    pub(crate) fn try_record_threshold_keys(
        &self,
        grant_id: &str,
        statement_sid: &str,
        axis: &'static str,
        band: &'static str,
    ) -> bool {
        let key = (grant_id.to_string(), statement_sid.to_string(), axis, band);
        self.threshold_emitted.borrow_mut().insert(key)
    }
}

// ===== kept from proxy.rs lines 1406-1443 =====

// SAFETY: matches the `unsafe impl` pattern on `DaemonPolicyBackend`. The
// inner `ProxyState` is `!Send` because of its SQLite store, and this
// struct itself holds a `RefCell<HashSet>` debounce set, but the daemon
// only ever uses these on a single-threaded `LocalSet`. The trait bound
// `EventSink: Send + Sync + 'static` is satisfied by promise, not by
// structural means; if a future refactor moves `DaemonEventSink` off the
// LocalSet, this invariant has to be re-proved.
unsafe impl Send for DaemonEventSink {}
unsafe impl Sync for DaemonEventSink {}

#[async_trait]
impl EventSink for DaemonEventSink {
    async fn log_event(
        &self,
        persona_id: Option<&str>,
        event_kind: &str,
        credential_name: Option<&str>,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<(), EventError> {
        self.log_event_sync(persona_id, event_kind, credential_name, outcome, detail)
    }

    async fn broadcast(&self, event: GrantEvent) {
        self.broadcast_sync(event);
    }

    async fn record_threshold_crossing(
        &self,
        grant_id: &str,
        statement_sid: &str,
        axis: ThresholdAxis,
        band: ThresholdBand,
    ) -> bool {
        self.record_threshold_crossing_sync(grant_id, statement_sid, axis, band)
    }
}

// ===== kept from proxy.rs lines 1445-1535 =====
/// Run the general LLM/HTTP credential-injection proxy until `shutdown`
/// flips to `true`.
///
/// Mirrors `run_git_echo_proxy`'s contract: when `bind_tx` is `Some`, the
/// bound `SocketAddr` is sent immediately after `TcpListener::bind`
/// completes (on success the actual local addr — important for
/// `127.0.0.1:0` callers reading the assigned port; on failure an
/// `std::io::Error`). Bind success/failure must not depend on whether the
/// receiver is still listening (silent-ignore on dropped rx).
///
/// Added `bind_tx` so the daemon runtime can
/// wait for bind, log the actual URL, and write the `proxy.url` sidecar
/// before entering the main accept loop, matching `run_git_echo_proxy`'s
/// startup discipline.
pub async fn run_proxy(
    config: ProxyConfig,
    state: Arc<ProxyState>,
    shutdown: watch::Receiver<bool>,
    bind_tx: Option<oneshot::Sender<Result<std::net::SocketAddr, std::io::Error>>>,
) -> Result<(), ProxyError> {
    let listener = match TcpListener::bind(config.bind_addr).await {
        Ok(l) => {
            let local_addr = l.local_addr().unwrap_or(config.bind_addr);
            if let Some(tx) = bind_tx {
                let _ = tx.send(Ok(local_addr));
            }
            l
        }
        Err(e) => {
            let annotated =
                crate::infra::socket::annotate_bind_error(e, &config.bind_addr.to_string());
            tracing::warn!(addr = %config.bind_addr, error = %annotated, "llm proxy failed to bind");
            if let Some(tx) = bind_tx {
                let kind = annotated.kind();
                let _ = tx.send(Err(std::io::Error::new(kind, annotated.to_string())));
            }
            return Err(ProxyError::from(annotated));
        }
    };

    // Wrap ProxyState in DaemonPolicyBackend so handle_request receives a
    // PolicyBackend rather than the raw state. DaemonPolicyBackend is
    // !Send (ProxyState carries the daemon store, and reaches the sink's
    // RefCell debounce set via event_sink), but is safe to use on the
    // single-threaded LocalSet inside the moved accept loop below.
    #[allow(clippy::arc_with_non_send_sync)]
    let backend = Arc::new(DaemonPolicyBackend::new(state));

    // P22-S2 — the generic LocalSet + accept loop now lives in
    // `proxy_forward_runtime::run_forward_accept_loop`; the bind + bind-error
    // annotation + DaemonPolicyBackend construction stay here because they
    // touch daemon-specific machinery. The loop body (per-connection
    // `serve_connection` dispatching `handle_request`) is byte-for-byte the
    // same as before the extraction.
    run_forward_accept_loop(listener, backend, shutdown).await;

    Ok(())
}

// ===== kept from proxy.rs lines 2233-2246 =====
/// Short, stable hash of a credential alias for
/// emission into the audit log's `credential` column.
///
/// Returns `credname-<first 16 hex of sha256>` — enough entropy to avoid
/// collisions inside a single persona's credential set, short enough to
/// stay log-readable, and prefixed so a reader can tell at a glance the
/// column holds a derivative and not a raw alias. Raw aliases live in
/// `statement_usage`/grant rows; to join a specific call, hash the raw
/// alias and match prefixes.
fn hash_credential_name_for_audit(credential_name: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(credential_name.as_bytes());
    format!("credname-{}", hex::encode(&digest[..8]))
}

// ===== kept from proxy.rs lines 2339-2591 =====
/// Run the Stream C post-flight meter against the full accumulated upstream
/// response body. Shared between the buffered (`.collect()`) path and the
/// SSE tee path so both produce identical audit + usage state.
///
/// `outcome` tags the audit record `complete` vs `partial` so the Grant
/// Receipt generated downstream can reflect whether the recorded tokens
/// are the full call or a best-effort snapshot after an interruption.
///
/// `upstream_status_is_success` carries the upstream HTTP response's
/// 2xx-ness through to the meter so the `usage.requests` counter only
/// increments on upstream-confirmed responses. See
/// `record_upstream_request`.
///
/// Caller wiring in the
/// proxy streaming path is in flight; this function is the shared meter
/// the buffered + SSE-tee paths will both invoke once that task lands.
#[allow(clippy::too_many_arguments, dead_code)]
fn run_post_flight_meter(
    state: &ProxyState,
    grant_id: &str,
    statement_sid: &str,
    resolved_stmt: &core_grant_types::Statement,
    persona_id: &str,
    credential_name: &str,
    target_host: &str,
    body: &[u8],
    outcome: StreamOutcome,
    upstream_status_is_success: bool,
) {
    tracing::debug!(
        target: "proxy.meter",
        target_host = %target_host,
        grant_id = %grant_id,
        sid = %statement_sid,
        body_len = body.len(),
        outcome = %outcome.audit_tag(),
        upstream_ok = upstream_status_is_success,
        "run_post_flight_meter: entering buffered meter path"
    );
    let Some(mut delta) = meter_response(target_host, body) else {
        tracing::info!(
            target: "proxy.meter.skip",
            reason = "meter-response-none",
            target_host = %target_host,
            grant_id = %grant_id,
            sid = %statement_sid,
            "run_post_flight_meter: meter_response returned None — see preceding skip-reason for branch"
        );
        return;
    };
    // Fold the upstream-confirmed
    // request count into the delta. `meter_response` no longer hardcodes
    // `requests: 1`; this is the single decision point that mints the
    // billable request against the grant. A successful upstream that
    // returned a parseable usage block counts as one request; a 5xx
    // (or any non-2xx) counts as zero, matching what providers
    // themselves bill.
    delta.requests = record_upstream_request(
        target_host,
        upstream_status_is_success,
        true, // we got a parseable usage block, by virtue of being past meter_response
    );
    // Emit a per-call metering audit event so the receipt + `ember audit`
    // can tell a `complete` stream from a `partial` one. The usage row in
    // `statement_usage` is identical for both cases; the audit record is
    // where the distinction lives.
    //
    // The `credential` audit column stores a short
    // hash of the credential alias, not the raw alias. Raw aliases would
    // let anyone with audit-log read access correlate persona ↔ credential
    // across rows, breaking persona isolation. The raw alias still lives
    // in the `statement_usage`/grant rows (single source of truth); a
    // troubleshooter can join `credential_name_hash` against the hash of
    // the raw alias when a specific call needs to be traced.
    //
    // Subprocess-logging discipline (#424 class): never `let _ =
    // log_event(...)` a security event. A silent drop is an invisible
    // audit gap. Surface the error to tracing so the operator at least
    // sees it in the daemon log if the store fails.
    let credential_hash = hash_credential_name_for_audit(credential_name);
    // Audit-log emission routes through the
    // sink shim. The store write itself is identical; only the
    // ownership of the call boundary moves.
    if let Err(e) = state.sink_log_event(
        Some(persona_id),
        "proxy.meter",
        Some(&credential_hash),
        outcome.audit_tag(),
        Some(&format!(
            "grant_id={grant_id} sid={statement_sid} tokens={} cents={}",
            delta.tokens, delta.cents
        )),
    ) {
        tracing::warn!(
            error = ?e,
            grant_id = %grant_id,
            sid = %statement_sid,
            "proxy.meter audit log_event failed"
        );
    }
    match state
        .store
        .increment_statement_usage(grant_id, statement_sid, delta)
    {
        Ok(delta) => {
            if let Some(budget) = &resolved_stmt.budget {
                emit_threshold_crossings(
                    state,
                    grant_id,
                    statement_sid,
                    persona_id,
                    credential_name,
                    budget,
                    &delta.prior,
                    &delta.current,
                );
            }
            // After the increment, check whether the grant is now
            // budget-terminal across all budget-bearing Statements
            // and flip status to `exhausted_by_budget` if so.
            let _ = state
                .store
                .mark_grant_exhausted_by_budget_if_terminal(grant_id);
        }
        Err(e) => {
            tracing::warn!(
                grant_id = %grant_id,
                sid = %statement_sid,
                error = ?e,
                "failed to increment statement usage (metering skipped)"
            );
        }
    }
}

/// Variant of `run_post_flight_meter` that consumes a structured
/// `UsageSummary` produced by the incremental SSE parser.
///
/// C44-TEE-INCR-PARSE: with the streaming parser, `TeeBody` no longer
/// holds the raw response bytes. The meter must work from the parsed
/// summary directly. The non-streaming JSON path still uses the
/// byte-slice `run_post_flight_meter` because its body genuinely is
/// available as a single `Bytes`.
///
/// `upstream_status_is_success` mirrors the buffered path: only a 2xx
/// upstream response should count as one billable request via
/// `record_upstream_request`. SSE responses always start with a 2xx
/// status (Anthropic doesn't open an event stream on 5xx), but plumbing
/// the bit explicitly keeps both paths symmetric and audit-ready.
///
/// Pairs with
/// `run_post_flight_meter` above; the SSE-tee path will call this once
/// caller wiring lands.
#[allow(clippy::too_many_arguments, dead_code)]
fn run_post_flight_meter_from_summary(
    state: &ProxyState,
    grant_id: &str,
    statement_sid: &str,
    resolved_stmt: &core_grant_types::Statement,
    persona_id: &str,
    credential_name: &str,
    target_host: &str,
    summary: &pricing::UsageSummary,
    outcome: StreamOutcome,
    upstream_status_is_success: bool,
) {
    tracing::debug!(
        target: "proxy.meter",
        target_host = %target_host,
        grant_id = %grant_id,
        sid = %statement_sid,
        outcome = %outcome.audit_tag(),
        saw_any_usage = summary.saw_any_usage,
        saw_message_stop = summary.saw_message_stop,
        upstream_ok = upstream_status_is_success,
        "run_post_flight_meter_from_summary: entering streaming meter path"
    );
    let Some(mut delta) = usage_from_summary(target_host, summary) else {
        tracing::info!(
            target: "proxy.meter.skip",
            reason = "usage-from-summary-none",
            target_host = %target_host,
            grant_id = %grant_id,
            sid = %statement_sid,
            saw_any_usage = summary.saw_any_usage,
            "run_post_flight_meter_from_summary: usage_from_summary returned None (no provider match or no usage in stream)"
        );
        return;
    };
    // Same fold as the buffered
    // path. `usage_from_summary` no longer hardcodes `requests: 1`; we
    // mint the billable request here once the upstream's confirmation
    // is known. A partial stream that observed any usage at all still
    // counts as one upstream-confirmed request — Anthropic accepted the
    // request and started responding, the cut-off is downstream of the
    // billable boundary.
    delta.requests = record_upstream_request(
        target_host,
        upstream_status_is_success,
        summary.saw_any_usage,
    );
    // The audit + increment paths below mirror `run_post_flight_meter`
    // verbatim — keep in sync if either evolves.
    let credential_hash = hash_credential_name_for_audit(credential_name);
    // Sink shim — see sibling helper.
    if let Err(e) = state.sink_log_event(
        Some(persona_id),
        "proxy.meter",
        Some(&credential_hash),
        outcome.audit_tag(),
        Some(&format!(
            "grant_id={grant_id} sid={statement_sid} tokens={} cents={}",
            delta.tokens, delta.cents
        )),
    ) {
        tracing::warn!(
            error = ?e,
            grant_id = %grant_id,
            sid = %statement_sid,
            "proxy.meter audit log_event failed"
        );
    }
    match state
        .store
        .increment_statement_usage(grant_id, statement_sid, delta)
    {
        Ok(delta) => {
            if let Some(budget) = &resolved_stmt.budget {
                emit_threshold_crossings(
                    state,
                    grant_id,
                    statement_sid,
                    persona_id,
                    credential_name,
                    budget,
                    &delta.prior,
                    &delta.current,
                );
            }
            let _ = state
                .store
                .mark_grant_exhausted_by_budget_if_terminal(grant_id);
        }
        Err(e) => {
            tracing::warn!(
                grant_id = %grant_id,
                sid = %statement_sid,
                error = ?e,
                "failed to increment statement usage (metering skipped)"
            );
        }
    }
}

// ===== kept from proxy.rs lines 3309-3461 =====
/// Emit threshold-crossing audit events for a metering update.
///
/// Looks at (prior, current, budget) on each axis (tokens, cents) and
/// emits a `budget.warning` at each band (80%, 95%) the update crossed
/// — never twice for the same (grant, sid, axis, band) in the lifetime
/// of the daemon process (debounce set on `ProxyState`). When `current`
/// meets or exceeds `budget`, emits a `budget.exhausted` audit record
/// (debounced the same way, band = `"100"`).
///
/// The caller is responsible for passing the Statement's current
/// resolved `budget` — this function does no read-back.
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_threshold_crossings(
    state: &ProxyState,
    grant_id: &str,
    statement_sid: &str,
    persona_id: &str,
    credential_name: &str,
    budget: &core_grant_types::Budget,
    prior: &core_grant_types::Usage,
    current: &core_grant_types::Usage,
) {
    // Cents axis runs on micro-cents internally
    // so sub-cent calls accumulate honestly. Both the cap and the
    // before/after counters are scaled to micro-cents; the displayed
    // `used`/`limit` in the emitted audit/push payload are stepped back
    // down to whole cents so receipts and dashboards stay human-readable.
    let cents_cap_micro = budget.cents.map(|c| c.saturating_mul(1_000_000));
    let axes: [(&'static str, Option<u64>, u64, u64); 2] = [
        ("tokens", budget.tokens, prior.tokens, current.tokens),
        (
            "cents",
            cents_cap_micro,
            prior.cents_micro,
            current.cents_micro,
        ),
    ];
    for (axis, cap, before, after) in axes.iter() {
        let Some(cap) = cap else { continue };
        if *cap == 0 {
            continue;
        }
        // Display values: cents axis carries micro-cents internally; step
        // back down for the audit payload so receipts and dashboards show
        // human-readable cent counts instead of raw micro-cent integers.
        let display_divisor: u64 = if *axis == "cents" { 1_000_000 } else { 1 };
        let display_used = *after / display_divisor;
        let display_cap = *cap / display_divisor;
        for &(band_label, band_frac) in &[("80", 0.80f64), ("95", 0.95f64)] {
            let threshold = (*cap as f64 * band_frac) as u64;
            if *before < threshold && *after >= threshold {
                emit_debounced(
                    state,
                    grant_id,
                    statement_sid,
                    axis,
                    band_label,
                    persona_id,
                    credential_name,
                    "budget.warning",
                    &format!(
                        "axis={axis} used={display_used} limit={display_cap} percent={band_label}"
                    ),
                    Some(display_used),
                    Some(display_cap),
                );
            }
        }
        if *before < *cap && *after >= *cap {
            emit_debounced(
                state,
                grant_id,
                statement_sid,
                axis,
                "100",
                persona_id,
                credential_name,
                "budget.exhausted",
                &format!("axis={axis} used={display_used} limit={display_cap}"),
                Some(display_used),
                Some(display_cap),
            );
        }
    }
}

/// Write a single threshold crossing to the audit log AND broadcast a
/// structured push notification when a `broadcast::Sender<GrantEvent>` is
/// attached. The in-memory debounce set ensures both paths emit at most
/// once per `(grant_id, statement_sid, axis, band)` for the lifetime of
/// the daemon process — callers are free to re-run the meter without fear
/// of duplicate pushes.
#[allow(clippy::too_many_arguments)]
fn emit_debounced(
    state: &ProxyState,
    grant_id: &str,
    statement_sid: &str,
    axis: &'static str,
    band_label: &'static str,
    persona_id: &str,
    credential_name: &str,
    action: &str,
    details: &str,
    used: Option<u64>,
    budget: Option<u64>,
) {
    // Debounce + audit + broadcast now route
    // through the `DaemonEventSink` reachable via `state.sink()`. The
    // sink owns the threshold-debounce set and the broadcast channel; the
    // sync shim methods on `ProxyState` keep this helper's signature
    // unchanged so callers do not have to thread `&dyn EventSink`.
    if !state
        .sink()
        .try_record_threshold_keys(grant_id, statement_sid, axis, band_label)
    {
        return;
    }
    if let Err(e) = state.sink_log_event(
        Some(persona_id),
        action,
        Some(credential_name),
        band_label,
        Some(details),
    ) {
        tracing::warn!(error = ?e, grant_id, statement_sid, axis, action, "log_event failed");
    }

    // Broadcast the structured event to connected socket clients so MCP/SDK
    // consumers receive `budget.warning`/`budget.exhausted` push
    // notifications in real time. The sink's `broadcast_sync` is a no-op
    // when no `events_tx` was installed (git-echo proxy, unit tests).
    if let (Some(used), Some(budget)) = (used, budget) {
        let event = if action == "budget.exhausted" {
            GrantEvent::BudgetExhausted {
                grant_id: grant_id.to_string(),
                statement_sid: statement_sid.to_string(),
                axis,
                used,
                budget,
            }
        } else {
            GrantEvent::BudgetWarning {
                grant_id: grant_id.to_string(),
                statement_sid: statement_sid.to_string(),
                axis,
                used,
                budget,
                percent: band_label,
            }
        };
        state.sink_broadcast(event);
    }
}

// ===== kept from proxy.rs lines 3787-4403 =====
// ---------------------------------------------------------------------------
// P69L — git smart-HTTP echo proxy
//
// Mechanical forwarding path for `git push` / `git clone` before the
// grant-aware `handle_git_receive_pack` path lands. Isolated from
// `handle_request` — no grant lookup, no vault touch.
//
// Audit trail (P1-AUDIT):
//   `handle_git_echo` emits `credential.access` (tracing::info!) at entry
//   with `action="github.push.<owner/repo>"` and a `request_id`. The
//   `PassthroughBody::Drop` emits `proxy.stream` with the same `request_id`
//   so operators can correlate entry and exit for each streaming push.
//
// Streaming model (P69L.0b):
//   Request body streams as `Incoming` directly to the upstream client —
//   no intermediate buffer. Response body streams back via
//   `ProxyBody::Passthrough(PassthroughBody<Incoming>)`. Pack-objects from
//   large pushes never reside fully in daemon memory.
//
// Concurrency cap (P0-GATE, see `STREAMING_REQUESTS_INFLIGHT`):
//   `handle_git_echo` acquires a `StreamingSlot` before touching upstream.
//   When all `MAX_CONCURRENT_STREAMING` slots are held, the function
//   returns 503 + `Retry-After: 1` immediately without opening an upstream
//   connection. The slot is released on clean EOF, upstream error, or
//   client disconnect via `PassthroughBody`'s RAII field-drop order.
//
// Hop-by-hop header filtering (P0-HOPBYHOP, see `strip_hop_by_hop_headers`):
//   `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`,
//   `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, and any token listed in
//   the upstream `Connection:` header are stripped from the response before
//   forwarding (RFC 7230 §6.1).
//
// RAII drop guard (P1-DROP-GUARD, see `PassthroughBody`):
//   Byte counter increments per data frame. On drop: `outcome=complete` if
//   EOF was observed, `outcome=partial` + `bytes_forwarded` otherwise.
//
// Timeouts (post-#662, see `HEADERS_DEADLINE` + `FRAME_IDLE_DEADLINE`):
//   Lazy-static `Client` with bounded idle pool; `HEADERS_DEADLINE` aborts
//   before upstream headers arrive (returns 504); `FRAME_IDLE_DEADLINE`
//   watchdog fires mid-body and marks the drop guard `outcome=partial`.
//
// Usage (manual):
//   - Caller spawns `run_git_echo_proxy` with a bind addr + ProxyState.
//   - Client git is configured with
//     `url."http://127.0.0.1:PORT/github.com/".insteadOf "https://github.com/"`
//     so push requests arrive as plain HTTP with paths shaped
//     `/github.com/{owner}/{repo}.git/...`.
//   - The proxy reads `x-ember-persona` + `x-ember-credential` headers,
//     resolves an active grant for that persona/credential pair, checks the
//     composite-grant chain permits `github:push` on the target repo, fetches
//     the raw token from the vault, substitutes
//     `Basic base64("x-access-token:{token}")` for recognised git-transport
//     paths, rewrites `Host` to `github.com`, and forwards over HTTPS. The
//     upstream response streams back to the client.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// P69L.0b-P0-TIMEOUTS — tunables for the git-echo upstream client.
// ---------------------------------------------------------------------------
//
// The git-echo path previously built a fresh `hyper_util` legacy Client (+
// HttpsConnector + rustls CryptoProvider wiring) on every request. That meant
// a TLS handshake per push, zero connection reuse, and no bound on the
// per-host idle pool. The constants below govern a single process-wide Client
// lazily initialised on first use.

/// Upper bound on how long an idle upstream TCP connection lingers in the
/// keep-alive pool before being closed. 90s matches a typical HTTPS
/// load-balancer idle timeout; longer and we'd pay reconnect cost on
/// half-closed sockets, shorter and we'd lose reuse during bursty pushes.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Maximum idle upstream sockets kept per `(scheme, host, port)` triple.
/// Bounds the FD footprint of the lazily-cached Client when many hosts are
/// touched (pathological case: a swarm of git origins); 8 is enough to
/// amortise handshakes across concurrent push fan-out without pinning file
/// descriptors indefinitely.
const POOL_MAX_IDLE_PER_HOST: usize = 8;

/// Maximum time we wait to receive response headers from the upstream after
/// dispatching a request. Covers TCP-connect + TLS handshake + request-line
/// transmission + upstream first-byte latency. 30s is aggressive enough to
/// surface dead/slow-loris upstreams long before a client-side git timeout
/// fires, and loose enough that a normal GitHub `git-receive-pack` handshake
/// (~100ms) is nowhere near the ceiling.
const HEADERS_DEADLINE: Duration = Duration::from_secs(30);

/// Maximum time we wait between body data frames once headers have flushed.
/// A well-behaved git/GitHub stream pushes frames continuously; going silent
/// for 30s is indistinguishable from a stalled upstream and abandoning the
/// stream is the correct behaviour. On elapse, `PassthroughBody` aborts with
/// `outcome=partial reason=frame-idle-timeout` so the partial drop-guard log
/// from P69L.0b-P1-DROP-GUARD surfaces the root cause.
const FRAME_IDLE_DEADLINE: Duration = Duration::from_secs(30);

/// Process-wide lazily-initialised upstream client used by the git-echo path.
///
/// Initialised on first `git_echo_client()` call. Uses hyper-rustls with
/// system webpki roots so production pushes to github.com work, but accepts
/// plain HTTP upstreams too (`https_or_http`) so tests can mock without
/// spinning up a TLS certificate. Connection pooling + keep-alive are
/// governed by `POOL_IDLE_TIMEOUT` / `POOL_MAX_IDLE_PER_HOST`.
static GIT_ECHO_CLIENT: OnceLock<
    Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Incoming,
    >,
> = OnceLock::new();

/// Return the process-wide git-echo Client, initialising it on first call.
///
/// Safe to call from any async context; the underlying `OnceLock` handles
/// concurrent racers. The returned reference has `'static` lifetime, so it
/// can be borrowed freely across `.await` points without ownership ceremony.
fn git_echo_client() -> &'static Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Incoming,
> {
    GIT_ECHO_CLIENT.get_or_init(|| {
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        Client::builder(TokioExecutor::new())
            .pool_idle_timeout(POOL_IDLE_TIMEOUT)
            .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
            .build(https)
    })
}

/// URL scheme for the upstream connection used by [`GitEchoConfig`].
///
/// A typed alternative to the stringly-typed `"http"` / `"https"` that
/// previously lived in the config struct. Using the enum prevents typos such
/// as `"htps"` from silently producing a broken target URL at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scheme::Http => f.write_str("http"),
            Scheme::Https => f.write_str("https"),
        }
    }
}

impl std::str::FromStr for Scheme {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "http" => Ok(Scheme::Http),
            "https" => Ok(Scheme::Https),
            other => Err(format!(
                "unknown scheme {:?}; expected \"http\" or \"https\"",
                other
            )),
        }
    }
}

/// Runtime configuration for the grant-aware git smart-HTTP echo proxy.
///
/// `state` carries the vault + grant store used for per-request credential
/// resolution: the proxy reads `x-ember-persona` + `x-ember-credential`
/// headers, resolves an active grant, verifies the composite-grant chain
/// permits `github:push` on the target repo, then fetches the raw token
/// from the vault. The caller never sees the token — Emberlink mediates.
#[derive(Clone)]
pub struct GitEchoConfig {
    pub bind_addr: std::net::SocketAddr,
    /// Upstream host we forward to (always `github.com` in production).
    pub upstream_host: String,
    /// Vault + grant store used for per-request credential resolution.
    /// Carries persona grants and the encrypted credential bytes.
    pub state: Arc<ProxyState>,
    /// URL scheme for the upstream connection. Production callers use
    /// [`Scheme::Https`]; tests can set [`Scheme::Http`] to forward to a
    /// plain-HTTP mock upstream without needing a TLS certificate.
    pub upstream_scheme: Scheme,
}

/// Run the Day-1 echo proxy until `shutdown` flips to `true`.
///
/// This is the mechanical sibling of `run_proxy` — same listener + LocalSet
/// pattern, but dispatches to `handle_git_echo` instead of `handle_request`.
/// Exposed `pub` so a separate test binary or an `#[ignore]`-d integration
/// test can spawn it without reaching into daemon state.
///
/// `bind_tx`: when `Some`, the bound `SocketAddr` is sent
/// exactly once immediately after `TcpListener::bind` succeeds. Bind errors
/// are sent as `Err` and the function returns. The receiver gets the actual
/// local addr (so `127.0.0.1:0` callers can read the assigned port). If the
/// caller has dropped the receiver the send is silently ignored — bind
/// success/failure must not depend on whether anyone is listening for it.
pub async fn run_git_echo_proxy(
    config: GitEchoConfig,
    mut shutdown: watch::Receiver<bool>,
    bind_tx: Option<oneshot::Sender<Result<std::net::SocketAddr, std::io::Error>>>,
) -> Result<(), ProxyError> {
    let listener = match TcpListener::bind(config.bind_addr).await {
        Ok(l) => {
            let local_addr = l.local_addr().unwrap_or(config.bind_addr);
            if let Some(tx) = bind_tx {
                let _ = tx.send(Ok(local_addr));
            }
            l
        }
        Err(e) => {
            // Mirror dashboard's "best effort to surface, then propagate"
            // pattern. We deliver the error to `bind_tx` if present, then
            // return ProxyError so the spawning task records a non-zero exit.
            //
            // P69E.8b: annotate `AddrInUse` failures with `lsof -i :<port>` +
            // daemon-stop hints so operators have an actionable path forward
            // instead of an opaque "Address already in use" log line.
            let annotated =
                crate::infra::socket::annotate_bind_error(e, &config.bind_addr.to_string());
            tracing::warn!(addr = %config.bind_addr, error = %annotated, "git echo proxy failed to bind");
            if let Some(tx) = bind_tx {
                let kind = annotated.kind();
                let _ = tx.send(Err(std::io::Error::new(kind, annotated.to_string())));
            }
            return Err(ProxyError::from(annotated));
        }
    };
    // `GitEchoConfig` embeds `Arc<ProxyState>` which is `!Sync` (RefCell inside).
    // This is intentional: the proxy runs on a `LocalSet` (single-threaded) so
    // `Send + Sync` are not required. The same pattern is used by `run_proxy`.
    #[allow(clippy::arc_with_non_send_sync)]
    let config = Arc::new(config);
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, _addr)) => {
                                let config = Arc::clone(&config);
                                let io = TokioIo::new(stream);
                                tokio::task::spawn_local(async move {
                                    let svc = hyper::service::service_fn(move |req| {
                                        let config = Arc::clone(&config);
                                        async move { handle_git_echo(config, req).await }
                                    });
                                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                                        .serve_connection(io, svc)
                                        .await
                                    {
                                        tracing::warn!(error = %e, "git echo connection error");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "git echo accept error");
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        })
        .await;
    Ok(())
}

/// Per-request handler for the Day-1 echo proxy.
///
/// Accepts the `insteadOf`-rewritten shape `/{upstream_host}/{rest...}` and
/// forwards `/{rest...}` to `https://{upstream_host}/{rest...}` with the
/// client's `Authorization` replaced by a grant-backed Basic-auth header. The
/// caller must supply `x-ember-persona` and `x-ember-credential` headers; the
/// proxy resolves the active grant, verifies the composite-grant chain permits
/// `github:push` on the target repo, fetches the raw token from the vault, and
/// synthesises `Basic base64("x-access-token:{token}")`. If the path does NOT
/// look like a git smart-HTTP request we fail closed with a 400 — the echo is
/// intentionally narrow.
pub async fn handle_git_echo(
    config: Arc<GitEchoConfig>,
    req: Request<Incoming>,
) -> Result<Response<ProxyBody>, ProxyError> {
    // C44-TEE-MEM (P69L.0b-P0-GATE): acquire a streaming slot BEFORE we
    // commit to building the upstream request. The passthrough body
    // holds this slot for the lifetime of the response; once we hit the
    // per-process `MAX_CONCURRENT_STREAMING` cap, fail-closed with 503 +
    // Retry-After so well-behaved clients back off rather than piling
    // up stalled streams that pin unbounded upstream sockets on the
    // daemon. We do this at function entry (not inside `stream_response`)
    // so we spend zero upstream bandwidth when the gate is saturated.
    let Some(streaming_slot) = StreamingSlot::try_acquire() else {
        tracing::warn!(
            inflight = STREAMING_REQUESTS_INFLIGHT.load(Ordering::Acquire),
            cap = MAX_CONCURRENT_STREAMING,
            "git echo: streaming concurrency cap reached — rejecting"
        );
        return Ok(service_unavailable("streaming-saturated"));
    };

    // P69L.0b-P1-AUDIT: mint a per-request correlating id so the
    // `credential.access` entry (below) and the `proxy.stream` entry
    // (from PassthroughBody::Drop) can be joined in the audit log.
    let request_id: Arc<str> = Arc::from(format!("req-{}", uuid::Uuid::new_v4()).as_str());

    // P69L.0c: resolve persona + credential from request headers.
    // Missing either header → 401 (the git client must be configured to
    // forward them; without both we cannot look up the grant).
    let headers = req.headers();
    let persona_id = match headers.get("x-ember-persona").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Ok(unauthorized("missing X-Ember-Persona header")),
    };
    let credential_name = match headers
        .get("x-ember-credential")
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.to_string(),
        None => return Ok(unauthorized("missing X-Ember-Credential header")),
    };

    let method = req.method().clone();
    let uri = req.uri().clone();

    // Parse the `insteadOf`-rewritten path: `/github.com/owner/repo.git/...`.
    // The leading segment MUST match `config.upstream_host` — anything else
    // is a routing mistake on the client and we refuse rather than silently
    // forwarding to an unexpected host.
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let expected_prefix = format!("/{}/", config.upstream_host);
    let upstream_path_and_query = match path_and_query.strip_prefix(&expected_prefix) {
        Some(rest) => format!("/{rest}"),
        None => {
            tracing::warn!(
                path = %path_and_query,
                expected_prefix = %expected_prefix,
                "git echo: path does not start with expected upstream prefix"
            );
            return Ok(bad_request(
                "git echo: path must start with /<upstream_host>/",
            ));
        }
    };

    // Detect git-transport shape so we only Basic-inject on the right paths.
    // Both phases of a push are recognised:
    //   - GET  /{owner}/{repo}.git/info/refs?service=git-receive-pack
    //   - POST /{owner}/{repo}.git/git-receive-pack
    // The read-side (git-upload-pack) is also tagged as git-transport because
    // `insteadOf` rewrites affect clone/fetch too and we want a consistent
    // credential substitution across every phase.
    let is_git_transport = is_git_smart_http_path(&upstream_path_and_query);

    // P69L.0c: grant-backed credential resolution.
    //
    // 1. Look up the active grant for (persona, credential). No active grant →
    //    403 (policy denies).
    // 2. Load and verify the composite AccessGrant chain from the store.
    // 3. Derive (action, resource) from the upstream path:
    //    action   = "github:push"  (receive-pack) or "github:read" (upload-pack)
    //    resource = "owner/repo"   extracted by git_echo_owner_repo
    // 4. Resolve the matching Statement. No match → 403.
    // 5. Fetch the raw credential bytes from the vault. Not found → 500.
    let push_target = git_echo_owner_repo(&upstream_path_and_query)
        .unwrap_or_else(|| upstream_path_and_query.trim_start_matches('/').to_string());

    let grant = match config
        .state
        .store
        .evaluate_grant(&persona_id, &credential_name)
    {
        Ok(g) => g,
        Err(StoreError::NotFound) => {
            tracing::warn!(
                persona_id = %persona_id,
                credential = %credential_name,
                "git echo: no active grant for persona/credential"
            );
            // Route through sink shim.
            if let Err(e) = config.state.sink_log_event(
                Some(&persona_id),
                "credential.access",
                Some(&credential_name),
                "denied_no_grant",
                Some(&format!("push_target={push_target}")),
            ) {
                tracing::warn!(error = ?e, "git echo: log_event(denied_no_grant) failed");
            }
            return Ok(forbidden("no active grant for persona/credential"));
        }
        Err(e) => return Err(ProxyError::Store(e)),
    };
    if !config
        .state
        .store
        .leases()
        .has_live_lease(&grant.id, chrono::Utc::now())
    {
        // ADR 211 §1/AC-2: the git echo proxy is an authority-consuming
        // credential-injection path. An active SQL grant without its
        // grant-scoped live lease is inert and must not reach statement
        // resolution, vault reads, or upstream traffic.
        tracing::warn!(
            grant_id = %grant.id,
            persona_id = %persona_id,
            credential = %credential_name,
            "git echo: active grant has no live lease"
        );
        if let Err(e) = config.state.sink_log_event(
            Some(&persona_id),
            "credential.access",
            Some(&credential_name),
            "denied_no_live_lease",
            Some(&format!("grant_id={} push_target={push_target}", grant.id)),
        ) {
            tracing::warn!(error = ?e, "git echo: log_event(denied_no_live_lease) failed");
        }
        return Ok(forbidden(&format!(
            "grant_inactive:no_live_lease:{}",
            grant.id
        )));
    }

    let access_grant = match config.state.store.get_access_grant(&grant.id) {
        Ok(ag) => ag,
        Err(e) => return Err(ProxyError::Store(e)),
    };

    // BKR-4b (ADR 205 §A.3 parts 1+2): root-authorize + chain-verify on the
    // composed `PersonaRootAuthority` seam — parity with the LLM lane
    // (`resolve_grant`, #5724) and the broker mints (#5708/#5718). The git-echo
    // lane is an authority-consuming credential-injection path; it must not
    // honor a grant whose issuing persona's root is not device-set-authorized
    // (1) or whose block chain does not verify against that root (2). Today the
    // seam is the transitional dev0 daemon-stored root (ADR 205 §A.5/§9 honest
    // limit); it firms to the presence device-set when ADR 206 steps 1–2 land,
    // with no caller change. Fail-closed; oracle-safe (the contract names only
    // the failing layer).
    {
        use crate::trust::use_time_verify::PersonaRootAuthority;
        let Some(root) = config
            .state
            .store
            .authorized_root_pubkey(&access_grant.issuing_persona_id)
        else {
            tracing::warn!(
                grant_id = %grant.id,
                persona_id = %persona_id,
                credential = %credential_name,
                "git echo: issuing persona root not authorized — denying"
            );
            if let Err(e) = config.state.sink_log_event(
                Some(&persona_id),
                "credential.access",
                Some(&credential_name),
                "denied_root_unauthorized",
                Some(&format!(
                    "grant_id={} issuer={}",
                    grant.id, access_grant.issuing_persona_id
                )),
            ) {
                tracing::warn!(error = ?e, "git echo: log_event(denied_root_unauthorized) failed");
            }
            return Ok(forbidden("git push grant root unauthorized"));
        };
        if core_crypto::grant_chain::verify_chain(&access_grant.blocks, &root).is_err() {
            tracing::warn!(
                grant_id = %grant.id,
                persona_id = %persona_id,
                credential = %credential_name,
                "git echo: grant chain verification failed — denying"
            );
            if let Err(e) = config.state.sink_log_event(
                Some(&persona_id),
                "credential.access",
                Some(&credential_name),
                "denied_chain_invalid",
                Some(&format!("grant_id={}", grant.id)),
            ) {
                tracing::warn!(error = ?e, "git echo: log_event(denied_chain_invalid) failed");
            }
            return Ok(forbidden("git push grant chain invalid"));
        }
    }

    // Classify the request: receive-pack = push, upload-pack = read.
    let git_action = if upstream_path_and_query.contains("git-receive-pack") {
        "github:push"
    } else {
        "github:read"
    };
    let resource = push_target.clone();

    let matched_sid = match resolve_statement_for_request(&access_grant, git_action, &resource) {
        Some((_, stmt)) => stmt.sid.clone(),
        None => {
            tracing::warn!(
                grant_id = %grant.id,
                persona_id = %persona_id,
                credential = %credential_name,
                action = %git_action,
                resource = %resource,
                "git echo: no applicable statement for request — denying"
            );
            // Route through sink shim.
            if let Err(e) = config.state.sink_log_event(
                Some(&persona_id),
                "credential.access",
                Some(&credential_name),
                "denied_no_applicable_statement",
                Some(&format!("action={git_action} resource={resource}")),
            ) {
                tracing::warn!(error = ?e, "git echo: log_event(denied_no_applicable_statement) failed");
            }
            return Ok(forbidden("no applicable statement for git push"));
        }
    };

    // Per-statement revocation parity with the LLM lane (resolve_grant) and
    // every other resolution site: a statement revoked while the parent grant
    // stays active MUST NOT inject a credential. Without this check the
    // git-push echo lane honored a credential the operator believed scoped-down.
    // (Sweep 3 finding S-REVOKE.)
    let revoked_sids = config
        .state
        .store
        .get_revoked_sids(&grant.id)
        .map_err(ProxyError::Store)?;
    if revoked_sids.contains(&matched_sid) {
        tracing::warn!(
            grant_id = %grant.id,
            persona_id = %persona_id,
            credential = %credential_name,
            statement_sid = %matched_sid,
            "git echo: matched statement is revoked — denying"
        );
        if let Err(e) = config.state.sink_log_event(
            Some(&persona_id),
            "credential.access",
            Some(&credential_name),
            "denied_statement_revoked",
            Some(&format!("grant_id={} sid={matched_sid}", grant.id)),
        ) {
            tracing::warn!(error = ?e, "git echo: log_event(denied_statement_revoked) failed");
        }
        return Ok(forbidden("git push statement revoked"));
    }

    // ADR 205 §A.4 — online grant-ancestry revocation walk, parity with the LLM
    // lane (`resolve_grant`) and the broker mints. The leaf grant is active and
    // its matched statement is not SID-revoked, but an ANCESTOR in its
    // `parent_grant_id` lineage may have been revoked without the eager
    // `cascade_revoke_children` write reaching this leaf (crash mid-cascade /
    // race / a presented embed-chain the column never cascaded). Refuse the
    // credential injection if so — previously this lane walked no ancestry, so a
    // revoked-ancestor grant could still inject a git-push credential.
    if let Some(revoked) = config.state.store.first_revoked_grant_ancestor(&grant.id) {
        tracing::warn!(
            grant_id = %grant.id,
            persona_id = %persona_id,
            credential = %credential_name,
            ancestor = %revoked.grant_id,
            "git echo: revoked grant ancestor — denying"
        );
        if let Err(e) = config.state.sink_log_event(
            Some(&persona_id),
            "credential.access",
            Some(&credential_name),
            "denied_ancestor_revoked",
            Some(&format!(
                "grant_id={} ancestor={} reason={}",
                grant.id, revoked.grant_id, revoked.reason
            )),
        ) {
            tracing::warn!(error = ?e, "git echo: log_event(denied_ancestor_revoked) failed");
        }
        return Ok(forbidden("git push grant ancestor revoked"));
    }

    // Fetch the raw credential from the vault. Not in vault → 500 + audit.
    // Wrap in Zeroizing so the raw key bytes are wiped on drop.
    let vault = config.state.current_vault()?;
    let credential_bytes: Zeroizing<Vec<u8>> = match vault.get(
        VaultScope::Interactive,
        &config.state.store,
        &credential_name,
    ) {
        Ok(b) => b,
        Err(VaultError::NotFound) => {
            tracing::warn!(
                credential = %credential_name,
                "git echo: credential not found in vault"
            );
            // Route through sink shim.
            if let Err(e) = config.state.sink_log_event(
                Some(&persona_id),
                "credential.access",
                Some(&credential_name),
                "error_vault_not_found",
                Some(&format!("push_target={push_target}")),
            ) {
                tracing::warn!(error = ?e, "git echo: log_event(error_vault_not_found) failed");
            }
            return Ok(internal_error("credential not found in vault"));
        }
        Err(e) => return Err(ProxyError::Vault(e)),
    };
    let credential_value: Zeroizing<String> =
        secret_utf8(credential_bytes, "git echo credential").map_err(ProxyError::PolicyBackend)?;

    // P69L.0b-P1-AUDIT: emit `credential.access` so operators can see
    // that a credential substitution occurred and which repo was targeted.
    // `action` mirrors the credential-correlation shape: "github.push.<owner/repo>".
    tracing::info!(
        event = "credential.access",
        allowed = true,
        action = %format!("github.push.{push_target}"),
        credential_name = %credential_name,
        persona_id = %persona_id,
        request_id = %request_id,
        "git echo: credential access"
    );
    // Route through sink shim.
    if let Err(e) = config.state.sink_log_event(
        Some(&persona_id),
        "credential.access",
        Some(&credential_name),
        "allowed",
        Some(&format!(
            "push_target={push_target} request_id={request_id}"
        )),
    ) {
        tracing::warn!(error = ?e, "git echo: log_event(allowed) failed");
    }

    // Split the request into parts + streaming body. The body is forwarded
    // as a stream — no collection into memory — so pack-objects flows on
    // git push without ever fully residing in the daemon process.
    let (parts, incoming_body) = req.into_parts();

    // P69L.0b-P0-TIMEOUTS: reuse the process-wide client so we don't pay a
    // TLS handshake per request. The pool bounds live on the Client itself
    // (see `git_echo_client()` / POOL_* constants).
    let client = git_echo_client();

    let target_url = format!(
        "{scheme}://{host}{path}",
        scheme = config.upstream_scheme,
        host = config.upstream_host,
        path = upstream_path_and_query,
    );
    let mut outgoing = Request::builder().method(method.clone()).uri(&target_url);

    // Forward every header except the ones we MUST control.
    //
    // - `authorization`: stripped unconditionally. Upstream must see only the
    //   header WE inject, never a header the client happened to send. This
    //   is the core product guarantee of the whole spike.
    // - `host`: rewritten to `upstream_host` so github.com's vhost routing
    //   matches. Hyper will also regenerate this from the URI, but being
    //   explicit prevents surprises if a client sends a bogus Host.
    // - `x-ember-*`: never appeared on the way in from git, but strip
    //   defensively in case a non-git client ever hits this endpoint.
    for (name, value) in &parts.headers {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "authorization" || lower == "host" || lower.starts_with("x-ember-") {
            continue;
        }
        outgoing = outgoing.header(name, value);
    }
    outgoing = outgoing.header("host", &config.upstream_host);

    // Inject Basic auth only for git-transport paths. Non-git paths get no
    // credential injected — they shouldn't be hitting this echo at all, and
    // we'd rather upstream reject with 401 than accidentally gate REST calls.
    if is_git_transport {
        let basic = build_github_basic_auth(&credential_value);
        outgoing = outgoing.header("authorization", basic);
    }

    // Pass the request body as a stream — `incoming_body` is `Incoming` and
    // implements `Body` directly. No intermediate buffer allocation.
    let outgoing_req = outgoing.body(incoming_body).map_err(|e| {
        tracing::warn!(error = %e, "git echo: failed to build outgoing request");
        ProxyError::Http(e)
    })?;

    tracing::info!(
        method = %method,
        upstream = %target_url,
        is_git_transport,
        "git echo forwarding"
    );

    // P69L.0b-P0-TIMEOUTS: cap the headers-received phase with
    // `HEADERS_DEADLINE`. `tokio::time::timeout` drops the inner future on
    // elapse, which cancels any in-flight TCP/TLS/request work and closes
    // the upstream socket — no leaked futures, no pinned sockets. On
    // timeout we return 504 to the client; `streaming_slot` is dropped at
    // function return so the concurrency counter is released.
    let upstream_resp =
        match tokio::time::timeout(HEADERS_DEADLINE, client.request(outgoing_req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "git echo: upstream request failed");
                return Err(ProxyError::Client(e));
            }
            Err(_elapsed) => {
                tracing::warn!(
                    upstream = %target_url,
                    deadline_secs = HEADERS_DEADLINE.as_secs(),
                    "git echo: upstream headers deadline exceeded — returning 504"
                );
                return Ok(gateway_timeout("upstream-headers-timeout"));
            }
        };

    // Stream the upstream response back to the client via `stream_response`.
    // Status, headers, and body frames flow through without accumulation —
    // P69L.0b streaming fix. P69L.1 (Anthropic) can reuse `stream_response`
    // for the same pattern.
    //
    // The `streaming_slot` acquired at function entry rides inside the
    // returned `PassthroughBody`; hyper will drop the body once the
    // response is fully written (clean EOF) or the client disconnects
    // mid-stream, releasing the slot in both cases.
    //
    // P69L.0b-P0-TIMEOUTS: wire a per-frame idle watchdog into the
    // passthrough body. If no data frame arrives within
    // `FRAME_IDLE_DEADLINE`, the stream aborts and drop emits
    // `outcome=partial reason=frame-idle-timeout`.
    //
    // P69L.0b-P1-AUDIT: thread the correlating `request_id` into the
    // passthrough body so Drop can emit `proxy.stream { request_id, ... }`
    // joinable with the `credential.access` entry above.
    let (resp_parts, resp_body) = stream_response_with_frame_idle(
        upstream_resp,
        Some(streaming_slot),
        Some(FRAME_IDLE_DEADLINE),
    )
    .into_parts();
    let resp_body = match resp_body {
        ProxyBody::Passthrough(pb) => ProxyBody::Passthrough(pb.with_request_id(request_id)),
        other => other,
    };
    Ok(Response::from_parts(resp_parts, resp_body))
}

/// HTTP 504 response used when the upstream fails to send response headers
/// within `HEADERS_DEADLINE`, or when a mid-stream frame-idle watchdog
/// fires before any body bytes have flushed downstream. Short body keeps
/// the response cheap to emit; diagnostic detail lives in the daemon log.
fn gateway_timeout(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::GATEWAY_TIMEOUT)
        .header("content-type", "text/plain; charset=utf-8")
        .body(box_full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

// ===== kept from proxy.rs lines 4453-4455 =====

#[cfg(test)]
mod tests;
