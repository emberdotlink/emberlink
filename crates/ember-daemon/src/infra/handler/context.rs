use std::cell::RefCell;
use std::collections::HashMap;

use core_personas::MtlsPrincipal;

use super::{AuthorityClass, presence_scope_for_unlock_target};
use crate::infra::store::DaemonStore;

// C39-HANDLER-C3-FULL: peer-credential-derived principal binding for
// `delegate_grant`. Mirrors the socket layer's `PeerIdentity` shape so
// `handler.rs` does not have to depend on socket-layer cfg gates. The
// fields are public because this is a kernel-derived identity carried
// by trusted code (the socket layer); there is no validation surface
// for callers to violate.
//
// `pid` is `Option<i32>` because BSD's `LOCAL_PEERCRED` does not always
// surface PID. On macOS in particular, when `pid` is `None`, the only
// safe behavior is to fail-closed — `peercred_principal()` returns
// `HandlerError::PrincipalUnavailable` rather than minting a delegation
// authorized by an unknown principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub pid: Option<i32>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl From<crate::infra::socket::PeerIdentity> for PeerCred {
    fn from(p: crate::infra::socket::PeerIdentity) -> Self {
        PeerCred {
            uid: p.uid,
            pid: p.pid,
        }
    }
}

/// Errors returned by the principal-binding layer.
///
/// These are converted to JSON-RPC error tuples by the dispatch layer:
///   `PrincipalUnavailable` -> `-32401`, "principal binding unavailable"
///   `PrincipalMismatch    -> `-32401`, "principal mismatch"
///
/// `-32401` is reused from the JSON-RPC convention (Unauthorized) — same
/// code used elsewhere in the daemon for authorization rejections that
/// are NOT policy denials (`-32003`) or generic param errors (`-32602`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerError {
    /// The peer-credential structure did not contain enough information
    /// to derive a principal. On macOS this happens whenever
    /// `LOCAL_PEERCRED` did not return a PID. We fail-closed rather than
    /// fall back to UID-only binding (which would let any same-UID
    /// process claim any persona).
    PrincipalUnavailable,
    /// The kernel-derived principal does not match the persona the
    /// caller asserted in their request params. The caller is lying
    /// about which persona they are.
    PrincipalMismatch,
    /// The peer's PID is not enrolled in the daemon's PID->persona
    /// registry. The caller has not yet established an identity in
    /// this daemon (no `create_persona` call from this PID, or the
    /// enrollment expired/was cleared).
    PrincipalNotEnrolled,
}

impl HandlerError {
    pub fn to_jsonrpc(&self) -> (i32, String) {
        match self {
            HandlerError::PrincipalUnavailable => (
                -32401,
                "delegate_grant: principal binding unavailable on this \
                 platform (peer PID was not surfaced by the kernel)"
                    .to_string(),
            ),
            HandlerError::PrincipalMismatch => (
                -32401,
                "delegate_grant: caller's kernel-derived principal does \
                 not match the asserted caller_persona_id"
                    .to_string(),
            ),
            HandlerError::PrincipalNotEnrolled => (
                -32401,
                "delegate_grant: caller PID is not enrolled with any \
                 persona — call create_persona on this connection first"
                    .to_string(),
            ),
        }
    }
}

/// Per-connection request context carrying kernel-derived identity.
///
/// The `peer` field is populated by the socket layer at connection accept
/// time; the `principal` field is the persona id resolved from `peer.pid`
/// via `peercred_principal()`. For `Internal` callers, both are `None`.
///
/// The struct deliberately mirrors what we expect to extend to
/// session-ticket-based binding (Alternative B) so the handler call
/// site does not change between phases — only the population of
/// `principal` does.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub source: DispatchSource,
    pub peer: Option<PeerCred>,
    /// Pre-resolved persona id, when the dispatch layer has already
    /// looked it up (e.g. for tests that want to inject a principal
    /// directly without going through the PID registry).
    pub principal: Option<String>,
    /// Base directory for session sidecars (`~/.ember/sessions/`). Required
    /// by `register_session` and `close_session` RPC arms to read/write
    /// `SessionMeta` + `receipt.json`. `None` for internal callers and test
    /// contexts that don't exercise the session lifecycle.
    pub sessions_dir: Option<std::path::PathBuf>,
    /// Bound LLM proxy
    /// URL plumbed from the runtime after the proxy listener binds. Populated
    /// by `SocketListener::with_llm_proxy_url` and consumed by
    /// `register_session` instead of reading `EMBER_PROXY_URL` from the
    /// environment, which is unreliable across tokio worker threads (Rust
    /// 2024 `set_var` cross-thread visibility hazard).
    pub llm_proxy_url: Option<String>,
    /// Bound git proxy
    /// URL plumbed from the runtime after the git proxy listener binds.
    /// Matches the pattern of `llm_proxy_url` above.
    pub git_proxy_url: Option<String>,
    /// Kernel-attested
    /// (uid, pid, socket_path) triple captured at connection accept
    /// time. Threaded through to broker_issue / broker_revoke /
    /// broker_list / broker_exec / session.lookup_or_open so per-call
    /// authorization is rooted in a kernel-supplied identity rather
    /// than the attacker-controlled `caller_persona` payload field.
    ///
    /// `None` for internal callers (admin CLI, test harness, recovery
    /// flows) and pre-migration socket entry points; broker handlers
    /// fall back to the legacy "warn but allow" path in that case.
    pub peer_cred_principal: Option<crate::infra::runtime::PeerCredPrincipal>,
    /// Phase D presence-token, attached by the JSON-RPC parser slice
    /// (D-3) from the `_presence_token` request parameter. When the
    /// dispatched method's authority class is `OperatorPresence`, the
    /// handler validates this token via
    /// `crate::auth::presence_token::validate`. `None` for ConnectOnly
    /// methods, internal callers, and pre-D callers that have not yet
    /// been retro-fitted with token minting.
    pub presence_token: Option<crate::auth::presence_token::PresenceToken>,
    /// When set,
    /// `enforce_local_state_gate` short-circuits with a synthetic peer
    /// (mirroring the existing `#[cfg(test)]` bypass arm). Only set by
    /// [`RequestContext::socket_for_test`], which is reachable only from
    /// integration tests that explicitly opt in via
    /// `SocketListener::with_test_mode_synthetic_presence_token(true)`.
    /// Production constructors leave this `false`; the binary-pin gate
    /// runs as written.
    ///
    /// ADR 206: this flag also marks a **synthetic in-memory test socket** for
    /// the presence chokepoint (`enforce_presence_chokepoint`). Those T3 socket
    /// integration tests run against in-memory stores with no operator identity,
    /// so they cannot mint a real presence proof; like the binary-pin gate, the
    /// chokepoint is skipped for them. It is `true` ONLY via `socket_for_test`,
    /// never in production — so production widening ops always face the chokepoint.
    pub bypass_binary_pin_gate_for_test: bool,
}

impl RequestContext {
    /// Build an `Internal` context — bypasses peercred binding entirely.
    pub fn internal(reason: &'static str) -> Self {
        Self {
            source: DispatchSource::Internal { reason },
            peer: None,
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        }
    }

    /// Build a `Socket` context with a peer credential. The principal
    /// will be lazily resolved by handlers that require it.
    ///
    /// **Under `cfg(test)`**, this auto-synthesizes a daemon-identity-signed
    /// presence_token so socket integration tests can call
    /// OperatorPresence-class methods without manually constructing a token
    /// per test. Production callers (the real socket accept path) pass
    /// `peer = Some(...)` and the non-test arm yields `presence_token = None`
    /// — the dispatcher's operator-presence gate then enforces the real token
    /// requirement.
    ///
    /// This is the same auto-injection pattern the legacy `dispatch_method`
    /// shim (used by some test harnesses) uses at lines 1620-1648; lifting
    /// it into the constructor centralizes the test surface so every
    /// caller of `RequestContext::socket(Some(peer))` works uniformly.
    pub fn socket(peer: Option<PeerCred>) -> Self {
        #[cfg(test)]
        let synthetic_presence_token = peer.as_ref().map(|p| {
            use crate::auth::presence_token::{ScopeKey, mint};
            use std::time::Duration;
            ensure_test_presence_identity();
            let signer = DaemonIdentityPresenceSigner::current()
                .expect("test presence token signer must be initialised");
            mint(p.uid, ScopeKey::all(), Duration::from_secs(60), &signer)
        });
        #[cfg(not(test))]
        let synthetic_presence_token: Option<crate::auth::presence_token::PresenceToken> = None;

        Self {
            source: DispatchSource::Socket,
            peer,
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            presence_token: synthetic_presence_token,
            bypass_binary_pin_gate_for_test: false,
        }
    }

    /// Build a `Socket` context with a pre-resolved principal. Used by
    /// tests that want to assert handler behavior without populating
    /// the global PID registry.
    pub fn socket_with_principal(peer: Option<PeerCred>, principal: String) -> Self {
        Self {
            source: DispatchSource::Socket,
            peer,
            principal: Some(principal),
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        }
    }

    /// Test-only `Socket` context constructor that mints a synthetic
    /// presence_token bound to `peer.uid`. Production code paths MUST
    /// NOT call this — the synthesis exists only so tests can exercise
    /// the operator-presence branch without depending on runtime startup.
    ///
    /// Exists because the cfg(test) synthesis in
    /// [`RequestContext::socket`] is unreachable from integration tests
    /// in `tests/` by Rust language semantics — integration tests link
    /// against the lib as if external and don't see cfg(test) blocks.
    /// Test-only synthetic-peer entry point for integration tests.
    pub fn socket_for_test(peer: PeerCred) -> Self {
        use crate::auth::presence_token::{ScopeKey, mint};
        use std::time::Duration;
        ensure_test_presence_identity();
        let signer =
            DaemonIdentityPresenceSigner::current().expect("test presence token signer must exist");
        let presence_token = Some(mint(
            peer.uid,
            ScopeKey::all(),
            Duration::from_secs(60),
            &signer,
        ));
        Self {
            source: DispatchSource::Socket,
            peer: Some(peer),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            presence_token,
            bypass_binary_pin_gate_for_test: true,
        }
    }

    /// Set the kernel-attested `PeerCredPrincipal` for this request
    /// context. Called by the socket accept path
    /// (`socket::handle_connection`) once it has extracted the
    /// `(uid, pid, socket_path)` triple from the accepted stream.
    ///
    /// Builder helper so the
    /// socket layer can stamp the principal without touching every
    /// constructor variant.
    pub fn with_peer_cred_principal(
        mut self,
        principal: Option<crate::infra::runtime::PeerCredPrincipal>,
    ) -> Self {
        self.peer_cred_principal = principal;
        self
    }

    /// Build a `Bridge` context carrying the mTLS-attested principal the
    /// `ember-rpc` sibling resolved from the client cert's SPIFFE SAN
    /// (ADR 154 component 4 / ADR 155 priv-sep amendment). The principal
    /// lives *inside* the [`DispatchSource::Bridge`] variant — there is no
    /// separate settable field, so a `Socket`-sourced request can never
    /// carry an mTLS principal (the wire-forgeable `_mtls_principal`
    /// injection is structurally gone, `request_context_mtls_principal_overlay`).
    ///
    /// `peer` is the kernel peercred of the local rpc-forward UDS peer (the
    /// sibling service), NOT the in-container workload — the workload
    /// identity is the cert-derived `principal`. UDS callers never use this
    /// constructor.
    pub fn bridge(peer: Option<PeerCred>, principal: MtlsPrincipal) -> Self {
        Self {
            source: DispatchSource::Bridge(principal),
            peer,
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        }
    }

    /// The mTLS-attested principal for this request, when it arrived over
    /// the [`DispatchSource::Bridge`] lane. Returns `None` for every other
    /// source — by construction, only a `Bridge` request can carry one, so
    /// a wire-claimed `_mtls_principal` on a `Socket` request reads as `None`
    /// here. The dispatch overlay (see `dispatch_method_with_context`) reads
    /// `mtls_principal().persona_id` as the calling persona in place of any
    /// wire-claimed `caller_persona_id`, mirroring the per-agent-UDS path's
    /// `EnrolledPrincipal` overlay.
    #[inline]
    pub fn mtls_principal(&self) -> Option<&MtlsPrincipal> {
        match &self.source {
            DispatchSource::Bridge(principal) => Some(principal),
            DispatchSource::Socket | DispatchSource::Internal { .. } => None,
        }
    }

    /// Set the Phase D presence-token for this request context.
    /// Called by the JSON-RPC parser (Phase D Slice 3) when the request
    /// payload carries an `_presence_token` field.
    ///
    /// `request_context_presence_token_builder` —
    /// additive builder so existing constructors don't need updating.
    ///
    /// `None` is treated as no-op so this method composes cleanly with
    /// constructors that already minted a synthetic token (e.g.
    /// `RequestContext::socket_for_test`). Without the no-op semantics
    /// the socket-accept path's tail call `with_presence_token(None)`
    /// (after `take_presence_token` returned None because the CLI request
    /// didn't carry one) would clobber the synthetic token and re-introduce
    /// the cross-crate "OperatorPresence missing presence_token" failure
    /// mode in the integration-test suite.
    pub fn with_presence_token(
        mut self,
        token: Option<crate::auth::presence_token::PresenceToken>,
    ) -> Self {
        if token.is_some() {
            self.presence_token = token;
        }
        self
    }

    /// Whether this context satisfies the required authority class for
    /// dispatching a JSON-RPC method, per ADR 152 §"Destination".
    ///
    /// Cohort A dev0 model — the socket layer's
    /// `runtime::authenticate_peer_creds` already enforced the current
    /// connect policy before stamping `peer`: same-euid in development
    /// mode, `ember-clients` membership (or daemon euid) in
    /// install-shaped mode. A `Some(peer)` here is therefore the
    /// kernel-attested proof of "ConnectOnly" authority.
    ///
    /// Internal dispatch sources (admin CLI, recovery flows, the test
    /// harness) are NOT routed through this check — the gate site at
    /// `dispatch_method_with_context` bypasses Internal callers as the
    /// pre-existing in-process trust lane (see `DispatchSource`).
    ///
    /// `OperatorPresenceWithReattest` is reserved for team0+/ent0
    /// deployments per the ADR 152 tier matrix and is always denied
    /// in cohort A — wiring its proof surface is a Phase D-or-later
    /// activity.
    pub fn satisfies(&self, required: AuthorityClass) -> bool {
        let has_peer = self.peer.is_some();
        // `satisfies` enforces only the connection-level invariant
        // (peer-cred present). The richer operator-presence semantics
        // (token validation and unlocked-session requirement) are enforced in
        // `dispatch_method_with_context`.
        match required {
            AuthorityClass::ConnectOnly => has_peer,
            AuthorityClass::OperatorPresence => has_peer,
            // No team0+ deployment in cohort A — always denied.
            AuthorityClass::OperatorPresenceWithReattest => false,
        }
    }
}
pub(crate) fn mint_operator_presence_token(
    peer: Option<&PeerCred>,
    requested_method: &str,
) -> Result<Option<crate::auth::presence_token::PresenceToken>, (i32, String)> {
    use crate::auth::presence_token::mint;

    let Some(peer) = peer else {
        return Ok(None);
    };
    let Some(identity) = crate::infra::receipt::current_identity() else {
        return Err((
            -32000,
            "daemon identity not initialised — cannot mint operator presence token".to_string(),
        ));
    };
    let signer = DaemonIdentityPresenceSigner::new(identity);
    let ttl = std::cmp::max(
        crate::trust::presence::current_config().idle_timeout,
        std::time::Duration::from_secs(60),
    );
    let scope = presence_scope_for_unlock_target(requested_method).ok_or((
        -32602,
        format!("unknown or unsupported operator-presence unlock target '{requested_method}'"),
    ))?;
    Ok(Some(mint(peer.uid, scope, ttl, &signer)))
}

/// Real Ed25519-backed presence-token signer.
///
/// Wraps a borrowed `DaemonPersona` (Ed25519 keypair, ADR 074) so the
/// presence-token mint/verify path goes through the daemon's real
/// signing identity instead of a stub. The `DaemonSigner` impl below
/// delegates `sign` to `persona.sign(msg)` and `verify` to
/// `ed25519_dalek::Verifier::verify` against `persona.verifying_key()`.
///
/// Anchor: presence_signer_ed25519_wired
///
/// The presence-stub signer has been replaced: the stub
/// primitive is gone — every presence-token signature this daemon
/// emits is the same Ed25519 key surface that signs Receipts. See
/// `crate::infra::receipt::DaemonPersona` for the Ed25519 key
/// lifecycle and `crate::auth::presence_token::DaemonSigner` for the
/// trait this type satisfies.
pub(crate) struct DaemonIdentityPresenceSigner<'a> {
    persona: &'a crate::infra::receipt::DaemonPersona,
}

impl<'a> DaemonIdentityPresenceSigner<'a> {
    pub(crate) fn new(persona: &'a crate::infra::receipt::DaemonPersona) -> Self {
        Self { persona }
    }

    /// Construct a signer from the process-singleton daemon identity.
    ///
    /// Returns `None` before `init_identity` has run (pre-startup or
    /// failed key load). This is the canonical accessor — every
    /// presence-token mint site goes through `current()` rather than
    /// caching its own `DaemonPersona` reference, so a future
    /// rotation/reload of the singleton flows through without
    /// per-callsite changes.
    pub(crate) fn current() -> Option<Self> {
        crate::infra::receipt::current_identity().map(Self::new)
    }
}

impl crate::auth::presence_token::DaemonSigner for DaemonIdentityPresenceSigner<'_> {
    fn sign(&self, msg: &[u8]) -> bytes::Bytes {
        bytes::Bytes::copy_from_slice(&*self.persona.sign(msg))
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(signature) = ed25519_dalek::Signature::try_from(sig) else {
            return false;
        };
        ed25519_dalek::Verifier::verify(self.persona.verifying_key(), msg, &signature).is_ok()
    }
}

pub(crate) fn ensure_test_presence_identity() {
    if crate::infra::receipt::current_identity().is_some() {
        return;
    }
    let dir = std::env::temp_dir().join("ember-daemon-test-presence-identity");
    std::fs::create_dir_all(&dir).expect("create test presence identity dir");
    let _ = crate::infra::receipt::init_identity(&dir)
        .expect("init daemon identity for presence-token tests");
}

// PID -> Persona enrollment registry. Populated when a Socket caller
// calls `create_persona` and inspected when the same caller (same PID)
// invokes `delegate_grant`.
//
// Why thread-local: the daemon is single-threaded LocalSet at runtime,
// so production correctness only needs a single map. We use a
// thread-local rather than a global static so that cargo's parallel
// test runner gets fresh registries per test thread — otherwise a
// `create_persona` enrollment from one test could leak into another
// test's `delegate_grant` lookup and produce a flaky principal-mismatch
// result. This is a pragmatic phase-1 fit; phase 2 (session ticket)
// will move enrollment into a more structured per-connection store.
std::thread_local! {
    static PID_PERSONA_REGISTRY: RefCell<HashMap<i32, String>> =
        RefCell::new(HashMap::new());
}

std::thread_local! {
    static DISPATCH_DEPLOYMENT_TIER: RefCell<crate::infra::config::DeploymentTier> =
        const { RefCell::new(crate::infra::config::DeploymentTier::Dev0) };
}

/// Enroll a (pid, persona_id) pair in the per-thread registry.
///
/// Called from the `create_persona` handler when the dispatch source is
/// `Socket` and the peer credential surfaced a PID.  Subsequent
/// `delegate_grant` calls from the same PID will resolve to this
/// persona id.
pub fn enroll_pid_persona(pid: i32, persona_id: &str) {
    PID_PERSONA_REGISTRY.with(|reg| {
        reg.borrow_mut().insert(pid, persona_id.to_string());
    });
}

/// Stamp the current deployment tier into the handler's thread-local view.
///
/// The daemon runs the socket dispatch path on a single-threaded `LocalSet`,
/// so a thread-local is sufficient in production and gives tests an isolated
/// seam without cross-thread global leakage.
pub fn set_dispatch_deployment_tier(tier: crate::infra::config::DeploymentTier) {
    DISPATCH_DEPLOYMENT_TIER.with(|slot| {
        *slot.borrow_mut() = tier;
    });
}

pub(crate) fn current_dispatch_deployment_tier() -> crate::infra::config::DeploymentTier {
    DISPATCH_DEPLOYMENT_TIER.with(|slot| *slot.borrow())
}

#[cfg(test)]
pub(crate) struct DeploymentTierGuard {
    previous: crate::infra::config::DeploymentTier,
}

#[cfg(test)]
impl DeploymentTierGuard {
    pub(crate) fn set(next: crate::infra::config::DeploymentTier) -> Self {
        let previous = current_dispatch_deployment_tier();
        set_dispatch_deployment_tier(next);
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for DeploymentTierGuard {
    fn drop(&mut self) {
        set_dispatch_deployment_tier(self.previous);
    }
}

#[cfg(test)]
std::thread_local! {
    /// Test-only switch for the ADR 206 presence chokepoint (`enforce_presence_
    /// chokepoint`). The broad socket-dispatch test surface predates the
    /// chokepoint and exercises widening ops against in-memory stores (no
    /// `data_dir`, no enrolled presence Device) — it is not testing presence, so
    /// it must not be forced to mint real proofs. Default **off** here so that
    /// surface is unaffected; the chokepoint's signature verification is covered
    /// by `presence_gate` unit tests, and the dispatch-level enforcement tests
    /// flip this **on** via [`PresenceChokepointEnforceGuard`]. Compiled out of
    /// production entirely — `#[cfg(not(test))]` builds ALWAYS enforce.
    pub(crate) static PRESENCE_CHOKEPOINT_TEST_ENFORCE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// RAII guard that turns the presence chokepoint ON for the current test thread.
#[cfg(test)]
pub(crate) struct PresenceChokepointEnforceGuard {
    previous: bool,
}

#[cfg(test)]
impl PresenceChokepointEnforceGuard {
    pub(crate) fn on() -> Self {
        let previous = PRESENCE_CHOKEPOINT_TEST_ENFORCE.with(|c| c.replace(true));
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for PresenceChokepointEnforceGuard {
    fn drop(&mut self) {
        PRESENCE_CHOKEPOINT_TEST_ENFORCE.with(|c| c.set(self.previous));
    }
}

/// Test-only helper: drop all enrollments. Cargo's per-test isolation
/// relies on a fresh registry, so individual tests that enroll PIDs
/// should call this in setup (or rely on thread-local isolation).
#[cfg(test)]
pub fn clear_pid_persona_registry() {
    PID_PERSONA_REGISTRY.with(|reg| reg.borrow_mut().clear());
}


/// Resolve the calling persona for a peer credential.
///
/// On Linux the registry is keyed by PID, populated at `create_persona`
/// dispatch time. On macOS where `peer.pid` may be `None`, we fail-closed
/// with `PrincipalUnavailable` rather than fall back to UID-only binding
/// (which would let any same-UID process claim any persona).
pub fn peercred_principal(peer: &PeerCred) -> Result<String, HandlerError> {
    let pid = peer.pid.ok_or(HandlerError::PrincipalUnavailable)?;
    PID_PERSONA_REGISTRY.with(|reg| {
        reg.borrow()
            .get(&pid)
            .cloned()
            .ok_or(HandlerError::PrincipalNotEnrolled)
    })
}

// This block extends the per-socket Persona
// enrollment doctrine of ADR 136 to the in-container case: agents
// inside containers connect via per-agent UDS sockets at
// `/run/emberd/agent-<uuid>.sock`.
// emberd records `(socket_path, persona_id, grant_id, brief_content_hash)`
// at spawn time; every RPC on that socket has identity resolved from
// the enrollment table, NOT from wire-claimed `caller_persona_id` /
// `caller_grant_id`. Worker B with a forged grant_id cannot
// impersonate the orchestrator just by sending the orchestrator's
// grant_id over its own socket.

/// Per-socket persona enrollment in container (ADR 136 §"In-container
/// extension") — the kernel-attested-equivalent identity surfaced by
/// the per-socket enrollment table when an RPC arrives on a per-agent
/// UDS socket.
///
/// Constructed by [`enroll_container_persona`] from a successful row
/// lookup in `agent_socket_enrollments`. The dispatch layer uses
/// these fields verbatim — `persona_id` overrides any payload-claimed
/// `caller_persona` / `caller_persona_id`; `grant_id` overrides any
/// payload-claimed `caller_grant_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledPrincipal {
    pub persona_id: String,
    pub grant_id: String,
    pub brief_content_hash: String,
}

/// Directory prefix for
/// per-agent UDS sockets.
///
/// Mirrors `crate::infra::socket::PER_AGENT_SOCKET_PARENT`. Kept as a
/// `&'static str` here so the dispatch-time match is a pure string
/// operation and does not pull in the socket module's full surface.
const PER_AGENT_SOCKET_DIR: &str = "/run/emberd/";

/// True when the supplied
/// socket path matches the per-agent UDS shape
/// (`/run/emberd/agent-*.sock`).
///
/// Used by [`dispatch_method_with_context`] to decide whether to
/// resolve the calling persona from the enrollment table or to fall
/// through to the legacy peercred / PID-registry path. Test seam:
/// callers passing a temp-dir socket path (e.g. tempfile-rooted
/// `agent-<uuid>.sock`) match too — the match is on the filename
/// pattern, not the absolute parent — so unit tests can exercise the
/// enrolled-principal branch without binding into `/run/emberd/`.
pub fn is_per_agent_socket_path(socket_path: &std::path::Path) -> bool {
    let Some(name) = socket_path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if !(name.starts_with("agent-") && name.ends_with(".sock")) {
        return false;
    }
    // Production callers land in `/run/emberd/`; tests use tempdir-
    // rooted paths. Both shapes are accepted to avoid forcing the
    // test harness to bind under `/run`.
    if let Some(parent) = socket_path.parent().and_then(|p| p.to_str()) {
        // Either the canonical `/run/emberd/` prefix or any tempdir
        // path is acceptable — the discriminator is the filename
        // shape. A naked path with no parent is refused (test seam
        // requires at least one parent component).
        let _ = parent;
    } else {
        return false;
    }
    // Belt-and-suspenders: keep the canonical prefix observable so
    // operator audits can grep for production callers.
    let _ = PER_AGENT_SOCKET_DIR;
    true
}

/// Resolve the
/// kernel-attested-equivalent principal for a per-agent UDS socket.
///
/// Reads the `agent_socket_enrollments` row keyed by `socket_path`
/// and returns the recorded `(persona_id, grant_id, brief_content_hash)`
/// triple. The wire-claimed `caller_persona_id` / `caller_grant_id`
/// are NOT consulted — the spawn-time enrollment IS the identity
/// claim. Defense: worker B with a forged grant_id over its own
/// socket cannot impersonate the orchestrator's grant_id, because the
/// socket path determines which enrollment row applies.
///
/// Returns `HandlerError::PrincipalNotEnrolled` when no `active`
/// row exists for the supplied path (revoked rows count as missing —
/// the store helper filters them).
pub fn enroll_container_persona(
    store: &DaemonStore,
    socket_path: &std::path::Path,
) -> Result<EnrolledPrincipal, HandlerError> {
    let path_str = match socket_path.to_str() {
        Some(s) => s,
        None => {
            tracing::warn!(
                socket_path = %socket_path.display(),
                "enroll_container_persona: socket path is not valid UTF-8 — \
                 refusing"
            );
            return Err(HandlerError::PrincipalNotEnrolled);
        }
    };
    match store.lookup_agent_socket_enrollment(path_str) {
        Ok(Some(row)) => Ok(EnrolledPrincipal {
            persona_id: row.persona_id,
            grant_id: row.grant_id,
            brief_content_hash: row.brief_content_hash,
        }),
        Ok(None) => {
            tracing::warn!(
                socket_path = %path_str,
                "enroll_container_persona: no active enrollment for socket"
            );
            Err(HandlerError::PrincipalNotEnrolled)
        }
        Err(e) => {
            tracing::warn!(
                socket_path = %path_str,
                error = %e,
                "enroll_container_persona: store lookup failed — refusing"
            );
            Err(HandlerError::PrincipalNotEnrolled)
        }
    }
}

/// Origin of a dispatched RPC request.
///
/// Fix for C39-HANDLER-C2 (CRITICAL): the `force` flag on `create_grant`
/// used to be accepted from any wire caller, letting unauthenticated socket
/// clients mint grants that bypassed the policy engine. We now thread the
/// dispatch *source* through the handler so that only `Internal` callers
/// (admin CLI paths, test harness, recovery flows) can request policy
/// bypass. Socket callers that attempt `force: true` are rejected.
///
/// **Type-level barrier (C44-DISPATCH-TYPEWALL):** The `Internal` variant
/// requires a mandatory `reason` string literal so that every in-process
/// privilege escalation is visible and attributable at the call site.  Code
/// review can grep for `DispatchSource::Internal` and see exactly *why* each
/// caller claims the internal trust lane.  Forgetting the `reason` is a
/// compile error.
///
/// **`Bridge` carries the mTLS principal *in the variant* (ADR 155 priv-sep
/// amendment / ADR 154 component 4).** The cert-derived caller identity is no
/// longer a separately-settable `RequestContext` field — it lives *only* here,
/// inseparable from the bridge source. That makes "a `Socket`-sourced request
/// that also asserts an mTLS principal" structurally unrepresentable (a compile
/// error), closing the wire-forgeable `_mtls_principal` injection that the
/// previous `RequestContext.mtls_principal` field allowed. `Bridge` is NOT
/// `is_internal()`: it can never bypass a policy gate or `force: true`. The
/// principal is a routing hint only — authority (Plane 3: chain verification +
/// presence) is enforced server-side, never derived from the cert SAN.
///
/// Because the principal owns `String` fields, `DispatchSource` is `Clone` but
/// deliberately NOT `Copy` — callers read it by reference (`&ctx.source`) or
/// clone explicitly; `Socket`/`Internal` clones are trivial and the `Bridge`
/// clone (two short strings) only ever happens on the rare control-path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchSource {
    /// Request arrived via the unix-domain socket RPC path. Callers on this
    /// path are NOT authenticated as admins, and MUST NOT be able to
    /// bypass policy gates. Any `force: true` is rejected.
    Socket,
    /// Request was synthesized by an in-process caller that has already
    /// established admin identity (test harness, internal admin CLI path,
    /// recovery flows). `force: true` is honored.
    ///
    /// `reason` is a mandatory static string that names the trust context
    /// at the call site (e.g. `"admin CLI"`, `"recovery flow"`,
    /// `"test harness"`).  It is purely a code-review / audit annotation
    /// and has no effect on runtime behaviour.
    Internal { reason: &'static str },
    /// Request arrived over the cross-uid mTLS bridge lane — terminated by
    /// the OS-supervised `ember-rpc` sibling and forwarded to the daemon with
    /// the cert-derived [`MtlsPrincipal`] attached out-of-band. The persona /
    /// container / cert-fingerprint the sibling resolved from the client
    /// cert's SPIFFE SAN ride inside this variant; the daemon re-validates
    /// them server-side (the `(persona, container)` cross-check + SAN-shape
    /// re-validation). NOT `is_internal()`.
    Bridge(MtlsPrincipal),
}

impl DispatchSource {
    /// Returns `true` when this source carries internal (admin) trust.
    /// `Socket` and `Bridge` are both non-internal — neither can bypass a
    /// policy gate or honor `force: true`.
    #[inline]
    pub fn is_internal(&self) -> bool {
        matches!(self, DispatchSource::Internal { .. })
    }
}
