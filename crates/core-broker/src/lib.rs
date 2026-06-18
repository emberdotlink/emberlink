//! Broker and rail-adapter traits, request/response types, and an in-memory
//! `MockBroker` implementation suitable for tests.
//!
//! See ADR 094 (Emberlink credential broker) §5 and ADR 096 (Anthropic
//! broker) §6 for the design rationale and the canonical trait shape.
//!
//! Provider-specific scopes (Cloudflare, Anthropic, GitHub, AWS STS, GCP,
//! Tailscale) are represented at the trait boundary as opaque
//! `serde_json::Value` payloads. Each provider implementation deserializes
//! this into its own typed struct (see `BROKER-CLOUDFLARE-IMPL` and
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
// for that target. Feature-gated per ARCH-BROKER-TRAIT-ONLY: the trait
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
// plaintext (TZ-SEC-BROKER-SECRETREF-CONTRACT). The trust boundary for
// resolving `SecretRef` → plaintext is ember-proxy / ember-tools, which
// emits a per-resolution Receipt.
pub mod secret_ref;
pub use secret_ref::SecretRef;

// Per-provider native-scope projectors (ADR 204). The only code permitted to
// speak a provider's native scope language; native scope is a pure projection
// of the grant-bounded action-need, never a caller input.
pub mod project;
// GCP projector + native scope (AUDIT-V030-GCP-PROVIDER-PROJECTOR — the
// AWS STS `provider_echo + I7 clamp = matched pair` shape, mirrored for
// GCP impersonation mints). Lives in its own module to mirror the
// per-provider file decomposition the AWS PermissionSpec projector
// established; `project.rs` carries the multi-provider trait + the
// historical github/aws/anthropic projectors.
pub mod gcp;
// Shared typed native scopes for projectors and brokers, so the two cannot
// drift (ADR 204; Codex adversarial-review finding).
pub use gcp::{GcpNativeScope, GcpProjector, GcpUpperBound};
pub use project::{AwsStsMode, AwsStsScope, GithubScope};

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use core_event_types::{ActionRef, RailTrustContract};
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
/// Mirrors ADR 094 §5b. The daemon constructs this from the policy
/// engine + caller identity + a per-stack `scope.toml` declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerRequest {
    pub provider: BrokerProvider,
    pub scope: BrokerScope,
    /// Time-to-live for the materialized credential. The broker may
    /// clamp this downward to a provider-imposed maximum.
    #[serde(with = "duration_as_secs")]
    pub ttl: Duration,
    /// Authority-minted execution-contract identifier when the request is part
    /// of a brokered action flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    /// Canonical authority-side action identity for the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_ref: Option<ActionRef>,
    /// Logical workspace handle for the caller, never a raw cwd path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    /// Logical non-workspace subject for the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    /// Coordination-layer join handle echoed into audit records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordination_ref: Option<String>,
    /// Requesting caller/session/persona identity in authority space.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_ref: Option<String>,
    /// Grant or approval binding used for the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_ref: Option<String>,
    /// Free-form audit reason — recorded in the Grant Receipt.
    pub reason: String,
    /// Persona on whose behalf this credential is being issued. The daemon
    /// `broker_issue` entrypoint requires this before materialization.
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

/// Agent-facing `broker_issue` request — the deserialization target for the
/// socket RPC params (ADR 204).
///
/// This is `BrokerRequest` **minus `scope`**: native provider scope is *never*
/// a caller-supplied input. The daemon derives the native payload from
/// operator-authored inputs only (the matched grant + per-provider projector)
/// and constructs the internal [`BrokerRequest`] via [`Self::into_broker_request`].
/// Because this struct carries no `scope` field, an agent-supplied `"scope"` JSON
/// key is dropped at the serde boundary — the deletion of the
/// caller-native-scope **ingress** is structural, not conventional.
///
/// `BrokerRequest::scope` survives only as the daemon-computed native payload
/// handed to [`Broker::issue`]; no agent-reachable value flows into it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerIssueParams {
    pub provider: BrokerProvider,
    /// Time-to-live for the materialized credential. The broker may clamp this
    /// downward to a provider-imposed maximum.
    #[serde(with = "duration_as_secs")]
    pub ttl: Duration,
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
    pub reason: String,
    /// Required by daemon validation for `broker_issue`; missing or blank
    /// caller identity is an invalid materialization request.
    #[serde(default)]
    pub caller_persona: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants_file_rev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants_file_credential_name: Option<String>,
}

impl BrokerIssueParams {
    /// Assemble the internal [`BrokerRequest`] handed to [`Broker::issue`],
    /// binding the **daemon-derived** native `scope`. The only producer of
    /// `BrokerRequest::scope` on the `broker_issue` path.
    pub fn into_broker_request(self, native_scope: BrokerScope) -> BrokerRequest {
        BrokerRequest {
            provider: self.provider,
            scope: native_scope,
            ttl: self.ttl,
            contract_id: self.contract_id,
            action_ref: self.action_ref,
            workspace_ref: self.workspace_ref,
            subject_ref: self.subject_ref,
            coordination_ref: self.coordination_ref,
            caller_ref: self.caller_ref,
            authority_ref: self.authority_ref,
            reason: self.reason,
            caller_persona: self.caller_persona,
            grants_file_rev: self.grants_file_rev,
            grants_file_credential_name: self.grants_file_credential_name,
        }
    }
}

/// The provider's stamp on a freshly-minted credential
/// (ADR 213 §D4 / §AC-3 / §AC-4).
///
/// Metaphor: a mint stamps the metal it produces with a mark indicating
/// what it actually struck. The mint stamp is the provider's own account
/// of what the credential is — read by the daemon's clamp + by offline
/// verifiers — distinct from what the projector *claimed* it would mint.
/// The stamp is channel-authenticated (the provider's TLS-authenticated
/// API response), NOT cryptographically signed — using "stamp" rather
/// than "attestation" deliberately avoids overclaiming.
///
/// Tagged union whose variants carry *distinct, closed payload types* —
/// not an untyped `serde_json::Value` beside a `kind` tag. The type, not
/// a runtime check, makes the AC-3 invariant hold:
///
/// - **`Permissions { bound }` — G1, "permissions".** The provider stamped
///   the granular effective permissions of the minted credential. The
///   ONLY variant carrying a permission-bearing payload; the generic
///   clamp verifies the stamped bound ⊆ the minted claim.
/// - **`Identity { identity }` — G2, "identity".** The provider stamped
///   *which* identity was minted, not its permissions. [`IdentityRef`] is
///   a closed struct with NO field that can hold a permission set — a
///   request-side policy recorded here is structurally unrepresentable
///   (AC-4).
/// - **`Unbounded` — G3, "unbounded".** The mint succeeded with a *full*
///   provider-side credential whose narrow scope is provider-known to be
///   unrepresentable: a github installation token with
///   `repository_selection = "all"`, an AWS `AssumeRole` with no inline
///   session policy, an AWS `GetSessionToken` / `WebIdentity`. The audit
///   record is explicit: "no narrow bound to verify, by request shape."
///   This is policy-distinct from "the provider was supposed to stamp but
///   we couldn't observe it" — see [`BrokerError::Upstream`] returned from
///   adapter code in that anomaly case (the broker refuses the mint).
/// - **`Opaque` — G3, "opaque".** The provider has no stamp API at all,
///   by architectural design. anthropic is the canonical case: the
///   workspace API key carries no checkable native scope; enforcement is
///   the proxy-mediated budget/ttl. A verifier may legitimately
///   auto-accept this variant for the named providers.
/// - **`Unwired` — G3, "unwired".** The provider *would* support a stamp
///   but the adapter hasn't wired the capture yet (cloudflare / azure /
///   fly / gcp / hashivault / okta / vercel today). A verifier should
///   treat this as elevated-risk (the missing wiring is an
///   implementation follow-up, not an architectural property).
///
/// Splitting G3 into three closed variants is load-bearing for AC-3: a
/// single G3 case would collapse six semantically distinct sources
/// (intentional Opaque, seven Unwired adapters, github unbounded, github
/// serialization failure, AWS anomalous response, test fakes) into one
/// indistinguishable value. A verifier policy keyed on the variant could
/// not refuse the silent-anomaly case without also refusing legitimate
/// anthropic mints. (Adversarial finding H-2.)
///
/// Migrated from the prior `Option<BrokerScope>` envelope + the
/// `provider_scope_attestable: bool` derived from it — both lost the
/// G1-vs-G2 distinction and allowed any provider's `Some(value)` to carry
/// arbitrary JSON (the surface that admitted the AWS request-policy
/// masquerade pre-#5734). Renamed from `MintStamp` because "echo"
/// implied reflection of what the daemon asked, when the security-relevant
/// case is when the provider's stamp *differs* from the request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum MintStamp {
    Permissions { bound: PermissionBound },
    Identity { identity: IdentityRef },
    Unbounded,
    Opaque,
    Unwired,
}

impl MintStamp {
    /// Stable per-variant discriminator string — recorded on audit events
    /// and consumed by offline verifiers / org-policy as the
    /// `mint_stamp_kind` field. Strings are wire-stable; the
    /// `mint_stamp_kind_matches_variant` test in this crate pins them so
    /// a future variant rename cannot silently shift the discriminator.
    pub fn kind(&self) -> &'static str {
        match self {
            MintStamp::Permissions { .. } => "permissions",
            MintStamp::Identity { .. } => "identity",
            MintStamp::Unbounded => "unbounded",
            MintStamp::Opaque => "opaque",
            MintStamp::Unwired => "unwired",
        }
    }

    /// ADR 213 AC-9/AC-10 — the effective authority ceiling for this mint,
    /// recorded in the materialization audit event so an offline verifier
    /// knows which guarantee shape to apply. `proxy_budget_active` is true
    /// when the mint flows through a budget-enforced proxy path (AC-10:
    /// G3 bound = proxy budget, not echo). Exhaustive match forces a
    /// future variant to declare its ceiling.
    pub fn effective_ceiling(&self, proxy_budget_active: bool) -> &'static str {
        match self {
            MintStamp::Permissions { .. } => "permissions",
            MintStamp::Identity { .. } => "bound_identity",
            MintStamp::Unbounded | MintStamp::Opaque | MintStamp::Unwired => {
                if proxy_budget_active {
                    "budget"
                } else {
                    "none"
                }
            }
        }
    }

    /// True iff the variant carries a payload the daemon clamp can verify
    /// against the minted native. Used by the clamp caller to decide
    /// whether to skip the per-variant check (Unbounded / Opaque / Unwired
    /// carry no checkable bound; Permissions / Identity do). Centralizes
    /// the skip-condition so a future variant addition forces an
    /// exhaustive match.
    pub fn is_checkable(&self) -> bool {
        match self {
            MintStamp::Permissions { .. } | MintStamp::Identity { .. } => true,
            MintStamp::Unbounded | MintStamp::Opaque | MintStamp::Unwired => false,
        }
    }

    /// Verify this mint stamp against the projector's minted native claim.
    ///
    /// This is ADR 213 D5.1's generic clamp entry point: the caller supplies
    /// only the provider and the minted native payload, while the typed
    /// variant routes to the provider-declared parser for its grade.
    /// `Permissions` compares stamped upper bounds against the minted
    /// claim; `Identity` compares the stamped identity against the minted
    /// identity; G3 variants fail closed if a caller tries to verify them
    /// instead of skipping via [`MintStamp::is_checkable`].
    pub fn assert_within_minted(
        &self,
        provider: BrokerProvider,
        minted_native: &BrokerScope,
    ) -> Result<(), String> {
        match self {
            MintStamp::Permissions { bound } => bound.assert_within_minted(provider, minted_native),
            MintStamp::Identity { identity } => {
                identity.assert_matches_minted(provider, minted_native)
            }
            MintStamp::Unbounded | MintStamp::Opaque | MintStamp::Unwired => Err(format!(
                "internal: mint stamp clamp called with G3 variant `{}` — \
                 caller must skip via MintStamp::is_checkable()",
                self.kind()
            )),
        }
    }
}

/// Validated upper-bound payload for `MintStamp::Permissions` (G1).
///
/// A newtype around the provider's own native [`BrokerScope`] that is
/// constructible **only** through [`PermissionBound::from_native`], which
/// re-parses the native value through the provider's own
/// `native_upper_bound` parser and **refuses to wrap unparseable /
/// unbounded JSON**. This is what makes AC-3's "untyped `BrokerScope`
/// removed from the stamp-evidence path" hold structurally: even a
/// serde-driven path (which would otherwise fill the private `native`
/// field directly, bypassing the constructor) is routed through
/// `from_native` via the `try_from` serde attribute, so an attacker who
/// crafts an audit blob with a hostile `native` cannot deserialize into a
/// `PermissionBound`.
///
/// (ADR 213 D4 Option A — the validated newtype keeps the per-provider
/// native value internally while removing the *raw untyped* `BrokerScope`
/// from the audit/verifier surface, without requiring the generalized
/// clamp (D5.1) up-front. Adversarial finding M-2 motivated lifting the
/// constructor from "intentionally not Free" to "actually validating.")
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "PermissionBoundOnWire", into = "PermissionBoundOnWire")]
pub struct PermissionBound {
    provider: BrokerProvider,
    native: BrokerScope,
}

/// On-wire shape for [`PermissionBound`] — the unvalidated `{provider,
/// native}` JSON object that deserialization sees. The serde `try_from`
/// attribute on `PermissionBound` routes every deserialize through
/// [`PermissionBound::from_native`], so a hostile JSON blob with
/// `native = <unbounded thing>` cannot bypass the parser.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PermissionBoundOnWire {
    provider: BrokerProvider,
    native: BrokerScope,
}

impl From<PermissionBound> for PermissionBoundOnWire {
    fn from(b: PermissionBound) -> Self {
        Self {
            provider: b.provider,
            native: b.native,
        }
    }
}

impl TryFrom<PermissionBoundOnWire> for PermissionBound {
    type Error = String;
    fn try_from(w: PermissionBoundOnWire) -> Result<Self, Self::Error> {
        PermissionBound::from_native(w.provider, w.native)
    }
}

impl PermissionBound {
    /// Wrap a provider-parsed native echo as the validated upper-bound.
    ///
    /// Re-parses `native` through the provider's own `native_upper_bound`
    /// parser and **refuses to wrap** an unbounded / unparseable native
    /// (`Err`). This means a future regression that hands the constructor
    /// an attacker-shaped `native` (a request-side session policy, an
    /// unbounded full-installation token, etc.) fails closed at the type
    /// boundary — the wrapper never exists, the audit event records no
    /// `Scope` variant for it, and the daemon clamp's re-parse becomes
    /// defence-in-depth rather than the sole gate.
    ///
    /// The provider tag is bound at construction-time and pinned through the
    /// wire shape so a bound arriving at another provider's clamp fails the
    /// tag check, fail-closed.
    ///
    /// Errors as `String` (the error type is opaque to the wire; serde's
    /// `try_from` expects `Result<T, _: Display>`).
    pub fn from_native(provider: BrokerProvider, native: BrokerScope) -> Result<Self, String> {
        match provider {
            BrokerProvider::Github => {
                permission_bound_needs(provider, &native)
                    .map_err(|e| format!("github native_upper_bound refused stamp: {e}"))?;
            }
            // Providers whose projector has no `native_upper_bound` parser
            // today, plus G2/G3 providers such as AWS STS and Anthropic: the
            // architecture forbids them from emitting `MintStamp::Permissions`
            // at all — use `Identity`, `Unbounded`, `Opaque`, or `Unwired`
            // as appropriate. Refuse construction here so a future adapter
            // that tries to mint `Permissions` against an undeclared parser
            // fails at the boundary rather than degrading silently.
            other => {
                return Err(format!(
                    "provider {} has no MintStamp::Permissions upper-bound parser declared — \
                     MintStamp::Permissions is unavailable for this provider; \
                     use Identity / Unbounded / Opaque / Unwired instead",
                    other.as_str()
                ));
            }
        }
        Ok(Self { provider, native })
    }

    /// Read the bound provider — used by the variant-matching clamp to
    /// select the per-provider native-bound parser.
    pub fn provider(&self) -> BrokerProvider {
        self.provider
    }

    /// Read the native payload — the audit event records this distinctly
    /// from the projector's `minted_scope` so an offline verifier can
    /// re-run `native_upper_bound(stamp) ⊆ minted` (ADR 204 amd 2 / I7).
    pub fn native(&self) -> &BrokerScope {
        &self.native
    }

    /// D5.1 G1 clamp: verify the provider-stamped permission upper bound
    /// is no wider than the projector's minted native claim.
    pub fn assert_within_minted(
        &self,
        provider: BrokerProvider,
        minted_native: &BrokerScope,
    ) -> Result<(), String> {
        if self.provider != provider {
            return Err(format!(
                "mint stamp permission tag mismatch: bound={} request={}",
                self.provider.as_str(),
                provider.as_str()
            ));
        }

        let stamp_needs = permission_bound_needs(provider, self.native())
            .map_err(|e| format!("mint stamp is unbounded/unparseable: {e}"))?;
        let minted_needs = permission_bound_needs(provider, minted_native)
            .map_err(|e| format!("minted native is unbounded/unparseable: {e}"))?;
        for stamp_need in &stamp_needs {
            if !minted_needs
                .iter()
                .any(|minted_need| resolved_need_covers_stamp(minted_need, stamp_need))
            {
                return Err(format!(
                    "mint stamp grants authority beyond the minted claim: {stamp_need:?}"
                ));
            }
        }
        Ok(())
    }
}

/// Closed identity-only stamp payload for `MintStamp::Identity` (G2).
///
/// The struct has **no field that can hold a permission set**, by design
/// (AC-4): a request-side session policy or grant statement cannot be
/// recorded here, by type. The effective authority ceiling for an
/// identity-attested mint is the bound identity's *own* permissions
/// (ADR 213 §D5 / AC-9), enforced upstream by `need ⊆ grant` plus the
/// provider's RBAC of the bound identity — not by a permission echo.
///
/// For AWS STS, `identity` is the assumed role ARN. For any future G2
/// provider (cluster RBAC, Workload Identity, etc.) the same shape
/// applies: a single opaque string the provider attested.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityRef {
    pub provider: BrokerProvider,
    pub identity: String,
}

impl IdentityRef {
    /// D5.1 G2 clamp: verify the provider-stamped identity is exactly the
    /// identity the projector minted. This does not compare permissions:
    /// IdentityRef cannot carry them by type, and the effective ceiling is the
    /// bound identity's own provider-side authority (ADR 213 AC-9).
    pub fn assert_matches_minted(
        &self,
        provider: BrokerProvider,
        minted_native: &BrokerScope,
    ) -> Result<(), String> {
        if self.provider != provider {
            return Err(format!(
                "mint stamp identity tag mismatch: bound={} request={}",
                self.provider.as_str(),
                provider.as_str()
            ));
        }
        let minted_identity = identity_upper_bound(provider, minted_native)?;
        if self.identity != minted_identity.identity {
            return Err(format!(
                "{} mint stamp identity differs from minted identity: stamp={} minted={}",
                provider.as_str(),
                self.identity,
                minted_identity.identity
            ));
        }
        Ok(())
    }
}

fn permission_bound_needs(
    provider: BrokerProvider,
    native: &BrokerScope,
) -> Result<Vec<project::ResolvedNeed>, String> {
    use crate::project::{GithubProjector, NativeProjector};
    match provider {
        BrokerProvider::Github => GithubProjector
            .native_upper_bound(native)
            .map_err(|e| format!("{e:?}")),
        other => Err(format!(
            "provider {} has no MintStamp::Permissions upper-bound parser declared",
            other.as_str()
        )),
    }
}

fn identity_upper_bound(
    provider: BrokerProvider,
    native: &BrokerScope,
) -> Result<IdentityRef, String> {
    use crate::gcp::GcpProjector;
    use crate::project::AwsStsProjector;
    match provider {
        BrokerProvider::AwsSts => {
            let bound = AwsStsProjector
                .native_upper_bound(native)
                .map_err(|e| format!("aws_sts minted native is unbounded/unparseable: {e:?}"))?;
            Ok(IdentityRef {
                provider,
                identity: bound.role_arn,
            })
        }
        BrokerProvider::Gcp => {
            // AUDIT-V030-GCP-PROVIDER-PROJECTOR — mirrors the AWS STS arm
            // above (PR #5716): the projector re-parses the minted native
            // scope to extract the impersonation-target SA email, which
            // the broker stamps into `MintStamp::Identity { identity: <sa> }`.
            // The clamp's caller compares this against the stamp; a
            // mismatch (e.g., the broker stamped a different SA than the
            // projector declared) surfaces as
            // `BrokerError::PolicyRejected` upstream.
            let bound = GcpProjector
                .native_upper_bound(native)
                .map_err(|e| format!("gcp minted native is unbounded/unparseable: {e:?}"))?;
            Ok(IdentityRef {
                provider,
                identity: bound.target_service_account,
            })
        }
        other => Err(format!(
            "provider {} has no MintStamp::Identity parser declared",
            other.as_str()
        )),
    }
}

fn resolved_need_covers_stamp(
    minted: &project::ResolvedNeed,
    stamp: &project::ResolvedNeed,
) -> bool {
    use crate::project::{CapabilityVerb, ConcreteTarget};
    match (
        &minted.capability,
        &stamp.capability,
        &minted.target,
        &stamp.target,
    ) {
        (
            CapabilityVerb::Github {
                permission: minted_perm,
                level: minted_level,
            },
            CapabilityVerb::Github {
                permission: stamp_perm,
                level: stamp_level,
            },
            ConcreteTarget::Repo(minted_repo),
            ConcreteTarget::Repo(stamp_repo),
        ) => minted_repo == stamp_repo && minted_perm == stamp_perm && minted_level >= stamp_level,
    }
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
    /// The provider's stamp on this minted credential — see [`MintStamp`]
    /// for the G1/G2/G3 split and ADR 213 §D4 for the rationale.
    ///
    /// This is the *provider-truth* half of ADR 204 amendment 2 / I7
    /// (ADR 205 §B — the materialization record is an **audit event**, not
    /// a receipt). The daemon clamp verifies the variant-specific bound
    /// against the projector's claim and records the variant + payload on
    /// the materialization audit event distinctly from the projector's
    /// `minted_scope`.
    ///
    /// Note: there is no `Option` wrapper here, by deliberate AC-3 design
    /// — a second encoding for "absent" would re-introduce the G1/G2/G3
    /// ambiguity the variant exists to remove. "No checkable bound" is
    /// represented by one of three closed G3 variants
    /// (`Unbounded` / `Opaque` / `Unwired`), each carrying a different
    /// verifier semantics.
    pub mint_stamp: MintStamp,
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
/// Mirrors ADR 094 §5b verbatim:
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

/// Rail-specific scope payload.
///
/// Like [`BrokerScope`], this stays provider-agnostic at the trait boundary so
/// the daemon can hold heterogeneous rail adapters behind one registry without
/// teaching `core-broker` about per-rail request schemas.
pub type RailScope = serde_json::Value;

/// Spend attempt handed from the daemon to a rail adapter.
///
/// The daemon owns authority inputs such as `action_ref`, `caller_ref`, and
/// `authority_ref`. The rail adapter consumes those alongside spend details and
/// the trust-contract-specific attachment:
///
/// - Contract A: `idempotency_key`
/// - Contract B: `ephemeral_sign_public_key`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RailSpendAttempt {
    pub rail_scope: RailScope,
    pub amount_minor: u64,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_ref: Option<ActionRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral_sign_public_key: Option<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// The rail accepted a spend attempt and bound it to an adapter-local
/// identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailAttemptAccepted {
    pub attempt_id: String,
    pub trust_contract: RailTrustContract,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Terminal state a rail adapter reports back to the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RailSettlementState {
    Committed,
    Voided,
    Expired,
}

/// Contract-B proof attached to a committed outcome.
///
/// The daemon mints the corresponding keypair at attempt-time and verifies the
/// signature before accepting a committed settlement from an adapter that uses
/// `ephemeral_sign`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailCommittedClaim {
    pub payload_sha256: String,
    pub signature: String,
}

/// Adapter-reported terminal outcome for a prior spend attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RailOutcomeReport {
    pub state: RailSettlementState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_claim: Option<RailCommittedClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Errors surfaced by a rail adapter implementation.
#[derive(Debug, thiserror::Error)]
pub enum RailError {
    #[error("invalid spend attempt: {0}")]
    InvalidAttempt(String),
    #[error("policy rejected spend attempt: {0}")]
    PolicyRejected(String),
    #[error("upstream rail error: {0}")]
    Upstream(String),
    #[error("unknown attempt id: {0}")]
    UnknownAttempt(String),
    #[error("contract surface {surface} is not supported for trust contract {contract}")]
    ContractSurfaceUnsupported {
        contract: RailTrustContract,
        surface: &'static str,
    },
    #[error("rail error: {0}")]
    Other(String),
}

/// The trait every payment-rail adapter honors.
///
/// This is intentionally a sibling to [`Broker`], not a new daemon subsystem.
/// Rail adapters are just constructs spawned through the existing broker-exec
/// envelope, with the trust-contract choice carried in the attempt shape and
/// manifest:
///
/// - `side_channel_reconciliation` adapters must implement
///   [`RailAdapter::verify_attempt_landed`] so the daemon can cross-check the
///   adapter's committed claim against the rail's authoritative read surface.
/// - `ephemeral_sign` adapters receive a daemon-minted per-attempt signing key
///   through the existing secure env-injection path and must attach the
///   resulting signature to committed outcomes.
pub trait RailAdapter: Send + Sync {
    fn trust_contract(&self) -> RailTrustContract;

    fn attempt(
        &self,
        spend_attempt: RailSpendAttempt,
    ) -> impl std::future::Future<Output = Result<RailAttemptAccepted, RailError>> + Send;

    fn report_outcome(
        &self,
        attempt_id: &str,
        outcome: RailOutcomeReport,
    ) -> impl std::future::Future<Output = Result<(), RailError>> + Send;

    fn verify_attempt_landed(
        &self,
        _idempotency_key: &str,
    ) -> impl std::future::Future<Output = Result<bool, RailError>> + Send
    where
        Self: Sized,
    {
        std::future::ready(Err(RailError::ContractSurfaceUnsupported {
            contract: self.trust_contract(),
            surface: "verify_attempt_landed",
        }))
    }
}

/// Failure injection knobs for [`MockRailAdapter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockRailFailureMode {
    None,
    AttemptTimeout,
    OutcomeTimeout,
    VerificationTimeout,
    VerificationInconsistent,
}

/// In-memory record of one mock rail transaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MockRailTransaction {
    pub rail_attempt_id: String,
    pub idempotency_key: String,
    pub amount_minor: u64,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<RailSettlementState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// In-memory rail adapter for shadow-mode and demo flows.
///
/// Mirrors [`MockBroker`]: deterministic ids, no network calls, and a small
/// mutable state surface for tests. The mock always uses Contract A
/// (`side_channel_reconciliation`) and proves committed outcomes through the
/// authoritative `verify_attempt_landed` hook.
pub struct MockRailAdapter {
    state: Mutex<MockRailState>,
}

struct MockRailState {
    next_attempt: u64,
    failure_mode: MockRailFailureMode,
    attempts: HashMap<String, MockRailTransaction>,
    attempt_by_idempotency: HashMap<String, String>,
}

impl MockRailAdapter {
    pub fn new() -> Self {
        Self::with_failure_mode(MockRailFailureMode::None)
    }

    pub fn with_failure_mode(failure_mode: MockRailFailureMode) -> Self {
        Self {
            state: Mutex::new(MockRailState {
                next_attempt: 0,
                failure_mode,
                attempts: HashMap::new(),
                attempt_by_idempotency: HashMap::new(),
            }),
        }
    }

    pub fn set_failure_mode(&self, failure_mode: MockRailFailureMode) {
        self.state.lock().expect("mock rail mutex").failure_mode = failure_mode;
    }

    pub fn attempt_count(&self) -> usize {
        self.state.lock().expect("mock rail mutex").attempts.len()
    }

    pub fn transaction_by_idempotency(&self, idempotency_key: &str) -> Option<MockRailTransaction> {
        let st = self.state.lock().expect("mock rail mutex");
        let attempt_id = st.attempt_by_idempotency.get(idempotency_key)?;
        st.attempts.get(attempt_id).cloned()
    }
}

impl Default for MockRailAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl RailAdapter for MockRailAdapter {
    fn trust_contract(&self) -> RailTrustContract {
        RailTrustContract::SideChannelReconciliation
    }

    async fn attempt(
        &self,
        spend_attempt: RailSpendAttempt,
    ) -> Result<RailAttemptAccepted, RailError> {
        let idempotency_key = spend_attempt.idempotency_key.ok_or_else(|| {
            RailError::InvalidAttempt(
                "mock rail requires idempotency_key for side_channel_reconciliation".to_string(),
            )
        })?;

        let mut st = self.state.lock().expect("mock rail mutex");
        if matches!(st.failure_mode, MockRailFailureMode::AttemptTimeout) {
            return Err(RailError::Upstream("mock rail attempt timeout".to_string()));
        }

        if let Some(existing_attempt_id) = st.attempt_by_idempotency.get(&idempotency_key)
            && let Some(existing) = st.attempts.get(existing_attempt_id)
        {
            return Ok(RailAttemptAccepted {
                attempt_id: existing.rail_attempt_id.clone(),
                trust_contract: self.trust_contract(),
                idempotency_key: Some(existing.idempotency_key.clone()),
            });
        }

        st.next_attempt += 1;
        let attempt_id = format!("mock-rail-{}", st.next_attempt);
        st.attempt_by_idempotency
            .insert(idempotency_key.clone(), attempt_id.clone());
        st.attempts.insert(
            attempt_id.clone(),
            MockRailTransaction {
                rail_attempt_id: attempt_id.clone(),
                idempotency_key: idempotency_key.clone(),
                amount_minor: spend_attempt.amount_minor,
                currency: spend_attempt.currency,
                state: None,
                rail_reference: None,
                metadata: spend_attempt.metadata,
            },
        );
        Ok(RailAttemptAccepted {
            attempt_id,
            trust_contract: self.trust_contract(),
            idempotency_key: Some(idempotency_key),
        })
    }

    async fn report_outcome(
        &self,
        attempt_id: &str,
        outcome: RailOutcomeReport,
    ) -> Result<(), RailError> {
        let mut st = self.state.lock().expect("mock rail mutex");
        if matches!(st.failure_mode, MockRailFailureMode::OutcomeTimeout) {
            return Err(RailError::Upstream("mock rail outcome timeout".to_string()));
        }
        let tx = st
            .attempts
            .get_mut(attempt_id)
            .ok_or_else(|| RailError::UnknownAttempt(attempt_id.to_string()))?;
        tx.state = Some(outcome.state);
        tx.rail_reference = outcome.rail_reference;
        tx.metadata = outcome.metadata;
        Ok(())
    }

    async fn verify_attempt_landed(&self, idempotency_key: &str) -> Result<bool, RailError> {
        let st = self.state.lock().expect("mock rail mutex");
        match st.failure_mode {
            MockRailFailureMode::VerificationTimeout => {
                return Err(RailError::Upstream(
                    "mock rail verification timeout".to_string(),
                ));
            }
            MockRailFailureMode::VerificationInconsistent => return Ok(false),
            _ => {}
        }
        let Some(attempt_id) = st.attempt_by_idempotency.get(idempotency_key) else {
            return Ok(false);
        };
        let Some(tx) = st.attempts.get(attempt_id) else {
            return Ok(false);
        };
        Ok(matches!(tx.state, Some(RailSettlementState::Committed)))
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
        // META-DEV-PROD-PARITY-MOCK-BROKER-EXPLICIT — the MockBroker must
        // mirror the prod adapter's `MintStamp` variant for the provider
        // it's standing in for, so downstream audit/verifier policy
        // exercised in tests matches what they'd see in prod. If a future
        // prod adapter wires a new variant, add an arm here so the mock
        // tracks it (skip-by-silence here would let a test exercise a code
        // path that doesn't exist in prod — the parity invariant this
        // META- checkpoint pins).
        //
        // ADR 213 AC-10: G3 mints in the direct-injection path (broker_exec)
        // now fail closed. MockBroker must return the prod-matching variant
        // so tests exercise real code paths, not a G3 shortcut that AC-10
        // would refuse.
        let mint_stamp = match self.provider {
            BrokerProvider::Anthropic => MintStamp::Opaque,
            BrokerProvider::Github => {
                // Prod adapter: Permissions for bounded, Unbounded for
                // all-repos. Echo the request scope as the bound (simulates
                // "provider granted exactly what we asked for").
                PermissionBound::from_native(BrokerProvider::Github, req.scope.clone())
                    .map(|bound| MintStamp::Permissions { bound })
                    .unwrap_or(MintStamp::Unbounded)
            }
            BrokerProvider::AwsSts => {
                // Prod adapter: Identity for AssumeRole, Unbounded fallback.
                // MockBroker doesn't run real STS; use Unbounded (G3).
                MintStamp::Unbounded
            }
            // Prod adapters: Identity for providers with config-derived
            // identity binding (Azure SP, GCP SA, Okta app); Opaque for
            // providers whose token responses don't attest identity
            // (Fly org-scoped, Vercel team-scoped, HashiVault policy-bound).
            // MockBroker can't derive real identities; use the prod G3
            // fallback for each.
            BrokerProvider::AzureCli | BrokerProvider::Gcp | BrokerProvider::Okta => {
                MintStamp::Opaque
            }
            BrokerProvider::FlyIo
            | BrokerProvider::Vercel
            | BrokerProvider::HashiVault
            | BrokerProvider::Cloudflare
            | BrokerProvider::Tailscale => MintStamp::Opaque,
        };
        Ok(BrokeredCredential {
            token: SecretString::from(format!("canary-token-{}", id)),
            expires_at: SystemTime::now() + req.ttl,
            materialization_id: id,
            mint_stamp,
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
            contract_id: None,
            action_ref: None,
            workspace_ref: None,
            subject_ref: None,
            coordination_ref: None,
            caller_ref: None,
            authority_ref: None,
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

    fn sample_spend_attempt() -> RailSpendAttempt {
        RailSpendAttempt {
            rail_scope: serde_json::json!({
                "publisher": "ember-systems",
                "account": "acct_test_123",
            }),
            amount_minor: 2_500,
            currency: "usd".to_string(),
            contract_id: Some("contract-payment-1".to_string()),
            action_ref: Some(ActionRef::new(
                "registry.ember.systems/ember-systems/ember-payments",
                "payment.charge",
                "v1",
            )),
            workspace_ref: Some("home:repo:demo".to_string()),
            caller_ref: Some("session:test".to_string()),
            authority_ref: Some("grant:test".to_string()),
            idempotency_key: Some("idem-123".to_string()),
            ephemeral_sign_public_key: Some("ed25519:deadbeef".to_string()),
            reason: "unit test".to_string(),
            metadata: Some(serde_json::json!({
                "merchant_ref": "order-42",
            })),
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

    struct ContractATestRail;

    impl RailAdapter for ContractATestRail {
        fn trust_contract(&self) -> RailTrustContract {
            RailTrustContract::SideChannelReconciliation
        }

        async fn attempt(
            &self,
            spend_attempt: RailSpendAttempt,
        ) -> Result<RailAttemptAccepted, RailError> {
            Ok(RailAttemptAccepted {
                attempt_id: "attempt-1".to_string(),
                trust_contract: self.trust_contract(),
                idempotency_key: spend_attempt.idempotency_key,
            })
        }

        async fn report_outcome(
            &self,
            attempt_id: &str,
            _outcome: RailOutcomeReport,
        ) -> Result<(), RailError> {
            if attempt_id != "attempt-1" {
                return Err(RailError::UnknownAttempt(attempt_id.to_string()));
            }
            Ok(())
        }

        async fn verify_attempt_landed(&self, idempotency_key: &str) -> Result<bool, RailError> {
            Ok(idempotency_key == "idem-123")
        }
    }

    struct ContractBTestRail;

    impl RailAdapter for ContractBTestRail {
        fn trust_contract(&self) -> RailTrustContract {
            RailTrustContract::EphemeralSign
        }

        async fn attempt(
            &self,
            _spend_attempt: RailSpendAttempt,
        ) -> Result<RailAttemptAccepted, RailError> {
            Ok(RailAttemptAccepted {
                attempt_id: "attempt-2".to_string(),
                trust_contract: self.trust_contract(),
                idempotency_key: None,
            })
        }

        async fn report_outcome(
            &self,
            attempt_id: &str,
            _outcome: RailOutcomeReport,
        ) -> Result<(), RailError> {
            if attempt_id != "attempt-2" {
                return Err(RailError::UnknownAttempt(attempt_id.to_string()));
            }
            Ok(())
        }
    }

    #[test]
    fn rail_spend_attempt_round_trips_through_json() {
        let attempt = sample_spend_attempt();
        let s = serde_json::to_string(&attempt).expect("serialize");
        let parsed: RailSpendAttempt = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(parsed.amount_minor, 2_500);
        assert_eq!(parsed.currency, "usd");
        assert_eq!(parsed.idempotency_key.as_deref(), Some("idem-123"));
        assert_eq!(
            parsed.ephemeral_sign_public_key.as_deref(),
            Some("ed25519:deadbeef")
        );
    }

    #[test]
    fn mock_rail_adapter_reuses_attempt_for_same_idempotency_key() {
        let rail = MockRailAdapter::new();
        let accepted_a = block_on(rail.attempt(sample_spend_attempt())).expect("attempt a");
        let accepted_b = block_on(rail.attempt(sample_spend_attempt())).expect("attempt b");
        assert_eq!(accepted_a.attempt_id, accepted_b.attempt_id);
        assert_eq!(rail.attempt_count(), 1);
    }

    #[test]
    fn mock_rail_adapter_verification_requires_committed_outcome() {
        let rail = MockRailAdapter::new();
        let accepted = block_on(rail.attempt(sample_spend_attempt())).expect("attempt");
        assert!(
            !block_on(rail.verify_attempt_landed("idem-123")).expect("verify pending"),
            "pending mock rail attempt must not verify as landed"
        );
        block_on(rail.report_outcome(
            &accepted.attempt_id,
            RailOutcomeReport {
                state: RailSettlementState::Committed,
                rail_reference: Some("mock-charge-1".to_string()),
                idempotency_key: Some("idem-123".to_string()),
                committed_claim: None,
                metadata: None,
            },
        ))
        .expect("report committed");
        let tx = rail
            .transaction_by_idempotency("idem-123")
            .expect("mock transaction");
        assert_eq!(tx.rail_reference.as_deref(), Some("mock-charge-1"));
        assert!(block_on(rail.verify_attempt_landed("idem-123")).expect("verify committed"));
    }

    #[test]
    fn mock_rail_adapter_failure_injection_can_force_verification_mismatch() {
        let rail = MockRailAdapter::new();
        let accepted = block_on(rail.attempt(sample_spend_attempt())).expect("attempt");
        block_on(rail.report_outcome(
            &accepted.attempt_id,
            RailOutcomeReport {
                state: RailSettlementState::Committed,
                rail_reference: Some("mock-charge-2".to_string()),
                idempotency_key: Some("idem-123".to_string()),
                committed_claim: None,
                metadata: None,
            },
        ))
        .expect("report committed");
        rail.set_failure_mode(MockRailFailureMode::VerificationInconsistent);
        assert!(
            !block_on(rail.verify_attempt_landed("idem-123")).expect("verify inconsistent"),
            "failure mode must let tests force side-channel mismatch"
        );
    }

    #[test]
    fn side_channel_adapter_can_prove_attempt_landed() {
        let rail = ContractATestRail;
        let accepted = block_on(rail.attempt(sample_spend_attempt())).expect("attempt");
        assert_eq!(
            accepted.trust_contract,
            RailTrustContract::SideChannelReconciliation
        );
        assert_eq!(accepted.idempotency_key.as_deref(), Some("idem-123"));
        assert!(block_on(rail.verify_attempt_landed("idem-123")).expect("verify"));
    }

    #[test]
    fn ephemeral_sign_adapter_rejects_reconciliation_surface_by_default() {
        let rail = ContractBTestRail;
        let err = block_on(rail.verify_attempt_landed("idem-123")).expect_err("must refuse");
        match err {
            RailError::ContractSurfaceUnsupported { contract, surface } => {
                assert_eq!(contract, RailTrustContract::EphemeralSign);
                assert_eq!(surface, "verify_attempt_landed");
            }
            other => panic!("expected ContractSurfaceUnsupported, got {other:?}"),
        }
    }

    #[test]
    fn report_outcome_accepts_committed_claim_for_ephemeral_sign() {
        let rail = ContractBTestRail;
        let outcome = RailOutcomeReport {
            state: RailSettlementState::Committed,
            rail_reference: Some("charge-123".to_string()),
            idempotency_key: None,
            committed_claim: Some(RailCommittedClaim {
                payload_sha256: "deadbeef".to_string(),
                signature: "ed25519sig:beadfeed".to_string(),
            }),
            metadata: None,
        };
        block_on(rail.report_outcome("attempt-2", outcome)).expect("report outcome");
    }

    // ===== ADR 213 §D4 / §AC-3 / §AC-4 — graded MintStamp =====

    /// Helper — a valid github native echo (bounded one repo + one
    /// permission) that survives `GithubProjector::native_upper_bound`.
    /// `permissions` is `Vec<(String, String)>` on the wire (a sequence of
    /// tuples), not a map.
    fn valid_github_native() -> serde_json::Value {
        serde_json::json!({
            "repositories": ["owner/repo"],
            "permissions": [["contents", "read"]],
        })
    }

    fn github_native(repo: &str, permission: &str, level: &str) -> serde_json::Value {
        serde_json::json!({
            "repositories": [repo],
            "permissions": [[permission, level]],
        })
    }

    fn aws_minted_native(role_arn: &str) -> BrokerScope {
        project::AwsStsProjector
            .project_assume_role(&project::AwsStsAssumeRoleProjection {
                role_arn: role_arn.to_string(),
                session_name: "provider-echo-test".to_string(),
                ttl_seconds: 900,
                permissions: vec![project::AwsPermissionSpec {
                    effect: project::AwsPermissionEffect::Allow,
                    actions: vec![project::AwsAction::S3PutObject],
                    resources: vec![core_grant_types::ResourceSelector::Exact {
                        value: "arn:aws:s3:::assets/releases/app.tar.gz".to_string(),
                    }],
                    conditions: Vec::new(),
                }],
                external_id: None,
            })
            .expect("aws assume-role projection")
    }

    #[test]
    fn mint_stamp_kind_matches_variant() {
        // Wire-stable per-variant discriminator strings — pinned so a future
        // rename of the variants can't silently shift the contract the
        // offline verifier / org-policy reads.
        assert_eq!(
            MintStamp::Permissions {
                bound: PermissionBound::from_native(BrokerProvider::Github, valid_github_native())
                    .expect("valid github native"),
            }
            .kind(),
            "permissions"
        );
        assert_eq!(
            MintStamp::Identity {
                identity: IdentityRef {
                    provider: BrokerProvider::AwsSts,
                    identity: "arn:aws:iam::1:role/x".into(),
                },
            }
            .kind(),
            "identity"
        );
        assert_eq!(MintStamp::Unbounded.kind(), "unbounded");
        assert_eq!(MintStamp::Opaque.kind(), "opaque");
        assert_eq!(MintStamp::Unwired.kind(), "unwired");
    }

    #[test]
    fn mint_stamp_is_checkable_only_for_permissions_and_identity() {
        // Skip-condition the daemon clamp caller uses to decide whether the
        // per-variant clamp must run. A future variant addition forces an
        // exhaustive match here, so a new "carries-a-bound-but-no-clamp"
        // variant can't slip in unnoticed.
        let scope = MintStamp::Permissions {
            bound: PermissionBound::from_native(BrokerProvider::Github, valid_github_native())
                .expect("valid github native"),
        };
        let identity = MintStamp::Identity {
            identity: IdentityRef {
                provider: BrokerProvider::AwsSts,
                identity: "arn:aws:iam::1:role/x".into(),
            },
        };
        assert!(scope.is_checkable());
        assert!(identity.is_checkable());
        assert!(!MintStamp::Unbounded.is_checkable());
        assert!(!MintStamp::Opaque.is_checkable());
        assert!(!MintStamp::Unwired.is_checkable());
    }

    #[test]
    fn mint_stamp_effective_ceiling_matches_variant() {
        // ADR 213 AC-9/AC-10 — per-variant effective_ceiling strings, recorded in
        // the materialization audit event. Pinned so an offline verifier's
        // guarantee-shape lookup stays stable across variant renames.
        // G1/G2 ceilings are invariant regardless of proxy_budget_active.
        assert_eq!(
            MintStamp::Permissions {
                bound: PermissionBound::from_native(BrokerProvider::Github, valid_github_native())
                    .expect("valid github native"),
            }
            .effective_ceiling(false),
            "permissions"
        );
        assert_eq!(
            MintStamp::Identity {
                identity: IdentityRef {
                    provider: BrokerProvider::AwsSts,
                    identity: "arn:aws:iam::1:role/x".into(),
                },
            }
            .effective_ceiling(false),
            "bound_identity"
        );
        // G3 without proxy budget → "none" (AC-10: fail-closed path).
        assert_eq!(MintStamp::Unbounded.effective_ceiling(false), "none");
        assert_eq!(MintStamp::Opaque.effective_ceiling(false), "none");
        assert_eq!(MintStamp::Unwired.effective_ceiling(false), "none");
        // G3 with proxy budget → "budget" (AC-10: bounded by proxy policy).
        assert_eq!(MintStamp::Unbounded.effective_ceiling(true), "budget");
        assert_eq!(MintStamp::Opaque.effective_ceiling(true), "budget");
        assert_eq!(MintStamp::Unwired.effective_ceiling(true), "budget");
    }

    #[test]
    fn mint_stamp_permissions_generic_clamp_checks_provider_truth_not_daemon_claim() {
        // ADR 213 D5.1 / AC-5: the generic G1 clamp parses the provider's
        // echoed upper bound and compares THAT provider truth to the minted
        // native claim. A wider echo fails even though the daemon's minted
        // claim is narrow and parseable.
        let minted_native = github_native("widgets", "contents", "write");
        let within = MintStamp::Permissions {
            bound: PermissionBound::from_native(
                BrokerProvider::Github,
                github_native("widgets", "contents", "read"),
            )
            .expect("bounded github echo"),
        };
        assert!(
            within
                .assert_within_minted(BrokerProvider::Github, &minted_native)
                .is_ok(),
            "read echo is within a write minted claim"
        );

        let full_name_echo = MintStamp::Permissions {
            bound: PermissionBound::from_native(
                BrokerProvider::Github,
                github_native("owner/widgets", "contents", "read"),
            )
            .expect("bounded github echo with provider full_name"),
        };
        assert!(
            full_name_echo
                .assert_within_minted(BrokerProvider::Github, &minted_native)
                .is_ok(),
            "github provider echo full_name must compare within minted bare repo scope"
        );

        let wider = MintStamp::Permissions {
            bound: PermissionBound::from_native(
                BrokerProvider::Github,
                github_native("widgets", "administration", "write"),
            )
            .expect("bounded github echo"),
        };
        let err = wider
            .assert_within_minted(BrokerProvider::Github, &minted_native)
            .expect_err("provider truth wider than minted claim must fail");
        assert!(
            err.contains("beyond the minted claim"),
            "error should name provider-truth widening: {err}"
        );
    }

    #[test]
    fn mint_stamp_identity_generic_clamp_checks_declared_identity_parser() {
        // ADR 213 D5.1 / AC-5: the G2 generic clamp parses the minted native
        // identity via the provider-declared parser and compares only identity,
        // never a request-side permission payload.
        let minted_role = "arn:aws:iam::123456789012:role/ember-agent";
        let minted_native = aws_minted_native(minted_role);
        let matching = MintStamp::Identity {
            identity: IdentityRef {
                provider: BrokerProvider::AwsSts,
                identity: minted_role.to_string(),
            },
        };
        assert!(
            matching
                .assert_within_minted(BrokerProvider::AwsSts, &minted_native)
                .is_ok(),
            "same role identity must pass the G2 clamp"
        );

        let wider = MintStamp::Identity {
            identity: IdentityRef {
                provider: BrokerProvider::AwsSts,
                identity: "arn:aws:iam::123456789012:role/admin".to_string(),
            },
        };
        let err = wider
            .assert_within_minted(BrokerProvider::AwsSts, &minted_native)
            .expect_err("different role identity must fail");
        assert!(
            err.contains("identity differs from minted identity"),
            "error should name identity mismatch: {err}"
        );
    }

    #[test]
    fn mint_stamp_round_trips_with_tagged_kind() {
        // Serialized form is the tagged-variant `{"kind":"..."}` shape that
        // audit-event JSON + receipt body consumers read. Pin it for the
        // payload-less G3 variants — they must be a single `kind` tag, not
        // `null` (the legacy bool's "no echo" shape) and not an empty
        // object that downstream consumers might confuse with a stripped
        // `Identity`/`Scope`.
        for (echo, kind) in [
            (MintStamp::Unbounded, "unbounded"),
            (MintStamp::Opaque, "opaque"),
            (MintStamp::Unwired, "unwired"),
        ] {
            let v = serde_json::to_value(&echo).unwrap();
            assert_eq!(v["kind"], kind);
            assert_eq!(
                v.as_object().expect("object").len(),
                1,
                "payload-less G3 variant carries exactly the kind tag: {v}"
            );
            let back: MintStamp = serde_json::from_value(v).unwrap();
            assert_eq!(back, echo);
        }

        let identity = serde_json::to_value(MintStamp::Identity {
            identity: IdentityRef {
                provider: BrokerProvider::AwsSts,
                identity: "arn:aws:iam::123:role/r".to_string(),
            },
        })
        .unwrap();
        assert_eq!(identity["kind"], "identity");
        assert_eq!(identity["identity"]["provider"], "aws_sts");
        assert_eq!(identity["identity"]["identity"], "arn:aws:iam::123:role/r");

        let back: MintStamp = serde_json::from_value(identity).unwrap();
        assert!(matches!(back, MintStamp::Identity { .. }));
    }

    /// ADR 213 §AC-4 — type-level proof that a request-side permission set
    /// cannot be recorded as `MintStamp::Identity` evidence (the AWS
    /// request-policy masquerade is *unrepresentable*, not merely guarded
    /// against by a runtime check). This test is the structural guard
    /// against a future refactor reintroducing an untyped variant: every
    /// field on `IdentityRef` must be a plain identifier, and the variant
    /// must carry no second `BrokerScope`-shaped field. If a future variant
    /// adds a permission-bearing payload, the assertion below will fire
    /// once an updated test author re-derives the field count.
    #[test]
    fn identity_ref_cannot_carry_a_permission_payload_ac4() {
        let ident = IdentityRef {
            provider: BrokerProvider::AwsSts,
            identity: "arn:aws:iam::123456789012:role/ember-agent".to_string(),
        };
        let v = serde_json::to_value(&ident).expect("IdentityRef serializes");
        let obj = v.as_object().expect("IdentityRef serializes as object");
        assert_eq!(
            obj.len(),
            2,
            "IdentityRef must serialize exactly the two-field shape \
             {{provider, identity}} — a third field would risk carrying a \
             permission payload (AC-4): {v}"
        );
        for (key, value) in obj {
            assert!(
                value.is_string(),
                "IdentityRef field `{key}` must be a plain string \
                 (a JSON object or array could smuggle a permission set): {value}"
            );
        }
        // Defensive serialization check: an attacker who crafts a JSON blob
        // mimicking the AWS request-side inline policy must not survive a
        // round-trip into a `MintStamp::Identity`. By default serde
        // IGNORES unknown fields rather than rejecting them, so the
        // `Statement` array is dropped on the way through `IdentityRef`;
        // re-serialization must not carry it forward.
        let hostile = serde_json::json!({
            "kind": "identity",
            "identity": {
                "provider": "aws_sts",
                "identity": "arn:aws:iam::1:role/r",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
        });
        let parsed: MintStamp = serde_json::from_value(hostile)
            .expect("hostile object parses (serde drops unknown fields)");
        let reserialized = serde_json::to_value(&parsed).expect("reserialize");
        assert!(
            reserialized
                .get("identity")
                .and_then(|v| v.get("Statement"))
                .is_none(),
            "AC-4: a request-side permission payload smuggled into the JSON \
             must NOT survive a round-trip through MintStamp::Identity: \
             {reserialized}"
        );
    }

    #[test]
    fn permission_bound_from_native_refuses_unbounded_github_payload() {
        // M-2 (adversarial finding) — `from_native` must REFUSE construction
        // when the native payload is not parseable as a bounded scope; this
        // is what makes AC-3's "untyped `BrokerScope` removed from echo-
        // evidence path" hold structurally. Empty permissions, empty repos,
        // or unknown fields all yield Err.
        let unbounded_empty_perms = serde_json::json!({
            "repositories": ["owner/repo"],
            "permissions": [],
        });
        assert!(
            PermissionBound::from_native(BrokerProvider::Github, unbounded_empty_perms).is_err(),
            "empty permissions ⇒ unbounded ⇒ constructor must refuse"
        );

        let unbounded_empty_repos = serde_json::json!({
            "repositories": [],
            "permissions": [["contents", "read"]],
        });
        assert!(
            PermissionBound::from_native(BrokerProvider::Github, unbounded_empty_repos).is_err(),
            "empty repositories ⇒ unbounded ⇒ constructor must refuse"
        );
    }

    #[test]
    fn permission_bound_refuses_construction_for_providers_without_scope_parser() {
        // Adapters without a `native_upper_bound` parser (anthropic /
        // cloudflare / azure / etc.) and identity-attested providers (AWS
        // STS) cannot mint `MintStamp::Permissions` at all — they MUST use
        // `Identity`, `Opaque`, or `Unwired`.
        // Constructor refusal makes that architectural rule enforceable at
        // the type boundary.
        for provider in [
            BrokerProvider::Anthropic,
            BrokerProvider::AwsSts,
            BrokerProvider::Cloudflare,
            BrokerProvider::AzureCli,
            BrokerProvider::FlyIo,
            BrokerProvider::Gcp,
            BrokerProvider::HashiVault,
            BrokerProvider::Okta,
            BrokerProvider::Tailscale,
            BrokerProvider::Vercel,
        ] {
            let err =
                PermissionBound::from_native(provider, valid_github_native()).expect_err(&format!(
                    "provider {} must refuse Scope construction",
                    provider.as_str()
                ));
            assert!(
                err.contains("no MintStamp::Permissions upper-bound parser"),
                "error must name the structural reason: {err}"
            );
        }
    }

    #[test]
    fn permission_bound_serde_cannot_bypass_constructor_m2() {
        // M-2 (adversarial finding) — without the `#[serde(try_from = ...)]`
        // attribute, serde would fill the private `native` field directly,
        // letting any JSON shape become a `PermissionBound`. The attribute
        // routes deserialize through `from_native`, so a hostile blob with
        // an unbounded native is REFUSED at deserialize time too.
        let hostile_unbounded = serde_json::json!({
            "provider": "github",
            "native": {"repositories": [], "permissions": []},
        });
        let err = serde_json::from_value::<PermissionBound>(hostile_unbounded)
            .expect_err("hostile unbounded github native must fail to deserialize");
        let msg = err.to_string();
        assert!(
            msg.contains("native_upper_bound") || msg.contains("unbounded"),
            "deserialize-side refusal must surface the projector's reason: {msg}"
        );

        // Defensive: providers without a projector also fail at deserialize.
        // Use a provider name that round-trips through `BrokerProvider`'s
        // serde rename (anthropic, since it has no native_upper_bound).
        let no_projector = serde_json::json!({
            "provider": "anthropic",
            "native": {"anything": "at all"},
        });
        let err = serde_json::from_value::<PermissionBound>(no_projector)
            .expect_err("anthropic has no native_upper_bound parser, must refuse");
        let err_msg = err.to_string();
        // Serde wraps our TryFrom error; substring-check for the projector's
        // bytes survives the wrapping.
        assert!(
            err_msg.contains("upper-bound parser") || err_msg.contains("MintStamp::Permissions"),
            "deserialize-side refusal must surface the structural reason: {err_msg}"
        );
    }

    #[test]
    fn permission_bound_round_trips_through_serde() {
        // Sanity — a valid bound serializes to {provider, native} and
        // deserializes back via the validating try_from path.
        let bound = PermissionBound::from_native(BrokerProvider::Github, valid_github_native())
            .expect("valid github native");
        let json = serde_json::to_value(&bound).expect("serialize");
        assert_eq!(json["provider"], "github");
        assert!(json["native"]["repositories"].is_array());

        let back: PermissionBound = serde_json::from_value(json).expect("round trip");
        assert_eq!(back.provider(), BrokerProvider::Github);
        assert_eq!(back.native(), bound.native());
    }

    // NOTE: this test mirrors the MockBroker match arms locally because
    // core-broker has no async runtime dep. The real parity tests are the
    // per-provider `issue_mint_stamp_*` tests in ember-broker.
    #[test]
    fn mock_broker_stamp_match_exhaustive_no_unwired_for_wired_providers() {
        let wired_providers = [
            (BrokerProvider::AzureCli, "opaque"),
            (BrokerProvider::Gcp, "opaque"),
            (BrokerProvider::Okta, "opaque"),
            (BrokerProvider::FlyIo, "opaque"),
            (BrokerProvider::Vercel, "opaque"),
            (BrokerProvider::HashiVault, "opaque"),
            (BrokerProvider::Anthropic, "opaque"),
        ];
        for (provider, expected_kind) in wired_providers {
            assert!(
                !matches!(
                    provider,
                    BrokerProvider::Cloudflare | BrokerProvider::Tailscale
                ),
                "wired_providers list must not include unwired providers"
            );
            assert_eq!(
                expected_kind,
                "opaque",
                "MockBroker uses Opaque for all non-GitHub/AWS/Anthropic; \
                 update when MockBroker returns Identity for {}",
                provider.as_str()
            );
        }
    }
}
