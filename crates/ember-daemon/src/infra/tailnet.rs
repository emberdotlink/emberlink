//! TAILNET-1 — k8s credential lease (escape-hatch reference impl).
//!
//! This module is the v1 reference implementation of the
//! "tailnet credential lease" pattern. The end-to-end shape is an
//! init container → JWT-verified `/tailnet/v1/lease` HTTP endpoint →
//! grant policy → leased credential delivered via tmpfs. TAILNET-1
//! ships ONLY the daemon-side primitive the rest of that shape is
//! built on:
//!
//!   `lease_credential(persona_id, credential_name, ttl, caller_tag)`
//!
//! which mints a short-lived grant against the
//! existing vault, packages the credential plaintext + expiry into a
//! [`LeaseHandle`], and lets the existing TTL-expiry sweep emit a
//! [`core_grant_types::grant_receipt::GrantReceipt`] when the lease expires.
//! Everything past the daemon socket — the JWT verification, the OIDC
//! discovery cache, the HTTP server binding to the Tailscale interface,
//! the init container's `tmpfs` write — is out of scope for this task
//! and lives in follow-up TAILNET-2/3/4 work.
//!
//! ### Why "escape-hatch"
//!
//! Per the 2026-04-25 design amendment, primary cluster secret-management
//! is SOPS-encrypted-at-rest with the daemon as a recipient. The lease
//! pattern in this module is reserved for the narrow set of cases SOPS
//! cannot serve:
//! per-request grants, per-pod-identity-bound credentials, workloads
//! that cannot mount filesystem secrets. Static API keys move to SOPS;
//! the lease pattern is reached for only when SOPS cannot apply.
//!
//! ### Threat model summary (full version in the proposal)
//!
//! - **The persona name in the request body is NOT trusted.** Identity
//!   binds to the validated Tailnet ACL tag (`caller_tag`), checked
//!   against an explicit allow-list before the daemon mints anything.
//!   In production the caller is identified by Tailscale node identity
//!   (the secondary defense-in-depth proof) plus a kube-apiserver-
//!   signed ServiceAccount JWT (the primary identity proof in
//!   TAILNET-2). At the daemon layer we surface only the tag-allowlist
//!   check: anything wider belongs at the HTTP listener, not in this
//!   primitive.
//! - **Vault never leaves the daemon host.** `lease_credential` returns
//!   the credential plaintext to the caller; the caller is responsible
//!   for delivery (tmpfs in v1, sidecar UNIX socket in v1.1, mutating
//!   admission webhook in v2). The daemon keeps the vault sealed.
//! - **TTL is mandatory and capped.** `lease_credential` rejects
//!   `ttl == 0` and any TTL above [`MAX_LEASE_TTL_SECS`]. Short TTLs
//!   bound the post-revocation blast radius; the cap forces operators
//!   into the per-operation grant pattern instead of long-lived
//!   credentials in pods.
//! - **Receipts close the loop.** When the lease expires, the existing
//!   TTL-expiry sweep ([`crate::infra::store::DaemonStore::expire_stale_grants`])
//!   emits a signed Grant Receipt via the daemon's identity key. The
//!   integration test below exercises the full round-trip: lease minted
//!   → expires_at backdated → sweep → receipt persisted + verifiable.

use std::time::Duration;

// TODO: GrantInfo retained because lease_credential calls
// create_grant which returns GrantInfo, and LeaseHandle is built from GrantInfo
// fields (id, persona_id, credential_name, expires_at). Migrate once create_grant
// is updated to return core_grants::Grant or a dedicated LeaseResult type.
use crate::infra::store::{DaemonStore, StoreError};
use crate::infra::vault::{VaultError, VaultScope};
use crate::trust::grant::GrantInfo;

/// Tailnet ACL tag the daemon will accept lease requests from. Bound to
/// the Team Zero homelab tag from `infra/tailnet/acl.json`. Anything
/// else is rejected before the grant is minted — see [`lease_credential`].
///
/// Today this is a single hard-coded constant because Team Zero has one
/// worker tag. When the operator product surfaces (Phase 3 of the
/// proposal) this becomes a configured allow-list keyed by cluster
/// identity.
pub const ALLOWED_CALLER_TAG: &str = "tag:team-zero-worker";

/// Hard cap on lease TTL. Any caller asking for longer is rejected with
/// `StoreError::InvalidInput` — see the proposal's "Revocation Behavior"
/// section. 15 minutes is the v1 ceiling; the sidecar productized form
/// (v1.1) lifts this to 1 hour because revocation is fast-fail there.
pub const MAX_LEASE_TTL_SECS: u64 = 15 * 60;

/// Result of a successful [`lease_credential`] call.
///
/// Carries enough state for the caller to deliver the credential to the
/// requesting workload (tmpfs in the v1 init-container reference, UNIX
/// socket in v1.1, sidecar in v2) and to correlate audit entries
/// against the daemon's grant receipt later.
#[derive(Debug, Clone)]
pub struct LeaseHandle {
    /// Daemon grant id. Becomes the correlation handle on the eventual
    /// [`core_grant_types::grant_receipt::GrantReceipt`] emitted at expiry.
    pub grant_id: String,
    /// Persona that issued the grant.
    pub persona_id: String,
    /// Credential resource the grant authorizes (e.g. `github-pat`).
    pub credential_name: String,
    /// Plaintext credential bytes, decrypted from the vault under the
    /// caller's authority. The caller is responsible for delivering
    /// these bytes safely (tmpfs / UNIX socket / sidecar) and zeroing
    /// any in-process copies; the daemon does not retain them once
    /// this struct is dropped at the call site.
    pub credential: Vec<u8>,
    /// RFC 3339 expiry timestamp. Mirrors the issued grant's `expires_at`
    /// field — the same string the dashboard / receipt will display.
    pub expires_at: String,
    /// Validated ACL tag the lease is bound to. Echoed back so the
    /// caller can include it in the receipt-side audit annotation.
    pub caller_tag: String,
}

/// Mint a short-lived grant against the daemon vault and return its
/// plaintext credential plus expiry.
///
/// Used by the (eventual) HTTPS lease endpoint that listens on the
/// Tailscale interface. **The HTTP layer must validate the SA JWT and
/// resolve `caller_tag` from the Tailnet identity before invoking this
/// function** — by the time `lease_credential` runs, `caller_tag` is
/// the trusted identity, not anything copied out of the request body.
///
/// `persona_id` is the persona whose authority issues the grant. It
/// must already exist and be `active`.
///
/// `credential_name` is the resource path inside the daemon vault that
/// holds the credential plaintext. The grant scope is `<credential_name>`
/// — single-resource, single-statement.
///
/// `ttl` is the lease lifetime. Capped at [`MAX_LEASE_TTL_SECS`].
/// Sub-second precision is rounded down to whole seconds to match the
/// underlying grant `expires_at` field precision.
///
/// `caller_tag` is the validated Tailnet ACL tag of the requesting
/// node. Must equal [`ALLOWED_CALLER_TAG`] for the lease to mint —
/// the daemon does NOT trust unvalidated tag strings from the wire.
///
/// Errors:
/// - `StoreError::Unauthorized` if `caller_tag` is not in the allow-list.
///   The error name is deliberate: from the daemon's perspective the
///   caller's identity is not authorized to lease, regardless of what
///   the persona policy says.
/// - `StoreError::InvalidInput` if `ttl` is zero, exceeds
///   [`MAX_LEASE_TTL_SECS`], or `credential_name` / `persona_id` is
///   empty. Mirrors the existing `create_grant` shape.
/// - `StoreError::NotFound` if the persona does not exist (propagated
///   from `create_grant`).
/// - `StoreError::Vault(...)` if the credential plaintext cannot be
///   retrieved from the vault — typically because no credential of
///   that name has been added, or the vault is locked.
pub fn lease_credential(
    store: &DaemonStore,
    persona_id: &str,
    credential_name: &str,
    ttl: Duration,
    caller_tag: &str,
) -> Result<LeaseHandle, StoreError> {
    if caller_tag != ALLOWED_CALLER_TAG {
        // Don't echo the rejected tag back in the error message — the
        // value is attacker-influenced and the operator-facing log is
        // the right place for diagnostics, not the wire response.
        tracing::warn!(
            allowed_tag = ALLOWED_CALLER_TAG,
            "tailnet lease rejected: caller tag is not on the allow-list"
        );
        return Err(StoreError::Unauthorized);
    }

    if persona_id.is_empty() {
        return Err(StoreError::InvalidInput(
            "lease_credential: persona_id must not be empty".to_string(),
        ));
    }
    if credential_name.is_empty() {
        return Err(StoreError::InvalidInput(
            "lease_credential: credential_name must not be empty".to_string(),
        ));
    }

    let ttl_secs = ttl.as_secs();
    if ttl_secs == 0 {
        return Err(StoreError::InvalidInput(
            "lease_credential: ttl must be > 0 seconds".to_string(),
        ));
    }
    if ttl_secs > MAX_LEASE_TTL_SECS {
        return Err(StoreError::InvalidInput(format!(
            "lease_credential: ttl {ttl_secs}s exceeds cap {MAX_LEASE_TTL_SECS}s"
        )));
    }

    // Pull the plaintext credential out of the vault BEFORE minting the
    // grant: if the credential is missing or the vault is locked, no
    // grant row gets written and the operator sees a clean failure.
    let vault = store.vault().ok_or_else(|| {
        StoreError::InvalidInput("lease_credential: daemon vault is not attached".to_string())
    })?;
    let credential = vault
        .get(VaultScope::Interactive, store, credential_name)
        .map_err(map_vault_err)?;

    // Mint a single-statement composite grant scoped to this resource.
    // Reuses the existing `create_grant` machinery so the receipt-emit
    // path on TTL expiry is identical to every other daemon grant —
    // we deliberately do NOT bypass `create_grant` to expose a "general
    // grant minting endpoint", per the task constraint.
    let info: GrantInfo =
        store.create_grant(persona_id, credential_name, credential_name, Some(ttl_secs))?;
    let expires_at = info.expires_at.clone().ok_or_else(|| {
        StoreError::InvalidInput("lease_credential: TTL grant returned no expires_at".to_string())
    })?;

    tracing::info!(
        grant_id = %info.id,
        persona_id = %persona_id,
        credential_name = %credential_name,
        caller_tag = %caller_tag,
        ttl_secs,
        "tailnet credential lease minted"
    );

    Ok(LeaseHandle {
        grant_id: info.id,
        persona_id: info.persona_id,
        credential_name: info.credential_name,
        credential: credential.to_vec(),
        expires_at,
        caller_tag: caller_tag.to_string(),
    })
}

/// Translate a [`VaultError`] into a [`StoreError`] without leaking
/// internal vault state. Mirrors the conversion used elsewhere in the
/// daemon for vault-backed paths.
fn map_vault_err(e: VaultError) -> StoreError {
    match e {
        VaultError::NotFound => StoreError::NotFound,
        VaultError::Crypto(msg) => StoreError::Vault(format!("vault decrypt: {msg}")),
        VaultError::Store(inner) => inner,
        other => StoreError::Vault(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::receipt::{current_identity, init_identity};
    use crate::infra::vault::Vault;
    use std::rc::Rc;

    /// Deterministic vault key shared across this binary's tests.
    const TEST_VAULT_KEY: [u8; 32] = [0xA7u8; 32];

    fn store_with_vault() -> DaemonStore {
        let store = DaemonStore::open_in_memory().expect("open in-memory store");
        store.set_vault(Rc::new(Vault::new(TEST_VAULT_KEY)));
        store
    }

    fn init_test_identity() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir for daemon identity");
        let _ = init_identity(dir.path());
        dir
    }

    #[test]
    fn rejects_caller_tag_outside_allow_list() {
        let store = store_with_vault();
        let persona = store.create_persona("agent-tailnet").expect("persona");
        let vault = store.vault().expect("vault");
        vault
            .add(
                VaultScope::Interactive,
                &store,
                "github-pat",
                b"ghp_test",
                None,
            )
            .expect("seed credential");

        let err = lease_credential(
            &store,
            &persona.id,
            "github-pat",
            Duration::from_secs(60),
            "tag:human-laptop",
        )
        .expect_err("non-worker tag must be rejected");
        assert!(matches!(err, StoreError::Unauthorized), "got {err:?}");
    }

    #[test]
    fn rejects_zero_ttl() {
        let store = store_with_vault();
        let persona = store.create_persona("agent-zero-ttl").expect("persona");
        let vault = store.vault().expect("vault");
        vault
            .add(
                VaultScope::Interactive,
                &store,
                "github-pat",
                b"ghp_test",
                None,
            )
            .expect("seed credential");

        let err = lease_credential(
            &store,
            &persona.id,
            "github-pat",
            Duration::from_secs(0),
            ALLOWED_CALLER_TAG,
        )
        .expect_err("zero TTL must be rejected");
        assert!(matches!(err, StoreError::InvalidInput(_)), "got {err:?}");
    }

    #[test]
    fn rejects_ttl_above_cap() {
        let store = store_with_vault();
        let persona = store.create_persona("agent-cap").expect("persona");
        let vault = store.vault().expect("vault");
        vault
            .add(
                VaultScope::Interactive,
                &store,
                "github-pat",
                b"ghp_test",
                None,
            )
            .expect("seed credential");

        let err = lease_credential(
            &store,
            &persona.id,
            "github-pat",
            Duration::from_secs(MAX_LEASE_TTL_SECS + 1),
            ALLOWED_CALLER_TAG,
        )
        .expect_err("over-cap TTL must be rejected");
        assert!(matches!(err, StoreError::InvalidInput(_)), "got {err:?}");
    }

    #[test]
    fn rejects_unknown_credential() {
        let store = store_with_vault();
        let persona = store.create_persona("agent-no-cred").expect("persona");

        let err = lease_credential(
            &store,
            &persona.id,
            "unknown-cred",
            Duration::from_secs(60),
            ALLOWED_CALLER_TAG,
        )
        .expect_err("missing credential must be rejected");
        assert!(matches!(err, StoreError::NotFound), "got {err:?}");
    }

    #[test]
    fn round_trip_mints_grant_and_emits_receipt_on_expiry() {
        // Full TAILNET-1 acceptance: grant minted, credential delivered,
        // receipt emitted on expiry. Mirrors the pattern from
        // `tests/receipt_emit_on_ttl_expiry.rs`.
        let _id_dir = init_test_identity();
        let identity = current_identity().expect("identity loaded");

        let store = store_with_vault();
        let persona = store.create_persona("agent-roundtrip").expect("persona");

        let vault = store.vault().expect("vault");
        vault
            .add(
                VaultScope::Interactive,
                &store,
                "github-pat",
                b"ghp_secret_value",
                None,
            )
            .expect("seed credential");

        let lease = lease_credential(
            &store,
            &persona.id,
            "github-pat",
            Duration::from_secs(60),
            ALLOWED_CALLER_TAG,
        )
        .expect("lease minted");

        // Credential round-trips through the vault correctly.
        assert_eq!(lease.credential, b"ghp_secret_value");
        assert_eq!(lease.persona_id, persona.id);
        assert_eq!(lease.credential_name, "github-pat");
        assert_eq!(lease.caller_tag, ALLOWED_CALLER_TAG);
        assert!(!lease.grant_id.is_empty(), "grant id must be populated");
        assert!(!lease.expires_at.is_empty(), "expires_at must be populated");

        // The minted grant is active and TTL-bounded.
        let grant = store.get_grant(&lease.grant_id).expect("get_grant");
        assert_eq!(grant.status, "active");
        assert!(
            grant.expires_at.is_some(),
            "TTL grant must carry expires_at"
        );

        // Pre-condition: zero receipts before the sweep.
        assert_eq!(
            store.receipt_count().expect("receipt_count"),
            0,
            "no receipts should exist before sweep"
        );

        // Backdate `expires_at` so the next sweep flips status to
        // `expired` without sleeping for real wall-clock time.
        store
            .conn()
            .execute(
                "UPDATE grants SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
                rusqlite::params![lease.grant_id],
            )
            .expect("backdate expires_at");

        let expired = store.expire_stale_grants().expect("sweep");
        assert_eq!(expired, 1, "exactly one grant should expire");

        // Post-condition: receipt persisted, linked from grant row,
        // and verifies under the daemon identity. This is the
        // `lease_credential → grant minted → receipt on expiry` round
        // trip the task acceptance criterion calls out.
        assert_eq!(
            store.receipt_count().expect("receipt_count"),
            1,
            "TTL-expired lease must produce exactly one receipt"
        );
        let info = store.get_grant(&lease.grant_id).expect("get_grant");
        let rid = info
            .receipt_id
            .expect("expired lease grant must reference its receipt id");
        let receipt = store.get_receipt(&rid).expect("get_receipt by id");
        assert_eq!(receipt.grant_id, lease.grant_id);
        crate::infra::receipt::verify_receipt(&receipt, &identity.pubkey_hex())
            .expect("emitted receipt verifies under daemon identity");
    }
}
