//! ADR 200 §2 / §5 — event-sourced genesis of the **operator** IdentityRoot.
//!
//! This is the device-rooted sibling of [`crate::infra::identity_substrate`]
//! (the daemon self-root). The two roots are deliberately distinct (§2: "the
//! daemon did X" and "the operator authorized X" must never be confusable), and
//! their key custody is the load-bearing difference:
//!
//! - The **daemon** root is Ed25519 and the daemon *holds* its key — it self-
//!   signs its genesis (it IS the daemon-class Device, §1).
//! - The **operator** root is **device-rooted ECDSA-P256** and is signed BY the
//!   operator's presence-device key (YubiKey PIV / Secure Enclave). The daemon
//!   MUST NEVER hold that private key — it stores only the device PUBLIC key.
//!   So this genesis machinery takes an **external** [`Signer`] (the device's
//!   P256 key). On real hardware that signer delegates to the device (OQ-6 /
//!   PR4c); in tests it is a synthetic [`core_crypto::P256Signer`].
//!
//! There is NO `seal_persona_secret` here: a device-rooted persona has no
//! daemon-sealed secret — its signing key is the device key itself, which the
//! daemon never holds.
//!
//! ## Chaining (vs. the daemon substrate)
//! Unlike `ensure_daemon_identity` (which appends with empty refs), this module
//! chains every operator event with a `Previous` ref so the materialized log
//! passes the independent `core_eventlog::verify_chain` (AC-1) — the operator
//! root is the one an external party re-verifies, so its chain integrity must
//! hold end-to-end.

use core_crypto::{DeviceSignatureVerifier, PublicKey, Signature, Signer};
use core_event_types::{
    AttestationTier, CustodyClass, DeviceEnrolledEvent, DeviceRevokedEvent, EventBody,
    EventRefRelation, PersonaCreatedEvent, PresenceFactor, RootCreatedEvent, SignerBinding,
};
use core_events::{EventEnvelope, EventRef};
use core_principals::{KeyAlgorithm, PublicKeyMaterial, SurvivalMode};
use core_state::{
    DeviceStatus, EventStore, IdentityAuthorizer, MaterializedState, PersonaStatus, RootStatus,
};

use std::time::{SystemTime, UNIX_EPOCH};

/// Canonical id namespace for an **operator** IdentityRoot, distinguishing it
/// from the daemon root (ADR 200 §2). The full device pubkey is appended to form
/// the root id; this prefix is the stable discriminator a reader uses to tell an
/// operator root from the daemon root in materialized state (there is no
/// kind-marker field on `RootRecord`). See [`operator_root_id`].
pub const OPERATOR_ROOT_ID_PREFIX: &str = "root-operator-";

/// Stable identifiers for the operator's event-sourced identity, derived
/// deterministically from the **device pubkey** so genesis is idempotent across
/// restarts and a different namespace from the daemon root (`root-operator-…`
/// vs `root-daemon-…`) keeps the two structurally distinct (ADR 200 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorIdentityIds {
    pub root_id: String,
    pub persona_id: String,
    pub key_id: String,
}

impl OperatorIdentityIds {
    /// Derive the operator identity ids from the **full** device pubkey hex (the
    /// `p256:`-prefixed SEC1 string, prefix stripped). The pubkey is the trust
    /// anchor an external verifier checks signatures against, so the id binds the
    /// full pubkey — no truncation, mirroring `DaemonIdentityIds::derive`.
    fn derive(device_pubkey: &str) -> Self {
        // Strip the `p256:` prefix if present so the id reads cleanly; either way
        // the full key material is bound. (A bare key with no prefix is bound as-is.)
        let pubkey_hex = device_pubkey.strip_prefix("p256:").unwrap_or(device_pubkey);
        Self {
            root_id: format!("{OPERATOR_ROOT_ID_PREFIX}{pubkey_hex}"),
            persona_id: format!("persona-operator-{pubkey_hex}"),
            key_id: format!("key-operator-{pubkey_hex}"),
        }
    }
}

/// Resolve **the** operator IdentityRoot id in `state` — the single Active root
/// whose id carries the [`OPERATOR_ROOT_ID_PREFIX`] (dev0 is single-operator, so
/// there is exactly one). Returns `None` when there is no operator root yet, or
/// when the operator root is revoked, or — fail-closed — when more than one
/// Active operator root is present (an anomaly the caller must not silently
/// resolve). Read-only; never panics.
pub fn operator_root_id(state: &MaterializedState) -> Option<&str> {
    let mut found: Option<&str> = None;
    for root in state.roots_current.values() {
        if root.root_id.starts_with(OPERATOR_ROOT_ID_PREFIX) && root.status == RootStatus::Active {
            if found.is_some() {
                // >1 active operator root: ambiguous, fail closed.
                return None;
            }
            found = Some(root.root_id.as_str());
        }
    }
    found
}

/// Resolve the active operator Durable Persona under the single active operator
/// IdentityRoot. Returns `None` when the operator root/persona is absent,
/// revoked, or ambiguous.
pub fn operator_persona_id(state: &MaterializedState) -> Option<&str> {
    let root_id = operator_root_id(state)?;
    let mut found: Option<&str> = None;
    for persona in state.personas_current.values() {
        if persona.root_id == root_id && persona.status == PersonaStatus::Active {
            if found.is_some() {
                return None;
            }
            found = Some(persona.persona_id.as_str());
        }
    }
    found
}

/// Read-only predicate: is `public_key` the active signing key of an Active
/// persona under **the operator IdentityRoot**?
///
/// The operator-rooted specialization of
/// `core_eventlog::is_active_persona_key_under_root` (reached here via the
/// `core_state` re-export): it resolves the operator
/// root via [`operator_root_id`] (the `root-operator-` convention lives here,
/// not in the generic identity layer) and delegates the membership test. This is
/// the stable read interface the broker capability lane (BKR-4 grant-chain-walk)
/// consumes to confirm a delegating persona is still a live operator principal,
/// without touching `verify_chain`. Returns `false` if no (unambiguous, Active)
/// operator root exists. Never panics; fail-closed.
pub fn is_active_persona_key_under_operator_root(
    state: &MaterializedState,
    public_key: &str,
) -> bool {
    match operator_root_id(state) {
        Some(root_id) => core_state::is_active_persona_key_under_root(state, root_id, public_key),
        None => false,
    }
}

/// Resolve the public keys that may sign an authority-WIDENING op for the
/// operator: the **active, `presence`-custody Devices enrolled under the operator
/// IdentityRoot** (Model C — root authority is the SET of enrolled presence
/// devices, ADR 200 §2). The G1 enforcement gate verifies a widening op's
/// nonce-bound presence signature against THESE keys — never a caller-supplied
/// pubkey, which would make the gate trivially bypassable (mint a nonce, sign
/// with your own key, present your own pubkey).
///
/// Returns empty when there is no unambiguous Active operator root, or no enrolled
/// presence Device under it. An empty set means widening **fails closed** (there
/// is no key to verify against) — the unconditional posture: presence enforcement
/// is never silently downgraded to a daemon-forgeable path just because no device
/// is enrolled. The single bootstrap door is `identity.device.enroll` (OperatorPresence /
/// native-unlock, NOT widening). Read-only; never panics; fail-closed.
///
/// `daemon`/`co-authority` custody and revoked/replaced Devices are excluded: only
/// an Active `presence`-custody Device can satisfy Operator Presence (ADR 200 §3).
/// Note this returns the CLAIMED-presence set; the attestation TIER actually proven
/// is a `verify_chain`/reverifier concern (G4), orthogonal to membership here.
pub fn active_presence_device_keys_under_operator_root(state: &MaterializedState) -> Vec<String> {
    let Some(root_id) = operator_root_id(state) else {
        return Vec::new();
    };
    state
        .devices_current
        .values()
        .filter(|d| {
            d.root_id == root_id
                && d.status == DeviceStatus::Active
                && d.custody_class == CustodyClass::Presence
        })
        .map(|d| d.active_key.public_key.clone())
        .collect()
}

/// Sibling to [`active_presence_device_keys_under_operator_root`] that also
/// returns each Device's `device_id` alongside its signing key, so a consumer can
/// attribute a verified presence signature to a `signing_device_id` (ADR 200 §4).
///
/// Used by the audit co-sign consumer (P23-S5): the audit-chain repair/migrate
/// operator co-signature is verified against THIS set (Model C, 1-of-N), never a
/// caller-supplied pubkey, and the matching Device's `device_id` becomes the
/// receipt's `signing_device_id`. Same fail-closed filter as the signing-key
/// sibling: Active, `presence`-custody, under the unambiguous operator root.
/// Empty when there is no operator root or no enrolled presence Device — the
/// co-sign then has no key to verify against and MUST fail closed (G1: never
/// accept a daemon-forgeable co-signer). Read-only; never panics.
pub fn active_presence_devices_under_operator_root(
    state: &MaterializedState,
) -> Vec<(String, String)> {
    let Some(root_id) = operator_root_id(state) else {
        return Vec::new();
    };
    state
        .devices_current
        .values()
        .filter(|d| {
            d.root_id == root_id
                && d.status == DeviceStatus::Active
                && d.custody_class == CustodyClass::Presence
        })
        .map(|d| (d.device_id.clone(), d.active_key.public_key.clone()))
        .collect()
}

/// Resolve the §4 ECIES **recipient** public keys for the operator's enrolled
/// presence Devices (ADR 206 §4 presence-as-decryption). Sibling to
/// [`active_presence_device_keys_under_operator_root`], but returns each Device's
/// `active_encryption_key` (the distinct ECIES recipient provisioned at
/// enrollment, slice 3) instead of its signing key.
///
/// A scope KEK is wrapped to EACH of these recipients (Model C — the operator
/// root authority is the SET of enrolled presence Devices, ADR 200 §2), so any
/// one enrolled Device can perform the §4 unwrap gesture. Same filter as the
/// signing-key sibling: Active, `presence`-custody, under the operator root.
/// Returns empty when there is no unambiguous Active operator root or no enrolled
/// presence Device — §4 sealing then has no recipient and MUST fail closed (never
/// fall back to an autonomous-key recipient; AC-4). Read-only; never panics.
pub fn active_presence_device_encryption_keys_under_operator_root(
    state: &MaterializedState,
) -> Vec<String> {
    let Some(root_id) = operator_root_id(state) else {
        return Vec::new();
    };
    state
        .devices_current
        .values()
        .filter(|d| {
            d.root_id == root_id
                && d.status == DeviceStatus::Active
                && d.custody_class == CustodyClass::Presence
        })
        .map(|d| d.active_encryption_key.public_key.clone())
        .collect()
}

/// Resolve the §4 ECIES recipient **key ids** for the operator's enrolled
/// presence Devices — the AC-7 recipient allowlist for storing a scope-KEK
/// wrap (`vault.se_provision`). A wrap may be provisioned ONLY to a `key_id`
/// in this set (plus, once it exists, the off-host cold-recovery recipient);
/// never to a daemon-supplied arbitrary recipient. This upholds ADR 206 §4
/// "no autonomous-key recipient" (the set is device-rooted, never the MEK) and
/// closes §6 finding M3 (a compromised daemon persisting a wrap to a recipient
/// it can unwrap autonomously, turning a one-time present-operator provision
/// into standing autonomous decrypt). Sibling of
/// [`active_presence_device_encryption_keys_under_operator_root`] but returns
/// each Device's `active_encryption_key.key_id` (the identifier
/// `vault.se_provision` carries as `ecies_key_id`) instead of its public key.
/// Same Active/`presence`/operator-root filter; empty when there is no operator
/// root or enrolled presence Device, so provisioning then fails closed (never
/// admits a recipient — AC-4). Read-only; never panics.
pub fn active_presence_device_ecies_key_ids_under_operator_root(
    state: &MaterializedState,
) -> Vec<String> {
    let Some(root_id) = operator_root_id(state) else {
        return Vec::new();
    };
    state
        .devices_current
        .values()
        .filter(|d| {
            d.root_id == root_id
                && d.status == DeviceStatus::Active
                && d.custody_class == CustodyClass::Presence
        })
        .map(|d| d.active_encryption_key.key_id.clone())
        .collect()
}

/// A `KEK_s` wrap recipient resolved from the operator's **event-sourced**
/// custody set (ADR 206 §4/§6). Carries the Device's §4 ECIES recipient key. This
/// is the data the AC-7 allowlist and the typed wrap gate are built from; it can
/// only be produced by [`active_kek_recipients_under_operator_root`], which reads
/// `devices_current` — so a recipient pubkey can never be daemon-fabricated.
#[derive(Debug, Clone)]
pub struct KekRecipientRef {
    pub device_id: String,
    /// The §4 ECIES recipient `key_id` (the `vault.se_provision` allowlist token).
    pub key_id: String,
    /// Recipient curve: `EcdsaP256` ⇒ a presence Device (SE `se_wrap`/`se_unwrap`);
    /// `AgeX25519` ⇒ an off-host Recovery recipient (software age wrap).
    pub algorithm: KeyAlgorithm,
    pub public_key: String,
    pub custody_class: CustodyClass,
}

/// ADR 206 §4/§6 — resolve the FULL, non-forgeable `KEK_s` recipient set under the
/// operator root: every Active Device whose custody is `Presence` (the enrolled
/// hardware presence set, Model C) OR `Recovery` (an off-host recovery recipient,
/// §6 — e.g. a printed `age` code). This is the single source of truth for
/// "`enrolled ∪ recovery`" — the AC-7 re-seal allowlist — and the input to the
/// typed wrap gate. A `KEK_s` may be wrapped to a recipient ONLY if it appears
/// here; nothing else (no MEK, no daemon-supplied pubkey) is ever admissible
/// (AC-4 + AC-7). `Daemon`/`Container`/`co-authority` and revoked/replaced Devices
/// are excluded. Empty when there is no unambiguous operator root or no recipient,
/// so §4 sealing then fails closed. Read-only; never panics.
pub fn active_kek_recipients_under_operator_root(
    state: &MaterializedState,
) -> Vec<KekRecipientRef> {
    let Some(root_id) = operator_root_id(state) else {
        return Vec::new();
    };
    state
        .devices_current
        .values()
        .filter(|d| {
            d.root_id == root_id
                && d.status == DeviceStatus::Active
                && matches!(
                    d.custody_class,
                    CustodyClass::Presence | CustodyClass::Recovery
                )
        })
        .map(|d| KekRecipientRef {
            device_id: d.device_id.clone(),
            key_id: d.active_encryption_key.key_id.clone(),
            algorithm: d.active_encryption_key.algorithm,
            public_key: d.active_encryption_key.public_key.clone(),
            custody_class: d.custody_class,
        })
        .collect()
}

/// The AC-7 recipient allowlist `key_id`s for storing a scope-KEK wrap — the
/// `enrolled ∪ recovery` union (sibling of
/// [`active_presence_device_ecies_key_ids_under_operator_root`], which is the
/// presence-only subset). `vault.se_provision` admits a wrap ONLY for a `key_id`
/// in this set, closing §6 finding M3 (a compromised daemon persisting a wrap to
/// a recipient it controls) for recovery recipients too. Empty ⇒ provisioning
/// fails closed. Read-only; never panics.
pub fn active_kek_recipient_ecies_key_ids_under_operator_root(
    state: &MaterializedState,
) -> Vec<String> {
    active_kek_recipients_under_operator_root(state)
        .into_iter()
        .map(|r| r.key_id)
        .collect()
}

/// The dev0 default §4 sealing scope — the operator-authority scope, anchored to
/// the operator device-set root. ADR 206 §4 ("default `KEK_s` = persona"): at
/// dev0 single-owner the operator's authority is the one default scope; crown-
/// jewel resources earn their OWN scope via ADR 201 Custody in a later slice
/// (the `presence_scope_kek` table is keyed `(scope_kind, scope_id, device_id)`
/// to admit those). Returns `(scope_kind, scope_id)` = `("operator", <root_id>)`,
/// or `None` when there is no unambiguous operator root — the caller MUST then
/// fail closed (no scope ⇒ no §4 recipient, never a global KEK). Read-only.
pub fn operator_authority_scope(state: &MaterializedState) -> Option<(String, String)> {
    operator_root_id(state).map(|root_id| ("operator".to_string(), root_id.to_string()))
}

/// Errors standing up the operator identity. Kept distinct from the daemon
/// substrate's error type so callers can tell the two genesis paths apart.
#[derive(Debug)]
pub enum OperatorIdentityError {
    /// The supplied device signer's pubkey does not match the device pubkey
    /// material that would be recorded as the root/persona `initial_key`
    /// (self-root invariant — an external verifier would reject the genesis).
    SelfRootMismatch,
    /// Building or appending a genesis / enrollment event failed.
    Genesis(String),
    /// META-V030-DEVICE-REVOKE-ERROR-CODE-SUBSPACE (F9.2 LOW): the structural
    /// last-presence-device guard refused the revoke because the targeted
    /// device is the lone Active `presence`-class Device under the operator
    /// root — revoking it would brick the authority set (no presence key left
    /// to sign a future widening op, including the replacement enroll).
    ///
    /// Split out of `Genesis(_)` so the daemon RPC can map it to a DISTINCT
    /// wire code (`-32032`) and the CLI can render a typed "enroll a
    /// replacement first" affordance instead of the generic presence-locked
    /// help. Other revoke refusals (unknown device id, already-revoked,
    /// signer-not-an-active-presence) keep flowing through `Genesis(_)` /
    /// `-32030`.
    ///
    /// Anchor: `device_revoke_last_device_distinct_error_code_landed`.
    LastPresenceDeviceGuard(String),
}

impl std::fmt::Display for OperatorIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SelfRootMismatch => write!(
                f,
                "operator self-root signer key does not match initial_key \
                 (would fail external verify)"
            ),
            Self::Genesis(m) => write!(f, "operator identity genesis: {m}"),
            Self::LastPresenceDeviceGuard(m) => {
                write!(f, "operator identity last-presence-device guard: {m}")
            }
        }
    }
}

impl std::error::Error for OperatorIdentityError {}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The current per-root chain head `(event_id, seq)` for `root_id`, scanned from
/// the persisted log. Returns `None` when no event references this root yet (the
/// next event is genesis). Events are stored in append (causal) order, so the
/// last matching one is the head; its seq is the seq carried on its own
/// `Previous` ref (0 for genesis), matching `verify_chain`'s head tracking.
fn chain_head_for_root(store: &EventStore, root_id: &str) -> Option<(String, u64)> {
    store
        .events()
        .iter()
        .rfind(|e| e.body.root_id() == Some(root_id))
        .map(|e| {
            let seq = e
                .refs
                .iter()
                .find(|r| r.relation == EventRefRelation::Previous)
                .map(|r| r.seq)
                .unwrap_or(0);
            (e.event_id.clone(), seq)
        })
}

/// Append a root-signed operator event, chaining it onto the root's current head
/// with a `Previous` ref (or genesis with empty refs when no head exists yet).
/// Verified with the prefix-dispatching `DeviceSignatureVerifier` (P256 device
/// key) under the `IdentityAuthorizer`.
fn append_root_signed(
    store: &mut EventStore,
    signer: &impl Signer,
    root_id: &str,
    key_id: &str,
    body: EventBody,
    event_id: &str,
    now: u64,
) -> Result<(), OperatorIdentityError> {
    let refs = match chain_head_for_root(store, root_id) {
        Some((head_event_id, head_seq)) => vec![EventRef::previous(head_event_id, head_seq + 1)],
        None => Vec::new(),
    };
    let envelope = EventEnvelope::from_body(
        event_id,
        body,
        refs,
        SignerBinding::root(root_id.to_string(), key_id.to_string()),
        signer,
    )
    .map_err(|e| OperatorIdentityError::Genesis(e.to_string()))?;

    store
        .append_with_authorizer(envelope, &DeviceSignatureVerifier, &IdentityAuthorizer, now)
        .map_err(|e| OperatorIdentityError::Genesis(e.to_string()))
}

/// Append a device-rooted operator event whose signature is supplied
/// **out-of-band**, chaining it onto the root's current head. This is the
/// production-callable sibling of [`append_root_signed`]: instead of an in-process
/// [`Signer`] (which the daemon must not hold for an operator device key, §2/§5)
/// it takes the verified device `signer_pubkey` and an `oob_sign` closure that
/// returns the device signature over the canonical event bytes. The assembled
/// envelope is verified on append (`DeviceSignatureVerifier` → P256), so a
/// signature that does not match `signer_pubkey` fails closed — this function
/// grants no authority the operator's key did not actually sign for.
#[allow(clippy::too_many_arguments)]
/// Genesis self-root invariant (defense in depth — restores the in-process path's
/// `SelfRootMismatch` guard at the shared OOB layer): a `RootCreated` /
/// `PersonaCreated` genesis event's recorded founding `initial_key` MUST equal the
/// signing key. Without it the append-time signature check still passes (it only
/// binds signature↔`signer`), but the materialized `active_key` could name a key
/// that never signed — local state an external `verify_chain` would reject (AC-1).
/// `DeviceEnrolled` is deliberately exempt: its signer is the EXISTING authority
/// (the founding device), distinct by design from the newly-enrolled `device_key`.
fn check_genesis_self_root(
    body: &EventBody,
    signer_pubkey: &PublicKey,
) -> Result<(), OperatorIdentityError> {
    let mismatch = match body {
        EventBody::RootCreated(e) => signer_pubkey.0 != e.initial_key.public_key,
        EventBody::PersonaCreated(e) => signer_pubkey.0 != e.initial_key.public_key,
        _ => false,
    };
    if mismatch {
        return Err(OperatorIdentityError::SelfRootMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_root_oob_signed(
    store: &mut EventStore,
    signer_pubkey: &PublicKey,
    root_id: &str,
    key_id: &str,
    body: EventBody,
    event_id: &str,
    now: u64,
    oob_sign: impl FnOnce(&[u8]) -> Signature,
) -> Result<(), OperatorIdentityError> {
    check_genesis_self_root(&body, signer_pubkey)?;

    let refs = match chain_head_for_root(store, root_id) {
        Some((head_event_id, head_seq)) => vec![EventRef::previous(head_event_id, head_seq + 1)],
        None => Vec::new(),
    };
    let envelope = EventEnvelope::from_oob_signed(
        event_id,
        body,
        refs,
        SignerBinding::root(root_id.to_string(), key_id.to_string()),
        signer_pubkey.clone(),
        oob_sign,
    )
    .map_err(|e| OperatorIdentityError::Genesis(e.to_string()))?;

    store
        .append_with_authorizer(envelope, &DeviceSignatureVerifier, &IdentityAuthorizer, now)
        .map_err(|e| OperatorIdentityError::Genesis(e.to_string()))
}

/// Ensure the operator's device-rooted IdentityRoot + operator Durable Persona
/// exist in the identity substrate, emitting the genesis events on first run.
///
/// **Idempotent + half-bootstrap-repairing**, exactly like
/// `ensure_daemon_identity`: genesis emits TWO events (root, then persona) in
/// separate transactions; a crash between them would strand the operator without
/// a persona. We check root and persona independently and (re-)append only what
/// is missing.
///
/// The crux (ADR 200 §2/§5): both the `RootCreated.initial_key` and the
/// `PersonaCreated.initial_key` are the device pubkey, and the events are signed
/// by `device_signer` (the device's P256 key). The daemon never holds this key —
/// it is supplied externally. The self-root invariant
/// (`device_signer.public_key == device_pubkey_material.public_key`) is asserted
/// up front so a future refactor that decouples them fails closed rather than
/// shipping a genesis no external verifier would accept.
pub fn ensure_operator_identity(
    store: &mut EventStore,
    device_pubkey_material: &PublicKeyMaterial,
    device_signer: &impl Signer,
) -> Result<OperatorIdentityIds, OperatorIdentityError> {
    // Self-root invariant: the signing key MUST be the key being enrolled as the
    // root's founding key — otherwise the genesis is unverifiable by any party
    // holding only the device pubkey (AC-1).
    if device_signer.public_key().0 != device_pubkey_material.public_key {
        return Err(OperatorIdentityError::SelfRootMismatch);
    }

    let ids = OperatorIdentityIds::derive(&device_pubkey_material.public_key);
    // Bind the recorded key material's key_id to our derived operator key_id so
    // the SignerBinding key_id (used by `authorize_root_key`'s key-id match) and
    // the stored `active_key.key_id` agree.
    let key_material = PublicKeyMaterial {
        key_id: ids.key_id.clone(),
        algorithm: device_pubkey_material.algorithm,
        public_key: device_pubkey_material.public_key.clone(),
    };

    let root_missing = store.materialized().root(&ids.root_id).is_none();
    let persona_missing = store.materialized().persona(&ids.persona_id).is_none();
    if !root_missing && !persona_missing {
        return Ok(ids);
    }

    let now = now_epoch_secs();

    // 1) Device-rooted operator IdentityRoot. `root_id` binds the full device
    //    pubkey so it can never collide with the daemon self-root (§2).
    if root_missing {
        append_root_signed(
            store,
            device_signer,
            &ids.root_id,
            &ids.key_id,
            EventBody::RootCreated(RootCreatedEvent {
                root_id: ids.root_id.clone(),
                display_name: "Operator".to_string(),
                initial_key: key_material.clone(),
            }),
            &format!("{}/genesis", ids.root_id),
            now,
        )?;
    }

    // 2) Operator Durable Persona — device-rooted, signing on the device key.
    //    NO separate secret, NO seal_persona_secret: the persona's signing key
    //    is the device key, which the daemon never holds.
    if persona_missing {
        append_root_signed(
            store,
            device_signer,
            &ids.root_id,
            &ids.key_id,
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: ids.root_id.clone(),
                persona_id: ids.persona_id.clone(),
                label: "Operator Persona".to_string(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: key_material,
            }),
            &format!("{}/persona", ids.root_id),
            now,
        )?;
    }

    Ok(ids)
}

/// Out-of-band sibling of [`ensure_operator_identity`]: stands up the operator
/// IdentityRoot + Durable Persona using signatures obtained **out-of-band** from
/// the operator's presence device, the daemon never holding the device key. This
/// is the production-callable genesis path (§2/§5): the daemon cannot self-sign an
/// operator self-root because it must not hold the operator key, so the in-process
/// [`Signer`] sibling exists only for the synthetic test stand-in.
///
/// `oob_sign` is invoked ONCE PER genesis event (root, then persona) — in
/// production each call is one presence-device tap; it receives the canonical
/// signing bytes and MUST return
/// `core_crypto::sign_with_context(DOMAIN_EVENT, device, bytes)` (see
/// [`EventEnvelope::from_oob_signed`]). Idempotent + half-bootstrap-repairing,
/// exactly like [`ensure_operator_identity`]: root and persona are checked
/// independently and only the missing event(s) are (re-)appended.
///
/// The self-root invariant (signer ≠ initial_key) is enforced two ways here: this
/// entrypoint derives BOTH the recorded `initial_key` and the verify `signer` from
/// the same `device_pubkey_material` (so they cannot diverge), and
/// [`append_root_oob_signed`] additionally guards genesis bodies at the shared
/// append layer (`SelfRootMismatch`). Append-time verification then proves the
/// `oob_sign` output was actually produced by that key — note that crypto check
/// alone binds signature↔`signer`, NOT `signer`↔`initial_key`, which is why the
/// genesis guard is retained rather than removed.
pub fn ensure_operator_identity_oob(
    store: &mut EventStore,
    device_pubkey_material: &PublicKeyMaterial,
    mut oob_sign: impl FnMut(&[u8]) -> Signature,
) -> Result<OperatorIdentityIds, OperatorIdentityError> {
    let ids = OperatorIdentityIds::derive(&device_pubkey_material.public_key);
    // Bind the recorded key material's key_id to our derived operator key_id (the
    // SignerBinding key_id and the stored active_key.key_id must agree), mirroring
    // `ensure_operator_identity`.
    let key_material = PublicKeyMaterial {
        key_id: ids.key_id.clone(),
        algorithm: device_pubkey_material.algorithm,
        public_key: device_pubkey_material.public_key.clone(),
    };
    // The device pubkey is both the recorded founding key and the verify anchor.
    let signer_pubkey = PublicKey(device_pubkey_material.public_key.clone());

    let root_missing = store.materialized().root(&ids.root_id).is_none();
    let persona_missing = store.materialized().persona(&ids.persona_id).is_none();
    if !root_missing && !persona_missing {
        return Ok(ids);
    }

    let now = now_epoch_secs();

    if root_missing {
        append_root_oob_signed(
            store,
            &signer_pubkey,
            &ids.root_id,
            &ids.key_id,
            EventBody::RootCreated(RootCreatedEvent {
                root_id: ids.root_id.clone(),
                display_name: "Operator".to_string(),
                initial_key: key_material.clone(),
            }),
            &format!("{}/genesis", ids.root_id),
            now,
            &mut oob_sign,
        )?;
    }

    if persona_missing {
        append_root_oob_signed(
            store,
            &signer_pubkey,
            &ids.root_id,
            &ids.key_id,
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: ids.root_id.clone(),
                persona_id: ids.persona_id.clone(),
                label: "Operator Persona".to_string(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: key_material,
            }),
            &format!("{}/persona", ids.root_id),
            now,
            &mut oob_sign,
        )?;
    }

    Ok(ids)
}

/// Enroll a presence Device under the operator root, appending a `DeviceEnrolled`
/// event signed by an **existing authority** (`authority_signer` — the founding
/// device, or any already-trusted presence Device under the root). The caller
/// supplies a fully-built [`DeviceEnrolledEvent`]; this function only chains and
/// signs it. For a backup SE key the caller builds it with `custody=Presence`,
/// `attestation_tier=None`, `presence_factor=UserPresence`,
/// `attestation_statement=None` (the dev0 floor — no vendor chain).
///
/// `authority_key_id` is the SignerBinding key_id for the signing authority — it
/// MUST match the founding root key's key_id (or the enrolled key_id of the
/// authority Device), or `authorize_root_key` rejects the event.
pub fn enroll_presence_device(
    store: &mut EventStore,
    root_id: &str,
    event: DeviceEnrolledEvent,
    authority_signer: &impl Signer,
    authority_key_id: &str,
    now: u64,
) -> Result<(), OperatorIdentityError> {
    append_root_signed(
        store,
        authority_signer,
        root_id,
        authority_key_id,
        EventBody::DeviceEnrolled(event),
        &format!("{root_id}/device/{}", store.events().len()),
        now,
    )
}

/// Out-of-band sibling of [`enroll_presence_device`]: appends a `DeviceEnrolled`
/// event signed **out-of-band** by an existing authority (the founding device, or
/// any already-trusted presence Device under the root), the daemon never holding
/// that key. `authority_pubkey` is the recorded signer + append-time verify anchor
/// and MUST be an active authority key under `root_id` (else `authorize_raw`
/// rejects). `event_id` is caller-supplied — and MUST be deterministic and
/// independent of mutable store state — so an off-host signer can reconstruct the
/// exact signing pre-image (ADR 200 §5; e.g. `"<root_id>/device/<device_pubkey>"`).
///
/// `oob_sign` receives the canonical signing bytes and MUST return
/// `core_crypto::sign_with_context(DOMAIN_EVENT, authority_device, bytes)` (see
/// [`EventEnvelope::from_oob_signed`]).
#[allow(clippy::too_many_arguments)]
pub fn enroll_presence_device_oob(
    store: &mut EventStore,
    root_id: &str,
    event: DeviceEnrolledEvent,
    authority_pubkey: &PublicKey,
    authority_key_id: &str,
    event_id: &str,
    now: u64,
    oob_sign: impl FnOnce(&[u8]) -> Signature,
) -> Result<(), OperatorIdentityError> {
    append_root_oob_signed(
        store,
        authority_pubkey,
        root_id,
        authority_key_id,
        EventBody::DeviceEnrolled(event),
        event_id,
        now,
        oob_sign,
    )
}

/// One step of an out-of-band first-run enrollment signing plan: the deterministic
/// event id and the exact bytes the operator's presence device must sign, i.e.
/// `core_crypto::sign_with_context(DOMAIN_EVENT, device, signing_bytes)`.
#[derive(Debug, Clone)]
pub struct OobEnrollStep {
    /// What this event establishes (operator-facing display / audit).
    pub purpose: &'static str,
    /// Deterministic event id — an external party can re-derive it.
    pub event_id: String,
    /// The exact pre-image the presence device signs (see [`OobEnrollStep`]).
    pub signing_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct OobBackupEnrollPlan {
    pub root_id: String,
    pub device_id: String,
    pub authority_key_id: String,
    pub event: DeviceEnrolledEvent,
    pub step: OobEnrollStep,
}

// META-V030-DEVICE-REVOKE-PLAN-CARRIER-REFACTOR — checkpoint
// `device_revoke_plan_uses_typed_carrier_landed`. The previous
// `device_revoke_plan` returned [`OobBackupEnrollPlan`] and stuffed a
// placeholder `DeviceEnrolledEvent` into its `event` field (all empty
// strings). That carrier was designed for enroll, not revoke — and a
// maintainer reading `plan.event` for revoke got a stub. Worse, a future
// refactor that added a required field to `DeviceEnrolledEvent` would
// silently leave the revoke placeholder broken. The typed
// [`OobRevokePlan`] below threads ONLY the fields the revoke ceremony
// actually consumes (`root_id` + `device_id` + `authority_key_id` +
// `reason` + `step`), with no placeholder event field. The COMMIT path
// re-builds the `DeviceRevokedEvent` from the same inputs (root_id,
// device_id, reason) — kept in the plan — so PREPARE and COMMIT cannot
// diverge. See the `device_revoke_plan_carrier_shape_is_typed`
// regression test for the field-shape pin.
#[derive(Debug, Clone)]
pub struct OobRevokePlan {
    /// Operator IdentityRoot the target Device is owned by.
    pub root_id: String,
    /// The Device being revoked.
    pub device_id: String,
    /// SignerBinding key_id for the signing authority — an active
    /// presence Device under `root_id` whose public key is the
    /// `authority_pubkey` PREPARE was called with.
    pub authority_key_id: String,
    /// Operator-supplied revocation reason, threaded so COMMIT can
    /// rebuild the exact `DeviceRevokedEvent` PREPARE computed signing
    /// bytes for (PREPARE-vs-COMMIT divergence guard).
    pub reason: String,
    /// Deterministic event id + the exact pre-image the authority
    /// presence Device must sign.
    pub step: OobEnrollStep,
}

/// One planned genesis/enrollment event: `(purpose, event_id, body, refs)`.
type PlannedEvent = (&'static str, String, EventBody, Vec<EventRef>);

fn pubkey_hex(public_key: &str) -> &str {
    public_key.strip_prefix("p256:").unwrap_or(public_key)
}

fn operator_device_id(public_key: &str) -> String {
    format!("device-operator-{}", pubkey_hex(public_key))
}

fn operator_device_key_id(public_key: &str) -> String {
    format!("key-operator-{}", pubkey_hex(public_key))
}

fn operator_ecies_key_id(public_key: &str) -> String {
    format!("key-operator-ecies-{}", pubkey_hex(public_key))
}

// ADR 206 §6 recovery-recipient ids. The age recovery pubkey (`age1…`, bech32
// lowercase-alphanumeric) is bound in full — no truncation — so the ids can never
// collide and an external verifier sees exactly which recipient was authorized,
// mirroring the operator-device id philosophy.
fn operator_recovery_device_id(age_pubkey: &str) -> String {
    format!("device-recovery-{age_pubkey}")
}

fn operator_recovery_device_key_id(age_pubkey: &str) -> String {
    format!("key-recovery-{age_pubkey}")
}

/// The §4 ECIES recipient `key_id` for a recovery recipient — the AC-7 allowlist
/// token a wrap is stored under (`vault.se_add_recipient_wrap`). Deterministic
/// from the `age1…` public half, so the operator session can name it without
/// re-encoding the convention.
pub fn operator_recovery_ecies_key_id(age_pubkey: &str) -> String {
    format!("key-recovery-ecies-{age_pubkey}")
}

fn active_presence_authority_key_id(
    state: &MaterializedState,
    root_id: &str,
    authority_pubkey: &PublicKey,
) -> Result<String, OperatorIdentityError> {
    let root = state.roots_current.get(root_id).ok_or_else(|| {
        OperatorIdentityError::Genesis(format!("operator root {root_id} not found"))
    })?;
    if root.status != RootStatus::Active {
        return Err(OperatorIdentityError::Genesis(format!(
            "operator root {root_id} is not active"
        )));
    }
    state
        .devices_current
        .values()
        .find(|d| {
            d.root_id == root_id
                && d.status == DeviceStatus::Active
                && d.custody_class == CustodyClass::Presence
                && d.active_key.public_key == authority_pubkey.0
        })
        .map(|d| d.active_key.key_id.clone())
        .ok_or_else(|| {
            OperatorIdentityError::Genesis(format!(
                "authority device key is not an active presence Device under {root_id}"
            ))
        })
}

fn backup_presence_device_event(
    root_id: &str,
    device_material: &PublicKeyMaterial,
    encryption_material: &PublicKeyMaterial,
    device_label: &str,
) -> (String, String, DeviceEnrolledEvent) {
    let device_id = operator_device_id(&device_material.public_key);
    let event_id = format!(
        "{root_id}/device/{}",
        pubkey_hex(&device_material.public_key)
    );
    let device_key = PublicKeyMaterial {
        key_id: operator_device_key_id(&device_material.public_key),
        algorithm: device_material.algorithm,
        public_key: device_material.public_key.clone(),
    };
    let encryption_key = PublicKeyMaterial {
        key_id: operator_ecies_key_id(&encryption_material.public_key),
        algorithm: encryption_material.algorithm,
        public_key: encryption_material.public_key.clone(),
    };
    (
        device_id.clone(),
        event_id,
        DeviceEnrolledEvent {
            root_id: root_id.to_string(),
            device_id,
            label: device_label.to_string(),
            device_key,
            encryption_key,
            custody_class: CustodyClass::Presence,
            attestation_statement: None,
            attestation_tier: AttestationTier::None,
            presence_factor: PresenceFactor::UserPresence,
        },
    )
}

pub fn backup_presence_device_enroll_plan(
    store: &EventStore,
    root_id: &str,
    authority_pubkey: &PublicKey,
    device_material: &PublicKeyMaterial,
    encryption_material: &PublicKeyMaterial,
    device_label: &str,
) -> Result<OobBackupEnrollPlan, OperatorIdentityError> {
    let authority_key_id =
        active_presence_authority_key_id(store.materialized(), root_id, authority_pubkey)?;
    let (device_id, event_id, event) =
        backup_presence_device_event(root_id, device_material, encryption_material, device_label);
    if store.materialized().device(&device_id).is_some() {
        return Err(OperatorIdentityError::Genesis(format!(
            "presence Device {device_id} is already enrolled"
        )));
    }
    let refs = match chain_head_for_root(store, root_id) {
        Some((head_event_id, head_seq)) => vec![EventRef::previous(head_event_id, head_seq + 1)],
        None => {
            return Err(OperatorIdentityError::Genesis(format!(
                "operator root {root_id} has no event chain"
            )));
        }
    };
    let body = EventBody::DeviceEnrolled(event.clone());
    let binding = SignerBinding::root(root_id.to_string(), authority_key_id.clone());
    let signing_bytes = EventEnvelope::signing_pre_image(&event_id, &body, &refs, &binding)
        .map_err(|e| OperatorIdentityError::Genesis(e.to_string()))?;
    Ok(OobBackupEnrollPlan {
        root_id: root_id.to_string(),
        device_id,
        authority_key_id,
        event,
        step: OobEnrollStep {
            purpose: "operator-backup-presence-device-enroll",
            event_id,
            signing_bytes,
        },
    })
}

// Enrollment plumbing signature — structurally many params (store, root, keys, label, sig, now).
#[allow(clippy::too_many_arguments)]
pub fn commit_backup_presence_device_enrollment(
    store: &mut EventStore,
    root_id: &str,
    authority_pubkey: &PublicKey,
    device_material: &PublicKeyMaterial,
    encryption_material: &PublicKeyMaterial,
    device_label: &str,
    signature: Signature,
    now: u64,
) -> Result<String, OperatorIdentityError> {
    let plan = backup_presence_device_enroll_plan(
        store,
        root_id,
        authority_pubkey,
        device_material,
        encryption_material,
        device_label,
    )?;
    let device_id = plan.device_id.clone();
    enroll_presence_device_oob(
        store,
        &plan.root_id,
        plan.event,
        authority_pubkey,
        &plan.authority_key_id,
        &plan.step.event_id,
        now,
        |_| signature,
    )?;
    Ok(device_id)
}

// ---------------------------------------------------------------------------
// ADR 200 §5/§6 — operator-driven device REVOCATION (V030-EMBER-DEVICE-REVOKE).
//
// A `DeviceRevoked` event is appended to the operator identity log under the
// operator IdentityRoot, signed by an EXISTING active `presence`-class Device
// (the daemon never holds that key — same OOB ceremony as backup-enroll).
// `core_eventlog::authorize::DeviceRevoked` accepts the signer iff (a) it is
// the operator root key OR (b) it is the device's own key — so revoking a
// distinct device requires a signature by another active presence Device,
// closing the cross-root tamper hole `require_device_owned_by_root` documents.
//
// Structural last-presence-device guard: refuses to revoke the final Active,
// `presence`-class Device under the root. With zero presence devices left,
// no future widening op (including a new enroll under §5) can be signed —
// the authority set would brick. Returned as a typed error so the daemon RPC
// can surface it as a recognizable refusal to the CLI.
// ---------------------------------------------------------------------------

/// Authority-set anchor: the structural lower bound on the operator's
/// Active `presence` Device count after a revoke commits. Held at 1 (and not
/// 0) so the authority set always has at least one key able to sign the next
/// widening op — including the enroll that would re-grow the set.
const MIN_ACTIVE_PRESENCE_DEVICES_AFTER_REVOKE: usize = 1;

fn revoke_event_id(root_id: &str, device_id: &str) -> String {
    format!("{root_id}/revoke/{device_id}")
}

/// Build the `DeviceRevoked` event body the operator presence Device must
/// sign to drop `device_id` out of the authority set. Pure; no store access.
fn device_revoke_event(root_id: &str, device_id: &str, reason: &str) -> DeviceRevokedEvent {
    DeviceRevokedEvent {
        root_id: root_id.to_string(),
        device_id: device_id.to_string(),
        reason: reason.to_string(),
    }
}

/// Resolve the `key_id` recorded for the active `presence` Device whose
/// signing key is `device_pubkey`, scoped to `root_id`. The same lookup the
/// backup-enroll plan uses for its authority key — reused so the same
/// fail-closed posture (no active presence-class Device with that key →
/// refuse) holds for revoke.
fn revoke_count_active_presence_devices_excluding(
    state: &MaterializedState,
    root_id: &str,
    excluded_device_id: &str,
) -> usize {
    state
        .devices_current
        .values()
        .filter(|d| {
            d.root_id == root_id
                && d.status == DeviceStatus::Active
                && d.custody_class == CustodyClass::Presence
                && d.device_id != excluded_device_id
        })
        .count()
}

/// Resolve the operator IdentityRoot id for `device_id` and return it along
/// with the device's current status and custody class. Returns `Err` if the
/// Device is unknown, owned by a different root, or already terminal.
fn resolve_revoke_target(
    state: &MaterializedState,
    device_id: &str,
) -> Result<String, OperatorIdentityError> {
    let device = state.devices_current.get(device_id).ok_or_else(|| {
        OperatorIdentityError::Genesis(format!("device {device_id} is not enrolled"))
    })?;
    if device.status != DeviceStatus::Active {
        return Err(OperatorIdentityError::Genesis(format!(
            "device {device_id} is not Active (status={:?}); refusing to re-revoke",
            device.status
        )));
    }
    Ok(device.root_id.clone())
}

/// PREPARE half of operator-driven device revocation. Computes — without
/// holding any key, without mutating state — the exact `DeviceRevoked` event
/// bytes the authority presence Device must sign. Also runs the structural
/// last-presence-device guard upfront so a PREPARE that the COMMIT would
/// reject can be refused before the operator is asked to tap.
pub fn device_revoke_plan(
    store: &EventStore,
    authority_pubkey: &PublicKey,
    target_device_id: &str,
    reason: &str,
) -> Result<OobRevokePlan, OperatorIdentityError> {
    let root_id = resolve_revoke_target(store.materialized(), target_device_id)?;

    // Authority-set guard (run at PREPARE so the operator never taps for an
    // op the COMMIT will refuse). Treat the revoke as if it had already
    // applied: count the OTHER active presence devices under the root.
    let target_device = store
        .materialized()
        .devices_current
        .get(target_device_id)
        .expect("checked by resolve_revoke_target");
    if target_device.custody_class == CustodyClass::Presence {
        let remaining = revoke_count_active_presence_devices_excluding(
            store.materialized(),
            &root_id,
            target_device_id,
        );
        if remaining < MIN_ACTIVE_PRESENCE_DEVICES_AFTER_REVOKE {
            // META-V030-DEVICE-REVOKE-ERROR-CODE-SUBSPACE (F9.2 LOW): typed
            // refusal so the daemon RPC can map THIS guard to a distinct
            // wire code (-32032) without renumbering the generic -32030
            // presence-locked bucket. Anchor:
            // device_revoke_last_device_distinct_error_code_landed.
            return Err(OperatorIdentityError::LastPresenceDeviceGuard(format!(
                "device-revoke: refusing to revoke the last active presence Device {target_device_id} under {root_id} — \
                 revocation would brick the authority set (no presence key would remain to sign a future widening op, \
                 including a replacement enroll). Enroll a replacement presence Device first (`ember device enroll --backup`)."
            )));
        }
    }

    let authority_key_id =
        active_presence_authority_key_id(store.materialized(), &root_id, authority_pubkey)?;
    let event_id = revoke_event_id(&root_id, target_device_id);
    let event = device_revoke_event(&root_id, target_device_id, reason);
    let refs = match chain_head_for_root(store, &root_id) {
        Some((head_event_id, head_seq)) => vec![EventRef::previous(head_event_id, head_seq + 1)],
        None => {
            return Err(OperatorIdentityError::Genesis(format!(
                "operator root {root_id} has no event chain"
            )));
        }
    };
    let body = EventBody::DeviceRevoked(event);
    let binding = SignerBinding::root(root_id.clone(), authority_key_id.clone());
    let signing_bytes = EventEnvelope::signing_pre_image(&event_id, &body, &refs, &binding)
        .map_err(|e| OperatorIdentityError::Genesis(e.to_string()))?;
    // Typed [`OobRevokePlan`] carrier — only the fields the revoke
    // ceremony actually consumes (`root_id` + `device_id` +
    // `authority_key_id` + `reason` + `step`). The COMMIT path rebuilds
    // the `DeviceRevokedEvent` from `root_id` / `target_device_id` /
    // `reason` (same inputs PREPARE computed `signing_bytes` for), so
    // PREPARE and COMMIT cannot diverge. Anchor:
    // `device_revoke_plan_uses_typed_carrier_landed`.
    Ok(OobRevokePlan {
        root_id,
        device_id: target_device_id.to_string(),
        authority_key_id,
        reason: reason.to_string(),
        step: OobEnrollStep {
            purpose: "operator-device-revoke",
            event_id,
            signing_bytes,
        },
    })
}

/// COMMIT half of operator-driven device revocation. Verifies the supplied
/// authority signature against the recorded P-256 key, re-runs the
/// last-presence-device guard, and appends the `DeviceRevoked` event.
/// Returns the revoked device id and the operator root id.
pub fn commit_device_revoke(
    store: &mut EventStore,
    authority_pubkey: &PublicKey,
    target_device_id: &str,
    reason: &str,
    signature: Signature,
    now: u64,
) -> Result<(String, String), OperatorIdentityError> {
    let plan = device_revoke_plan(store, authority_pubkey, target_device_id, reason)?;
    let body =
        EventBody::DeviceRevoked(device_revoke_event(&plan.root_id, target_device_id, reason));
    append_root_oob_signed(
        store,
        authority_pubkey,
        &plan.root_id,
        &plan.authority_key_id,
        body,
        &plan.step.event_id,
        now,
        |_| signature,
    )?;
    Ok((plan.root_id, target_device_id.to_string()))
}

// ---------------------------------------------------------------------------
// ADR 206 §6 — off-host recovery-recipient enrollment (the printed `age` code).
//
// A recovery recipient is enrolled as a `CustodyClass::Recovery` Device under the
// operator root, SIGNED by an existing operator presence authority (Model C) — so
// it is non-forgeable: a compromised daemon cannot add a recipient it controls
// (AC-7 / §6 finding M3). Its `age1…` public half is recorded (device_key and
// encryption_key both, algorithm `AgeX25519`); the PRIVATE half is the printed
// recovery code, which lives provably off-host and which the daemon NEVER holds
// (finding C3). The recipient never signs and is never a root authority — it only
// ever decrypts a `KEK_s` wrap during recovery. Reuses the exact OOB ceremony +
// authorizer + materializer as a backup presence Device (one custody-member
// model); only the custody class + key curve differ.
// ---------------------------------------------------------------------------

/// Build the `DeviceEnrolled` event that records an off-host `age` recovery
/// recipient as a `CustodyClass::Recovery` Device. The single `age1…` public half
/// is recorded in BOTH the (inert) signing slot and the §4 ECIES recipient slot,
/// with algorithm `AgeX25519` loudly marking it incapable of signing.
fn recovery_recipient_event(
    root_id: &str,
    recovery_age_pubkey: &str,
    label: &str,
) -> (String, String, DeviceEnrolledEvent) {
    let device_id = operator_recovery_device_id(recovery_age_pubkey);
    let event_id = format!("{root_id}/recovery/{recovery_age_pubkey}");
    let device_key = PublicKeyMaterial {
        key_id: operator_recovery_device_key_id(recovery_age_pubkey),
        algorithm: KeyAlgorithm::AgeX25519,
        public_key: recovery_age_pubkey.to_string(),
    };
    let encryption_key = PublicKeyMaterial {
        key_id: operator_recovery_ecies_key_id(recovery_age_pubkey),
        algorithm: KeyAlgorithm::AgeX25519,
        public_key: recovery_age_pubkey.to_string(),
    };
    (
        device_id.clone(),
        event_id,
        DeviceEnrolledEvent {
            root_id: root_id.to_string(),
            device_id,
            label: label.to_string(),
            device_key,
            encryption_key,
            custody_class: CustodyClass::Recovery,
            attestation_statement: None,
            attestation_tier: AttestationTier::None,
            // Non-presence custody MUST record an `unattended` factor (there is no
            // live human gesture — opening the recovery code is an offline act).
            presence_factor: PresenceFactor::Unattended,
        },
    )
}

/// **Prepare** half of recovery-recipient enrollment (ADR 206 §6): compute — with
/// no key held and no state mutation — the exact bytes an existing operator
/// presence device must sign to bind `recovery_age_pubkey` as a `Recovery` Device
/// under `root_id`. The operator signs [`OobEnrollStep::signing_bytes`] off-host,
/// then hands the signature to [`commit_recovery_recipient_enrollment`]. Reuses
/// [`OobBackupEnrollPlan`] (same shape: deterministic event id + signing bytes).
pub fn recovery_recipient_enroll_plan(
    store: &EventStore,
    root_id: &str,
    authority_pubkey: &PublicKey,
    recovery_age_pubkey: &str,
    label: &str,
) -> Result<OobBackupEnrollPlan, OperatorIdentityError> {
    let authority_key_id =
        active_presence_authority_key_id(store.materialized(), root_id, authority_pubkey)?;
    let (device_id, event_id, event) =
        recovery_recipient_event(root_id, recovery_age_pubkey, label);
    if store.materialized().device(&device_id).is_some() {
        return Err(OperatorIdentityError::Genesis(format!(
            "recovery recipient {device_id} is already enrolled"
        )));
    }
    let refs = match chain_head_for_root(store, root_id) {
        Some((head_event_id, head_seq)) => vec![EventRef::previous(head_event_id, head_seq + 1)],
        None => {
            return Err(OperatorIdentityError::Genesis(format!(
                "operator root {root_id} has no event chain"
            )));
        }
    };
    let body = EventBody::DeviceEnrolled(event.clone());
    let binding = SignerBinding::root(root_id.to_string(), authority_key_id.clone());
    let signing_bytes = EventEnvelope::signing_pre_image(&event_id, &body, &refs, &binding)
        .map_err(|e| OperatorIdentityError::Genesis(e.to_string()))?;
    Ok(OobBackupEnrollPlan {
        root_id: root_id.to_string(),
        device_id,
        authority_key_id,
        event,
        step: OobEnrollStep {
            purpose: "operator-recovery-recipient-enroll",
            event_id,
            signing_bytes,
        },
    })
}

/// **Commit** half of recovery-recipient enrollment: append the operator-presence-
/// signed `DeviceEnrolled(Recovery)` event, verified at append time against the
/// authority device key. The daemon holds neither the authority key nor the
/// recovery secret. Returns the enrolled recovery Device id.
#[allow(clippy::too_many_arguments)]
pub fn commit_recovery_recipient_enrollment(
    store: &mut EventStore,
    root_id: &str,
    authority_pubkey: &PublicKey,
    recovery_age_pubkey: &str,
    label: &str,
    signature: Signature,
    now: u64,
) -> Result<String, OperatorIdentityError> {
    let plan = recovery_recipient_enroll_plan(
        store,
        root_id,
        authority_pubkey,
        recovery_age_pubkey,
        label,
    )?;
    let device_id = plan.device_id.clone();
    enroll_presence_device_oob(
        store,
        &plan.root_id,
        plan.event,
        authority_pubkey,
        &plan.authority_key_id,
        &plan.step.event_id,
        now,
        |_| signature,
    )?;
    Ok(device_id)
}

/// The deterministic genesis+enroll event sequence for a FIRST-RUN operator
/// bootstrap on an empty operator log: `RootCreated` → `PersonaCreated` →
/// `DeviceEnrolled` (the founding presence device enrolls itself at the dev0 floor:
/// custody=Presence, tier=None, presence_factor=UserPresence). This is the SINGLE
/// source of truth shared by [`genesis_enroll_plan`] (prepare) and
/// [`commit_first_run_enrollment`] (commit), so the bytes the operator signs can
/// never diverge from the bytes the daemon appends. Pure; no store access. The
/// hard-coded refs (`Previous(genesis,1)`, `Previous(persona,2)`) match exactly
/// what sequential appends to an empty log produce via `chain_head_for_root`.
fn first_run_event_sequence(
    device_material: &PublicKeyMaterial,
    encryption_material: &PublicKeyMaterial,
    device_label: &str,
) -> (OperatorIdentityIds, String, Vec<PlannedEvent>) {
    let ids = OperatorIdentityIds::derive(&device_material.public_key);
    let pubkey_hex = pubkey_hex(&device_material.public_key);
    let key_material = PublicKeyMaterial {
        key_id: ids.key_id.clone(),
        algorithm: device_material.algorithm,
        public_key: device_material.public_key.clone(),
    };
    // The §4 ECIES recipient key (ADR 206). A DISTINCT SE key from the signing
    // key — macOS SE can't enforce sign-vs-decrypt usage on one key, so the
    // founding device provisions a second `UserPresence` key for sealing. Its
    // key_id binds the encryption pubkey (no truncation), so it can never
    // collide with the signing `key-operator-<pk>` id.
    let encryption_key_material = PublicKeyMaterial {
        key_id: operator_ecies_key_id(&encryption_material.public_key),
        algorithm: encryption_material.algorithm,
        public_key: encryption_material.public_key.clone(),
    };
    let root_event_id = format!("{}/genesis", ids.root_id);
    let persona_event_id = format!("{}/persona", ids.root_id);
    let device_id = format!("device-operator-{pubkey_hex}");
    let device_event_id = format!("{}/device/{}", ids.root_id, pubkey_hex);

    let seq = vec![
        (
            "operator-root-genesis",
            root_event_id.clone(),
            EventBody::RootCreated(RootCreatedEvent {
                root_id: ids.root_id.clone(),
                display_name: "Operator".to_string(),
                initial_key: key_material.clone(),
            }),
            Vec::new(),
        ),
        (
            "operator-persona-genesis",
            persona_event_id.clone(),
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: ids.root_id.clone(),
                persona_id: ids.persona_id.clone(),
                label: "Operator Persona".to_string(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: key_material.clone(),
            }),
            vec![EventRef::previous(root_event_id, 1)],
        ),
        (
            "operator-presence-device-enroll",
            device_event_id,
            EventBody::DeviceEnrolled(DeviceEnrolledEvent {
                root_id: ids.root_id.clone(),
                device_id: device_id.clone(),
                label: device_label.to_string(),
                device_key: key_material,
                encryption_key: encryption_key_material,
                custody_class: CustodyClass::Presence,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::UserPresence,
            }),
            vec![EventRef::previous(persona_event_id, 2)],
        ),
    ];
    (ids, device_id, seq)
}

/// **Prepare** half of the first-run operator-bootstrap ceremony (ADR 200 §5): the
/// daemon computes — *without holding any key and without mutating state* — the
/// exact ordered bytes the operator's founding presence device must sign to stand
/// up the operator root + persona and enroll itself as the dev0-floor presence
/// Device. The operator signs each [`OobEnrollStep::signing_bytes`] off-host
/// (YubiKey PIV / SE, in the GUI session), then the collected signatures are
/// handed to [`commit_first_run_enrollment`]. Returns the derived ids, the
/// deterministic enrolled `device_id` (so a prepare-mode RPC can report it before
/// any signature exists — same value [`commit_first_run_enrollment`] returns), and
/// one step per genesis event. Because the daemon is the authoritative
/// byte-computer, there is no client/daemon reconstruction divergence.
pub fn genesis_enroll_plan(
    device_material: &PublicKeyMaterial,
    encryption_material: &PublicKeyMaterial,
    device_label: &str,
) -> Result<(OperatorIdentityIds, String, Vec<OobEnrollStep>), OperatorIdentityError> {
    let (ids, device_id, seq) =
        first_run_event_sequence(device_material, encryption_material, device_label);
    let binding = SignerBinding::root(ids.root_id.clone(), ids.key_id.clone());
    let mut steps = Vec::with_capacity(seq.len());
    for (purpose, event_id, body, refs) in &seq {
        let signing_bytes = EventEnvelope::signing_pre_image(event_id, body, refs, &binding)
            .map_err(|e| OperatorIdentityError::Genesis(e.to_string()))?;
        steps.push(OobEnrollStep {
            purpose,
            event_id: event_id.clone(),
            signing_bytes,
        });
    }
    Ok((ids, device_id, steps))
}

/// **Commit** half of the first-run operator-bootstrap ceremony: takes the
/// operator's out-of-band signatures (one per [`genesis_enroll_plan`] step, in
/// order) and appends the genesis + enrollment events, each verified at append
/// time against the founding device key (`DeviceSignatureVerifier` → P256). The
/// daemon never holds the key. Returns the operator ids + the enrolled device id.
///
/// Fail-closed: the signature count must match the plan; a wrong/forged signature
/// fails the append-time verification; a genesis whose signer ≠ `initial_key` is
/// rejected ([`check_genesis_self_root`]).
///
/// **Idempotent + half-bootstrap-repairing** (symmetric with
/// [`ensure_operator_identity_oob`]): each event is appended only if not already
/// materialized, so a partial commit — a bad final signature, or a crash between
/// the per-event SQLite transactions — is *completed* by re-running with the full
/// (re-prepared) signature set, rather than stranding the operator on a root that
/// can never gain its presence Device. A clean re-commit is a no-op. The
/// deterministic hard-coded refs make the resume safe at any partial point.
pub fn commit_first_run_enrollment(
    store: &mut EventStore,
    device_material: &PublicKeyMaterial,
    encryption_material: &PublicKeyMaterial,
    device_label: &str,
    signatures: &[Signature],
    now: u64,
) -> Result<(OperatorIdentityIds, String), OperatorIdentityError> {
    let (ids, device_id, seq) =
        first_run_event_sequence(device_material, encryption_material, device_label);

    if signatures.len() != seq.len() {
        return Err(OperatorIdentityError::Genesis(format!(
            "expected {} signatures (one per planned genesis event), got {}",
            seq.len(),
            signatures.len()
        )));
    }

    let signer_pubkey = PublicKey(device_material.public_key.clone());
    let binding = SignerBinding::root(ids.root_id.clone(), ids.key_id.clone());

    for ((_purpose, event_id, body, refs), sig) in seq.into_iter().zip(signatures.iter()) {
        // Skip events already materialized (repair/idempotency). The pubkey-derived
        // ids mean an existing root/persona/device at these ids was created for THIS
        // device key, so skipping is safe; the hard-coded refs still line up for any
        // remaining event regardless of how far a prior partial commit got.
        if event_already_materialized(store, &body) {
            continue;
        }
        check_genesis_self_root(&body, &signer_pubkey)?;
        let sig = sig.clone();
        let envelope = EventEnvelope::from_oob_signed(
            event_id,
            body,
            refs,
            binding.clone(),
            signer_pubkey.clone(),
            move |_bytes| sig,
        )
        .map_err(|e| OperatorIdentityError::Genesis(e.to_string()))?;
        store
            .append_with_authorizer(envelope, &DeviceSignatureVerifier, &IdentityAuthorizer, now)
            .map_err(|e| OperatorIdentityError::Genesis(e.to_string()))?;
    }

    Ok((ids, device_id))
}

/// Whether the materialized state already contains the entity a genesis/enroll
/// `body` would create — the per-event idempotency check that makes
/// [`commit_first_run_enrollment`] half-bootstrap-repairing.
fn event_already_materialized(store: &EventStore, body: &EventBody) -> bool {
    match body {
        EventBody::RootCreated(e) => store.materialized().root(&e.root_id).is_some(),
        EventBody::PersonaCreated(e) => store.materialized().persona(&e.persona_id).is_some(),
        EventBody::DeviceEnrolled(e) => store.materialized().device(&e.device_id).is_some(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    //! T2: operator identity unit tests use temporary vault directories.

    use super::*;
    use core_crypto::{P256Signer, PublicKey};
    // `CustodyClass` comes from `use super::*` (module-level import).
    use core_event_types::{AttestationTier, PresenceFactor};
    use core_eventlog::verify::{VerifyOutcome, verify_chain};
    use core_principals::KeyAlgorithm;
    use tempfile::TempDir;

    /// A synthetic operator presence-device P256 signer + its pubkey material.
    fn device_signer(scalar: u8) -> (P256Signer, PublicKeyMaterial) {
        let signer = P256Signer::from_scalar_bytes(&[scalar; 32]).unwrap();
        let material = signer.public_key_material(format!("dev-key-{scalar}"));
        (signer, material)
    }

    /// A synthetic ECIES recipient key material, DISTINCT from the `device_signer`
    /// of the same scalar (ADR 206 §4: the §4 recipient is a separate SE key, never
    /// the signing key). Deterministic so a test's PREPARE and COMMIT agree on the
    /// canonical bytes.
    fn enc_material(scalar: u8) -> PublicKeyMaterial {
        let signer = P256Signer::from_scalar_bytes(&[scalar ^ 0xFF; 32]).unwrap();
        signer.public_key_material(format!("enc-key-{scalar}"))
    }

    fn open_store(dir: &TempDir) -> EventStore {
        EventStore::open(dir.path().join("operator-events.db")).expect("open store")
    }

    /// Collect the operator root's events from the store as a slice for
    /// `verify_chain` (which verifies a SINGLE root's chain).
    fn operator_chain(store: &EventStore, root_id: &str) -> Vec<EventEnvelope> {
        store
            .events()
            .iter()
            .filter(|e| e.body.root_id() == Some(root_id))
            .cloned()
            .collect()
    }

    #[test]
    fn genesis_materializes_device_rooted_root_and_persona() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (signer, material) = device_signer(0x11);

        let ids = ensure_operator_identity(&mut store, &material, &signer).unwrap();

        let root = store
            .materialized()
            .root(&ids.root_id)
            .expect("operator root materialized");
        let persona = store
            .materialized()
            .persona(&ids.persona_id)
            .expect("operator persona materialized");

        // Device-rooted: the root's founding key IS the device P256 key.
        assert_eq!(root.active_key.public_key, signer.public_key().0);
        assert_eq!(root.active_key.algorithm, KeyAlgorithm::EcdsaP256);
        assert_eq!(persona.root_id, ids.root_id);
        assert_eq!(persona.active_key.public_key, signer.public_key().0);
        // Distinct namespace from the daemon root.
        assert!(ids.root_id.starts_with("root-operator-"));
    }

    fn root_record(root_id: &str, status: RootStatus) -> core_state::RootRecord {
        core_state::RootRecord {
            root_id: root_id.into(),
            display_name: "r".into(),
            active_key: PublicKeyMaterial {
                key_id: format!("{root_id}-key"),
                algorithm: KeyAlgorithm::EcdsaP256,
                public_key: format!("pk-{root_id}"),
            },
            status,
        }
    }

    #[test]
    fn operator_root_id_resolves_skips_daemon_and_fails_closed() {
        let mut state = MaterializedState::default();
        // A daemon-namespaced root (no operator prefix) is ignored.
        state.roots_current.insert(
            "root-daemon-abc".into(),
            root_record("root-daemon-abc", RootStatus::Active),
        );
        assert_eq!(operator_root_id(&state), None, "no operator root yet");

        // One active operator root → resolves to it.
        let op = format!("{OPERATOR_ROOT_ID_PREFIX}deadbeef");
        state
            .roots_current
            .insert(op.clone(), root_record(&op, RootStatus::Active));
        assert_eq!(operator_root_id(&state), Some(op.as_str()));

        // Revoked operator root → None (no live operator authority).
        state.roots_current.get_mut(&op).unwrap().status = RootStatus::Revoked;
        assert_eq!(
            operator_root_id(&state),
            None,
            "revoked operator root must not resolve"
        );

        // Two ACTIVE operator roots → ambiguous → fail closed (None).
        state.roots_current.get_mut(&op).unwrap().status = RootStatus::Active;
        let op2 = format!("{OPERATOR_ROOT_ID_PREFIX}feedface");
        state
            .roots_current
            .insert(op2.clone(), root_record(&op2, RootStatus::Active));
        assert_eq!(
            operator_root_id(&state),
            None,
            "two active operator roots must fail closed"
        );
    }

    #[test]
    fn is_active_persona_key_under_operator_root_matches_operator_persona() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (signer, material) = device_signer(0x66);
        ensure_operator_identity(&mut store, &material, &signer).unwrap();
        let state = store.materialized(); // &MaterializedState

        // The operator persona's active key (= the founding device key) matches.
        assert!(is_active_persona_key_under_operator_root(
            state,
            &signer.public_key().0
        ));
        // A random key does not.
        assert!(!is_active_persona_key_under_operator_root(
            state,
            "pk-nobody"
        ));
        // No operator root at all → false (fail closed), never panics.
        assert!(!is_active_persona_key_under_operator_root(
            &MaterializedState::default(),
            &signer.public_key().0
        ));
    }

    #[test]
    fn self_root_invariant_rejects_wrong_signer() {
        // The signer is a DIFFERENT key than the pubkey material being enrolled
        // as the root's founding key → genesis must fail closed.
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (signer_a, _material_a) = device_signer(0x22);
        let (_signer_b, material_b) = device_signer(0x33);
        let err = ensure_operator_identity(&mut store, &material_b, &signer_a).unwrap_err();
        assert!(matches!(err, OperatorIdentityError::SelfRootMismatch));
    }

    #[test]
    fn full_ceremony_verifies_and_backup_device_gains_authority() {
        // AC-1 external-verifier shape: ensure_operator_identity creates
        // root+persona; enroll a backup presence device (tier=None) under it; run
        // verify_chain over the materialized log holding ONLY the device pubkey
        // and assert PASS; then a later root op signed by the BACKUP key verifies.
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (founding_signer, founding_material) = device_signer(0x44);
        let ids =
            ensure_operator_identity(&mut store, &founding_material, &founding_signer).unwrap();

        // Backup SE presence key (dev0 floor: tier=None, no attestation statement).
        let (backup_signer, backup_material_raw) = device_signer(0x55);
        let backup_key_id = "key-operator-backup".to_string();
        let backup_material = PublicKeyMaterial {
            key_id: backup_key_id.clone(),
            algorithm: KeyAlgorithm::EcdsaP256,
            public_key: backup_signer.public_key().0,
        };
        assert_eq!(backup_material.public_key, backup_material_raw.public_key);

        let backup_device_id = "device-operator-backup".to_string();
        enroll_presence_device(
            &mut store,
            &ids.root_id,
            DeviceEnrolledEvent {
                root_id: ids.root_id.clone(),
                device_id: backup_device_id.clone(),
                label: "Backup YubiKey".to_string(),
                device_key: backup_material.clone(),
                encryption_key: enc_material(0x55),
                custody_class: CustodyClass::Presence,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::UserPresence,
            },
            &founding_signer,
            &ids.key_id,
            now_epoch_secs(),
        )
        .unwrap();

        // The backup device is materialized as an active presence Device.
        let dev = store
            .materialized()
            .device(&backup_device_id)
            .expect("backup device materialized");
        assert_eq!(dev.custody_class, CustodyClass::Presence);
        assert_eq!(dev.active_key.public_key, backup_signer.public_key().0);

        // AC-1: an INDEPENDENT verifier holding only the founding device pubkey
        // re-verifies the whole device-rooted chain.
        let anchor = PublicKey(founding_signer.public_key().0);
        let chain = operator_chain(&store, &ids.root_id);
        match verify_chain(&chain, &anchor) {
            VerifyOutcome::Pass { verified_count, .. } => {
                assert_eq!(verified_count, chain.len());
            }
            other => panic!("expected Pass, got {other:?}"),
        }

        // The backup presence Device gained root authority: a later root op
        // (creating a second persona) signed by the BACKUP key authorizes — the
        // 1-of-N device set in action (Model C).
        let second_persona_id = format!("{}-p2", ids.persona_id);
        append_root_signed(
            &mut store,
            &backup_signer,
            &ids.root_id,
            &backup_key_id,
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: ids.root_id.clone(),
                persona_id: second_persona_id.clone(),
                label: "Second Operator Persona".to_string(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: backup_material,
            }),
            &format!("{}/persona2", ids.root_id),
            now_epoch_secs(),
        )
        .expect("backup presence device must authorize a root-level op");
        assert!(store.materialized().persona(&second_persona_id).is_some());

        // And the extended chain still verifies under the same anchor (the backup
        // key was authorized transitively by the founding key's enrollment).
        let chain = operator_chain(&store, &ids.root_id);
        assert!(matches!(
            verify_chain(&chain, &anchor),
            VerifyOutcome::Pass { .. }
        ));
    }

    #[test]
    fn kek_recipient_set_unions_presence_and_recovery_and_excludes_off_allowlist() {
        // ADR 206 §4/§6 AC-7: the KEK_s recipient allowlist = enrolled presence
        // Devices ∪ off-host Recovery recipients, and NOTHING else. This is the
        // single source feeding the type-gated wrap, so any recipient absent here
        // is structurally unwrappable — the runtime evidence behind the type gate.
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);

        // No operator root → empty (fail closed).
        assert!(
            active_kek_recipients_under_operator_root(store.materialized()).is_empty(),
            "no operator root => no KEK recipients"
        );

        let (founding, material) = device_signer(0x7A);
        let ids = ensure_operator_identity(&mut store, &material, &founding).unwrap();

        // Root + persona but no enrolled Device yet → still empty.
        assert!(
            active_kek_recipients_under_operator_root(store.materialized()).is_empty(),
            "root+persona without an enrolled Device => no KEK recipients"
        );

        // Enroll a presence Device (P-256 SE) — a KEK recipient.
        let (_pdev, p_material) = device_signer(0x8B);
        enroll_presence_device(
            &mut store,
            &ids.root_id,
            DeviceEnrolledEvent {
                root_id: ids.root_id.clone(),
                device_id: "device-presence-1".into(),
                label: "Mac SE".into(),
                device_key: p_material,
                encryption_key: enc_material(0x8B),
                custody_class: CustodyClass::Presence,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::UserPresence,
            },
            &founding,
            &ids.key_id,
            now_epoch_secs(),
        )
        .unwrap();

        // Enroll an off-host Recovery recipient (printed age code) — also a KEK
        // recipient, via the SAME DeviceEnrolled path with custody = Recovery.
        let recovery_pub = "age1recoverytestpubkeyplaceholder000000000000000000000000";
        let (_rid, _eid, recovery_event) =
            recovery_recipient_event(&ids.root_id, recovery_pub, "Printed recovery code");
        enroll_presence_device(
            &mut store,
            &ids.root_id,
            recovery_event,
            &founding,
            &ids.key_id,
            now_epoch_secs(),
        )
        .unwrap();

        let recipients = active_kek_recipients_under_operator_root(store.materialized());
        assert_eq!(recipients.len(), 2, "recipient set = presence ∪ recovery");
        assert!(
            recipients
                .iter()
                .any(|r| r.custody_class == CustodyClass::Presence
                    && r.algorithm == KeyAlgorithm::EcdsaP256),
            "presence Device present in the recipient set"
        );
        let rec = recipients
            .iter()
            .find(|r| r.custody_class == CustodyClass::Recovery)
            .expect("recovery recipient present in the set");
        assert_eq!(rec.algorithm, KeyAlgorithm::AgeX25519);
        assert_eq!(rec.public_key, recovery_pub);

        // AC-7 NEGATIVE: the allowlist is EXACTLY the two enrolled recipients; an
        // arbitrary/never-enrolled key is absent, so KEK_s can never be wrapped to
        // it (the type gate has no constructor outside this resolution).
        let key_ids = active_kek_recipient_ecies_key_ids_under_operator_root(store.materialized());
        assert_eq!(key_ids.len(), 2);
        assert!(key_ids.iter().any(|k| k == &rec.key_id));
        assert!(
            !key_ids.iter().any(|k| k.contains("attacker")),
            "an unenrolled recipient must never appear in the AC-7 allowlist"
        );
    }

    #[test]
    fn active_presence_device_keys_resolves_enrolled_presence_set() {
        // The G1 gate verifies a widening op's presence signature against THIS set
        // (Model C), never a caller-supplied key. Empty set => widening fails closed.
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);

        // No operator root yet → empty (fail closed).
        assert!(
            active_presence_device_keys_under_operator_root(store.materialized()).is_empty(),
            "no operator root => no presence keys"
        );

        let (founding, material) = device_signer(0x4A);
        let ids = ensure_operator_identity(&mut store, &material, &founding).unwrap();

        // Root + persona exist but NO DeviceEnrolled yet → still empty: the gate
        // resolves Devices (devices_current), not the bare persona key.
        assert!(
            active_presence_device_keys_under_operator_root(store.materialized()).is_empty(),
            "root+persona without an enrolled presence Device => empty"
        );

        // Enroll a presence Device (the dev0 floor).
        let (dev, _dev_raw) = device_signer(0x5B);
        let dev_material = PublicKeyMaterial {
            key_id: "key-operator-dev".into(),
            algorithm: KeyAlgorithm::EcdsaP256,
            public_key: dev.public_key().0,
        };
        enroll_presence_device(
            &mut store,
            &ids.root_id,
            DeviceEnrolledEvent {
                root_id: ids.root_id.clone(),
                device_id: "device-operator-1".into(),
                label: "Operator YubiKey".into(),
                device_key: dev_material,
                encryption_key: enc_material(0x5B),
                custody_class: CustodyClass::Presence,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::UserPresence,
            },
            &founding,
            &ids.key_id,
            now_epoch_secs(),
        )
        .unwrap();

        let keys = active_presence_device_keys_under_operator_root(store.materialized());
        assert_eq!(
            keys,
            vec![dev.public_key().0],
            "enrolled presence Device resolves"
        );

        // ADR 206 §4: the ECIES recipient helper resolves the DISTINCT encryption
        // key (not the signing key) for the same enrolled Device.
        let enc_keys =
            active_presence_device_encryption_keys_under_operator_root(store.materialized());
        assert_eq!(
            enc_keys,
            vec![enc_material(0x5B).public_key],
            "enrolled presence Device's §4 ECIES recipient resolves"
        );
        assert_ne!(
            enc_keys, keys,
            "the §4 recipient set must be distinct from the signing-key set"
        );

        // ADR 206 §4 AC-7 — the recipient allowlist resolves the enrolled
        // Device's ECIES `key_id` (what `vault.se_provision` carries as
        // `ecies_key_id`); a non-enrolled recipient is NOT a member, so a
        // provision wrap to it fails closed; and an empty operator state admits
        // no recipient.
        let recipient_ids =
            active_presence_device_ecies_key_ids_under_operator_root(store.materialized());
        assert_eq!(
            recipient_ids,
            vec![enc_material(0x5B).key_id],
            "AC-7 allowlist resolves the enrolled §4 ECIES recipient key_id"
        );
        assert!(
            !recipient_ids
                .iter()
                .any(|k| k == "key-operator-ecies-attacker"),
            "AC-7: a non-enrolled recipient is not on the allowlist (fails closed)"
        );
        assert!(
            active_presence_device_ecies_key_ids_under_operator_root(&MaterializedState::default())
                .is_empty(),
            "AC-7: no operator root => empty allowlist => provisioning fails closed"
        );

        // A different MaterializedState with no operator root never panics (both helpers).
        assert!(
            active_presence_device_keys_under_operator_root(&MaterializedState::default())
                .is_empty()
        );
        assert!(
            active_presence_device_encryption_keys_under_operator_root(
                &MaterializedState::default()
            )
            .is_empty()
        );
    }

    #[test]
    fn active_presence_device_keys_excludes_revoked_and_spans_the_device_set() {
        // Lock the exclusion predicates: a SECOND presence Device joins the
        // authority set (Model C), and a REVOKED Device drops out of it.
        use core_event_types::DeviceRevokedEvent;

        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (founding, material) = device_signer(0x6C);
        let ids = ensure_operator_identity(&mut store, &material, &founding).unwrap();

        let enroll = |store: &mut EventStore, scalar: u8, device_id: &str| -> String {
            let (dev, _) = device_signer(scalar);
            let pk = dev.public_key().0;
            enroll_presence_device(
                store,
                &ids.root_id,
                DeviceEnrolledEvent {
                    root_id: ids.root_id.clone(),
                    device_id: device_id.to_string(),
                    label: device_id.to_string(),
                    device_key: PublicKeyMaterial {
                        key_id: format!("key-{device_id}"),
                        algorithm: KeyAlgorithm::EcdsaP256,
                        public_key: pk.clone(),
                    },
                    encryption_key: enc_material(scalar),
                    custody_class: CustodyClass::Presence,
                    attestation_statement: None,
                    attestation_tier: AttestationTier::None,
                    presence_factor: PresenceFactor::UserPresence,
                },
                &founding,
                &ids.key_id,
                now_epoch_secs(),
            )
            .unwrap();
            pk
        };

        let pk_a = enroll(&mut store, 0x7D, "device-a");
        let pk_b = enroll(&mut store, 0x8E, "device-b");

        // Model C: both enrolled presence Devices are in the authority set.
        let mut keys = active_presence_device_keys_under_operator_root(store.materialized());
        keys.sort();
        let mut expected = vec![pk_a.clone(), pk_b.clone()];
        expected.sort();
        assert_eq!(keys, expected, "both enrolled presence Devices resolve");

        // Revoke device-a (founding key signs the revocation) — it must drop out.
        append_root_signed(
            &mut store,
            &founding,
            &ids.root_id,
            &ids.key_id,
            EventBody::DeviceRevoked(DeviceRevokedEvent {
                root_id: ids.root_id.clone(),
                device_id: "device-a".into(),
                reason: "test revoke".into(),
            }),
            &format!("{}/revoke-a", ids.root_id),
            now_epoch_secs(),
        )
        .unwrap();

        let keys = active_presence_device_keys_under_operator_root(store.materialized());
        assert_eq!(
            keys,
            vec![pk_b],
            "revoked Device must drop out of the authority set"
        );
    }

    #[test]
    fn ensure_is_idempotent_across_calls_and_reopen() {
        let dir = TempDir::new().unwrap();
        let (signer, material) = device_signer(0x66);

        let ids1 = {
            let mut store = open_store(&dir);
            let ids = ensure_operator_identity(&mut store, &material, &signer).unwrap();
            // Second call is a no-op (no double-create).
            let again = ensure_operator_identity(&mut store, &material, &signer).unwrap();
            assert_eq!(ids, again);
            assert_eq!(store.materialized().personas_current.len(), 1);
            assert_eq!(store.materialized().roots_current.len(), 1);
            ids
        };

        // Reopen from disk: genesis must NOT be re-emitted.
        let mut store = open_store(&dir);
        let ids2 = ensure_operator_identity(&mut store, &material, &signer).unwrap();
        assert_eq!(ids1, ids2);
        assert_eq!(store.materialized().roots_current.len(), 1);
        assert_eq!(store.materialized().personas_current.len(), 1);
    }

    #[test]
    fn half_bootstrap_is_repaired_not_stranded() {
        // Simulate a crash between the root append and the persona append: a store
        // with the operator root but NOT the persona. ensure must append the
        // missing persona (and the repaired chain must still verify).
        let dir = TempDir::new().unwrap();
        let (signer, material) = device_signer(0x77);
        let ids = OperatorIdentityIds::derive(&material.public_key);
        let key_material = PublicKeyMaterial {
            key_id: ids.key_id.clone(),
            algorithm: material.algorithm,
            public_key: material.public_key.clone(),
        };

        // Append ONLY the root genesis (root present, persona missing).
        {
            let mut store = open_store(&dir);
            append_root_signed(
                &mut store,
                &signer,
                &ids.root_id,
                &ids.key_id,
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: ids.root_id.clone(),
                    display_name: "Operator".to_string(),
                    initial_key: key_material,
                }),
                &format!("{}/genesis", ids.root_id),
                now_epoch_secs(),
            )
            .unwrap();
            assert!(store.materialized().root(&ids.root_id).is_some());
            assert!(store.materialized().persona(&ids.persona_id).is_none());
        }

        // Reopen and run ensure: it must repair (append the missing persona).
        let mut store = open_store(&dir);
        assert!(store.materialized().persona(&ids.persona_id).is_none());
        ensure_operator_identity(&mut store, &material, &signer).unwrap();
        assert!(
            store.materialized().persona(&ids.persona_id).is_some(),
            "half-bootstrap must be repaired: operator persona created on next ensure"
        );
        assert_eq!(store.materialized().roots_current.len(), 1);
        assert_eq!(store.materialized().personas_current.len(), 1);

        // The repaired chain verifies under the device anchor.
        let anchor = PublicKey(signer.public_key().0);
        let chain = operator_chain(&store, &ids.root_id);
        assert!(matches!(
            verify_chain(&chain, &anchor),
            VerifyOutcome::Pass { .. }
        ));
    }

    #[test]
    fn oob_genesis_and_enroll_verifies_and_forgery_fails_closed() {
        // ADR 200 §5: the daemon stands up genesis + enrollment WITHOUT holding
        // the operator device key — it obtains signatures out-of-band. A synthetic
        // P256 device stands in for the YubiKey/SE; in production the closure
        // marshals the bytes to the device and returns the pasted p256sig hex.
        use core_crypto::{DOMAIN_EVENT, sign_with_context};

        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (device, material) = device_signer(0xA1);

        let ids = ensure_operator_identity_oob(&mut store, &material, |bytes| {
            sign_with_context(DOMAIN_EVENT, &device, bytes)
        })
        .unwrap();

        // Genesis materialized, device-rooted on the device key.
        let root = store
            .materialized()
            .root(&ids.root_id)
            .expect("operator root materialized via OOB genesis");
        assert_eq!(root.active_key.public_key, device.public_key().0);
        assert!(store.materialized().persona(&ids.persona_id).is_some());

        // Enroll a SECOND presence device, authority = the founding device (OOB).
        let (dev2, dev2_material_raw) = device_signer(0xB2);
        let dev2_id = "device-operator-2".to_string();
        let dev2_material = PublicKeyMaterial {
            key_id: "key-operator-2".into(),
            algorithm: KeyAlgorithm::EcdsaP256,
            public_key: dev2.public_key().0,
        };
        assert_eq!(dev2_material.public_key, dev2_material_raw.public_key);
        let founding_pubkey = PublicKey(device.public_key().0);
        enroll_presence_device_oob(
            &mut store,
            &ids.root_id,
            DeviceEnrolledEvent {
                root_id: ids.root_id.clone(),
                device_id: dev2_id.clone(),
                label: "Second presence device".into(),
                device_key: dev2_material,
                encryption_key: enc_material(0xB2),
                custody_class: CustodyClass::Presence,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::UserPresence,
            },
            &founding_pubkey,
            &ids.key_id,
            // Deterministic, store-state-independent event id (shape β): an
            // off-host signer reconstructs the same signing pre-image.
            &format!("{}/device/{}", ids.root_id, dev2.public_key().0),
            now_epoch_secs(),
            |bytes| sign_with_context(DOMAIN_EVENT, &device, bytes),
        )
        .unwrap();
        assert_eq!(
            store
                .materialized()
                .device(&dev2_id)
                .expect("second device materialized")
                .custody_class,
            CustodyClass::Presence
        );

        // AC-1: an INDEPENDENT verifier holding only the founding device pubkey
        // re-verifies the whole device-rooted chain produced via the OOB path.
        let anchor = PublicKey(device.public_key().0);
        let chain = operator_chain(&store, &ids.root_id);
        assert!(matches!(
            verify_chain(&chain, &anchor),
            VerifyOutcome::Pass { .. }
        ));

        // Forgery: an OOB signature from a DIFFERENT key over a fresh genesis must
        // fail closed at append — the daemon cannot mint authority for a key it
        // never signed with (this is the property the whole OOB model rests on).
        let dir2 = TempDir::new().unwrap();
        let mut store2 = open_store(&dir2);
        let (_real, real_material) = device_signer(0xC3);
        let (attacker, _attacker_material) = device_signer(0xD4);
        let err = ensure_operator_identity_oob(&mut store2, &real_material, |bytes| {
            // Attacker signs; its key does NOT match real_material's recorded pubkey.
            sign_with_context(DOMAIN_EVENT, &attacker, bytes)
        })
        .unwrap_err();
        assert!(matches!(err, OperatorIdentityError::Genesis(_)));
        assert!(
            store2.materialized().roots_current.is_empty(),
            "forged genesis must not materialize any operator root"
        );
    }

    #[test]
    fn first_run_plan_commit_round_trip_verifies() {
        // The real OOB ceremony: PREPARE (daemon computes bytes, no key/no
        // mutation) → operator signs off-host → COMMIT (daemon appends, verifies).
        use core_crypto::{DOMAIN_EVENT, sign_with_context};

        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (device, material) = device_signer(0x1A);
        let enc = enc_material(0x1A);

        let (plan_ids, plan_device_id, steps) =
            genesis_enroll_plan(&material, &enc, "Operator YubiKey").unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].purpose, "operator-root-genesis");
        assert_eq!(steps[2].purpose, "operator-presence-device-enroll");

        // Operator signs each prepared blob off-host (synthetic P256 stand-in).
        let signatures: Vec<_> = steps
            .iter()
            .map(|s| sign_with_context(DOMAIN_EVENT, &device, &s.signing_bytes))
            .collect();

        let (commit_ids, device_id) = commit_first_run_enrollment(
            &mut store,
            &material,
            &enc,
            "Operator YubiKey",
            &signatures,
            now_epoch_secs(),
        )
        .unwrap();
        assert_eq!(plan_ids, commit_ids);
        // The prepare-mode device_id matches what commit returns (single source).
        assert_eq!(plan_device_id, device_id);

        // Root + persona + presence device materialized on the device key — the
        // commit bytes matched the prepared bytes (else append-verify would fail).
        assert!(store.materialized().root(&commit_ids.root_id).is_some());
        assert!(
            store
                .materialized()
                .persona(&commit_ids.persona_id)
                .is_some()
        );
        let dev = store
            .materialized()
            .device(&device_id)
            .expect("presence device materialized");
        assert_eq!(dev.custody_class, CustodyClass::Presence);
        assert_eq!(dev.active_key.public_key, device.public_key().0);

        // AC-1: independent verifier with only the device pubkey re-verifies.
        let anchor = PublicKey(device.public_key().0);
        let chain = operator_chain(&store, &commit_ids.root_id);
        assert!(matches!(
            verify_chain(&chain, &anchor),
            VerifyOutcome::Pass { .. }
        ));
        // The enrolled device is the operator's active persona key.
        assert!(is_active_persona_key_under_operator_root(
            store.materialized(),
            &device.public_key().0
        ));

        // ADR 206 §4 AC-7 — the recipient allowlist resolves the PRODUCTION
        // ECIES recipient key_id format (`key-operator-ecies-<pubkeyhex>`) that
        // `vault.se_provision` matches the supplied `ecies_key_id` against. This
        // pins the daemon side of the CLI↔daemon contract (the CLI sends
        // `format!("key-operator-ecies-{}", hex::encode(ecies_pub))` over the
        // same bytes), so a future drift in either derivation fails THIS test
        // rather than silently fail-closing every legitimate provision.
        let recipients =
            active_presence_device_ecies_key_ids_under_operator_root(store.materialized());
        assert_eq!(
            recipients,
            vec![format!(
                "key-operator-ecies-{}",
                pubkey_hex(&enc.public_key)
            )],
            "AC-7 allowlist resolves the production key-operator-ecies-<hex> recipient id"
        );
    }

    #[test]
    fn first_run_commit_rejects_bad_sig_count_and_is_idempotent() {
        use core_crypto::{DOMAIN_EVENT, sign_with_context};

        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (device, material) = device_signer(0x2B);
        let enc = enc_material(0x2B);
        let (_ids, _device_id, steps) = genesis_enroll_plan(&material, &enc, "k").unwrap();

        // Wrong signature count → fail closed, nothing materializes.
        let too_few: Vec<_> = steps
            .iter()
            .take(2)
            .map(|s| sign_with_context(DOMAIN_EVENT, &device, &s.signing_bytes))
            .collect();
        assert!(
            commit_first_run_enrollment(
                &mut store,
                &material,
                &enc,
                "k",
                &too_few,
                now_epoch_secs()
            )
            .is_err()
        );
        assert!(store.materialized().roots_current.is_empty());

        // Correct commit succeeds; a clean re-commit is an idempotent no-op (NOT a
        // refusal) — counts are unchanged.
        let sigs: Vec<_> = steps
            .iter()
            .map(|s| sign_with_context(DOMAIN_EVENT, &device, &s.signing_bytes))
            .collect();
        commit_first_run_enrollment(&mut store, &material, &enc, "k", &sigs, now_epoch_secs())
            .unwrap();
        let roots = store.materialized().roots_current.len();
        let personas = store.materialized().personas_current.len();
        commit_first_run_enrollment(&mut store, &material, &enc, "k", &sigs, now_epoch_secs())
            .expect("idempotent re-commit is a no-op");
        assert_eq!(store.materialized().roots_current.len(), roots);
        assert_eq!(store.materialized().personas_current.len(), personas);
    }

    #[test]
    fn first_run_commit_partial_failure_is_repairable() {
        // A bad FINAL signature (or a crash before the device append) must leave the
        // operator recoverable: root+persona land, the device does not, and re-running
        // commit with the full correct signature set COMPLETES the enrollment rather
        // than refusing. Regression guard for the half-bootstrap-repair invariant.
        use core_crypto::{DOMAIN_EVENT, sign_with_context};

        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (device, material) = device_signer(0x3C);
        let enc = enc_material(0x3C);
        let (ids, _device_id, steps) = genesis_enroll_plan(&material, &enc, "k").unwrap();

        let good: Vec<_> = steps
            .iter()
            .map(|s| sign_with_context(DOMAIN_EVENT, &device, &s.signing_bytes))
            .collect();

        // Forge the device-enroll signature (sign the WRONG bytes) → partial commit.
        let mut bad = good.clone();
        bad[2] = sign_with_context(DOMAIN_EVENT, &device, b"not the device event bytes");
        let err =
            commit_first_run_enrollment(&mut store, &material, &enc, "k", &bad, now_epoch_secs())
                .unwrap_err();
        assert!(matches!(err, OperatorIdentityError::Genesis(_)));
        // root + persona landed, device did NOT (forged sig rejected at append).
        assert!(store.materialized().root(&ids.root_id).is_some());
        assert!(store.materialized().persona(&ids.persona_id).is_some());
        let device_id = format!(
            "device-operator-{}",
            material
                .public_key
                .strip_prefix("p256:")
                .unwrap_or(&material.public_key)
        );
        assert!(store.materialized().device(&device_id).is_none());

        // Repair: re-commit with the full CORRECT signatures completes the device.
        commit_first_run_enrollment(&mut store, &material, &enc, "k", &good, now_epoch_secs())
            .expect("partial commit must be repairable");
        assert!(store.materialized().device(&device_id).is_some());
        let anchor = PublicKey(device.public_key().0);
        let chain = operator_chain(&store, &ids.root_id);
        assert!(matches!(
            verify_chain(&chain, &anchor),
            VerifyOutcome::Pass { .. }
        ));
    }

    #[test]
    fn oob_genesis_guard_rejects_signer_mismatched_with_initial_key() {
        // The append-time signature check alone binds signature↔signer, NOT
        // signer↔initial_key. The genesis guard in `append_root_oob_signed` closes
        // that: a RootCreated whose recorded `initial_key` is device A but whose
        // signing `signer` is device B (with a VALID B-signature) must be rejected
        // SelfRootMismatch, so local materialized state can never name an
        // active_key an external verify_chain would reject.
        use core_crypto::{DOMAIN_EVENT, sign_with_context};

        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (signer_b, _b_material) = device_signer(0xE5);
        let (_signer_a, a_material) = device_signer(0xF6); // recorded initial_key
        let ids = OperatorIdentityIds::derive(&a_material.public_key);
        let a_key_material = PublicKeyMaterial {
            key_id: ids.key_id.clone(),
            algorithm: a_material.algorithm,
            public_key: a_material.public_key.clone(),
        };
        let signer_b_pubkey = PublicKey(signer_b.public_key().0);

        let err = append_root_oob_signed(
            &mut store,
            &signer_b_pubkey, // signer = B
            &ids.root_id,
            &ids.key_id,
            EventBody::RootCreated(RootCreatedEvent {
                root_id: ids.root_id.clone(),
                display_name: "Operator".to_string(),
                initial_key: a_key_material, // initial_key = A  → mismatch
            }),
            &format!("{}/genesis", ids.root_id),
            now_epoch_secs(),
            |bytes| sign_with_context(DOMAIN_EVENT, &signer_b, bytes), // VALID B sig
        )
        .unwrap_err();
        assert!(matches!(err, OperatorIdentityError::SelfRootMismatch));
        assert!(
            store.materialized().roots_current.is_empty(),
            "signer↔initial_key mismatch must not materialize a root"
        );
    }

    #[test]
    fn operator_root_id_is_device_pubkey_derived_and_distinct() {
        // Two different device keys → two different operator roots; and the
        // operator namespace never collides with the daemon namespace.
        let (_s_a, a) = device_signer(0x88);
        let (_s_b, b) = device_signer(0x99);
        let ids_a = OperatorIdentityIds::derive(&a.public_key);
        let ids_b = OperatorIdentityIds::derive(&b.public_key);
        assert_ne!(ids_a.root_id, ids_b.root_id);
        assert!(ids_a.root_id.starts_with("root-operator-"));
        assert!(!ids_a.root_id.starts_with("root-daemon-"));
    }

    // ── V030-EMBER-DEVICE-REVOKE ───────────────────────────────────────────────

    /// Helper: bootstrap an operator root + enroll BOTH the founding presence
    /// Device and a backup presence Device. The founding key is also enrolled
    /// as a `Presence`-class Device under the root (mirrors what
    /// `commit_first_run_enrollment` does in production — `ensure_operator_identity`
    /// alone only creates root + persona, NOT the device row).
    /// Returns `(founding signer + material, backup signer + material, root_id,
    /// founding key_id, backup device_id, backup pubkey)`. Centralizes the
    /// 2-device authority-set fixture the revoke tests share.
    #[allow(clippy::type_complexity)]
    fn bootstrap_with_backup(
        store: &mut EventStore,
        founding_scalar: u8,
        backup_scalar: u8,
    ) -> (
        P256Signer,
        PublicKeyMaterial,
        P256Signer,
        PublicKeyMaterial,
        String,
        String,
        String,
        PublicKey,
    ) {
        let (founding, f_material) = device_signer(founding_scalar);
        let ids = ensure_operator_identity(store, &f_material, &founding).unwrap();

        // Enroll the founding device itself as a Presence-class Device. In
        // production this is what `commit_first_run_enrollment` does as the
        // third event of the genesis triple. Without it the founding key is
        // only the ROOT key — never a member of `devices_current` — and our
        // tests cannot exercise the "revoke a backup, founding survives" path
        // because the count would drop below the structural floor.
        let founding_device_id = format!(
            "device-operator-{}",
            f_material
                .public_key
                .strip_prefix("p256:")
                .unwrap_or(&f_material.public_key)
        );
        enroll_presence_device(
            store,
            &ids.root_id,
            DeviceEnrolledEvent {
                root_id: ids.root_id.clone(),
                device_id: founding_device_id.clone(),
                label: "Founding Device".to_string(),
                device_key: PublicKeyMaterial {
                    key_id: ids.key_id.clone(),
                    algorithm: KeyAlgorithm::EcdsaP256,
                    public_key: f_material.public_key.clone(),
                },
                encryption_key: enc_material(founding_scalar),
                custody_class: CustodyClass::Presence,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::UserPresence,
            },
            &founding,
            &ids.key_id,
            now_epoch_secs(),
        )
        .unwrap();

        let (backup, b_material) = device_signer(backup_scalar);
        let b_pk = backup.public_key().0;
        enroll_presence_device(
            store,
            &ids.root_id,
            DeviceEnrolledEvent {
                root_id: ids.root_id.clone(),
                device_id: format!("device-backup-{backup_scalar:02x}"),
                label: "Backup Device".to_string(),
                device_key: PublicKeyMaterial {
                    key_id: format!("key-backup-{backup_scalar:02x}"),
                    algorithm: KeyAlgorithm::EcdsaP256,
                    public_key: b_pk.clone(),
                },
                encryption_key: enc_material(backup_scalar),
                custody_class: CustodyClass::Presence,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::UserPresence,
            },
            &founding,
            &ids.key_id,
            now_epoch_secs(),
        )
        .unwrap();
        let backup_device_id = format!("device-backup-{backup_scalar:02x}");
        (
            founding,
            f_material,
            backup,
            b_material,
            ids.root_id,
            ids.key_id,
            backup_device_id,
            PublicKey(b_pk),
        )
    }

    /// T1a — `commit_device_revoke` flips the target Device's status to
    /// Revoked and drops it from the presence authority set. The founding
    /// device signs (it is itself an active presence Device under the root).
    #[test]
    fn commit_device_revoke_flips_status_and_drops_from_authority_set() {
        use core_crypto::{DOMAIN_EVENT, Signer, sign_with_context};

        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (founding, _f_material, _backup_signer, _b_material, _root_id, _key_id, backup_id, _) =
            bootstrap_with_backup(&mut store, 0x10, 0x20);

        let plan = device_revoke_plan(
            &store,
            &PublicKey(founding.public_key().0),
            &backup_id,
            "test revoke",
        )
        .expect("plan succeeds when authority key is active presence");
        let signature = sign_with_context(DOMAIN_EVENT, &founding, &plan.step.signing_bytes);
        commit_device_revoke(
            &mut store,
            &PublicKey(founding.public_key().0),
            &backup_id,
            "test revoke",
            signature,
            now_epoch_secs(),
        )
        .expect("commit succeeds with valid authority signature");

        // Status flipped to Revoked.
        let device = store
            .materialized()
            .devices_current
            .get(&backup_id)
            .expect("device record still present");
        assert_eq!(device.status, DeviceStatus::Revoked);

        // Presence-gate filter excludes the revoked device.
        let keys = active_presence_device_keys_under_operator_root(store.materialized());
        assert_eq!(
            keys.len(),
            1,
            "after revoke, only the founding presence Device remains in the authority set"
        );
        assert_eq!(keys[0], founding.public_key().0);
    }

    /// T1b — last-presence-device guard: the daemon refuses to revoke the
    /// final Active `presence` Device under the root. Bricking the authority
    /// set is structurally refused.
    #[test]
    fn device_revoke_refuses_last_active_presence_device() {
        use core_crypto::Signer;

        // Bootstrap with ONLY the founding presence Device (no backup).
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (founding, material) = device_signer(0x30);
        let ids = ensure_operator_identity(&mut store, &material, &founding).unwrap();
        let founding_device_id = format!(
            "device-operator-{}",
            material
                .public_key
                .strip_prefix("p256:")
                .unwrap_or(&material.public_key)
        );

        // Enroll the founding device as a Presence-class Device (mirrors
        // production `commit_first_run_enrollment`). Without this it would
        // not be in `devices_current` at all and the guard wouldn't fire
        // — the more interesting test is the one-presence-Device case.
        enroll_presence_device(
            &mut store,
            &ids.root_id,
            DeviceEnrolledEvent {
                root_id: ids.root_id.clone(),
                device_id: founding_device_id.clone(),
                label: "Founding Device".to_string(),
                device_key: PublicKeyMaterial {
                    key_id: ids.key_id.clone(),
                    algorithm: KeyAlgorithm::EcdsaP256,
                    public_key: founding.public_key().0,
                },
                encryption_key: enc_material(0x30),
                custody_class: CustodyClass::Presence,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::UserPresence,
            },
            &founding,
            &ids.key_id,
            now_epoch_secs(),
        )
        .unwrap();

        // Sanity: exactly ONE active presence Device under the root.
        assert_eq!(
            active_presence_device_keys_under_operator_root(store.materialized()).len(),
            1
        );

        // PLAN must refuse — the operator should never even be asked to tap.
        let err = device_revoke_plan(
            &store,
            &PublicKey(founding.public_key().0),
            &founding_device_id,
            "would-brick",
        )
        .unwrap_err();
        // META-V030-DEVICE-REVOKE-ERROR-CODE-SUBSPACE: the last-device guard
        // returns its own typed variant (mapped to -32032 at the RPC boundary),
        // not the generic Genesis(_) bucket the other refusals use.
        // Anchor: device_revoke_last_device_distinct_error_code_landed.
        assert!(
            matches!(err, OperatorIdentityError::LastPresenceDeviceGuard(_)),
            "last-device guard must surface as the typed variant, got: {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("last active presence Device") && msg.contains("brick"),
            "last-device refusal message must name the structural reason; got: {msg}"
        );
    }

    /// T1c — the eventlog authorizer rejects a revoke signed by a key that is
    /// not an active presence Device under the operator root. The plan
    /// helper's fail-closed posture matches the authorizer.
    #[test]
    fn device_revoke_refuses_unknown_authority_key() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (_founding, _f_material, _b_signer, _b_material, _root_id, _key_id, backup_id, _) =
            bootstrap_with_backup(&mut store, 0x40, 0x50);
        // A key that was never enrolled.
        let (attacker, _attacker_material) = device_signer(0x60);

        let err = device_revoke_plan(
            &store,
            &PublicKey(attacker.public_key().0),
            &backup_id,
            "attacker revoke",
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not an active presence Device"),
            "unknown-authority refusal must name the missing-authority reason; got: {msg}"
        );
    }

    /// T1d — the plan refuses on an unknown device id (no silent no-op).
    #[test]
    fn device_revoke_refuses_unknown_device_id() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (founding, _f_material, _b_signer, _b_material, _root_id, _key_id, _backup_id, _) =
            bootstrap_with_backup(&mut store, 0x70, 0x80);

        let err = device_revoke_plan(
            &store,
            &PublicKey(founding.public_key().0),
            "device-not-in-store",
            "noop",
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not enrolled"),
            "unknown-device refusal must name the not-enrolled reason; got: {msg}"
        );
    }

    /// T1e — re-revoking an already-Revoked device is a typed refusal, not a
    /// silent no-op (so audit chains never carry duplicate Revoked rows).
    #[test]
    fn device_revoke_refuses_already_revoked() {
        use core_crypto::{DOMAIN_EVENT, Signer, sign_with_context};

        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (founding, _f_material, _b_signer, _b_material, _root_id, _key_id, backup_id, _) =
            bootstrap_with_backup(&mut store, 0x90, 0xA0);

        let plan = device_revoke_plan(
            &store,
            &PublicKey(founding.public_key().0),
            &backup_id,
            "first revoke",
        )
        .unwrap();
        let sig = sign_with_context(DOMAIN_EVENT, &founding, &plan.step.signing_bytes);
        commit_device_revoke(
            &mut store,
            &PublicKey(founding.public_key().0),
            &backup_id,
            "first revoke",
            sig,
            now_epoch_secs(),
        )
        .unwrap();

        let err = device_revoke_plan(
            &store,
            &PublicKey(founding.public_key().0),
            &backup_id,
            "second revoke",
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not Active"), "got: {msg}");
    }

    /// META-V030-DEVICE-REVOKE-PLAN-CARRIER-REFACTOR — pins the
    /// [`OobRevokePlan`] carrier shape so a future field addition to the
    /// plan forces this test to be updated rather than producing a
    /// silent runtime stub (which is what the placeholder
    /// `DeviceEnrolledEvent` field on the previous shared
    /// `OobBackupEnrollPlan` carrier would have done — adversarial
    /// finding F10.2 LOW on PR #5898). Anchor:
    /// `device_revoke_plan_uses_typed_carrier_landed`.
    ///
    /// The destructuring pattern `{ root_id, device_id,
    /// authority_key_id, reason, step }` is the load-bearing assertion:
    /// adding a field to `OobRevokePlan` without updating this pattern
    /// is a hard compile error (non-exhaustive destructuring of a local
    /// struct). The string assertions then pin the field values
    /// PREPARE must produce so a maintainer cannot silently drop the
    /// COMMIT-input threading either.
    #[test]
    fn device_revoke_plan_carrier_shape_is_typed() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let (founding, _f_material, _b_signer, _b_material, root_id, _key_id, backup_id, _) =
            bootstrap_with_backup(&mut store, 0xB0, 0xC0);

        let plan = device_revoke_plan(
            &store,
            &PublicKey(founding.public_key().0),
            &backup_id,
            "carrier-shape-pin",
        )
        .expect("plan succeeds when authority key is active presence");

        // Exhaustive destructure — a future field addition to
        // `OobRevokePlan` fails this match at compile time, surfacing
        // the carrier-shape change at the regression-test boundary
        // rather than as a silent runtime stub.
        let OobRevokePlan {
            root_id: plan_root_id,
            device_id: plan_device_id,
            authority_key_id: plan_authority_key_id,
            reason: plan_reason,
            step:
                OobEnrollStep {
                    purpose,
                    event_id,
                    signing_bytes,
                },
        } = plan;

        assert_eq!(plan_root_id, root_id);
        assert_eq!(plan_device_id, backup_id);
        assert!(
            !plan_authority_key_id.is_empty(),
            "authority_key_id must be threaded (the SignerBinding key_id COMMIT uses)"
        );
        // Reason MUST be threaded so COMMIT can rebuild the exact
        // `DeviceRevokedEvent` PREPARE computed `signing_bytes` for.
        assert_eq!(plan_reason, "carrier-shape-pin");
        assert_eq!(purpose, "operator-device-revoke");
        assert!(
            event_id.contains("/revoke/") && event_id.contains(&backup_id),
            "event_id is deterministic and names the revoke target; got: {event_id}"
        );
        assert!(
            !signing_bytes.is_empty(),
            "signing_bytes must be the canonical event pre-image"
        );
    }
}
