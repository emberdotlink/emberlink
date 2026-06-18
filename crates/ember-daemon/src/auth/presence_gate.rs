//! ADR 200 §3/§6 — the uniform `require_authority(op, lane)` presence gate.
//!
//! This supersedes the daemon-signed presence token (`presence_token.rs`,
//! daemon-forgeable) as the authority anchor for **authority-widening** ops. A
//! widening op is admitted only with a **fresh, nonce-bound signature by a
//! `presence`-class Device** the daemon does not hold a private key for (G1):
//!
//! 1. The daemon issues a single-use **nonce** bound to `(op_id, daemon
//!    fingerprint, method)` and tombstones it in `presence_challenges`.
//! 2. The operator signs the **canonical intent bytes** (domain-separated,
//!    nonce-bound) on their YubiKey PIV (`presence` Device), out-of-band.
//! 3. `require_authority` consumes the nonce atomically (DELETE-then-validate,
//!    mirroring `webauthn_challenges`), then verifies the signature against the
//!    enrolled presence-Device's P256 key via `core_crypto::verify_device_signature`
//!    — **never** the Ed25519 path (algorithm-confusion bar).
//!
//! Freshness (AC-3): PIV has no FIDO sign-counter, so the daemon-issued
//! single-use nonce is the SOLE freshness primitive. The `(op_id, nonce)`
//! tombstone makes a captured signature non-replayable.
//!
//! Lane policy (OQ-5, operator-approved 2026-05-30): [`presence_required`] is the
//! op→lane map. It is a SIBLING predicate to `authority_class_for_method`, NOT a
//! re-derivation from `AuthorityClass::OperatorPresence` — because `vault_lock`
//! / `close_session` already escape that class via
//! `operator_presence_token_optional_method`, so re-deriving would mis-gate.

/// Domain separation for the presence-gate signing tuple (ADR 174 v2 §4 pattern,
/// extended with the nonce per ADR 200 §3). Binds the signature to THIS protocol
/// so it cannot be substituted across contexts.
pub const DOMAIN_PRESENCE_INTENT: &str = "emberlink.v1.presence_authority_intent";

/// The lane an operation requires (ADR 200 §6). dev0 uses `Presence` and
/// `Routine`; `CoAuthority` is reserved for team0 (assigned to nothing here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityLane {
    /// Authority-widening: a fresh presence-Device signature is required.
    Presence,
    /// A designated co-authority (KMS / second-emberd) approval is required.
    /// Reserved — not assigned to any dev0 method.
    CoAuthority,
    /// Operator-grade but bounded/reversible/within-existing-authority — rides
    /// the unlocked-session proof, no per-op presence signature.
    Routine,
}

/// Per-resource presence policy, orthogonal to the method-level
/// [`AuthorityLane`].
///
/// `AuthorityLane` is a property of the *method* (op→lane is a constant
/// table). `PresencePolicy` is a property of the *resource* (per-vault-row
/// today; future: per-grant, per-binding). A row tagged
/// [`PerAccessFresh`](PresencePolicy::PerAccessFresh) demands a fresh,
/// nonce-bound presence-Device signature on every access, including paths
/// that the method-lane table would normally let ride a cached unlock.
/// Closes the cached-unlock bypass surfaced by PR #6088.
///
/// Folding both axes into one vocabulary (this enum + [`AuthorityLane`])
/// retires the previous parallel structure where vault rows carried a
/// `requires_biometric: bool` while methods carried `presence_required`.
/// Per the 2026-06-17 directional audit (Fork 1) and the unified read-gate
/// at the bottom of `infra::vault::Vault::get_with_read_gate`, presence
/// is required iff `is_presence_widening(method) ||
/// resource.presence_policy == PerAccessFresh`.
///
/// Naming convention: the variant strings (`lane_default`,
/// `per_access_fresh`) are the on-the-wire SQLite encoding; do not rename
/// without a coordinated schema migration. See
/// `infra::store::DaemonStore::apply_credentials_migrations`.
///
/// Anchor: `vault_presence_policy_unified_with_adr206`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresencePolicy {
    /// Defer to the calling method's [`AuthorityLane`]: reads ride cached
    /// unlock; widening writes go through `required_lane`. The default
    /// state of a vault row that does not opt into per-resource
    /// escalation.
    LaneDefault,
    /// Every access — read OR write — demands a fresh nonce-bound
    /// presence-Device signature. Mapped from the legacy
    /// `requires_biometric=1` flag on existing vault rows; the canonical
    /// state for high-sensitivity rows (provider credentials, signing
    /// material) where the operator wants a tap on every retrieval rather
    /// than just on the widening dispatch.
    PerAccessFresh,
}

impl PresencePolicy {
    /// True iff this policy demands a fresh presence-Device signature on
    /// every access regardless of method lane. Used by the vault read-gate
    /// to enforce the per-resource override on lanes that would otherwise
    /// allow cached unlock.
    pub fn requires_fresh_presence(self) -> bool {
        matches!(self, PresencePolicy::PerAccessFresh)
    }

    /// Construct from the legacy boolean flag carried on vault rows pre
    /// the presence-policy unification. `true` →
    /// `PerAccessFresh`, `false` → `LaneDefault`. Used by the SQLite
    /// migration in `infra::store` and by handlers still ingesting the
    /// boolean flag at the protocol boundary.
    pub fn from_requires_biometric(requires_biometric: bool) -> Self {
        if requires_biometric {
            PresencePolicy::PerAccessFresh
        } else {
            PresencePolicy::LaneDefault
        }
    }

    /// The on-the-wire SQLite encoding. `lane_default` / `per_access_fresh`
    /// are stable strings — coordinate with a schema migration if these
    /// ever change.
    pub fn as_db_str(self) -> &'static str {
        match self {
            PresencePolicy::LaneDefault => "lane_default",
            PresencePolicy::PerAccessFresh => "per_access_fresh",
        }
    }

    /// Parse from the on-the-wire SQLite encoding. Returns
    /// `LaneDefault` for any unknown value so a forward-compat row never
    /// fail-OPEN-closes vault reads on an unrecognized policy label.
    pub fn from_db_str(raw: &str) -> Self {
        match raw {
            "per_access_fresh" => PresencePolicy::PerAccessFresh,
            // `lane_default` and anything else fall through to the
            // safe-default lane behavior (still gated by widening dispatch
            // for writes; cached-unlock-OK for routine reads).
            _ => PresencePolicy::LaneDefault,
        }
    }
}

/// The op→lane map (OQ-5, operator-approved 2026-05-30). Returns the lane a
/// method requires. `Routine` is the default for any OperatorPresence-class
/// method not listed `Presence` here; ConnectOnly reads never reach this gate.
///
/// The bright line (operator): `Presence` IFF the op CREATES/EXPANDS standing
/// authority, enrolls/replaces a custody device, mutates the trust/identity
/// root, performs an irreversible high-trust mutation a compromised daemon must
/// not self-authorize (audit-chain repair, MEK / local-state-key rotation,
/// binary pin), or unseals daemon-held key material.
pub fn required_lane(method: &str) -> AuthorityLane {
    if is_presence_widening(method) {
        AuthorityLane::Presence
    } else {
        AuthorityLane::Routine
    }
}

/// True iff `method` is authority-widening and therefore requires a fresh
/// presence-Device signature (ADR 200 §6, operator-approved op→lane table).
pub fn is_presence_widening(method: &str) -> bool {
    matches!(
        method,
        // Identity / persona root surgery.
        "create_persona"
        | "build_init_first_grant_receipt"
        // Grant ISSUANCE / authority expansion (agent offline-attenuation of an
        // existing grant via its own bounded key is distinct and unaffected).
        | "create_grant"
        | "create_composite_grant"
        | "delegate_grant"
        | "extend_grant"
        | "grant.extend"
        | "propose_grant"
        | "create_standing_grant"
        | "save_delegation_template"
        | "resolve_approval"
        | "approval.resolve"
        | "approval_resolve"
        | "approval.narrow"
        | "approval_narrow"
        // Session launch grant (ADR 158 Touch-ID-at-launch). Resume/re-attach
        // rides describe_runtime_attach_target (ConnectOnly), NOT this.
        | "register_session"
        // Vault writes + ACL/MEK mutation. vault_rotate_execute REMOVES the
        // ADR-198 D7 SO_PEERCRED carve-out (superseded by G1, operator-approved).
        | "vault_add"
        | "vault_put"
        | "vault_migrate_acl"
        | "vault_rotate_execute"
        | "vault_export_sealed"
        | "vault_import_sealed"
        // Local-state key rotation + binary pin = irreversible high-trust.
        | "local_state_key_rotate_and_reencrypt"
        | "binary_pin_generate"
        // Unsealing daemon-held key material (split from sops.wrap = routine).
        | "sops_unwrap_dek"
        | "sops.unwrap"
        // Device enrollment (custody-class establishment).
        | "headless_enroll"
        // Audit-chain repair = irreversible trust-record mutation.
        | "audit_repair_chain"
        // Presence proof ceremony entrypoint.
        | "presence/request_proof"
        | "presence_request_proof" // NOTE: operator device enrollment (`identity.device.enroll`, ADR 200 §5)
                                   // is deliberately NOT widening — it is OperatorPresence-gated by the
                                   // daemon's native unlock, because the widening lane's nonce-bound
                                   // presence-signature check needs an already-enrolled presence Device, which
                                   // is exactly the bootstrap chicken/egg enrollment must break (session-03 §5).
                                   // The retired `presence/enroll`/`presence_enroll` stub previously sat here.
    )
    // OQ-5 op→lane RESOLVED (operator-routed adversarial verdicts, 2026-05-31 —
    // session-02-presence-gate.md §"3 contested calls"). The three contested
    // calls are NOT widening; they stay Routine and are deliberately absent above:
    //
    //   1. The "tap-once-opens-N-seconds" TTL window = 3/3 PRESENCE forgery hole
    //      (the daemon, being both gate AND dispatcher, could ride an open window
    //      to manufacture authority the human never approved). DECISION: no window.
    //      This gate is strictly PER-OP TAP — `require_authority` verifies a fresh,
    //      single-use, nonce-bound signature on EVERY widening call (AC-3); it holds
    //      no time-window state, so no window mechanism exists to exploit. The safe
    //      relief valve (a signed batch manifest committing one tap to ≤16 enumerated
    //      (op_id,nonce) ops) is a separate DEFERRED slice — see buildout follow-up
    //      `G6-FOLLOWUP-signed-batch-manifest`; NOT needed for correctness here.
    //   2. broker_issue = Routine (capability/exercise lane, no presence). The
    //      "req.scope ⊆ grant.scope" subset enforcement that BOUNDS broker_issue is
    //      broker-internal, NOT a gate concern — it is owned by the broker lane
    //      (BKR-1/2, `issue_with_registry` via `core_grants::scope::enforce_subset`)
    //      per the cross-lane lock (buildout §8 lock 1). G6 DECLARES the lane; BKR
    //      IMPLEMENTS the subset. G6 does not implement it and does not block on it.
    //   3. broker_exec / broker_resolve = Routine (same capability lane).
    //   4. vault_remove = Routine for THIS gate. (Its separate audit-chaining gap —
    //      a `vault.remove` mutation must leave a tamper-evident audit record — is
    //      closed in the dispatch handler, not here.)
}

/// Canonical, domain-separated, nonce-bound signing bytes for a presence intent
/// (ADR 174 v2 §4 + ADR 200 §3). RFC 8785 (JCS) over the 6-field intent object
/// so an **independent, out-of-tree** verifier can reproduce the exact bytes
/// from the spec alone (AC-1) — not by reverse-engineering a Rust `BTreeMap` +
/// `serde_json` quirk. The operator's presence Device signs THESE bytes; the
/// verifier reconstructs them from the recorded fields + the issued nonce and
/// checks the signature. Frozen by the `golden_canonical_intent_bytes` fixture;
/// the same canonicalizer the inner [`presence_params_digest`] and the receipt
/// lane use (`core_crypto::canonicalize_jcs`), so there is one canonical form.
///
/// `params_digest` binds the **object** of the op (its authority-relevant
/// params), not just the **verb** (`method`) — ADR 206 §1.3 "Intent-bound:
/// covers a canonical serialization of the *exact* operation(s)". Without it the
/// proof admits ANY instance of `method` (approval-laundering Finding 1: a
/// compromised daemon shows `create_grant read:foo`, the operator taps, the
/// daemon dispatches `create_grant *:admin` under the same verifying proof).
/// Computed by [`presence_params_digest`]; bound into the nonce row at mint and
/// recomputed over the RECEIVED params at consume (handler chokepoint).
pub fn canonical_presence_intent_bytes(
    method: &str,
    op_id: &str,
    nonce: &str,
    daemon_fingerprint: &str,
    params_digest: &str,
) -> Vec<u8> {
    // RFC 8785 (JCS) canonical form: keys sorted by UTF-16 code unit, minimal
    // string escaping, no insignificant whitespace. A third-party verifier with
    // only the ADR spec + the public key can reproduce these exact bytes, which
    // `serde_json::to_vec` of a Rust `BTreeMap` could not guarantee (its escaping
    // is an implementation detail, not a documented wire format). All values are
    // strings, so canonicalization is infallible.
    let value = serde_json::json!({
        "ctx": DOMAIN_PRESENCE_INTENT,
        "method": method,
        "op_id": op_id,
        "nonce": nonce,
        "daemon_fingerprint": daemon_fingerprint,
        "params_digest": params_digest,
    });
    core_crypto::canonicalize_jcs(&value).expect("string-only intent object always canonicalizes")
}

/// ADR 206 §1.3 (Intent-bound) / H1 mitigation — the canonical digest of an
/// operation's **authority-relevant params**, bound into the presence intent so
/// the signed proof covers the OBJECT (params) and not merely the VERB (method).
///
/// blake3 over the JCS-canonical params (`core_crypto::canonicalize_jcs`,
/// the same canonicalizer the receipt lane uses) with the post-sign **envelope
/// fields removed**: `_presence_proof`, `scope_kek`, and `_presence_token` are
/// all attached to the request AFTER the operator signs (and the daemon receives
/// them on the wire), so they must NOT be part of the digested body — otherwise
/// the signer's digest (computed before attachment) and the verifier's digest
/// (computed over the received request) could never agree. Both sides call THIS
/// function over their respective views of the params, and the stripped sets are
/// identical, so the digests match iff the authority-relevant params match.
///
/// Returns `Err` only if the params contain a value JCS cannot canonicalize
/// (non-finite float) — impossible for wire-parsed JSON; callers fail closed.
pub fn presence_params_digest(
    params: &serde_json::Value,
) -> Result<String, core_crypto::CanonicalizeError> {
    let mut digestable = params.clone();
    if let serde_json::Value::Object(map) = &mut digestable {
        // Envelope/transport fields attached after signing — never part of the
        // operator's signed intent. Keep this set in sync with the CLI's
        // `attach_presence_proof` / `attach_presence_proof_and_scope_kek` /
        // `attach_presence_token`.
        //
        // FORWARD NOTE: today the ONLY presence-signable caller is the host
        // operator on the main socket, so the daemon recomputes this digest over
        // the SAME params the CLI signed. The per-agent / mTLS-bridge persona
        // overlay (`handler.rs` `overlaid_params`) injects `persona`/`persona_id`/
        // grant fields that are NOT in this strip-set — benign now (overlay paths
        // cannot produce a real `_presence_proof`), but if a future change ever
        // routes a presence-signable widening op through that overlay, the
        // daemon-recomputed digest would diverge from the operator-signed one
        // (universal false-break). Revisit this strip-set / sign over post-overlay
        // params at that point.
        map.remove("_presence_proof");
        map.remove("scope_kek");
        map.remove("_presence_token");
    }
    let canon = core_crypto::canonicalize_jcs(&digestable)?;
    Ok(format!("b3:{}", blake3::hash(&canon).to_hex()))
}

/// Verify a presence-Device signature over the canonical intent bytes. The
/// `device_public_key` is the enrolled presence Device's `p256:` key (from
/// `persona_device_access` / `devices_current`, custody_class=presence). Routed
/// through `verify_device_signature` so P256 keys use the P256 verifier.
pub fn verify_presence_signature(
    method: &str,
    op_id: &str,
    nonce: &str,
    daemon_fingerprint: &str,
    params_digest: &str,
    device_public_key: &str,
    signature: &core_crypto::Signature,
) -> bool {
    let bytes =
        canonical_presence_intent_bytes(method, op_id, nonce, daemon_fingerprint, params_digest);
    core_crypto::verify_device_signature(
        &core_crypto::PublicKey(device_public_key.to_string()),
        &bytes,
        signature,
    )
}

/// Outcome of a presence-authority check.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthorityOutcome {
    /// The op is routine — no presence signature required (rides session proof).
    Routine,
    /// A widening op carrying a verified, fresh presence-Device signature.
    PresenceVerified,
    /// A widening op whose presence signature is missing or did not verify.
    PresenceRequired(String),
}

/// The uniform gate (ADR 200 §6). Decides whether `method` may proceed, given an
/// optionally-supplied presence proof. This is the daemon-side orchestration:
///
/// - Routine ops pass through (the unlocked-session proof already gates them at
///   the existing OperatorPresence layer; this gate adds nothing for them).
/// - A widening op REQUIRES a `PresenceProof`: a fresh nonce (already consumed +
///   tombstoned by the caller via `DaemonStore::consume_presence_nonce`) and a
///   signature over the canonical intent bytes verifying against the enrolled
///   presence Device's key. The daemon holds no presence private key (G1), so it
///   cannot synthesize this.
///
/// **Internal callers are NOT exempted for widening ops** (closes adversarial
/// A2): `source_is_internal` does not short-circuit a `Presence` lane — the
/// signature is required regardless of dispatch source.
pub fn require_authority(
    method: &str,
    source_is_internal: bool,
    proof: Option<&PresenceProof<'_>>,
) -> AuthorityOutcome {
    match required_lane(method) {
        AuthorityLane::Routine => AuthorityOutcome::Routine,
        // co-authority is reserved (team0); treat as presence-strength here so a
        // dev0 misconfiguration fails closed rather than silently routine.
        AuthorityLane::Presence | AuthorityLane::CoAuthority => {
            let _ = source_is_internal; // intentionally NOT an exemption (A2).
            let Some(p) = proof else {
                return AuthorityOutcome::PresenceRequired(format!(
                    "widening op '{method}' requires a presence-Device signature"
                ));
            };
            let ok = verify_presence_signature(
                method,
                p.op_id,
                p.nonce,
                p.daemon_fingerprint,
                p.params_digest,
                p.device_public_key,
                p.signature,
            );
            if ok {
                AuthorityOutcome::PresenceVerified
            } else {
                AuthorityOutcome::PresenceRequired(format!(
                    "presence signature for '{method}' did not verify against the enrolled device"
                ))
            }
        }
    }
}

/// A presence proof supplied with a widening RPC. The `nonce` must already have
/// been consumed + tombstoned (single-use, AC-3) before this proof is trusted;
/// `device_public_key` is the enrolled presence Device's `p256:` key.
pub struct PresenceProof<'a> {
    pub op_id: &'a str,
    pub nonce: &'a str,
    pub daemon_fingerprint: &'a str,
    /// The [`presence_params_digest`] of the op's authority-relevant params,
    /// bound into the signed intent so the proof covers the OBJECT, not just the
    /// VERB (ADR 206 §1.3 / approval-laundering Finding 1).
    pub params_digest: &'a str,
    pub device_public_key: &'a str,
    pub signature: &'a core_crypto::Signature,
}

/// A presence proof as it arrives on the wire — the `_presence_proof` object the
/// operator-session signing driver attaches to a widening RPC (ADR 206 §1). It
/// carries only what the operator produced: the `op_id`/`nonce` it asked the
/// daemon to mint, and the presence Device's signature over the daemon-computed
/// `canonical_presence_intent_bytes`.
///
/// The enrolled Device **public key is deliberately NOT carried here**. A
/// wire-supplied key could never be trusted as the anchor (a compromised client
/// would just supply its own); the daemon verifies the signature against the
/// `presence`-class Device key set it materializes itself from the operator root
/// (1-of-N — see [`wire_proof_verifies_against_any`]). The `daemon_fingerprint`
/// is likewise the daemon's own (`identity_root_fingerprint`), never wire-claimed.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WirePresenceProof {
    pub op_id: String,
    pub nonce: String,
    /// ECDSA-P256 DER signature, `p256sig:<der-hex>` (the untagged der-hex form is
    /// accepted too and normalized — mirrors the enrollment COMMIT path).
    pub signature: String,
}

impl WirePresenceProof {
    /// Normalize the wire signature to the tagged [`core_crypto::Signature`] the
    /// P256 verifier strips (`p256sig:<der-hex>`), accepting the untagged der-hex
    /// form for parity with the enrollment COMMIT path.
    pub fn normalized_signature(&self) -> core_crypto::Signature {
        let tagged = if self.signature.starts_with("p256sig:") {
            self.signature.clone()
        } else {
            format!("p256sig:{}", self.signature)
        };
        core_crypto::Signature(tagged)
    }
}

/// Verify a [`WirePresenceProof`] against the enrolled `presence`-class Device key
/// set (1-of-N): returns `true` iff at least one enrolled key verifies the
/// signature over the canonical intent bytes for `(method, op_id, nonce,
/// daemon_fingerprint)`.
///
/// **The caller MUST have already atomically consumed the nonce**
/// (`DaemonStore::consume_presence_nonce`, which binds `op_id`/`method`/
/// `daemon_fingerprint` + freshness + single-use) before trusting a `true` here —
/// this function checks only the signature, not replay/freshness. An empty
/// `enrolled_keys` returns `false` (fail-closed: no anchor → no admission).
pub fn wire_proof_verifies_against_any(
    method: &str,
    daemon_fingerprint: &str,
    params_digest: &str,
    enrolled_keys: &[String],
    proof: &WirePresenceProof,
) -> bool {
    let sig = proof.normalized_signature();
    enrolled_keys.iter().any(|key| {
        verify_presence_signature(
            method,
            &proof.op_id,
            &proof.nonce,
            daemon_fingerprint,
            params_digest,
            key,
            &sig,
        )
    })
}

/// Return the enrolled `(device_id, public_key)` whose presence signature
/// verified, when attribution is needed for an audit receipt.
pub fn wire_proof_matching_device(
    method: &str,
    daemon_fingerprint: &str,
    params_digest: &str,
    enrolled_devices: &[(String, String)],
    proof: &WirePresenceProof,
) -> Option<(String, String)> {
    let sig = proof.normalized_signature();
    enrolled_devices
        .iter()
        .find(|(_device_id, key)| {
            verify_presence_signature(
                method,
                &proof.op_id,
                &proof.nonce,
                daemon_fingerprint,
                params_digest,
                key,
                &sig,
            )
        })
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A P256 presence-Device keypair for tests (RFC6979 — deterministic).
    fn p256_device(scalar: u8) -> (String, p256::ecdsa::SigningKey) {
        let sk = p256::ecdsa::SigningKey::from_bytes(&[scalar; 32].into()).unwrap();
        let pt = sk.verifying_key().to_encoded_point(false);
        (format!("p256:{}", hex::encode(pt.as_bytes())), sk)
    }

    /// A fixed, opaque params digest for the tests that do not vary it.
    /// `canonical_presence_intent_bytes` treats `params_digest` as an opaque
    /// field, so any stable string exercises the binding.
    const TD: &str = "b3:testdigest";

    fn sign_intent(
        sk: &p256::ecdsa::SigningKey,
        method: &str,
        op_id: &str,
        nonce: &str,
        fp: &str,
        digest: &str,
    ) -> core_crypto::Signature {
        use p256::ecdsa::signature::Signer as _;
        let bytes = canonical_presence_intent_bytes(method, op_id, nonce, fp, digest);
        let sig: p256::ecdsa::Signature = sk.sign(&bytes);
        core_crypto::Signature(format!("p256sig:{}", hex::encode(sig.to_der().as_bytes())))
    }

    #[test]
    fn routine_op_passes_without_proof() {
        assert_eq!(
            require_authority("broker_exec", false, None),
            AuthorityOutcome::Routine
        );
    }

    #[test]
    fn widening_op_without_proof_is_refused_even_internal() {
        // A2: Internal source does NOT exempt a widening op.
        let out = require_authority("create_grant", true, None);
        assert!(
            matches!(out, AuthorityOutcome::PresenceRequired(_)),
            "internal must not bypass: {out:?}"
        );
    }

    #[test]
    fn widening_op_with_valid_presence_signature_verifies() {
        let (pk, sk) = p256_device(0x21);
        let sig = sign_intent(&sk, "create_grant", "op-7", "pnonce-xyz", "fp-1", TD);
        let proof = PresenceProof {
            op_id: "op-7",
            nonce: "pnonce-xyz",
            daemon_fingerprint: "fp-1",
            params_digest: TD,
            device_public_key: &pk,
            signature: &sig,
        };
        assert_eq!(
            require_authority("create_grant", false, Some(&proof)),
            AuthorityOutcome::PresenceVerified
        );
    }

    #[test]
    fn widening_op_rejects_signature_over_different_op_or_nonce() {
        let (pk, sk) = p256_device(0x22);
        // Signature is over op-7/nonce-A; proof claims op-7/nonce-B (replay/swap).
        let sig = sign_intent(&sk, "create_grant", "op-7", "nonce-A", "fp-1", TD);
        let proof = PresenceProof {
            op_id: "op-7",
            nonce: "nonce-B",
            daemon_fingerprint: "fp-1",
            params_digest: TD,
            device_public_key: &pk,
            signature: &sig,
        };
        assert!(matches!(
            require_authority("create_grant", false, Some(&proof)),
            AuthorityOutcome::PresenceRequired(_)
        ));
    }

    #[test]
    fn widening_op_rejects_signature_over_different_params() {
        // Finding 1 (params substitution): a signature minted over digest-A must
        // NOT verify when the proof carries digest-B (the daemon substituted the
        // op body after the tap). The verb is identical; only the OBJECT differs.
        let (pk, sk) = p256_device(0x22);
        let sig = sign_intent(&sk, "create_grant", "op-7", "n-1", "fp-1", "b3:read-foo");
        let proof = PresenceProof {
            op_id: "op-7",
            nonce: "n-1",
            daemon_fingerprint: "fp-1",
            params_digest: "b3:admin-everything",
            device_public_key: &pk,
            signature: &sig,
        };
        assert!(
            matches!(
                require_authority("create_grant", false, Some(&proof)),
                AuthorityOutcome::PresenceRequired(_)
            ),
            "a proof signed over different params must not verify"
        );
    }

    #[test]
    fn widening_op_rejects_wrong_device_key() {
        let (_pk_a, sk_a) = p256_device(0x23);
        let (pk_b, _sk_b) = p256_device(0x24);
        let sig = sign_intent(&sk_a, "vault_add", "op-9", "n-1", "fp-1", TD);
        // Verify against device B's key — must fail.
        let proof = PresenceProof {
            op_id: "op-9",
            nonce: "n-1",
            daemon_fingerprint: "fp-1",
            params_digest: TD,
            device_public_key: &pk_b,
            signature: &sig,
        };
        assert!(matches!(
            require_authority("vault_add", false, Some(&proof)),
            AuthorityOutcome::PresenceRequired(_)
        ));
    }

    #[test]
    fn widening_ops_require_presence() {
        for m in [
            "create_grant",
            "create_persona",
            "delegate_grant",
            "vault_add",
            "vault_rotate_execute",
            "audit_repair_chain",
            "headless_enroll",
            "sops.unwrap",
            "binary_pin_generate",
            "register_session",
        ] {
            assert_eq!(
                required_lane(m),
                AuthorityLane::Presence,
                "{m} must be presence"
            );
        }
    }

    #[test]
    fn routine_ops_do_not_require_presence() {
        for m in [
            // Reversible / privilege-reduction.
            "revoke_persona",
            "recover_persona_abandon",
            "revoke_grant",
            "vault_lock",
            "close_session",
            // Within-existing-grant execution.
            "broker_exec",
            "sandbox_exec",
            "use_credential",
            // Reads.
            "audit_log_query",
            "grant_summary",
            "list_all_grants",
            // Encrypt-only (no unseal).
            "sops.wrap",
            "sops.pubkey",
            // Agent-side asks (the decision resolve_approval is presence; the ask is not).
            "submit_approval",
            "request_access",
        ] {
            assert_eq!(
                required_lane(m),
                AuthorityLane::Routine,
                "{m} must be routine"
            );
        }
    }

    #[test]
    fn oq5_contested_calls_resolved_to_routine() {
        // OQ-5 (buildout §8 lock 1 / session-02 verdicts): the three contested
        // calls resolve to the Routine/capability lane, NOT widening. broker_issue
        // is bounded by the broker-internal subset enforcement (BKR-1/2), not this
        // gate; vault_remove's audit-chaining is a separate handler concern.
        for m in [
            "broker_issue",
            "broker_exec",
            "broker_resolve",
            "vault_remove",
        ] {
            assert_eq!(
                required_lane(m),
                AuthorityLane::Routine,
                "{m} must be routine (OQ-5)"
            );
            assert_eq!(
                require_authority(m, false, None),
                AuthorityOutcome::Routine,
                "{m} must be admitted with no presence proof"
            );
        }
    }

    #[test]
    fn presence_gate_is_per_op_tap_with_no_window() {
        // Verdict #1: the "tap-once-opens-N-seconds" window is rejected. The gate
        // is stateless — a just-verified widening op opens NO window for the next
        // one; each call independently requires its own fresh proof (AC-3).
        let (pk, sk) = p256_device(0x31);
        let sig = sign_intent(&sk, "create_grant", "op-A", "n-A", "fp", TD);
        let proof = PresenceProof {
            op_id: "op-A",
            nonce: "n-A",
            daemon_fingerprint: "fp",
            params_digest: TD,
            device_public_key: &pk,
            signature: &sig,
        };
        assert_eq!(
            require_authority("create_grant", false, Some(&proof)),
            AuthorityOutcome::PresenceVerified
        );
        // Immediately after a successful tap, a second widening op with NO proof is
        // still refused — the prior tap opened no window.
        assert!(matches!(
            require_authority("create_grant", false, None),
            AuthorityOutcome::PresenceRequired(_)
        ));
        assert!(matches!(
            require_authority("vault_add", false, None),
            AuthorityOutcome::PresenceRequired(_)
        ));
    }

    fn sign_intent_untagged(
        sk: &p256::ecdsa::SigningKey,
        method: &str,
        op_id: &str,
        nonce: &str,
        fp: &str,
        digest: &str,
    ) -> String {
        use p256::ecdsa::signature::Signer as _;
        let bytes = canonical_presence_intent_bytes(method, op_id, nonce, fp, digest);
        let sig: p256::ecdsa::Signature = sk.sign(&bytes);
        hex::encode(sig.to_der().as_bytes())
    }

    #[test]
    fn wire_proof_verifies_against_enrolled_key_one_of_n() {
        let (pk_a, _sk_a) = p256_device(0x41);
        let (pk_b, sk_b) = p256_device(0x42);
        // Operator signs with device B (untagged der-hex — must be normalized).
        let proof = WirePresenceProof {
            op_id: "op-1".into(),
            nonce: "n-1".into(),
            signature: sign_intent_untagged(&sk_b, "create_grant", "op-1", "n-1", "fp", TD),
        };
        // Enrolled set is {A, B}; B verifies → admitted (1-of-N).
        assert!(wire_proof_verifies_against_any(
            "create_grant",
            "fp",
            TD,
            &[pk_a.clone(), pk_b.clone()],
            &proof,
        ));
        // Enrolled set is {A} only → the B-signed proof does NOT verify.
        assert!(!wire_proof_verifies_against_any(
            "create_grant",
            "fp",
            TD,
            &[pk_a],
            &proof
        ));
    }

    #[test]
    fn wire_proof_accepts_tagged_signature_form() {
        let (pk, sk) = p256_device(0x43);
        let tagged = sign_intent(&sk, "vault_add", "op-2", "n-2", "fp", TD).0;
        assert!(tagged.starts_with("p256sig:"));
        let proof = WirePresenceProof {
            op_id: "op-2".into(),
            nonce: "n-2".into(),
            signature: tagged,
        };
        assert!(wire_proof_verifies_against_any(
            "vault_add",
            "fp",
            TD,
            &[pk],
            &proof
        ));
    }

    #[test]
    fn wire_proof_rejects_empty_enrolled_set_and_wrong_binding() {
        let (pk, sk) = p256_device(0x44);
        let proof = WirePresenceProof {
            op_id: "op-3".into(),
            nonce: "n-3".into(),
            signature: sign_intent_untagged(&sk, "create_grant", "op-3", "n-3", "fp", TD),
        };
        // Fail-closed: no enrolled anchor → no admission.
        assert!(!wire_proof_verifies_against_any(
            "create_grant",
            "fp",
            TD,
            &[],
            &proof
        ));
        // Wrong method binding (signature was over create_grant) → rejected.
        assert!(!wire_proof_verifies_against_any(
            "vault_add",
            "fp",
            TD,
            &[pk.clone()],
            &proof
        ));
        // Wrong daemon fingerprint → rejected.
        assert!(!wire_proof_verifies_against_any(
            "create_grant",
            "fp-other",
            TD,
            &[pk.clone()],
            &proof
        ));
        // Wrong params digest (the proof was signed over TD) → rejected. This is
        // the Finding 1 binding on the WIRE path.
        assert!(!wire_proof_verifies_against_any(
            "create_grant",
            "fp",
            "b3:other",
            &[pk],
            &proof
        ));
    }

    #[test]
    fn canonical_bytes_are_deterministic_and_nonce_bound() {
        let a = canonical_presence_intent_bytes("create_grant", "op-1", "nonce-abc", "fp-x", TD);
        let b = canonical_presence_intent_bytes("create_grant", "op-1", "nonce-abc", "fp-x", TD);
        assert_eq!(a, b, "same inputs → identical bytes");
        // A different nonce changes the bytes (freshness binding).
        let c = canonical_presence_intent_bytes("create_grant", "op-1", "nonce-xyz", "fp-x", TD);
        assert_ne!(a, c);
        // A different method changes the bytes (no cross-op substitution).
        let d = canonical_presence_intent_bytes("delegate_grant", "op-1", "nonce-abc", "fp-x", TD);
        assert_ne!(a, d);
        // A different params digest changes the bytes (no cross-object substitution).
        let e = canonical_presence_intent_bytes(
            "create_grant",
            "op-1",
            "nonce-abc",
            "fp-x",
            "b3:other",
        );
        assert_ne!(a, e, "params_digest must be bound into the signed bytes");
        // Domain separation is present.
        assert!(String::from_utf8_lossy(&a).contains(DOMAIN_PRESENCE_INTENT));
    }

    /// AC-1 golden: an independent, out-of-tree verifier holding only the ADR 206
    /// §1.3 spec + the public key must reproduce these EXACT bytes. This freezes
    /// the canonical wire form (RFC 8785 JCS over the 6-field intent object):
    /// keys in UTF-16 code-unit order, compact, minimally escaped. Any drift in
    /// the canonicalizer, field set, or key naming breaks this on purpose — it is
    /// a wire-compatibility contract, not an incidental snapshot.
    #[test]
    fn golden_canonical_intent_bytes() {
        let bytes = canonical_presence_intent_bytes(
            "create_grant",
            "op-golden-1",
            "nonce-golden",
            "fp-golden",
            "b3:deadbeef",
        );
        let expected = br#"{"ctx":"emberlink.v1.presence_authority_intent","daemon_fingerprint":"fp-golden","method":"create_grant","nonce":"nonce-golden","op_id":"op-golden-1","params_digest":"b3:deadbeef"}"#;
        assert_eq!(
            bytes,
            expected,
            "canonical intent bytes drifted from the frozen AC-1 golden\n got: {}\nwant: {}",
            String::from_utf8_lossy(&bytes),
            String::from_utf8_lossy(expected),
        );
    }

    #[test]
    fn params_digest_strips_envelope_fields_and_is_deterministic() {
        // The operator's pre-sign view of the params (no envelope fields yet).
        let signed_view = serde_json::json!({
            "scope": "repo:read", "persona": "demo", "ttl": "7d"
        });
        // The daemon's received view: identical authority params PLUS the
        // post-sign envelope fields. The digest MUST be identical.
        let received_view = serde_json::json!({
            "ttl": "7d",                        // key order differs — JCS normalizes
            "persona": "demo",
            "scope": "repo:read",
            "_presence_proof": {"op_id": "x", "nonce": "y", "signature": "z"},
            "scope_kek": "deadbeef",
            "_presence_token": {"sig": "whatever"}
        });
        let a = presence_params_digest(&signed_view).unwrap();
        let b = presence_params_digest(&received_view).unwrap();
        assert_eq!(
            a, b,
            "envelope fields must not affect the digest; JCS normalizes key order"
        );
        assert!(a.starts_with("b3:"));
    }

    #[test]
    fn params_digest_is_param_sensitive() {
        // Changing any authority-relevant param changes the digest (Finding 1:
        // the digest is what binds the OBJECT into the signed intent).
        let read = presence_params_digest(&serde_json::json!({"scope": "repo:read"})).unwrap();
        let admin = presence_params_digest(&serde_json::json!({"scope": "*:admin"})).unwrap();
        assert_ne!(read, admin, "different params → different digest");
    }
}
