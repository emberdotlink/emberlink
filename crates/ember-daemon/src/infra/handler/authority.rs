use super::*;

// Quarantine state. Flipped by the daemon
// runtime's startup sampling verify (or any later detected break) so the
// dispatch layer can refuse write-class socket methods while still allowing
// read-class probes (audit_verify, audit_query, audit_log_query,
// audit_explain, receipt_tree, ping) for operator diagnosis.
//
// A one-way latch: set once, never cleared without daemon restart. Recovery
// is via the audit-chain repair RPC (ADR 174 v2 — pending), after which the
// operator restarts the daemon and the next startup-verify walks clean.
//
// `quarantine_serve_mode_binds_socket` (ADR 174 v2 §1, CRIT-1 from v1
// adversarial review): on a startup-verify Break the daemon now stays up
// long enough to bind the socket and enter the serve loop. The dispatcher
// quarantine gate (search `is_quarantined()`) refuses every non-read-class
// method so the chain cannot be extended over the break, but the read-class
// probes + the future repair RPC remain reachable for operator diagnosis +
// recovery. The pre-fix path returned `DaemonError::AuditChainBreak` at the
// runtime startup-verify call site (`runtime.rs`) before any bind happened,
// which made the v1 repair workflow unreachable — see
// `docs/grill-transcripts/20260519-200327-ADR-174-ADVERSARIAL-REVIEW.md`.
static QUARANTINED: AtomicBool = AtomicBool::new(false);
static QUARANTINE_REASON: OnceLock<String> = OnceLock::new();
static QUARANTINE_AUTHORITY: OnceLock<QuarantineAuthority> = OnceLock::new();

/// System-side dimension of quarantine entry. Mirrors the
/// `BrokerRegistryAuthority` precedent (`crates/ember-daemon/src/broker/
/// handler.rs`, PR #3847): the dispatcher's `is_quarantined()` gate already
/// answers _whether_ the daemon is quarantined; this enum captures _which
/// system path_ flipped the latch so the audit-chain repair RPC + the
/// dashboard `/health` surface can branch on entry-class without parsing
/// the free-text reason. Per ADR 174 v2 R1 D6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineAuthority {
    /// The runtime's startup sampling verify detected a chain break before
    /// the serve loop bound the socket. The repair RPC accepts this class
    /// (it cannot otherwise reach the daemon — there is no live socket
    /// pre-quarantine on startup).
    StartupAuditChainBreak,
    /// A dispatcher arm detected a chain break while the daemon was already
    /// serving. Not yet wired by any caller — reserved so the
    /// `quarantine_authority()` consumers can distinguish startup-entry
    /// from mid-serve-entry once the mid-serve detector lands.
    MidServeAuditChainBreak,
    /// audit_verifier_outcome_v2 — a chain-topology invariant fired
    /// (e.g. multiple segment-genesis rows, post-migration NULL row_hash
    /// in segment > 0, non-monotonic segment_id). Distinct from
    /// `*AuditChainBreak` so the repair flow can branch on cause.
    TopologyViolation,
    /// audit_verifier_outcome_v2 — daemon crashed mid-repair: receipt
    /// minted but tombstone row never committed. The
    /// `ember audit chain-repair-finalize` CLI verb is the operator
    /// recovery path.
    IncompleteRepair,
    /// audit_verifier_outcome_v2 — symmetric counterpart to
    /// `IncompleteRepair`: tombstone row committed but the repair
    /// receipt was never minted. Recovered via the same
    /// `chain-repair-finalize` verb.
    IncompleteRepairReceipt,
    /// audit_verifier_outcome_v2 — the witness file at
    /// `/var/log/ember-audit-witness.log` has the wrong owner (e.g. the
    /// daemon's `ember` uid owns it, undermining the cross-trust-domain
    /// anchor). Surfaced by the periodic witness-integrity check
    /// (in Phase C).
    WitnessOwnerMismatch,
}

impl QuarantineAuthority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StartupAuditChainBreak => "startup_audit_chain_break",
            Self::MidServeAuditChainBreak => "mid_serve_audit_chain_break",
            Self::TopologyViolation => "topology_violation",
            Self::IncompleteRepair => "incomplete_repair",
            Self::IncompleteRepairReceipt => "incomplete_repair_receipt",
            Self::WitnessOwnerMismatch => "witness_owner_mismatch",
        }
    }
}

/// Flip the daemon into quarantine. Idempotent (later calls don't overwrite
/// the first-recorded reason or authority). Called by runtime startup verify
/// on tamper detect and by handler arms that detect a break mid-serve.
///
/// Emits a `WARN` log line at entry so the operator sees the entry-authority
/// + reason in `/var/log/emberd.err` and knows the socket-bound serve loop
///   continued (the dispatcher refuses non-read-class writes; the repair RPC
///   is reachable). Per ADR 174 v2 R1 D6.
pub fn enter_quarantine(authority: QuarantineAuthority, reason: String) {
    enter_quarantine_into(
        &QUARANTINED,
        &QUARANTINE_REASON,
        &QUARANTINE_AUTHORITY,
        authority,
        reason,
    );
}

/// Parameterised quarantine entry — accepts the storage cells so tests can
/// exercise the entry shape without contaminating the process-global latch.
/// Production callers use [`enter_quarantine`]. Mirrors the
/// `install_registry_into` precedent in `crates/ember-daemon/src/broker/handler.rs`.
pub(super) fn enter_quarantine_into(
    quarantined: &AtomicBool,
    reason_cell: &OnceLock<String>,
    authority_cell: &OnceLock<QuarantineAuthority>,
    authority: QuarantineAuthority,
    reason: String,
) {
    tracing::warn!(
        authority = authority.as_str(),
        reason = %reason,
        "entered quarantine; socket-bound serve loop continues with non-read-class methods refused"
    );
    quarantined.store(true, Ordering::Release);
    let _ = reason_cell.set(reason);
    let _ = authority_cell.set(authority);
}

/// Read the quarantine latch. Used by the dispatch-method gate.
pub fn is_quarantined() -> bool {
    QUARANTINED.load(Ordering::Acquire)
}

/// Read the quarantine reason, if any. Used by the dispatch-method gate's
/// error payload + the dashboard `/health` surface.
pub fn quarantine_reason() -> Option<&'static str> {
    QUARANTINE_REASON.get().map(String::as_str)
}

/// Read the entry-authority for the current quarantine episode, if any.
/// Used by the audit-chain repair RPC (pending) to branch on whether the
/// daemon entered quarantine via startup-verify vs mid-serve detection.
pub fn quarantine_authority() -> Option<QuarantineAuthority> {
    QUARANTINE_AUTHORITY.get().copied()
}

/// audit_repair_chain_rpc_landed — clear the quarantine latch on a
/// successful operator-co-signed `audit.repair_chain` call. Per the
/// v0.3-RC B4 acceptance criterion: a successful truncate-after-row
/// repair exits quarantine-serve mode in-process (no daemon restart
/// required). This narrows ADR 174 v2 §1 Synthesis-1's
/// "no in-process leave_quarantine" contract to: operator-co-signed
/// repair is the ONLY in-process exit; every other quarantine entry
/// still requires the restart-after-repair flow.
///
/// The companion `QUARANTINE_REASON` + `QUARANTINE_AUTHORITY`
/// `OnceLock`s are NOT cleared — those record the entry-episode for
/// forensics and the operator can still inspect them post-repair via
/// `quarantine_reason()` / `quarantine_authority()`. The latch
/// (`QUARANTINED` AtomicBool) is the only thing the dispatcher gate
/// reads; clearing it suffices to re-enable write-class methods.
///
/// Called from `audit::truncate_after_row` after the SQLite COMMIT +
/// receipt mint both succeed. Idempotent — a double-call no-ops.
pub fn clear_quarantine_after_repair() {
    let was_quarantined = QUARANTINED.swap(false, Ordering::Release);
    if was_quarantined {
        tracing::warn!(
            authority = quarantine_authority()
                .map(|a| a.as_str())
                .unwrap_or("unrecorded"),
            "audit_repair_chain_rpc_landed: quarantine cleared after operator-co-signed repair"
        );
    }
}

/// audit_repair_chain_rpc_landed — quarantine-allowed method whitelist.
/// Per ADR 174 v2 §1 R1 D3: a tamper-detected daemon refuses every
/// write-class method EXCEPT `audit_repair_chain` (the operator-co-
/// signed unbrick path) and the read-class diagnostic methods. This
/// function wraps [`is_read_class_method`] with the single repair
/// exception. The dispatcher uses this in lieu of `is_read_class_method`
/// for the quarantine gate.
pub fn quarantine_allowed_method(method: &str) -> bool {
    is_read_class_method(method)
        || method == "audit_repair_chain"
        || method == "recovery_action_receipt"
}

/// audit_repair_chain_rpc_landed — test-only setter for the global
/// `QUARANTINED` AtomicBool. Used by the B4 test suite to flip the
/// quarantine latch WITHOUT touching `QUARANTINE_AUTHORITY` /
/// `QUARANTINE_REASON` (both `OnceLock`s that contaminate sibling tests
/// once set). Production callers MUST use [`enter_quarantine`] which
/// records the entry-authority for forensics.
#[cfg(test)]
pub(crate) fn force_quarantine_latch_for_test(value: bool) {
    QUARANTINED.store(value, Ordering::Release);
}

/// Read-class socket methods that proceed even when the daemon is
/// quarantined. The principle: a tamper-detected daemon should still let
/// the operator query the audit log to diagnose the break, but must refuse
/// any write that would extend the tampered chain or mutate state.
///
/// Default-deny: anything not on this list is treated as write-class and
/// refused while quarantined. New read-class methods must be added here
/// explicitly.
pub(super) fn is_read_class_method(method: &str) -> bool {
    matches!(
        method,
        "ping"
            | "audit_verify"
            | "audit_repair_chain_prepare"
            | "audit_query"
            | "audit.query"
            | "audit_log_query"
            | "audit_explain"
            | "receipt_tree"
            | "receipt_query"
            | "receipt.list"
            | "receipt.get"
            | "list_personas"
            | "list_grants"
            | "list_operator_grants"
            | "list_all_grants"
            | "list_credentials"
            | "list_devices"
            | "list_roots"
            | "list_personas_with_grants"
            | "list_pending_approvals"
            | "show_persona"
            | "show_grant"
            | "show_device"
            | "show_root"
            | "binary_manifest_show"
            | "health"
            | "status"
            | "vault_status"
            | "catalog.search_actions"
            | "catalog_search_actions"
            // ADR 198 — vault_rotate_plan is read-class: it mints a
            // confirmation token + returns the rotation plan, mutating no
            // vault state. (vault_rotate_execute is NOT read-class — it is the
            // OperatorPresence mutation.)
            | "vault_rotate_plan"
            | "version"
            // ADR 158 §C4 — delegation_list / delegation_show are read-only
            // operator surfaces. delegation_revoke is intentionally NOT
            // read-class (it's a state mutation, even though authority
            // is only ever removed).
            | "delegation_list"
            | "delegation_show"
            | "describe_runtime_attach_target"
    )
}

/// Authority class required to dispatch a JSON-RPC method, per ADR 152
/// §"Destination". Phase B
/// declares the type + table; Phase B-enforce will gate dispatch on
/// the lookup. **No enforcement in this slice.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityClass {
    /// Any ember-clients group member. Examples: `status`,
    /// `personas.list`, `grants.list`, `receipts.search`, dashboard
    /// mirror methods.
    ConnectOnly,
    /// ember-clients + recent operator-presence proof bound to this
    /// uid. Examples: `delegate_grant`, `create_agent_persona`,
    /// `vault.add`, `vault.get`, `orchestrator.spawn`.
    OperatorPresence,
    /// ember-clients + presence proof + WebAuthn challenge re-attested
    /// within N minutes. Reserved for team0+/ent0 tier; not enabled in
    /// cohort A dev0 (per ADR 152 tier matrix).
    OperatorPresenceWithReattest,
}

/// Authority class required to dispatch `method`, per the ADR 152
/// tier matrix.
///
/// Phase B-enforce
/// flips the table
/// from telemetry-only to enforcing and classifies every currently-
/// shipping JSON-RPC method:
///
///   * `ConnectOnly`  — read-class methods; any ember-clients group
///     member that the socket layer already let through can call them.
///     The ADR 206 §4 presence-as-decryption unlock endpoints
///     (`vault.se_provision` / `vault.se_unlock_begin` /
///     `vault.se_unlock_complete`) live here because the operator-session
///     `se_unwrap` tap IS the presence proof and a wrong scope KEK fails
///     every authority open closed.
///   * `OperatorPresence` — mutating / sensitive methods; callers
///     must arrive with a recent daemon-signed operator-presence proof
///     except for privilege-reduction seams that tear authority down
///     (`vault_lock`, `close_session`). See
///     `operator_presence_token_optional_method` for the canonical list.
///   * `OperatorPresenceWithReattest` — reserved for team0+/ent0
///     deployments per the ADR 152 tier matrix; no method is classified
///     here in cohort A.
///
/// **Returns `Option<AuthorityClass>`.** `Some(_)` for explicitly-
/// classified methods. `None` for methods that aren't in this table —
/// the dispatch layer treats `None` as "unknown method," skips both
/// authority gates, and lets the dispatcher's `_ => Err(-32601)` arm
/// emit the standard JSON-RPC "Method not found" response. This is
/// the correct behavior for unknown methods per the JSON-RPC 2.0
/// contract: -32601 (Method not found), NOT -32001 (authority error).
///
/// authority_gate_unknown_method_returns_minus_32601 — checkpoint for the
/// downstream gate behavior; the gate at `dispatch_method` skips on
/// `None` and the dispatcher's _ arm returns -32601.
///
/// authority_class_not_met — checkpoint for the gate downstream that
/// reads this lookup; downstream emits the JSON-RPC -32001 error
/// with that string for KNOWN methods that fail the authority check.
///
/// **The "added to dispatcher, forgot to classify" failure mode** —
/// which the previous fall-through-to-OperatorPresence guarded against
/// — is now caught by `ALL_CLASSIFIED_METHODS_MATCH_DISPATCHER_ARMS`
/// in the test module. A method that lands in the dispatcher without
/// a classification entry returns -32601 (effectively unreachable from
/// external callers) AND fails the exhaustivity test; the dev sees the
/// gap at test time instead of shipping unprotected.
// Load-bearing per-method authority
// resolution. Every dispatch arm must have an explicit entry here; unknown
// names return None so JSON-RPC method-not-found stays distinct from authority
// denial.
pub fn authority_class_for_method(method: &str) -> Option<AuthorityClass> {
    match method {
        // ---------------- ConnectOnly: read-class methods ----------
        //
        // These are the broad read-class methods callable by any
        // ember-clients member. Operator-only read-class surfaces such
        // as `list_operator_grants` and `list_all_grants` are classified
        // below under OperatorPresence.
        //
        // P13-S3: `audit_verify`, `vault_status`, broker status, and
        // `trust.*` are intentionally global ConnectOnly diagnostics.
        // They report daemon/operator posture, not persona-owned rows, so
        // team0/ent0 callers must not be forced through a principal scope
        // helper just to inspect daemon health.
        // team0_readclass_per_uid_filter: P13 classifies every ConnectOnly
        // method as persona-scoped, fail-closed, neutral, or intentionally
        // global; do not add new ConnectOnly arms without making that choice
        // explicit in the dispatcher and tests.
        "ping"
        | "audit_verify"
        | "audit_repair_chain_prepare"
        | "audit_query"
        | "audit.query"
        | "receipt_query"
        | "receipt.list"
        | "receipt.get"
        | "list_personas"
        | "list_grants"
        | "list_pending_approvals"
        | "list_receipts"
        | "get_receipt"
        | "list_standing_grants"
        | "grant_status"
        | "recover_grant_rebuild_chain_status"
        | "recover_persona_restore_status"
        | "grant_budget_status"
        | "evaluate_grant"
        | "daemon_persona"
        | "presence_token_mint"
        | "poll_notifications"
        | "await_approval"
        | "headless_preflight_gaps"
        // Authority Catalog action search is a daemon-owned read-only
        // projection over bundled Action Manifests. It does not decide
        // authority or inspect secrets; invocation still routes through
        // action_ref -> execution_contract -> need <= grant.
        | "catalog.search_actions"
        | "catalog_search_actions"
        // P10-S3 preflight authority coverage: read-only verdict over a
        // planned action set against active grant statements + posture.
        // Persona-scoped inside the handler via
        // `persona_scoped_param_for_connect_only` (P13 read-class choice:
        // persona-scoped, fail-closed on multi-uid tiers).
        | "preflight_authority_coverage"
        | "vault_status"
        // ADR 198 — read-class: mints the rotation confirmation token.
        | "vault_rotate_plan"
        // MEK sealed backup/recovery. These are not read-class (quarantine
        // still refuses them), but they deliberately do not ride the normal
        // OperatorPresence live-vault window: `vault_import_sealed` must be
        // callable when no MEK is loaded. They are still operator-proofed by
        // `presence_chokepoint_applies` because `presence_gate::is_presence_widening`
        // includes both method names.
        | "vault_export_sealed"
        | "vault_import_sealed"
        | "broker.github_status"
        | "broker_github_status"
        | "broker.registry_status"
        | "broker_registry_status"
        | "trust.list"
        | "trust_list"
        | "trust.show"
        | "trust_show"
        | "trust.explain"
        | "trust_explain"
        // Per ADR 162 §Component 3 —
        // `trust.rotation_status` is read-only ("is anything in
        // flight?"). `trust.rotate_dev_ir` itself is a registry
        // mutation and goes through the standard authority path.
        | "trust.rotation_status"
        | "trust_rotation_status"
        // refresh_cert
        // is read-class authority (produces a new cert from an existing
        // valid one; never escalates). Per ADR 173 §Component 4.
        // Anchor: refresh_cert_dispatch_landed
        | "refresh_cert"
        // `status` is the daemon's combined read-class projection
        // (personas + active grants + sandboxes + pending approvals +
        // recent activity, all filtered through
        // team0_connect_only_persona_scope). The dispatcher arm lives
        // at the line marked `"status" =>` and only reads — it mints
        // no credentials, mutates no state. ConnectOnly mirrors the
        // adjacent `list_*` / `grant_status` / `vault_status` arms.
        | "status"
        // Local anonymous telemetry
        // posture. These methods toggle only the daemon-local empirical
        // collector and purge its local files; they mint no credential and do
        // not expose telemetry row contents over the socket.
        | "telemetry.status"
        | "telemetry_status"
        | "telemetry.opt_in"
        | "telemetry_opt_in"
        | "telemetry.opt_out"
        | "telemetry_opt_out"
        // (Tier 1):
        // subprocess_audit_log is intentionally ConnectOnly. The handler
        // builds the action string from the vendor field (whitelist-
        // gated) and refuses any caller-supplied action prefix, so a
        // ConnectOnly peer cannot impersonate broker / vault / grant
        // actions. The write goes through the chain extender, which is
        // gated by quarantine and serialized via BEGIN IMMEDIATE.
        | "subprocess_audit_log"
        // ADR 206 §4 presence-as-decryption unlock. The operator-session CLI does
        // the `se_unwrap` tap (the cryptographic presence gate) and submits the
        // resulting scope KEK; these endpoints ride the peer-cred gate like the
        // other proof-acquisition endpoints. They do not consume an OperatorPresence
        // proof — the tap IS the proof, and a wrong KEK fails every authority open
        // closed. `se_unlock_begin` is a pure read (opaque wrapped blobs).
        //
        // ADR 206 slice 4 C retired the forgeable native/managed/lazy vault-unlock
        // ceremony (`vault_unlock_begin` / `vault_unlock_wait` /
        // `vault_unlock_complete` / `presence_complete_local_auth` /
        // `presence_complete_native_proof`); the §4 RPCs below are the only
        // operator-presence unlock acquisition surface now.
        | "vault.se_provision"
        | "vault/se_provision"
        | "vault_se_provision"
        | "vault.se_unlock_begin"
        | "vault/se_unlock_begin"
        | "vault_se_unlock_begin"
        | "vault.se_unlock_complete"
        | "vault/se_unlock_complete"
        | "vault_se_unlock_complete"
        // ADR 206 §6 — `vault.se_add_recipient_wrap` stores ONE more recipient's
        // wrap of the scope KEK_s (multi-recipient: enrolled ∪ recovery). Same
        // posture as `se_provision`: the operator-session CLI performs the wrap and
        // the daemon admits it ONLY if `ecies_key_id` is in the event-sourced AC-7
        // allowlist (mutates no grant, mints no credential). ConnectOnly rides the
        // SO_PEERCRED operator gate.
        | "vault.se_add_recipient_wrap"
        | "vault/se_add_recipient_wrap"
        | "vault_se_add_recipient_wrap"
        // ADR 200 §3 — `presence/request_nonce` mints the single-use, daemon-bound
        // nonce a widening op's presence signature must cover. Proof-ACQUISITION:
        // the nonce is inert until signed by the enrolled presence Device, mints no
        // credential, and mutates no authority state — so it rides the peer-cred
        // gate like the other `presence/*` acquisition endpoints, NOT the
        // OperatorPresence lane (whose proofs it helps produce).
        | "presence/request_nonce"
        | "presence_request_nonce"
        // ADR 158 §C4 — `delegation_revoke` is the load-bearing operator
        // authority-control surface: "revoke is always safe — operator only
        // ever removes authority." Classified ConnectOnly so an operator can
        // kill a runaway agent even when the vault is locked or a presence
        // token is unavailable. `delegation_list` / `delegation_show` are read-only.
        | "delegation_revoke"
        | "delegation_list"
        | "delegation_show"
        // P14-S2: `recover diagnose` emits a daemon-signed
        // `recovery.action` receipt for the read-only diagnostic walk.
        // The receipt body describes the inspected local machine state; it
        // does not expose persona-owned rows beyond the ConnectOnly probes
        // the caller already invoked.
        | "recovery_action_receipt"
        // P9-S4 attach summary is read-only. The authority-changing attach
        // remains `register_session`, which stays OperatorPresence-gated.
        | "describe_runtime_attach_target"
        // ADR 200 §5 — read-only PREPARE half of the operator-bootstrap ceremony
        // (tap-reduction). Pure: validates the device key and computes the bytes
        // to sign; mutates nothing, holds no key, touches no vault. ConnectOnly so
        // the PREPARE read does not trigger a redundant native-unlock Touch ID tap —
        // the operator's SE tap over these bytes is the real presence proof,
        // verified at COMMIT (`identity.device.enroll`) append time. The plan
        // reveals no secret material.
        | "identity.device.enroll_plan"
        | "identity_device_enroll_plan"
        // ADR 200 §5 / AC-2 backup-device enrollment. Same posture as primary
        // enrollment: PREPARE is read-only, and COMMIT authority is the existing
        // presence Device's P-256 signature over the prepared DeviceEnrolled
        // bytes, not the daemon native-unlock window.
        | "identity.device.enroll_backup_plan"
        | "identity_device_enroll_backup_plan"
        | "identity.device.enroll_backup"
        | "identity_device_enroll_backup"
        // ADR 200 §5 operator-bootstrap ceremony COMMIT (G2 Slice 1b).
        //
        // ADR 206 slice 4 C reclassified this OperatorPresence → ConnectOnly. The
        // old OperatorPresence classification rested on the daemon's NATIVE unlock
        // (Touch ID) being the gate at bootstrap; that forgeable native-unlock path
        // is now deleted. enroll is NOT a vault-widening op and its authority does
        // NOT come from the §4 unlock window — it is GENESIS-SELF-ANCHORED: COMMIT
        // appends each genesis/enroll event verified at append time against the
        // founding presence device's P-256 signature (`DeviceSignatureVerifier`),
        // and a wrong/forged signature (or a signer ≠ recorded `initial_key`) fails
        // closed. The operator's SE tap over the PREPARE bytes IS the presence
        // proof. Gating it on the §4 unlock window would be a bootstrap chicken/egg
        // (no vault window can exist before the first device is enrolled).
        // ConnectOnly still rides the SO_PEERCRED operator gate (a cross-uid peer
        // cannot connect). The COMMIT half mutates state but mints no credential and
        // touches no vault.
        | "identity.device.enroll"
        | "identity_device_enroll"
        // V030-EMBER-DEVICE-REVOKE — operator-driven device revocation. Same
        // posture as `identity.device.enroll`: the COMMIT authority is the
        // existing presence Device's P-256 signature over the prepared
        // DeviceRevoked event bytes (verified at append time), NOT the §4
        // unlock window. PREPARE is read-only. Mints no credential, touches no
        // vault. ConnectOnly rides the SO_PEERCRED operator gate.
        // Anchor: ember_device_revoke_surface_landed.
        | "identity.device.revoke"
        | "identity_device_revoke"
        // ADR 206 §6 — recovery-recipient enrollment. Identical posture to
        // `identity.device.enroll`: genesis-self-anchored, the COMMIT authority is
        // an existing presence Device's P-256 signature over the prepared
        // DeviceEnrolled(Recovery) bytes (verified at append time), NOT the §4
        // unlock window. PREPARE is read-only. Mints no credential, touches no
        // vault. ConnectOnly rides the SO_PEERCRED operator gate.
        | "identity.recovery.enroll"
        | "identity_recovery_enroll"
        // V030-EMBER-DEVICE-LIST — read-only enrolled-device inventory
        // (ADR 200). No vault tap; no presence gate; mints no credential,
        // mutates no state. Intentionally global ConnectOnly diagnostic
        // (operator posture, not persona-owned rows).
        // Anchor: ember_device_list_surface_landed.
        | "identity.device.list"
        | "identity_device_list"
        // P22-S2 Door-1 leaf-pin (ADR 197 §2). The launcher reports the pid of
        // the harness child it spawned so the per-session UDS gate can pin
        // against it. Fires mid-launch right after spawn — must NOT require a
        // fresh presence token (register_session already did the operator
        // Touch ID). Classified ConnectOnly: it rides the SO_PEERCRED operator
        // gate (a cross-uid peer cannot connect at all), sets a security
        // binding first-write-wins, mints no credential and touches no vault.
        | "report_session_leaf"
        // ADR 216 double-envelope provision + unlock. Same posture as vault.se_*:
        // the operator-session CLI does the SE tap (cryptographic presence gate) and
        // submits the result; these endpoints ride the peer-cred gate. The SE tap IS
        // the proof, and a wrong scope KEK fails every authority open closed.
        | "vault.de_provision_begin"
        | "vault/de_provision_begin"
        | "vault_de_provision_begin"
        | "vault.de_provision_outer"
        | "vault/de_provision_outer"
        | "vault_de_provision_outer"
        | "vault.de_unlock_begin"
        | "vault/de_unlock_begin"
        | "vault_de_unlock_begin"
        | "vault.de_unlock_complete"
        | "vault/de_unlock_complete"
        | "vault_de_unlock_complete" => Some(AuthorityClass::ConnectOnly),

        // ---------------- OperatorPresence: mutating / sensitive ---
        //
        // Anything that mints credentials, mutates grants, touches
        // the vault, or routes a broker call. Methods on this lane require
        // both a daemon-signed presence-token (or managed unlock authority)
        // and an unlocked interactive session on every tier. Proof
        // acquisition itself is classified above as ConnectOnly because it
        // produces the proof this lane consumes.
        "create_persona"
        | "build_init_first_grant_receipt"
        | "persona_signer"
        | "revoke_persona"
        | "audit_log_query"
        | "audit_explain"
        | "grant_summary"
        | "detect_anomalies"
        | "receipt_tree"
        | "list_operator_grants"
        | "list_all_grants"
        | "headless_status"
        | "create_grant"
        | "create_composite_grant"
        | "delegate_grant"
        | "revoke_grant"
        | "recover_grant_abandon"
        | "recover_persona_abandon"
        | "extend_grant"
        | "grant.extend"
        | "revoke_statement"
        | "evaluate_tool_call"
        | "use_credential"
        | "vault_add"
        | "vault_put"
        | "vault_list"
        | "vault_remove"
        | "vault_lock"
        | "vault_unlock"
        | "vault_get"
        | "vault_migrate_acl"
        // ADR 198 D7 — vault_rotate_execute is the OperatorPresence mutation,
        // the same tier as the revoke_* ops (NOT token-optional). The gate is
        // the existing per-method operator-authorization seam; no fresh
        // biometric tap (that was reversed as ceremony — it cannot fire
        // headless and the socket is already SO_PEERCRED-gated to the operator).
        | "vault_rotate_execute"
        | "sandbox_create"
        | "sandbox_list"
        | "sandbox_stop"
        | "sandbox_delete"
        | "sandbox_exec"
        | "sandbox_run"
        | "local_state_key_get"
        | "local_state_key_set"
        | "local_state_key_rotate_and_reencrypt"
        | "binary_pin_generate"
        | "submit_approval"
        | "propose_grant"
        | "resolve_approval"
        | "approval.resolve"
        | "approval_resolve"
        | "approval.narrow"
        | "approval_narrow"
        | "grant.expire_stale"
        | "expire_grants"
        | "create_standing_grant"
        | "remove_standing_grant"
        | "request_access"
        | "broker_issue"
        | "broker_revoke"
        | "broker_list"
        | "broker_resolve"
        | "broker_exec"
        | "broker.mint_gh_token"
        | "broker_register_pid_watcher"
        | "presence/request_proof"
        | "presence_request_proof"
        | "sops_unwrap_dek"
        | "sops.pubkey"
        | "sops.wrap"
        | "sops.unwrap"
        | "register_session"
        | "close_session"
        // ADR 194 §5 output 3 — the planner's one explicit mutation. A saved
        // delegation template overlay-overrides the bundled set, so writing one
        // is authority-shaping and must be operator-gated (template poisoning
        // otherwise). The grant is still minted at launch via register_session.
        | "save_delegation_template"
        | "headless_enroll"
        | "headless_revoke"
        // audit_repair_chain_rpc_landed (B4 + adversarial CRIT-2 fix
        // 2026-05-22): the operator-co-signed audit-chain repair RPC
        // MUST classify as OperatorPresence so the gate at
        // `dispatch_method_with_context:2556` fires. Pre-fix it fell
        // through to `_ => None` and the gate short-circuited —
        // unauthenticated UDS peers could submit a self-signed
        // RepairIntent and wipe the audit tail. The signature check
        // inside the dispatcher arm is a defense-in-depth layer; the
        // OperatorPresence + enrollment gate (handler:audit_repair_chain
        // arm) is the load-bearing one.
        | "audit_repair_chain" => Some(AuthorityClass::OperatorPresence),

        // ---------------- OperatorPresenceWithReattest ----------------
        //
        // Reserved for the team0+/ent0 tier per ADR 152. No method
        // in cohort A dev0 is classified here. Adding one without
        // also wiring a WebAuthn re-attestation surface would brick
        // it (`RequestContext::satisfies` always returns false for
        // this class until Phase D lands).

        // ---------------- Fall-through: unknown method --------------
        //
        // Returns `None` so the dispatch layer can distinguish
        // "method is known but caller lacks authority" (-32001) from
        // "method does not exist" (-32601, the JSON-RPC contract).
        //
        // The previous "fall closed to OperatorPresence" semantic was
        // intended to catch "added to dispatcher, forgot to classify"
        // bugs, but it also broke the JSON-RPC unknown-method contract
        // (test_unknown_method failed on origin/main for ~8h on
        // 2026-05-17 returning -32001 instead of -32601). The classify-
        // forgetfulness check is now enforced by the
        // `ALL_CLASSIFIED_METHODS_MATCH_DISPATCHER_ARMS` test which
        // surfaces gaps at `cargo test` time instead of by smuggling
        // the wrong error code at runtime.
        _ => None,
    }
}

fn operator_presence_privilege_reduction_method(method: &str) -> bool {
    matches!(method, "vault_lock" | "close_session")
}

pub(super) fn operator_presence_token_optional_method(method: &str) -> bool {
    operator_presence_privilege_reduction_method(method)
}

pub(super) const PRESENCE_SCOPE_CLASS_VAULT: &str = "class:vault";
pub(super) const PRESENCE_SCOPE_CLASS_SESSION_RUNTIME: &str = "class:session-runtime";

pub(super) fn presence_scope_for_unlock_target(
    method: &str,
) -> Option<crate::auth::presence_token::ScopeKey> {
    use crate::auth::presence_token::ScopeKey;

    Some(match method {
        "vault_unlock" => ScopeKey::new(PRESENCE_SCOPE_CLASS_VAULT),
        "register_session" => ScopeKey::new(PRESENCE_SCOPE_CLASS_SESSION_RUNTIME),
        _ if matches!(
            authority_class_for_method(method),
            Some(AuthorityClass::OperatorPresence)
        ) =>
        {
            ScopeKey::new(method)
        }
        _ => return None,
    })
}

pub(super) fn authority_error(reason: &str) -> (i32, String) {
    (
        -32001,
        json!({
            "error": "authority_class_not_met",
            "reason": reason
        })
        .to_string(),
    )
}

pub(super) fn presence_scope_allows_method(
    scope: &crate::auth::presence_token::ScopeKey,
    method: &str,
) -> bool {
    match scope.as_str() {
        "*" => true,
        PRESENCE_SCOPE_CLASS_VAULT => matches!(
            method,
            "vault_unlock"
                | "vault_add"
                | "vault_put"
                | "vault_list"
                | "vault_remove"
                | "vault_get"
                | "vault_migrate_acl"
                // ADR 198 D7 — the rotation mutation is gated by the class:vault
                // operator-presence scope (same lane as the other vault writes).
                | "vault_rotate_execute"
        ),
        PRESENCE_SCOPE_CLASS_SESSION_RUNTIME => matches!(
            method,
            "register_session"
                | "use_credential"
                | "evaluate_tool_call"
                | "broker_issue"
                | "broker_revoke"
                | "broker_list"
                | "broker_resolve"
                | "broker_exec"
                | "broker.mint_gh_token"
                | "broker_register_pid_watcher"
        ),
        exact => exact == method,
    }
}

pub(super) fn session_runtime_scope_from_open_session(
    method: &str,
    params: &serde_json::Value,
    ctx: &RequestContext,
) -> Option<crate::auth::presence_token::ScopeKey> {
    if !matches!(method, "broker_resolve" | "broker_exec") {
        return None;
    }
    let sessions_dir = ctx.sessions_dir.as_ref()?;
    let session_id = params
        .get("session_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())?;
    let requested_persona = match method {
        "broker_resolve" => params.get("persona_id").and_then(|v| v.as_str()),
        "broker_exec" => params.get("caller_persona").and_then(|v| v.as_str()),
        _ => None,
    }
    .filter(|s| !s.is_empty())?;

    let session_store = core_state::SessionStore::new(sessions_dir.clone());

    if let Some((attachment_id, endpoint_token)) =
        crate::infra::attachment::attachment_endpoint_from_params(params)
    {
        match session_store.resolve_attachment_endpoint(attachment_id, endpoint_token) {
            Ok(Some((meta, endpoint))) => {
                if meta.session_id != session_id {
                    tracing::warn!(
                        method = %method,
                        request_session_id = %session_id,
                        endpoint_session_id = %meta.session_id,
                        attachment_id = %attachment_id,
                        "dispatch_method: attachment endpoint session mismatch"
                    );
                    return None;
                }
                if meta.persona != requested_persona {
                    tracing::warn!(
                        method = %method,
                        session_id = %session_id,
                        attachment_id = %attachment_id,
                        session_persona = %meta.persona,
                        requested_persona = %requested_persona,
                        "dispatch_method: attachment endpoint persona mismatch"
                    );
                    return None;
                }
                if endpoint.is_active() || endpoint.is_rebinding() {
                    return Some(crate::auth::presence_token::ScopeKey::new(
                        PRESENCE_SCOPE_CLASS_SESSION_RUNTIME,
                    ));
                }
                tracing::warn!(
                    method = %method,
                    session_id = %session_id,
                    attachment_id = %attachment_id,
                    endpoint_state = %endpoint.state,
                    "dispatch_method: attachment endpoint is not active for session-runtime scope"
                );
                return None;
            }
            Ok(None) => {
                tracing::warn!(
                    method = %method,
                    session_id = %session_id,
                    attachment_id = %attachment_id,
                    "dispatch_method: attachment endpoint not found or token mismatch"
                );
                return None;
            }
            Err(e) => {
                tracing::warn!(
                    method = %method,
                    session_id = %session_id,
                    attachment_id = %attachment_id,
                    error = %e,
                    "dispatch_method: failed to resolve attachment endpoint for session-runtime scope"
                );
                return None;
            }
        }
    }

    let meta = match session_store.read(session_id) {
        Ok(Some(meta)) => meta,
        Ok(None) => return None,
        Err(e) => {
            tracing::warn!(
                method = %method,
                session_id = %session_id,
                error = %e,
                "dispatch_method: failed to read session meta for session-runtime authority fallback"
            );
            return None;
        }
    };
    if meta.persona != requested_persona {
        tracing::warn!(
            method = %method,
            session_id = %session_id,
            session_persona = %meta.persona,
            requested_persona = %requested_persona,
            "dispatch_method: session-runtime persona mismatch"
        );
        return None;
    }
    if let Some(mtls) = ctx.mtls_principal() {
        if mtls.persona_id != requested_persona {
            tracing::warn!(
                method = %method,
                session_id = %session_id,
                mtls_persona = %mtls.persona_id,
                requested_persona = %requested_persona,
                "dispatch_method: session-runtime mTLS persona mismatch"
            );
            return None;
        }
        if mtls.container_id != session_id {
            tracing::warn!(
                method = %method,
                session_id = %session_id,
                mtls_container_id = %mtls.container_id,
                "dispatch_method: session-runtime mTLS container mismatch"
            );
            return None;
        }
        return Some(crate::auth::presence_token::ScopeKey::new(
            PRESENCE_SCOPE_CLASS_SESSION_RUNTIME,
        ));
    }

    let principal = ctx.peer_cred_principal.as_ref()?;
    if principal.pid <= 0 {
        tracing::warn!(
            method = %method,
            session_id = %session_id,
            principal_pid = principal.pid,
            "dispatch_method: session-runtime principal missing usable pid"
        );
        return None;
    }
    let caller_pid = principal.pid as u32;
    if !crate::infra::pid::process_is_same_or_descendant(caller_pid, meta.launcher_pid) {
        tracing::warn!(
            method = %method,
            session_id = %session_id,
            launcher_pid = meta.launcher_pid,
            caller_pid,
            "dispatch_method: session-runtime caller is not in launcher process family"
        );
        return None;
    }

    Some(crate::auth::presence_token::ScopeKey::new(
        PRESENCE_SCOPE_CLASS_SESSION_RUNTIME,
    ))
}
