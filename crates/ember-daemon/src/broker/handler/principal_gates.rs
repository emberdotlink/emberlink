//! Broker caller authority gates.
//!
//! This module owns the checks that run before broker entrypoints cross from
//! agent space into authority space: grant schema pins, peercred/persona
//! binding, enrollment posture, pid liveness, namespace drift, and peer binary
//! pinning. Keeping these gates together gives tests one focused authority seam
//! instead of making every broker handler load the whole RPC implementation.

use serde_json::Value;

use crate::binary_manifest::BinaryManifest;
#[cfg(target_os = "linux")]
use crate::binary_manifest::ManifestVerifyError;
use crate::infra::store::DaemonStore;

use super::current_manifest;

// ---------------------------------------------------------------------------
// Grant schema-version pin
// ---------------------------------------------------------------------------

/// Error code for "the grant's schema_version does not match this
/// daemon's compiled-in pin". Distinct from the other broker refusal
/// codes so operators can tell apart "old daemon reading a new grant",
/// "new daemon reading an old grant", and any of the principal /
/// binary / persona refusals. CRIT-A from the first adversarial
/// review — see [`core_grants::GRANT_SCHEMA_VERSION_PIN`].
pub const ERR_GRANT_SCHEMA_VERSION_MISMATCH: i32 = -32010;

/// Refuse any grant whose `schema_version` does not equal this
/// daemon's compiled-in [`core_grants::GRANT_SCHEMA_VERSION_PIN`].
///
/// Run at every broker entry point that consumes a grant — `issue`,
/// `revoke`, `list`, `resolve`, `exec` — before any provider IO and
/// before policy/HITL evaluation. A grant minted under a different
/// schema interpretation cannot be safely processed under this
/// daemon's interpretation, even if the in-memory `Grant` shape
/// parses successfully (serde back-compat fills missing fields with
/// defaults that may widen authority relative to the original mint).
///
/// Returns `Err((-32010, "grant_schema_version_mismatch: ...")`)` on
/// mismatch, with the grant id, the daemon's pin, and the grant's
/// declared version in the message so the operator can diagnose the
/// refusal without reading the SQL row.
pub fn check_grant_schema_version(grant: &core_grants::Grant) -> Result<(), (i32, String)> {
    if grant.schema_version != core_grants::GRANT_SCHEMA_VERSION_PIN {
        tracing::warn!(
            grant_id = %grant.id,
            grant_schema_version = grant.schema_version,
            pin = core_grants::GRANT_SCHEMA_VERSION_PIN,
            "broker handler: refusing request — grant schema_version does not match daemon pin"
        );
        return Err((
            ERR_GRANT_SCHEMA_VERSION_MISMATCH,
            format!(
                "grant_schema_version_mismatch: grant {} declares schema_version={} \
                 but daemon pin is {}",
                grant.id,
                grant.schema_version,
                core_grants::GRANT_SCHEMA_VERSION_PIN
            ),
        ));
    }
    Ok(())
}

/// Scan all of `caller_persona`'s active grants and refuse with
/// `-32010` on the first schema-version mismatch.
///
/// Companion to [`check_grant_schema_version`] for broker handlers
/// that DON'T look up a specific grant during their main flow
/// (`revoke`, `list`, `resolve`, `exec` — these operate on
/// materialization ids, not grants). When the payload names a
/// `caller_persona`, this gate enumerates that persona's active
/// grants and applies the pin check to each one BEFORE the request
/// proceeds. If ANY active grant the persona owns disagrees with
/// the pin, the daemon refuses the request — a schema-mismatch on
/// any grant the caller could plausibly invoke is grounds to
/// refuse all credential ops from that persona until the operator
/// reconciles the schema drift.
///
/// Resolution order:
///
/// 1. Payload omits `persona_id_field` → no-op (legacy/internal
///    callers, same posture as `check_principal_against_persona`).
/// 2. `list_active_grants()` returns empty → no-op (persona owns
///    no grants; downstream gates will handle the missing-grant
///    case themselves).
/// 3. Any active grant whose `schema_version` ≠ pin → refuse with
///    `-32010` and a structured message naming the offending grant.
pub fn check_grants_schema_version_for_persona(
    store: &DaemonStore,
    params: &Value,
    persona_id_field: &str,
) -> Result<(), (i32, String)> {
    let Some(persona_id) = params.get(persona_id_field).and_then(|v| v.as_str()) else {
        return Ok(());
    };
    let active_grants = store
        .list_active_grants()
        .map_err(|e| (-32603, format!("failed to query active grants: {e}")))?;
    for g in active_grants {
        if g.persona_id != persona_id {
            continue;
        }
        let core_grant = crate::trust::grant::grant_info_to_core(&g);
        check_grant_schema_version(&core_grant)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Peercred principal-binding gate
// ---------------------------------------------------------------------------

/// Enforce that the kernel-attested `PeerCredPrincipal.uid` matches
/// the uid bound to the persona named by the request payload's
/// `persona_id_field`. Mismatch is refused with the dedicated
/// `-32004` "principal binding mismatch" code per the
/// principal-binding contract.
///
/// Resolution order:
///
/// 1. When the request payload does not carry the named persona field
///    OR the field is not a string, the gate is a no-op — daemon-
///    internal / smoke callers that omit `caller_persona` continue to
///    operate under the legacy "warn but allow" posture documented in
///    `issue_with_registry`. The brief calls this out: the legacy
///    no-`caller_persona` path remains for daemon-internal smoke
///    tests; the per-agent UDS-socket integration will make
///    `caller_persona` mandatory on the agent-process socket.
/// 2. When `principal` is `None` (no kernel attestation available —
///    Internal source, or pre-migration entry point), the gate is a
///    no-op. Internal callers bypass principal binding by design.
/// 3. When the persona has no bound uid — consulted via
///    `lookup_persona_uid_from_enrollments(store, persona_id)`, the
///    per-agent UDS enrollment table, the sole source of truth.
///    If the surface carries no binding, the gate is a no-op —
///    legacy fail-open posture preserved for personas that pre-date
///    the enrollment surface (legacy `create_persona`).
/// 4. Otherwise: compare `principal.uid` with the bound uid; refuse
///    with `-32004` on mismatch.
pub fn check_principal_against_persona(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
    persona_id_field: &str,
) -> Result<(), (i32, String)> {
    let Some(principal) = principal else {
        return Ok(());
    };
    let Some(persona_id) = params.get(persona_id_field).and_then(|v| v.as_str()) else {
        return Ok(());
    };
    // The
    // enrollment table is now the sole source of truth. No-binding
    // preserves the legacy fail-open posture for legacy personas that
    // pre-date the per-agent UDS enrollment surface.
    let bound_uid =
        match crate::infra::store::lookup_persona_uid_from_enrollments(store, persona_id) {
            Ok(Some(uid)) => uid,
            Ok(None) | Err(_) => return Ok(()),
        };
    if principal.uid != bound_uid {
        tracing::warn!(
            principal_uid = principal.uid,
            principal_pid = principal.pid,
            persona_id = %persona_id,
            bound_uid,
            "broker handler: rejecting request — kernel-attested uid does not match persona's bound uid"
        );
        return Err((
            -32004,
            format!(
                "principal binding mismatch: peercred uid {} does not match persona '{}' bound uid {}",
                principal.uid, persona_id, bound_uid
            ),
        ));
    }
    Ok(())
}

/// Fail-closed gate.
/// Anchor: `fail_closed_broker_resolve`.
///
/// `check_principal_against_persona` (above) is fail-open by design — it
/// no-ops when the persona has no enrollment row, preserving the legacy
/// posture for callers that pre-date the per-agent UDS enrollment surface.
/// `broker_resolve` is the first RPC to lose that posture per the locked
/// rollout order (Step A);
/// every other broker RPC keeps the fail-open gate until its rollout step
/// (B/C/D) lands.
///
/// Returns `Err((-32401, _))` when:
///   * `principal` is present (kernel attestation available), AND
///   * `params[persona_id_field]` is a string, AND
///   * `lookup_persona_uid_from_enrollments(store, persona_id)` returns
///     `Ok(None)` — no active enrollment row keyed by `persona_id`.
///
/// Returns `Ok(())` when:
///   * `principal` is None (Internal source / no kernel attestation —
///     daemon-internal callers bypass kernel binding by design), OR
///   * `params[persona_id_field]` is absent (legacy smoke callers), OR
///   * an enrollment row exists for `persona_id` (the legacy gate's
///     uid-match check already ran via `check_principal_against_persona`
///     and produced its own refusal on mismatch — this gate only adds
///     the missing-enrollment refusal).
pub fn check_principal_enrollment_strict(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
    persona_id_field: &str,
) -> Result<(), (i32, String)> {
    if principal.is_none() {
        return Ok(());
    }
    let Some(persona_id) = params.get(persona_id_field).and_then(|v| v.as_str()) else {
        return Ok(());
    };
    match crate::infra::store::lookup_persona_uid_from_enrollments(store, persona_id) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err((
            -32401,
            format!(
                "unenrolled persona '{persona_id}': PrincipalNotEnrolled (fail_closed_broker_resolve)"
            ),
        )),
        Err(e) => Err((
            -32401,
            format!(
                "unenrolled persona '{persona_id}': PrincipalNotEnrolled (enrollment lookup failed: {e})"
            ),
        )),
    }
}

/// Completion marker (Step E).
///
/// The parent rollout (`/autogrill fail-closed-transition` Decision 3,
/// LOCKED order) flipped each broker RPC to refuse an unenrolled
/// `caller_persona` with `-32401`, in the order
/// `broker_resolve → broker_exec → broker_issue → broker_revoke + broker_list`
/// (Steps A–D, PRs #4211/#4215/#4221/#4225). All five of those RPCs now call
/// [`check_principal_enrollment_strict`].
///
/// Step E names `session.register` (the `register_session` RPC) as the
/// declared *final* step. Re-grounding the open disambiguation
/// against current code
/// resolves it to **option (b)**: `register_session` is the bootstrap
/// **enrollment writer** — it calls
/// `DaemonStore::record_host_mode_socket_enrollment` to create the
/// `agent_socket_enrollments` row that the five gated RPCs above then
/// require. Gating the writer on prior enrollment would permanently deadlock
/// bootstrap (a caller could never become enrolled). `register_session`
/// therefore stays open by design; its independent gates are kernel-attested
/// peercred binding (`check_principal_against_persona` /
/// `check_principal_is_alive`) and `OperatorPresence`
/// (`class:session-runtime`), not enrollment.
///
/// `mint_gh_token`, `mint_sub_persona`, and the `bindings.*` RPCs are outside
/// the parent's locked scope (`broker_resolve → … → session.register`) and
/// are not part of this rollout.
///
/// The bootstrap-open invariant is guarded by
/// `register_session_uses_trusted_principal_when_present` and
/// `register_session_stays_open_for_unenrolled_attested_caller_completes_rollout_e`:
/// an attested but unenrolled caller must still register. Do NOT add
/// [`check_principal_enrollment_strict`] to `register_session`.
///
/// Sentinels:
/// - parent completion — `fail_closed_rpc_rollout_complete`
/// - E disambiguation resolved — `fail_closed_e_session_register_resolved`
pub const FAIL_CLOSED_RPC_ROLLOUT_COMPLETE: &str = "fail_closed_rpc_rollout_complete";

// ---------------------------------------------------------------------------
// resolve_legacy_socket_enrollment — shared `/var/run/emberd.sock` caller
// classifier
// ---------------------------------------------------------------------------

/// Resolution of
/// a shared-socket RPC caller against the `agent_socket_enrollments`
/// table.
///
/// Step B of the collapse plumbed the 6 shared `/var/run/emberd.sock`
/// RPC entry points (broker_issue, broker_revoke, broker_list,
/// broker_resolve, broker_exec, broker.bindings.{register,list,remove,
/// move}) into one of three explicit branches so the legacy per-process
/// `PERSONA_UID_REGISTRY` thread-local could retire (Step C, now
/// landed). The variant names the caller's relationship to the
/// per-agent UDS enrollment surface; downstream gates
/// (`check_principal_against_persona`, `check_principal_is_alive`)
/// continue to fire as today, but the resolution makes the "which
/// trust lane is this caller on" decision auditable at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacySocketResolution {
    /// The caller's persona has an active row in `agent_socket_enrollments`.
    /// Carries the row so downstream code can consult `peer_uid`,
    /// `grant_id`, and the namespace-binding tuple without re-querying.
    Enrolled(crate::infra::store::AgentSocketEnrollment),
    /// The caller is daemon-internal (admin CLI, dashboard via HTTP-to-
    /// socket, recovery flow, smoke test): no kernel-attested principal
    /// was supplied. Peercred binding bypassed by design — the
    /// in-process trust lane pre-dates kernel attestation and remains
    /// the supported posture for these callers. The carried `reason`
    /// string surfaces the bypass in operator logs.
    Internal { reason: String },
    /// No enrollment row keyed by the request's persona. Legacy fail-
    /// open posture preserved post-Step-C — with the
    /// `PERSONA_UID_REGISTRY` thread-local retired, the downstream
    /// gate (`check_principal_against_persona`) sees no binding for
    /// the persona and treats the call as a legacy / pre-enrollment
    /// caller. The resolver itself does not refuse.
    NoEnrollment,
}

/// Classify a
/// shared-socket RPC caller against the per-agent UDS enrollment
/// surface.
///
/// Resolution order:
///
/// 1. `principal` is `None` → `Internal { reason: "no-kernel-attested-principal" }`.
///    The daemon-internal trust lane (admin CLI, dashboard, smoke tests)
///    threads `None` for the kernel-attested principal because there is
///    no peer socket to read peercred from; the call rides the
///    pre-peercred in-process lane.
/// 2. The request payload omits `persona_id_field` → `Internal {
///    reason: "no-persona-claim" }`. Legacy entry points that don't
///    name a calling persona (admin-issued grants, smoke harness)
///    bypass enrollment by design.
/// 3. An active `agent_socket_enrollments` row exists for the claimed
///    persona → `Enrolled(row)`. The most-recently enrolled active row
///    is returned when the persona has been re-enrolled (the
///    `ORDER BY enrolled_at DESC LIMIT 1` deterministic tie-break).
/// 4. Otherwise → `NoEnrollment`. The legacy fail-open posture is
///    preserved; with the `PERSONA_UID_REGISTRY` thread-local retired
///    in Step C, the downstream `check_principal_against_persona`
///    gate sees no binding for the persona and treats the call as a
///    legacy / pre-enrollment caller.
///
/// Returns `Err(StoreError::Sqlite)` only on a real SQLite error
/// (corrupt db, schema mismatch); the no-row and missing-field cases
/// resolve to `Ok(NoEnrollment)` / `Ok(Internal)` respectively so the
/// caller can apply policy uniformly without unwrapping a separate
/// error class.
///
/// Anchor: `fn resolve_legacy_socket_enrollment` is the brief's
/// failing-test grep target.
pub fn resolve_legacy_socket_enrollment(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
    persona_id_field: &str,
) -> Result<LegacySocketResolution, crate::infra::store::StoreError> {
    // (1) No kernel-attested principal → Internal trust lane.
    let Some(_principal) = principal else {
        return Ok(LegacySocketResolution::Internal {
            reason: "no-kernel-attested-principal".to_string(),
        });
    };

    // (2) No persona claim in payload → Internal trust lane (legacy
    // shape: admin CLI / smoke harness that doesn't name a persona).
    let Some(persona_id) = params.get(persona_id_field).and_then(|v| v.as_str()) else {
        return Ok(LegacySocketResolution::Internal {
            reason: "no-persona-claim".to_string(),
        });
    };

    // (3) Active enrollment row exists for the claimed persona →
    // surface it so the caller can read peer_uid / grant_id directly
    // without re-querying. The query mirrors the
    // `lookup_persona_uid_from_enrollments` shape: filter on
    // state = 'active', tie-break by enrolled_at DESC for re-enrollment.
    let result = store.conn().query_row(
        "SELECT socket_path, persona_id, grant_id, brief_content_hash, \
                enrolled_at, state, cgroup_v2_id, userns_inode, mnt_ns_inode \
         FROM agent_socket_enrollments \
         WHERE persona_id = ?1 AND state = 'active' \
         ORDER BY enrolled_at DESC \
         LIMIT 1",
        rusqlite::params![persona_id],
        |row| {
            Ok(crate::infra::store::AgentSocketEnrollment {
                socket_path: row.get(0)?,
                persona_id: row.get(1)?,
                grant_id: row.get(2)?,
                brief_content_hash: row.get(3)?,
                enrolled_at: row.get(4)?,
                state: row.get(5)?,
                cgroup_v2_id: row.get(6)?,
                userns_inode: row.get(7)?,
                mnt_ns_inode: row.get(8)?,
            })
        },
    );
    match result {
        Ok(row) => Ok(LegacySocketResolution::Enrolled(row)),
        // (4) No active enrollment → legacy fail-open posture.
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(LegacySocketResolution::NoEnrollment),
        Err(e) => Err(crate::infra::store::StoreError::Sqlite(e)),
    }
}

/// Emit a
/// structured trace line classifying a shared-socket RPC call.
///
/// Wrapper around [`resolve_legacy_socket_enrollment`] that swallows
/// the `StoreError` (treated as `NoEnrollment` for logging purposes;
/// the downstream gate will surface the real refusal) and records the
/// resolution variant against the supplied `method` label. Step B
/// keeps the call observability-only — the legacy peercred-uid gate
/// continues to enforce uid binding via the existing
/// `check_principal_against_persona` chain. Step C will replace the
/// fallback with a fail-closed posture once every legacy caller has
/// been migrated.
pub(super) fn log_legacy_socket_resolution(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
    persona_id_field: &str,
    method: &str,
) {
    match resolve_legacy_socket_enrollment(principal, store, params, persona_id_field) {
        Ok(LegacySocketResolution::Enrolled(row)) => {
            tracing::debug!(
                method,
                persona_id = %row.persona_id,
                socket_path = %row.socket_path,
                "legacy-socket-resolution: enrolled (per-agent UDS surface)"
            );
        }
        Ok(LegacySocketResolution::Internal { reason }) => {
            tracing::debug!(
                method,
                reason = %reason,
                "legacy-socket-resolution: internal (daemon-internal trust lane)"
            );
        }
        Ok(LegacySocketResolution::NoEnrollment) => {
            tracing::debug!(
                method,
                "legacy-socket-resolution: no-enrollment (legacy fail-open — Step C retires this branch)"
            );
        }
        Err(e) => {
            // SQLite errors during classification are not fatal at
            // Step B — the gate downstream still fires. Log so
            // operators see the lookup failure.
            tracing::warn!(
                method,
                error = %e,
                "legacy-socket-resolution: store lookup failed (resolution treated as no-enrollment)"
            );
        }
    }
}

/// Error code for "principal pidfd reports the bound peer process has
/// been reaped" — distinct from `-32004` (uid binding mismatch) so
/// operators can tell apart "wrong uid" from "PID-reuse / stale-PID
/// attack".
pub const ERR_PRINCIPAL_NOT_ALIVE: i32 = -32007;

/// Liveness gate paired with `check_principal_against_persona`.
///
/// When a kernel-attested principal is bound to a pidfd (Linux 5.3+),
/// the broker refuses any request whose underlying peer process has
/// been reaped. The pidfd is reuse-immune — if the kernel later hands
/// the original PID out to a new process, the pidfd still refers to
/// the now-dead original. This blocks the "send request, exit, kernel
/// recycles PID for a different process, that process now appears as
/// the original caller" attack.
///
/// Resolution order:
///
/// 1. `principal` is `None` → no-op. Internal callers bypass kernel
///    attestation by design.
/// 2. `principal.is_alive()` returns `true` → proceed (this covers
///    both "process alive" and "no pidfd bound, fall back to legacy
///    bare-PID posture").
/// 3. `principal.is_alive()` returns `false` → refuse with
///    `ERR_PRINCIPAL_NOT_ALIVE` (`-32007`).
pub fn check_principal_is_alive(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
) -> Result<(), (i32, String)> {
    let Some(principal) = principal else {
        return Ok(());
    };
    if !principal.is_alive() {
        return Err((
            ERR_PRINCIPAL_NOT_ALIVE,
            format!(
                "principal not alive: peer pid {} (uid {}) has been reaped — refusing request to avoid PID-reuse forgery",
                principal.pid, principal.uid
            ),
        ));
    }
    Ok(())
}

/// Error code for "the peer process's kernel-observable namespace
/// inodes do not match the (userns_inode, mnt_ns_inode, cgroup_v2_id)
/// tuple recorded on the agent_socket_enrollments row at spawn
/// completion". Distinct from `-32004` (uid mismatch), `-32007`
/// (principal not alive), and `-32008` (unmanifested binary) so
/// operators can tell apart "wrong uid", "stale PID", "unmanifested
/// binary", and "namespace rebind" at the log line.
pub const ERR_PRINCIPAL_NAMESPACE_MISMATCH: i32 = -32401;

/// Pure-function result of comparing
/// the recorded `agent_socket_enrollments` tuple against the live
/// namespace inodes captured from the principal's `/proc/<pid>` view.
///
/// `Match` means every populated recorded column equals the live
/// value. `Mismatch` carries one human-readable string per drifted
/// column (e.g. `"cgroup_v2_id recorded=42 live=99"`) so operators
/// can tell which namespace was swapped at the log line.
///
/// The comparator is factored out so the T1 property test
/// (`compare_ns_inodes_property_round_trip` and family) can drive
/// every mismatch permutation without I/O — it never reads `/proc`,
/// never opens a store, just exercises the field-by-field equality.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
pub enum NsCompareResult {
    /// All populated (non-NULL) recorded columns match the live capture.
    Match,
    /// At least one populated recorded column drifted. `fields` is the
    /// per-column diagnostic in the order `(cgroup_v2_id, userns_inode,
    /// mnt_ns_inode)`. Empty `fields` is unreachable from
    /// [`compare_ns_inodes`] (a no-mismatch result returns `Match`).
    Mismatch { fields: Vec<String> },
}

/// Pure comparator factored out of
/// [`check_principal_namespace_inodes`] for T1 property-test coverage.
///
/// `recorded` is the `(cgroup_v2_id, userns_inode, mnt_ns_inode)` triple
/// projected from the `agent_socket_enrollments` row; each field is
/// `Option<i64>` because legacy rows + non-Linux call sites carry NULL.
/// `live` is the freshly-captured tuple from the principal's
/// `/proc/<pid>` view (always all three fields populated on Linux).
///
/// Semantics:
///
/// - For each recorded `Some(want)`: compare against the corresponding
///   live field. If `want != live`, push a per-column diagnostic.
/// - Recorded `None` columns are SKIPPED — they were not enrolled, so
///   they cannot drift.
/// - All three recorded `None` (legacy NULL binding) → `Match` with
///   zero comparisons. The wrapping
///   [`check_principal_namespace_inodes`] short-circuits before
///   calling the comparator in that case for parity with the legacy
///   no-op posture, but the comparator itself is harmless if invoked.
/// - Any non-empty `fields` → `Mismatch`. Order is canonical
///   (`cgroup_v2_id` first, then `userns_inode`, then `mnt_ns_inode`).
///
/// Pure — no I/O, no allocations beyond the per-mismatch strings, no
/// global state. Suitable for property-test fuzzing over arbitrary
/// `(Option<i64>, Option<i64>, Option<i64>)` × `(i64, i64, i64)` inputs.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
pub(crate) fn compare_ns_inodes(
    recorded: (Option<i64>, Option<i64>, Option<i64>),
    live: crate::spawn::scion::NamespaceInodes,
) -> NsCompareResult {
    let (rec_cgroup, rec_userns, rec_mntns) = recorded;
    let mut fields: Vec<String> = Vec::new();
    if let Some(want) = rec_cgroup
        && want != live.cgroup_v2_id
    {
        fields.push(format!(
            "cgroup_v2_id recorded={want} live={}",
            live.cgroup_v2_id
        ));
    }
    if let Some(want) = rec_userns
        && want != live.userns_inode
    {
        fields.push(format!(
            "userns_inode recorded={want} live={}",
            live.userns_inode
        ));
    }
    if let Some(want) = rec_mntns
        && want != live.mnt_ns_inode
    {
        fields.push(format!(
            "mnt_ns_inode recorded={want} live={}",
            live.mnt_ns_inode
        ));
    }
    if fields.is_empty() {
        NsCompareResult::Match
    } else {
        NsCompareResult::Mismatch { fields }
    }
}

/// Container-binding gate paired with [`check_principal_is_alive`].
///
/// Verify the peer process's
/// kernel-observable namespace inodes still match the
/// `(userns_inode, mnt_ns_inode, cgroup_v2_id)` tuple captured at
/// spawn-completion and persisted on the
/// `agent_socket_enrollments` row for `principal.socket_path`. A
/// mismatch is the kernel-visible signal that the per-agent UDS
/// has been re-bound to a different namespace identity — exactly
/// the post-spawn rebind attack the three-tuple was introduced to
/// detect.
///
/// Resolution order:
///
/// 1. `principal` is `None` → no-op. Internal callers bypass kernel
///    attestation by design (admin CLI, recovery flows, test
///    harness without a real socket).
/// 2. No `agent_socket_enrollments` row for `principal.socket_path`
///    → no-op. Host-resident / pre-SCION callers never enrolled a
///    tuple; the legacy peercred + pidfd gates remain authoritative.
/// 3. The enrollment row exists but ALL three namespace columns are
///    NULL → no-op (legacy NULL bindings). The Step-A schema
///    introduced the columns; Step-B populates them on the
///    container spawn path; rows recorded before Step-B (or on
///    non-container call sites) carry NULL and must not be refused.
/// 4. On non-Linux targets: `/proc/<pid>/ns/{user,mnt}` does not
///    exist. The capture surface is Linux-only; treat as no-op so
///    macOS / BSD daemons continue to serve broker traffic without
///    this gate. Linux is the production target where the rebind
///    attack is in-scope.
/// 5. Linux + at least one non-NULL column: capture the live tuple
///    from the principal's `/proc/<pid>` and compare against the
///    recorded values. ANY non-NULL recorded column whose live
///    value differs is a refuse with
///    [`ERR_PRINCIPAL_NAMESPACE_MISMATCH`] (`-32401`).
///
/// If the live capture itself fails (process exited mid-call,
/// `/proc` unreadable, malformed cgroup file), the gate refuses
/// with `-32401`: we cannot prove the binding still holds, so we
/// fail-closed in the same posture as `check_principal_is_alive`'s
/// `poll()` error path.
pub fn check_principal_namespace_inodes(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
) -> Result<(), (i32, String)> {
    let Some(principal) = principal else {
        return Ok(());
    };

    // Resolve the enrollment row for the principal's socket. A
    // missing row means the caller is host-resident / pre-SCION;
    // the legacy peercred + pidfd gates remain authoritative.
    let path_str = match principal.socket_path.to_str() {
        Some(s) => s,
        None => {
            // Non-UTF-8 socket path — refuse (this should be
            // unreachable in production where the daemon owns the
            // /run/emberd path). Fail-closed.
            return Err((
                ERR_PRINCIPAL_NAMESPACE_MISMATCH,
                format!(
                    "principal namespace gate: peer socket path is not valid UTF-8: {}",
                    principal.socket_path.display()
                ),
            ));
        }
    };
    let row = match store.lookup_agent_socket_enrollment(path_str) {
        Ok(Some(r)) => r,
        Ok(None) => {
            // No enrollment row for this socket — host-resident
            // legacy path. Fall through to the existing gates.
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(
                socket_path = %path_str,
                error = %e,
                "check_principal_namespace_inodes: store lookup failed — \
                 refusing to avoid a silent bypass"
            );
            return Err((
                ERR_PRINCIPAL_NAMESPACE_MISMATCH,
                format!("principal namespace gate: store lookup for {path_str} failed: {e}"),
            ));
        }
    };

    // Legacy NULL bindings (rows recorded before Step-B / on
    // non-container call sites) — no-op. The gate only fires when
    // there is something to compare against.
    if row.cgroup_v2_id.is_none() && row.userns_inode.is_none() && row.mnt_ns_inode.is_none() {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        // Capture the live tuple from the principal's pid. If the
        // capture fails (process exited, /proc unreadable), fail-
        // closed — we cannot prove the binding still holds.
        let pid_u32 = u32::try_from(principal.pid).map_err(|_| {
            (
                ERR_PRINCIPAL_NAMESPACE_MISMATCH,
                format!(
                    "principal namespace gate: peer pid {} is not a positive u32",
                    principal.pid
                ),
            )
        })?;
        let live = match crate::spawn::scion::capture_container_ns_inodes(pid_u32) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    peer_pid = principal.pid,
                    peer_uid = principal.uid,
                    socket_path = %path_str,
                    error = %e,
                    "check_principal_namespace_inodes: live capture failed — \
                     refusing request"
                );
                return Err((
                    ERR_PRINCIPAL_NAMESPACE_MISMATCH,
                    format!(
                        "principal namespace gate: live capture for pid {} failed: {e}",
                        principal.pid
                    ),
                ));
            }
        };

        // Delegate the field-by-field
        // equality to the pure `compare_ns_inodes` comparator. The
        // comparator returns a typed result so the receipt-emission +
        // log message path below can name the specific column(s) that
        // drifted (operator triage).
        match compare_ns_inodes((row.cgroup_v2_id, row.userns_inode, row.mnt_ns_inode), live) {
            NsCompareResult::Match => Ok(()),
            NsCompareResult::Mismatch { fields: mismatches } => {
                tracing::warn!(
                    peer_pid = principal.pid,
                    peer_uid = principal.uid,
                    socket_path = %path_str,
                    mismatches = ?mismatches,
                    "check_principal_namespace_inodes: refusing request — \
                     namespace inode tuple drifted from spawn-time enrollment"
                );
                // Emit a refusal Receipt
                // so the audit trail captures the namespace-rebind
                // detection. The payload kind
                // `namespace_inode_mismatch_refused` (checkpoint) is
                // distinct from `broker_resolve_persona_binding_violation`
                // so operators querying the audit log can filter on the
                // namespace-drift cohort without conflating it with the
                // persona-binding cohort. Best-effort: if the event-log
                // write itself fails we still refuse the RPC (the
                // primary trust-boundary action) and log the secondary
                // failure to tracing.
                let payload = serde_json::json!({
                    "kind": "namespace_inode_mismatch_refused",
                    "peer_pid": principal.pid,
                    "peer_uid": principal.uid,
                    "socket_path": path_str,
                    "mismatches": mismatches,
                });
                if let Err(e) = store.log_event(
                    None,
                    "broker.resolve.refused",
                    None,
                    "denied",
                    Some(&payload.to_string()),
                ) {
                    tracing::warn!(
                        error = %e,
                        peer_pid = principal.pid,
                        socket_path = %path_str,
                        "check_principal_namespace_inodes: failed to record \
                         namespace_inode_mismatch_refused receipt (continuing with refusal)"
                    );
                }
                Err((
                    ERR_PRINCIPAL_NAMESPACE_MISMATCH,
                    format!(
                        "principal namespace mismatch: peer pid {} on {path_str} drifted from enrollment ({})",
                        principal.pid,
                        mismatches.join(", ")
                    ),
                ))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // /proc/<pid>/ns/{user,mnt} is Linux-only. macOS / BSDs
        // never populate the recorded tuple (the spawn path on
        // those targets uses the non-Linux stub which errors out),
        // so a non-Linux daemon should not be carrying non-NULL
        // namespace inode columns in production. Log + skip rather
        // than refuse: the production target is Linux, and we want
        // dev-on-macOS to keep functioning.
        let _ = row;
        tracing::debug!(
            peer_pid = principal.pid,
            peer_uid = principal.uid,
            socket_path = %path_str,
            "check_principal_namespace_inodes: skipping (non-Linux target — \
             /proc/<pid>/ns unavailable)"
        );
        Ok(())
    }
}

/// Error code for "the peer binary failed signed-manifest pin
/// verification". Distinct from `-32004` (uid mismatch) and `-32007`
/// (principal not alive) so operators can tell apart "wrong uid",
/// "stale PID", and "unmanifested binary" at the log line.
pub const ERR_BINARY_PIN_REFUSED: i32 = -32008;

/// Verify the peer process's on-disk binary matches the signed
/// binary manifest. Returns `Ok(())` when the peer is pinned, the
/// binary is in the manifest, and no debugger is attached.
///
/// Resolution order:
///
/// 1. `principal` is `None` → no-op. Internal callers bypass kernel
///    attestation entirely (admin CLI, recovery flows, tests).
/// 2. `current_manifest()` is `None` → no-op. The daemon started
///    without a signed manifest on disk (fresh install, pre-cohort-A
///    distribution). Refusing in this state would brick every
///    legacy install; we instead lean on the startup signature gate
///    (`PATH-PINNING-STARTUP-VERIFY`) to ensure that IF a manifest
///    is present at startup it is signed by the IdentityRoot. Once
///    the cohort-A distribution lands universally, this case
///    flips to fail-closed.
/// 3. On non-Linux targets: `/proc` does not exist. Skip
///    verification with a `tracing::debug!` — the broker still has
///    the peercred uid + persona-binding gate. macOS' equivalent
///    (`proc_pidpath` + `csops`) is a follow-up surface.
/// 4. Linux + manifest present: call `verify_peer_binary`. Map any
///    error to `(-32008, …)` with a structured log line so the
///    operator can diagnose the refusal.
pub fn check_peer_binary_pinned(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
) -> Result<(), (i32, String)> {
    let manifest = current_manifest();
    check_peer_binary_pinned_with(principal, manifest.as_deref())
}

/// Testable inner — same logic as [`check_peer_binary_pinned`] but
/// the manifest is passed explicitly so tests can exercise the
/// refusal path without poking the process-global `MANIFEST`
/// `OnceCell`. The dispatchers consume the `OnceCell` lookup; tests
/// drive this entry point directly.
pub fn check_peer_binary_pinned_with(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    manifest: Option<&BinaryManifest>,
) -> Result<(), (i32, String)> {
    let Some(principal) = principal else {
        return Ok(());
    };
    let Some(manifest) = manifest else {
        // No manifest installed — pin verification disabled by
        // virtue of the daemon having no pin database to consult.
        return Ok(());
    };

    #[cfg(target_os = "linux")]
    {
        match crate::binary_manifest::verify_peer_binary(principal.pid, manifest) {
            Ok(entry) => {
                tracing::debug!(
                    peer_pid = principal.pid,
                    peer_uid = principal.uid,
                    tool = %entry.tool_name,
                    version = %entry.version,
                    "broker handler: peer binary pin verified"
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    peer_pid = principal.pid,
                    peer_uid = principal.uid,
                    error = %e,
                    "broker handler: refusing request — peer binary failed pin verification"
                );
                let msg = match &e {
                    ManifestVerifyError::HashNotInManifest { .. } => {
                        format!("binary_pin_refused: {e}")
                    }
                    ManifestVerifyError::PathNotInManifest { .. } => {
                        format!("binary_pin_refused: {e}")
                    }
                    ManifestVerifyError::TracerAttached { .. } => {
                        format!("binary_pin_refused: {e}")
                    }
                    ManifestVerifyError::ProcReadFailed { .. }
                    | ManifestVerifyError::BinaryHashFailed { .. } => {
                        format!("binary_pin_refused: {e}")
                    }
                };
                Err((ERR_BINARY_PIN_REFUSED, msg))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = manifest; // suppress unused-binding on non-Linux builds
        tracing::debug!(
            peer_pid = principal.pid,
            peer_uid = principal.uid,
            "broker handler: skipping peer binary pin verification (non-Linux target — /proc unavailable)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::runtime::PeerCredPrincipal;
    use std::path::PathBuf;

    fn test_principal(uid: u32, pid: i32) -> PeerCredPrincipal {
        PeerCredPrincipal::new(uid, pid, PathBuf::from("/tmp/test-agent.sock"))
    }

    fn seed_persona_uid_via_enrollments(store: &DaemonStore, persona_id: &str, uid: u32) {
        let socket_path = format!("/run/emberd/test-agent-{persona_id}.sock");
        store
            .record_agent_socket_enrollment(
                &socket_path,
                persona_id,
                "test-grant",
                "test-hash",
                None,
                None,
                None,
            )
            .expect("seed enrollment for test");
        store
            .conn()
            .execute(
                "UPDATE agent_socket_enrollments SET peer_uid = ?1 WHERE socket_path = ?2",
                rusqlite::params![uid as i64, &socket_path],
            )
            .expect("seed peer_uid for test");
    }

    /// Legacy path: when the payload omits `caller_persona`, the gate
    /// is a no-op (daemon-internal smoke callers). Sibling brief
    /// work makes `caller_persona` mandatory on
    /// the agent-process socket; this gate is the structural seam.
    #[tokio::test]
    async fn handle_broker_issue_skips_gate_when_caller_persona_absent() {
        // Even though the principal exists, the gate is bypassed when
        // the payload does not carry caller_persona.
        let principal = test_principal(7007, 1);
        let store = DaemonStore::open_in_memory().unwrap();
        let params = serde_json::json!({"provider": "cloudflare"});
        let gate =
            check_principal_against_persona(Some(&principal), &store, &params, "caller_persona");
        assert!(
            gate.is_ok(),
            "no-caller_persona path must skip the gate: {gate:?}"
        );
    }

    /// Legacy path: when no principal is supplied (Internal source or
    /// pre-migration socket entry point), the gate is a no-op even
    /// when the payload carries `caller_persona`. Internal callers
    /// bypass peercred binding by design.
    #[tokio::test]
    async fn handle_broker_issue_skips_gate_when_principal_absent() {
        let store = DaemonStore::open_in_memory().unwrap();
        seed_persona_uid_via_enrollments(&store, "internal-persona", 8008);

        // Principal absent — even with a binding, the gate cannot fire.
        let params = serde_json::json!({"caller_persona": "internal-persona"});
        let gate = check_principal_against_persona(None, &store, &params, "caller_persona");
        assert!(
            gate.is_ok(),
            "no-principal path must skip the gate: {gate:?}"
        );
    }

    /// Companion — a live principal proceeds normally past the
    /// pidfd gate. Uses the current test process's own pid (it is
    /// trivially alive) and exercises `check_principal_is_alive`
    /// directly so we don't need a full issue round-trip.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn handle_broker_issue_accepts_live_principal() {
        let my_pid = std::process::id() as i32;
        let euid = unsafe { libc::geteuid() };
        let principal = match PeerCredPrincipal::new_with_pidfd_for_test(
            euid,
            my_pid,
            std::path::PathBuf::from("/tmp/test-agent.sock"),
        ) {
            Some(p) => p,
            None => {
                eprintln!(
                    "skipping handle_broker_issue_accepts_live_principal: \
                     pidfd_open unavailable (need Linux 5.3+)"
                );
                return;
            }
        };

        assert!(
            principal.is_alive(),
            "principal bound to current pid must report alive"
        );
        let gate = check_principal_is_alive(Some(&principal));
        assert!(
            gate.is_ok(),
            "live principal must pass the pidfd gate: {gate:?}"
        );
    }

    /// Principal without a bound pidfd (legacy kernel, or built via
    /// `PeerCredPrincipal::new()` for Internal dispatch / tests) falls
    /// back to the bare-PID posture: `is_alive()` is `true` and the
    /// gate is a no-op.
    #[tokio::test]
    async fn check_principal_is_alive_skips_when_no_pidfd_bound() {
        let principal = test_principal(1234, 9999);
        // No pidfd was opened in `new()`, so `is_alive()` returns
        // true unconditionally (legacy posture).
        assert!(principal.is_alive());
        let gate = check_principal_is_alive(Some(&principal));
        assert!(
            gate.is_ok(),
            "no-pidfd principal must pass the gate: {gate:?}"
        );
    }

    /// `principal == None` — Internal callers bypass the pidfd gate
    /// by design (admin CLI, recovery flows, test harness without
    /// a real socket).
    #[tokio::test]
    async fn check_principal_is_alive_skips_when_principal_absent() {
        let gate = check_principal_is_alive(None);
        assert!(
            gate.is_ok(),
            "no-principal path must skip the gate: {gate:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Container-binding gate. Refuses any
    // peer whose kernel-observable namespace inodes drifted from the
    // (cgroup_v2_id, userns_inode, mnt_ns_inode) tuple recorded on the
    // `agent_socket_enrollments` row at spawn-completion. Tests drive
    // `check_principal_namespace_inodes` directly with an in-memory store
    // so the dispatcher path is not required.
    // -----------------------------------------------------------------------

    /// `principal == None` — Internal callers (admin CLI / recovery flows)
    /// bypass the gate. Mirrors the `check_principal_is_alive` no-op
    /// posture for the principal-absent case.
    #[test]
    fn check_principal_namespace_inodes_skips_when_principal_absent() {
        let store = DaemonStore::open_in_memory().expect("open in-memory store");
        let gate = check_principal_namespace_inodes(None, &store);
        assert!(
            gate.is_ok(),
            "no-principal path must skip the gate: {gate:?}"
        );
    }

    /// No `agent_socket_enrollments` row → no-op. The principal's
    /// socket path is not enrolled (host-resident / pre-SCION call
    /// site); the gate falls through to the legacy peercred + pidfd
    /// surface upstream of this check.
    #[test]
    fn check_principal_namespace_inodes_skips_when_no_enrollment_row() {
        let store = DaemonStore::open_in_memory().expect("open in-memory store");
        let principal = test_principal(1000, std::process::id() as i32);
        let gate = check_principal_namespace_inodes(Some(&principal), &store);
        assert!(
            gate.is_ok(),
            "no-enrollment path must skip the gate (legacy host-resident): {gate:?}"
        );
    }

    /// Enrollment row exists but all three namespace columns are NULL
    /// (legacy NULL binding — row recorded before Step-B / on a
    /// non-container call site). The gate is a no-op.
    #[test]
    fn check_principal_namespace_inodes_skips_when_legacy_null_binding() {
        let store = DaemonStore::open_in_memory().expect("open in-memory store");
        let socket_path = "/tmp/test-agent.sock";
        store
            .record_agent_socket_enrollment(
                socket_path,
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-0000000000aa",
                "blake3:0",
                None,
                None,
                None,
            )
            .expect("record enrollment");
        let principal =
            PeerCredPrincipal::new(1000, std::process::id() as i32, PathBuf::from(socket_path));
        let gate = check_principal_namespace_inodes(Some(&principal), &store);
        assert!(
            gate.is_ok(),
            "all-NULL namespace columns must skip the gate (legacy): {gate:?}"
        );
    }

    /// Linux + recorded tuple + live /proc tuple drifted from
    /// enrollment → refuse with `-32401`. We construct a synthetic
    /// mismatch by recording deliberately-wrong inode values; the
    /// live `capture_container_ns_inodes` for the current test pid
    /// will produce real inodes which cannot match these
    /// `0xdead`-shaped sentinels.
    #[cfg(target_os = "linux")]
    #[test]
    fn check_principal_namespace_inodes_refuses_mismatch() {
        let store = DaemonStore::open_in_memory().expect("open in-memory store");
        let socket_path = "/tmp/test-agent-mismatch.sock";
        // Synthetic checkpoint inodes — production inode numbers are
        // small positives, so the live capture for the test pid will
        // not collide with these by accident.
        store
            .record_agent_socket_enrollment(
                socket_path,
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-0000000000aa",
                "blake3:0",
                Some(0x0dead_cafe),
                Some(0x0dead_beef),
                Some(0x0dead_face),
            )
            .expect("record enrollment");
        let principal =
            PeerCredPrincipal::new(1000, std::process::id() as i32, PathBuf::from(socket_path));
        let gate = check_principal_namespace_inodes(Some(&principal), &store);
        let (code, msg) = gate.expect_err("drifted-tuple must refuse with -32401");
        assert_eq!(
            code, ERR_PRINCIPAL_NAMESPACE_MISMATCH,
            "expected -32401 namespace mismatch, got {code}: {msg}"
        );
        assert!(
            msg.contains("principal namespace") || msg.contains("namespace"),
            "error must mention namespace, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // T1 + T2 coverage for the
    // namespace-inode comparator and the JSON-RPC error path. T1 is a
    // proptest-driven property test over the pure `compare_ns_inodes`
    // function; T2 is a fixture test that drives
    // `check_principal_namespace_inodes` against an in-memory
    // `agent_socket_enrollments` row and asserts the typed -32401
    // refusal. T3 lives in `tests/container_persona_enrollment.rs`
    // (real-socket integration test) and asserts the
    // `namespace_inode_mismatch_refused` Receipt lands on the
    // audit_log. Anchor: `namespace_inode_mismatch_refused`.
    // -----------------------------------------------------------------------

    /// T1 (property test) — for any captured inodes `(c, u, m)` and any
    /// live inodes `(c', u', m')`, `compare_ns_inodes` returns `Match`
    /// iff every populated recorded column equals the corresponding
    /// live column; otherwise `Mismatch` with one diagnostic per
    /// drifted column, in canonical order.
    ///
    /// The proptest generates the full Cartesian space:
    ///   - three independent `Option<i64>` recorded columns (so the
    ///     legacy-NULL, partially-NULL, and all-populated rows are
    ///     all exercised).
    ///   - three independent `i64` live columns.
    /// Anchor: `namespace_inode_mismatch_refused` (matches the
    /// payload kind the comparator's refusal path emits via
    /// `store.log_event`).
    #[test]
    fn compare_ns_inodes_property_namespace_inode_mismatch_refused() {
        use crate::spawn::scion::NamespaceInodes;
        use proptest::prelude::*;

        let mut runner = proptest::test_runner::TestRunner::default();
        runner
            .run(
                &(
                    proptest::option::of(any::<i64>()),
                    proptest::option::of(any::<i64>()),
                    proptest::option::of(any::<i64>()),
                    any::<i64>(),
                    any::<i64>(),
                    any::<i64>(),
                ),
                |(rec_c, rec_u, rec_m, live_c, live_u, live_m)| {
                    let live = NamespaceInodes {
                        cgroup_v2_id: live_c,
                        userns_inode: live_u,
                        mnt_ns_inode: live_m,
                    };
                    let result = compare_ns_inodes((rec_c, rec_u, rec_m), live);

                    // Independently compute the oracle: which populated
                    // recorded columns differ from the live tuple?
                    let cgroup_drifted = rec_c.map(|w| w != live_c).unwrap_or(false);
                    let userns_drifted = rec_u.map(|w| w != live_u).unwrap_or(false);
                    let mntns_drifted = rec_m.map(|w| w != live_m).unwrap_or(false);
                    let any_drifted = cgroup_drifted || userns_drifted || mntns_drifted;

                    match (any_drifted, &result) {
                        (false, NsCompareResult::Match) => Ok(()),
                        (true, NsCompareResult::Mismatch { fields }) => {
                            // Canonical-order check: cgroup_v2_id is
                            // always emitted before userns_inode, which
                            // is emitted before mnt_ns_inode.
                            let cgroup_idx = fields
                                .iter()
                                .position(|f| f.starts_with("cgroup_v2_id"));
                            let userns_idx = fields
                                .iter()
                                .position(|f| f.starts_with("userns_inode"));
                            let mntns_idx = fields
                                .iter()
                                .position(|f| f.starts_with("mnt_ns_inode"));
                            prop_assert_eq!(
                                cgroup_idx.is_some(),
                                cgroup_drifted,
                                "cgroup_v2_id presence must match drift: fields={:?}",
                                fields
                            );
                            prop_assert_eq!(
                                userns_idx.is_some(),
                                userns_drifted,
                                "userns_inode presence must match drift: fields={:?}",
                                fields
                            );
                            prop_assert_eq!(
                                mntns_idx.is_some(),
                                mntns_drifted,
                                "mnt_ns_inode presence must match drift: fields={:?}",
                                fields
                            );
                            if let (Some(a), Some(b)) = (cgroup_idx, userns_idx) {
                                prop_assert!(
                                    a < b,
                                    "cgroup_v2_id must precede userns_inode in fields: {:?}",
                                    fields
                                );
                            }
                            if let (Some(a), Some(b)) = (userns_idx, mntns_idx) {
                                prop_assert!(
                                    a < b,
                                    "userns_inode must precede mnt_ns_inode in fields: {:?}",
                                    fields
                                );
                            }
                            Ok(())
                        }
                        (false, NsCompareResult::Mismatch { fields }) => Err(
                            proptest::test_runner::TestCaseError::fail(format!(
                                "no drift but Mismatch returned: fields={fields:?}"
                            )),
                        ),
                        (true, NsCompareResult::Match) => Err(
                            proptest::test_runner::TestCaseError::fail(format!(
                                "drift in (c={cgroup_drifted}, u={userns_drifted}, m={mntns_drifted}) but Match returned"
                            )),
                        ),
                    }
                },
            )
            .expect("property holds for all generated tuples");
    }

    /// T1 corner case — explicit permutation table covering every
    /// "exactly one column drifted" case, "exactly two drifted", "all
    /// three drifted". Pinned cases so a CI-stable regression catches
    /// any future refactor that scrambles the column order or drops
    /// a column. Anchor: `namespace_inode_mismatch_refused`.
    #[test]
    fn compare_ns_inodes_permutations_namespace_inode_mismatch_refused_cases() {
        use crate::spawn::scion::NamespaceInodes;

        // Live capture used as the "current" tuple.
        let live = NamespaceInodes {
            cgroup_v2_id: 100,
            userns_inode: 200,
            mnt_ns_inode: 300,
        };

        // (recorded triple, expected mismatched columns, label)
        let cases: &[((Option<i64>, Option<i64>, Option<i64>), &[&str], &str)] = &[
            // All match — populated and equal.
            ((Some(100), Some(200), Some(300)), &[], "all-match"),
            // Exactly cgroup_v2_id drifted.
            (
                (Some(999), Some(200), Some(300)),
                &["cgroup_v2_id"],
                "cgroup-only-drifted",
            ),
            // Exactly userns_inode drifted.
            (
                (Some(100), Some(999), Some(300)),
                &["userns_inode"],
                "userns-only-drifted",
            ),
            // Exactly mnt_ns_inode drifted.
            (
                (Some(100), Some(200), Some(999)),
                &["mnt_ns_inode"],
                "mntns-only-drifted",
            ),
            // cgroup + userns drifted.
            (
                (Some(999), Some(998), Some(300)),
                &["cgroup_v2_id", "userns_inode"],
                "cgroup-userns-drifted",
            ),
            // cgroup + mnt drifted.
            (
                (Some(999), Some(200), Some(998)),
                &["cgroup_v2_id", "mnt_ns_inode"],
                "cgroup-mntns-drifted",
            ),
            // userns + mnt drifted.
            (
                (Some(100), Some(999), Some(998)),
                &["userns_inode", "mnt_ns_inode"],
                "userns-mntns-drifted",
            ),
            // All three drifted.
            (
                (Some(999), Some(998), Some(997)),
                &["cgroup_v2_id", "userns_inode", "mnt_ns_inode"],
                "all-three-drifted",
            ),
            // Legacy-NULL row — comparator must return Match.
            ((None, None, None), &[], "legacy-null-binding"),
            // Partial-NULL row — recorded cgroup drifted, others NULL.
            (
                (Some(999), None, None),
                &["cgroup_v2_id"],
                "partial-null-cgroup-drifted",
            ),
            // Partial-NULL row — recorded userns matches, others NULL.
            ((None, Some(200), None), &[], "partial-null-userns-matches"),
        ];

        for (recorded, expected_cols, label) in cases {
            let result = compare_ns_inodes(*recorded, live);
            if expected_cols.is_empty() {
                assert!(
                    matches!(result, NsCompareResult::Match),
                    "{label}: expected Match, got {result:?}"
                );
            } else {
                let fields = match &result {
                    NsCompareResult::Mismatch { fields } => fields.clone(),
                    NsCompareResult::Match => {
                        panic!("{label}: expected Mismatch, got Match")
                    }
                };
                assert_eq!(
                    fields.len(),
                    expected_cols.len(),
                    "{label}: expected {} mismatched columns, got {}: {fields:?}",
                    expected_cols.len(),
                    fields.len()
                );
                for (col, field) in expected_cols.iter().zip(fields.iter()) {
                    assert!(
                        field.starts_with(col),
                        "{label}: expected field {col} at position, got: {field}"
                    );
                }
            }
        }
    }

    /// T2 fixture — in-memory `agent_socket_enrollments` row with
    /// captured inodes that cannot match the live capture from the
    /// current test process pid. The gate's full path runs (store
    /// lookup → live capture → comparator → log_event refusal Receipt
    /// → typed `-32401` return). Asserts:
    ///
    ///   1. the return value carries `ERR_PRINCIPAL_NAMESPACE_MISMATCH`
    ///      (`-32401`),
    ///   2. the audit_log row with action `broker.resolve.refused`
    ///      carries the `namespace_inode_mismatch_refused` payload
    ///      kind.
    ///
    /// Anchor: `namespace_inode_mismatch_refused`.
    #[cfg(target_os = "linux")]
    #[test]
    fn check_principal_namespace_inodes_emits_namespace_inode_mismatch_refused_receipt() {
        use crate::infra::audit::AuditFilter;

        let store = DaemonStore::open_in_memory().expect("open in-memory store");
        let socket_path = "/tmp/test-agent-mismatch-receipt.sock";
        store
            .record_agent_socket_enrollment(
                socket_path,
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-0000000000aa",
                "blake3:0",
                Some(0x0dead_aaaa),
                Some(0x0dead_bbbb),
                Some(0x0dead_cccc),
            )
            .expect("record enrollment");

        let principal =
            PeerCredPrincipal::new(1000, std::process::id() as i32, PathBuf::from(socket_path));
        let gate = check_principal_namespace_inodes(Some(&principal), &store);
        let (code, msg) = gate.expect_err("drifted-tuple must refuse with -32401");
        assert_eq!(
            code, ERR_PRINCIPAL_NAMESPACE_MISMATCH,
            "expected -32401, got {code}: {msg}"
        );

        // Verify the refusal Receipt landed on the audit_log.
        let entries = store
            .query_audit(&AuditFilter {
                action: Some("broker.resolve.refused".to_string()),
                ..Default::default()
            })
            .expect("query_audit must succeed");
        let mismatch_rows: Vec<_> = entries
            .iter()
            .filter(|e| {
                e.details
                    .as_deref()
                    .map(|d| d.contains("namespace_inode_mismatch_refused"))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(
            mismatch_rows.len(),
            1,
            "exactly one namespace_inode_mismatch_refused refusal Receipt expected, got: {entries:?}"
        );
        let row = mismatch_rows[0];
        assert_eq!(row.outcome, "denied", "Receipt outcome must be denied");
        let details = row.details.as_deref().expect("Receipt must carry details");
        assert!(
            details.contains("namespace_inode_mismatch_refused"),
            "Receipt payload must name the checkpoint kind, got: {details}"
        );
        assert!(
            details.contains(socket_path),
            "Receipt payload must name the socket path, got: {details}"
        );
    }

    // -----------------------------------------------------------------------
    // Peer binary pinning
    // gate. The broker handlers consult the signed manifest at connect time
    // and refuse a request whose peer's on-disk binary is not in the
    // manifest. Tests drive `check_peer_binary_pinned_with` directly to
    // avoid `OnceCell` cross-test pollution from `current_manifest()`.
    // -----------------------------------------------------------------------

    /// `check_peer_binary_pinned_with(principal=None, …)` is a no-op
    /// regardless of manifest state — Internal callers bypass kernel
    /// attestation by design.
    #[test]
    fn check_peer_binary_pinned_skips_when_principal_absent() {
        let manifest = BinaryManifest::default();
        let gate = check_peer_binary_pinned_with(None, Some(&manifest));
        assert!(
            gate.is_ok(),
            "no-principal path must skip the gate: {gate:?}"
        );
    }

    /// `check_peer_binary_pinned_with(principal=Some(…), manifest=None)` is
    /// a no-op — a daemon with no manifest installed has nothing to
    /// pin against. Pin verification is "disabled" in that state.
    #[test]
    fn check_peer_binary_pinned_skips_when_manifest_absent() {
        let principal = test_principal(1000, std::process::id() as i32);
        let gate = check_peer_binary_pinned_with(Some(&principal), None);
        assert!(
            gate.is_ok(),
            "no-manifest path must skip the gate: {gate:?}"
        );
    }

    /// Failing-test contract from the brief —
    /// `handle_broker_issue_refuses_unmanifested_binary`. The peer
    /// principal's pid resolves to a real binary on disk (the test
    /// process itself) but the manifest is empty. The broker handler
    /// must refuse with `-32008` BEFORE any provider IO. We exercise
    /// `check_peer_binary_pinned_with` directly because the
    /// `handle_broker_issue` wrapper uses the process-global
    /// `MANIFEST` `OnceCell` whose single-shot install would pollute
    /// other tests in the same binary.
    #[cfg(target_os = "linux")]
    #[test]
    fn handle_broker_issue_refuses_unmanifested_binary() {
        let principal = test_principal(1000, std::process::id() as i32);
        let manifest = BinaryManifest::default(); // empty — peer not pinned
        let res = check_peer_binary_pinned_with(Some(&principal), Some(&manifest));
        let (code, msg) = res.expect_err("issue must refuse unmanifested peer binary");
        assert_eq!(
            code, ERR_BINARY_PIN_REFUSED,
            "expected -32008 binary_pin_refused, got {code}: {msg}"
        );
        assert!(
            msg.contains("binary_pin_refused"),
            "error must mention pin refusal, got: {msg}"
        );
    }

    /// Companion: when the manifest DOES contain the peer binary's
    /// hash + path, the gate is a pass-through.
    #[cfg(target_os = "linux")]
    #[test]
    fn check_peer_binary_pinned_with_accepts_manifested_binary() {
        let my_pid = std::process::id() as i32;
        let exe_path =
            std::fs::read_link(format!("/proc/{my_pid}/exe")).expect("/proc/self/exe must resolve");
        let bytes = std::fs::read(&exe_path).expect("read test binary");
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bytes);
        let hash = format!("blake3:{}", hex::encode(hasher.finalize().as_bytes()));

        let manifest = BinaryManifest {
            entries: vec![crate::binary_manifest::BinaryManifestEntry {
                tool_name: "ember-test-runner".to_string(),
                version: "0.0.0".to_string(),
                content_hash: hash,
                absolute_path: exe_path,
                installed_at: 0,
                publisher: "did:emberlink".to_string(),
                channel: crate::binary_manifest::BinaryDistributionChannel::Bundled,
            }],
        };

        let principal = test_principal(1000, my_pid);
        let gate = check_peer_binary_pinned_with(Some(&principal), Some(&manifest));
        assert!(
            gate.is_ok(),
            "manifested binary must pass the gate: {gate:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Pin the grant schema_version at the
    // broker boundary. A grant minted under a different schema interpretation
    // is refused with -32010 BEFORE any provider IO or policy evaluation.
    // -----------------------------------------------------------------------

    /// Construct a `core_grants::Grant` fixture with `schema_version` set
    /// to `version`. Other fields take placeholder values — only
    /// `schema_version` matters for this gate.
    fn fixture_grant_with_schema_version(version: u32) -> core_grants::Grant {
        core_grants::Grant {
            id: uuid::Uuid::new_v4(),
            issuer: core_grants::PrincipalId("fixture-persona".to_string()),
            scope: core_grants::Scope {
                capability: "cloudflare".to_string(),
                resource_id: None,
                constraints: Vec::new(),
            },
            state: core_grants::GrantState::Active,
            expires_at: None,
            parent_id: None,
            delegation_depth: 0,
            usage: core_grants::Usage::zero(),
            schema_version: version,
        }
    }

    /// Failing-test contract from the brief — a grant whose
    /// `schema_version` does not match the daemon's compiled-in pin must
    /// be refused at the broker boundary with `-32010`. The error
    /// message names the offending grant id and both versions so the
    /// operator can diagnose without reading the SQL row directly.
    #[test]
    fn handle_broker_issue_refuses_mismatched_schema_version() {
        let stale = fixture_grant_with_schema_version(0);
        let result = check_grant_schema_version(&stale);
        let (code, msg) =
            result.expect_err("schema_version=0 must be refused when daemon pin is 1+");
        assert_eq!(
            code, ERR_GRANT_SCHEMA_VERSION_MISMATCH,
            "expected -32010 grant_schema_version_mismatch, got {code}: {msg}"
        );
        assert_eq!(code, -32010, "error code must be -32010 per brief");
        assert!(
            msg.contains("grant_schema_version_mismatch"),
            "error message must namespace the refusal kind, got: {msg}"
        );
        assert!(
            msg.contains("schema_version=0"),
            "error message must name the offending grant's version, got: {msg}"
        );
    }

    /// A grant whose `schema_version` matches the daemon's pin is
    /// admitted by the gate — the check is a pass-through for in-pin
    /// grants.
    #[test]
    fn check_grant_schema_version_accepts_current_pin() {
        let fresh = fixture_grant_with_schema_version(core_grants::GRANT_SCHEMA_VERSION_PIN);
        check_grant_schema_version(&fresh).expect("pinned schema_version must pass the gate");
    }

    /// A grant minted via `core_grants::create()` automatically carries
    /// the daemon's current pin — exercising the construction-time
    /// invariant the brief installs alongside the gate.
    #[test]
    fn create_grant_stamps_current_schema_version_pin() {
        let spec = core_grants::GrantSpec {
            issuer: core_grants::PrincipalId("issuer".to_string()),
            scope: core_grants::Scope {
                capability: "read".to_string(),
                resource_id: None,
                constraints: Vec::new(),
            },
            expires_at: None,
        };
        let grant = core_grants::create(spec).expect("create must succeed");
        assert_eq!(
            grant.schema_version,
            core_grants::GRANT_SCHEMA_VERSION_PIN,
            "core_grants::create must stamp the current pin"
        );
        check_grant_schema_version(&grant).expect("freshly-minted grant must pass the gate");
    }

    /// Pre-field on-disk grants deserialize with `schema_version`
    /// defaulted to the daemon's pin via
    /// `#[serde(default = "default_schema_version")]`. Back-compat
    /// guarantee: legacy JSON without the field still parses to a Grant
    /// the broker gate admits.
    #[test]
    fn grant_deserializes_without_schema_version_field() {
        let legacy_json = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000000",
            "issuer": "legacy-issuer",
            "scope": {
                "capability": "read",
                "resource_id": null,
                "constraints": []
            },
            "state": "Active",
            "expires_at": null,
            "parent_id": null,
            "delegation_depth": 0,
            "usage": { "used": 0 }
        });
        let grant: core_grants::Grant =
            serde_json::from_value(legacy_json).expect("legacy grant must parse");
        assert_eq!(
            grant.schema_version,
            core_grants::GRANT_SCHEMA_VERSION_PIN,
            "missing schema_version must default to the current pin"
        );
    }

    // -----------------------------------------------------------------------
    // T2 fixture
    // tests on resolve_legacy_socket_enrollment. Each test covers one of the
    // three resolution states the helper distinguishes for shared-socket
    // (legacy /var/run/emberd.sock) RPC callers.
    // -----------------------------------------------------------------------

    /// Internal trust lane (1): when no kernel-attested principal is
    /// supplied, the caller rides the daemon-internal in-process lane
    /// (admin CLI / recovery / smoke harness). The resolver must surface
    /// `Internal { reason: "no-kernel-attested-principal" }` so the gate
    /// downstream understands peercred binding is bypassed by design.
    #[test]
    fn resolve_legacy_socket_enrollment_returns_internal_when_principal_absent() {
        let store = DaemonStore::open_in_memory().unwrap();
        let params = serde_json::json!({"caller_persona": "anything"});

        let resolution = resolve_legacy_socket_enrollment(None, &store, &params, "caller_persona")
            .expect("resolver must succeed when principal absent");
        match resolution {
            LegacySocketResolution::Internal { reason } => {
                assert_eq!(
                    reason, "no-kernel-attested-principal",
                    "no-principal lane must name itself in the reason field"
                );
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    /// Internal trust lane (2): kernel-attested principal supplied, but
    /// the payload omits the named persona field. Legacy admin shapes
    /// that don't claim a persona ride the Internal lane — the gate
    /// downstream is a no-op (matches the existing
    /// `check_principal_against_persona` posture for missing-field).
    #[test]
    fn resolve_legacy_socket_enrollment_returns_internal_when_persona_field_absent() {
        let store = DaemonStore::open_in_memory().unwrap();
        let principal = test_principal(1234, 1);
        let params = serde_json::json!({"provider": "cloudflare"});

        let resolution =
            resolve_legacy_socket_enrollment(Some(&principal), &store, &params, "caller_persona")
                .expect("resolver must succeed when persona field absent");
        match resolution {
            LegacySocketResolution::Internal { reason } => {
                assert_eq!(
                    reason, "no-persona-claim",
                    "no-persona-field lane must name itself in the reason field"
                );
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    /// Enrolled lane: kernel-attested principal supplied, payload names
    /// a persona, and an active row exists in `agent_socket_enrollments`
    /// for that persona. The resolver must surface the row so downstream
    /// code can consult `peer_uid`, `grant_id`, and the binding tuple
    /// without re-querying.
    #[test]
    fn resolve_legacy_socket_enrollment_returns_enrolled_when_active_row_present() {
        let store = DaemonStore::open_in_memory().unwrap();
        let persona_id = "persona-with-enrollment";
        let socket_path = "/run/emberd/agent-resolve-enrolled.sock";
        store
            .record_agent_socket_enrollment(
                socket_path,
                persona_id,
                "grant-resolve-enrolled",
                "hash-resolve-enrolled",
                None,
                None,
                None,
            )
            .unwrap();

        let principal = test_principal(4242, 9999);
        let params = serde_json::json!({"caller_persona": persona_id});

        let resolution =
            resolve_legacy_socket_enrollment(Some(&principal), &store, &params, "caller_persona")
                .expect("resolver must succeed for active enrollment");
        match resolution {
            LegacySocketResolution::Enrolled(row) => {
                assert_eq!(row.persona_id, persona_id);
                assert_eq!(row.socket_path, socket_path);
                assert_eq!(row.grant_id, "grant-resolve-enrolled");
                assert_eq!(row.state, "active");
            }
            other => panic!("expected Enrolled, got {other:?}"),
        }
    }

    /// NoEnrollment lane: kernel-attested principal supplied, payload
    /// names a persona, but no active row exists for that persona. The
    /// resolver must surface `NoEnrollment` so the legacy fail-open
    /// posture is preserved (the downstream gate consults the legacy
    /// per-process registry for these callers during Step B).
    #[test]
    fn resolve_legacy_socket_enrollment_returns_no_enrollment_when_persona_missing() {
        let store = DaemonStore::open_in_memory().unwrap();
        let principal = test_principal(7777, 1);
        let params = serde_json::json!({"caller_persona": "persona-with-no-enrollment"});

        let resolution =
            resolve_legacy_socket_enrollment(Some(&principal), &store, &params, "caller_persona")
                .expect("resolver must succeed when no enrollment exists");
        assert!(
            matches!(resolution, LegacySocketResolution::NoEnrollment),
            "expected NoEnrollment, got {resolution:?}"
        );
    }

    /// Revoked enrollments are filtered out: an `agent_socket_enrollments`
    /// row whose `state = 'revoked'` must not surface as Enrolled. The
    /// resolver returns `NoEnrollment` so the gate downstream applies
    /// the legacy fail-open posture rather than treating the revoked row
    /// as live identity.
    #[test]
    fn resolve_legacy_socket_enrollment_skips_revoked_rows() {
        let store = DaemonStore::open_in_memory().unwrap();
        let persona_id = "persona-revoked";
        let socket_path = "/run/emberd/agent-resolve-revoked.sock";
        store
            .record_agent_socket_enrollment(
                socket_path,
                persona_id,
                "grant-resolve-revoked",
                "hash-resolve-revoked",
                None,
                None,
                None,
            )
            .unwrap();
        store
            .revoke_agent_socket_enrollment(socket_path)
            .expect("revoke");

        let principal = test_principal(8888, 1);
        let params = serde_json::json!({"caller_persona": persona_id});

        let resolution =
            resolve_legacy_socket_enrollment(Some(&principal), &store, &params, "caller_persona")
                .expect("resolver must succeed even when only revoked rows exist");
        assert!(
            matches!(resolution, LegacySocketResolution::NoEnrollment),
            "revoked-only persona must resolve to NoEnrollment, got {resolution:?}"
        );
    }
}
