//! CLASSIFICATION: PUBLIC
//!
//! `endpoint_gate_framework` — one per-session endpoint gate framework, ADR 215
//! slice 3.
//!
//! # What this provides
//!
//! The original per-session daemon↔session channels had three bespoke
//! admission postures:
//!
//! - the LLM lane (`session_proxy`) gates with the full Door-1
//!   **leaf-exact pid pin** + pid-reuse-immunity + optional binary attestation;
//! - the SSH bridge (`ember_broker::ssh_agent_bridge`) used to gate with a
//!   bare `expected_peer_uid` check (ADR 214 F1 fallback — strictly weaker
//!   than leaf-pin, and explicitly the place where the per-issuee binding
//!   deferred by ADR 214 lands);
//! - the codex loopback-TCP lane had **no kernel gate at all** —
//!   credential-safe by construction (strict endpoint + server-side cred
//!   resolution + upstream pin), but not an admission policy.
//!
//! Same trust boundary, three postures. ADR 215 §3 named this as one of the
//! consolidation targets and prescribes **one framework** built from the
//! kernel primitives (`SO_PEERCRED` / `LOCAL_PEERTOKEN`, pid-reuse-immunity via
//! pidversion or `/proc` start-time, optional binary attestation) plus a
//! **declared admission policy per lane** ([`AdmissionPolicy`]).
//!
//! # What slice 3 ships
//!
//! This module is the **gate framework primitives + admission policy enum +
//! the pure-logic decision function**. The existing `session_proxy`
//! `evaluate_primary_gate` is now a thin wrapper that maps its
//! `(bound_uid, expected_leaf, bound_version)` inputs onto the
//! [`AdmissionPolicy::LeafExact`] arm of [`evaluate_admission`], so the LLM
//! lane rides the framework.
//!
//! The SSH bridge now injects an evaluator backed by
//! [`AdmissionPolicy::OwnerUid`] (`endpoint_gate_ssh_f1_wired`) instead of
//! carrying its own uid comparison. The honest graduation target remains
//! [`AdmissionPolicy::LeafSubtree`] once the ADR 214 F1 descendant-walk
//! primitive is settled.
//!
//! The codex loopback-TCP lane now carries a named
//! [`AdmissionPolicy::OwnerUid`] posture with a loud
//! `codex-loopback-no-kernel-attestation` audit event on every accepted
//! connection (`endpoint_gate_codex_owner_uid_named`). This does not change
//! the residual same-uid ephemeral-port spend risk; it retires the unnamed
//! no-gate exception.
//!
//! # Composition with `ARCH-AGENT-EGRESS-GATING-DEFAULT`
//!
//! `ARCH-AGENT-EGRESS-GATING-DEFAULT` makes `ember-proxy` the default egress
//! gate for in-container agents. That gate's host edge is **one per-session
//! endpoint** in the §1 ADR-215 sense, so it rides the same admission
//! framework — for the container case the policy is
//! [`AdmissionPolicy::CertSan`] (persona+container SAN cross-check, ADR
//! 154/173). `endpoint_gate_egress_default_composed` implements the ASN.1 SAN
//! extraction and pure decision; the live mTLS egress listener bind remains a
//! future hook because the separate `ember-proxy` crate is not present on
//! `origin/main`.
//!
//! # Why fold the existing leaf-exact gate into this framework
//!
//! The framework is **not new machinery** — it is the rename of the LLM
//! lane's `evaluate_primary_gate` into a shape every other lane can call
//! the same way. Two consequences:
//!
//! 1. The existing test surface in `session_proxy::tests` continues to pass
//!    (those tests cover the `LeafExact` arm in the new framework's terms),
//!    so the framework's correctness on the LLM lane is anchored to live tests
//!    from day one.
//! 2. Lane integrations plug into one decision function instead of duplicating
//!    uid-match / pid-pin / reuse-immunity / cert-SAN arms. Net: 3 bespoke
//!    gates → 1 framework with declared policies.

use std::fmt;

use core_crypto::ca::{SpiffeUri, parse_spiffe_uri_container};
use x509_parser::prelude::FromDer;

/// Kernel-attested identity of the peer of a per-session endpoint, read via
/// the host's primitive (`LOCAL_PEERTOKEN` on macOS / `SO_PEERCRED` + `/proc`
/// start-time on Linux).
///
/// This is the *primitive* — independent of the admission policy that will
/// consume it. Each lane reads it from whatever socket type it owns
/// (`UnixStream::peer_cred` on the SSH bridge; `getsockopt(LOCAL_PEERTOKEN)`
/// on the LLM lane) and feeds the same struct into [`evaluate_admission`].
///
/// `version` is `None` only when the reuse-immunity anchor could not be read
/// (macOS pidversion / Linux start-time); the gate then falls back to a
/// pid-only binding (degraded — a recycled pid is no longer distinguishable —
/// but uid-match + leaf-pin where applicable still hold).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub uid: u32,
    pub pid: i32,
    pub version: Option<u64>,
    /// DER-encoded peer client certificate for the container mTLS edge. Host
    /// peercred lanes leave this empty; [`AdmissionPolicy::CertSan`] is the
    /// only arm that consumes it.
    pub cert_der: Option<Vec<u8>>,
}

impl PeerIdentity {
    pub fn host(uid: u32, pid: i32, version: Option<u64>) -> Self {
        Self {
            uid,
            pid,
            version,
            cert_der: None,
        }
    }

    pub fn cert_san(cert_der: Vec<u8>) -> Self {
        Self {
            uid: 0,
            pid: 1,
            version: None,
            cert_der: Some(cert_der),
        }
    }
}

/// The admission policy declared by a lane at endpoint-bind time. The lane's
/// kernel-attested [`PeerIdentity`] is checked against this policy by
/// [`evaluate_admission`].
///
/// Per ADR 215 §3, the four policy variants are:
///
/// - **`LeafExact`** — the connecting pid must equal the launcher-reported
///   harness leaf pid (Door-1 leaf-pin). The strictest host-side gate — used
///   by the LLM lane. Rejects a same-uid sibling or a compromised in-tree
///   subagent that spins up its own harness pointed at the socket.
/// - **`LeafSubtree`** — the connecting pid must be a descendant of the
///   pinned launcher process tree. Used by the SSH/git lane: the connecting
///   client is a `git`/`ssh` child of the harness, not the leaf itself.
///   Weaker than `LeafExact` because process-tree membership is race-prone,
///   but strictly stronger than uid-only — and the honest home for the F1
///   SSH gate.
/// - **`OwnerUid`** — uid match only. The dev0 floor; the **explicit**
///   fallback, not an accident. Used today by:
///   - the SSH bridge (ADR 214 F1) — until the per-issuee binding lands as
///     `LeafSubtree`,
///   - the codex no-gate exception (loopback-TCP cannot read peer-cred for a
///     non-root daemon — the gate degenerates to `OwnerUid` *in name* with a
///     loud audit; security comes from the credential-safe-by-construction
///     arm, not this admission policy).
/// - **`CertSan`** — container edge: the SPIFFE SAN on the per-spawn mTLS
///   client cert must cross-check the bound persona+container (ADR 154/173).
///   The container-equivalent of the host `LeafExact` policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionPolicy {
    /// Strictest host gate: leaf-exact pid pin (LLM lane today).
    ///
    /// - `bound_uid` — uid captured at `register_session`.
    /// - `expected_leaf` — launcher-reported harness leaf pid (`0` = not
    ///   reported yet → fail closed).
    /// - `bound_version` — reuse-immunity anchor captured on the session's
    ///   first admitted connection, or `None` if this is the first.
    LeafExact {
        bound_uid: u32,
        expected_leaf: u32,
        bound_version: Option<u64>,
    },
    /// Pid-tree containment (SSH/git lane target — the honest home for ADR
    /// 214 F1 per-issuee binding). The connecting pid must be a descendant of
    /// `launcher_pid`. Today's SSH bridge delegates through the framework on
    /// the weaker `OwnerUid` floor; this arm is the documented graduation path.
    LeafSubtree {
        bound_uid: u32,
        launcher_pid: u32,
        bound_version: Option<u64>,
    },
    /// dev0 floor: uid match only. Explicit, audited, named as a policy — not
    /// an oversight.
    OwnerUid { bound_uid: u32 },
    /// Container edge: SPIFFE SAN cross-check. The peer-cred plumbing here is
    /// not the kernel primitive; the cert SAN is what's load-bearing.
    /// `expected_san` is the canonical "persona|container" string the bridge
    /// expected at register time.
    CertSan { expected_san: String },
}

impl fmt::Display for AdmissionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdmissionPolicy::LeafExact { .. } => f.write_str("leaf-exact"),
            AdmissionPolicy::LeafSubtree { .. } => f.write_str("leaf-subtree"),
            AdmissionPolicy::OwnerUid { .. } => f.write_str("owner-uid"),
            AdmissionPolicy::CertSan { .. } => f.write_str("cert-san"),
        }
    }
}

/// Why an admission attempt was rejected. Names the arm + the relevant
/// observed-vs-expected values so the reason is both loggable and unit-
/// testable without a real socket / second uid on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionReject {
    /// Connecting peer's uid did not match the bound uid. Common to every
    /// policy variant — the uid arm runs first.
    UidMismatch { expected: u32, actual: u32 },
    /// Non-positive / invalid peer pid (kernel returned something we can't
    /// reason about — fail closed).
    InvalidPid { pid: i32 },
    /// `LeafExact` only — the launcher has not yet reported the harness leaf
    /// pid, so there is nothing to pin against. The launcher reports it
    /// right after spawn; an early connection is dropped and the client
    /// retries.
    LeafUnreported { pid: i32 },
    /// `LeafExact` only — the connecting pid is not the launcher-reported
    /// harness leaf.
    LeafPidMismatch { pid: i32, expected_leaf: u32 },
    /// `LeafSubtree` only — the connecting pid is not a descendant of the
    /// pinned launcher process. This PR carries the variant for callers to
    /// pattern-match on; the actual descendant walk is wired in the SSH F1
    /// rewire follow-up so we don't add cross-uid `proc_pidinfo` reads here
    /// before the architecture for the walk is settled (ADR 197 amendment
    /// notes the macOS non-root cross-uid hazard).
    NotInLeafSubtree { pid: i32, launcher_pid: u32 },
    /// Reuse-immunity anchor differs from the one captured on the session's
    /// first admitted connection — the pid was recycled by a different
    /// process. The macOS analogue of the Linux pidfd reaped-process signal.
    Recycled {
        pid: i32,
        bound_version: u64,
        actual_version: u64,
    },
    /// `CertSan` only — the expected bind string was not the canonical
    /// `persona|container` value captured at session bind time.
    CertSanExpectedMalformed { expected_san: String },
    /// `CertSan` only — the peer certificate was missing, malformed, or did
    /// not carry the required SPIFFE persona/container SAN pair.
    CertSanExtractFailed { reason: String },
    /// `CertSan` only — the cert's persona SAN did not match the bound
    /// persona.
    CertSanPersonaMismatch { expected: String, actual: String },
    /// `CertSan` only — the cert's container SAN did not match the bound
    /// container.
    CertSanContainerMismatch { expected: String, actual: String },
}

/// What [`evaluate_admission`] decided for an admitted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionAdmit {
    /// First connection on a session that pins a reuse-immunity anchor
    /// (`LeafExact` / `LeafSubtree`): the caller captures `peer.version` as
    /// the session's anchor for the rest of the session.
    CapturePidVersion(Option<u64>),
    /// A subsequent connection whose `(pid, version)` matched the captured
    /// binding, or an `OwnerUid`-policy admission (no anchor to capture).
    BoundMatch,
}

/// Pure decision for the kernel-attested gate arms — uid match first, then
/// the policy-specific arm, then the reuse-immunity anchor (where the policy
/// captures one).
///
/// No syscalls: every input is read by the caller (`peer` from each lane's
/// primitive socket read) so this is directly unit-testable without a real
/// socket or a second uid on the host.
///
/// # Invariants (asserted by the tests)
///
/// - `UidMismatch` always wins — the uid arm runs first under every policy.
/// - `LeafExact` with `expected_leaf == 0` fails closed (the launcher has
///   not reported a leaf — there is nothing to pin against).
/// - `OwnerUid` never inspects `peer.pid` (beyond the invalid-pid sanity
///   check) — it is uid-only by definition.
/// - `CertSan` parses the peer certificate SAN and checks the ADR 154/173
///   persona+container SPIFFE pair against the bound `persona|container`.
pub fn evaluate_admission(
    policy: &AdmissionPolicy,
    peer: PeerIdentity,
) -> Result<AdmissionAdmit, AdmissionReject> {
    // Arm 0: invalid pid is a fail-closed checkpoint under every policy.
    if peer.pid <= 0 {
        return Err(AdmissionReject::InvalidPid { pid: peer.pid });
    }

    match policy {
        AdmissionPolicy::LeafExact {
            bound_uid,
            expected_leaf,
            bound_version,
        } => evaluate_leaf_exact(*bound_uid, *expected_leaf, *bound_version, peer),
        AdmissionPolicy::LeafSubtree {
            bound_uid,
            launcher_pid,
            bound_version,
        } => evaluate_leaf_subtree(*bound_uid, *launcher_pid, *bound_version, peer),
        AdmissionPolicy::OwnerUid { bound_uid } => evaluate_owner_uid(*bound_uid, peer),
        AdmissionPolicy::CertSan { expected_san } => evaluate_cert_san(expected_san, peer),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CertSanBinding {
    persona_id: String,
    container_id: String,
}

fn evaluate_cert_san(
    expected_san: &str,
    peer: PeerIdentity,
) -> Result<AdmissionAdmit, AdmissionReject> {
    let expected = parse_expected_cert_san(expected_san)?;
    let cert_der =
        peer.cert_der
            .as_deref()
            .ok_or_else(|| AdmissionReject::CertSanExtractFailed {
                reason: "missing peer client cert".to_string(),
            })?;
    let actual = extract_cert_san_binding(cert_der)?;

    if actual.persona_id != expected.persona_id {
        return Err(AdmissionReject::CertSanPersonaMismatch {
            expected: expected.persona_id,
            actual: actual.persona_id,
        });
    }
    if actual.container_id != expected.container_id {
        return Err(AdmissionReject::CertSanContainerMismatch {
            expected: expected.container_id,
            actual: actual.container_id,
        });
    }
    Ok(AdmissionAdmit::BoundMatch)
}

fn parse_expected_cert_san(expected_san: &str) -> Result<CertSanBinding, AdmissionReject> {
    let mut parts = expected_san.split('|');
    let persona_id = parts.next().unwrap_or_default();
    let container_id = parts.next().unwrap_or_default();
    if persona_id.is_empty() || container_id.is_empty() || parts.next().is_some() {
        return Err(AdmissionReject::CertSanExpectedMalformed {
            expected_san: expected_san.to_string(),
        });
    }
    if parse_short_persona_san(&format!("spiffe://emberd/persona/{persona_id}")).as_deref()
        != Some(persona_id)
    {
        return Err(AdmissionReject::CertSanExpectedMalformed {
            expected_san: expected_san.to_string(),
        });
    }
    match parse_spiffe_uri_container(&format!("spiffe://emberd/container/{container_id}")) {
        Ok(SpiffeUri::Container { container_ref }) if container_ref == container_id => {}
        _ => {
            return Err(AdmissionReject::CertSanExpectedMalformed {
                expected_san: expected_san.to_string(),
            });
        }
    }
    Ok(CertSanBinding {
        persona_id: persona_id.to_string(),
        container_id: container_id.to_string(),
    })
}

fn parse_short_persona_san(uri: &str) -> Option<String> {
    let persona = uri.strip_prefix("spiffe://emberd/persona/")?;
    if persona.contains('/') || !valid_persona_label(persona) {
        return None;
    }
    Some(persona.to_string())
}

fn valid_persona_label(label: &str) -> bool {
    let mut chars = label.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    let mut len = 1usize;
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return false;
        }
        len += 1;
    }
    len <= 63
}

fn extract_cert_san_binding(cert_der: &[u8]) -> Result<CertSanBinding, AdmissionReject> {
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der).map_err(|e| {
        AdmissionReject::CertSanExtractFailed {
            reason: format!("parse client cert: {e}"),
        }
    })?;
    let san = cert
        .subject_alternative_name()
        .map_err(|e| AdmissionReject::CertSanExtractFailed {
            reason: format!("parse SAN extension: {e}"),
        })?
        .ok_or_else(|| AdmissionReject::CertSanExtractFailed {
            reason: "missing SAN extension".to_string(),
        })?;

    let mut persona_id = None;
    let mut container_id = None;

    for gn in &san.value.general_names {
        let x509_parser::extensions::GeneralName::URI(uri) = gn else {
            continue;
        };

        if let Some(persona) = parse_short_persona_san(uri) {
            persona_id = Some(persona);
            continue;
        }

        match parse_spiffe_uri_container(uri) {
            Ok(SpiffeUri::Persona { persona, .. }) => {
                persona_id = Some(persona);
            }
            Ok(SpiffeUri::Container { container_ref }) => {
                container_id = Some(container_ref);
            }
            Err(_) => {}
        }
    }

    let persona_id = persona_id.ok_or_else(|| AdmissionReject::CertSanExtractFailed {
        reason: "missing spiffe://emberd/persona/<persona> SAN".to_string(),
    })?;
    let container_id = container_id.ok_or_else(|| AdmissionReject::CertSanExtractFailed {
        reason: "missing spiffe://emberd/container/<container> SAN".to_string(),
    })?;

    Ok(CertSanBinding {
        persona_id,
        container_id,
    })
}

/// `LeafExact` arm — uid match + Door-1 leaf-pin + reuse-immunity. This is
/// the policy the LLM lane has shipped since P22-S2; the existing
/// `session_proxy::evaluate_primary_gate` is now a thin wrapper that builds
/// this policy and calls [`evaluate_admission`].
fn evaluate_leaf_exact(
    bound_uid: u32,
    expected_leaf: u32,
    bound_version: Option<u64>,
    peer: PeerIdentity,
) -> Result<AdmissionAdmit, AdmissionReject> {
    // 1. Kernel-attested uid match.
    if peer.uid != bound_uid {
        return Err(AdmissionReject::UidMismatch {
            expected: bound_uid,
            actual: peer.uid,
        });
    }
    // 2. Door-1 leaf-pin.
    if expected_leaf == 0 {
        return Err(AdmissionReject::LeafUnreported { pid: peer.pid });
    }
    if peer.pid as u32 != expected_leaf {
        return Err(AdmissionReject::LeafPidMismatch {
            pid: peer.pid,
            expected_leaf,
        });
    }
    // 3. Reuse-immunity.
    bind_or_check_version(bound_version, peer)
}

/// `LeafSubtree` arm. This PR carries the variant + shape; the actual
/// descendant walk is wired in the SSH F1 rewire follow-up so the cross-uid
/// `proc_pidinfo` hazard called out in the ADR 197 amendment is dealt with
/// in one place at wire time. Today the arm rejects any non-leaf pid as
/// `NotInLeafSubtree` — strictly stronger than today's SSH bridge which
/// admits any same-uid pid.
fn evaluate_leaf_subtree(
    bound_uid: u32,
    launcher_pid: u32,
    bound_version: Option<u64>,
    peer: PeerIdentity,
) -> Result<AdmissionAdmit, AdmissionReject> {
    if peer.uid != bound_uid {
        return Err(AdmissionReject::UidMismatch {
            expected: bound_uid,
            actual: peer.uid,
        });
    }
    // The launcher itself is in its own subtree. Any other pid in this PR is
    // not admitted — the descendant-walk wire lands in the SSH F1 rewire.
    if peer.pid as u32 == launcher_pid {
        return bind_or_check_version(bound_version, peer);
    }
    Err(AdmissionReject::NotInLeafSubtree {
        pid: peer.pid,
        launcher_pid,
    })
}

/// `OwnerUid` arm — uid match only. Used by the SSH bridge today and the
/// codex no-gate exception's degenerate "admission policy". No anchor capture
/// because there is no per-pid binding to anchor against.
fn evaluate_owner_uid(
    bound_uid: u32,
    peer: PeerIdentity,
) -> Result<AdmissionAdmit, AdmissionReject> {
    if peer.uid != bound_uid {
        return Err(AdmissionReject::UidMismatch {
            expected: bound_uid,
            actual: peer.uid,
        });
    }
    Ok(AdmissionAdmit::BoundMatch)
}

/// Shared reuse-immunity arm: bind on first connection, then require match.
/// Used by `LeafExact` and `LeafSubtree`; not used by `OwnerUid`.
fn bind_or_check_version(
    bound_version: Option<u64>,
    peer: PeerIdentity,
) -> Result<AdmissionAdmit, AdmissionReject> {
    match bound_version {
        None => Ok(AdmissionAdmit::CapturePidVersion(peer.version)),
        Some(bound) => match peer.version {
            None => Err(AdmissionReject::Recycled {
                pid: peer.pid,
                bound_version: bound,
                actual_version: 0,
            }),
            Some(v) if v == bound => Ok(AdmissionAdmit::BoundMatch),
            Some(v) => Err(AdmissionReject::Recycled {
                pid: peer.pid,
                bound_version: bound,
                actual_version: v,
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32, pid: i32, version: Option<u64>) -> PeerIdentity {
        PeerIdentity::host(uid, pid, version)
    }

    fn bridge_client_cert_der(persona: &str, container: &str) -> Vec<u8> {
        let ca = crate::trust::bridge_ca::BridgeCa::mint();
        let (cert_pem, _key_pem) = ca
            .sign_client_cert(
                persona,
                Some(container),
                std::time::Duration::from_secs(3600),
            )
            .expect("bridge client cert mint");
        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).expect("PEM parses");
        pem.contents.to_vec()
    }

    // ---- Invalid pid is a cross-policy fail-closed checkpoint ----

    #[test]
    fn invalid_pid_rejects_under_every_policy() {
        let p = peer(1000, 0, Some(7));
        let policies = [
            AdmissionPolicy::LeafExact {
                bound_uid: 1000,
                expected_leaf: 0,
                bound_version: None,
            },
            AdmissionPolicy::LeafSubtree {
                bound_uid: 1000,
                launcher_pid: 1,
                bound_version: None,
            },
            AdmissionPolicy::OwnerUid { bound_uid: 1000 },
            AdmissionPolicy::CertSan {
                expected_san: "ignored".to_string(),
            },
        ];
        for policy in &policies {
            assert_eq!(
                evaluate_admission(policy, p.clone()),
                Err(AdmissionReject::InvalidPid { pid: 0 }),
                "policy {} should reject invalid pid",
                policy
            );
        }
    }

    // ---- Uid mismatch wins under every policy that checks uid ----

    #[test]
    fn uid_mismatch_wins_for_leaf_exact() {
        let r = evaluate_admission(
            &AdmissionPolicy::LeafExact {
                bound_uid: 1000,
                expected_leaf: 4242,
                bound_version: None,
            },
            peer(1001, 4242, Some(7)),
        );
        assert_eq!(
            r,
            Err(AdmissionReject::UidMismatch {
                expected: 1000,
                actual: 1001,
            })
        );
    }

    #[test]
    fn uid_mismatch_wins_for_leaf_subtree() {
        let r = evaluate_admission(
            &AdmissionPolicy::LeafSubtree {
                bound_uid: 1000,
                launcher_pid: 4242,
                bound_version: None,
            },
            peer(1001, 4242, Some(7)),
        );
        assert_eq!(
            r,
            Err(AdmissionReject::UidMismatch {
                expected: 1000,
                actual: 1001,
            })
        );
    }

    #[test]
    fn uid_mismatch_wins_for_owner_uid() {
        let r = evaluate_admission(
            &AdmissionPolicy::OwnerUid { bound_uid: 1000 },
            peer(1001, 4242, None),
        );
        assert_eq!(
            r,
            Err(AdmissionReject::UidMismatch {
                expected: 1000,
                actual: 1001,
            })
        );
    }

    // ---- LeafExact arm ----

    #[test]
    fn leaf_exact_fails_closed_when_leaf_unreported() {
        let r = evaluate_admission(
            &AdmissionPolicy::LeafExact {
                bound_uid: 1000,
                expected_leaf: 0,
                bound_version: None,
            },
            peer(1000, 4242, Some(7)),
        );
        assert_eq!(r, Err(AdmissionReject::LeafUnreported { pid: 4242 }));
    }

    #[test]
    fn leaf_exact_rejects_non_leaf_pid() {
        let r = evaluate_admission(
            &AdmissionPolicy::LeafExact {
                bound_uid: 1000,
                expected_leaf: 4242,
                bound_version: None,
            },
            peer(1000, 5555, Some(7)),
        );
        assert_eq!(
            r,
            Err(AdmissionReject::LeafPidMismatch {
                pid: 5555,
                expected_leaf: 4242,
            })
        );
    }

    #[test]
    fn leaf_exact_first_connection_captures_anchor() {
        let r = evaluate_admission(
            &AdmissionPolicy::LeafExact {
                bound_uid: 1000,
                expected_leaf: 4242,
                bound_version: None,
            },
            peer(1000, 4242, Some(99)),
        );
        assert_eq!(r, Ok(AdmissionAdmit::CapturePidVersion(Some(99))));
    }

    #[test]
    fn leaf_exact_subsequent_match_admits() {
        let r = evaluate_admission(
            &AdmissionPolicy::LeafExact {
                bound_uid: 1000,
                expected_leaf: 4242,
                bound_version: Some(99),
            },
            peer(1000, 4242, Some(99)),
        );
        assert_eq!(r, Ok(AdmissionAdmit::BoundMatch));
    }

    #[test]
    fn leaf_exact_rejects_recycled_pid() {
        let r = evaluate_admission(
            &AdmissionPolicy::LeafExact {
                bound_uid: 1000,
                expected_leaf: 4242,
                bound_version: Some(99),
            },
            peer(1000, 4242, Some(100)),
        );
        assert_eq!(
            r,
            Err(AdmissionReject::Recycled {
                pid: 4242,
                bound_version: 99,
                actual_version: 100,
            })
        );
    }

    #[test]
    fn leaf_exact_anchor_missing_when_bound_fails_closed() {
        let r = evaluate_admission(
            &AdmissionPolicy::LeafExact {
                bound_uid: 1000,
                expected_leaf: 4242,
                bound_version: Some(99),
            },
            peer(1000, 4242, None),
        );
        assert_eq!(
            r,
            Err(AdmissionReject::Recycled {
                pid: 4242,
                bound_version: 99,
                actual_version: 0,
            })
        );
    }

    // ---- LeafSubtree arm (future descendant-walk graduation path) ----

    #[test]
    fn leaf_subtree_admits_launcher_pid_itself() {
        // The launcher is trivially in its own subtree (the root). The actual
        // descendant walk wire lands in the SSH F1 follow-up; this confirms
        // the trivial case is honored.
        let r = evaluate_admission(
            &AdmissionPolicy::LeafSubtree {
                bound_uid: 1000,
                launcher_pid: 4242,
                bound_version: None,
            },
            peer(1000, 4242, Some(7)),
        );
        assert_eq!(r, Ok(AdmissionAdmit::CapturePidVersion(Some(7))));
    }

    #[test]
    fn leaf_subtree_rejects_non_launcher_pid_until_wired() {
        let r = evaluate_admission(
            &AdmissionPolicy::LeafSubtree {
                bound_uid: 1000,
                launcher_pid: 4242,
                bound_version: None,
            },
            peer(1000, 9999, None),
        );
        assert_eq!(
            r,
            Err(AdmissionReject::NotInLeafSubtree {
                pid: 9999,
                launcher_pid: 4242,
            })
        );
    }

    // ---- OwnerUid arm ----

    #[test]
    fn owner_uid_admits_matching_uid_regardless_of_pid() {
        // OwnerUid does NOT pin a pid; any positive pid with the right uid
        // admits. This is the explicit dev0 floor.
        let r = evaluate_admission(
            &AdmissionPolicy::OwnerUid { bound_uid: 1000 },
            peer(1000, 12345, None),
        );
        assert_eq!(r, Ok(AdmissionAdmit::BoundMatch));
    }

    #[test]
    fn owner_uid_admit_does_not_capture_anchor() {
        // OwnerUid never captures a pid-version anchor — there is no per-pid
        // binding to anchor against.
        let r = evaluate_admission(
            &AdmissionPolicy::OwnerUid { bound_uid: 1000 },
            peer(1000, 12345, Some(42)),
        );
        assert_eq!(r, Ok(AdmissionAdmit::BoundMatch));
    }

    // ---- CertSan arm ----

    #[test]
    fn cert_san_admits_persona_and_container_match() {
        let cert_der = bridge_client_cert_der("alice", "ctr-abc123");
        let r = evaluate_admission(
            &AdmissionPolicy::CertSan {
                expected_san: "alice|ctr-abc123".to_string(),
            },
            PeerIdentity::cert_san(cert_der),
        );
        assert_eq!(r, Ok(AdmissionAdmit::BoundMatch));
    }

    #[test]
    fn cert_san_rejects_persona_mismatch() {
        let cert_der = bridge_client_cert_der("alice", "ctr-abc123");
        let r = evaluate_admission(
            &AdmissionPolicy::CertSan {
                expected_san: "bob|ctr-abc123".to_string(),
            },
            PeerIdentity::cert_san(cert_der),
        );
        assert_eq!(
            r,
            Err(AdmissionReject::CertSanPersonaMismatch {
                expected: "bob".to_string(),
                actual: "alice".to_string(),
            })
        );
    }

    #[test]
    fn cert_san_rejects_container_mismatch() {
        let cert_der = bridge_client_cert_der("alice", "ctr-abc123");
        let r = evaluate_admission(
            &AdmissionPolicy::CertSan {
                expected_san: "alice|ctr-other".to_string(),
            },
            PeerIdentity::cert_san(cert_der),
        );
        assert_eq!(
            r,
            Err(AdmissionReject::CertSanContainerMismatch {
                expected: "ctr-other".to_string(),
                actual: "ctr-abc123".to_string(),
            })
        );
    }

    #[test]
    fn cert_san_rejects_cert_extract_failure() {
        let r = evaluate_admission(
            &AdmissionPolicy::CertSan {
                expected_san: "alice|ctr-abc123".to_string(),
            },
            PeerIdentity::cert_san(b"not a der cert".to_vec()),
        );
        match r {
            Err(AdmissionReject::CertSanExtractFailed { reason }) => {
                assert!(
                    reason.contains("parse client cert"),
                    "extract failure should name parse stage: {reason}"
                );
            }
            other => panic!("expected cert extract failure, got {other:?}"),
        }
    }

    #[test]
    fn cert_san_rejects_malformed_expected_binding() {
        let cert_der = bridge_client_cert_der("alice", "ctr-abc123");
        let r = evaluate_admission(
            &AdmissionPolicy::CertSan {
                expected_san: "Alice|ctr-abc123".to_string(),
            },
            PeerIdentity::cert_san(cert_der),
        );
        assert_eq!(
            r,
            Err(AdmissionReject::CertSanExpectedMalformed {
                expected_san: "Alice|ctr-abc123".to_string(),
            })
        );
    }

    // ---- Display ----

    #[test]
    fn admission_policy_display_matches_adr215_lane_names() {
        // The ADR-215 §3 lane names — keep them stable for log/audit search.
        assert_eq!(
            AdmissionPolicy::LeafExact {
                bound_uid: 0,
                expected_leaf: 0,
                bound_version: None,
            }
            .to_string(),
            "leaf-exact"
        );
        assert_eq!(
            AdmissionPolicy::LeafSubtree {
                bound_uid: 0,
                launcher_pid: 0,
                bound_version: None,
            }
            .to_string(),
            "leaf-subtree"
        );
        assert_eq!(
            AdmissionPolicy::OwnerUid { bound_uid: 0 }.to_string(),
            "owner-uid"
        );
        assert_eq!(
            AdmissionPolicy::CertSan {
                expected_san: "x".to_string(),
            }
            .to_string(),
            "cert-san"
        );
    }
}
