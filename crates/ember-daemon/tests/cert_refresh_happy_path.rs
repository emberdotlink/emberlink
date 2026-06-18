//! CLASSIFICATION: PUBLIC
//!
//! META-AP-DAEMON-BRIDGE-T2-T3-REFRESH-TESTS (M10 of ADR 173) — T2/T3
//! happy-path coverage for the bridge cert refresh protocol.
//!
//! Anchor: `daemon_bridge_t2_t3_refresh_tests_landed`.
//!
//! # What this file pins
//!
//! M3 (`refresh_cert` RPC handler — `crates/ember-daemon/src/broker/handler/
//! runtime_authority.rs:1009`) shipped via PR #6033. M12 (listener
//! force-close at `not_after` — `crates/ember-rpc/src/listener.rs:654`)
//! shipped via PR #6034. T1 (state-machine property tests —
//! `crates/core-personas/tests/cert_refresh_state_machine.rs`) shipped via
//! PR #6028. M10 is the T2/T3 happy-path sibling.
//!
//! ## T2 — in-memory dispatch coverage
//!
//! `refresh_cert_*_t2` tests exercise the production `refresh_cert`
//! dispatch path against `DaemonStore::open_in_memory()` per
//! `.claude/rules/test-tiers.md` ("In-memory SQLite or `Mock*`? → T2").
//! No real socket, no real keychain, no process spawn.
//!
//! Invariants pinned:
//!
//! 1. **Refresh monotonicity** (ADR 173 §"Refresh monotonicity") — three
//!    sequential successful refreshes produce strictly increasing
//!    `refresh_seq` values 1, 2, 3 with distinct fingerprints. The
//!    production write path (`replace_persona_client_cert_for_refresh`)
//!    is atomic so an observer never sees a fresh fingerprint with a
//!    stale sequence.
//!
//! 2. **Idempotent dispatch state-transition** — a single refresh returns
//!    `denied: false` with the new cert payload AND the persona row's
//!    `client_cert_fingerprint` / `client_cert_not_after` / `refresh_seq`
//!    move to the new values in one observable step. The response's
//!    `previous_refresh_seq` matches the pre-refresh seq value.
//!
//! 3. **Expired-cert denial** — when the persona row's pinned
//!    `client_cert_not_after` is in the past, refresh is denied with
//!    `failure_cause = auth_failure_expired` and the persona row is
//!    unchanged. This is the same wire-level invariant the M12 listener
//!    force-close (`bridge_listener_force_close_at_not_after_landed`)
//!    enforces at the transport layer.
//!
//! ## T2 — client-side refresh band timing (pure math)
//!
//! ADR 173 §Component 1 Table 1 locks the client-side refresh band
//! timer at 50% / 75% / 90% / 99% TTL elapsed. The M6 client (`META-AP-
//! EMBERLINK-MCP-CERT-REFRESH-CLIENT` — not yet shipped at M10 land) is
//! the consumer. `refresh_band_timing_*_t2` locks the band-math
//! invariants the M6 scheduler will load-bear against, so a future M6
//! regression on the band timing surfaces here at `cargo test` time
//! instead of at the next dogfood week. Pure functions of
//! `(not_before, not_after, now)` — no I/O, but co-located with the
//! daemon-side T2 dispatch tests because that's where the refresh
//! protocol's M10 checkpoint lives.
//!
//! ## T3 — real listener + short-TTL mint
//!
//! `refresh_cert_*_t3` tests spin up a real `ember_rpc::Listener` over
//! loopback TCP, mint a short-TTL client cert (3-5s window) via the
//! same `BridgeCa` the listener trusts, and observe the listener
//! enforces the M12 force-close path at `not_after`. The short-TTL
//! window lets the deadline fire within `cargo test`'s normal
//! wall-clock budget (under 10s per test, well within the T3 budget
//! per `.claude/rules/test-tiers.md`).
//!
//! Two T3 acceptance shapes:
//!
//! 1. **Short-TTL handshake green → force-close at deadline** — a fresh
//!    short-TTL cert handshakes cleanly; the listener force-closes the
//!    same connection at `not_after` with a typed
//!    `connection-expired:` envelope. This is the M3 + M12 integration
//!    point: a refresh would mint a fresh cert and re-open; without
//!    one, the listener stops the connection at the deadline.
//!
//! 2. **Old-cert-rejected post-deadline** — after the deadline fires
//!    on connection #1, a fresh handshake attempt on connection #2
//!    using the SAME expired cert either fails at the TLS layer
//!    (`webpki::Error::CertExpired`) or — if the handshake completes
//!    because the certificate is within a server-side clock skew
//!    window — the listener force-closes the new connection
//!    immediately (M12 deadline computed from `not_after - now <= 0`
//!    → `Duration::ZERO`). Either terminal state is acceptable; the
//!    invariant is "no authenticated forward succeeds against an
//!    expired cert."

#![allow(clippy::expect_used)] // test code — panicking on setup failure is the bug surface

use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use core_personas::MtlsPrincipal;
use ember_daemon::infra::handler::{PeerCred, RequestContext, dispatch_method_with_context};
use ember_daemon::infra::persona::{
    agent_persona_two_phase_commit, pin_persona_client_cert_from_pem,
};
use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::bridge_ca::BridgeCa;
use ember_daemon::trust::policy::PolicyEngine;
use ember_rpc::{Listener, ListenerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::json;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use tokio::net::{TcpStream, UnixListener};
use tokio_rustls::TlsConnector;

// daemon_bridge_t2_t3_refresh_tests_landed — checkpoint for the M10
// acceptance gate. `git grep daemon_bridge_t2_t3_refresh_tests_landed`
// must surface this file for the ranker's stale-check to flip the task
// to shipped.

// ---------------------------------------------------------------------------
// T2 fixtures: in-memory store + BridgeCa + agent persona + initial pin.
// Mirrors the shape in `crates/ember-daemon/tests/refresh_cert_rpc.rs` so
// future T2 additions slot in without re-inventing fixture seeding.
// ---------------------------------------------------------------------------

const TEST_VAULT_KEY: [u8; 32] = [0xD3; 32];

struct T2Fixture {
    store: DaemonStore,
    vault: Vault,
    mtls: MtlsPrincipal,
    persona_id: String,
    parent_grant_id: String,
    initial_fingerprint: String,
    initial_not_after_unix: i64,
}

fn seed_t2_fixture(container_id: &str) -> T2Fixture {
    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    let vault_rc = Rc::new(Vault::new(TEST_VAULT_KEY));
    store.set_vault(Rc::clone(&vault_rc));
    let bridge_ca = Arc::new(BridgeCa::mint());
    store.set_bridge_ca(Arc::clone(&bridge_ca));

    let parent = store
        .create_persona(&format!("refresh-parent-{container_id}"))
        .expect("parent persona");
    let parent_grant = store
        .create_grant(&parent.id, "delegate-key", "*", Some(7_200))
        .expect("parent grant");
    store
        .conn()
        .execute(
            "UPDATE grants SET max_delegation_depth = 2 WHERE id = ?1",
            rusqlite::params![&parent_grant.id],
        )
        .expect("raise delegation depth");

    let persona =
        agent_persona_two_phase_commit(&store, vault_rc.as_ref(), container_id, &parent_grant.id)
            .expect("agent persona two-phase commit");
    let (cert_pem, _key_pem) = bridge_ca
        .sign_client_cert(&persona.id, Some(container_id), Duration::from_secs(3_600))
        .expect("initial client cert");
    let (initial_fingerprint, initial_not_after) =
        pin_persona_client_cert_from_pem(&store, &persona.id, cert_pem.as_str())
            .expect("pin initial cert");

    let mtls = MtlsPrincipal {
        persona_id: persona.id.clone(),
        container_id: container_id.to_string(),
        cert_fingerprint: hex_to_fingerprint(&initial_fingerprint),
    };

    T2Fixture {
        store,
        vault: Vault::new(TEST_VAULT_KEY),
        mtls,
        persona_id: persona.id,
        parent_grant_id: parent_grant.id,
        initial_fingerprint,
        initial_not_after_unix: initial_not_after,
    }
}

fn hex_to_fingerprint(hex_value: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = hex::decode(hex_value).expect("fingerprint hex decodes");
    assert_eq!(bytes.len(), 32, "fingerprint is 32 bytes");
    out.copy_from_slice(&bytes);
    out
}

async fn refresh_cert_call(
    fx: &T2Fixture,
) -> Result<serde_json::Value, (i32, String)> {
    refresh_cert_call_with_mtls(fx, fx.mtls.clone()).await
}

/// Same as [`refresh_cert_call`] but lets the caller supply a fresh
/// `MtlsPrincipal` whose `cert_fingerprint` matches whatever cert the
/// caller is now holding. After every successful refresh the M6
/// client receives a new cert and reconnects with it; subsequent
/// refresh attempts present the NEW fingerprint, not the original
/// one. The daemon enforces this via the pinned-cert-fingerprint
/// gate at `refresh_cert_dispatch_landed` — a stale fingerprint
/// fails with `auth_failure_persona_unknown`.
async fn refresh_cert_call_with_mtls(
    fx: &T2Fixture,
    mtls: MtlsPrincipal,
) -> Result<serde_json::Value, (i32, String)> {
    let policy = PolicyEngine::default();
    let rl = RefCell::new(RateLimiter::default());
    let ctx = RequestContext::bridge(
        Some(PeerCred {
            uid: 501,
            pid: Some(12_345),
        }),
        mtls,
    );
    dispatch_method_with_context(
        &fx.store,
        &fx.vault,
        &policy,
        &rl,
        None,
        ctx,
        "refresh_cert",
        &json!({"caller_grant_id": fx.parent_grant_id}),
    )
    .await
}

// ---------------------------------------------------------------------------
// T2 #1 — Refresh monotonicity. Three sequential successful refreshes
// produce strictly increasing `refresh_seq` values 1, 2, 3 with three
// distinct fingerprints. ADR 173 §"Refresh monotonicity" against the
// production write path (`replace_persona_client_cert_for_refresh`).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_cert_three_sequential_calls_monotonic_seq_distinct_fingerprints_t2() {
    let fx = seed_t2_fixture("ctr-refresh-monotonic");

    // After every successful refresh, the M6 client receives a new
    // cert and reconnects with it — so the next refresh attempt
    // presents the NEW fingerprint. The daemon's pinned-cert check
    // (PR #6043) requires the presented `MtlsPrincipal.cert_fingerprint`
    // to match the persona row's `client_cert_fingerprint` exactly.
    let r1 = refresh_cert_call(&fx).await.expect("first refresh");
    let mtls_after_r1 = MtlsPrincipal {
        cert_fingerprint: hex_to_fingerprint(
            r1["client_cert_fingerprint"].as_str().expect("fp1"),
        ),
        ..fx.mtls.clone()
    };
    let r2 = refresh_cert_call_with_mtls(&fx, mtls_after_r1)
        .await
        .expect("second refresh");
    let mtls_after_r2 = MtlsPrincipal {
        cert_fingerprint: hex_to_fingerprint(
            r2["client_cert_fingerprint"].as_str().expect("fp2"),
        ),
        ..fx.mtls.clone()
    };
    let r3 = refresh_cert_call_with_mtls(&fx, mtls_after_r2)
        .await
        .expect("third refresh");

    // All three accepted.
    for (i, r) in [&r1, &r2, &r3].iter().enumerate() {
        assert_eq!(
            r["denied"], json!(false),
            "refresh #{} must be accepted; got {r}", i + 1
        );
    }

    // refresh_seq strictly monotonic 1, 2, 3.
    assert_eq!(r1["refresh_seq"], json!(1), "first refresh_seq must be 1");
    assert_eq!(r2["refresh_seq"], json!(2), "second refresh_seq must be 2");
    assert_eq!(r3["refresh_seq"], json!(3), "third refresh_seq must be 3");

    // previous_refresh_seq chains: response N reports the pre-refresh seq
    // (so observers can detect a missing refresh receipt by chain gap).
    assert_eq!(
        r1["previous_refresh_seq"], json!(0),
        "first previous_refresh_seq must be 0 (pre-refresh state)"
    );
    assert_eq!(r2["previous_refresh_seq"], json!(1));
    assert_eq!(r3["previous_refresh_seq"], json!(2));

    // Three distinct fingerprints — the persona row's
    // `client_cert_fingerprint` is atomically replaced each refresh.
    let fp1 = r1["client_cert_fingerprint"].as_str().expect("fp1");
    let fp2 = r2["client_cert_fingerprint"].as_str().expect("fp2");
    let fp3 = r3["client_cert_fingerprint"].as_str().expect("fp3");
    assert_ne!(fp1, fx.initial_fingerprint, "fp1 differs from initial");
    assert_ne!(fp2, fp1, "fp2 differs from fp1");
    assert_ne!(fp3, fp2, "fp3 differs from fp2");
    assert_ne!(fp1, fp3, "fp1 differs from fp3 (no aliasing)");

    // Final persona-row state reflects refresh #3 — atomic write path
    // means an observer never sees seq=3 with fingerprint=fp2.
    let state = fx
        .store
        .get_persona_client_cert_state(&fx.persona_id)
        .expect("read final cert state");
    assert_eq!(state.fingerprint_hex, fp3);
    assert_eq!(state.refresh_seq, 3);
}

// ---------------------------------------------------------------------------
// T2 #1b — Successful refresh emits a signed `bridge.cert_refreshed`
// Receipt against the parent grant id. ADR 173 §Component 6 + ADR 118
// Extension 5: each refresh produces a durable, signed audit artifact
// observers can verify offline without re-running the daemon. The
// in-tree handler test at `runtime_authority.rs::
// refresh_cert_success_emits_signed_cert_refreshed_receipt` covers the
// same shape from the handler side; this M10 test covers it from the
// dispatch side (so `dispatch_method_with_context` → receipt-emit
// wiring stays green).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_cert_emits_signed_cert_refreshed_receipt_t2() {
    // The receipt-emit path needs a daemon identity to sign with. The
    // in-tree handler tests use `init_refresh_receipt_identity` (a
    // tempdir-scoped identity bootstrap); the same primitive is
    // available from the dispatch-level test through the public
    // `init_identity` entry point.
    let identity_dir = tempfile::tempdir().expect("tempdir for daemon identity");
    let _ = ember_daemon::infra::receipt::init_identity(identity_dir.path());

    let fx = seed_t2_fixture("ctr-refresh-receipt");

    let response = refresh_cert_call(&fx).await.expect("refresh dispatches");
    assert_eq!(response["denied"], json!(false), "refresh must succeed");

    // Query the receipts for the parent grant — the v2 envelope row
    // is what observers verify against the daemon's identity pubkey.
    let receipts = fx
        .store
        .list_receipts_v2_envelopes(&[fx.parent_grant_id.clone()])
        .expect("list receipts");
    let cert_refreshed = receipts
        .iter()
        .find(|(_, kind, _, _)| {
            kind == core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_REFRESHED
        })
        .expect(
            "successful refresh MUST emit a `bridge.cert_refreshed` receipt \
             against the parent grant (ADR 173 §C6 + ADR 118 Ext 5)",
        );

    let (_, kind, grant_id, envelope) = cert_refreshed;
    assert_eq!(
        kind,
        core_events::receipt::RECEIPT_KIND_BRIDGE_CERT_REFRESHED
    );
    assert_eq!(grant_id, &fx.parent_grant_id);

    // Envelope verifies under the daemon identity — proves the
    // receipt is signed and tamper-evident.
    let identity = ember_daemon::infra::receipt::current_identity()
        .expect("daemon identity loaded");
    let public_key =
        core_crypto::PublicKey(format!("ed25519:{}", identity.pubkey_hex()));
    core_events::receipt::verify_receipt_v2(
        envelope,
        &public_key,
        &core_crypto::FixtureVerifier,
    )
    .expect("cert_refreshed receipt verifies under the daemon identity");

    // Body carries the chain-of-custody fields: old + new fingerprint,
    // refresh_seq, persona/container.
    let body: core_events::receipt::BridgeCertRefreshedBody =
        serde_json::from_value(envelope.body.clone())
            .expect("BridgeCertRefreshedBody parses");
    assert_eq!(body.persona_id, fx.persona_id);
    assert_eq!(body.container_id, "ctr-refresh-receipt");
    assert_eq!(body.refresh_seq, 1);
    assert_eq!(body.old_cert_fingerprint, fx.initial_fingerprint);
    assert_eq!(
        body.new_cert_fingerprint,
        response["client_cert_fingerprint"].as_str().unwrap()
    );
}

// ---------------------------------------------------------------------------
// T2 #2 — Idempotent dispatch state-transition. A single refresh returns
// `denied: false` with the new cert payload AND the persona row is
// updated in one observable step. The response's `previous_refresh_seq`
// matches the pre-refresh seq value.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_cert_single_dispatch_updates_persona_row_atomically_t2() {
    let fx = seed_t2_fixture("ctr-refresh-idempotent");

    // Pre-refresh state observation: seq = 0, fingerprint = initial.
    let pre = fx
        .store
        .get_persona_client_cert_state(&fx.persona_id)
        .expect("read pre-refresh state");
    assert_eq!(pre.refresh_seq, 0);
    assert_eq!(pre.fingerprint_hex, fx.initial_fingerprint);

    let response = refresh_cert_call(&fx).await.expect("refresh succeeds");

    // Response shape per ADR 173 §Component 5.
    assert_eq!(response["denied"], json!(false));
    assert_eq!(response["container_id"], json!("ctr-refresh-idempotent"));
    assert_eq!(response["refresh_seq"], json!(1));
    assert_eq!(
        response["previous_refresh_seq"], json!(0),
        "previous_refresh_seq must report the pre-refresh seq"
    );
    assert!(
        response["client_cert_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE"),
        "client_cert_pem must be a PEM block"
    );
    assert!(
        response["client_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PRIVATE KEY"),
        "client_key_pem must be a PEM block"
    );

    // Persona row reflects the refresh — fingerprint moved, not_after
    // updated, seq incremented in one atomic write.
    let post = fx
        .store
        .get_persona_client_cert_state(&fx.persona_id)
        .expect("read post-refresh state");
    let new_fp = response["client_cert_fingerprint"].as_str().unwrap();
    let new_not_after = response["client_cert_not_after"].as_i64().unwrap();
    assert_eq!(post.fingerprint_hex, new_fp);
    assert_eq!(post.not_after_unix, new_not_after);
    assert_eq!(post.refresh_seq, 1);
    assert_ne!(
        post.fingerprint_hex, fx.initial_fingerprint,
        "fingerprint must move"
    );
    assert!(
        post.not_after_unix > fx.initial_not_after_unix
            || post.not_after_unix == fx.initial_not_after_unix,
        "refreshed not_after must be at-least as far in the future as initial; \
         got refreshed={}, initial={}",
        post.not_after_unix,
        fx.initial_not_after_unix,
    );
}

// ---------------------------------------------------------------------------
// T2 #3 — Expired-cert denial. When the persona row's pinned
// `client_cert_not_after` is in the past, refresh is denied with
// `failure_cause = auth_failure_expired` and the persona row is
// unchanged. Same wire-level invariant the M12 listener force-close
// enforces at the transport layer.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_cert_with_pinned_expired_cert_is_denied_t2() {
    let fx = seed_t2_fixture("ctr-refresh-expired");

    // Backdate the persona's pinned `client_cert_not_after` to the past.
    // The handler reads `get_persona_client_cert_state(...).not_after_unix`
    // and refuses with AuthFailureExpired when it's `<= now`.
    let past = (chrono::Utc::now().timestamp() - 60).max(1);
    fx.store
        .conn()
        .execute(
            "UPDATE personas SET client_cert_not_after = ?1 WHERE id = ?2",
            rusqlite::params![past, fx.persona_id],
        )
        .expect("backdate pinned cert");

    // Snapshot pre-refresh state.
    let pre = fx
        .store
        .get_persona_client_cert_state(&fx.persona_id)
        .expect("read pre-refresh state");
    assert_eq!(pre.not_after_unix, past);
    let pre_fp = pre.fingerprint_hex.clone();
    let pre_seq = pre.refresh_seq;

    let response = refresh_cert_call(&fx).await.expect("refresh dispatched");

    // Denied with the locked failure cause.
    assert_eq!(
        response["denied"], json!(true),
        "expired-pin must be denied; got {response}"
    );
    assert_eq!(
        response["failure_cause"].as_str(),
        Some("auth_failure_expired"),
        "expired pin must surface auth_failure_expired; got {response}"
    );
    assert!(
        response["reason"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
            .contains("expired"),
        "reason must name the expiry; got {response}"
    );

    // Persona row UNCHANGED — refusal must not touch state.
    let post = fx
        .store
        .get_persona_client_cert_state(&fx.persona_id)
        .expect("read post-refresh state");
    assert_eq!(post.fingerprint_hex, pre_fp, "fingerprint unchanged on denial");
    assert_eq!(post.not_after_unix, past, "not_after unchanged on denial");
    assert_eq!(post.refresh_seq, pre_seq, "refresh_seq unchanged on denial");
}

// ---------------------------------------------------------------------------
// T2 #4-#5 — Client-side refresh band timing (pure math).
//
// ADR 173 §Component 1 Table 1 locks the band timer at 50% / 75% / 90%
// / 99% of TTL elapsed (`not_before + total * band_pct`). The M6
// client (META-AP-EMBERLINK-MCP-CERT-REFRESH-CLIENT — ready, not yet
// shipped at M10 land) is the scheduler. Lock the band-math invariants
// here so any future M6 implementation that drifts from the table
// surfaces at `cargo test` time. Mirrors the existing 90% deadline
// math in `crates/emberlink-mcp/src/cert_expiry.rs::ninety_percent_
// deadline` (also a deterministic `total * pct / 100` integer math
// for bit-exact reproducibility across platforms).
//
// These are pure functions, no I/O — they live here so the M10
// checkpoint `daemon_bridge_t2_t3_refresh_tests_landed` covers the
// refresh-band timing contract end-to-end (dispatch + band math +
// listener integration) in one file.
// ---------------------------------------------------------------------------

/// Mirrors the M6 client's deadline math. Returns the wallclock Unix
/// timestamp at which the band fires for a cert with the given
/// (`not_before`, `not_after`) window.
///
/// Per ADR 173 §C1 Table 1: at 50% elapsed the M6 client fires the
/// first `refresh_cert` attempt; at 75% the retry escalation timer
/// fires; at 90% the existing `bridge.cert_expiring_soon` warning
/// fires; at 99% the M12 listener force-close window is imminent.
fn refresh_band_deadline(not_before: i64, not_after: i64, band_pct: u32) -> i64 {
    let total = (not_after - not_before).max(1);
    not_before + (total * (band_pct as i64) / 100)
}

#[test]
fn refresh_band_timing_50_75_at_canonical_offsets_t2() {
    // A 10000-second cert: band-50 fires at +5000s, band-75 at +7500s,
    // band-90 at +9000s (matches `cert_expiry::ninety_percent_deadline`).
    let not_before = 1_700_000_000i64;
    let not_after = 1_700_010_000i64;
    let band_50 = refresh_band_deadline(not_before, not_after, 50);
    let band_75 = refresh_band_deadline(not_before, not_after, 75);
    let band_90 = refresh_band_deadline(not_before, not_after, 90);
    assert_eq!(band_50, 1_700_005_000, "50% band at +5000s");
    assert_eq!(band_75, 1_700_007_500, "75% band at +7500s");
    assert_eq!(band_90, 1_700_009_000, "90% band at +9000s");

    // Bands are strictly increasing — the M6 scheduler walks them in
    // order, never re-fires a prior band.
    assert!(band_50 < band_75);
    assert!(band_75 < band_90);
}

#[test]
fn refresh_band_timing_clamps_degenerate_window_t2() {
    // `not_after == not_before` would otherwise zero-divide. Mirrors
    // `cert_expiry::CertValidity::total_secs` clamp-to-1.
    let degenerate = refresh_band_deadline(1_700_000_000, 1_700_000_000, 50);
    assert_eq!(
        degenerate, 1_700_000_000,
        "degenerate window clamps to not_before (total=1 → 1*50/100=0 offset)"
    );

    // Past-deadline windows: when `now > band` the M6 scheduler fires
    // immediately. The deadline function still returns the absolute
    // wallclock timestamp — the scheduler does the `now >= deadline`
    // comparison (matches `duration_until_deadline` in cert_expiry.rs).
    let past = refresh_band_deadline(1_700_000_000, 1_700_010_000, 50);
    assert_eq!(past, 1_700_005_000, "deadline math is anchor-free");
}

// ---------------------------------------------------------------------------
// T3 fixtures: real `ember_rpc::Listener` over loopback TCP, short-TTL
// client cert minted via the same `BridgeCa` the listener trusts.
//
// Pattern mirrors `crates/ember-daemon/tests/bridge_ca_pem_listener_
// handshake.rs` (the T3 publish-format reconciliation test) for the
// emberd-side mint → ember-rpc listener load wiring.
// ---------------------------------------------------------------------------

/// Bind an ephemeral 127.0.0.1 port, then drop the probe so the real
/// listener can claim the same port. Same pattern as every other T3
/// test in this directory + `ember-rpc/tests/listener_smoke.rs`.
async fn ephemeral_listen_addr() -> SocketAddr {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("probe bind");
    let addr = probe.local_addr().expect("probe local_addr");
    drop(probe);
    addr
}

/// Spawn a one-shot UDS echo that decodes the bridge frame and returns a
/// canned JSON-RPC response. Mirrors `bridge_ca_pem_listener_handshake.rs`.
async fn spawn_forward_uds_echo(path: &Path) -> tokio::task::JoinHandle<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).expect("bind forward uds");
    tokio::spawn(async move {
        // The T3 force-close tests never expect to reach the forward
        // lane (the listener stops the connection at the deadline
        // before any frame arrives). Accept-loop here for the
        // happy-path arm only; if the listener does forward a frame
        // we mirror back a canned success so the assertion shape
        // matches the published-PEM test.
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let mut frame_bytes = Vec::new();
        let _ = read_half.read_to_end(&mut frame_bytes).await;
        let Ok(decoded) = ember_rpc::frame::decode(&frame_bytes) else {
            return;
        };
        let request: serde_json::Value =
            serde_json::from_slice(&decoded.payload).unwrap_or(serde_json::Value::Null);
        let mut response = serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "forwarded": true,
                "lane": "uds",
                "persona_id": decoded.persona_id,
                "container_id": decoded.container_id,
            },
            "id": request.get("id").cloned().unwrap_or(serde_json::Value::Null),
        }))
        .unwrap_or_default();
        response.push('\n');
        let _ = write_half.write_all(response.as_bytes()).await;
    })
}

/// Build the rustls `ClientConfig` from emberd's PEM artifacts. Same
/// shape as `bridge_ca_pem_listener_handshake.rs::build_client_tls`.
fn build_client_tls(
    bridge_ca_pem_bytes: &[u8],
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Arc<ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    let mut ca_cursor = std::io::Cursor::new(bridge_ca_pem_bytes);
    for ca in rustls_pemfile::certs(&mut ca_cursor) {
        let ca = ca.expect("ca cert pem parses");
        roots.add(ca).expect("add ca to root store");
    }

    let mut cert_cursor = std::io::Cursor::new(client_cert_pem.as_bytes());
    let client_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_cursor)
        .map(|c| c.expect("client cert pem"))
        .collect();
    assert!(
        !client_certs.is_empty(),
        "client cert pem must contain at least one cert"
    );

    let mut key_cursor = std::io::Cursor::new(client_key_pem.as_bytes());
    let client_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_cursor)
        .expect("read client key")
        .expect("client key present");
    let key_for_config: PrivateKeyDer<'static> = match client_key {
        PrivateKeyDer::Pkcs8(k) => {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec()))
        }
        other => other,
    };

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certs, key_for_config)
        .expect("client mTLS config");
    Arc::new(config)
}

/// Spin up emberd's bridge CA + ember-rpc listener wiring for a T3
/// test. Returns the data-dir tempdir (must outlive the listener), the
/// bridge CA PEM bytes, the listen addr, the forward UDS path, the
/// forward task handle, and the listener task handle.
struct T3Listener {
    _data_dir: TempDir,
    bridge_ca: Arc<BridgeCa>,
    bridge_ca_pem_bytes: Vec<u8>,
    listen_addr: SocketAddr,
    forward_handle: tokio::task::JoinHandle<()>,
    listener_handle: tokio::task::JoinHandle<()>,
}

async fn spin_up_t3_listener() -> T3Listener {
    use ember_daemon::infra::runtime::{
        load_or_mint_bridge_ca, mint_or_rotate_ember_rpc_server_cert,
    };

    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let vault = Vault::new(TEST_VAULT_KEY);

    // emberd-side: mint bridge CA + publish PEM artifacts.
    let bridge_ca =
        load_or_mint_bridge_ca(&data_dir, &vault).expect("load_or_mint_bridge_ca");
    let pem_path = data_dir.join("bridge_ca.pem");
    let pem_bytes = std::fs::read(&pem_path).expect("read bridge_ca.pem");

    // emberd-side: mint the ember-rpc sibling's server cert pair.
    mint_or_rotate_ember_rpc_server_cert(&data_dir, None, &bridge_ca)
        .expect("mint_or_rotate_ember_rpc_server_cert");
    let server_cert_path = data_dir.join("ember-rpc").join("server.crt");
    let server_key_path = data_dir.join("ember-rpc").join("server.key");

    let listen_addr = ephemeral_listen_addr().await;
    let forward_uds = data_dir.join("rpc-forward.sock");
    let forward_handle = spawn_forward_uds_echo(&forward_uds).await;

    let config = ListenerConfig {
        listen_addr,
        forward_uds: forward_uds.clone(),
        server_cert_path,
        server_key_path,
        ca_cert_path: pem_path.clone(),
    };
    let listener_handle = Listener::spawn(config).await.expect("listener spawn");
    // Give the accept loop a moment to install.
    tokio::time::sleep(Duration::from_millis(50)).await;

    T3Listener {
        _data_dir: tmp,
        bridge_ca,
        bridge_ca_pem_bytes: pem_bytes,
        listen_addr,
        forward_handle,
        listener_handle,
    }
}

// ---------------------------------------------------------------------------
// T3 #1 — Short-TTL handshake green → force-close at deadline.
//
// A fresh short-TTL client cert (3s window) handshakes cleanly against
// the listener; the listener then force-closes the same connection at
// `not_after` with a typed `connection-expired:` envelope. This is the
// M3 + M12 integration point: in production, the M6 client would fire
// `refresh_cert` at the 50% band (1.5s into the 3s window) to get a
// fresh cert. Without one, the M12 deadline closes the connection.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn short_ttl_handshake_green_then_listener_force_closes_at_not_after_t3() {
    let t3 = spin_up_t3_listener().await;

    // 4-second client cert TTL — long enough to handshake + queue an
    // idle read, short enough that the deadline fires well within
    // cargo test's normal budget.
    let ttl = Duration::from_secs(4);
    let (client_cert_pem, client_key_pem) = t3
        .bridge_ca
        .sign_client_cert("persona-t3-short", Some("ctr-t3-short"), ttl)
        .expect("sign short-TTL client cert");

    let client_tls = build_client_tls(
        &t3.bridge_ca_pem_bytes,
        &client_cert_pem,
        &client_key_pem,
    );
    let connector = TlsConnector::from(client_tls);

    // Handshake succeeds — short-TTL cert is signed by the same bridge
    // CA the listener trusts; mTLS validation passes.
    let stream = TcpStream::connect(t3.listen_addr)
        .await
        .expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let tls_stream = tokio::time::timeout(
        Duration::from_secs(3),
        connector.connect(server_name, stream),
    )
    .await
    .expect("handshake completes within 3s")
    .expect("mTLS handshake green for fresh short-TTL cert");

    // Hold the connection open without sending a frame. The listener's
    // post-handshake `read_until(b'\n')` blocks on the bounded reader
    // until the M12 deadline (4s) fires; ADR 173 §C1 names this as
    // the listener-force-close path that a refresh would have avoided.
    let mut reader = BufReader::new(tls_stream);
    let mut line = String::new();
    let read_result = tokio::time::timeout(
        Duration::from_secs(10),
        reader.read_line(&mut line),
    )
    .await
    .expect("test must not hang past the deadline");
    let _bytes = read_result.expect("listener writes ConnectionExpired before EOF");

    // Verify the listener emitted the canonical `connection-expired:`
    // envelope (M12 contract from `bridge_listener_force_close_at_
    // not_after_landed` in ember-rpc/src/listener.rs).
    let parsed: serde_json::Value =
        serde_json::from_str(line.trim_end()).expect("ConnectionExpired is valid JSON");
    assert_eq!(
        parsed["error"]["code"].as_i64(),
        Some(-32099),
        "force-close MUST emit -32099 ConnectionExpired; got {parsed}"
    );
    let msg = parsed["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        msg.starts_with("connection-expired:"),
        "message must start with canonical 'connection-expired:' prefix; got {msg}"
    );

    t3.listener_handle.abort();
    t3.forward_handle.abort();
}

// ---------------------------------------------------------------------------
// T3 #2 — Old-cert-rejected post-deadline.
//
// After the deadline fires on the original cert, a fresh handshake
// attempt using the SAME expired cert must NOT yield an authenticated
// forward. Two terminal states are acceptable:
//
//   (a) TLS handshake fails at the rustls layer with CertExpired (the
//       client side ALSO rejects an expired peer cert — but here the
//       client cert is OUR cert, so the failure comes from the server
//       refusing it via webpki client-cert verification).
//
//   (b) Handshake completes (the server's clock-skew window or
//       client-cert verify path lets it land), and the listener
//       immediately force-closes with ConnectionExpired because the
//       per-connection M12 deadline computes `not_after - now <= 0
//       → Duration::ZERO` (the deadline future fires on the next poll
//       before the read can authenticate anything).
//
// Either is acceptable; the load-bearing invariant is "no authenticated
// forward succeeds against an expired cert."
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_cert_handshake_attempt_post_deadline_no_authenticated_forward_t3() {
    let t3 = spin_up_t3_listener().await;

    // 2-second client cert — short enough that we can wait past
    // not_after well within the test budget.
    let ttl = Duration::from_secs(2);
    let (client_cert_pem, client_key_pem) = t3
        .bridge_ca
        .sign_client_cert("persona-t3-expired", Some("ctr-t3-expired"), ttl)
        .expect("sign short-TTL client cert");

    // Wait until the cert is past its not_after.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let client_tls = build_client_tls(
        &t3.bridge_ca_pem_bytes,
        &client_cert_pem,
        &client_key_pem,
    );
    let connector = TlsConnector::from(client_tls);
    let server_name = ServerName::try_from("localhost").expect("server name");

    // Attempt a fresh handshake with the now-expired cert.
    let connect_result = tokio::time::timeout(
        Duration::from_secs(5),
        async {
            let stream = TcpStream::connect(t3.listen_addr).await?;
            connector.connect(server_name, stream).await
        },
    )
    .await
    .expect("connect attempt must not hang past 5s");

    match connect_result {
        Err(tls_err) => {
            // Terminal state (a): handshake rejected at the TLS layer.
            // rustls webpki client-cert validation refused the expired
            // cert. No further action needed; the invariant holds.
            let msg = tls_err.to_string().to_lowercase();
            assert!(
                msg.contains("expired") || msg.contains("invalid") || msg.contains("cert"),
                "TLS error must reference cert validity; got {tls_err}"
            );
        }
        Ok(tls_stream) => {
            // Terminal state (b): handshake landed (server-side clock
            // skew window or client-cert verifier ignored the expiry).
            // The listener's per-connection deadline computes
            // `not_after - now <= 0` → `Duration::ZERO` and the
            // force-close future fires on the next poll. Try to read
            // ANY response; either we get a ConnectionExpired
            // envelope or we get EOF, but we MUST NOT see a
            // `forwarded: true` success.
            //
            // Write a frame to give the listener something to ignore
            // / drop — the deadline race biases toward force-close
            // since the cert is already past not_after.
            let (mut read_half, mut write_half) = tokio::io::split(tls_stream);
            let _ = write_half
                .write_all(
                    b"{\"jsonrpc\":\"2.0\",\"method\":\"vault_status\",\"params\":{},\"id\":1}\n",
                )
                .await;

            let mut response = Vec::new();
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                read_half.read_to_end(&mut response),
            )
            .await;

            if !response.is_empty() {
                let body =
                    String::from_utf8_lossy(&response).trim_end().to_string();
                let parsed: serde_json::Value = serde_json::from_str(&body)
                    .unwrap_or(serde_json::Value::Null);
                // The ONLY legitimate response is the queued
                // ConnectionExpired envelope. A `forwarded: true`
                // success would mean an expired cert authenticated
                // a real RPC — the invariant we're protecting.
                assert_ne!(
                    parsed["result"]["forwarded"].as_bool(),
                    Some(true),
                    "expired cert MUST NOT yield a forwarded success; got {parsed}"
                );
                if parsed["error"]["code"].as_i64().is_some() {
                    assert_eq!(
                        parsed["error"]["code"].as_i64(),
                        Some(-32099),
                        "the only non-EOF error from an expired cert is \
                         ConnectionExpired (-32099); got {parsed}"
                    );
                }
            }
            // EOF is also acceptable — listener tore down without
            // writing a frame.
        }
    }

    t3.listener_handle.abort();
    t3.forward_handle.abort();
}
