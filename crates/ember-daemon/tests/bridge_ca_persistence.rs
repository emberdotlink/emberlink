//! CLASSIFICATION: PUBLIC
//!
//! META-AP-DAEMON-BRIDGE-CA-SE-SEALED-B-STARTUP — T2 integration coverage
//! for the Bridge CA load-or-mint helper.
//!
//! Spinning up the full `DaemonRuntime::run` requires a PID file, a Unix
//! socket bind, broker registration, and tokio plumbing — none of which
//! are load-bearing for the persistence contract. Instead, this test
//! drives the factored `infra::runtime::load_or_mint_bridge_ca` helper
//! directly (the same call-site `run()` uses) against a real on-disk
//! `<data_dir>`, sealed under a real `Vault::new(...)`.
//!
//! The acceptance bits (from the brief):
//!
//!   1. First run mints — `bridge_ca.wrap`, `bridge_ca.sealed`,
//!      `bridge_ca.pub`, and `bridge_ca.pem` all appear; the helper returns
//!      a usable `Arc<BridgeCa>` and its fingerprint matches the on-disk pub.
//!   2. Restart preserves — call the helper a second time against the
//!      same `data_dir` + same vault and observe the same fingerprint.
//!      This is the load-bearing invariant: "Daemon restart must NOT
//!      wipe outstanding per-agent client certs" (bridge_ca.rs §Why
//!      SE-sealed).
//!
//! The brief calls this T2; per the test-tier guidance in
//! `.claude/rules/test-tiers.md`, integration tests under `tests/`
//! always count as T2 regardless of what they spin up. There's no
//! daemon process, no socket, no Anthropic SDK — just a `TempDir`, a
//! `Vault`, and the helper.

use ember_daemon::infra::runtime::load_or_mint_bridge_ca;
use ember_daemon::infra::vault::Vault;
use tempfile::TempDir;

/// Stable deterministic vault key for these tests. Matches the pattern
/// used in `tests/budget_persistence.rs`.
const TEST_VAULT_KEY: [u8; 32] = [0x42u8; 32];

/// Pre: empty `<data_dir>`.
/// Post:
///   - `bridge_ca.wrap`, `bridge_ca.sealed`, `bridge_ca.pub`, and
///     `bridge_ca.pem` all exist.
///   - `bridge_ca.pub` is exactly 32 bytes (ed25519 verifying key).
///   - `bridge_ca.pem` parses as a single PEM certificate.
///   - The helper-returned fingerprint equals `blake3(pub bytes)`.
#[test]
fn first_run_writes_all_public_artifacts() {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path();
    let vault = Vault::new(TEST_VAULT_KEY);

    let ca = load_or_mint_bridge_ca(data_dir, &vault).expect("first-run load_or_mint");

    assert!(
        data_dir.join("bridge_ca.wrap").exists(),
        "first run must write bridge_ca.wrap"
    );
    assert!(
        data_dir.join("bridge_ca.sealed").exists(),
        "first run must write bridge_ca.sealed"
    );
    assert!(
        data_dir.join("bridge_ca.pub").exists(),
        "first run must write bridge_ca.pub"
    );
    assert!(
        data_dir.join("bridge_ca.pem").exists(),
        "first run must write bridge_ca.pem"
    );

    let pub_bytes = std::fs::read(data_dir.join("bridge_ca.pub")).expect("read pub");
    assert_eq!(pub_bytes.len(), 32, "ed25519 verifying key is 32 bytes");
    let pem_bytes = std::fs::read(data_dir.join("bridge_ca.pem")).expect("read pem");
    let mut cursor = std::io::Cursor::new(pem_bytes);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<_, _>>()
        .expect("published PEM root parses");
    assert_eq!(certs.len(), 1, "exactly one PEM CA cert published");

    let computed_fp = *blake3::hash(&pub_bytes).as_bytes();
    assert_eq!(
        ca.fingerprint(),
        computed_fp,
        "in-memory fingerprint matches on-disk pub-bytes hash"
    );
}

/// Pre: helper called once, then again with the same `data_dir` + vault.
/// Post: second call returns the SAME fingerprint as the first. This
/// pins the persistence-across-restart invariant — Slice C/D embed the
/// fingerprint in Spawn Receipts, and a fingerprint drift across a
/// daemon restart would invalidate every outstanding per-agent client
/// cert.
#[test]
fn restart_preserves_fingerprint() {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path();
    let vault = Vault::new(TEST_VAULT_KEY);

    let ca1 = load_or_mint_bridge_ca(data_dir, &vault).expect("first-run");
    let fp_before = ca1.fingerprint();
    let pub_before = std::fs::read(data_dir.join("bridge_ca.pub")).expect("read pub before");

    // Drop the first instance so we're testing genuine load-from-disk,
    // not in-memory reuse.
    drop(ca1);

    let ca2 = load_or_mint_bridge_ca(data_dir, &vault).expect("restart load");
    let fp_after = ca2.fingerprint();
    let pub_after = std::fs::read(data_dir.join("bridge_ca.pub")).expect("read pub after");

    assert_eq!(
        fp_after, fp_before,
        "fingerprint stable across simulated daemon restart"
    );
    assert_eq!(
        pub_after, pub_before,
        "pub bytes stable across simulated daemon restart"
    );
}
