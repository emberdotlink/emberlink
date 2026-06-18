//! `ember demo seed` — **DEMO-ONLY** synthetic Grant-Receipt seeder.
//!
//! For the SCION 2026-05-15 Beat 8 close, `ember receipt tree --grant <id>`
//! needs at least a few receipts on the chain to render. The production
//! spawn flow does not yet emit receipts at every step (filed as
//! META-AP-PRODUCTION-SPAWN-WITNESS-EMISSION and related per-call-receipt
//! tasks). Until those land, this verb mints synthetic Grant Receipts onto
//! an existing grant chain so the demo has artifacts to display.
//!
//! ## Why this is gated to `demo` and not a production code path
//!
//! The seeded receipts pass v1 signature verification (signed by the local
//! daemon persona) but their *bodies* are placeholders — they reference a
//! `TerminalReason::Expired` reason and zero approval/usage history, none
//! of which corresponds to real agent activity. Mixing this into a
//! production receipt-emission path would produce signed-but-fictional
//! audit data; that's exactly the lie the Grant Warden product exists to
//! prevent.

use core_grant_types::grant_receipt::TerminalReason;
use ember_daemon::infra::config::DaemonConfig;
use ember_daemon::infra::receipt::{DaemonPersona, emit_receipt};
use ember_daemon::infra::store::DaemonStore;

/// Errors raised by `ember demo seed`.
#[derive(Debug)]
pub enum SeedError {
    Config(String),
    Store(String),
    Grant(String),
    Identity(String),
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedError::Config(e) => write!(f, "config: {e}"),
            SeedError::Store(e) => write!(f, "store: {e}"),
            SeedError::Grant(e) => write!(f, "grant: {e}"),
            SeedError::Identity(e) => write!(f, "identity: {e}"),
        }
    }
}

impl std::error::Error for SeedError {}

/// Seed `count` synthetic Grant Receipts onto `grant_id`.
///
/// Returns the list of created receipt ids.
pub fn cmd_demo_seed(
    config: &DaemonConfig,
    grant_id: &str,
    count: usize,
) -> Result<Vec<String>, SeedError> {
    config
        .ensure_dirs()
        .map_err(|e| SeedError::Config(e.to_string()))?;

    let db_path = config.data_dir.join("daemon.db");
    let store = DaemonStore::open(&db_path)
        .map_err(|e| SeedError::Store(format!("open {}: {e}", db_path.display())))?;

    let grant = store
        .get_grant(grant_id)
        .map_err(|e| SeedError::Grant(format!("get_grant({grant_id}): {e}")))?;

    let identity = DaemonPersona::load_or_create(&config.data_dir)
        .map_err(|e| SeedError::Identity(e.to_string()))?;

    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        // TerminalReason::Expired is the cheapest placeholder — it has no
        // sub-fields and no semantic implication beyond "this grant ended
        // by hitting its TTL". The seeded receipt is signed correctly but
        // its body is otherwise empty (zero usage, zero approvals).
        let rid = emit_receipt(&store, &identity, &grant, TerminalReason::Expired)
            .map_err(|e| SeedError::Store(format!("emit_receipt: {e}")))?;
        ids.push(rid);
    }
    Ok(ids)
}
