//!
//! `ember audit ...` CLI subcommands. Installed-path `show` / `export`
//! route through the daemon's operator-only `audit_log_query` seam, while
//! `query` uses daemon `receipt_query`. Installed-path `explain` now routes
//! through daemon `audit_explain`, which is explicitly a current-state view:
//! the audit event row is historical, but the grant/policy projections come
//! from the daemon's current live state. The chain verify path (this
//! module's `verify`) is different: it routes through the daemon's
//! `audit_verify` socket method so the operator gets the authoritative
//! answer from the trust authority that owns the chain.

pub mod verify;
