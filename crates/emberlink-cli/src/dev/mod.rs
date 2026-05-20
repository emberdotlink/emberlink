//! `ember dev` subcommand module — design Phase 4 dev daemon install + sync flow.
//!
//! Sentinels:
//! - `dev_prod_parity_ember_dev_install_skeleton_landed` (slice-A: prior change)
//! - `dev_prod_parity_ember_dev_install_slice_b_landed` (this PR: gh_app + uids)
//! - `dev_prod_parity_ember_dev_sync_landed` (prior change)
//!

pub mod gh_app;
pub mod identity_root;
pub mod info;
pub mod install;
pub mod sync;
pub mod uids;

/// Checkpoint constant consumed by the headless `target_state_anchor` gate.
/// Its presence in the compiled binary confirms phase-1 skeleton landed.
#[doc(hidden)]
pub const SENTINEL_DEV_PROD_PARITY_EMBER_DEV_INSTALL_SKELETON_LANDED: &str =
    "dev_prod_parity_ember_dev_install_skeleton_landed";

/// Checkpoint constant confirming slice-B (GH App + uid/group provisioning) landed.
#[doc(hidden)]
pub const SENTINEL_DEV_PROD_PARITY_EMBER_DEV_INSTALL_SLICE_B_LANDED: &str =
    "dev_prod_parity_ember_dev_install_slice_b_landed";
