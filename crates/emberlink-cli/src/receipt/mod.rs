//! Receipt rendering surface for friendly-dev artifacts.
//!
//! Per ADR 120 §7: `ember receipt list` / `ember receipt show <id>` /
//! `ember receipt export --format md`
//! produces a markdown summary that fits in a Slack/iMessage paste.
//!
//! [`rollup`] adds the `ember receipt rollup` verb (per
//! `docs/construct-receipt-rollup.md` and AP-CONSTRUCT-RECEIPT-ROLLUP-CLI),
//! collapsing 4-Receipt construct invocations into one row keyed by
//! `materialization_id` and exposing the chain-integrity walker used by
//! `ember receipt verify --materialization`.

pub mod render;
pub mod rollup;
pub mod rotation_chain;
pub mod tree;
pub mod verify_dispatch;

pub use render::render_receipt_markdown;
pub use rollup::{RollupError, RollupFilters, RollupRow, rollup_command, verify_chain};
pub use rotation_chain::{
    ChainLoadError, format_chain_failure, format_chain_success, list_witnesses_ascending,
};
pub use tree::{
    TreeError, TreeExport, TreeGrant, TreeReceipt, TreeSpawnWitness, VerifyTreeOutcome, build_tree,
    cmd_receipt_tree, format_verify_outcome, read_tree_export, render_tree_ascii,
    verify_tree_offline,
};
pub use verify_dispatch::{DispatchOutcome, dispatch_verify, format_outcome};
