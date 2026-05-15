//! Receipt rendering surface for friendly-dev artifacts.
//!
//! Per design §7: `ember receipt show` / `ember receipt export --format md`
//! produces a markdown summary that fits in a Slack/iMessage paste.
//!
//! [`rollup`] adds the `ember receipt rollup` verb (per
//! `docs/construct-receipt-rollup.md` and AP-CONSTRUCT-RECEIPT-ROLLUP-CLI),
//! collapsing 4-Receipt construct invocations into one row keyed by
//! `materialization_id` and exposing the chain-integrity walker used by
//! `ember receipt verify --materialization`.

pub mod render;
pub mod rollup;
pub mod tree;
pub mod verify_dispatch;

pub use render::render_receipt_markdown;
pub use rollup::{rollup_command, verify_chain, RollupError, RollupFilters, RollupRow};
pub use tree::{
    build_tree, cmd_receipt_tree, format_verify_outcome, read_tree_export, render_tree_ascii,
    verify_tree_offline, TreeError, TreeExport, TreeGrant, TreeReceipt, TreeSpawnWitness,
    VerifyTreeOutcome,
};
pub use verify_dispatch::{dispatch_verify, format_outcome, DispatchOutcome};
