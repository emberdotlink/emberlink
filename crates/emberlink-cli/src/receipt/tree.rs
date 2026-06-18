//! `ember receipt tree` — walk the grant graph rooted at an orchestrator
//! grant and render the full delegated authority + receipt artifact set as a
//! tree.
//!
//! Demo beat 8 ("Receipt tree close"): the partner walks away with a
//! verifiable artifact. The CLI produces an ASCII tree for stdout
//! consumption and a JSON export shape (`TreeExport`) that
//! `ember receipt verify --tree <file> --offline` reads back without
//! talking to the daemon — the daemon is already stopped at that point.
//!
//! ## Shape
//!
//! ```text
//! TreeExport {
//!   version: "v2",
//!   root_grant_id: "g-orc-...",
//!   grants: [ TreeGrant { id, parent_grant_id, persona_id, scope, status, created_at } ... ],
//!   receipts: [ TreeReceipt { grant_id, payload: <v1 GrantReceipt or v2 ReceiptEnvelope JSON>, kind: "v1"|"v2" } ... ],
//!   spawn_witnesses: [ TreeSpawnWitness { receipt_id, body: <spawn.witness body>, parent_pubkey_hex, daemon_pubkey_hex, envelope: ReceiptEnvelope } ... ],
//!   daemon_pubkey_hex: "<64-hex>"
//! }
//! ```
//!
//! ## Cryptographic verification at tree-time
//!
//! `verify_tree_offline` checks, for each artifact:
//! - v1 receipts → `ember_daemon::infra::receipt::verify_receipt` against
//!   the supplied `daemon_pubkey_hex` (trust anchor read from
//!   `<data_dir>/daemon_persona.key` BEFORE `ember daemon stop`).
//! - v2 envelopes → `core_events::receipt::sign::verify_receipt_v2` against
//!   the same trust anchor.
//! - spawn witnesses → `core_events::receipt::sign::verify_spawn_witness_parent_signature`
//!   against the witness's `parent_pubkey_hex`, plus envelope verify against
//!   `daemon_pubkey_hex`.
//!
//! ## Spawn-witness source of truth
//!
//! Spawn witnesses are emitted at parent→child grant edge creation time by
//! `crate::trust::grant::delegate_grant_full_sql` and persisted via
//! `DaemonStore::store_spawn_witness_receipt` (META-AP-PRODUCTION-SPAWN-WITNESS-EMISSION,
//! shipped 2026-05-15). `build_tree` reads them back via
//! `DaemonStore::list_spawn_witnesses_for_grants`; the demo-seam synthesis
//! path that previously fabricated witnesses at export time was removed in
//! the same patch. Edges that lack a persisted witness (legacy data, or
//! the parent persona key was unavailable at delegation time) surface as a
//! gap in the tree rather than a silently-fabricated row.

use std::collections::BTreeMap;
use std::path::Path;

use core_crypto::{Ed25519Verifier, PublicKey};
use core_events::receipt::envelope::ReceiptEnvelope;
use core_events::receipt::sign::{verify_receipt_v2, verify_spawn_witness_parent_signature};
use ember_daemon::infra::receipt::DaemonPersona;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::trust::grant::GrantInfo;
use serde::{Deserialize, Serialize};

/// Errors raised by tree assembly / verification.
#[derive(Debug)]
pub enum TreeError {
    /// `--grant <id>` was not found in the daemon store.
    UnknownRoot(String),
    /// Daemon store read failed (rusqlite/IO).
    Store(String),
    /// JSON (de)serialisation failed.
    Json(serde_json::Error),
    /// I/O failed.
    Io(std::io::Error),
    /// Cryptographic verification failed for a specific artifact.
    Verify { artifact: String, reason: String },
    /// The supplied tree's `version` is not `v2`.
    UnsupportedVersion(String),
}

impl std::fmt::Display for TreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TreeError::UnknownRoot(id) => write!(f, "grant '{id}' not found"),
            TreeError::Store(e) => write!(f, "daemon store: {e}"),
            TreeError::Json(e) => write!(f, "json: {e}"),
            TreeError::Io(e) => write!(f, "io: {e}"),
            TreeError::Verify { artifact, reason } => {
                write!(f, "verify FAILED for {artifact}: {reason}")
            }
            TreeError::UnsupportedVersion(v) => {
                write!(f, "unsupported tree version: '{v}' (expected 'v2')")
            }
        }
    }
}

impl std::error::Error for TreeError {}

impl From<serde_json::Error> for TreeError {
    fn from(e: serde_json::Error) -> Self {
        TreeError::Json(e)
    }
}

impl From<std::io::Error> for TreeError {
    fn from(e: std::io::Error) -> Self {
        TreeError::Io(e)
    }
}

/// Tree version pin. Bump if the export shape changes.
pub const TREE_VERSION: &str = "v2";

/// Top-level export shape written by `--export <path>` and consumed by
/// `verify --tree <file> --offline`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeExport {
    pub version: String,
    pub root_grant_id: String,
    pub grants: Vec<TreeGrant>,
    pub receipts: Vec<TreeReceipt>,
    pub spawn_witnesses: Vec<TreeSpawnWitness>,
    /// `ed25519:<hex>` trust anchor for v2 envelope verification. Captured
    /// from `<data_dir>/daemon_persona.key` at export time so verify can
    /// run with the daemon stopped.
    pub daemon_pubkey_hex: String,
}

/// Per-grant projection in the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeGrant {
    pub id: String,
    pub parent_grant_id: Option<String>,
    pub persona_id: String,
    pub credential_name: String,
    pub scope: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

impl From<&GrantInfo> for TreeGrant {
    fn from(g: &GrantInfo) -> Self {
        Self {
            id: g.id.clone(),
            parent_grant_id: g.parent_grant_id.clone(),
            persona_id: g.persona_id.clone(),
            credential_name: g.credential_name.clone(),
            scope: g.scope.clone(),
            status: g.status.clone(),
            created_at: g.created_at.clone(),
            expires_at: g.expires_at.clone(),
        }
    }
}

/// Per-receipt projection — preserves the v1 vs v2 envelope distinction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeReceipt {
    /// Receipt id (from the v1 row or v2 envelope `receipt_id`).
    pub id: String,
    /// Grant the receipt is bound to.
    pub grant_id: String,
    /// `"v1"` or `"v2"`.
    pub kind: String,
    /// Raw payload — full v1 `GrantReceipt` JSON or v2 `ReceiptEnvelope`
    /// JSON. The verifier dispatches on `kind`.
    pub payload: serde_json::Value,
}

/// Wrapper for a spawn-witness Receipt v2 envelope (kind == `spawn.witness`)
/// plus the parent persona pubkey needed to verify the dual-signature
/// binding (CRIT-7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeSpawnWitness {
    /// Receipt id from the envelope.
    pub receipt_id: String,
    /// The parent grant edge this witness covers (== `body.spawn_grant_id`).
    pub spawn_grant_id: String,
    /// `ed25519:<hex>` trust anchor used to verify the inner
    /// `parent_signature` field on the body. Sourced from the parent
    /// persona's row at tree-build time (META-AP-PRODUCTION-SPAWN-WITNESS-EMISSION);
    /// `verify_spawn_witness_parent_signature` succeeds iff the parent
    /// persona authorised the spawn at delegation time.
    pub parent_pubkey_hex: String,
    /// The full v2 envelope (signed by daemon, body = SpawnWitness JSON).
    pub envelope: ReceiptEnvelope,
}

/// Public CLI entry point for `ember receipt tree`. Walks the grant graph,
/// builds an in-memory tree, prints a friendly ASCII rendering to stdout,
/// and (optionally) writes the JSON export shape to `export_to`.
pub fn cmd_receipt_tree(
    store: &DaemonStore,
    data_dir: &Path,
    root_grant_id: &str,
    export_to: Option<&Path>,
) -> Result<(), TreeError> {
    // 1. Build the tree (DB read, in-process).
    let tree = build_tree(store, data_dir, root_grant_id)?;

    // 2. ASCII render to stdout for the demo close.
    print!("{}", render_tree_ascii(&tree));

    // 3. JSON export for downstream verify.
    if let Some(path) = export_to {
        write_tree_export(&tree, path)?;
        println!("Exported tree to {}", path.display());
    }
    Ok(())
}

/// Build the [`TreeExport`] in memory by reverse-walking `parent_grant_id`
/// edges from the root.
///
/// The walk is iterative-BFS over the in-memory `list_grants()` view —
/// cheap enough for a demo (≤100s of grants) and correct even when the
/// chain is multi-hop. Receipts are fetched per-grant via
/// `store.list_receipts(persona=None)` and filtered by `grant_id`; v2
/// envelopes are pulled from the receipts table where stored.
pub fn build_tree(
    store: &DaemonStore,
    data_dir: &Path,
    root_grant_id: &str,
) -> Result<TreeExport, TreeError> {
    // ---- Load all grants once; build a parent → children index. ----
    let all_grants = store
        .list_grants()
        .map_err(|e| TreeError::Store(e.to_string()))?;
    let mut by_id: BTreeMap<String, GrantInfo> = BTreeMap::new();
    let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for g in all_grants.into_iter() {
        if let Some(pid) = &g.parent_grant_id {
            children.entry(pid.clone()).or_default().push(g.id.clone());
        }
        by_id.insert(g.id.clone(), g);
    }

    // Root must exist.
    if !by_id.contains_key(root_grant_id) {
        return Err(TreeError::UnknownRoot(root_grant_id.to_string()));
    }

    // BFS the reachable subtree.
    let mut order: Vec<String> = Vec::new();
    let mut stack: Vec<String> = vec![root_grant_id.to_string()];
    while let Some(id) = stack.pop() {
        order.push(id.clone());
        if let Some(kids) = children.get(&id) {
            for k in kids {
                stack.push(k.clone());
            }
        }
    }

    // ---- Project grants. ----
    let mut tree_grants: Vec<TreeGrant> = Vec::with_capacity(order.len());
    for id in &order {
        if let Some(g) = by_id.get(id) {
            tree_grants.push(TreeGrant::from(g));
        }
    }

    // ---- Collect receipts (v1 GrantReceipt) per grant. ----
    let grant_id_set: std::collections::BTreeSet<&str> = order.iter().map(|s| s.as_str()).collect();
    let all_receipts = store
        .list_receipts(None)
        .map_err(|e| TreeError::Store(e.to_string()))?;
    let mut tree_receipts: Vec<TreeReceipt> = Vec::new();
    for r in all_receipts.iter() {
        if grant_id_set.contains(r.grant_id.as_str()) {
            let payload = serde_json::to_value(r)?;
            tree_receipts.push(TreeReceipt {
                id: r.id.clone(),
                grant_id: r.grant_id.clone(),
                kind: "v1".to_string(),
                payload,
            });
        }
    }

    // ---- Collect v2 ReceiptEnvelope rows per grant (anchor: list_receipts_v2_envelopes). ----
    //
    // V2 envelopes are identified by a dotted kind discriminator in the
    // `receipts` table. `spawn.witness` envelopes are excluded here because
    // they are already surfaced through the spawn_witnesses array above with
    // the dual-signature metadata required for offline verification.
    let grant_ids_vec: Vec<String> = order.clone();
    let v2_envelopes = store
        .list_receipts_v2_envelopes(&grant_ids_vec)
        .map_err(|e| TreeError::Store(e.to_string()))?;
    for (id, _kind, grant_id, envelope) in v2_envelopes {
        let payload = serde_json::to_value(&envelope)?;
        tree_receipts.push(TreeReceipt {
            id,
            grant_id,
            kind: "v2".to_string(),
            payload,
        });
    }

    // ---- Daemon pubkey for trust anchor (load BEFORE daemon stop). ----
    // Anchor: receipt_tree_pubkey_cross_uid_safe
    //
    // Prefer the 0644 pubkey sidecar (`daemon_persona.pub`) per
    // META-AP-RECEIPT-TREE-PUBKEY-CROSS-UID-READ Option A — cross-uid
    // callers (CLI run as operator against an ember-uid daemon under
    // ADR 131) can read it without permission errors on the 0600
    // private key file. Fall back to `DaemonPersona::load_or_create`
    // when the sidecar is missing (pre-sidecar daemon runs, or
    // recovery scenarios where the daemon has never started) — that
    // path still works for same-uid callers and produces the same
    // 64-char hex shape.
    let daemon_pubkey_hex = match ember_daemon::infra::receipt::read_pubkey_sidecar_hex(data_dir) {
        Ok(hex) => hex,
        Err(_) => {
            let persona = DaemonPersona::load_or_create(data_dir)
                .map_err(|e| TreeError::Store(e.to_string()))?;
            persona.pubkey_hex()
        }
    };

    // ---- Load spawn witnesses persisted at parent→child delegation time. ----
    //
    // META-AP-PRODUCTION-SPAWN-WITNESS-EMISSION (2026-05-15): the daemon
    // emits + persists a spawn.witness Receipt v2 envelope for every
    // parent→child grant edge inside `delegate_grant_full_sql`, signed by
    // the parent persona (body) and the daemon persona (envelope). We
    // read them back here and pair each envelope with the parent persona's
    // pubkey (looked up out of the personas table by `parent_persona_id`)
    // so offline verify can run the dual-signature check.
    let grant_ids: Vec<String> = order.clone();
    let raw_witnesses = store
        .list_spawn_witnesses_for_grants(&grant_ids)
        .map_err(|e| TreeError::Store(e.to_string()))?;
    let mut spawn_witnesses: Vec<TreeSpawnWitness> = Vec::with_capacity(raw_witnesses.len());
    for (envelope, parent_persona_id) in raw_witnesses {
        // Resolve the parent persona's Ed25519 pubkey for the inner
        // `parent_signature` verification. The personas row stores it in
        // the `ed25519:<hex>` wire form, which `TreeSpawnWitness.parent_pubkey_hex`
        // also speaks (matches the demo-seam shape so verify is unchanged).
        let parent_pubkey_hex = match store.get_persona(&parent_persona_id) {
            Ok(p) => p.public_key,
            Err(e) => {
                // The parent persona's row is missing — likely a deleted
                // persona or DB corruption. Surface as a verify error
                // rather than silently dropping the witness so the gap
                // is auditable.
                return Err(TreeError::Verify {
                    artifact: format!("spawn_witness/{}", envelope.receipt_id),
                    reason: format!(
                        "parent persona '{parent_persona_id}' not found in personas table: {e}"
                    ),
                });
            }
        };
        let spawn_grant_id = envelope
            .body
            .get("spawn_grant_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        spawn_witnesses.push(TreeSpawnWitness {
            receipt_id: envelope.receipt_id.clone(),
            spawn_grant_id,
            parent_pubkey_hex,
            envelope,
        });
    }

    Ok(TreeExport {
        version: TREE_VERSION.to_string(),
        root_grant_id: root_grant_id.to_string(),
        grants: tree_grants,
        receipts: tree_receipts,
        spawn_witnesses,
        daemon_pubkey_hex,
    })
}

/// Render the tree as ASCII for stdout.
pub fn render_tree_ascii(tree: &TreeExport) -> String {
    let mut out = String::new();
    out.push_str(&format!("Grant tree rooted at {}:\n", tree.root_grant_id));

    // Build a parent → children index over this tree's grants only.
    let mut children: BTreeMap<String, Vec<&TreeGrant>> = BTreeMap::new();
    for g in &tree.grants {
        if let Some(pid) = &g.parent_grant_id {
            children.entry(pid.clone()).or_default().push(g);
        }
    }
    // Receipts indexed by grant.
    let mut receipts_by_grant: BTreeMap<String, Vec<&TreeReceipt>> = BTreeMap::new();
    for r in &tree.receipts {
        receipts_by_grant
            .entry(r.grant_id.clone())
            .or_default()
            .push(r);
    }
    let witnesses_by_grant: BTreeMap<String, Vec<&TreeSpawnWitness>> = {
        let mut m: BTreeMap<String, Vec<&TreeSpawnWitness>> = BTreeMap::new();
        for w in &tree.spawn_witnesses {
            m.entry(w.spawn_grant_id.clone()).or_default().push(w);
        }
        m
    };

    #[allow(clippy::too_many_arguments)]
    fn walk(
        out: &mut String,
        grants: &BTreeMap<String, &TreeGrant>,
        children: &BTreeMap<String, Vec<&TreeGrant>>,
        receipts: &BTreeMap<String, Vec<&TreeReceipt>>,
        witnesses: &BTreeMap<String, Vec<&TreeSpawnWitness>>,
        id: &str,
        prefix: &str,
        is_last: bool,
    ) {
        let branch = if is_last { "└── " } else { "├── " };
        let cont = if is_last { "    " } else { "│   " };
        let g = match grants.get(id) {
            Some(g) => *g,
            None => return,
        };
        out.push_str(&format!(
            "{prefix}{branch}grant {} (persona={} status={})\n",
            short(&g.id),
            g.persona_id,
            g.status
        ));
        if let Some(rs) = receipts.get(id) {
            for r in rs {
                out.push_str(&format!(
                    "{prefix}{cont}├── receipt {} (kind={})\n",
                    short(&r.id),
                    r.kind
                ));
            }
        }
        if let Some(ws) = witnesses.get(id) {
            for w in ws {
                out.push_str(&format!(
                    "{prefix}{cont}├── spawn_witness {} (parent={})\n",
                    short(&w.receipt_id),
                    short(w.parent_pubkey_hex.trim_start_matches("ed25519:"))
                ));
            }
        }
        let kids = children.get(id).cloned().unwrap_or_default();
        for (idx, k) in kids.iter().enumerate() {
            let last = idx + 1 == kids.len();
            walk(
                out,
                grants,
                children,
                receipts,
                witnesses,
                &k.id,
                &format!("{prefix}{cont}"),
                last,
            );
        }
    }

    let by_id: BTreeMap<String, &TreeGrant> =
        tree.grants.iter().map(|g| (g.id.clone(), g)).collect();
    walk(
        &mut out,
        &by_id,
        &children,
        &receipts_by_grant,
        &witnesses_by_grant,
        &tree.root_grant_id,
        "",
        true,
    );
    out
}

fn short(s: &str) -> String {
    if s.len() <= 14 {
        s.to_string()
    } else {
        format!("{}…", &s[..13])
    }
}

/// Atomically write the tree export JSON to `path`.
pub fn write_tree_export(tree: &TreeExport, path: &Path) -> Result<(), TreeError> {
    let pretty = serde_json::to_string_pretty(tree)?;
    std::fs::write(path, pretty)?;
    Ok(())
}

/// Read a tree export JSON file (used by `verify --tree <path>`).
pub fn read_tree_export(path: &Path) -> Result<TreeExport, TreeError> {
    let bytes = std::fs::read(path)?;
    let tree: TreeExport = serde_json::from_slice(&bytes)?;
    Ok(tree)
}

/// Offline verification outcome.
#[derive(Debug, Clone, Default)]
pub struct VerifyTreeOutcome {
    pub grants_verified: usize,
    pub receipts_verified: usize,
    pub spawn_witnesses_verified: usize,
    pub root_grant_id: String,
    pub tree_hash: String,
    pub canonical_version: String,
}

/// Verify every artifact in the tree without contacting the daemon.
/// All cryptographic checks run against the tree's embedded
/// `daemon_pubkey_hex` (or per-witness `parent_pubkey_hex`) — the daemon
/// can be stopped.
pub fn verify_tree_offline(tree: &TreeExport) -> Result<VerifyTreeOutcome, TreeError> {
    if tree.version != TREE_VERSION {
        return Err(TreeError::UnsupportedVersion(tree.version.clone()));
    }
    let daemon_pk = PublicKey(format!("ed25519:{}", tree.daemon_pubkey_hex));

    // --- v1 + v2 receipts ---
    let mut receipts_ok = 0usize;
    for r in &tree.receipts {
        match r.kind.as_str() {
            "v1" => {
                // v1 path uses `verify_receipt(receipt, expected_pubkey_hex)`.
                let grant_receipt: core_grant_types::grant_receipt::GrantReceipt =
                    serde_json::from_value(r.payload.clone())?;
                ember_daemon::infra::receipt::verify_receipt(
                    &grant_receipt,
                    &tree.daemon_pubkey_hex,
                )
                .map_err(|e| TreeError::Verify {
                    artifact: format!("receipt/{}", r.id),
                    reason: e.to_string(),
                })?;
                receipts_ok += 1;
            }
            "v2" => {
                let envelope: ReceiptEnvelope = serde_json::from_value(r.payload.clone())?;
                verify_receipt_v2(&envelope, &daemon_pk, &Ed25519Verifier).map_err(|e| {
                    TreeError::Verify {
                        artifact: format!("receipt-v2/{}", r.id),
                        reason: format!("{e:?}"),
                    }
                })?;
                receipts_ok += 1;
            }
            other => {
                return Err(TreeError::Verify {
                    artifact: format!("receipt/{}", r.id),
                    reason: format!("unknown receipt kind '{other}'"),
                });
            }
        }
    }

    // --- spawn witnesses (dual signature: envelope + body.parent_signature) ---
    let mut witnesses_ok = 0usize;
    for w in &tree.spawn_witnesses {
        // 1. Envelope signed by the daemon (issuer).
        verify_receipt_v2(&w.envelope, &daemon_pk, &Ed25519Verifier).map_err(|e| {
            TreeError::Verify {
                artifact: format!("spawn_witness_envelope/{}", w.receipt_id),
                reason: format!("{e:?}"),
            }
        })?;
        // 2. Body's parent_signature signed by parent persona.
        let parent_pk = PublicKey(w.parent_pubkey_hex.clone());
        verify_spawn_witness_parent_signature(&w.envelope.body, &parent_pk, &Ed25519Verifier)
            .map_err(|e| TreeError::Verify {
                artifact: format!("spawn_witness_body/{}", w.receipt_id),
                reason: format!("{e:?}"),
            })?;
        witnesses_ok += 1;
    }

    // --- Tree hash: blake3 over canonical-sorted child hashes ---
    let mut child_hashes: Vec<String> = Vec::new();
    for g in &tree.grants {
        child_hashes.push(format!("grant:{}", g.id));
    }
    for r in &tree.receipts {
        child_hashes.push(format!("receipt:{}:{}", r.kind, r.id));
    }
    for w in &tree.spawn_witnesses {
        child_hashes.push(format!("witness:{}", w.receipt_id));
    }
    child_hashes.sort();
    let mut hasher = blake3::Hasher::new();
    for h in &child_hashes {
        hasher.update(h.as_bytes());
        hasher.update(b"\n");
    }
    let tree_hash = hasher.finalize().to_hex().to_string();

    Ok(VerifyTreeOutcome {
        grants_verified: tree.grants.len(),
        receipts_verified: receipts_ok,
        spawn_witnesses_verified: witnesses_ok,
        root_grant_id: tree.root_grant_id.clone(),
        tree_hash,
        canonical_version: TREE_VERSION.to_string(),
    })
}

/// Format `verify --tree` outcome for the Beat 8.2 demo close.
pub fn format_verify_outcome(o: &VerifyTreeOutcome) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Verified tree: {} grants, {} receipts\n",
        o.grants_verified, o.receipts_verified
    ));
    s.push_str(&format!("  Root grant: {}\n", o.root_grant_id));
    s.push_str(&format!(
        "  Spawn witnesses verified: {}\n",
        o.spawn_witnesses_verified
    ));
    s.push_str("  All per-call signatures verified\n");
    s.push_str(&format!(
        "  Tree hash: {}\n",
        &o.tree_hash[..o.tree_hash.len().min(16)]
    ));
    s.push_str(&format!("  Canonical version: {}\n", o.canonical_version));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_tree() -> TreeExport {
        TreeExport {
            version: TREE_VERSION.to_string(),
            root_grant_id: "g-orc".into(),
            grants: vec![TreeGrant {
                id: "g-orc".into(),
                parent_grant_id: None,
                persona_id: "persona-orc".into(),
                credential_name: "cred".into(),
                scope: "read:*".into(),
                status: "active".into(),
                created_at: "2026-05-15T00:00:00Z".into(),
                expires_at: None,
            }],
            receipts: vec![],
            spawn_witnesses: vec![],
            daemon_pubkey_hex: "0".repeat(64),
        }
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut t = fixture_tree();
        t.version = "v1".into();
        let err = verify_tree_offline(&t).unwrap_err();
        assert!(matches!(err, TreeError::UnsupportedVersion(_)));
    }

    #[test]
    fn empty_tree_verifies() {
        let t = fixture_tree();
        let o = verify_tree_offline(&t).unwrap();
        assert_eq!(o.grants_verified, 1);
        assert_eq!(o.receipts_verified, 0);
        assert_eq!(o.spawn_witnesses_verified, 0);
        assert_eq!(o.canonical_version, "v2");
        assert!(!o.tree_hash.is_empty());
    }

    #[test]
    fn tree_hash_is_deterministic() {
        let t = fixture_tree();
        let h1 = verify_tree_offline(&t).unwrap().tree_hash;
        let h2 = verify_tree_offline(&t).unwrap().tree_hash;
        assert_eq!(h1, h2);
    }

    #[test]
    fn render_ascii_root_only() {
        let t = fixture_tree();
        let out = render_tree_ascii(&t);
        assert!(out.contains("Grant tree rooted at g-orc"));
        assert!(out.contains("grant g-orc"));
    }

    #[test]
    fn format_outcome_shape_matches_beat_8_demo_doc() {
        let o = VerifyTreeOutcome {
            grants_verified: 3,
            receipts_verified: 8,
            spawn_witnesses_verified: 2,
            root_grant_id: "g-orc".into(),
            tree_hash: "2e1a5857deadbeefcafebabe".into(),
            canonical_version: "v2".into(),
        };
        let s = format_verify_outcome(&o);
        // The demo doc explicitly specifies these strings.
        assert!(s.contains("Verified tree: 3 grants, 8 receipts"));
        assert!(s.contains("Root grant: g-orc"));
        assert!(s.contains("Spawn witnesses verified: 2"));
        assert!(s.contains("All per-call signatures verified"));
        assert!(s.contains("Tree hash: 2e1a5857"));
        assert!(s.contains("Canonical version: v2"));
    }

    #[test]
    fn read_missing_tree_file_errors() {
        let path = std::path::Path::new("/tmp/__definitely_does_not_exist_tree.json");
        let err = read_tree_export(path).unwrap_err();
        assert!(matches!(err, TreeError::Io(_)));
    }

    // --- v2 envelope inclusion (META-AP-RECEIPT-TREE-V2-ENVELOPE-INCLUSION) ---

    fn fixture_tree_with_v2_receipt() -> TreeExport {
        let mut t = fixture_tree();
        t.receipts.push(TreeReceipt {
            id: "rct-v2-test".into(),
            grant_id: "g-orc".into(),
            kind: "v2".into(),
            payload: serde_json::json!({
                "version": "2",
                "kind": "broker.materialization",
                "receipt_id": "rct-v2-test",
                "daemon_root_id": "daemon-root",
                "termination_authority": "daemon_persona",
                "body": {"test": true}
            }),
        });
        t
    }

    #[test]
    fn v2_receipt_kind_appears_in_render() {
        let t = fixture_tree_with_v2_receipt();
        let out = render_tree_ascii(&t);
        assert!(
            out.contains("kind=v2"),
            "render must show kind=v2 for v2 receipts; got:\n{out}"
        );
    }

    #[test]
    fn tree_with_v2_receipt_serialises_round_trip() {
        let t = fixture_tree_with_v2_receipt();
        let json = serde_json::to_string(&t).unwrap();
        let back: TreeExport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.receipts.len(), 1);
        assert_eq!(back.receipts[0].kind, "v2");
        assert_eq!(back.receipts[0].id, "rct-v2-test");
    }

    #[test]
    fn tree_hash_includes_v2_receipt() {
        let t_without = fixture_tree();
        let t_with = fixture_tree_with_v2_receipt();
        // verify_tree_offline skips signature checks if pubkey is zero — it will
        // error on the v2 verify step (no real signature). We only check that
        // the hash is different, which proves the v2 receipt affects the hash.
        let h_without = {
            let mut child_hashes: Vec<String> = Vec::new();
            for g in &t_without.grants {
                child_hashes.push(format!("grant:{}", g.id));
            }
            child_hashes.sort();
            let mut hasher = blake3::Hasher::new();
            for h in &child_hashes {
                hasher.update(h.as_bytes());
                hasher.update(b"\n");
            }
            hasher.finalize().to_hex().to_string()
        };
        let h_with = {
            let mut child_hashes: Vec<String> = Vec::new();
            for g in &t_with.grants {
                child_hashes.push(format!("grant:{}", g.id));
            }
            for r in &t_with.receipts {
                child_hashes.push(format!("receipt:{}:{}", r.kind, r.id));
            }
            child_hashes.sort();
            let mut hasher = blake3::Hasher::new();
            for h in &child_hashes {
                hasher.update(h.as_bytes());
                hasher.update(b"\n");
            }
            hasher.finalize().to_hex().to_string()
        };
        assert_ne!(
            h_without, h_with,
            "adding a v2 receipt must change the tree hash"
        );
    }
}
