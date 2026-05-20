use std::collections::{BTreeMap, BTreeSet};

use core_events::receipt::envelope::ReceiptEnvelope;
use serde::{Deserialize, Serialize};

use crate::infra::receipt::current_identity;
use crate::infra::store::DaemonStore;
use crate::trust::grant::GrantInfo;

#[derive(Debug, thiserror::Error)]
pub enum ReceiptTreeError {
    #[error("grant '{0}' not found")]
    UnknownRoot(String),
    #[error("daemon store: {0}")]
    Store(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("receipt tree requires an initialised daemon identity")]
    IdentityUnavailable,
    #[error("verify FAILED for {artifact}: {reason}")]
    VerifyGap { artifact: String, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeExport {
    pub version: String,
    pub root_grant_id: String,
    pub grants: Vec<TreeGrant>,
    pub receipts: Vec<TreeReceipt>,
    pub spawn_witnesses: Vec<TreeSpawnWitness>,
    pub daemon_pubkey_hex: String,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeReceipt {
    pub id: String,
    pub grant_id: String,
    pub kind: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeSpawnWitness {
    pub receipt_id: String,
    pub spawn_grant_id: String,
    pub parent_pubkey_hex: String,
    pub envelope: ReceiptEnvelope,
}

pub const TREE_VERSION: &str = "v2";

pub fn build_tree(
    store: &DaemonStore,
    root_grant_id: &str,
) -> Result<TreeExport, ReceiptTreeError> {
    let daemon_pubkey_hex = current_identity()
        .ok_or(ReceiptTreeError::IdentityUnavailable)?
        .pubkey_hex();

    let all_grants = store
        .list_grants()
        .map_err(|e| ReceiptTreeError::Store(e.to_string()))?;
    let mut by_id: BTreeMap<String, GrantInfo> = BTreeMap::new();
    let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for g in all_grants {
        if let Some(pid) = &g.parent_grant_id {
            children.entry(pid.clone()).or_default().push(g.id.clone());
        }
        by_id.insert(g.id.clone(), g);
    }

    if !by_id.contains_key(root_grant_id) {
        return Err(ReceiptTreeError::UnknownRoot(root_grant_id.to_string()));
    }

    let mut order: Vec<String> = Vec::new();
    let mut stack: Vec<String> = vec![root_grant_id.to_string()];
    while let Some(id) = stack.pop() {
        order.push(id.clone());
        if let Some(kids) = children.get(&id) {
            for kid in kids {
                stack.push(kid.clone());
            }
        }
    }

    let mut tree_grants: Vec<TreeGrant> = Vec::with_capacity(order.len());
    for id in &order {
        if let Some(g) = by_id.get(id) {
            tree_grants.push(TreeGrant::from(g));
        }
    }

    let grant_id_set: BTreeSet<&str> = order.iter().map(String::as_str).collect();
    let all_receipts = store
        .list_receipts(None)
        .map_err(|e| ReceiptTreeError::Store(e.to_string()))?;
    let mut tree_receipts: Vec<TreeReceipt> = Vec::new();
    for r in &all_receipts {
        if grant_id_set.contains(r.grant_id.as_str()) {
            tree_receipts.push(TreeReceipt {
                id: r.id.clone(),
                grant_id: r.grant_id.clone(),
                kind: "v1".to_string(),
                payload: serde_json::to_value(r)?,
            });
        }
    }

    let v2_envelopes = store
        .list_receipts_v2_envelopes(&order)
        .map_err(|e| ReceiptTreeError::Store(e.to_string()))?;
    for (id, _kind, grant_id, envelope) in v2_envelopes {
        tree_receipts.push(TreeReceipt {
            id,
            grant_id,
            kind: "v2".to_string(),
            payload: serde_json::to_value(&envelope)?,
        });
    }

    let raw_witnesses = store
        .list_spawn_witnesses_for_grants(&order)
        .map_err(|e| ReceiptTreeError::Store(e.to_string()))?;
    let mut spawn_witnesses: Vec<TreeSpawnWitness> = Vec::with_capacity(raw_witnesses.len());
    for (envelope, parent_persona_id) in raw_witnesses {
        let parent_pubkey_hex = match store.get_persona(&parent_persona_id) {
            Ok(p) => p.public_key,
            Err(e) => {
                return Err(ReceiptTreeError::VerifyGap {
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
