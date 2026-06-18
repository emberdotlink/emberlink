//! Merkle root for permits per ADR 118 §"Merkle leaf format".
//! Each leaf = `blake3(JCS({ts, tool, input_hash, resolved}))`.

use blake3::Hasher;
use serde::Serialize;

use super::body::ClaimSegmentDigest;

/// Compute a single leaf hash. Caller passes the canonical leaf payload.
pub fn merkle_leaf(canonical_leaf: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(canonical_leaf);
    *hasher.finalize().as_bytes()
}

/// Compute Merkle root over a list of leaf hashes (binary tree, blake3 inner-node hash).
/// Returns all-zeros for empty input.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for chunk in layer.chunks(2) {
            let mut hasher = Hasher::new();
            hasher.update(&chunk[0]);
            if chunk.len() == 2 {
                hasher.update(&chunk[1]);
            } else {
                // Odd leaf: duplicate per RFC 6962 convention.
                hasher.update(&chunk[0]);
            }
            next.push(*hasher.finalize().as_bytes());
        }
        layer = next;
    }
    layer[0]
}

/// Canonical leaf for one segment digest in a segmented session/composite
/// receipt. This is intentionally line-based rather than JSON-based so the
/// contract stays bit-stable without introducing another canonical JSON
/// dependency at the receipt-merkle seam.
pub fn claim_segment_digest_leaf(digest: &ClaimSegmentDigest) -> [u8; 32] {
    let canonical = format!(
        "segment_no={}\nfirst_scope_seq={}\nlast_scope_seq={}\nclaim_count={}\nstarted_at={}\nended_at={}\nmerkle_root={}",
        digest.segment_no,
        digest.first_scope_seq,
        digest.last_scope_seq,
        digest.claim_count,
        digest.started_at,
        digest.ended_at,
        digest.merkle_root
    );
    merkle_leaf(canonical.as_bytes())
}

/// Full-scope history root over segment digests.
///
/// This is distinct from `ReceiptBody.permits_merkle_root`, which continues to
/// cover only the inline `claim_events[]` carried in the receipt body. For
/// truncated session/composite bodies, `claim_history_merkle_root` anchors the
/// complete claim history represented by `claim_segment_summaries[]`.
pub fn claim_history_merkle_root(digests: &[ClaimSegmentDigest]) -> String {
    if digests.is_empty() {
        return String::new();
    }
    let mut ordered = digests.to_vec();
    ordered.sort_by_key(|digest| digest.segment_no);
    let leaves: Vec<[u8; 32]> = ordered.iter().map(claim_segment_digest_leaf).collect();
    hex_lower(&merkle_root(&leaves))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[allow(dead_code)]
#[derive(Serialize)]
struct LeafPayload<'a> {
    ts: &'a str,
    tool: &'a str,
    input_hash: &'a str,
    resolved: &'a serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::body::ClaimSegmentDigest;

    #[test]
    fn empty_root_is_zero() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_leaf_root_equals_leaf() {
        let leaf = merkle_leaf(b"hello");
        let root = merkle_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn two_leaves_deterministic() {
        let a = merkle_leaf(b"a");
        let b = merkle_leaf(b"b");
        let root1 = merkle_root(&[a, b]);
        let root2 = merkle_root(&[a, b]);
        assert_eq!(root1, root2);
    }

    #[test]
    fn odd_leaf_duplicates() {
        let a = merkle_leaf(b"a");
        let b = merkle_leaf(b"b");
        let c = merkle_leaf(b"c");
        let root = merkle_root(&[a, b, c]);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn claim_history_root_empty_is_empty_string() {
        assert_eq!(claim_history_merkle_root(&[]), "");
    }

    #[test]
    fn claim_history_root_is_order_stable_by_segment_number() {
        let a = ClaimSegmentDigest {
            segment_no: 1,
            first_scope_seq: 65,
            last_scope_seq: 72,
            claim_count: 8,
            started_at: "2026-05-22T12:05:00Z".into(),
            ended_at: "2026-05-22T12:10:00Z".into(),
            merkle_root: "bbbb".into(),
        };
        let b = ClaimSegmentDigest {
            segment_no: 0,
            first_scope_seq: 1,
            last_scope_seq: 64,
            claim_count: 64,
            started_at: "2026-05-22T12:00:00Z".into(),
            ended_at: "2026-05-22T12:05:00Z".into(),
            merkle_root: "aaaa".into(),
        };
        let root1 = claim_history_merkle_root(&[a.clone(), b.clone()]);
        let root2 = claim_history_merkle_root(&[b, a]);
        assert_eq!(root1, root2);
        assert!(!root1.is_empty());
    }
}
