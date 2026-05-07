//! Merkle root for permits per design §"Merkle leaf format".
//! Each leaf = `blake3(JCS({ts, tool, input_hash, resolved}))`.

use blake3::Hasher;
use serde::Serialize;

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
}
