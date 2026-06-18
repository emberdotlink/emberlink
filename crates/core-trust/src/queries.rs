//! Trust graph query API (P32).
//!
//! Convenience functions for querying the trust graph — who trusts whom,
//! active grants, and BFS network traversal. All functions are pure
//! (no I/O) and WASM-compatible.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use core_principals::TrustAttestation;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Summary of a single trust relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSummary {
    pub attestor: String,
    pub subject: String,
    pub domain: String,
    pub score: f32,
}

/// A node in the trust graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustNode {
    pub id: String,
    pub depth: usize,
}

/// A directed edge in the trust graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEdge {
    pub from: String,
    pub to: String,
    pub domain: String,
    pub score: f32,
}

/// A subgraph of the trust network reachable from a starting persona.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGraph {
    pub nodes: Vec<TrustNode>,
    pub edges: Vec<TrustEdge>,
}

// ---------------------------------------------------------------------------
// Query functions
// ---------------------------------------------------------------------------

/// Maximum BFS traversal depth to prevent DoS on large graphs.
pub const MAX_NETWORK_DEPTH: usize = 10;

/// Maximum number of nodes returned by `trust_network` to bound memory.
const MAX_NETWORK_NODES: usize = 1000;

/// Filter out recipient-bound attestations (ADR 008: local-only data boundary).
/// Only public (unbound) attestations are visible in queries.
fn public_attestations(attestations: &[TrustAttestation]) -> Vec<&TrustAttestation> {
    attestations
        .iter()
        .filter(|a| a.recipient_bound.is_none())
        .collect()
}

/// All *public* trust attestations where `subject` is the target — "who trusts this persona?"
/// Recipient-bound attestations are excluded (ADR 008).
pub fn who_trusts(attestations: &[TrustAttestation], subject: &str) -> Vec<TrustSummary> {
    public_attestations(attestations)
        .into_iter()
        .filter(|a| a.subject == subject)
        .map(|a| TrustSummary {
            attestor: a.attester.clone(),
            subject: a.subject.clone(),
            domain: a.domain.clone(),
            score: a.score,
        })
        .collect()
}

/// All *public* trust attestations issued by `attestor` — "who does this persona trust?"
/// Recipient-bound attestations are excluded (ADR 008).
pub fn who_i_trust(attestations: &[TrustAttestation], attestor: &str) -> Vec<TrustSummary> {
    public_attestations(attestations)
        .into_iter()
        .filter(|a| a.attester == attestor)
        .map(|a| TrustSummary {
            attestor: a.attester.clone(),
            subject: a.subject.clone(),
            domain: a.domain.clone(),
            score: a.score,
        })
        .collect()
}

/// BFS traversal of the *public* trust graph from `start`, following outbound trust edges
/// up to `max_depth` hops (clamped to [`MAX_NETWORK_DEPTH`]). Returns the discovered subgraph
/// with at most [`MAX_NETWORK_NODES`] nodes to prevent DoS.
///
/// Recipient-bound attestations are excluded (ADR 008).
pub fn trust_network(
    attestations: &[TrustAttestation],
    start: &str,
    max_depth: usize,
) -> TrustGraph {
    let max_depth = max_depth.min(MAX_NETWORK_DEPTH);

    // Build adjacency from public attestations only.
    let mut adj: BTreeMap<&str, Vec<(&str, &str, f32)>> = BTreeMap::new();
    for a in public_attestations(attestations) {
        adj.entry(a.attester.as_str()).or_default().push((
            a.subject.as_str(),
            a.domain.as_str(),
            a.score,
        ));
    }

    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut queue: VecDeque<(&str, usize)> = VecDeque::new();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    visited.insert(start);
    queue.push_back((start, 0));
    nodes.push(TrustNode {
        id: start.to_string(),
        depth: 0,
    });

    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        if let Some(neighbors) = adj.get(node) {
            for &(subject, domain, score) in neighbors {
                edges.push(TrustEdge {
                    from: node.to_string(),
                    to: subject.to_string(),
                    domain: domain.to_string(),
                    score,
                });
                if !visited.contains(subject) {
                    visited.insert(subject);
                    queue.push_back((subject, depth + 1));
                    nodes.push(TrustNode {
                        id: subject.to_string(),
                        depth: depth + 1,
                    });
                    if nodes.len() >= MAX_NETWORK_NODES {
                        return TrustGraph { nodes, edges };
                    }
                }
            }
        }
    }

    TrustGraph { nodes, edges }
}

// ---------------------------------------------------------------------------
// Trust graph export
// ---------------------------------------------------------------------------

/// A node in the exported visualization graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub node_type: String,
}

/// An edge in the exported visualization graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub edge_type: String,
    pub label: Option<String>,
    pub weight: Option<f64>,
}

/// Combined trust graph export for visualization tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGraphExport {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

/// Export a visualization-ready trust graph rooted at `start`, combining trust
/// attestations into a unified node/edge format. Filters out recipient-bound
/// attestations (ADR 008).
pub fn export_trust_graph(
    attestations: &[TrustAttestation],
    start: &str,
    max_depth: usize,
) -> TrustGraphExport {
    let graph = trust_network(attestations, start, max_depth);

    let nodes = graph
        .nodes
        .into_iter()
        .map(|n| GraphNode {
            id: n.id,
            node_type: "persona".to_string(),
        })
        .collect();

    let edges = graph
        .edges
        .into_iter()
        .map(|e| GraphEdge {
            from: e.from,
            to: e.to,
            edge_type: "trust".to_string(),
            label: Some(e.domain),
            weight: Some(e.score as f64),
        })
        .collect();

    TrustGraphExport { nodes, edges }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn att(attester: &str, subject: &str, domain: &str, score: f32) -> TrustAttestation {
        TrustAttestation {
            id: format!("att:{attester}:{subject}:{domain}"),
            attester: attester.to_string(),
            subject: subject.to_string(),
            domain: domain.to_string(),
            score,
            recipient_bound: None,
        }
    }

    fn indexed_attestation(idx: usize, from: u8, to: u8) -> TrustAttestation {
        let attester = format!("node_{}", from % 8);
        let subject = format!("node_{}", to % 8);
        TrustAttestation {
            id: format!("att:{idx}:{attester}:{subject}"),
            attester,
            subject,
            domain: "relay".to_string(),
            score: 1.0,
            recipient_bound: None,
        }
    }

    fn private_attestation(idx: u8) -> TrustAttestation {
        TrustAttestation {
            id: format!("att:private:{idx}"),
            attester: "node_0".to_string(),
            subject: format!("private_{idx}"),
            domain: "relay".to_string(),
            score: 1.0,
            recipient_bound: Some("peer-only".to_string()),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn trust_network_keeps_public_bfs_bounded_and_recipient_private(
            pairs in proptest::collection::vec((0u8..8, 0u8..8), 0..32),
            private_indices in proptest::collection::vec(0u8..8, 0..8),
            max_depth in 0usize..16,
        ) {
            let mut attestations: Vec<TrustAttestation> = pairs
                .into_iter()
                .enumerate()
                .map(|(idx, (from, to))| indexed_attestation(idx, from, to))
                .collect();
            attestations.extend(private_indices.into_iter().map(private_attestation));

            let graph = trust_network(&attestations, "node_0", max_depth);
            let effective_depth = max_depth.min(MAX_NETWORK_DEPTH);
            let mut seen = BTreeSet::new();
            let mut depths = std::collections::BTreeMap::new();

            for node in &graph.nodes {
                prop_assert!(seen.insert(node.id.as_str()), "duplicate node {}", node.id);
                prop_assert!(
                    node.depth <= effective_depth,
                    "node {} exceeded max depth {effective_depth}: {}",
                    node.id,
                    node.depth
                );
                prop_assert!(
                    !node.id.starts_with("private_"),
                    "recipient-bound node leaked into public trust graph: {}",
                    node.id
                );
                depths.insert(node.id.as_str(), node.depth);
            }

            prop_assert_eq!(depths.get("node_0"), Some(&0));

            for edge in &graph.edges {
                prop_assert!(
                    !edge.from.starts_with("private_") && !edge.to.starts_with("private_"),
                    "recipient-bound edge leaked into public trust graph: {:?}",
                    edge
                );
                let from_depth = depths
                    .get(edge.from.as_str())
                    .copied()
                    .ok_or_else(|| TestCaseError::fail(format!("edge from missing node: {edge:?}")))?;
                prop_assert!(
                    from_depth < effective_depth,
                    "edge emitted from depth-limited node at depth {from_depth}: {:?}",
                    edge
                );
                prop_assert!(
                    depths.contains_key(edge.to.as_str()),
                    "edge target missing from node set: {:?}",
                    edge
                );
            }
        }
    }

    #[test]
    fn who_trusts_filters_by_subject() {
        let attestations = vec![
            att("alice", "bob", "relay", 0.8),
            att("carol", "bob", "relay", 0.6),
            att("dave", "erin", "relay", 0.9),
        ];
        let result = who_trusts(&attestations, "bob");
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|s| s.subject == "bob"));
    }

    #[test]
    fn who_trusts_empty_for_unknown_subject() {
        let attestations = vec![att("alice", "bob", "relay", 0.8)];
        assert!(who_trusts(&attestations, "nobody").is_empty());
    }

    #[test]
    fn who_i_trust_filters_by_attestor() {
        let attestations = vec![
            att("alice", "bob", "relay", 0.8),
            att("alice", "carol", "storage", 0.7),
            att("dave", "erin", "relay", 0.9),
        ];
        let result = who_i_trust(&attestations, "alice");
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|s| s.attestor == "alice"));
    }

    #[test]
    fn trust_network_bfs_depth_1() {
        let attestations = vec![
            att("alice", "bob", "relay", 0.8),
            att("alice", "carol", "relay", 0.7),
            att("bob", "dave", "relay", 0.6),
        ];
        let graph = trust_network(&attestations, "alice", 1);
        // alice + bob + carol at depth 1
        assert_eq!(graph.nodes.len(), 3);
        // alice->bob and alice->carol edges
        assert_eq!(graph.edges.len(), 2);
        // dave should NOT be in nodes (depth 2)
        assert!(!graph.nodes.iter().any(|n| n.id == "dave"));
    }

    #[test]
    fn trust_network_bfs_depth_2() {
        let attestations = vec![
            att("alice", "bob", "relay", 0.8),
            att("bob", "carol", "relay", 0.7),
            att("carol", "dave", "relay", 0.6),
        ];
        let graph = trust_network(&attestations, "alice", 2);
        assert_eq!(graph.nodes.len(), 3); // alice, bob, carol
        assert!(graph.nodes.iter().any(|n| n.id == "carol" && n.depth == 2));
        assert!(!graph.nodes.iter().any(|n| n.id == "dave"));
    }

    #[test]
    fn trust_network_handles_cycles() {
        let attestations = vec![
            att("alice", "bob", "relay", 0.8),
            att("bob", "alice", "relay", 0.7),
        ];
        let graph = trust_network(&attestations, "alice", 5);
        assert_eq!(graph.nodes.len(), 2); // no infinite loop
    }

    #[test]
    fn who_trusts_excludes_recipient_bound() {
        let attestations = vec![
            att("alice", "bob", "relay", 0.8),
            TrustAttestation {
                id: "att:private".into(),
                attester: "carol".into(),
                subject: "bob".into(),
                domain: "relay".into(),
                score: 0.6,
                recipient_bound: Some("specific-peer".into()),
            },
        ];
        let result = who_trusts(&attestations, "bob");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].attestor, "alice");
    }

    #[test]
    fn trust_network_excludes_recipient_bound() {
        let attestations = vec![
            att("alice", "bob", "relay", 0.8),
            TrustAttestation {
                id: "att:private".into(),
                attester: "alice".into(),
                subject: "secret".into(),
                domain: "relay".into(),
                score: 0.9,
                recipient_bound: Some("peer-only".into()),
            },
        ];
        let graph = trust_network(&attestations, "alice", 2);
        assert!(!graph.nodes.iter().any(|n| n.id == "secret"));
    }

    #[test]
    fn trust_network_depth_zero_returns_only_start() {
        let attestations = vec![att("alice", "bob", "relay", 0.8)];
        let graph = trust_network(&attestations, "alice", 0);
        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.nodes[0].id, "alice");
        assert!(graph.edges.is_empty());
    }
}
