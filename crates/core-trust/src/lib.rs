pub mod queries;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use core_crypto::Signer;
use core_event_types::{
    EventBody, EventRefRelation, SignerBinding, TrustAttestedEvent, TrustRevokedEvent,
};
use core_events::EventEnvelope;
use core_principals::{DerivedTrustStatement, TrustExplanation};
use core_principals::{TrustAttestation, TrustThreshold};

// ---------------------------------------------------------------------------
// Badge authority weighting (ADR 030)
// ---------------------------------------------------------------------------

/// Default maximum trust graph traversal depth for authority weighting.
pub const DEFAULT_MAX_DEPTH: u32 = 3;

/// Authority weight scores for a badge as seen from a specific viewer's trust graph.
///
/// All sub-scores are normalized to `[0.0, 1.0]`. `total` is a weighted combination.
#[derive(Debug, Clone, PartialEq)]
pub struct BadgeWeight {
    /// Score based on how many identities in the trust graph recognize this issuer.
    /// Normalized: `convergence_count / first_degree_peer_count` (capped at 1.0).
    pub convergence_score: f32,
    /// How many first-degree peers have a trust edge toward the issuer.
    pub convergence_count: u32,
    /// Score based on shortest path from viewer to issuer (1.0 = direct, 0.0 = beyond max depth).
    pub distance_score: f32,
    /// Shortest path in hops from viewer to issuer. `None` means unreachable within max depth.
    pub graph_distance: Option<u32>,
    /// Score based on the issuer's inbound trust signals relative to badges issued.
    /// High issue-to-trust ratio signals spam; balanced ratio signals reputation.
    pub issuer_score: f32,
    /// Inbound trust attestations pointing at the issuer.
    pub issuer_inbound_trust_count: u32,
    /// Total badges the issuer has issued (across all recipients).
    pub issuer_badges_issued: u32,
    /// Weighted combination of all sub-scores. Range: `[0.0, 1.0]`.
    pub total: f32,
}

/// Input data for badge authority weight computation.
/// Passed as a single struct to keep the pure function signature clean.
pub struct BadgeWeightInput<'a> {
    /// Persona ID of the badge issuer being evaluated.
    pub issuer_id: &'a str,
    /// Persona ID of the viewer computing authority.
    pub viewer_id: &'a str,
    /// All trust attestations available in the viewer's local store.
    pub trust_edges: &'a [TrustAttestation],
    /// Total number of badges the issuer has issued (supplied by caller from badge store).
    pub issuer_badges_issued: u32,
    /// Maximum graph traversal depth. Use [`DEFAULT_MAX_DEPTH`] if unsure.
    pub max_depth: u32,
}

/// Compute authority weight for a badge issuer as seen from a viewer's trust graph.
///
/// This is a pure function — no I/O, no side effects, deterministic given the same inputs.
///
/// # Scoring
/// - **distance_score**: `1.0` if issuer == viewer, `1/(depth)` for each hop, `0.0` if unreachable.
/// - **convergence_score**: fraction of first-degree peers who have any trust edge to the issuer.
/// - **issuer_score**: based on inbound trust signals vs badges issued. High badge volume with few
///   inbound trust signals signals spam; balanced ratio signals genuine reputation.
/// - **total**: weighted sum — distance 40%, convergence 40%, issuer reputation 20%.
pub fn compute_badge_weight(input: &BadgeWeightInput<'_>) -> BadgeWeight {
    let issuer_id = input.issuer_id;
    let viewer_id = input.viewer_id;
    let trust_edges = input.trust_edges;
    let max_depth = input.max_depth.max(1);

    // --- Graph distance via BFS over trust edges ---
    // Build adjacency list: attester -> set of subjects they trust
    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in trust_edges {
        adj.entry(edge.attester.as_str())
            .or_default()
            .push(edge.subject.as_str());
    }

    let graph_distance: Option<u32> = if issuer_id == viewer_id {
        Some(0)
    } else {
        bfs_shortest_path(viewer_id, issuer_id, &adj, max_depth)
    };

    // If issuer is unreachable within max_depth, all scores are zero.
    // Authority from an identity you can't reach through your trust graph is meaningless.
    if graph_distance.is_none() {
        return BadgeWeight {
            convergence_score: 0.0,
            convergence_count: 0,
            distance_score: 0.0,
            graph_distance: None,
            issuer_score: 0.0,
            issuer_inbound_trust_count: 0,
            issuer_badges_issued: input.issuer_badges_issued,
            total: 0.0,
        };
    }

    let distance_score: f32 = match graph_distance {
        Some(0) => 1.0,
        Some(d) => 1.0 / (d as f32),
        None => 0.0,
    };

    // --- Convergence: first-degree peers who have a trust edge to the issuer ---
    // First-degree peers = identities that viewer directly trusts (one hop)
    let first_degree_peers: Vec<&str> = adj
        .get(viewer_id)
        .map(|v| v.as_slice())
        .unwrap_or(&[])
        .to_vec();

    let first_degree_count = first_degree_peers.len() as u32;

    // Among all nodes reachable within max_depth, count those with a trust edge to issuer
    let reachable = reachable_nodes(viewer_id, &adj, max_depth);

    let convergence_count: u32 = trust_edges
        .iter()
        .filter(|e| e.subject == issuer_id && reachable.contains(e.attester.as_str()))
        .count() as u32;

    let convergence_score: f32 = if first_degree_count == 0 {
        // No peers at all — convergence is unknowable; treat as neutral (0.5) since issuer is reachable
        0.5
    } else {
        // Normalize by first-degree count, cap at 1.0
        (convergence_count as f32 / first_degree_count as f32).min(1.0)
    };

    // --- Issuer reputation: inbound trust signals vs badges issued ---
    let issuer_inbound_trust_count: u32 = trust_edges
        .iter()
        .filter(|e| e.subject == issuer_id)
        .count() as u32;

    let badges_issued = input.issuer_badges_issued;

    let issuer_score: f32 = compute_issuer_score(issuer_inbound_trust_count, badges_issued);

    // --- Weighted total: distance 40%, convergence 40%, issuer 20% ---
    let total =
        (0.40 * distance_score + 0.40 * convergence_score + 0.20 * issuer_score).clamp(0.0, 1.0);

    BadgeWeight {
        convergence_score,
        convergence_count,
        distance_score,
        graph_distance,
        issuer_score,
        issuer_inbound_trust_count,
        issuer_badges_issued: badges_issued,
        total,
    }
}

/// BFS to find shortest path length from `start` to `target`, bounded by `max_depth`.
fn bfs_shortest_path<'a>(
    start: &'a str,
    target: &'a str,
    adj: &BTreeMap<&'a str, Vec<&'a str>>,
    max_depth: u32,
) -> Option<u32> {
    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut queue: VecDeque<(&str, u32)> = VecDeque::new();
    visited.insert(start);
    queue.push_back((start, 0));

    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        if let Some(neighbors) = adj.get(node) {
            for &neighbor in neighbors {
                if neighbor == target {
                    return Some(depth + 1);
                }
                if !visited.contains(neighbor) {
                    visited.insert(neighbor);
                    queue.push_back((neighbor, depth + 1));
                }
            }
        }
    }
    None
}

/// Collect all node IDs reachable from `start` within `max_depth` hops.
fn reachable_nodes<'a>(
    start: &'a str,
    adj: &BTreeMap<&'a str, Vec<&'a str>>,
    max_depth: u32,
) -> BTreeSet<&'a str> {
    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut queue: VecDeque<(&str, u32)> = VecDeque::new();
    visited.insert(start);
    queue.push_back((start, 0));

    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        if let Some(neighbors) = adj.get(node) {
            for &neighbor in neighbors {
                if !visited.contains(neighbor) {
                    visited.insert(neighbor);
                    queue.push_back((neighbor, depth + 1));
                }
            }
        }
    }
    visited
}

/// Compute a normalized issuer reputation score from inbound trust signals and badge volume.
///
/// - An issuer with many inbound trust signals and moderate badge volume scores high.
/// - An issuer with zero inbound signals and high badge volume scores low (spam signal).
/// - A new issuer with no history scores neutral (0.5).
fn compute_issuer_score(inbound_trust: u32, badges_issued: u32) -> f32 {
    if inbound_trust == 0 && badges_issued == 0 {
        // Unknown issuer — neutral
        return 0.5;
    }
    if inbound_trust == 0 {
        // Issues badges but nobody trusts them
        return 0.0;
    }
    // Ratio: inbound trust / badges issued, capped at 1.0
    // High trust-to-badge ratio = high quality issuer
    // Low ratio (spammer) approaches 0
    let ratio = inbound_trust as f32 / (badges_issued as f32).max(1.0);
    ratio.min(1.0)
}

// ---------------------------------------------------------------------------
// Dispute weighting (ADR 030 counter-attestation)
// ---------------------------------------------------------------------------

/// A single dispute to factor into badge authority scoring.
pub struct DisputeInput<'a> {
    /// Persona ID of the identity that filed the dispute.
    pub disputer_id: &'a str,
}

/// Compute a dispute penalty for a badge, reducing authority based on disputes
/// from identities in the viewer's trust graph. Closer/more-trusted disputers
/// carry more weight.
///
/// Returns a penalty in `[0.0, 1.0]` — subtract from or multiply against the badge weight total.
/// - 0.0 = no disputes or all disputers are unreachable
/// - 1.0 = maximum penalty (many close disputers)
pub fn compute_dispute_penalty(
    viewer_id: &str,
    disputes: &[DisputeInput<'_>],
    trust_edges: &[TrustAttestation],
    max_depth: u32,
) -> f32 {
    if disputes.is_empty() {
        return 0.0;
    }

    let max_depth = max_depth.max(1);

    // Build adjacency list
    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in trust_edges {
        adj.entry(edge.attester.as_str())
            .or_default()
            .push(edge.subject.as_str());
    }

    // For each dispute, compute a weight based on graph distance from viewer to disputer.
    // Close disputers (distance=1) contribute more penalty than distant ones.
    let mut total_weight: f32 = 0.0;

    for dispute in disputes {
        let distance = if dispute.disputer_id == viewer_id {
            Some(0)
        } else {
            bfs_shortest_path(viewer_id, dispute.disputer_id, &adj, max_depth)
        };

        match distance {
            Some(0) => total_weight += 1.0, // viewer themselves disputes
            Some(1) => total_weight += 0.8, // direct peer disputes
            Some(2) => total_weight += 0.4, // two hops away
            Some(d) => total_weight += 1.0 / (d as f32), // diminishing
            None => {}                      // unreachable = no weight
        }
    }

    // Normalize: cap penalty at 1.0. A single close dispute can cause significant penalty,
    // multiple distant disputes accumulate.
    total_weight.min(1.0)
}

/// Adjust a badge weight total by applying the dispute penalty.
/// Returns the adjusted total, clamped to `[0.0, 1.0]`.
pub fn apply_dispute_penalty(badge_weight_total: f32, dispute_penalty: f32) -> f32 {
    (badge_weight_total * (1.0 - dispute_penalty)).clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Badge-gated grant condition evaluation
// ---------------------------------------------------------------------------

/// Input for evaluating badge-gated grant conditions.
pub struct BadgeGateInput<'a> {
    /// Persona ID of the grant issuer (viewer for trust graph).
    pub issuer_persona_id: &'a str,
    /// Persona ID of the claimant whose badges are checked.
    pub claimant_persona_id: &'a str,
    /// All badges held by the claimant (active, non-revoked, non-expired).
    pub claimant_badges: &'a [ClaimantBadge<'a>],
    /// Trust edges available in the issuer's local store.
    pub trust_edges: &'a [TrustAttestation],
    /// Badge issuance counts per issuer persona, for issuer_score computation.
    /// Key: issuer persona ID, Value: total badges issued by that persona.
    pub issuer_badge_counts: &'a std::collections::BTreeMap<String, u32>,
    /// Maximum graph traversal depth. Use [`DEFAULT_MAX_DEPTH`] if unsure.
    pub max_depth: u32,
}

/// A badge held by the claimant, with enough metadata for gate evaluation.
pub struct ClaimantBadge<'a> {
    pub badge_type: &'a str,
    pub issuer_persona_id: &'a str,
}

/// Result of evaluating a single `GrantCondition` against a claimant.
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionResult {
    /// The condition is satisfied.
    Met,
    /// The condition is not satisfied, with a human-readable reason.
    Unmet(String),
}

impl ConditionResult {
    pub fn is_met(&self) -> bool {
        matches!(self, Self::Met)
    }
}

/// Evaluate a list of grant conditions against a claimant's badges.
///
/// Returns `Met` only if ALL conditions are satisfied. On first failure,
/// returns `Unmet` with the reason.
pub fn evaluate_grant_conditions(
    conditions: &[core_grant_types::grant_conditions::GrantCondition],
    input: &BadgeGateInput<'_>,
) -> ConditionResult {
    if conditions.is_empty() {
        return ConditionResult::Met;
    }
    for condition in conditions {
        let result = evaluate_single_condition(condition, input);
        if !result.is_met() {
            return result;
        }
    }
    ConditionResult::Met
}

fn evaluate_single_condition(
    condition: &core_grant_types::grant_conditions::GrantCondition,
    input: &BadgeGateInput<'_>,
) -> ConditionResult {
    use core_grant_types::grant_conditions::GrantCondition;

    match condition {
        GrantCondition::BadgeGate {
            badge_type,
            min_convergence,
            max_distance,
            min_authority,
        } => {
            // Find matching badges held by the claimant.
            let matching_badges: Vec<_> = input
                .claimant_badges
                .iter()
                .filter(|b| b.badge_type == badge_type)
                .collect();

            if matching_badges.is_empty() {
                return ConditionResult::Unmet(format!(
                    "claimant does not hold badge of type '{badge_type}'"
                ));
            }

            // Check if ANY matching badge satisfies all threshold requirements.
            for badge in &matching_badges {
                let badges_issued = input
                    .issuer_badge_counts
                    .get(badge.issuer_persona_id)
                    .copied()
                    .unwrap_or(0);

                let weight = compute_badge_weight(&BadgeWeightInput {
                    issuer_id: badge.issuer_persona_id,
                    viewer_id: input.issuer_persona_id,
                    trust_edges: input.trust_edges,
                    issuer_badges_issued: badges_issued,
                    max_depth: input.max_depth,
                });

                // Check convergence threshold.
                if let Some(min_c) = min_convergence
                    && (weight.convergence_score as f64) < *min_c
                {
                    continue; // try next matching badge
                }

                // Check distance threshold.
                if let Some(max_d) = max_distance {
                    match weight.graph_distance {
                        Some(d) if d <= *max_d => {}
                        _ => continue, // unreachable or too far
                    }
                }

                // Check authority threshold.
                if let Some(min_a) = min_authority
                    && (weight.total as f64) < *min_a
                {
                    continue;
                }

                // All thresholds met for this badge.
                return ConditionResult::Met;
            }

            // No matching badge met all thresholds.
            ConditionResult::Unmet(format!(
                "badge '{badge_type}' held but does not meet threshold requirements"
            ))
        }

        GrantCondition::All(sub_conditions) => {
            // GC-H1 defence in depth: deserialization rejects empty `All`,
            // but if an empty variant is constructed in-process (e.g. by a
            // future internal builder bug), fail closed instead of silently
            // returning `Met` via vacuous truth.
            if sub_conditions.is_empty() {
                return ConditionResult::Unmet(
                    "empty All combinator: no sub-conditions specified (fail-closed)".to_string(),
                );
            }
            for sub in sub_conditions {
                let result = evaluate_single_condition(sub, input);
                if !result.is_met() {
                    return result;
                }
            }
            ConditionResult::Met
        }

        GrantCondition::Any(sub_conditions) => {
            // GC-H1 defence in depth: deserialization rejects empty `Any`.
            // If a malformed variant somehow reaches the evaluator, fail
            // closed instead of short-circuiting to `Met`.
            if sub_conditions.is_empty() {
                return ConditionResult::Unmet(
                    "empty Any combinator: no alternatives provided (fail-closed)".to_string(),
                );
            }
            let mut last_reason = String::new();
            for sub in sub_conditions {
                let result = evaluate_single_condition(sub, input);
                if result.is_met() {
                    return ConditionResult::Met;
                }
                if let ConditionResult::Unmet(reason) = result {
                    last_reason = reason;
                }
            }
            ConditionResult::Unmet(format!(
                "none of the alternatives were satisfied: {last_reason}"
            ))
        }
    }
}

pub fn trust_attested_event(
    event_id: impl Into<String>,
    attestation: TrustAttestation,
    signer_binding: SignerBinding,
    signer: &impl Signer,
) -> Result<EventEnvelope, core_types::ValidationError> {
    EventEnvelope::from_body(
        event_id,
        EventBody::TrustAttested(TrustAttestedEvent {
            attestation_id: attestation.id,
            attester_persona_id: attestation.attester,
            subject_persona_id: attestation.subject,
            domain: attestation.domain,
            score: attestation.score,
            recipient_bound: attestation.recipient_bound,
        }),
        Vec::new(),
        signer_binding,
        signer,
    )
}

pub fn trust_revoked_event(
    event_id: impl Into<String>,
    attestation_id: impl Into<String>,
    attester_persona_id: impl Into<String>,
    previous_event_id: impl Into<String>,
    signer_binding: SignerBinding,
    signer: &impl Signer,
) -> Result<EventEnvelope, core_types::ValidationError> {
    EventEnvelope::from_body(
        event_id,
        EventBody::TrustRevoked(TrustRevokedEvent {
            attestation_id: attestation_id.into(),
            attester_persona_id: attester_persona_id.into(),
        }),
        vec![core_events::EventRef {
            relation: EventRefRelation::Previous,
            target_event_id: previous_event_id.into(),
            seq: 0,
        }],
        signer_binding,
        signer,
    )
}

pub fn derive_score(
    attestations: &[TrustAttestation],
    subject: &str,
    domain: &str,
) -> Option<DerivedTrustStatement> {
    derive_score_for_recipient(attestations, subject, domain, None)
}

pub fn derive_score_for_recipient(
    attestations: &[TrustAttestation],
    subject: &str,
    domain: &str,
    recipient: Option<&str>,
) -> Option<DerivedTrustStatement> {
    let matches: Vec<_> = attestations
        .iter()
        .filter(|a| {
            a.subject == subject
                && a.domain == domain
                && match (&a.recipient_bound, recipient) {
                    (None, _) => true,
                    (Some(bound), Some(viewer)) => bound == viewer,
                    (Some(_), None) => false,
                }
        })
        .collect();
    if matches.is_empty() {
        return None;
    }

    let total: f32 = matches.iter().map(|a| a.score).sum();
    Some(DerivedTrustStatement {
        id: format!("derived:{subject}:{domain}"),
        subject: subject.to_string(),
        domain: domain.to_string(),
        normalized_score: total / matches.len() as f32,
    })
}

/// Check whether a subject meets a caller-supplied trust threshold in a given domain.
/// Returns the derived score and whether it meets the threshold.
pub fn meets_threshold(
    attestations: &[TrustAttestation],
    subject: &str,
    domain: &str,
    threshold: TrustThreshold,
) -> Option<(DerivedTrustStatement, bool)> {
    let statement = derive_score(attestations, subject, domain)?;
    let met = threshold.is_met_by(statement.normalized_score);
    Some((statement, met))
}

pub fn meets_threshold_for_recipient(
    attestations: &[TrustAttestation],
    subject: &str,
    domain: &str,
    threshold: TrustThreshold,
    recipient: Option<&str>,
) -> Option<(DerivedTrustStatement, bool)> {
    let statement = derive_score_for_recipient(attestations, subject, domain, recipient)?;
    let met = threshold.is_met_by(statement.normalized_score);
    Some((statement, met))
}

pub fn explain(statement: &DerivedTrustStatement) -> TrustExplanation {
    TrustExplanation {
        summary: format!(
            "Trust score for {} in {} is {:.2}",
            statement.subject, statement.domain, statement.normalized_score
        ),
        redacted_summary: format!(
            "Trust score in {} is {:.2}",
            statement.domain, statement.normalized_score
        ),
    }
}

/// Explain a threshold check result in human-readable terms.
pub fn explain_threshold_check(
    statement: &DerivedTrustStatement,
    threshold: TrustThreshold,
    met: bool,
) -> TrustExplanation {
    let status = if met { "meets" } else { "does not meet" };
    TrustExplanation {
        summary: format!(
            "Trust score for {} in {} is {:.2} — {} threshold {:.2}",
            statement.subject,
            statement.domain,
            statement.normalized_score,
            status,
            threshold.value()
        ),
        redacted_summary: format!(
            "Trust score in {} is {:.2} — {} threshold {:.2}",
            statement.domain,
            statement.normalized_score,
            status,
            threshold.value()
        ),
    }
}

pub fn derive_public_statements(attestations: &[TrustAttestation]) -> Vec<DerivedTrustStatement> {
    let mut keys = BTreeSet::new();
    for attestation in attestations {
        keys.insert((attestation.subject.clone(), attestation.domain.clone()));
    }

    keys.into_iter()
        .filter_map(|(subject, domain)| derive_score(attestations, &subject, &domain))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::FixtureSigner;
    use core_event_types::{EventType, SignerBinding};
    use proptest::prelude::*;

    fn test_attestation(
        attester: &str,
        subject: &str,
        domain: &str,
        score: f32,
    ) -> TrustAttestation {
        TrustAttestation {
            id: format!("att:{attester}:{subject}:{domain}"),
            attester: attester.to_string(),
            subject: subject.to_string(),
            domain: domain.to_string(),
            score,
            recipient_bound: None,
        }
    }

    #[test]
    fn meets_threshold_above() {
        let attestations = vec![test_attestation("alice", "bob", "relay", 0.8)];
        let threshold = TrustThreshold::new(0.5).unwrap();
        let (statement, met) = meets_threshold(&attestations, "bob", "relay", threshold).unwrap();
        assert!(met);
        assert!((statement.normalized_score - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn meets_threshold_below() {
        let attestations = vec![test_attestation("alice", "bob", "relay", 0.2)];
        let threshold = TrustThreshold::new(0.5).unwrap();
        let (_, met) = meets_threshold(&attestations, "bob", "relay", threshold).unwrap();
        assert!(!met);
    }

    #[test]
    fn meets_threshold_no_attestations() {
        let attestations: Vec<TrustAttestation> = vec![];
        let threshold = TrustThreshold::new(0.5).unwrap();
        assert!(meets_threshold(&attestations, "bob", "relay", threshold).is_none());
    }

    #[test]
    fn public_score_excludes_recipient_bound_attestations() {
        let attestations = vec![
            test_attestation("alice", "bob", "relay", 0.8),
            TrustAttestation {
                id: "att:hidden".into(),
                attester: "carol".into(),
                subject: "bob".into(),
                domain: "relay".into(),
                score: 0.2,
                recipient_bound: Some("peer-demo".into()),
            },
        ];

        let statement = derive_score(&attestations, "bob", "relay").unwrap();

        assert!((statement.normalized_score - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn recipient_view_includes_matching_recipient_bound_attestations() {
        let attestations = vec![
            test_attestation("alice", "bob", "relay", 0.8),
            TrustAttestation {
                id: "att:hidden".into(),
                attester: "carol".into(),
                subject: "bob".into(),
                domain: "relay".into(),
                score: 0.2,
                recipient_bound: Some("peer-demo".into()),
            },
        ];

        let statement =
            derive_score_for_recipient(&attestations, "bob", "relay", Some("peer-demo")).unwrap();

        assert!((statement.normalized_score - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn recipient_view_excludes_attestations_for_other_recipients() {
        let attestations = vec![
            test_attestation("alice", "bob", "relay", 0.8),
            TrustAttestation {
                id: "att:hidden".into(),
                attester: "carol".into(),
                subject: "bob".into(),
                domain: "relay".into(),
                score: 0.2,
                recipient_bound: Some("peer-demo".into()),
            },
        ];

        let statement =
            derive_score_for_recipient(&attestations, "bob", "relay", Some("different-peer"))
                .unwrap();

        assert!((statement.normalized_score - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn threshold_validation() {
        assert!(TrustThreshold::new(-0.1).is_err());
        assert!(TrustThreshold::new(1.1).is_err());
        assert!(TrustThreshold::new(0.0).is_ok());
        assert!(TrustThreshold::new(1.0).is_ok());
    }

    #[test]
    fn explain_threshold_check_formatting() {
        let statement = DerivedTrustStatement {
            id: "derived:bob:relay".to_string(),
            subject: "bob".to_string(),
            domain: "relay".to_string(),
            normalized_score: 0.8,
        };
        let threshold = TrustThreshold::new(0.5).unwrap();
        let explanation = explain_threshold_check(&statement, threshold, true);
        assert!(explanation.summary.contains("meets threshold"));
        assert!(!explanation.redacted_summary.contains("bob"));
    }

    #[test]
    fn derive_public_statements_groups_current_edges_by_subject_and_domain() {
        let attestations = vec![
            test_attestation("alice", "bob", "relay", 0.8),
            test_attestation("carol", "bob", "relay", 0.6),
            test_attestation("dave", "erin", "storage", 0.9),
            TrustAttestation {
                id: "att:hidden".into(),
                attester: "mallory".into(),
                subject: "bob".into(),
                domain: "relay".into(),
                score: 0.1,
                recipient_bound: Some("peer-demo".into()),
            },
        ];

        let statements = derive_public_statements(&attestations);

        assert_eq!(statements.len(), 2);
        assert!(statements.iter().any(|statement| {
            statement.subject == "bob"
                && statement.domain == "relay"
                && (statement.normalized_score - 0.7).abs() < f32::EPSILON
        }));
        assert!(statements.iter().any(|statement| {
            statement.subject == "erin"
                && statement.domain == "storage"
                && (statement.normalized_score - 0.9).abs() < f32::EPSILON
        }));
    }

    #[test]
    fn trust_event_builders_emit_typed_events() {
        let signer = FixtureSigner::new("trust-builder");
        let attested = trust_attested_event(
            "evt-trust-1",
            test_attestation("persona-a", "persona-b", "relay", 0.8),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
            &signer,
        )
        .unwrap();
        let revoked = trust_revoked_event(
            "evt-trust-2",
            "att:persona-a:persona-b:relay",
            "persona-a",
            "evt-trust-1",
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
            &signer,
        )
        .unwrap();

        assert_eq!(attested.event_type, EventType::TrustAttested);
        assert_eq!(revoked.event_type, EventType::TrustRevoked);
        assert_eq!(revoked.refs.len(), 1);
    }

    // --- Badge weight tests ---

    fn make_edge(attester: &str, subject: &str) -> TrustAttestation {
        TrustAttestation {
            id: format!("edge:{attester}:{subject}"),
            attester: attester.to_string(),
            subject: subject.to_string(),
            domain: "general".to_string(),
            score: 1.0,
            recipient_bound: None,
        }
    }

    // Anchor: core_trust_proptest_graph_landed
    fn chain_edges(hops: usize) -> Vec<TrustAttestation> {
        let mut edges = Vec::new();
        let mut previous = "viewer".to_string();
        for step in 1..=hops {
            let next = if step == hops {
                "issuer".to_string()
            } else {
                format!("hop_{step}")
            };
            edges.push(make_edge(&previous, &next));
            previous = next;
        }
        edges
    }

    fn node_id(idx: u8) -> String {
        format!("node_{}", idx % 8)
    }

    fn indexed_edges(pairs: Vec<(u8, u8)>) -> Vec<TrustAttestation> {
        pairs
            .into_iter()
            .enumerate()
            .map(|(idx, (from, to))| {
                let attester = node_id(from);
                let subject = node_id(to);
                let mut edge = make_edge(&attester, &subject);
                edge.id = format!("edge:{idx}:{attester}:{subject}");
                edge
            })
            .collect()
    }

    fn assert_unit_interval(value: f32, field: &str) -> Result<(), TestCaseError> {
        prop_assert!(value.is_finite(), "{field} must be finite, got {value}");
        prop_assert!(
            (0.0..=1.0).contains(&value),
            "{field} must stay in [0.0, 1.0], got {value}"
        );
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn badge_weight_chain_distance_respects_max_depth(
            hops in 0usize..8,
            max_depth in 0u32..6,
            issuer_badges_issued in 0u32..500,
        ) {
            let edges = chain_edges(hops);
            let issuer_id = if hops == 0 { "viewer" } else { "issuer" };
            let weight = compute_badge_weight(&BadgeWeightInput {
                issuer_id,
                viewer_id: "viewer",
                trust_edges: &edges,
                issuer_badges_issued,
                max_depth,
            });

            let effective_depth = max_depth.max(1);
            if hops == 0 || hops as u32 <= effective_depth {
                prop_assert_eq!(weight.graph_distance, Some(hops as u32));
                let expected_distance = if hops <= 1 {
                    1.0
                } else {
                    1.0 / hops as f32
                };
                prop_assert!(
                    (weight.distance_score - expected_distance).abs() < 1e-6,
                    "distance score drifted for hops={hops}: {:?}",
                    weight
                );
            } else {
                prop_assert_eq!(weight.graph_distance, None);
                prop_assert_eq!(weight.total, 0.0);
            }

            assert_unit_interval(weight.distance_score, "distance_score")?;
            assert_unit_interval(weight.convergence_score, "convergence_score")?;
            assert_unit_interval(weight.issuer_score, "issuer_score")?;
            assert_unit_interval(weight.total, "total")?;
        }

        #[test]
        fn badge_weight_scores_are_bounded_for_generated_graphs(
            pairs in proptest::collection::vec((0u8..8, 0u8..8), 0..32),
            viewer_idx in 0u8..8,
            issuer_idx in 0u8..8,
            issuer_badges_issued in any::<u32>(),
            max_depth in 0u32..12,
        ) {
            let edges = indexed_edges(pairs);
            let viewer = node_id(viewer_idx);
            let issuer = node_id(issuer_idx);
            let weight = compute_badge_weight(&BadgeWeightInput {
                issuer_id: &issuer,
                viewer_id: &viewer,
                trust_edges: &edges,
                issuer_badges_issued,
                max_depth,
            });

            assert_unit_interval(weight.distance_score, "distance_score")?;
            assert_unit_interval(weight.convergence_score, "convergence_score")?;
            assert_unit_interval(weight.issuer_score, "issuer_score")?;
            assert_unit_interval(weight.total, "total")?;
            if let Some(distance) = weight.graph_distance {
                prop_assert!(
                    distance <= max_depth.max(1),
                    "graph distance {distance} exceeded max depth {max_depth}"
                );
            } else {
                prop_assert_eq!(weight.total, 0.0);
            }
        }

        #[test]
        fn adding_reachable_inbound_trust_edge_does_not_lower_weight(
            peer_count in 1usize..8,
            trusted_peer_idx in 0usize..8,
            extra_peer_idx in 0usize..8,
            issuer_badges_issued in 0u32..500,
        ) {
            let trusted_peer_idx = trusted_peer_idx % peer_count;
            let extra_peer_idx = extra_peer_idx % peer_count;
            let mut edges = Vec::new();
            for idx in 0..peer_count {
                edges.push(make_edge("viewer", &format!("peer_{idx}")));
            }
            edges.push(make_edge(&format!("peer_{trusted_peer_idx}"), "issuer"));

            let before = compute_badge_weight(&BadgeWeightInput {
                issuer_id: "issuer",
                viewer_id: "viewer",
                trust_edges: &edges,
                issuer_badges_issued,
                max_depth: DEFAULT_MAX_DEPTH,
            });

            let mut expanded_edges = edges.clone();
            expanded_edges.push(make_edge(&format!("peer_{extra_peer_idx}"), "issuer"));
            let after = compute_badge_weight(&BadgeWeightInput {
                issuer_id: "issuer",
                viewer_id: "viewer",
                trust_edges: &expanded_edges,
                issuer_badges_issued,
                max_depth: DEFAULT_MAX_DEPTH,
            });

            prop_assert_eq!(before.graph_distance, after.graph_distance);
            prop_assert!(
                after.convergence_count >= before.convergence_count,
                "extra inbound edge lowered convergence count: before={before:?} after={after:?}"
            );
            prop_assert!(
                after.total + 1e-6 >= before.total,
                "extra inbound edge lowered authority total: before={before:?} after={after:?}"
            );
        }

        #[test]
        fn dispute_penalty_is_bounded_and_monotonic_for_direct_extra_dispute(
            pairs in proptest::collection::vec((0u8..8, 0u8..8), 0..32),
            dispute_indices in proptest::collection::vec(0u8..8, 0..16),
            max_depth in 0u32..12,
        ) {
            let edges = indexed_edges(pairs);
            let names: Vec<String> = (0..8).map(node_id).collect();
            let disputes: Vec<DisputeInput<'_>> = dispute_indices
                .iter()
                .map(|idx| DisputeInput {
                    disputer_id: names[*idx as usize].as_str(),
                })
                .collect();
            let penalty = compute_dispute_penalty("node_0", &disputes, &edges, max_depth);
            assert_unit_interval(penalty, "penalty")?;

            let mut edges_with_direct = edges.clone();
            edges_with_direct.push(make_edge("node_0", "direct_extra"));
            let mut disputes_with_direct: Vec<DisputeInput<'_>> = dispute_indices
                .iter()
                .map(|idx| DisputeInput {
                    disputer_id: names[*idx as usize].as_str(),
                })
                .collect();
            disputes_with_direct.push(DisputeInput {
                disputer_id: "direct_extra",
            });
            let penalty_with_direct = compute_dispute_penalty(
                "node_0",
                &disputes_with_direct,
                &edges_with_direct,
                max_depth,
            );

            assert_unit_interval(penalty_with_direct, "penalty_with_direct")?;
            prop_assert!(
                penalty_with_direct + 1e-6 >= penalty,
                "adding a reachable direct dispute lowered penalty: {penalty} -> {penalty_with_direct}"
            );
        }
    }

    #[test]
    fn badge_weight_direct_trust_scores_high() {
        // viewer directly trusts issuer
        let edges = vec![make_edge("viewer", "issuer")];
        let weight = compute_badge_weight(&BadgeWeightInput {
            issuer_id: "issuer",
            viewer_id: "viewer",
            trust_edges: &edges,
            issuer_badges_issued: 5,
            max_depth: DEFAULT_MAX_DEPTH,
        });

        assert_eq!(weight.graph_distance, Some(1));
        assert!((weight.distance_score - 1.0).abs() < 0.01);
        assert!(weight.total > 0.5, "direct trust should score above 0.5");
    }

    #[test]
    fn badge_weight_issuer_equals_viewer_distance_zero() {
        let edges: Vec<TrustAttestation> = vec![];
        let weight = compute_badge_weight(&BadgeWeightInput {
            issuer_id: "alice",
            viewer_id: "alice",
            trust_edges: &edges,
            issuer_badges_issued: 0,
            max_depth: DEFAULT_MAX_DEPTH,
        });

        assert_eq!(weight.graph_distance, Some(0));
        assert!((weight.distance_score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn badge_weight_two_hop_path() {
        // viewer -> peer -> issuer
        let edges = vec![make_edge("viewer", "peer"), make_edge("peer", "issuer")];
        let weight = compute_badge_weight(&BadgeWeightInput {
            issuer_id: "issuer",
            viewer_id: "viewer",
            trust_edges: &edges,
            issuer_badges_issued: 2,
            max_depth: DEFAULT_MAX_DEPTH,
        });

        assert_eq!(weight.graph_distance, Some(2));
        assert!((weight.distance_score - 0.5).abs() < 0.01);
    }

    #[test]
    fn badge_weight_unreachable_issuer_distance_score_zero() {
        let edges = vec![make_edge("viewer", "peer")];
        let weight = compute_badge_weight(&BadgeWeightInput {
            issuer_id: "stranger",
            viewer_id: "viewer",
            trust_edges: &edges,
            issuer_badges_issued: 100,
            max_depth: DEFAULT_MAX_DEPTH,
        });

        assert_eq!(weight.graph_distance, None);
        assert!((weight.distance_score - 0.0).abs() < f32::EPSILON);
        assert_eq!(weight.total, 0.0);
    }

    #[test]
    fn badge_weight_convergence_multiple_peers_trust_issuer() {
        // viewer trusts peer_a and peer_b; both trust issuer
        let edges = vec![
            make_edge("viewer", "peer_a"),
            make_edge("viewer", "peer_b"),
            make_edge("peer_a", "issuer"),
            make_edge("peer_b", "issuer"),
        ];
        let weight = compute_badge_weight(&BadgeWeightInput {
            issuer_id: "issuer",
            viewer_id: "viewer",
            trust_edges: &edges,
            issuer_badges_issued: 10,
            max_depth: DEFAULT_MAX_DEPTH,
        });

        // Both first-degree peers trust issuer -> convergence_count = 2, first_degree = 2
        assert_eq!(weight.convergence_count, 2);
        assert!((weight.convergence_score - 1.0).abs() < 0.01);
    }

    #[test]
    fn badge_weight_issuer_score_spam_signal() {
        // Issuer has zero inbound trust and high badge count → spam signal
        let edges: Vec<TrustAttestation> = vec![make_edge("viewer", "issuer")];
        let weight = compute_badge_weight(&BadgeWeightInput {
            issuer_id: "issuer",
            viewer_id: "viewer",
            trust_edges: &edges,
            issuer_badges_issued: 10000,
            max_depth: DEFAULT_MAX_DEPTH,
        });

        // inbound_trust = 1 (viewer->issuer), ratio = 1/10000 ≈ 0.0001 → near zero
        assert!(weight.issuer_score < 0.01);
    }

    #[test]
    fn badge_weight_issuer_score_well_trusted() {
        // Issuer has many inbound trust signals relative to badges issued
        let mut edges: Vec<TrustAttestation> = Vec::new();
        for i in 0..5u32 {
            edges.push(make_edge(&format!("peer_{i}"), "issuer"));
        }
        edges.push(make_edge("viewer", "peer_0"));

        let weight = compute_badge_weight(&BadgeWeightInput {
            issuer_id: "issuer",
            viewer_id: "viewer",
            trust_edges: &edges,
            issuer_badges_issued: 3,
            max_depth: DEFAULT_MAX_DEPTH,
        });

        // ratio = 5 inbound / 3 issued = 1.67 → capped at 1.0
        assert!((weight.issuer_score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn badge_weight_total_is_weighted_combination() {
        // Verify the total formula: 40% distance + 40% convergence + 20% issuer
        let edges = vec![make_edge("viewer", "issuer"), make_edge("other", "issuer")];
        let weight = compute_badge_weight(&BadgeWeightInput {
            issuer_id: "issuer",
            viewer_id: "viewer",
            trust_edges: &edges,
            issuer_badges_issued: 1,
            max_depth: DEFAULT_MAX_DEPTH,
        });

        let expected_total = (0.40 * weight.distance_score
            + 0.40 * weight.convergence_score
            + 0.20 * weight.issuer_score)
            .clamp(0.0, 1.0);
        assert!((weight.total - expected_total).abs() < 1e-6);
    }

    #[test]
    fn badge_weight_max_depth_limits_traversal() {
        // issuer is 4 hops away; max_depth=3 → unreachable
        let edges = vec![
            make_edge("viewer", "a"),
            make_edge("a", "b"),
            make_edge("b", "c"),
            make_edge("c", "issuer"),
        ];
        let weight = compute_badge_weight(&BadgeWeightInput {
            issuer_id: "issuer",
            viewer_id: "viewer",
            trust_edges: &edges,
            issuer_badges_issued: 1,
            max_depth: 3,
        });

        assert_eq!(weight.graph_distance, None);
        assert_eq!(weight.total, 0.0);
    }

    // --- Dispute penalty tests ---

    #[test]
    fn dispute_penalty_no_disputes() {
        let edges = vec![make_edge("viewer", "issuer")];
        let penalty = compute_dispute_penalty("viewer", &[], &edges, DEFAULT_MAX_DEPTH);
        assert!((penalty - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn dispute_penalty_direct_peer_dispute() {
        let edges = vec![make_edge("viewer", "disputer")];
        let disputes = vec![DisputeInput {
            disputer_id: "disputer",
        }];
        let penalty = compute_dispute_penalty("viewer", &disputes, &edges, DEFAULT_MAX_DEPTH);
        // Direct peer: 0.8
        assert!((penalty - 0.8).abs() < 0.01);
    }

    #[test]
    fn dispute_penalty_viewer_self_disputes() {
        let edges: Vec<TrustAttestation> = vec![];
        let disputes = vec![DisputeInput {
            disputer_id: "viewer",
        }];
        let penalty = compute_dispute_penalty("viewer", &disputes, &edges, DEFAULT_MAX_DEPTH);
        // Viewer themselves: 1.0
        assert!((penalty - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn dispute_penalty_unreachable_disputer() {
        let edges = vec![make_edge("viewer", "peer")];
        let disputes = vec![DisputeInput {
            disputer_id: "stranger",
        }];
        let penalty = compute_dispute_penalty("viewer", &disputes, &edges, DEFAULT_MAX_DEPTH);
        assert!((penalty - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn dispute_penalty_multiple_disputes_accumulate() {
        let edges = vec![make_edge("viewer", "peer_a"), make_edge("viewer", "peer_b")];
        let disputes = vec![
            DisputeInput {
                disputer_id: "peer_a",
            },
            DisputeInput {
                disputer_id: "peer_b",
            },
        ];
        let penalty = compute_dispute_penalty("viewer", &disputes, &edges, DEFAULT_MAX_DEPTH);
        // Two direct peers: 0.8 + 0.8 = 1.6, capped at 1.0
        assert!((penalty - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn apply_dispute_penalty_reduces_weight() {
        let total = 0.8;
        let penalty = 0.5;
        let adjusted = apply_dispute_penalty(total, penalty);
        assert!((adjusted - 0.4).abs() < f32::EPSILON);
    }

    #[test]
    fn apply_dispute_penalty_zero_preserves_weight() {
        let total = 0.7;
        let adjusted = apply_dispute_penalty(total, 0.0);
        assert!((adjusted - 0.7).abs() < f32::EPSILON);
    }

    // --- Badge-gated grant condition tests ---

    fn badge_gate_input<'a>(
        issuer: &'a str,
        claimant: &'a str,
        badges: &'a [ClaimantBadge<'a>],
        edges: &'a [TrustAttestation],
        counts: &'a std::collections::BTreeMap<String, u32>,
    ) -> BadgeGateInput<'a> {
        BadgeGateInput {
            issuer_persona_id: issuer,
            claimant_persona_id: claimant,
            claimant_badges: badges,
            trust_edges: edges,
            issuer_badge_counts: counts,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }

    #[test]
    fn badge_gate_no_conditions_always_met() {
        let empty_counts = std::collections::BTreeMap::new();
        let input = badge_gate_input("issuer", "claimant", &[], &[], &empty_counts);
        let result = evaluate_grant_conditions(&[], &input);
        assert!(result.is_met());
    }

    #[test]
    fn badge_gate_simple_badge_held() {
        let badges = [ClaimantBadge {
            badge_type: "verified-dev",
            issuer_persona_id: "badge-issuer",
        }];
        let edges = vec![make_edge("issuer", "badge-issuer")];
        let mut counts = std::collections::BTreeMap::new();
        counts.insert("badge-issuer".into(), 5);

        let conditions = vec![core_grant_types::grant_conditions::GrantCondition::badge(
            "verified-dev",
        )];
        let input = badge_gate_input("issuer", "claimant", &badges, &edges, &counts);
        let result = evaluate_grant_conditions(&conditions, &input);
        assert!(result.is_met());
    }

    #[test]
    fn badge_gate_badge_not_held() {
        let conditions = vec![core_grant_types::grant_conditions::GrantCondition::badge(
            "verified-dev",
        )];
        let empty_counts = std::collections::BTreeMap::new();
        let input = badge_gate_input("issuer", "claimant", &[], &[], &empty_counts);
        let result = evaluate_grant_conditions(&conditions, &input);
        assert!(!result.is_met());
        if let ConditionResult::Unmet(reason) = result {
            assert!(reason.contains("does not hold badge"));
        }
    }

    #[test]
    fn badge_gate_with_distance_threshold() {
        let badges = [ClaimantBadge {
            badge_type: "subway-rider",
            issuer_persona_id: "far-issuer",
        }];
        // far-issuer is 3 hops from issuer
        let edges = vec![
            make_edge("issuer", "a"),
            make_edge("a", "b"),
            make_edge("b", "far-issuer"),
        ];
        let mut counts = std::collections::BTreeMap::new();
        counts.insert("far-issuer".into(), 1);

        // max_distance=2 should fail (issuer is 3 hops away)
        let conditions = vec![
            core_grant_types::grant_conditions::GrantCondition::badge_with_thresholds(
                "subway-rider",
                None,
                Some(2),
                None,
            ),
        ];
        let input = badge_gate_input("issuer", "claimant", &badges, &edges, &counts);
        let result = evaluate_grant_conditions(&conditions, &input);
        assert!(!result.is_met());

        // max_distance=3 should pass
        let conditions = vec![
            core_grant_types::grant_conditions::GrantCondition::badge_with_thresholds(
                "subway-rider",
                None,
                Some(3),
                None,
            ),
        ];
        let result = evaluate_grant_conditions(&conditions, &input);
        assert!(result.is_met());
    }

    #[test]
    fn badge_gate_all_combinator() {
        let badges = [
            ClaimantBadge {
                badge_type: "verified-dev",
                issuer_persona_id: "badge-issuer",
            },
            ClaimantBadge {
                badge_type: "subway-rider",
                issuer_persona_id: "badge-issuer",
            },
        ];
        let edges = vec![make_edge("issuer", "badge-issuer")];
        let mut counts = std::collections::BTreeMap::new();
        counts.insert("badge-issuer".into(), 2);

        let conditions = vec![core_grant_types::grant_conditions::GrantCondition::All(
            vec![
                core_grant_types::grant_conditions::GrantCondition::badge("verified-dev"),
                core_grant_types::grant_conditions::GrantCondition::badge("subway-rider"),
            ],
        )];
        let input = badge_gate_input("issuer", "claimant", &badges, &edges, &counts);
        let result = evaluate_grant_conditions(&conditions, &input);
        assert!(result.is_met());
    }

    #[test]
    fn badge_gate_any_combinator() {
        let badges = [ClaimantBadge {
            badge_type: "subway-rider",
            issuer_persona_id: "badge-issuer",
        }];
        let edges = vec![make_edge("issuer", "badge-issuer")];
        let mut counts = std::collections::BTreeMap::new();
        counts.insert("badge-issuer".into(), 1);

        let conditions = vec![core_grant_types::grant_conditions::GrantCondition::Any(
            vec![
                core_grant_types::grant_conditions::GrantCondition::badge("verified-dev"),
                core_grant_types::grant_conditions::GrantCondition::badge("subway-rider"),
            ],
        )];
        let input = badge_gate_input("issuer", "claimant", &badges, &edges, &counts);
        let result = evaluate_grant_conditions(&conditions, &input);
        assert!(result.is_met());
    }

    /// GC-H1 defence in depth: deserialization rejects empty `All`/`Any`
    /// combinators, but the evaluator must also fail closed if a malformed
    /// variant is constructed in-process (bypassing serde). Previously the
    /// evaluator returned `Met` on `All(vec![])` (vacuous truth) and
    /// `Any(vec![])` (early `Met` short-circuit), giving a covert always-pass
    /// shape if any future caller built one programmatically.
    #[test]
    fn empty_all_combinator_evaluates_unmet() {
        let empty_counts = std::collections::BTreeMap::new();
        let input = badge_gate_input("issuer", "claimant", &[], &[], &empty_counts);
        let conditions = vec![core_grant_types::grant_conditions::GrantCondition::All(
            vec![],
        )];
        let result = evaluate_grant_conditions(&conditions, &input);
        assert!(!result.is_met(), "empty All must be Unmet (fail-closed)");
        if let ConditionResult::Unmet(reason) = result {
            assert!(
                reason.contains("empty All"),
                "expected empty-All reason, got: {reason}"
            );
        }
    }

    #[test]
    fn empty_any_combinator_evaluates_unmet() {
        let empty_counts = std::collections::BTreeMap::new();
        let input = badge_gate_input("issuer", "claimant", &[], &[], &empty_counts);
        let conditions = vec![core_grant_types::grant_conditions::GrantCondition::Any(
            vec![],
        )];
        let result = evaluate_grant_conditions(&conditions, &input);
        assert!(!result.is_met(), "empty Any must be Unmet (fail-closed)");
        if let ConditionResult::Unmet(reason) = result {
            assert!(
                reason.contains("empty Any"),
                "expected empty-Any reason, got: {reason}"
            );
        }
    }
}
