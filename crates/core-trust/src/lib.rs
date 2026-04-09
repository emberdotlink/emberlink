use std::collections::BTreeSet;

use core_crypto::Signer;
use core_events::EventEnvelope;
use core_types::{
    DerivedTrustStatement, EventBody, EventRefRelation, SignerBinding, TrustAttestation,
    TrustAttestedEvent, TrustExplanation, TrustRevokedEvent, TrustThreshold,
};

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
    use core_types::{EventType, SignerBinding};

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
}
