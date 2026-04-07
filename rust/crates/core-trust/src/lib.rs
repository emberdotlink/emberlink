use core_types::{DerivedTrustStatement, TrustAttestation, TrustExplanation};

pub fn derive_score(attestations: &[TrustAttestation], subject: &str, domain: &str) -> Option<DerivedTrustStatement> {
    let matches: Vec<_> = attestations
        .iter()
        .filter(|a| a.subject == subject && a.domain == domain)
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

pub fn explain(statement: &DerivedTrustStatement) -> TrustExplanation {
    TrustExplanation {
        summary: format!(
            "Trust score for {} in {} is {:.2}",
            statement.subject, statement.domain, statement.normalized_score
        ),
        redacted_summary: format!("Trust score in {} is {:.2}", statement.domain, statement.normalized_score),
    }
}

