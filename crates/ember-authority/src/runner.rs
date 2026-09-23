use crate::model::{DiagnosticFacts, DiagnosticInput, Refusal};

pub const DIAGNOSTIC_RUNNER: &str = "builtin.diagnostic.authority-status/v1";

pub trait JournalHealth: Send + Sync {
    fn health(&self) -> Result<&'static str, Refusal>;
}

pub struct DiagnosticRunner;

impl DiagnosticRunner {
    pub fn run(
        input: &DiagnosticInput,
        journal: &dyn JournalHealth,
    ) -> Result<DiagnosticFacts, Refusal> {
        input.validate()?;
        let health = journal
            .health()
            .map_err(|_| Refusal::new("runner_failed"))?;
        if health != "ready" {
            return Err(Refusal::new("runner_failed"));
        }
        Ok(DiagnosticFacts {
            challenge: input.challenge.clone(),
            journal_health: health.into(),
        })
    }
}
