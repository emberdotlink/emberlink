#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosurePreset {
    Minimal,
    Professional,
    Friends,
    Pseudonymous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDisclosurePreset {
    ScoreOnly,
    ScoreWithSummary,
}

