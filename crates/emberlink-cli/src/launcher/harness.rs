use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarnessKind {
    Claude,
    Codex,
    Cursor,
    Gemini,
    Other,
}

impl HarnessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
            Self::Gemini => "gemini",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for HarnessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_matches_cli_strings() {
        assert_eq!(HarnessKind::Claude.to_string(), "claude");
        assert_eq!(HarnessKind::Codex.to_string(), "codex");
        assert_eq!(HarnessKind::Cursor.to_string(), "cursor");
        assert_eq!(HarnessKind::Gemini.to_string(), "gemini");
        assert_eq!(HarnessKind::Other.to_string(), "other");
    }
}
