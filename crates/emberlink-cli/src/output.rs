//! Typed output abstraction for CLI handlers (DRY-10).
//!
//! Today every handler builds output strings ad-hoc — ANSI escapes, tabs,
//! plain text, JSON-by-string-format — all interleaved with domain logic.
//! This module gives handlers a small typed surface (`heading`, `row`,
//! `data`, `success`, `warn`, `error`) that renders into the right shape
//! for the active mode:
//!
//! * `Mode::Human { color }` — default. Headings and success lines get
//!   bold/colored ANSI when `color` is true.
//! * `Mode::Json` — NDJSON. Headings and success lines are suppressed;
//!   each `row(..)` becomes one JSON array line, each `data(..)` becomes
//!   one JSON object line.
//! * `Mode::Quiet` — only `row` data lines + `warn`/`error` survive. No
//!   headings, no success blurbs. Designed for shell pipelines.
//!
//! `warn` and `error` are always shown — silencing problem output by
//! flag is a footgun.
//!
//! Renderer is configured at startup from the `--json` / `--quiet` /
//! `--color` flags on `Args`. See `crate::cli::Args::output_mode`.
//!
//! Migration status: this is a strangler-fig abstraction. One representative
//! handler (`handle_grant_list`) was migrated as a proof of concept; the
//! other ~70 string-builder handlers are tracked as `DRY-10-MIGRATE`
//! follow-ups. Until they migrate, `--json` / `--quiet` only affect the
//! handlers that have opted in.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Human { color: bool },
    Json,
    Quiet,
}

pub struct Output {
    mode: Mode,
    buffer: String,
}

impl Output {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            buffer: String::new(),
        }
    }

    pub fn human(color: bool) -> Self {
        Self::new(Mode::Human { color })
    }

    pub fn json() -> Self {
        Self::new(Mode::Json)
    }

    pub fn quiet() -> Self {
        Self::new(Mode::Quiet)
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn into_string(self) -> String {
        self.buffer
    }

    /// Section heading. Suppressed in Json + Quiet.
    pub fn heading(&mut self, text: &str) -> &mut Self {
        if let Mode::Human { color } = self.mode {
            if color {
                // Bold via ANSI without a dep — keeps cargo lean.
                self.buffer.push_str("\x1b[1m");
                self.buffer.push_str(text);
                self.buffer.push_str("\x1b[0m\n");
            } else {
                self.buffer.push_str(text);
                self.buffer.push('\n');
            }
        }
        self
    }

    /// Tabular row. In Json mode emits one NDJSON array line.
    pub fn row(&mut self, cells: &[&str]) -> &mut Self {
        match self.mode {
            Mode::Human { .. } | Mode::Quiet => {
                self.buffer.push_str(&cells.join("\t"));
                self.buffer.push('\n');
            }
            Mode::Json => {
                let arr: Value = cells
                    .iter()
                    .map(|c| Value::String((*c).to_string()))
                    .collect();
                self.buffer
                    .push_str(&serde_json::to_string(&arr).unwrap_or_default());
                self.buffer.push('\n');
            }
        }
        self
    }

    /// Structured data emit (Object form). Mode-aware:
    ///   - Json: serializes the value as one NDJSON line
    ///   - Human/Quiet: pretty-prints the value (Json with indent)
    pub fn data(&mut self, v: &Value) -> &mut Self {
        match self.mode {
            Mode::Json => {
                self.buffer
                    .push_str(&serde_json::to_string(v).unwrap_or_default());
                self.buffer.push('\n');
            }
            Mode::Human { .. } | Mode::Quiet => {
                self.buffer
                    .push_str(&serde_json::to_string_pretty(v).unwrap_or_default());
                self.buffer.push('\n');
            }
        }
        self
    }

    /// Success line. Suppressed in Quiet + Json.
    pub fn success(&mut self, text: &str) -> &mut Self {
        if matches!(self.mode, Mode::Human { .. }) {
            self.buffer.push_str(text);
            self.buffer.push('\n');
        }
        self
    }

    /// Warning line. Always shown.
    pub fn warn(&mut self, text: &str) -> &mut Self {
        match self.mode {
            Mode::Human { color } if color => {
                self.buffer.push_str("\x1b[33m");
                self.buffer.push_str(text);
                self.buffer.push_str("\x1b[0m\n");
            }
            _ => {
                self.buffer.push_str(text);
                self.buffer.push('\n');
            }
        }
        self
    }

    /// Error line. Always shown.
    pub fn error(&mut self, text: &str) -> &mut Self {
        match self.mode {
            Mode::Human { color } if color => {
                self.buffer.push_str("\x1b[31m");
                self.buffer.push_str(text);
                self.buffer.push_str("\x1b[0m\n");
            }
            _ => {
                self.buffer.push_str(text);
                self.buffer.push('\n');
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_row_emits_array() {
        let mut o = Output::json();
        o.row(&["a", "b"]);
        assert!(o.into_string().contains("[\"a\",\"b\"]"));
    }

    #[test]
    fn human_no_color_strips_ansi() {
        let mut o = Output::human(false);
        o.heading("Grants").row(&["id1"]).success("done");
        let s = o.into_string();
        assert!(!s.contains("\x1b["));
        assert!(s.contains("Grants"));
    }

    #[test]
    fn quiet_suppresses_heading_keeps_rows() {
        let mut o = Output::quiet();
        o.heading("Grants").row(&["id1"]);
        let s = o.into_string();
        assert!(!s.contains("Grants"));
        assert!(s.contains("id1"));
    }

    #[test]
    fn warn_and_error_always_emit() {
        for mode in [Mode::Human { color: false }, Mode::Json, Mode::Quiet] {
            let mut o = Output::new(mode);
            o.warn("watch out").error("bad");
            let s = o.into_string();
            assert!(s.contains("watch out"));
            assert!(s.contains("bad"));
        }
    }

    #[test]
    fn json_suppresses_heading_and_success() {
        let mut o = Output::json();
        o.heading("Grants").success("done").row(&["id1"]);
        let s = o.into_string();
        assert!(!s.contains("Grants"));
        assert!(!s.contains("done"));
        assert!(s.contains("[\"id1\"]"));
    }

    #[test]
    fn data_json_mode_compact() {
        let mut o = Output::json();
        o.data(&serde_json::json!({"id": "g-1", "mode": "standing"}));
        let s = o.into_string();
        // Compact JSON has no newline inside the object.
        assert!(s.contains("\"id\":\"g-1\""));
        assert!(s.contains("\"mode\":\"standing\""));
    }

    #[test]
    fn data_human_mode_pretty() {
        let mut o = Output::human(false);
        o.data(&serde_json::json!({"id": "g-1"}));
        let s = o.into_string();
        // Pretty JSON has the field on its own line.
        assert!(s.contains("\"id\": \"g-1\""));
    }

    #[test]
    fn human_color_emits_ansi_bold_for_heading() {
        let mut o = Output::human(true);
        o.heading("Grants");
        let s = o.into_string();
        assert!(s.contains("\x1b[1m"));
        assert!(s.contains("\x1b[0m"));
        assert!(s.contains("Grants"));
    }

    #[test]
    fn mode_accessor_round_trip() {
        let o = Output::new(Mode::Human { color: true });
        assert_eq!(o.mode(), Mode::Human { color: true });
        let o = Output::json();
        assert_eq!(o.mode(), Mode::Json);
        let o = Output::quiet();
        assert_eq!(o.mode(), Mode::Quiet);
    }
}
