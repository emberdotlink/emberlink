/// Guardian enrollment via grant link.
///
/// `recovery guardian-invite` — generate a guardian enrollment link.
/// `recovery guardian-list`   — list enrolled guardians.
use std::fmt::Write as _;

use emberlink_app::UiAction;

use crate::DemoApp;

const GUARDIAN_ENROLL_TTL_SECS: u64 = 30 * 24 * 3600; // 30 days

impl DemoApp {
    /// `recovery guardian-invite [--persona <id>] [--relay <addr>]`
    ///
    /// Generates a one-shot grant offer with scope `guardian:enroll` and a
    /// 30-day TTL, then prints the enrollment URL.
    pub(crate) fn handle_guardian_invite(&mut self, tokens: &[&str]) -> String {
        let mut persona_ref: Option<String> = None;
        let mut relay: Option<String> = None;

        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" | "-p" if i + 1 < tokens.len() => {
                    persona_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--relay" | "-r" if i + 1 < tokens.len() => {
                    relay = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                other => return format!("unknown flag: {other}\n"),
            }
        }

        // Resolve persona: explicit or first active.
        let persona_id = match persona_ref {
            Some(ref r) => {
                let mat = self.app_runtime.store.materialized();
                // Accept by ID or by label prefix.
                let found = mat
                    .personas_current
                    .values()
                    .find(|p| p.persona_id == *r || p.label.to_lowercase().starts_with(&r.to_lowercase()))
                    .map(|p| p.persona_id.clone());
                match found {
                    Some(id) => id,
                    None => return format!("error: unknown persona: {r}\n"),
                }
            }
            None => {
                match self
                    .app_runtime
                    .store
                    .materialized()
                    .personas_current
                    .keys()
                    .next()
                {
                    Some(id) => id.clone(),
                    None => return "error: no personas found; run `init` first\n".to_string(),
                }
            }
        };

        let action = UiAction::CreateGrantOffer {
            issuing_persona_id: persona_id.clone(),
            mode: "one_shot".to_string(),
            // Guardian-enrollment is not expressible in the credential-shorthand
            // spec grammar — `parse_statement_spec` rejects it. The `CreateGrantOffer`
            // path validates specs up front and will reject this today.
            // TODO: extend spec grammar or take typed `Vec<Statement>` directly on this action.
            statement_specs: vec!["guardian:enroll".to_string()],
            expires_in_secs: Some(GUARDIAN_ENROLL_TTL_SECS),
            relay_hint: relay,
            conditions: vec![],
        };

        match self.app_runtime.handle_action(action) {
            Ok((result, _mutated)) => {
                let offer_id = result["offer_id"].as_str().unwrap_or("unknown");
                let grant_link = result["grant_link"].as_str().unwrap_or("");
                // Build the guardian-specific deep-link URL.
                // The grant link is https://ember.link/[?relay=...]#/claim/<offer_id>?...
                // We rewrite the path segment to /guardian/ so the web surface
                // knows to run the guardian enrollment flow.
                let guardian_url = grant_link.replace("#/claim/", "#/guardian/");

                let mut out = String::new();
                writeln!(&mut out, "guardian enrollment link\t{offer_id}").unwrap();
                writeln!(&mut out, "url\t{guardian_url}").unwrap();
                writeln!(&mut out).unwrap();
                writeln!(
                    &mut out,
                    "Share this link with your guardian. When they claim it, they'll be enrolled as your recovery guardian."
                )
                .unwrap();
                out
            }
            Err(e) => format!("error: {e}\n"),
        }
    }

    /// `recovery guardian-list`
    ///
    /// Lists all enrolled guardians for the active identity, grouped by root.
    pub(crate) fn handle_guardian_list(&mut self, _tokens: &[&str]) -> String {
        let mat = self.app_runtime.store.materialized();
        let guardians: Vec<_> = mat.guardians_current.values().collect();

        // Determine the active persona's root for display.
        let active_persona = mat.personas_current.values().next();
        let persona_label = active_persona
            .map(|p| p.label.as_str())
            .unwrap_or("(no persona)");

        // Find the recovery policy threshold if one exists.
        let threshold = mat
            .recovery_policies_current
            .values()
            .next()
            .map(|pol| pol.guardian_threshold);

        let mut out = String::new();
        writeln!(&mut out, "guardians for persona {persona_label}").unwrap();
        writeln!(&mut out, "──────────────────────────").unwrap();

        if guardians.is_empty() {
            writeln!(&mut out, "(none enrolled)").unwrap();
        } else {
            for g in &guardians {
                writeln!(&mut out, "id: {}\tlabel: {}\troot: {}", g.guardian_id, g.label, g.root_id).unwrap();
            }
        }

        writeln!(&mut out, "──────────────────────────").unwrap();

        let count = guardians.len();
        match threshold {
            Some(t) => {
                writeln!(&mut out, "{count} guardian(s) (threshold: {t})").unwrap();
            }
            None => {
                writeln!(&mut out, "{count} guardian(s) (no recovery policy set)").unwrap();
            }
        }

        out
    }
}
