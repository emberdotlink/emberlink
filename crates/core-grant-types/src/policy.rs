#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonaTemplate {
    Professional,
    Friends,
    Pseudonymous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDisclosurePreset {
    ScoreOnly,
    ScoreWithSummary,
}

pub fn parse_persona_template(input: &str) -> Option<PersonaTemplate> {
    match input {
        "professional" => Some(PersonaTemplate::Professional),
        "friends" => Some(PersonaTemplate::Friends),
        "pseudonymous" => Some(PersonaTemplate::Pseudonymous),
        _ => None,
    }
}

pub fn persona_template_label(template: PersonaTemplate) -> &'static str {
    match template {
        PersonaTemplate::Professional => "professional",
        PersonaTemplate::Friends => "friends",
        PersonaTemplate::Pseudonymous => "pseudonymous",
    }
}

pub fn disclosure_profile_for_template(template: PersonaTemplate) -> &'static str {
    match template {
        PersonaTemplate::Professional => "persona.professional",
        PersonaTemplate::Friends => "persona.friends",
        PersonaTemplate::Pseudonymous => "persona.pseudonymous",
    }
}

pub fn persona_template_for_disclosure_profile(profile: &str) -> Option<PersonaTemplate> {
    match profile {
        "persona.professional" => Some(PersonaTemplate::Professional),
        "persona.friends" => Some(PersonaTemplate::Friends),
        "persona.pseudonymous" => Some(PersonaTemplate::Pseudonymous),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persona_templates_map_to_disclosure_profiles_deterministically() {
        assert_eq!(
            persona_template_label(PersonaTemplate::Professional),
            "professional"
        );
        assert_eq!(
            disclosure_profile_for_template(PersonaTemplate::Pseudonymous),
            "persona.pseudonymous"
        );
        assert_eq!(
            persona_template_for_disclosure_profile("persona.friends"),
            Some(PersonaTemplate::Friends)
        );
    }
}
