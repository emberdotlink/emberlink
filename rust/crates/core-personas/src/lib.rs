use core_types::{Persona, SurvivalMode, VisibilityPreset};

pub fn create_persona(
    id: impl Into<String>,
    root_id: impl Into<String>,
    label: impl Into<String>,
    preset: VisibilityPreset,
    survival_mode: SurvivalMode,
) -> Persona {
    Persona {
        id: id.into(),
        root_id: root_id.into(),
        label: label.into(),
        preset,
        survival_mode,
    }
}

