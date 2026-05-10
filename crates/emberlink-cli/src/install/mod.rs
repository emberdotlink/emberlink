//! Operator-facing install wizard.
//!
//! This module owns the user-friendly install flow that drives the daemon-side
//! provisioning primitives in [`ember_daemon::install`]. The current slice
//! ([T-INSTALL-WIZARD-V0-3-0-A]) only sets up the scaffold — platform
//! detection, sudo elevation, and a transcript log. Subsequent slices wire the
//! detected platform to the actual install steps and add a CLI verb.

pub mod non_interactive;
pub mod verify;
pub mod wizard;

pub use non_interactive::{
    install_non_interactive, install_non_interactive_with, InstallNonInteractiveOptions, Posture,
    PrivilegeProbe, RealPrivilegeProbe,
};
pub use verify::{
    default_trust_list, verify_install_bundle, BundleManifest, TrustedPublisher, VerifyError,
    BUNDLE_MANIFEST_SCHEMA_VERSION, EMBERLINK_RELEASE_PUBLISHER_DID,
};
pub use wizard::{
    clear_wizard_state, load_wizard_state, run_install_wizard, run_rollback, run_wizard_steps,
    run_wizard_steps_from, save_wizard_state, wizard_resume_or_rollback,
    wizard_resume_or_rollback_with_choice, wizard_step_add_user_to_group,
    wizard_step_chown_data_dirs, wizard_step_emit_launch_spec, wizard_step_provision_user,
    wizard_step_verify, InstallPrimitives, Platform, RealPrimitives, ResumeAction, StepOutcome,
    WizardContext, WizardError, WizardState, WIZARD_STEPS,
};
