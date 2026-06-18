//! Operator-facing install wizard.
//!
//! This module owns the user-friendly install flow that drives the daemon-side
//! provisioning primitives in [`ember_daemon::install`]. The current slice
//! ([T-INSTALL-WIZARD-V0-3-0-A]) only sets up the scaffold — platform
//! detection, sudo elevation, and a transcript log. Subsequent slices wire the
//! detected platform to the actual install steps and add a CLI verb.

pub mod channel;
pub mod linux;
pub mod non_interactive;
pub mod shell_init;
pub mod verify;
pub mod wizard;

pub use non_interactive::{
    InstallNonInteractiveOptions, Posture, PrivilegeProbe, RealPrivilegeProbe,
    install_non_interactive, install_non_interactive_with,
};
pub use verify::{
    BUNDLE_MANIFEST_SCHEMA_VERSION, BundleManifest, EMBERLINK_RELEASE_PUBLISHER_DID,
    TrustedPublisher, VerifyError, default_trust_list, verify_install_bundle,
};
pub use wizard::{
    DaemonInstallPromptError, DaemonInstallStatus, InstallPrimitives, Platform, RealPrimitives,
    RealSudoRunner, ResumeAction, StepOutcome, SudoRunner, WIZARD_STEPS, WizardContext,
    WizardError, WizardState, clear_wizard_state, detect_daemon_installed, load_wizard_state,
    prompt_install_daemon, prompt_install_daemon_with, run_install_wizard, run_rollback,
    run_wizard_steps, run_wizard_steps_from, save_wizard_state, wizard_resume_or_rollback,
    wizard_resume_or_rollback_with_choice, wizard_step_add_user_to_group,
    wizard_step_chown_data_dirs, wizard_step_emit_launch_spec, wizard_step_provision_user,
    wizard_step_verify,
};
