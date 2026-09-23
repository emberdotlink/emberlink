#![deny(unsafe_code)]

pub mod action_admission;
pub mod action_definition;
pub mod audit;
pub mod canonical;
pub mod control;
pub mod device;
pub mod identity;
pub mod initialization;
pub mod ipc;
pub mod kernel;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) mod macos_process;
pub mod model;
pub mod network_enforcement;
pub mod operation;
pub mod receipt;
pub mod recovery;
pub mod runner;
#[allow(unsafe_code)]
pub mod runtime_presence;

pub const AUTHORITY_STATE_DIRECTORY: &str = ".local/state/ember-authority";

#[allow(unsafe_code)]
pub fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}
