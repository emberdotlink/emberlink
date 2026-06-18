//! Operator-owned Emberlink filesystem paths.
//!
//! ADR 218 split daemon-owned state into OS system paths and operator-owned
//! state into OS-conventional per-user paths. This module is the small CLI-side
//! counterpart to `internal-automation`'s `EnginePaths::resolve_via_project_dirs()`.

use std::path::PathBuf;

/// Reverse-DNS tuple shared with `internal-automation` per ADR 218.
const PROJECT_DIRS_QUALIFIER: &str = "sh";
const PROJECT_DIRS_ORGANIZATION: &str = "Emberlink";
const PROJECT_DIRS_APPLICATION: &str = "Emberlink";

/// Resolve the operator-owned Emberlink data root.
///
/// macOS resolves under `~/Library/Application Support/...`; Linux resolves
/// under `$XDG_DATA_HOME` or `~/.local/share/...`. The final casing/path segment
/// is delegated to `directories-next::ProjectDirs` to match the established
/// repo pattern.
pub fn data_root() -> Option<PathBuf> {
    directories_next::ProjectDirs::from(
        PROJECT_DIRS_QUALIFIER,
        PROJECT_DIRS_ORGANIZATION,
        PROJECT_DIRS_APPLICATION,
    )
    .map(|dirs| dirs.data_dir().to_path_buf())
}

/// Operator-owned install wizard state directory.
///
/// Holds the human transcript and resume/rollback breadcrumb. These are not
/// daemon state and must not live under the retired `~/.ember` tree.
pub fn install_state_dir() -> Option<PathBuf> {
    data_root().map(|root| root.join("install"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_state_dir_is_not_home_dot_ember() {
        let dir = install_state_dir().expect("project dirs should resolve on test host");
        let rendered = dir.to_string_lossy();
        assert!(
            !rendered.contains("/.ember/"),
            "operator install state must not use retired ~/.ember path: {rendered}"
        );
        assert!(
            rendered.contains("Emberlink") || rendered.contains("emberlink"),
            "operator install state path must include the Emberlink project segment: {rendered}"
        );
        assert_eq!(dir.file_name(), Some(std::ffi::OsStr::new("install")));
    }
}
