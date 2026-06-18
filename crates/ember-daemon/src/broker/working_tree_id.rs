//! CLASSIFICATION: PUBLIC
//! Stable working-tree identifier derived from a cwd path (META-ARCH-DCC-2).
//!
//! Walks up from a canonicalized `cwd` until finding an ancestor directory
//! that contains a `.git/` subdirectory. Returns that ancestor's absolute
//! canonical path as a `String`, which downstream callers (DCC-3 TOFU,
//! DCC-6 HTTPS dispatch) use as a binding-lookup key.

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum WorkingTreeIdError {
    #[error("no .git/ ancestor found walking up from {0:?}")]
    NoGitDirAncestor(PathBuf),
    #[error("canonicalize failed: {0}")]
    CanonicalizeFailed(#[from] std::io::Error),
}

/// Resolve a stable working-tree identifier from a cwd path.
///
/// Walks up from `cwd` (canonicalized) until finding an ancestor
/// containing `.git/`. Returns that ancestor's absolute canonical path
/// as a `String`. Refuses if no `.git/` ancestor is found.
pub fn working_tree_id(cwd: &Path) -> Result<String, WorkingTreeIdError> {
    let canonical = cwd.canonicalize()?;
    canonical
        .ancestors()
        .find(|p| p.join(".git").is_dir())
        .map(|p| p.to_string_lossy().into_owned())
        .ok_or(WorkingTreeIdError::NoGitDirAncestor(canonical))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_up_to_git_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        let sub = tmp.path().join("a").join("b");
        std::fs::create_dir_all(&sub).unwrap();

        let resolved = working_tree_id(&sub).unwrap();
        let expected = tmp
            .path()
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(resolved, expected);
    }

    #[test]
    fn refuses_when_no_git_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        let result = working_tree_id(tmp.path());
        assert!(matches!(
            result,
            Err(WorkingTreeIdError::NoGitDirAncestor(_))
        ));
    }
}
