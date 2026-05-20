//! `ember dev info` — verify the dev install state.
//!
//! Phase 11 of the `ember dev install` flow (design Phase 4). Reports
//! the current dev install state: IdentityRoot fingerprint, install paths,
//! socket path. Daemon reachability and full state reporting will expand
//! as phases 2-10 land.
//!

use super::identity_root;
use crate::install_paths::{DEV_DAEMON_SOCKET_REL, DEV_INSTALL_ROOT, DEV_PLIST_LABEL};

/// Run `ember dev info`.
pub fn run() -> Result<(), String> {
    let home = dirs_next::home_dir().unwrap_or_else(|| std::path::PathBuf::from("~"));
    let socket_path = home.join(DEV_DAEMON_SOCKET_REL);

    println!("ember dev install state");
    println!("  install root:   {DEV_INSTALL_ROOT}");
    println!("  plist label:    {DEV_PLIST_LABEL}");
    println!("  socket:         {}", socket_path.display());
    println!("  keychain label: {}", identity_root::KEYCHAIN_LABEL);

    match identity_root::ensure_dev_identity_root() {
        Ok(handle) => {
            println!(
                "  identity root:  {} (loaded from keychain)",
                handle.fingerprint
            );
        }
        Err(e) => {
            println!("  identity root:  <not found — run 'ember dev install' first> ({e})");
        }
    }

    // Daemon reachability stub (phases 2-10 fill this in).
    println!(
        "  daemon:         <not yet checked — run after 'ember dev install' completes all phases>"
    );

    Ok(())
}
