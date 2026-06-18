//! CLASSIFICATION: PUBLIC
//!
//! Pins META-T3-USER-SOCKET-LEAK-GUARD-D acceptance: dropping a
//! `TestDaemonHandle` reaps the wrapped child via SIGTERM (with SIGKILL
//! fallback) so a panicking test cannot leak the spawned daemon process.

mod common;

use common::spawn::TestDaemonHandle;

#[test]
fn test_daemon_handle_kills_child_on_drop() {
    let child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    let handle = TestDaemonHandle::from_child(child);
    drop(handle);
    // Process should be gone.
    let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
    assert!(!alive, "child still alive after handle drop");
}
