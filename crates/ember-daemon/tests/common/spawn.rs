//! CLASSIFICATION: PUBLIC
//!
//! Shared test helper for spawning the ember daemon and guaranteeing the
//! child process is reaped on test exit. Per META-T3-USER-SOCKET-LEAK-GUARD-D
//! defense-in-depth: subtask A's type-system fix (`for_test` constructor)
//! prevents tests from inheriting user-home paths, but a panicking test still
//! leaks the spawned `Child` because `Drop` doesn't run on bare
//! `std::process::Child`. `TestDaemonHandle` adds the missing reap step.

use std::process::Child;
use std::time::{Duration, Instant};

/// RAII wrapper around a spawned daemon `Child`. On `Drop` it issues
/// `SIGTERM`, waits up to 5 seconds for graceful shutdown, then falls back
/// to `SIGKILL`. The signal-handling is intentionally simple — no
/// crossbeam, no tokio — because the Drop must run in test-panic context
/// where async runtimes may have already torn down.
pub struct TestDaemonHandle {
    child: Child,
}

impl TestDaemonHandle {
    pub fn from_child(child: Child) -> Self {
        Self { child }
    }

    #[allow(dead_code)] // Used by future Phase-2 migrations; harness API.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for TestDaemonHandle {
    fn drop(&mut self) {
        // SIGTERM → wait up to 5s → SIGKILL fallback.
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
