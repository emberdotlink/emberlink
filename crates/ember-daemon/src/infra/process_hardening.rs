//! CLASSIFICATION: PUBLIC
//!
//! Process-level memory hardening for the daemon.
//!
//! Called once at startup, before any secrets are loaded. Defence-in-depth:
//! each measure closes a distinct exfiltration surface for in-memory key
//! material (vault MEK, lease-KEK, persona secrets, credential plaintext).
//!
//! | Measure                | macOS              | Linux                       |
//! |------------------------|--------------------|-----------------------------|
//! | Anti-debug             | PT_DENY_ATTACH     | prctl(PR_SET_DUMPABLE, 0)   |
//! | Core-dump suppression  | RLIMIT_CORE → 0    | RLIMIT_CORE → 0             |

/// Apply process-level memory hardening. Best-effort on each measure —
/// a failure logs a warning but does not abort the daemon (the operator
/// may be running in a container or test harness where the syscall is
/// unavailable or restricted).
pub fn harden_process() {
    deny_debugger_attach();
    suppress_core_dumps();
}

fn deny_debugger_attach() {
    #[cfg(target_os = "macos")]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        let rc = unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut::<i8>(), 0) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!(error = %err, "PT_DENY_ATTACH failed — debugger attach remains possible");
        } else {
            tracing::info!("PT_DENY_ATTACH applied — debugger attachment blocked");
        }
    }

    #[cfg(target_os = "linux")]
    {
        const PR_SET_DUMPABLE: libc::c_int = 4;
        let rc = unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!(error = %err, "prctl(PR_SET_DUMPABLE, 0) failed — ptrace remains possible");
        } else {
            tracing::info!("PR_SET_DUMPABLE cleared — ptrace attach blocked for non-root");
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        tracing::debug!("no debugger-deny mechanism available on this platform");
    }
}

fn suppress_core_dumps() {
    let zero_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero_limit) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(error = %err, "setrlimit(RLIMIT_CORE, 0) failed — core dumps may contain key material");
    } else {
        tracing::info!("RLIMIT_CORE set to 0 — core dumps suppressed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_process_does_not_panic() {
        harden_process();
    }

    #[test]
    fn suppress_core_dumps_zeroes_rlimit() {
        suppress_core_dumps();
        let mut current = libc::rlimit {
            rlim_cur: u64::MAX,
            rlim_max: u64::MAX,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut current) };
        assert_eq!(rc, 0);
        assert_eq!(current.rlim_cur, 0);
    }
}
