// ---------------------------------------------------------------------------
// forkpty spawn helper
// ---------------------------------------------------------------------------

/// Install a parent-death watchdog in the calling (child) process so the
/// child terminates when the daemon (parent) exits.
///
/// Linux: uses `prctl(PR_SET_PDEATHSIG, SIGHUP)`. The kernel preserves the
/// pdeathsig setting across `execve(2)`, so the post-exec image still
/// receives SIGHUP when the daemon dies. This is the canonical solution
/// and is exec-correct.
///
/// macOS: lacks a kernel-mediated equivalent. We spawn a small getppid-poll
/// pthread that wakes every 500ms and `SIGKILL`s itself if `getppid()`
/// returns 1 (init/launchd reaped the parent). **Limitation:** the pthread
/// is wiped by `execve(2)`, so this watchdog only protects the small
/// pre-exec window inside `forkpty_exec_and_bridge`. After the child
/// exec's into the Construct binary, parent-death cleanup falls back to
/// the daemon's own signal handlers (SIGTERM cascade) for graceful
/// shutdown; ungraceful daemon death (SIGKILL, panic-without-cleanup)
/// will orphan the child to launchd. A robust post-exec fix requires an
/// out-of-process checkpoint (e.g. a wrapper binary that polls getppid then
/// forwards SIGKILL to the wrapped child) and is tracked as a follow-up.
///
/// # Safety
///
/// Must be called post-`fork(2)` pre-`execve(2)` in the child branch
/// where the process is single-threaded. Errors are returned but callers
/// generally ignore them — the watchdog is best-effort and child startup
/// should continue regardless.
#[cfg(unix)]
unsafe fn install_parent_death_watchdog(parent_pid: libc::pid_t) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = parent_pid; // kernel knows the parent without us telling it
        let r = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGHUP, 0, 0, 0) };
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        // PTY_BRIDGE_MACOS_DONE
        // Best-effort getppid-poll watchdog. See the doc-comment above
        // for the exec-wipe limitation.
        //
        // libc 0.2.184 updated `pthread_create`'s `start_routine`
        // parameter from `unsafe extern "C" fn` to safe `extern "C" fn`
        // — the function ITSELF is no longer required to be unsafe by
        // the type signature. The body's libc::getppid / libc::kill
        // calls remain inside `unsafe { … }` blocks per usual rules.
        extern "C" fn watchdog_main(arg: *mut libc::c_void) -> *mut libc::c_void {
            let parent_pid = arg as libc::pid_t;
            loop {
                // 500ms sleep — matches the brief's detection-latency budget.
                let ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 500_000_000,
                };
                unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
                // Two checks: (a) our actual parent (getppid) was reaped to
                // launchd (PID 1), or (b) the original parent_pid no longer
                // exists (kill(pid, 0) returns ESRCH). Either is a sufficient
                // signal that the daemon died; SIGKILL ourselves to avoid
                // orphaned-Construct lingering.
                let ppid = unsafe { libc::getppid() };
                if ppid == 1 || ppid != parent_pid {
                    unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
                    // unreachable, but keep the loop tidy
                    return std::ptr::null_mut();
                }
            }
        }

        let mut tid: libc::pthread_t = 0;
        let mut attr: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::pthread_attr_init(&mut attr) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Detached: we never join; the thread runs until exec wipes it or it
        // SIGKILLs the process.
        let _ =
            unsafe { libc::pthread_attr_setdetachstate(&mut attr, libc::PTHREAD_CREATE_DETACHED) };
        let rc = unsafe {
            libc::pthread_create(
                &mut tid,
                &attr,
                watchdog_main,
                parent_pid as *mut libc::c_void,
            )
        };
        let _ = unsafe { libc::pthread_attr_destroy(&mut attr) };
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc));
        }
        Ok(())
    }
    // Other Unix targets (e.g. *bsd) are not supported by the daemon today.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = parent_pid;
        Ok(())
    }
}

/// Fork with a new pty pair, exec the Construct binary in the child with the
/// slave fd wired to stdin/stdout/stderr, then run `pty_bridge_run` in the
/// parent. Returns `(exit_code, Option<bridge_error_string>)`.
///
/// Must be called from a blocking thread (not directly from async context)
/// because `forkpty(3)` + `execvp(3)` are fork-unsafe in a multithreaded
/// async runtime. `handle_broker_exec` dispatches via
/// `tokio::task::spawn_blocking`.
///
/// Linux uses `execvpe(3)` directly. macOS lacks `execvpe`; the child clears
/// inherited env and `setenv`s each entry, then `execvp`s for PATH lookup
/// (single-threaded post-fork makes direct env manipulation safe).
/// Parent-death cleanup: Linux uses `PR_SET_PDEATHSIG` (kernel-mediated,
/// exec-correct). macOS uses a best-effort pre-exec `getppid`-poll
/// pthread (see [`install_parent_death_watchdog`] for the exec-wipe
/// limitation). Both are installed via the same helper so the call site
/// stays uniform.
///
/// Shim-EOF cascade (ADR 124 §"Shim-EOF correctness"): the bridge returns
/// a [`BridgeExit`] tag. If [`BridgeExit::ShimDisappeared`], this helper
/// dispatches via [`on_shim_eof`] to either SIGTERM the child (default)
/// or let it drain. The returned [`ShimEofOutcome`] feeds the
/// `revoked_early` / `shim_disappeared_at` fields on the
/// `session.construct_invocation` Receipt.
/// Portable `errno()` read for the
/// forkpty child branch. macOS uses `__error()`; Linux exposes
/// `__errno_location()`. The cfg-gated wrapper keeps the call site
/// platform-agnostic. Only called from the Linux-gated privilege-drop
/// site; the `allow(dead_code)` keeps macOS builds clean.
#[cfg(unix)]
#[inline]
#[allow(dead_code)]
fn io_errno() -> i32 {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    unsafe {
        *libc::__error()
    }
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location()
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
    {
        // Fallback for other Unix targets — std::io::Error::last_os_error
        // uses an allocator (Heap_to_Box), which is not async-signal-safe,
        // but no allocator interaction has happened yet at this point in
        // the forked child so it is acceptable here.
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }
}

// `target_uid` / `target_gid` are
// the per-spawn pool lease values. `None` means "don't drop privileges"
// (test pools running as the test uid, or pre-pool legacy callers if
// any). When `Some`, the child branch calls `setresgid` then `setresuid`
// before `execvpe` — group drop first, per `ember_exec::spawn::
// drop_privileges` precedent.
//
// `too_many_arguments` is allowed here intentionally: a struct-of-args
// would not improve readability since every arg is consumed exactly
// once in a sync sub-step of the same fork+exec sequence; the previous
// 6-arg shape was already grandfathered against this lint.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub(super) fn forkpty_exec_and_bridge(
    binary: &str,
    argv: &[String],
    env: &[(String, String)],
    cwd: &str,
    socket_path: &std::path::Path,
    shim_eof_policy: ShimEofPolicy,
    target_uid: Option<u32>,
    target_gid: Option<u32>,
) -> Result<(i32, Option<String>, ShimEofOutcome), String> {
    use std::ffi::CString;

    // Build NUL-terminated argv for execvp: argv[0] = binary, rest = argv.
    let binary_c = CString::new(binary).map_err(|e| format!("binary CString: {e}"))?;
    let mut execv_argv: Vec<CString> = Vec::with_capacity(argv.len() + 1);
    execv_argv.push(binary_c.clone());
    for a in argv {
        execv_argv.push(CString::new(a.as_str()).map_err(|e| format!("argv CString: {e}"))?);
    }
    // execvp expects a null-terminated array of pointers.
    let mut execv_ptrs: Vec<*const libc::c_char> = execv_argv.iter().map(|s| s.as_ptr()).collect();
    execv_ptrs.push(std::ptr::null());

    // Linux uses execvpe with a packed NUL-terminated envp; build it here.
    // macOS unsets inherited env + setenv's per-entry below — it iterates
    // `env` directly, so this packed form is unused on darwin.
    #[cfg(target_os = "linux")]
    let env_strings: Vec<CString> = env
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).map_err(|e| format!("env CString: {e}")))
        .collect::<Result<_, _>>()?;
    #[cfg(target_os = "linux")]
    let env_ptrs: Vec<*const libc::c_char> = {
        let mut v: Vec<*const libc::c_char> = env_strings.iter().map(|s| s.as_ptr()).collect();
        v.push(std::ptr::null());
        v
    };

    // cwd as CString for chdir in child.
    let cwd_c = CString::new(cwd).map_err(|e| format!("cwd CString: {e}"))?;

    let mut master_fd: libc::c_int = -1;
    // winsize zeroed — SIGWINCH propagation is a follow-up.
    // libc 0.2.184 widened forkpty's winp from *const to *mut; binding
    // must be `mut` and the reference passed as `&mut`.
    let mut ws = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let pid = unsafe {
        libc::forkpty(
            &mut master_fd,
            std::ptr::null_mut(), // slave name not needed
            std::ptr::null_mut(), // termios default
            &mut ws,
        )
    };

    if pid < 0 {
        let errno = std::io::Error::last_os_error();
        return Err(format!("forkpty failed: {errno}"));
    }

    if pid == 0 {
        // ---- CHILD ----
        // chdir to requested working directory.
        unsafe { libc::chdir(cwd_c.as_ptr()) };

        // Drop privileges to the
        // per-spawn pool uid before any exec'd code runs. We must
        // do this AFTER chdir (in case the target dir is only
        // readable by the daemon uid) and BEFORE
        // `install_parent_death_watchdog` / `execvpe`, so the child
        // process never gets a moment of authority above the pool
        // uid. Group drops first per `ember_exec::spawn::
        // drop_privileges` (otherwise we'd lose the ability to
        // change groups after dropping user identity).
        //
        // This branch runs in the forked child with a single
        // thread; `setresgid`/`setresuid` are async-signal-safe
        // pure syscall wrappers, no allocator interaction.
        //
        // On error: write a brief diagnostic to stderr (still attached
        // to the pty slave, so the daemon-side bridge captures it),
        // then `_exit(127)` — the parent observes a non-zero exit
        // via the pty bridge and surfaces it in the receipt.
        //
        // Linux-only: `setresuid`/`setresgid` are not in POSIX and
        // macOS does not implement them. The separate-uid daemon
        // posture (ADR 131) only runs on Linux in production, and
        // the macOS dev path runs as the operator's uid so the
        // privilege drop would no-op anyway. On macOS the child
        // runs as the daemon uid — same as before this patch.
        // Linux production gets the per-spawn drop.
        #[cfg(target_os = "linux")]
        if let (Some(uid), Some(gid)) = (target_uid, target_gid) {
            // setresgid(gid, gid, gid) — drop group first.
            let rc = unsafe { libc::setresgid(gid, gid, gid) };
            if rc != 0 {
                let errno = io_errno();
                let msg = format!(
                    "META-BROKER-EXEC-PER-SPAWN-UID: setresgid({gid}) failed: errno={errno}\n"
                );
                unsafe {
                    libc::write(libc::STDERR_FILENO, msg.as_ptr() as *const _, msg.len());
                    libc::_exit(127);
                }
            }
            // setresuid(uid, uid, uid) — drop user identity after
            // gid is locked.
            let rc = unsafe { libc::setresuid(uid, uid, uid) };
            if rc != 0 {
                let errno = io_errno();
                let msg = format!(
                    "META-BROKER-EXEC-PER-SPAWN-UID: setresuid({uid}) failed: errno={errno}\n"
                );
                unsafe {
                    libc::write(libc::STDERR_FILENO, msg.as_ptr() as *const _, msg.len());
                    libc::_exit(127);
                }
            }
        }
        // Silence unused-binding warnings on non-Linux targets where
        // we deliberately skip the privilege drop.
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (target_uid, target_gid);
        }

        // Install the parent-death watchdog. On Linux this is the kernel-mediated
        // PR_SET_PDEATHSIG (survives exec). On macOS it is a best-effort
        // pre-exec getppid-poll thread that is wiped at exec; see
        // `install_parent_death_watchdog` doc-comment for the limitation.
        let _ = unsafe { install_parent_death_watchdog(libc::getppid()) };

        // Replace the child image with the requested binary. The slave fd is
        // already attached to stdin/stdout/stderr by forkpty.
        //
        // Linux: execvpe = execve + PATH lookup. envp wholly replaces the
        // child's inherited environment in one call.
        #[cfg(target_os = "linux")]
        unsafe {
            libc::execvpe(binary_c.as_ptr(), execv_ptrs.as_ptr(), env_ptrs.as_ptr());
        }
        // macOS: no execvpe. Replicate it: drop every inherited env var via
        // unsetenv, setenv each from our prepared list, then execvp for PATH
        // lookup. We're single-threaded in the forked child, so direct env
        // manipulation cannot race.
        #[cfg(target_os = "macos")]
        unsafe {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            // Capture inherited env keys before mutation (unsetenv shrinks
            // environ as it goes; iterating environ in place would skip).
            let inherited_keys: Vec<CString> = std::env::vars_os()
                .filter_map(|(k, _)| CString::new(k.as_bytes()).ok())
                .collect();
            for k in &inherited_keys {
                libc::unsetenv(k.as_ptr());
            }
            // setenv each KEY=VALUE from the caller's env. We already hold
            // these as `env: &[(String, String)]` — re-deriving is cheaper
            // and safer than re-parsing the NUL-terminated env_ptrs slice.
            for (k, v) in env {
                if let (Ok(key_c), Ok(val_c)) = (CString::new(k.as_str()), CString::new(v.as_str()))
                {
                    libc::setenv(key_c.as_ptr(), val_c.as_ptr(), 1);
                }
            }
            libc::execvp(binary_c.as_ptr(), execv_ptrs.as_ptr());
        }
        // exec*() only returns on error — exit immediately so the daemon
        // does not loop in a forked copy of the async runtime.
        unsafe { libc::_exit(127) };
    }

    // ---- PARENT ----
    // Run the PTY bridge (poll loop) until child exits or shim disappears.
    let (bridge_exit, bridge_err) = match pty_bridge_run(master_fd, socket_path, pid) {
        Ok(exit) => (Some(exit), None),
        Err(e) => (None, Some(e.to_string())),
    };

    // Apply the shim-EOF policy if the bridge surfaced a shim disappearance.
    // The 1-second SIGTERM-arrival contract is met by sending the signal
    // synchronously here, immediately after the bridge thread returns.
    let shim_outcome = match bridge_exit {
        Some(BridgeExit::ShimDisappeared) => {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let sigterm_sent = on_shim_eof(pid as i32, shim_eof_policy);
            if sigterm_sent {
                ShimEofOutcome::RevokedEarly {
                    at_unix_secs: now_secs,
                }
            } else {
                ShimEofOutcome::ShimDisappearedDrain {
                    at_unix_secs: now_secs,
                }
            }
        }
        // ChildPtyClosed or bridge error → no special policy.
        _ => ShimEofOutcome::ChildExitedFirst,
    };

    // Defer master fd close on drain — closing the master sends SIGHUP to
    // the slave's foreground process group, which would kill the very child
    // we are trying to let drain. Keep master open across waitpid in that
    // case; it gets closed unconditionally once the child has been reaped.
    let drain_in_progress = matches!(shim_outcome, ShimEofOutcome::ShimDisappearedDrain { .. });
    if !drain_in_progress {
        unsafe { libc::close(master_fd) };
    }

    // Reap the child.
    let mut status: libc::c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited < 0 {
        let errno = std::io::Error::last_os_error();
        tracing::warn!(pid = pid, error = %errno, "broker_exec pty: waitpid failed");
    }

    if drain_in_progress {
        unsafe { libc::close(master_fd) };
    }

    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        // Signaled or other abnormal termination — both buckets get -1
        // (we don't distinguish WIFSIGNALED-vs-other in the receipt).
        -1
    };

    Ok((exit_code, bridge_err, shim_outcome))
}

// ---------------------------------------------------------------------------
// PTY bridge — wire framing for SIGWINCH propagation
// ---------------------------------------------------------------------------
//
// ## Client → Daemon wire format
//
// All data sent from the client (e.g. ember-gh) to the daemon over the PTY
// UDS uses a simple tagged-frame protocol so winsize control messages can
// be multiplexed alongside stdin data.
//
// Frame layout:
//
//   +--------+------------------+------------------------+
//   | 1 byte | depends on tag   | description            |
//   +--------+------------------+------------------------+
//   |  0x00  | u16 BE len, data | stdin data frame       |
//   |  0x57  | 8 bytes (4×u16 BE: rows, cols, xpix, ypix)| winsize frame  |
//   +--------+------------------+------------------------+
//
// TAG_DATA   (0x00): 1-byte tag + 2-byte BE payload length + payload bytes.
//                    Daemon writes payload directly to master fd.
// TAG_WINSIZE (0x57): 1-byte tag + rows(u16 BE) + cols(u16 BE) +
//                    xpixel(u16 BE) + ypixel(u16 BE) = 9 bytes total.
//                    Daemon calls TIOCSWINSZ on the master fd, which
//                    notifies the child process of the new terminal size.
//
// ## Daemon → Client wire format
//
// Raw bytes (no framing). The child's pty output is forwarded verbatim.

/// Tag byte for a stdin data frame (client → daemon).
pub const TAG_DATA: u8 = 0x00;

/// Tag byte for a terminal winsize update frame (client → daemon).
/// ASCII 'W' — mnemonic for WinSize.
pub const TAG_WINSIZE: u8 = 0x57;

/// Signal-forwarding control frames (single-byte, no payload).
/// ASCII 'I'/'J'/'K'/'L' — mnemonic for sIgInt / sigTerm / siKstp(Z) / siKont.
/// Sent by the shim when its own delivered signal must reach the daemon-spawned
/// child across the UDS boundary (ADR 124 §"Foreground-pgrp asymmetry").
pub const TAG_SIGINT: u8 = 0x49;
pub const TAG_SIGTERM: u8 = 0x4A;
pub const TAG_SIGTSTP: u8 = 0x4B;
pub const TAG_SIGCONT: u8 = 0x4C;

/// Encode a stdin data chunk as a `TAG_DATA` frame.
///
/// Frame: `[0x00, len_hi, len_lo, data...]`
/// Caller must ensure `data.len() <= u16::MAX`.
pub fn encode_data_frame(data: &[u8]) -> Vec<u8> {
    let len = data.len().min(u16::MAX as usize);
    let mut out = Vec::with_capacity(3 + len);
    out.push(TAG_DATA);
    out.push((len >> 8) as u8);
    out.push((len & 0xff) as u8);
    out.extend_from_slice(&data[..len]);
    out
}

/// Encode a winsize update as a `TAG_WINSIZE` frame.
///
/// Frame: `[0x57, rows_hi, rows_lo, cols_hi, cols_lo, xpix_hi, xpix_lo, ypix_hi, ypix_lo]`
/// Total: 9 bytes.
pub fn encode_winsize_frame(rows: u16, cols: u16, xpixel: u16, ypixel: u16) -> [u8; 9] {
    [
        TAG_WINSIZE,
        (rows >> 8) as u8,
        (rows & 0xff) as u8,
        (cols >> 8) as u8,
        (cols & 0xff) as u8,
        (xpixel >> 8) as u8,
        (xpixel & 0xff) as u8,
        (ypixel >> 8) as u8,
        (ypixel & 0xff) as u8,
    ]
}

/// Decoded frame from the client → daemon channel.
#[derive(Debug, PartialEq)]
pub enum PtyFrame {
    Data(Vec<u8>),
    Winsize {
        rows: u16,
        cols: u16,
        xpixel: u16,
        ypixel: u16,
    },
    /// Forwarded signal — daemon delivers it to the spawned child via
    /// `libc::kill(spawned_child_pid, sig)`. One of `libc::SIGINT` /
    /// `SIGTERM` / `SIGTSTP` / `SIGCONT`.
    Signal(libc::c_int),
}

/// Attempt to decode one frame from the front of `buf`.
///
/// Returns `Some((frame, bytes_consumed))` if a complete frame is present,
/// or `None` if more bytes are needed.
pub fn decode_one_frame(buf: &[u8]) -> Option<(PtyFrame, usize)> {
    let tag = *buf.first()?;
    match tag {
        TAG_DATA => {
            if buf.len() < 3 {
                return None;
            }
            let len = ((buf[1] as usize) << 8) | (buf[2] as usize);
            if buf.len() < 3 + len {
                return None;
            }
            Some((PtyFrame::Data(buf[3..3 + len].to_vec()), 3 + len))
        }
        TAG_WINSIZE => {
            if buf.len() < 9 {
                return None;
            }
            let rows = ((buf[1] as u16) << 8) | (buf[2] as u16);
            let cols = ((buf[3] as u16) << 8) | (buf[4] as u16);
            let xpixel = ((buf[5] as u16) << 8) | (buf[6] as u16);
            let ypixel = ((buf[7] as u16) << 8) | (buf[8] as u16);
            Some((
                PtyFrame::Winsize {
                    rows,
                    cols,
                    xpixel,
                    ypixel,
                },
                9,
            ))
        }
        TAG_SIGINT => Some((PtyFrame::Signal(libc::SIGINT), 1)),
        TAG_SIGTERM => Some((PtyFrame::Signal(libc::SIGTERM), 1)),
        TAG_SIGTSTP => Some((PtyFrame::Signal(libc::SIGTSTP), 1)),
        TAG_SIGCONT => Some((PtyFrame::Signal(libc::SIGCONT), 1)),
        _ => {
            // Unknown tag: skip the byte and keep parsing. This guards
            // against stray bytes during protocol negotiation.
            Some((PtyFrame::Data(vec![]), 1))
        }
    }
}

/// Apply a winsize to the pty master fd via TIOCSWINSZ.
#[cfg(unix)]
fn apply_winsize_to_master(master_fd: RawFd, rows: u16, cols: u16, xpixel: u16, ypixel: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: xpixel,
        ws_ypixel: ypixel,
    };
    unsafe {
        libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws);
    }
}

// ---------------------------------------------------------------------------
// PTY bridge — poll loop
// ---------------------------------------------------------------------------

use std::os::fd::RawFd;

/// Pseudoterminal bridge handle. Owns the master fd; the slave fd is
/// passed to the spawned child process.
#[derive(Debug)]
pub struct PtyBridge {
    pub master_fd: RawFd,
}

/// Reason the PTY bridge loop returned. Distinguishes natural child exit
/// (master fd EOF / POLLHUP) from shim disappearance (UDS read returned
/// 0 before the child closed its PTY). ADR 124 §"Shim-EOF correctness".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeExit {
    /// Bridge exited because the spawned child closed its end of the PTY
    /// (master fd EOF, EIO, or POLLHUP). The natural-completion path.
    ChildPtyClosed,
    /// Bridge exited because the shim's UDS connection EOFed (returned 0
    /// from `read()`). The child may still be alive — `forkpty_exec_and_bridge`
    /// applies the [`ShimEofPolicy`] to decide whether to SIGTERM or drain.
    ShimDisappeared,
}

/// Policy applied when the bridge thread detects shim-EOF (UDS read of
/// zero bytes) before the spawned child has exited. Sourced from
/// `construct.toml`'s `[actions.<name>].on_shim_eof` field.
///
/// Default is [`ShimEofPolicy::Sigterm`] — matches the wedge framing that
/// the agent supervises its credential lifecycle; if the agent's
/// representative went away, the work it requested should stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShimEofPolicy {
    /// SIGTERM the spawned child immediately on shim-EOF.
    #[default]
    Sigterm,
    /// Let the spawned child run to natural completion. Cred is still
    /// revoked on child exit via the normal path.
    Drain,
}

impl ShimEofPolicy {
    /// Parse a `construct.toml` `on_shim_eof` string. Empty / unrecognized
    /// values fall back to the default (SIGTERM). The validator in
    /// `core-events::construct_toml` rejects unrecognized values at parse
    /// time; this is defense-in-depth for hot-path callers.
    pub fn from_toml_value(s: Option<&str>) -> Self {
        match s {
            Some("drain") => ShimEofPolicy::Drain,
            Some("sigterm") | None => ShimEofPolicy::Sigterm,
            Some(_) => ShimEofPolicy::Sigterm,
        }
    }
}

/// Outcome of the shim-EOF policy decision for a single `broker_exec`
/// invocation. Drives the `revoked_early` / `shim_disappeared_at` fields
/// on the emitted `session.construct_invocation` Receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimEofOutcome {
    /// Shim never disappeared during this exec — the bridge exited via
    /// the natural child-PTY-closed path. No special Receipt fields.
    ChildExitedFirst,
    /// Shim disappeared and the SIGTERM policy ran. Receipt records
    /// `revoked_early = true` with `at_unix_secs`.
    RevokedEarly { at_unix_secs: u64 },
    /// Shim disappeared and the drain policy let the child run to
    /// completion. Receipt records `shim_disappeared_at = at_unix_secs`.
    ShimDisappearedDrain { at_unix_secs: u64 },
}

/// Apply the shim-EOF policy to a live child PID. Returns `true` iff a
/// SIGTERM was actually delivered (Sigterm policy + `kill(2)` success).
///
/// The bridge thread calls back into this function from
/// [`forkpty_exec_and_bridge`] when [`pty_bridge_run`] returns
/// [`BridgeExit::ShimDisappeared`].
#[cfg(unix)]
pub fn on_shim_eof(child_pid: i32, policy: ShimEofPolicy) -> bool {
    match policy {
        ShimEofPolicy::Sigterm => {
            tracing::warn!(
                pid = child_pid,
                "broker_exec: shim disappeared (UDS EOF) — SIGTERM cascade per default policy"
            );
            let r = unsafe { libc::kill(child_pid as libc::pid_t, libc::SIGTERM) };
            r == 0
        }
        ShimEofPolicy::Drain => {
            tracing::warn!(
                pid = child_pid,
                "broker_exec: shim disappeared (UDS EOF) — drain policy: child continues to natural exit"
            );
            false
        }
    }
}

#[cfg(not(unix))]
pub fn on_shim_eof(_child_pid: i32, _policy: ShimEofPolicy) -> bool {
    false
}

#[derive(Debug, thiserror::Error)]
pub enum PtyBridgeError {
    #[error("forkpty syscall failed: errno={0}")]
    ForkptyFailed(i32),
    #[error("not yet implemented: {0}")]
    NotImplemented(String),
    #[error("io: {0}")]
    Io(String),
}

/// Run the daemon-side pty bridge for a Construct invocation.
///
/// Per ADR 124 §1 step 4 daemon-as-process-supervisor lifecycle:
/// - The daemon allocated a pty pair (forkpty); slave fd was attached
///   to the spawned binary's stdin/stdout/stderr.
/// - This function takes ownership of the master fd and bridges
///   stdin/stdout/stderr to the agent's terminal via a Unix-domain
///   stream connection.
/// - SIGWINCH from the agent's terminal is propagated to the child via
///   the master fd using TIOCSWINSZ (see wire format above).
/// - On child exit (or master fd EOF), the bridge cleans up file
///   descriptors and returns.
///
/// Parent-death cleanup is wired in [`forkpty_exec_and_bridge`] via
/// [`install_parent_death_watchdog`]: Linux uses `PR_SET_PDEATHSIG`
/// (kernel-mediated, exec-correct); macOS uses a best-effort pre-exec
/// `getppid`-poll pthread.
///
/// Returns a [`BridgeExit`] tag distinguishing natural child exit
/// ([`BridgeExit::ChildPtyClosed`]) from shim disappearance
/// ([`BridgeExit::ShimDisappeared`]) so the caller can dispatch the
/// appropriate shim-EOF policy (SIGTERM vs drain).
pub fn pty_bridge_run(
    master_fd: RawFd,
    socket_path: &std::path::Path,
    spawned_child_pid: libc::pid_t,
) -> Result<BridgeExit, PtyBridgeError> {
    // PTY_BRIDGE_FORKPTY_DONE
    // PTY_BRIDGE_SIGWINCH_DONE
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| PtyBridgeError::Io(format!("connect {}: {}", socket_path.display(), e)))?;
    let stream_fd = stream.as_raw_fd();

    set_nonblocking(master_fd)?;
    set_nonblocking(stream_fd)?;

    let mut buf = [0u8; 4096];
    // Reassembly buffer for partial frames arriving from the client.
    let mut recv_buf: Vec<u8> = Vec::with_capacity(4096);

    loop {
        let mut fds = [
            libc::pollfd {
                fd: master_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stream_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PtyBridgeError::Io(format!("poll: {err}")));
        }

        // Master fd readable → child output → forward raw bytes to client.
        if fds[0].revents & libc::POLLIN != 0 {
            let n = unsafe { libc::read(master_fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n == 0 {
                return Ok(BridgeExit::ChildPtyClosed);
            }
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(PtyBridgeError::Io(format!("master read: {err}")));
                }
            } else {
                // Daemon → client: raw bytes, no framing. Tolerate stream
                // write errors as a shim-EOF signal — if we can't push to
                // the shim, the shim is effectively gone.
                if let Err(e) = stream.write_all(&buf[..n as usize]) {
                    if e.kind() == std::io::ErrorKind::BrokenPipe
                        || e.kind() == std::io::ErrorKind::ConnectionReset
                    {
                        return Ok(BridgeExit::ShimDisappeared);
                    }
                    return Err(PtyBridgeError::Io(format!("stream write: {e}")));
                }
            }
        }

        // Client socket readable → stdin data or winsize frames.
        if fds[1].revents & libc::POLLIN != 0 {
            match stream.read(&mut buf) {
                Ok(0) => return Ok(BridgeExit::ShimDisappeared),
                Ok(n) => {
                    // Append into reassembly buffer and drain complete frames.
                    recv_buf.extend_from_slice(&buf[..n]);
                    dispatch_frames(master_fd, spawned_child_pid, &mut recv_buf)?;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(PtyBridgeError::Io(format!("stream read: {e}"))),
            }
        }

        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(BridgeExit::ChildPtyClosed);
        }

        // POLLHUP on the stream fd before any zero-byte read means the
        // shim's end was closed — surface as ShimDisappeared so the
        // caller's policy fires.
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(BridgeExit::ShimDisappeared);
        }
    }
}

/// Consume complete frames from `buf` and dispatch them:
/// - `PtyFrame::Data` → write payload to `master_fd`.
/// - `PtyFrame::Winsize` → call TIOCSWINSZ on `master_fd`.
/// - `PtyFrame::Signal` → `libc::kill(spawned_child_pid, sig)`.
fn dispatch_frames(
    master_fd: RawFd,
    spawned_child_pid: libc::pid_t,
    buf: &mut Vec<u8>,
) -> Result<(), PtyBridgeError> {
    loop {
        match decode_one_frame(buf) {
            None => break,
            Some((frame, consumed)) => {
                match frame {
                    PtyFrame::Data(data) => {
                        if !data.is_empty() {
                            write_all_fd(master_fd, &data)?;
                        }
                    }
                    PtyFrame::Winsize {
                        rows,
                        cols,
                        xpixel,
                        ypixel,
                    } => {
                        #[cfg(unix)]
                        apply_winsize_to_master(master_fd, rows, cols, xpixel, ypixel);
                        #[cfg(not(unix))]
                        let _ = (rows, cols, xpixel, ypixel);
                        tracing::debug!(
                            rows,
                            cols,
                            xpixel,
                            ypixel,
                            "pty bridge: TIOCSWINSZ applied"
                        );
                    }
                    PtyFrame::Signal(sig) => {
                        // Forward the shim's delivered signal to the
                        // daemon-spawned child. ADR 124 §"Foreground-pgrp
                        // asymmetry across the UDS boundary".
                        unsafe {
                            libc::kill(spawned_child_pid, sig);
                        }
                        tracing::debug!(
                            sig,
                            pid = { spawned_child_pid },
                            "pty bridge: forwarded signal to child"
                        );
                    }
                }
                buf.drain(..consumed);
            }
        }
    }
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> Result<(), PtyBridgeError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(PtyBridgeError::Io(format!(
            "F_GETFL fd {fd}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let r = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if r < 0 {
        return Err(PtyBridgeError::Io(format!(
            "F_SETFL fd {fd}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<(), PtyBridgeError> {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            return Err(PtyBridgeError::Io(format!("write fd {fd}: {err}")));
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // T1: PTY wire-format encode/decode round-trips (no fd required)
    // -----------------------------------------------------------------------

    /// Encode a data frame and round-trip it through decode_one_frame.
    #[test]
    fn pty_wire_data_frame_roundtrip() {
        let payload = b"hello pty";
        let frame = encode_data_frame(payload);
        // TAG_DATA + 2-byte length + payload
        assert_eq!(frame[0], TAG_DATA);
        assert_eq!(frame[1], 0x00);
        assert_eq!(frame[2], payload.len() as u8);
        assert_eq!(&frame[3..], payload);

        let (decoded, consumed) = decode_one_frame(&frame).expect("decode should succeed");
        assert_eq!(consumed, frame.len());
        assert_eq!(decoded, PtyFrame::Data(payload.to_vec()));
    }

    /// Encode a winsize frame and round-trip it through decode_one_frame.
    #[test]
    fn pty_wire_winsize_frame_roundtrip() {
        let frame = encode_winsize_frame(50, 200, 1200, 800);
        assert_eq!(frame.len(), 9);
        assert_eq!(frame[0], TAG_WINSIZE);
        // rows = 50 = 0x0032
        assert_eq!(frame[1], 0x00);
        assert_eq!(frame[2], 0x32);
        // cols = 200 = 0x00C8
        assert_eq!(frame[3], 0x00);
        assert_eq!(frame[4], 0xC8);

        let (decoded, consumed) = decode_one_frame(&frame).expect("decode should succeed");
        assert_eq!(consumed, 9);
        assert_eq!(
            decoded,
            PtyFrame::Winsize {
                rows: 50,
                cols: 200,
                xpixel: 1200,
                ypixel: 800
            }
        );
    }

    /// Partial frame: decode_one_frame returns None when not enough bytes.
    #[test]
    fn pty_wire_partial_frame_returns_none() {
        // Only the tag byte for a winsize frame — not enough
        let partial = [TAG_WINSIZE, 0x00, 0x18];
        assert!(decode_one_frame(&partial).is_none());

        // Only tag + 1 byte of a data frame with len=5
        let partial_data = [TAG_DATA, 0x00, 0x05, 0xAA, 0xBB];
        assert!(decode_one_frame(&partial_data).is_none());
    }

    /// Two frames concatenated: decode_one_frame advances correctly.
    #[test]
    fn pty_wire_sequential_frames_decode() {
        let ws_frame = encode_winsize_frame(24, 80, 0, 0);
        let data_frame = encode_data_frame(b"input");
        let mut combined = ws_frame.to_vec();
        combined.extend_from_slice(&data_frame);

        let (first, c1) = decode_one_frame(&combined).unwrap();
        assert_eq!(
            first,
            PtyFrame::Winsize {
                rows: 24,
                cols: 80,
                xpixel: 0,
                ypixel: 0
            }
        );
        let (second, c2) = decode_one_frame(&combined[c1..]).unwrap();
        assert_eq!(second, PtyFrame::Data(b"input".to_vec()));
        assert_eq!(c1 + c2, combined.len());
    }
    #[test]
    fn pty_bridge_run_socketpair_round_trip() {
        use std::io::{Read, Write};
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::{UnixListener, UnixStream};

        // Simulate (master_fd <-> agent terminal) with a UnixStream pair.
        let (master_a, mut master_b) = UnixStream::pair().expect("master pair");

        // Agent-side UDS: bind a listener at a unique tmp path.
        let socket_path = std::env::temp_dir().join(format!(
            "emberd-pty-test-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        // Agent-side server: accept, echo first read back as a TAG_DATA
        // frame (the bridge expects framed input on the UDS read path —
        // see ## Client → Daemon wire format above). Pre-2026-05-08 the
        // echo was raw bytes, which `decode_one_frame` consumed one
        // byte at a time as Data(vec![]), and master_b's read_exact
        // never received the echoed payload — the test hung.
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 32];
            let n = s.read(&mut buf).expect("server read");
            let frame = encode_data_frame(&buf[..n]);
            s.write_all(&frame).expect("server echo");
            // Drop s to close socket → bridge gets EOF on stream → returns Ok.
        });

        // Bridge runs in another thread; master_a's RawFd is what handle_broker_exec
        // would have produced via forkpty.
        let master_a_fd = master_a.into_raw_fd();
        let socket_path_for_bridge = socket_path.clone();
        let bridge = std::thread::spawn(move || {
            // Test uses 0 for pid — the test exercises framing, not
            // signal delivery; no signal frames are sent through this path.
            pty_bridge_run(master_a_fd, &socket_path_for_bridge, 0)
        });

        // Send "hello" via master_b (other end of pty pair). Bridge reads from
        // master_a_fd and forwards to UDS server, which echoes it back.
        master_b.write_all(b"hello").expect("write hello");
        let mut echoed = [0u8; 5];
        master_b.read_exact(&mut echoed).expect("read echoed");
        assert_eq!(&echoed, b"hello");

        // Close master_b → bridge sees EOF on master_a_fd → returns Ok.
        drop(master_b);
        let bridge_result = bridge.join().expect("bridge thread");
        assert!(bridge_result.is_ok(), "bridge result: {bridge_result:?}");
        // The server dropped the UDS first (after echoing) — the bridge sees
        // ShimDisappeared either via the stream close or via master EOF
        // depending on poll order; both are acceptable Ok variants.
        let exit = bridge_result.unwrap();
        assert!(
            matches!(
                exit,
                BridgeExit::ChildPtyClosed | BridgeExit::ShimDisappeared
            ),
            "unexpected bridge exit: {exit:?}"
        );
        let _ = server.join();
        let _ = std::fs::remove_file(&socket_path);
    }

    /// PTY_BRIDGE_INTEGRATED — spawn + bridge + exit integration test.
    ///
    /// Uses `forkpty_exec_and_bridge` directly (T1 unit, no daemon socket
    /// required). Spawns `/bin/true` (exits 0 immediately), with a UDS
    /// listener that accepts and drops the connection. Asserts exit_code == 0
    /// and no hard error from the bridge.
    #[test]
    #[cfg(unix)]
    fn forkpty_exec_and_bridge_spawn_true_exits_zero() {
        use std::os::unix::net::UnixListener;

        let socket_path = std::env::temp_dir().join(format!(
            "emberd-pty-integ-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        // Agent-side listener: accept the bridge connection then drop it so the
        // bridge poll loop gets EOF and returns.
        let server = std::thread::spawn(move || {
            let (_s, _) = listener.accept().expect("accept");
            // drop _s immediately — bridge gets EOF on stream side → returns Ok
        });

        let result = forkpty_exec_and_bridge(
            "/usr/bin/true",
            &[],
            &[],
            "/tmp",
            &socket_path,
            // Use Drain so the test exercises natural-exit ordering even
            // when the bridge happens to see UDS EOF first — without it,
            // the default SIGTERM policy can race ahead of /bin/true's exit
            // and signal the still-running process. Original integration
            // intent here is "spawn → bridge → reap exit code".
            ShimEofPolicy::Drain,
            // No privilege drop in
            // this T1 unit test (running as the test process uid).
            None,
            None,
        );

        let _ = server.join();
        let _ = std::fs::remove_file(&socket_path);

        let (exit_code, bridge_err, _outcome) =
            result.expect("forkpty_exec_and_bridge should not hard-fail");
        assert_eq!(
            exit_code, 0,
            "bin/true must exit 0; bridge_err={bridge_err:?}"
        );
        // Bridge error is tolerated (EOF from server is a clean exit, not an
        // error), but we log if it surfaces as a string anyway.
        if let Some(ref e) = bridge_err {
            // An "io: master read:" EIO on pty close is normal when the child
            // exits — PTY master gets EIO rather than EOF on Linux. Accept it.
            assert!(
                e.contains("master read") || e.contains("EIO") || e.contains("connect"),
                "unexpected bridge error: {e}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // T2: shim-EOF policy — SIGTERM (default) + drain (override)
    //
    // Each test spawns `/bin/sleep N` under `forkpty_exec_and_bridge` with a
    // UDS listener that immediately drops its accepted connection so the
    // bridge surfaces `ShimDisappeared`. The shim-EOF policy then either
    // SIGTERMs the spawned child (default) or lets it drain to natural exit
    // (`drain` override). Receipt evidence is asserted via the returned
    // `ShimEofOutcome`, which `handle_broker_exec` projects into the
    // `session.construct_invocation` audit row.
    // -----------------------------------------------------------------------

    /// Default shim-EOF policy: spawn `/bin/sleep 60` under the bridge,
    /// have the agent-side UDS server drop the connection immediately
    /// (= shim disappeared), assert the child gets SIGTERM'd within ~1s
    /// and the outcome reports `RevokedEarly` (the on-wire receipt
    /// `revoked_early = true` evidence comes from this field).
    #[test]
    #[cfg(unix)]
    fn forkpty_exec_and_bridge_shim_eof_default_sigterms_child_within_1s() {
        use std::os::unix::net::UnixListener;
        use std::time::Instant;

        let socket_path = std::env::temp_dir().join(format!(
            "emberd-pty-shim-sigterm-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        // Agent-side: accept the bridge connection, then immediately drop it.
        // This simulates "shim disappeared" — the daemon's bridge thread sees
        // UDS EOF before the spawned child exits.
        let server = std::thread::spawn(move || {
            let (_s, _) = listener.accept().expect("accept");
            // Drop _s immediately — bridge sees stream EOF / read returning 0.
        });

        let started = Instant::now();
        let result = forkpty_exec_and_bridge(
            "/bin/sleep",
            &["60".to_string()],
            &[],
            "/tmp",
            &socket_path,
            ShimEofPolicy::Sigterm,
            // No privilege drop in
            // T1 unit tests (running as the test process uid).
            None,
            None,
        );
        let elapsed = started.elapsed();

        let _ = server.join();
        let _ = std::fs::remove_file(&socket_path);

        let (exit_code, _bridge_err, outcome) =
            result.expect("forkpty_exec_and_bridge should not hard-fail");

        // SIGTERM cascade contract: the child must be reaped within 1 second
        // of shim disappearance. Some headroom (3s) for slow test runners.
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "expected SIGTERM cascade to reap child quickly; took {elapsed:?}"
        );

        // Child was killed by signal — sleep didn't get to natural exit, so
        // exit_code reflects WIFSIGNALED → -1.
        assert_eq!(
            exit_code, -1,
            "child should have been signal-terminated (exit_code -1)"
        );

        // Outcome is RevokedEarly with a sensible timestamp.
        match outcome {
            ShimEofOutcome::RevokedEarly { at_unix_secs } => {
                assert!(
                    at_unix_secs > 0,
                    "RevokedEarly timestamp should be non-zero, got {at_unix_secs}"
                );
            }
            other => panic!("expected RevokedEarly, got {other:?}"),
        }
    }

    /// Drain shim-EOF policy: spawn `/bin/sleep 1` under the bridge with
    /// `ShimEofPolicy::Drain`, have the agent-side UDS server drop the
    /// connection immediately, assert the daemon does NOT SIGTERM the
    /// child — it runs to natural completion, and the outcome reports
    /// `ShimDisappearedDrain` (the on-wire receipt `shim_disappeared_at`
    /// evidence comes from this field).
    #[test]
    #[cfg(unix)]
    fn forkpty_exec_and_bridge_shim_eof_drain_lets_child_run_to_completion() {
        use std::os::unix::net::UnixListener;
        use std::time::Instant;

        let socket_path = std::env::temp_dir().join(format!(
            "emberd-pty-shim-drain-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        // Agent-side: accept the bridge connection, then immediately drop it.
        let server = std::thread::spawn(move || {
            let (_s, _) = listener.accept().expect("accept");
        });

        let started = Instant::now();
        let result = forkpty_exec_and_bridge(
            "/bin/sleep",
            &["1".to_string()],
            &[],
            "/tmp",
            &socket_path,
            ShimEofPolicy::Drain,
            // No privilege drop in
            // T1 unit tests (running as the test process uid).
            None,
            None,
        );
        let elapsed = started.elapsed();

        let _ = server.join();
        let _ = std::fs::remove_file(&socket_path);

        let (exit_code, _bridge_err, outcome) =
            result.expect("forkpty_exec_and_bridge should not hard-fail");

        // Drain policy: child should have run for ~1s. We assert at least
        // 700ms elapsed to confirm we did not interrupt it. (The 1s sleep
        // gives enough margin against scheduler jitter.)
        assert!(
            elapsed >= std::time::Duration::from_millis(700),
            "expected drain to let /bin/sleep 1 run to natural completion; only took {elapsed:?}"
        );

        // Sleep exits 0 on natural completion.
        assert_eq!(
            exit_code, 0,
            "/bin/sleep 1 should exit 0 under drain policy"
        );

        // Outcome is ShimDisappearedDrain with a sensible timestamp.
        match outcome {
            ShimEofOutcome::ShimDisappearedDrain { at_unix_secs } => {
                assert!(
                    at_unix_secs > 0,
                    "ShimDisappearedDrain timestamp should be non-zero, got {at_unix_secs}"
                );
            }
            other => panic!("expected ShimDisappearedDrain, got {other:?}"),
        }
    }

    /// `on_shim_eof` checkpoint test: drain policy returns false (no signal
    /// sent) without touching any process. Defends the policy enum's
    /// behavior independent of the bridge integration.
    #[test]
    #[cfg(unix)]
    fn on_shim_eof_drain_does_not_signal() {
        // Self-PID is fine — drain policy never invokes kill(2), so the
        // PID is irrelevant. Use a deliberately-invalid checkpoint value
        // that would fail kill(2) if the policy mistakenly signaled.
        let sigterm_sent = on_shim_eof(0, ShimEofPolicy::Drain);
        assert!(!sigterm_sent, "drain policy must never SIGTERM");
    }

    /// `ShimEofPolicy::from_toml_value` — defends the parser fallback
    /// behavior so unrecognized strings default to SIGTERM (defense-in-depth
    /// behind the construct.toml validator).
    #[test]
    fn shim_eof_policy_from_toml_value_defaults_to_sigterm() {
        assert_eq!(ShimEofPolicy::from_toml_value(None), ShimEofPolicy::Sigterm);
        assert_eq!(
            ShimEofPolicy::from_toml_value(Some("sigterm")),
            ShimEofPolicy::Sigterm
        );
        assert_eq!(
            ShimEofPolicy::from_toml_value(Some("drain")),
            ShimEofPolicy::Drain
        );
        // Unknown → fallback to SIGTERM (validator catches at parse-time;
        // hot path defends against direct construction).
        assert_eq!(
            ShimEofPolicy::from_toml_value(Some("garbage")),
            ShimEofPolicy::Sigterm
        );
    }

    // -----------------------------------------------------------------------
    //
    // Wire-format extension: single-byte TAG_SIGINT/TERM/TSTP/CONT frames
    // carry a forwarded signal across the shim ↔ daemon UDS. The daemon
    // dispatches each as `libc::kill(spawned_child_pid, sig)` so the user's
    // delivered signal reaches the actual child despite the foreground-pgrp
    // asymmetry across the UDS boundary (ADR 124).
    // -----------------------------------------------------------------------

    /// `decode_one_frame` returns a `PtyFrame::Signal` with the right libc
    /// constant for each single-byte TAG_SIG* tag, consuming exactly 1 byte.
    #[test]
    fn decode_one_frame_signal_tags_round_trip() {
        let cases = [
            (TAG_SIGINT, libc::SIGINT),
            (TAG_SIGTERM, libc::SIGTERM),
            (TAG_SIGTSTP, libc::SIGTSTP),
            (TAG_SIGCONT, libc::SIGCONT),
        ];
        for (tag, expected_sig) in cases {
            let buf = [tag];
            let (frame, consumed) = decode_one_frame(&buf).expect("signal frame should decode");
            assert_eq!(frame, PtyFrame::Signal(expected_sig), "tag 0x{tag:02x}");
            assert_eq!(consumed, 1, "signal frame should consume exactly 1 byte");
        }
    }

    /// Tag bytes are pinned to the wire-format spec — must agree with the
    /// shim's mirrored constants in `crates/ember-gh/src/main.rs`. Drift
    /// between the two would silently break signal forwarding.
    #[test]
    fn signal_tag_byte_values_are_pinned() {
        assert_eq!(TAG_SIGINT, 0x49);
        assert_eq!(TAG_SIGTERM, 0x4A);
        assert_eq!(TAG_SIGTSTP, 0x4B);
        assert_eq!(TAG_SIGCONT, 0x4C);
    }

    /// Integration: spawn `/bin/cat` (which blocks reading from PTY stdin),
    /// send a single-byte `TAG_SIGINT` (0x49) through the bridge UDS, and
    /// assert the spawned child exits with the kill-by-signal indicator.
    ///
    /// `forkpty_exec_and_bridge` projects WIFSIGNALED into `exit_code = -1`
    /// (the WEXITSTATUS path returns the actual code); evidence that the
    /// child got killed by the forwarded signal is `exit_code == -1` plus
    /// the absence of any natural-exit signaling.
    #[test]
    #[cfg(unix)]
    fn pty_bridge_forwards_sigint_to_child() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;

        let socket_path = std::env::temp_dir().join(format!(
            "emberd-pty-sigint-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        // Agent-side: accept the bridge connection, send TAG_SIGINT, then
        // keep the connection alive so the shim-EOF policy does NOT fire
        // (a closed socket would trigger the default SIGTERM cascade and
        // mask the SIGINT-forwarding evidence we're testing).
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            // Forward a SIGINT to the daemon. The daemon's bridge thread
            // decodes this and calls libc::kill(spawned_child_pid, SIGINT).
            s.write_all(&[TAG_SIGINT]).expect("write TAG_SIGINT");
            s.flush().ok();
            // Hold the connection open until cat exits + bridge closes
            // its end (master EOFs → ChildPtyClosed). This avoids
            // racing with the shim-EOF SIGTERM cascade.
            let mut buf = [0u8; 64];
            // Best-effort drain of any pty output until daemon closes.
            use std::io::Read;
            loop {
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });

        let result = forkpty_exec_and_bridge(
            "/bin/cat",
            &[],
            &[],
            "/tmp",
            &socket_path,
            // Drain so a stray shim-EOF wouldn't mask the signal-forwarding
            // path. We expect the child to die from forwarded SIGINT before
            // the shim-EOF check matters.
            ShimEofPolicy::Drain,
            // No privilege drop in
            // T1 unit tests (running as the test process uid).
            None,
            None,
        );

        let _ = server.join();
        let _ = std::fs::remove_file(&socket_path);

        let (exit_code, _bridge_err, _outcome) =
            result.expect("forkpty_exec_and_bridge should not hard-fail");

        // /bin/cat reading from a PTY without TTY closure does not exit on
        // its own. exit_code = -1 is the WIFSIGNALED projection — evidence
        // the child was reaped via signal (the forwarded SIGINT).
        assert_eq!(
            exit_code, -1,
            "expected /bin/cat to be terminated by forwarded SIGINT (WIFSIGNALED → -1)"
        );
    }
}
